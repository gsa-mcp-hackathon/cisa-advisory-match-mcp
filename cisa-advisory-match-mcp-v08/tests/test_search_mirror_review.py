"""Conflicting page metadata cannot be overridden by a healthy source reference."""
import asyncio
from datetime import datetime, timedelta, timezone

from advisory_matcher.service import run_inventory
from fake_client import ADVISORY_ID, FakeClient


class SearchMirrorClient(FakeClient):
    def __init__(self, mirror, *, next_mirror=None, include_candidate=False):
        super().__init__()
        self.mirror = mirror
        self.next_mirror = next_mirror
        self.include_candidate = include_candidate

    async def call_tool(self, name, args):
        response = await super().call_tool(name, args)
        if name == "cisa_search_ics_advisories":
            more = self.next_mirror is not None and not args.get("cursor")
            return {"results": [{"advisoryId": ADVISORY_ID}] if self.include_candidate else [],
                    "hasMore": more, "cursor": "page-two" if more else None,
                    "totalCount": int(self.include_candidate),
                    "mirror": self.next_mirror if args.get("cursor") else self.mirror}
        return response


def inventory():
    return [{"asset_id": "fictional-search-mirror", "manufacturer": "Unmapped test manufacturer",
             "product": "Unmapped test product", "version": "1"}]


def assert_incomplete(mirror):
    report = asyncio.run(run_inventory(inventory(), SearchMirrorClient(mirror)))
    assert report["coverage"]["source_freshness"] == "within_policy_window"
    assert report["coverage"]["candidate_selection_complete"] is False
    assert report["coverage"]["searches"][0]["queries"][0]["complete"] is False
    assert report["results"][0]["outcome"] == "needs_review"
    assert any("Search mirror metadata" in warning for warning in report["warnings"])
    return report


def test_search_page_not_ready_overrides_healthy_reference():
    assert_incomplete({"ready": False})


def test_search_page_unfinished_sync_overrides_healthy_reference():
    assert_incomplete({"syncStatus": "in_progress"})


def test_search_page_failed_documents_override_healthy_reference():
    assert_incomplete({"failedDocumentCount": 2})


def test_search_page_stale_timestamp_overrides_healthy_reference():
    assert_incomplete({"lastCompletedAt": "2020-01-01T00:00:00Z"})


def test_search_page_future_timestamp_overrides_healthy_reference():
    assert_incomplete({"lastCompletedAt": (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat()})


def test_missing_page_metadata_does_not_claim_verified_page_freshness():
    report = asyncio.run(run_inventory(inventory(), SearchMirrorClient({})))
    query = report["coverage"]["searches"][0]["queries"][0]
    assert query["mirror_freshness"] == "unknown"
    assert query["complete"] is True  # Pagination completes; healthy global metadata is separate.


def test_malformed_page_timestamp_remains_unknown():
    report = asyncio.run(run_inventory(inventory(), SearchMirrorClient({"lastCompletedAt": "invalid"})))
    assert report["coverage"]["searches"][0]["queries"][0]["mirror_freshness"] == "unknown"


def test_later_healthy_page_cannot_erase_earlier_conflict():
    report = asyncio.run(run_inventory(inventory(), SearchMirrorClient(
        {"ready": False, "lastCompletedAt": "2020-01-01T00:00:00Z"},
        next_mirror={"ready": True, "syncStatus": "complete", "failedDocumentCount": 0,
                     "lastCompletedAt": datetime.now(timezone.utc).isoformat()})))
    query = report["coverage"]["searches"][0]["queries"][0]
    assert query["pages_checked"] == 2
    assert query["mirror_freshness"] == "stale_or_inconsistent"
    assert query["complete"] is False
    assert report["coverage"]["candidate_selection_complete"] is False


def test_page_conflict_keeps_original_source_positive_with_incomplete_coverage():
    asset = [{"asset_id": "fictional-positive", "manufacturer": "Honeywell",
              "product": "IQ4E Firmware", "version": "3.29"}]
    report = asyncio.run(run_inventory(asset, SearchMirrorClient({"ready": False}, include_candidate=True)))
    assert report["results"][0]["outcome"] == "affected_range_match"
    assert report["results"][0]["coverage_complete_for_selected_candidates"] is False
    assert any("incomplete" in reason for reason in report["results"][0]["review_reasons"])
