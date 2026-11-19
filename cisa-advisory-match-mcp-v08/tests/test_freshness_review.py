"""Freshness must not turn an uncertain index into a clean discovery result.

Fixture-only tests. They make no assertion about live upstream index freshness.
"""
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from advisory_matcher.service import run_inventory
from fake_client import ADVISORY_ID, FakeClient


class FreshnessClient(FakeClient):
    def __init__(self, stamp):
        super().__init__()
        self.stamp = stamp

    async def call_tool(self, name, args):
        result = await super().call_tool(name, args)
        if name == "cisa_list_reference":
            mirror = result["sources"]["csafMirror"]
            if self.stamp is None:
                mirror.pop("lastCompletedAt", None)
            else:
                mirror["lastCompletedAt"] = self.stamp
        if name == "cisa_search_ics_advisories":
            return {"results": [], "hasMore": False, "totalCount": 0}
        return result


def item():
    return {"asset_id": "fictional-only", "manufacturer": "Unmapped test vendor",
            "product": "Unmapped test product", "version": "1.0"}


@pytest.mark.parametrize("stamp", [
    None,
    "not-a-timestamp",
    "2020-01-01T00:00:00Z",
    (datetime.now(timezone.utc) + timedelta(hours=3)).isoformat(),
])
def test_bad_or_missing_index_freshness_makes_discovery_incomplete(stamp):
    result = asyncio.run(run_inventory([item()], FreshnessClient(stamp)))
    assert result["coverage"]["candidate_selection_complete"] is False
    assert result["coverage"]["source_freshness"] in {"unknown", "stale_or_inconsistent"}
    assert result["results"][0]["outcome"] == "needs_review"


def test_recent_index_allows_bounded_empty_search_but_not_a_global_safety_claim():
    result = asyncio.run(run_inventory([item()], FreshnessClient(datetime.now(timezone.utc).isoformat())))
    assert result["coverage"]["candidate_selection_complete"] is True
    assert result["coverage"]["source_freshness"] == "within_policy_window"
    assert result["results"][0]["outcome"] == "no_match_in_checked_advisories"
    assert "does not mean safe" in result["claim_limit"]


def test_stale_index_does_not_block_a_selected_original_advisory_check():
    selected = {"asset_id": "fictional-selected", "manufacturer": "Honeywell",
                "product": "IQ4E Firmware", "version": "3.29"}
    result = asyncio.run(run_inventory([selected], FreshnessClient("2020-01-01T00:00:00Z"),
                                       advisory_ids=[ADVISORY_ID]))
    assert result["coverage"]["mode"] == "selected_advisories"
    assert result["coverage"]["source_freshness"] == "stale_or_inconsistent"
    assert result["coverage"]["candidate_selection_complete"] is True
    assert result["results"][0]["outcome"] == "affected_range_match"
    assert any("stale" in warning for warning in result["warnings"])
