"""A confirmed finding must not hide a second unresolved finding.

The advisory is a modified local fixture and is not an actual extra CVE.
"""
import asyncio
from copy import deepcopy

from advisory_matcher.service import run_inventory
from fake_client import ADVISORY_ID, FakeClient


def fictional_asset():
    return {"asset_id": "fictional-mixed-review", "manufacturer": "Honeywell",
            "product": "IQ4E Firmware", "version": "3.29"}


def mixed_client():
    client = FakeClient()
    unresolved = deepcopy(client.document["vulnerabilities"][0])
    unresolved["cve"] = "CVE-2099-1000"  # Synthetic, not a real advisory finding.
    affected_ids = unresolved["product_status"]["known_affected"]
    unresolved["product_status"] = {"under_investigation": affected_ids}
    client.document["vulnerabilities"].append(unresolved)
    return client


def test_confirmed_and_unresolved_findings_are_both_visible():
    report = asyncio.run(run_inventory([fictional_asset()], mixed_client(), advisory_ids=[ADVISORY_ID]))
    row = report["results"][0]
    assert row["outcome"] == "affected_range_match"
    assert {f["cve"]: f["assessment"] for f in row["findings"]} == {
        "CVE-2026-3611": "affected_range_match", "CVE-2099-1000": "needs_review"}
    assert row["assessment_counts"] == {"affected_range_match": 1,
                                       "outside_affected_range": 0, "needs_review": 1}
    assert row["has_unresolved_findings"] is True
    assert any("require review" in reason for reason in row["review_reasons"])


def test_incomplete_coverage_remains_visible_even_with_a_positive():
    report = asyncio.run(run_inventory([fictional_asset()], mixed_client(),
                         advisory_ids=[ADVISORY_ID, "ICSA-26-048-04"], max_advisories=1))
    row = report["results"][0]
    assert row["outcome"] == "affected_range_match"
    assert row["coverage_complete_for_selected_candidates"] is False
    assert any("incomplete" in reason for reason in row["review_reasons"])
    assert row["has_unresolved_findings"] is True


def test_output_budget_fallback_does_not_expose_stale_finding_summary(monkeypatch):
    from advisory_matcher import service
    monkeypatch.setattr(service, "MAX_OUTPUT_BYTES", 1000)
    report = asyncio.run(run_inventory([fictional_asset()], mixed_client(), advisory_ids=[ADVISORY_ID]))
    row = report["results"][0]
    assert report["coverage"]["output_truncated"] is True
    assert row["findings"] == [] and row["findings_omitted_count"] == 2
    assert row["outcome"] == "needs_review"
    assert row["assessment_counts"] is None
    assert row["has_unresolved_findings"] is None
