"""Independent regression checks for alias integration and expanded reports."""
import asyncio
import json

from advisory_matcher.aliases import AliasCatalog
from advisory_matcher import service
from fake_client import ADVISORY_ID, FakeClient


def _record(identifier, names, mode="candidate", **extra):
    return {"id": identifier, "names": names, "mode": mode,
            "source_urls": ["https://example.com/alias-source"],
            "source_title": "Synthetic alias source", "rationale": "Synthetic relationship for budget regression.", **extra}


def _bind_catalog(monkeypatch, data):
    catalog = AliasCatalog(data)
    monkeypatch.setattr(service, "alias_metadata", catalog.metadata)
    monkeypatch.setattr(service, "vendor_search_terms", catalog.vendor_search_terms)
    monkeypatch.setattr(service, "input_hints", catalog.input_hints)
    # Source fixture's Honeywell product does not match this synthetic vendor.
    monkeypatch.setattr(service, "match_device", lambda item, document: [])
    return catalog


def test_expanded_name_hints_cannot_bypass_total_output_limit(monkeypatch):
    records = [_record(f"product-{i}", ["Device", f"Device variant {i}"],
                       vendors=["Synthetic Vendor"], rationale="x" * 2400) for i in range(12)]
    _bind_catalog(monkeypatch, {"schema_version": 1, "version": "test", "vendors": [], "products": records})
    inventory = [{"asset_id": f"fictional-{i}", "manufacturer": "Synthetic Vendor", "product": "Device", "version": "1"} for i in range(20)]
    report = asyncio.run(service.run_inventory(inventory, FakeClient(), advisory_ids=[ADVISORY_ID]))
    assert len(json.dumps(report).encode()) <= service.MAX_OUTPUT_BYTES
    assert len(report["results"]) == 20
    assert all(row["outcome"] == "needs_review" for row in report["results"])
    assert report["coverage"]["candidate_selection_complete"] is False


def test_expanded_vendor_references_cannot_bypass_total_output_limit(monkeypatch):
    records = [_record(f"vendor-{i}", ["Synthetic Vendor", f"Related vendor {i}"], rationale="x" * 2400) for i in range(120)]
    _bind_catalog(monkeypatch, {"schema_version": 1, "version": "test", "vendors": records, "products": []})
    inventory = [{"asset_id": "fictional-1", "manufacturer": "Synthetic Vendor", "product": "Device", "version": "1"}]
    report = asyncio.run(service.run_inventory(inventory, FakeClient()))
    assert len(json.dumps(report).encode()) <= service.MAX_OUTPUT_BYTES
    assert report["coverage"]["candidate_selection_complete"] is False


def test_aliased_discovery_never_exceeds_shared_request_budget(monkeypatch):
    records = [_record(f"vendor-{v}", [f"Vendor {v}", f"Alias {v}a", f"Alias {v}b"], mode="equivalent") for v in range(4)]
    _bind_catalog(monkeypatch, {"schema_version": 1, "version": "test", "vendors": records, "products": []})
    client = FakeClient()
    client.pages = [{"results": [], "hasMore": True, "cursor": "next"}, {"results": [], "hasMore": False}]
    inventory = [{"asset_id": f"fictional-{i}", "manufacturer": f"Vendor {i}", "product": "Device", "version": "1"} for i in range(4)]
    report = asyncio.run(service.run_inventory(inventory, client))
    searches = [(name, args) for name, args in client.calls if name == "cisa_search_ics_advisories"]
    assert len(searches) == service.MAX_TOTAL_SEARCH_REQUESTS
    assert report["coverage"]["search_requests_used"] == len(searches)
    assert all(not state["complete"] for state in report["coverage"]["searches"])
    assert all(row["outcome"] == "needs_review" for row in report["results"])


def test_packaged_pme_alias_is_manufacturer_specific():
    from advisory_matcher.aliases import compare_identity
    assert compare_identity("Schneider Electric", "PME", "Schneider Electric", "Power Monitoring Expert")["match_type"] == "verified_alias"
    assert compare_identity("Emerson", "PME", "Emerson", "PAC Machine Edition")["match_type"] == "verified_alias"
    assert not compare_identity("Schneider Electric", "PME", "Emerson", "PAC Machine Edition")["matched"]
    assert not compare_identity("Emerson", "PME", "Emerson", "Power Monitoring Expert")["matched"]


def test_packaged_factorytalk_editions_remain_distinct():
    from advisory_matcher.aliases import compare_identity
    assert not compare_identity("Rockwell Automation", "FactoryTalk View SE", "Rockwell Automation", "FactoryTalk View Machine Edition")["matched"]
    assert compare_identity("Rockwell Automation", "FactoryTalk View SE", "Rockwell Automation", "FactoryTalk View Site Edition")["match_type"] == "verified_alias"


def test_packaged_firmware_short_name_is_review_not_affected():
    from advisory_matcher.matching import match_device
    from test_matching import document, inventory
    findings = match_device(inventory(product="IQ4E"), document())
    assert findings and all(f["assessment"] == "needs_review" for f in findings)
    assert all(not f["cvss"] for f in findings)
    assert not match_device(inventory(product="IQ412 Firmware"), document())
