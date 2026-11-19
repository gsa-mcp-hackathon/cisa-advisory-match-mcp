"""Independent checks for expanded name catalogs and identity safety.

Synthetic advisory documents exercise matching policy, not real exposure.
"""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from advisory_matcher.aliases import AliasCatalog, get_catalog
from advisory_matcher import matching

ROOT = Path(__file__).resolve().parents[1]


def record(identifier, names, *, mode="equivalent", vendors=None):
    result = {"id": identifier, "names": names, "mode": mode,
              "source_urls": ["https://example.test/documented-name"],
              "source_title": "Synthetic independent review source",
              "rationale": "Synthetic name relationship for regression testing."}
    if vendors is not None:
        result["vendors"] = vendors
    return result


def synthetic_csaf(vendor, product, *, rule="<2"):
    return {"product_tree": {"branches": [
        {"category": "vendor", "name": vendor, "branches": [
            {"category": "product_name", "name": product, "branches": [
                {"category": "product_version_range", "name": rule,
                 "product": {"product_id": "test-product", "name": f"{vendor} {product}: {rule}"}}
            ]}
        ]}
    ]}, "vulnerabilities": [{"cve": "CVE-2099-1000", "product_status": {"known_affected": ["test-product"]}}]}


def item(vendor, product, version="1"):
    return {"asset_id": "fictional-expansion-review", "manufacturer": vendor, "product": product, "version": version}


def test_shared_acronym_inside_one_manufacturer_stays_ambiguous(monkeypatch):
    cat = AliasCatalog({"schema_version": 1, "version": "synthetic", "vendors": [], "products": [
        record("first", ["Process Monitoring Environment", "PME"], vendors=["Test Vendor"]),
        record("second", ["Plant Management Editor", "PME"], vendors=["Test Vendor"]),
    ]})
    monkeypatch.setattr(matching, "compare_identity", cat.compare_identity)
    findings = matching.match_device(item("Test Vendor", "PME"), synthetic_csaf("Test Vendor", "Process Monitoring Environment"))
    assert findings[0]["assessment"] == "needs_review"
    assert findings[0]["cvss"] == []


def test_candidate_brand_cannot_turn_product_alias_into_affected_match(monkeypatch):
    cat = AliasCatalog({"schema_version": 1, "version": "synthetic", "vendors": [
        record("ownership", ["Parent", "Brand"], mode="candidate")], "products": [
        record("product", ["Device 500 Firmware", "D500 FW"], vendors=["Parent", "Brand"])]})
    monkeypatch.setattr(matching, "compare_identity", cat.compare_identity)
    assert matching.match_device(item("Parent", "D500 FW"), synthetic_csaf("Brand", "Device 500 Firmware")) == []
    findings = matching.match_device(item("Parent", "Device 500 Firmware"), synthetic_csaf("Brand", "Device 500 Firmware"))
    assert findings[0]["assessment"] == "needs_review"


def test_equivalent_alias_cannot_erase_product_family_context(monkeypatch):
    cat = AliasCatalog({"schema_version": 1, "version": "synthetic", "vendors": [], "products": [
        record("product", ["Device 500 Firmware", "D500 FW"], vendors=["Test Vendor"])]})
    source = synthetic_csaf("Test Vendor", "Device 500 Firmware")
    vendor = source["product_tree"]["branches"][0]
    vendor["branches"] = [{"category": "product_family", "name": "Safety series", "branches": vendor["branches"]}]
    monkeypatch.setattr(matching, "compare_identity", cat.compare_identity)
    findings = matching.match_device(item("Test Vendor", "D500 FW"), source)
    assert findings[0]["assessment"] == "needs_review"
    assert any("product family" in issue for issue in findings[0]["evidence"][0]["identity_issues"])


def test_catalog_product_mappings_never_apply_to_unrelated_vendor():
    cat = get_catalog()
    data = json.loads((ROOT / "advisory_matcher/data/aliases.json").read_text())
    for group in data["products"]:
        result = cat.compare_identity("Unrelated Synthetic Manufacturer", group["names"][0],
                                      "Unrelated Synthetic Manufacturer", group["names"][1])
        assert not result["matched"], group["id"]


def test_catalog_candidate_products_cannot_create_positive_affected_decision():
    data = json.loads((ROOT / "advisory_matcher/data/aliases.json").read_text())
    for group in data["products"]:
        if group["mode"] != "candidate":
            continue
        for vendor in group["vendors"]:
            findings = matching.match_device(item(vendor, group["names"][0]),
                                             synthetic_csaf(vendor, group["names"][1]))
            assert findings and all(f["assessment"] == "needs_review" for f in findings), (group["id"], vendor)


def test_matching_preserves_original_and_source_names_under_alias_resolution():
    original = item("Honeywell International Inc.", "IQ4E Firmware")
    source = synthetic_csaf("Honeywell", "IQ4E Firmware")
    saved_input, saved_source = deepcopy(original), deepcopy(source)
    findings = matching.match_device(original, source)
    assert findings[0]["assessment"] == "affected_range_match"
    detail = findings[0]["evidence"][0]
    assert detail["input_identity"] == {"manufacturer": original["manufacturer"], "product": original["product"]}
    assert detail["vendor_names"] == ["Honeywell"]
    assert detail["identity_matches"][0]["mappings"][0]["source_urls"]
    assert original == saved_input and source == saved_source


def real_document(filename):
    return json.loads((ROOT / "tests/fixtures/expansion" / filename).read_bytes())


def test_expansion_fixtures_retain_the_pinned_original_bytes():
    records = json.loads((ROOT / "tests/fixtures/expansion-fixture-provenance.json").read_text())
    assert len(records) == 4
    for provenance in records:
        raw = (ROOT / "tests/fixtures/expansion" / provenance["filename"]).read_bytes()
        doc = json.loads(raw)
        assert hashlib.sha256(raw).hexdigest() == provenance["sha256"]
        assert provenance["source_commit"] == "020f7c01c13b08df34a9557e734d76ed7943c537"
        assert provenance["source_commit"] in provenance["source_url"]
        assert doc["document"]["tracking"]["version"] == provenance["revision"]
        assert provenance["original_bytes"] is True


@pytest.mark.parametrize("filename,vendor,product,version,product_id,cve,assessment", [
    ("icsa-22-242-03.json", "Hitachi Energy", "Modular Switchgear Monitoring", "2.2",
     "CSAFPID-0001", "CVE-2015-6584", "affected_range_match"),
    ("icsa-22-242-03.json", "Hitachi Energy", "Modular Switchgear Monitoring", "2.3",
     "CSAFPID-0001", "CVE-2015-6584", "outside_affected_range"),
    ("icsa-25-072-07.json", "Siemens", "6GK5876-4AA00-2DA2", "8.2",
     "CSAFPID-0014", "CVE-2025-23384", "affected_range_match"),
    ("icsa-25-072-07.json", "Siemens", "6GK5876-4AA00-2DA2", "8.2.1",
     "CSAFPID-0014", "CVE-2025-23384", "outside_affected_range"),
    ("icsa-25-072-07.json", "Siemens", "6GK5876-4AA00-2BA2", "8.2",
     "CSAFPID-0013", "CVE-2025-23384", "affected_range_match"),
    ("icsa-20-212-04.json", "Mitsubishi Electric", "MELSOFT GX Developer", "8.504A",
     "CSAFPID-0016", "CVE-2020-14521", "needs_review"),
])
def test_new_names_match_only_the_expected_real_product_and_version(
        filename, vendor, product, version, product_id, cve, assessment):
    doc = real_document(filename)
    before = deepcopy(doc)
    findings = matching.match_device(item(vendor, product, version), doc)
    assert len(findings) == 1
    assert findings[0]["cve"] == cve
    assert findings[0]["assessment"] == assessment
    assert {e["product_id"] for e in findings[0]["evidence"]} == {product_id}
    assert findings[0]["evidence"][0]["identity_matches"][0]["match_type"] == "verified_alias"
    assert doc == before
    if assessment == "needs_review":
        assert findings[0]["cvss"] == []


def test_real_prm_alias_keeps_unsupported_source_release_prefix_for_review():
    doc = real_document("icsa-14-133-01.json")
    findings = matching.match_device(item("Yokogawa", "Plant Resource Manager", "3.11.20"), doc)
    assert {f["cve"] for f in findings} == {
        "CVE-2014-0781", "CVE-2014-0782", "CVE-2014-0783", "CVE-2014-0784"}
    assert all(f["assessment"] == "needs_review" and not f["cvss"] for f in findings)
    for finding in findings:
        assert {e["product_id"] for e in finding["evidence"]} == {"CSAFPID-0015"}
        assert finding["evidence"][0]["version_rule"] == "<=R3.11.20"
        assert finding["evidence"][0]["identity_matches"][0]["match_type"] == "verified_alias"


@pytest.mark.parametrize("filename,vendor,product", [
    ("icsa-22-242-03.json", "Hitachi Energy", "MSM-I"),
    ("icsa-22-242-03.json", "Hitachi Energy", "MSM-II"),
    ("icsa-22-242-03.json", "Siemens", "Modular Switchgear Monitoring"),
    ("icsa-25-072-07.json", "Siemens", "SCALANCE M876-4"),
    ("icsa-25-072-07.json", "Siemens", "6GK5876-4AA00-2DA3"),
    ("icsa-25-072-07.json", "Yokogawa", "6GK5876-4AA00-2DA2"),
    ("icsa-20-212-04.json", "Mitsubishi Electric", "MELSOFT GX Developer Pro"),
    ("icsa-20-212-04.json", "Mitsubishi Electric", "GX Works"),
    ("icsa-14-133-01.json", "Emerson", "Plant Resource Manager"),
])
def test_real_advisories_do_not_accept_other_models_editions_or_vendors(filename, vendor, product):
    assert matching.match_device(item(vendor, product), real_document(filename)) == []


def test_exact_regional_sku_does_not_alias_another_region():
    cat = get_catalog()
    assert not cat.compare_identity(
        "Siemens", "6GK5876-4AA00-2DA2", "Siemens",
        "SCALANCE M876-4 (EU) (6GK5876-4AA00-2BA2)")["matched"]


def test_ambiguous_bare_names_and_historical_product_names_need_review():
    cat = get_catalog()
    for vendor, left, right in [
        ("Siemens", "PDM", "SIMATIC PDM"),
        ("Siemens", "ALM", "Automation License Manager"),
        ("AVEVA", "Historian", "AVEVA Historian"),
        ("Emerson", "Proficy Machine Edition", "PAC Machine Edition"),
    ]:
        result = cat.compare_identity(vendor, left, vendor, right)
        assert result["matched"] and result["needs_review"]
    # Candidate PDM does not travel through the verified pair to a third label.
    assert not cat.compare_identity("Siemens", "PDM", "Siemens", "Process Device Manager")["matched"]
    assert not cat.compare_identity("Emerson", "Proficy Machine Edition", "Emerson", "PME")["matched"]


@pytest.mark.parametrize("vendor,left,source_vendor,right", [
    ("SEL", "RTAC", "SEL", "acSELerator RTAC"),
    ("Eaton", "IPM", "Eaton", "IPM VA"),
    ("Eaton", "IPM", "Eaton", "IPM Infrastructure"),
    ("Eaton", "VPM", "Eaton", "Visual Power Manager Professional"),
    ("Triangle MicroWorks", "DTM", "Delta Electronics", "DTM Soft"),
    ("NI", "TestStand", "Emerson", "TestStand"),
])
def test_new_component_platform_and_manufacturer_boundaries(vendor, left, source_vendor, right):
    assert not get_catalog().compare_identity(vendor, left, source_vendor, right)["matched"]


def test_new_successor_and_parent_relationships_are_review_only():
    for vendor, left, source_vendor, right in [
        ("Moxa", "MXview", "Moxa", "MXview One"),
        ("Horner APG", "Cscape", "Horner Automation", "Cscape"),
        ("AVEVA", "PI Server", "OSIsoft", "PI Server"),
    ]:
        result = get_catalog().compare_identity(vendor, left, source_vendor, right)
        assert result["matched"] and result["needs_review"]
