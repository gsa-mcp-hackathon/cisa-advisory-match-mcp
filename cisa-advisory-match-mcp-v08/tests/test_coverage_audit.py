"""Source-label coverage cannot silently flatten context or claim accuracy."""
from copy import deepcopy
import hashlib
import json

import pytest

from advisory_matcher.aliases import AliasCatalog
from scripts.audit_alias_coverage import audit, extract_document, mapping_status


def branch(category, name, children=None, product_id=None):
    result = {"category": category, "name": name}
    if children is not None:
        result["branches"] = children
    if product_id:
        result["product"] = {"product_id": product_id, "name": "source full name"}
    return result


def document(branches, advisory_id="ICSA-26-100-01"):
    return {"document": {"tracking": {"id": advisory_id}}, "product_tree": {"branches": branches}}


def normal_document(advisory_id="ICSA-26-100-01"):
    return document([branch("vendor", "Vendor", [branch("product_name", "Model", [branch("product_version", "1.0", product_id="P1")])])], advisory_id)


def test_extract_keeps_source_and_case_whitespace_equivalent_lineage():
    doc = document([branch("vendor", "Vendor", [branch("vendor", " VENDOR ", [branch("product_name", "Model", [branch("product_name", "MODEL", [branch("product_version", "1.0", product_id="P1")])])])])])
    saved = deepcopy(doc)
    result = extract_document(doc)
    assert result["included"] and len(result["pairs"]) == 1
    assert result["issues"] == []
    assert doc == saved


@pytest.mark.parametrize("branches", [
    [branch("vendor", "Vendor", [branch("vendor", "Other Vendor", [branch("product_name", "Model", product_id="P1")])])],
    [branch("vendor", "Vendor", [branch("product_name", "Suite", [branch("product_name", "Component", product_id="P1")])])],
    [branch("product_name", "Model", product_id="P1")],
    [branch("vendor", "Vendor", [branch("product_version", "1.0", product_id="P1")])],
])
def test_ambiguous_or_missing_lineage_is_not_in_denominator(branches):
    result = extract_document(document(branches))
    assert result["pairs"] == []
    assert result["issues"][0]["reason"] == "ambiguous_or_missing_vendor_product_lineage"


def test_family_context_retained_and_relationships_not_flattened():
    doc = document([branch("vendor", "Vendor", [branch("product_family", "Family", [branch("product_name", "Model", product_id="P1")])])])
    doc["product_tree"]["relationships"] = [{"product_reference": "P1", "relates_to_product_reference": "P2"}]
    doc["product_tree"]["full_product_names"] = [{"product_id": "P3", "name": "Vendor Model"}]
    result = extract_document(doc)
    assert len(result["pairs"]) == 1
    assert result["pairs"][0]["extra_context"] == [{"category": "product_family", "name": "Family"}]
    assert result["relationship_count"] == result["flat_product_count"] == 1


def test_feed_metadata_is_excluded():
    assert extract_document({"feed": {"title": "OT"}})["included"] is False


def test_unusual_advisory_identifier_is_still_included():
    parsed = extract_document(normal_document("ICSA-16-231-01-0"))
    assert parsed["included"]
    assert parsed["advisory_id"] == "ICSA-16-231-01-0"
    assert len(parsed["pairs"]) == 1


def record(identifier, names, mode="equivalent", vendors=None):
    value = {"id": identifier, "names": names, "mode": mode,
             "source_urls": ["https://example.com/public-source"],
             "source_title": "Test fixture only", "rationale": "Test policy"}
    if vendors:
        value["vendors"] = vendors
    return value


def catalog_data():
    return {"schema_version": 1, "version": "test",
            "vendors": [record("v", ["Vendor", "Vendor Inc."]), record("v-parent", ["Vendor", "Parent"], "candidate")],
            "products": [record("p", ["Model", "Model Long Name"], vendors=["Vendor"]),
                         record("p-old", ["Old Model", "Model"], "candidate", ["Vendor"])]}


def test_catalog_status_uses_direct_scoped_runtime_policy():
    data = catalog_data()
    catalog = AliasCatalog(data)
    status = mapping_status(catalog, data, "Vendor Inc.", "Model")
    assert status["status"] == "equivalent_available"
    assert status["equivalent_alternates"] == ["Model Long Name"]
    assert status["review_alternates"] == ["Old Model"]
    assert mapping_status(catalog, data, "Wrong Vendor", "Model")["status"] == "no_documented_alias"
    assert mapping_status(catalog, data, "Parent", "Model")["status"] == "no_documented_alias"
    assert mapping_status(catalog, data, "Vendor", "Old Model")["status"] == "review_only"


def write_fixture_snapshot(tmp_path):
    corpus = tmp_path / "corpus"
    corpus.mkdir()
    docs = {"2026/icsa-26-100-01.json": normal_document(),
            "2026/icsma-26-100-02.json": normal_document("ICSMA-26-100-02"),
            "feed.json": {"feed": {}}}
    files = []
    for relative, doc in docs.items():
        raw = json.dumps(doc).encode()
        path = corpus / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
        blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        files.append({"path": "csaf_files/OT/white/" + relative, "sha": blob, "size": len(raw)})
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"commit": "a" * 40, "tree_truncated": False, "files": files}))
    catalog = tmp_path / "catalog.json"
    catalog.write_text(json.dumps(catalog_data()))
    return corpus, manifest, catalog


def test_full_audit_distinguishes_scope_and_reproduces_from_saved_manifest(tmp_path):
    corpus, manifest, catalog = write_fixture_snapshot(tmp_path)
    out = tmp_path / "out"
    result = audit(corpus, catalog, catalog, manifest, out)
    assert result["manifest_json_files"] == 3
    assert result["source_counts"]["advisory_files"] == 2
    assert result["source_counts"]["advisories_with_current_runtime_id_format"] == 1
    assert result["source_counts"]["advisories_outside_current_runtime_id_format"] == 1
    assert result["unique_scoped_product_labels"] == 1
    assert result["alias_presence"]["current"]["scoped_products"] == {"equivalent_available": 1}
    repeat = audit(corpus, catalog, catalog, out / "source-manifest.json", tmp_path / "again")
    assert repeat == result


def test_changed_or_missing_source_bytes_fail_audit(tmp_path):
    corpus, manifest, catalog = write_fixture_snapshot(tmp_path)
    path = corpus / "2026/icsa-26-100-01.json"
    path.write_text(path.read_text() + " ")
    with pytest.raises(ValueError, match="pinned Git blob"):
        audit(corpus, catalog, catalog, manifest, tmp_path / "out")
    path.unlink()
    with pytest.raises(ValueError, match="does not match manifest"):
        audit(corpus, catalog, catalog, manifest, tmp_path / "out")
