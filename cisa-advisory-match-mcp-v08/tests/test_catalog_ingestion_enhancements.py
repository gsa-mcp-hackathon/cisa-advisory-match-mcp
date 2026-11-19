import json
import tempfile
import unittest
from pathlib import Path

from advisory_matcher.catalog_index import build_catalog, search_catalog


def document():
    return {"document": {"title": "Example", "tracking": {"id": "sample"}},
            "product_tree": {"branches": [{"category": "vendor", "name": "Acme", "branches": [
                {"category": "product_name", "name": "Widget", "product": {"product_id": "one", "name": "Acme Widget"}}]}]}}


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "source"
        self.output = Path(self.tmp.name) / "catalog.sqlite3"
        for scope in ("IT", "OT"):
            base = self.root / "csaf_files" / scope / "white"
            (base / "2026").mkdir(parents=True)
            (base / "index.txt").write_text("2026/sample.json\n")
            (base / "2026" / "sample.json").write_text(json.dumps(document()))

    def tearDown(self):
        self.tmp.cleanup()

    def path(self, scope="IT"):
        return self.root / "csaf_files" / scope / "white" / "2026" / "sample.json"

    def test_long_source_name_preserved_with_bounded_limit(self):
        doc = document()
        doc["product_tree"]["branches"][0]["branches"][0]["product"]["name"] = "Widget " + "x" * 757
        self.path().write_text(json.dumps(doc))
        manifest = build_catalog(self.root, self.output)
        self.assertEqual(manifest["sources"]["IT"]["indexed"], 1)
        rows = search_catalog(self.output, "Widget", scope="IT")["candidates"]
        self.assertEqual(len(rows[0]["product_name"]), 764)

    def test_flat_names_are_searchable_without_invented_vendor(self):
        doc = document()
        doc["product_tree"]["full_product_names"] = [{"product_id": "flat", "name": "Other Controller"}]
        self.path().write_text(json.dumps(doc))
        manifest = build_catalog(self.root, self.output)
        self.assertEqual(manifest["sources"]["IT"]["complex_documents"], 1)
        result = search_catalog(self.output, "Other Controller", scope="IT")
        self.assertEqual(result["candidate_count"], 1)
        self.assertEqual(result["candidates"][0]["manufacturer"], "")
        self.assertEqual(search_catalog(self.output, "Other Controller", "Acme", scope="IT")["candidate_count"], 0)

    def test_duplicate_flat_product_id_rejected(self):
        doc = document()
        doc["product_tree"]["full_product_names"] = [{"product_id": "one", "name": "Conflicting"}]
        self.path().write_text(json.dumps(doc))
        self.assertEqual(build_catalog(self.root, self.output)["sources"]["IT"]["failed"], 1)

    def test_failures_record_only_safe_reason_categories(self):
        doc = document()
        doc["document"]["tracking"]["id"] = "different"
        self.path().write_text(json.dumps(doc))
        self.path("OT").write_text('{"secret":"not for output","secret":1}')
        manifest = build_catalog(self.root, self.output)
        self.assertEqual(manifest["sources"]["IT"]["failure_reasons"], {"id_filename_mismatch": 1})
        self.assertEqual(manifest["sources"]["OT"]["failure_reasons"], {"duplicate_json_member": 1})
        self.assertNotIn("not for output", json.dumps(manifest))

    def test_commit_pinned_source_link_and_unverified_origin(self):
        rev = "a" * 40
        manifest = build_catalog(self.root, self.output, revision=rev)
        result = search_catalog(self.output, "Widget", scope="IT")
        self.assertIn("/" + rev + "/", result["candidates"][0]["source_url"])
        self.assertEqual(manifest["origin"], "operator_provided_unverified")

    def test_unverified_source_link_uses_develop(self):
        build_catalog(self.root, self.output)
        result = search_catalog(self.output, "Widget", scope="IT")
        self.assertIn("/develop/", result["candidates"][0]["source_url"])

    def test_symlinked_ancestor_rejected(self):
        folder = self.root / "csaf_files" / "IT" / "white" / "2026"
        outside = Path(self.tmp.name) / "outside"
        folder.rename(outside)
        folder.symlink_to(outside, target_is_directory=True)
        manifest = build_catalog(self.root, self.output)
        self.assertEqual(manifest["sources"]["IT"]["failed"], 1)
        self.assertEqual(manifest["sources"]["IT"]["failure_reasons"], {"unsafe_missing_or_oversized_document": 1})

    def test_long_aggregate_branch_path_rejected(self):
        doc = document()
        node = doc["product_tree"]["branches"][0]
        node["name"] = "v" * 400
        node["branches"][0]["category"] = "vendor"
        node["branches"][0]["name"] = "w" * 200
        self.path().write_text(json.dumps(doc))
        self.assertEqual(build_catalog(self.root, self.output)["sources"]["IT"]["failed"], 1)


if __name__ == "__main__":
    unittest.main()
