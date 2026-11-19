"""Identity tests for sourced aliases, avoiding model/family/ownership conflation."""
from copy import deepcopy
import hashlib
import unittest

from advisory_matcher.aliases import AliasCatalog, normalize


def record(identifier, names, *, mode="equivalent", vendors=None):
    value = {"id": identifier, "names": names, "mode": mode,
             "source_urls": ["https://vendor.example.test/identity"],
             "rationale": "Synthetic documented-name fixture for behavior tests.",
             "source_title": "Synthetic fixture"}
    if vendors is not None:
        value["vendors"] = vendors
    return value


def catalog_data():
    return {"schema_version": 1, "version": "test-1",
            "vendors": [record("v-acme", ["Acme", "Acme Incorporated", "Acme Inc."]),
                        record("v-brand", ["Acme", "Legacy Controls"], mode="candidate"),
                        record("v-child", ["Legacy Controls", "Another Owner"], mode="candidate")],
            "products": [record("p-42", ["Controller 42 Firmware", "C42 Firmware"], vendors=["Acme"]),
                         record("p-short", ["Controller 42 Firmware", "C42"], mode="candidate", vendors=["Acme"])]}


class AliasTests(unittest.TestCase):
    def setUp(self):
        self.catalog = AliasCatalog(catalog_data())

    def compare(self, vendor="Acme", product="Controller 42 Firmware", *,
                source_vendor="Acme", source_product="Controller 42 Firmware"):
        return self.catalog.compare_identity(vendor, product, source_vendor, source_product)

    def test_normalization_preserves_component_and_model_punctuation(self):
        self.assertEqual(normalize("  ACME   Controller "), "acme controller")
        self.assertNotEqual(normalize("C-42"), normalize("C42"))
        self.assertEqual(normalize(None), "")

    def test_exact_priority_ignores_ownership_aliases(self):
        result = self.compare()
        self.assertEqual(result, {"matched": True, "needs_review": False, "match_type": "exact", "mappings": [], "reason": ""})

    def test_missing_identity_is_not_an_exact_match(self):
        for vendor, product in [("", ""), (None, None), ("Acme", ""), ("", "Firmware")]:
            with self.subTest(vendor=vendor, product=product):
                self.assertFalse(self.catalog.compare_identity(vendor, product, vendor, product)["matched"])

    def test_verified_vendor_and_product_aliases_combine(self):
        result = self.compare("Acme Inc.", "C42 Firmware")
        self.assertTrue(result["matched"])
        self.assertFalse(result["needs_review"])
        self.assertEqual(result["match_type"], "verified_alias")
        self.assertEqual([m["id"] for m in result["mappings"]], ["v-acme", "p-42"])
        self.assertTrue(all(m["source_urls"] for m in result["mappings"]))

    def test_verified_mappings_work_in_both_directions(self):
        result = self.compare(source_vendor="Acme Incorporated", source_product="C42 Firmware")
        self.assertEqual(result["match_type"], "verified_alias")

    def test_candidate_product_is_never_confirmed_identity(self):
        result = self.compare(product="C42")
        self.assertTrue(result["matched"])
        self.assertTrue(result["needs_review"])
        self.assertEqual(result["match_type"], "candidate_alias")

    def test_candidate_vendor_and_exact_product_remain_review(self):
        result = self.compare("Legacy Controls")
        self.assertTrue(result["matched"])
        self.assertTrue(result["needs_review"])

    def test_candidate_vendor_cannot_unlock_product_alias(self):
        result = self.compare("Legacy Controls", "C42 Firmware")
        self.assertFalse(result["matched"])

    def test_candidate_vendor_chains_are_not_traversed(self):
        self.assertFalse(self.compare("Another Owner")["matched"])
        self.assertNotIn("Another Owner", self.catalog.vendor_search_terms("Acme", 12)["terms"])

    def test_equivalence_is_not_transitively_expanded(self):
        data = catalog_data()
        data["vendors"].append(record("v-second", ["Acme Incorporated", "Acme Automation"]))
        cat = AliasCatalog(data)
        self.assertFalse(cat.compare_identity("Acme Automation", "C42", "Acme", "C42")["matched"])

    def test_unlisted_spelling_is_not_fuzzy_matched(self):
        for vendor, product in [("Acme Corp", "Controller 42 Firmware"), ("Acme", "Controller-42 Firmware"),
                                ("Acme", "Controller 420 Firmware"), ("Acme", "PLC"), ("Acme", "Controller 42")]:
            with self.subTest(vendor=vendor, product=product):
                self.assertFalse(self.compare(vendor, product)["matched"])

    def test_product_mapping_cannot_cross_manufacturer(self):
        result = self.compare("Different", "C42 Firmware", source_vendor="Different")
        self.assertFalse(result["matched"])

    def test_product_scope_can_use_verified_vendor_spelling(self):
        result = self.compare("Acme Incorporated", "C42 Firmware", source_vendor="Acme Inc.")
        self.assertTrue(result["matched"])
        self.assertFalse(result["needs_review"])

    def test_conflicting_direct_policy_requires_review(self):
        data = catalog_data()
        data["products"].append(record("p-conflict", ["Controller 42 Firmware", "C42 Firmware"], mode="candidate", vendors=["Acme"]))
        result = AliasCatalog(data).compare_identity("Acme", "C42 Firmware", "Acme", "Controller 42 Firmware")
        self.assertTrue(result["needs_review"])
        self.assertIn("Conflicting", result["reason"])

    def test_alias_collision_with_two_canonical_vendors_requires_review(self):
        data = catalog_data()
        data["vendors"].append(record("v-collision", ["Unrelated Corporation", "Acme Inc."]))
        result = AliasCatalog(data).compare_identity("Acme Inc.", "Controller 42 Firmware", "Acme", "Controller 42 Firmware")
        self.assertTrue(result["needs_review"])
        self.assertEqual({m["id"] for m in result["mappings"]}, {"v-acme", "v-collision"})

    def test_ambiguous_vendor_group_order_does_not_change_review(self):
        for first in [["AB", "Company A"], ["Company A", "AB"]]:
            for second in [["AB", "Company B"], ["Company B", "AB"]]:
                data = {"schema_version": 1, "version": "test", "vendors": [
                    record("a", first), record("b", second)], "products": []}
                with self.subTest(first=first, second=second):
                    result = AliasCatalog(data).compare_identity("Company A", "P", "AB", "P")
                    self.assertTrue(result["matched"])
                    self.assertTrue(result["needs_review"])

    def test_nested_equivalent_groups_with_no_competing_labels_are_compatible(self):
        data = catalog_data()
        data["vendors"].append(record("v-subset", ["Acme Inc.", "Acme"]))
        result = AliasCatalog(data).compare_identity("Acme Inc.", "P", "Acme", "P")
        self.assertFalse(result["needs_review"])

    def test_exact_match_still_wins_over_catalog_conflict(self):
        data = catalog_data()
        data["vendors"].append(record("v-collision", ["Unrelated Corporation", "Acme Inc."]))
        result = AliasCatalog(data).compare_identity("Acme Inc.", "P1", "Acme Inc.", "P1")
        self.assertEqual(result["match_type"], "exact")

    def test_search_terms_report_omitted_names(self):
        result = self.catalog.vendor_search_terms("  ACME ", 2)
        self.assertEqual(result["terms"], ["ACME", "Acme Incorporated"])
        self.assertEqual(result["omitted_terms"], ["Acme Inc.", "Legacy Controls"])
        self.assertEqual([m["id"] for m in result["mappings"]], ["v-acme", "v-brand"])

    def test_unknown_vendor_search_retains_original_only(self):
        result = self.catalog.vendor_search_terms("New Vendor")
        self.assertEqual(result, {"terms": ["New Vendor"], "omitted_terms": [], "mappings": []})

    def test_search_budget_validation(self):
        for count in [0, 13, True, 1.5, "3"]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                self.catalog.vendor_search_terms("Acme", count)

    def test_metadata_hash_uses_actual_source_bytes_when_available(self):
        raw = b"the exact serialized package catalog"
        metadata = AliasCatalog(catalog_data(), source_bytes=raw).metadata()
        self.assertEqual(metadata["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(metadata["vendor_groups"], 3)
        self.assertEqual(metadata["product_groups"], 2)

    def test_mutating_input_or_outputs_cannot_change_catalog(self):
        data = catalog_data()
        cat = AliasCatalog(data)
        data["vendors"][0]["names"].append("Attacker")
        result = cat.compare_identity("Acme Inc.", "P1", "Acme", "P1")
        result["mappings"][0]["names"].append("Attacker")
        result["mappings"][0]["source_urls"].clear()
        self.assertFalse(cat.compare_identity("Attacker", "P1", "Acme", "P1")["matched"])
        self.assertTrue(cat.compare_identity("Acme Inc.", "P1", "Acme", "P1")["mappings"][0]["source_urls"])

    def test_hints_are_scoped_and_do_not_establish_identity(self):
        result = self.catalog.input_hints("Acme Inc.", "C42")
        self.assertEqual([r["id"] for r in result["mappings"]], ["p-short"])
        self.assertEqual(result["mappings"][0]["mode"], "candidate")
        self.assertEqual(self.catalog.input_hints("Legacy Controls", "C42")["mappings"], [])
        self.assertEqual(self.catalog.input_hints("Other Vendor", "C42")["mappings"], [])

    def test_hints_are_bounded(self):
        data = catalog_data()
        data["products"] = [record(f"p-{i}", [f"P{i}", "Generic short label"], mode="candidate", vendors=["Acme"]) for i in range(15)]
        result = AliasCatalog(data).input_hints("Acme", "Generic short label")
        self.assertEqual(len(result["mappings"]), 12)
        self.assertEqual(result["omitted_count"], 3)

    def test_same_acronym_resolves_only_in_its_manufacturer_scope(self):
        data = {"schema_version": 1, "version": "test", "vendors": [], "products": [
            record("schneider-pme", ["Power Monitoring Expert", "PME"], vendors=["Schneider Electric"]),
            record("emerson-pme", ["PAC Machine Edition", "PME"], vendors=["Emerson"])]}
        cat = AliasCatalog(data)
        self.assertEqual(cat.compare_identity("Schneider Electric", "PME", "Schneider Electric", "Power Monitoring Expert")["match_type"], "verified_alias")
        self.assertEqual(cat.compare_identity("Emerson", "PME", "Emerson", "PAC Machine Edition")["match_type"], "verified_alias")
        self.assertFalse(cat.compare_identity("Schneider Electric", "PME", "Schneider Electric", "PAC Machine Edition")["matched"])
        self.assertFalse(cat.compare_identity("Emerson", "PME", "Emerson", "Power Monitoring Expert")["matched"])

    def test_schema_boolean_is_not_a_version_number(self):
        data = catalog_data()
        data["schema_version"] = True
        with self.assertRaises(ValueError):
            AliasCatalog(data)

    def test_catalog_rejects_duplicate_identifiers(self):
        data = catalog_data()
        data["products"][0]["id"] = "v-acme"
        with self.assertRaises(ValueError):
            AliasCatalog(data)

    def test_catalog_rejects_invalid_modes_and_missing_provenance(self):
        for field, value in [("mode", "fuzzy"), ("source_urls", []), ("rationale", ""), ("source_title", "")]:
            data = catalog_data()
            data["vendors"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                AliasCatalog(data)

    def test_catalog_rejects_unsafe_source_urls(self):
        for url in ["http://example.test", "https://user:secret@example.test/a", "file:///tmp/a", "https:///missing-host"]:
            data = catalog_data()
            data["vendors"][0]["source_urls"] = [url]
            with self.subTest(url=url), self.assertRaises(ValueError):
                AliasCatalog(data)

    def test_catalog_rejects_unscoped_product_aliases(self):
        data = catalog_data()
        del data["products"][0]["vendors"]
        with self.assertRaises(ValueError):
            AliasCatalog(data)

    def test_catalog_rejects_duplicate_normalized_and_unbounded_names(self):
        for names in [["Acme", " ACME "], ["Acme"], ["Acme", "B" * 241], ["Acme", "A\nB"]]:
            data = catalog_data()
            data["vendors"][0]["names"] = names
            with self.subTest(names=names), self.assertRaises(ValueError):
                AliasCatalog(data)


if __name__ == "__main__":
    unittest.main()
