"""Missing relationship-aware identity parsing cannot be a clean no-match."""
import asyncio
import copy

import pytest

from advisory_matcher.matching import match_device
from advisory_matcher.service import run_inventory
from fake_client import ADVISORY_ID, FakeClient


def doc():
    return {
        "product_tree": {
            "branches": [{"category": "vendor", "name": "Test Manufacturer", "branches": [
                {"category": "product_name", "name": "Branch Product", "branches": [
                    {"category": "product_version_range", "name": "<2", "product": {
                        "product_id": "P1", "name": "Branch Product below 2"}}
                ]},
                {"category": "product_name", "name": "Host Product", "branches": [
                    {"category": "product_version", "name": "1", "product": {
                        "product_id": "P2", "name": "Host Product 1"}}
                ]}
            ]}],
            "relationships": [{"category": "installed_on", "product_reference": "P1",
                "relates_to_product_reference": "P2", "full_product_name": {
                    "product_id": "P3", "name": "Installed product on host"}}],
        },
        "vulnerabilities": [{"cve": "CVE-2099-1234", "product_status": {"known_affected": ["P3"]}}],
    }


def item(product):
    return {"asset_id": "fictional-relationship-case", "manufacturer": "Test Manufacturer",
            "product": product, "version": "1"}


def test_unmatched_branch_name_with_relationships_requires_review():
    with pytest.raises(ValueError, match="Relationship-generated"):
        match_device(item("Installed product on host"), doc())


def test_matched_branch_with_no_relevant_status_and_unrelated_relationship_requires_review():
    source = doc()
    source["product_tree"]["relationships"][0]["product_reference"] = "P2"
    source["vulnerabilities"][0]["product_status"] = {"known_affected": ["P3"]}
    with pytest.raises(ValueError, match="Relationship-generated"):
        match_device(item("Branch Product"), source)


def test_related_product_id_still_returns_review_finding():
    findings = match_device(item("Branch Product"), doc())
    assert findings and findings[0]["assessment"] == "needs_review"


def test_unrelated_relationship_does_not_downgrade_positive_branch_finding():
    source = doc()
    source["product_tree"]["relationships"][0]["product_reference"] = "P2"
    source["vulnerabilities"][0]["product_status"] = {"known_affected": ["P1"]}
    findings = match_device(item("Branch Product"), source)
    assert findings and findings[0]["assessment"] == "affected_range_match"


def test_service_discloses_unsupported_relationship_instead_of_no_match():
    client = FakeClient()
    source = doc()
    source["document"] = copy.deepcopy(client.document["document"])
    client.document = source
    report = asyncio.run(run_inventory([item("Installed product on host")], client,
                                       advisory_ids=[ADVISORY_ID]))
    assert report["coverage"]["advisories_unsupported"] == [ADVISORY_ID]
    assert report["coverage"]["candidate_selection_complete"] is False
    assert report["results"][0]["outcome"] == "needs_review"
