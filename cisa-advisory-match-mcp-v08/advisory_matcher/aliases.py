"""Local, sourced name mappings with explicit review and discovery boundaries.

A mapping is one documented group, not a graph edge to transitively close.
Candidate relationships (brands, parents, short names) never establish identity.
The catalog is operator-maintained package data; advisory text cannot add aliases.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_MAX_RECORDS = 2000
_MAX_NAMES = 40
_MAX_NAME_LENGTH = 240
_MAX_CATALOG_BYTES = 2 * 1024 * 1024
_CATALOG_PATH = Path(__file__).parent / "data" / "aliases.json"


def normalize(value: Any) -> str:
    """Normalize case and whitespace, never punctuation or partial words."""
    return " ".join(value.split()).casefold() if isinstance(value, str) else ""


def _strings(value: Any, *, field: str, minimum: int = 1, maximum: int = _MAX_NAMES,
             max_length: int = _MAX_NAME_LENGTH) -> list[str]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise ValueError(f"Alias catalog {field} has an invalid list length")
    if any(not isinstance(item, str) or not item.strip() or len(item) > max_length
           or any(ord(char) < 32 or ord(char) == 127 for char in item) for item in value):
        raise ValueError(f"Alias catalog {field} contains invalid text")
    if len({normalize(item) for item in value}) != len(value):
        raise ValueError(f"Alias catalog {field} contains duplicate normalized values")
    return list(value)


def _result(matched: bool = False, *, review: bool = False, kind: str = "none",
            mappings: list[dict] | None = None, reason: str = "") -> dict:
    return {"matched": matched, "needs_review": review, "match_type": kind,
            "mappings": mappings or [], "reason": reason}


class AliasCatalog:
    """Validate a catalog and compare identities without network or fuzzy search."""

    def __init__(self, data: dict, *, source_bytes: bytes | None = None):
        if (not isinstance(data, dict) or type(data.get("schema_version")) not in {str, int}
                or data.get("schema_version") not in {1, "1"}):
            raise ValueError("Unsupported alias catalog schema_version")
        version = data.get("version")
        if not isinstance(version, str) or not version or len(version) > 80:
            raise ValueError("Alias catalog version is required")
        # A private copy prevents a caller changing a checked catalog in place.
        self._data = deepcopy(data)
        encoded = json.dumps(self._data, ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(encoded) > _MAX_CATALOG_BYTES or source_bytes is not None and len(source_bytes) > _MAX_CATALOG_BYTES:
            raise ValueError("Alias catalog exceeds the byte budget")
        self._sha256 = hashlib.sha256(source_bytes if source_bytes is not None else encoded).hexdigest()
        self._records: dict[str, list[dict]] = {}
        self._index: dict[str, dict[str, list[dict]]] = {}
        seen_ids: set[str] = set()
        for category in ("vendors", "products"):
            records = self._data.get(category)
            if not isinstance(records, list) or len(records) > _MAX_RECORDS:
                raise ValueError(f"Alias catalog {category} must be a bounded list")
            index: dict[str, list[dict]] = {}
            for record in records:
                if not isinstance(record, dict):
                    raise ValueError("Alias catalog records must be objects")
                identifier = record.get("id")
                if not isinstance(identifier, str) or not identifier or len(identifier) > 100 or identifier in seen_ids:
                    raise ValueError("Alias catalog ids must be nonempty and unique")
                seen_ids.add(identifier)
                _strings(record.get("names"), field="names", minimum=2)
                if record.get("mode") not in {"equivalent", "candidate"}:
                    raise ValueError("Alias catalog mode must be equivalent or candidate")
                urls = _strings(record.get("source_urls"), field="source_urls", maximum=12, max_length=1500)
                for url in urls:
                    parsed = urlsplit(url)
                    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
                        raise ValueError("Alias sources must be credential-free HTTPS URLs")
                for field, limit in (("rationale", 2500), ("source_title", 500)):
                    value = record.get(field)
                    if not isinstance(value, str) or not value.strip() or len(value) > limit:
                        raise ValueError(f"Alias catalog {field} is required and bounded")
                if category == "products":
                    _strings(record.get("vendors"), field="vendors")
                for name in record["names"]:
                    index.setdefault(normalize(name), []).append(record)
            self._records[category] = records
            self._index[category] = index

    def metadata(self) -> dict:
        return {"schema_version": self._data["schema_version"], "version": self._data["version"],
                "sha256": self._sha256, "vendor_groups": len(self._records["vendors"]),
                "product_groups": len(self._records["products"])}

    @staticmethod
    def _summary(record: dict, category: str) -> dict:
        fields = ("id", "mode", "names", "source_urls", "rationale", "source_title", "vendors")
        return {"kind": "manufacturer" if category == "vendors" else "product",
                **{key: deepcopy(record[key]) for key in fields if key in record}}

    def _scope_applies(self, record: dict, left_vendor: str, right_vendor: str) -> bool:
        # Each actual manufacturer must be exact or directly equivalent to a
        # documented scope label. Candidate ownership links cannot expand scope.
        for actual in (left_vendor, right_vendor):
            if not any((check := self._compare_names(actual, scope, "vendors"))["matched"]
                       and not check["needs_review"] for scope in record["vendors"]):
                return False
        return True

    def _compare_names(self, left: Any, right: Any, category: str,
                       *, vendors: tuple[str, str] | None = None) -> dict:
        a, b = normalize(left), normalize(right)
        if not a or not b:
            return _result(reason="A required identity label is missing.")
        if a == b:
            return _result(True, kind="exact")
        indexed = self._index[category]
        possible = indexed.get(a, [])
        direct = [record for record in possible if b in {normalize(n) for n in record["names"]}
                  and (category == "vendors" or vendors is not None and self._scope_applies(record, *vendors))]
        if not direct:
            return _result(reason="No documented direct mapping applies to these labels and manufacturer scope.")
        # Conflicting direct policies or overlapping equivalent groups sharing an alias
        # are kept as review candidates rather than selecting the first record.
        # Equivalent groups for one identity should be consolidated in the catalog;
        # a partially overlapping group is ambiguous regardless of label ordering.
        conflict = len({record["mode"] for record in direct}) > 1
        related = []
        for name in (a, b):
            for record in indexed.get(name, []):
                if record["mode"] == "equivalent" and (category == "vendors" or vendors is not None and self._scope_applies(record, *vendors)):
                    related.append(record)
        for first in related:
            for second in related:
                first_names = {normalize(n) for n in first["names"]}
                second_names = {normalize(n) for n in second["names"]}
                if (first_names & second_names and not first_names <= second_names
                        and not second_names <= first_names):
                    conflict = True
        records = direct + ([r for r in related if r not in direct] if conflict else [])
        review = conflict or any(r["mode"] == "candidate" for r in direct)
        return _result(True, review=review, kind="candidate_alias" if review else "verified_alias",
                       mappings=[self._summary(r, category) for r in records],
                       reason=("Conflicting or ambiguous alias definitions require identity review." if conflict
                               else "The documented relationship requires product identity confirmation." if review
                               else "A documented direct equivalent-name mapping applies."))

    def compare_identity(self, input_vendor: Any, input_product: Any,
                         source_vendor: Any, source_product: Any) -> dict:
        vendor = self._compare_names(input_vendor, source_vendor, "vendors")
        if not vendor["matched"]:
            return vendor
        # Candidate vendor identity permits an exact product label to surface
        # for review, but cannot be combined with another alias inference.
        if vendor["needs_review"]:
            if normalize(input_product) and normalize(input_product) == normalize(source_product):
                return _result(True, review=True, kind="candidate_alias", mappings=vendor["mappings"],
                               reason=vendor["reason"])
            return _result(reason="A candidate manufacturer relationship cannot establish a product alias.")
        product = self._compare_names(input_product, source_product, "products",
                                      vendors=(input_vendor, source_vendor))
        if not product["matched"]:
            return product
        mappings = vendor["mappings"] + product["mappings"]
        review = product["needs_review"]
        return _result(True, review=review,
                       kind="candidate_alias" if review else "verified_alias" if mappings else "exact",
                       mappings=mappings, reason=product["reason"] or vendor["reason"])

    def input_hints(self, vendor: str, product: str) -> dict:
        """Return sourced, scoped suggestions without establishing a match."""
        records = [record for record in self._index["products"].get(normalize(product), [])
                   if self._scope_applies(record, vendor, vendor)]
        return {"mappings": [self._summary(record, "products") for record in records[:12]],
                "omitted_count": max(0, len(records) - 12)}

    def vendor_search_terms(self, vendor: str, max_terms: int = 3) -> dict:
        if not isinstance(vendor, str) or not normalize(vendor) or len(vendor) > _MAX_NAME_LENGTH:
            raise ValueError("A bounded manufacturer name is required")
        if type(max_terms) is not int or not 1 <= max_terms <= 12:
            raise ValueError("max_terms must be an integer from 1 to 12")
        # Original input remains first. Equivalent spellings precede candidate
        # relationships, with stable catalog ordering and no recursive expansion.
        records = sorted(self._index["vendors"].get(normalize(vendor), []),
                         key=lambda record: record["mode"] != "equivalent")
        terms = [" ".join(vendor.split())]
        seen = {normalize(vendor)}
        for record in records:
            for label in record["names"]:
                if normalize(label) not in seen:
                    seen.add(normalize(label))
                    terms.append(label)
        return {"terms": terms[:max_terms], "omitted_terms": terms[max_terms:],
                "mappings": [self._summary(r, "vendors") for r in records]}


@lru_cache(maxsize=1)
def get_catalog() -> AliasCatalog:
    """Read operator-maintained package data once. Missing/invalid data fails closed."""
    raw = _CATALOG_PATH.read_bytes()
    if len(raw) > _MAX_CATALOG_BYTES:
        raise ValueError("Alias catalog exceeds the byte budget")
    return AliasCatalog(json.loads(raw), source_bytes=raw)


def compare_identity(input_vendor: Any, input_product: Any,
                     source_vendor: Any, source_product: Any) -> dict:
    return get_catalog().compare_identity(input_vendor, input_product, source_vendor, source_product)


def vendor_search_terms(vendor: str, max_terms: int = 3) -> dict:
    return get_catalog().vendor_search_terms(vendor, max_terms)


def catalog_metadata() -> dict:
    return get_catalog().metadata()


def input_hints(vendor: str, product: str) -> dict:
    return get_catalog().input_hints(vendor, product)


def metadata() -> dict:
    """Alias for catalog_metadata for report integration."""
    return catalog_metadata()
