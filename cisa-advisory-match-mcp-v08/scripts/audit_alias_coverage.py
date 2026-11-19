#!/usr/bin/env python3
"""Offline inventory of CISA source labels and the local alias catalog.

This measures documented alias presence, never supported-device coverage,
vulnerability recall, match correctness, or the existence of all possible aliases.
No aliases are inferred or written by this script. No network requests are made.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from advisory_matcher.aliases import AliasCatalog, normalize  # noqa: E402

SOURCE_PREFIX = "csaf_files/OT/white/"
ADVISORY_ID = re.compile(r"ICS(?:M)?A-\d{2}-\d{3}-\d{2}[a-z]?", re.I)
CORE_ADVISORY_ID = re.compile(r"ICSA-\d{2}-\d{3}-\d{2}")
IDENTITY_CONTEXT = {"vendor", "product_name", "product_version", "product_version_range"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_document(document: dict) -> dict:
    """Retain branch lineage; never guess missing vendors or flatten families.

    A measured pair requires a branch product definition with exactly one
    distinct normalized vendor and product_name in its ancestry. Additional
    family/component/version context is retained and counted, not discarded.
    Ambiguous or missing lineage is recorded outside the pair denominator.
    Relationship-generated and flat products are not interpreted.
    """
    tracking = document.get("document", {}).get("tracking", {})
    advisory_id = tracking.get("id", "")
    if not isinstance(advisory_id, str) or not advisory_id.strip():
        return {"included": False, "reason": "not_an_advisory_with_tracking_identity", "advisory_id": advisory_id}
    tree = document.get("product_tree", {})
    if not isinstance(tree, dict):
        tree = {}
    result = {"included": True, "advisory_id": advisory_id,
              "kind": advisory_id.upper().split("-")[0], "pairs": [],
              "vendor_labels": set(), "issues": [], "branch_product_count": 0,
              "relationship_count": len(tree.get("relationships", [])),
              "flat_product_count": len(tree.get("full_product_names", []))}
    branches = tree.get("branches", [])
    if not isinstance(branches, list) or not branches:
        result["issues"].append({"reason": "missing_or_invalid_branches", "path": []})
        return result
    pending = [(branch, []) for branch in reversed(branches)]
    while pending:
        node, ancestors = pending.pop()
        if not isinstance(node, dict) or not isinstance(node.get("category"), str) or not isinstance(node.get("name"), str):
            result["issues"].append({"reason": "invalid_branch", "path": ancestors})
            continue
        path = ancestors + [{"category": node["category"], "name": node["name"]}]
        if node["category"] == "vendor" and normalize(node["name"]):
            result["vendor_labels"].add(node["name"])
        if "product" in node:
            result["branch_product_count"] += 1
            product = node["product"]
            vendors = {normalize(x["name"]): x["name"] for x in path if x["category"] == "vendor" and normalize(x["name"])}
            names = {normalize(x["name"]): x["name"] for x in path if x["category"] == "product_name" and normalize(x["name"])}
            if not isinstance(product, dict) or not isinstance(product.get("product_id"), str) or not product["product_id"]:
                result["issues"].append({"reason": "missing_or_invalid_product_id", "path": path})
            elif len(vendors) != 1 or len(names) != 1:
                result["issues"].append({"reason": "ambiguous_or_missing_vendor_product_lineage",
                                         "product_id": product["product_id"], "path": path})
            else:
                context = [x for x in path if x["category"] not in IDENTITY_CONTEXT]
                result["pairs"].append({"vendor": next(iter(vendors.values())),
                                        "product": next(iter(names.values())),
                                        "product_id": product["product_id"], "extra_context": context})
        children = node.get("branches", [])
        if not isinstance(children, list):
            result["issues"].append({"reason": "invalid_children", "path": path})
        else:
            pending.extend((child, path) for child in reversed(children))
    result["vendor_labels"] = sorted(result["vendor_labels"], key=lambda x: (normalize(x), x))
    return result


def mapping_status(catalog: AliasCatalog, data: dict, vendor: str, product: str | None = None) -> dict:
    """Test actual direct policy behavior; candidate links remain separate."""
    if product is not None:
        hints = catalog.input_hints(vendor, product)
        if hints["omitted_count"]:
            raise ValueError("Coverage audit cannot count a product with omitted catalog hints")
        records = hints["mappings"]
    else:
        records = [r for r in data["vendors"] if normalize(vendor) in {normalize(n) for n in r["names"]}]
    equivalent, candidate, group_ids = set(), set(), set()
    for record in records:
        for alternate in record["names"]:
            original = product if product is not None else vendor
            if normalize(alternate) == normalize(original):
                continue
            if product is None:
                decision = catalog.compare_identity(vendor, "coverage exact placeholder", alternate, "coverage exact placeholder")
            else:
                decision = catalog.compare_identity(vendor, product, vendor, alternate)
            if decision["matched"]:
                group_ids.update(m["id"] for m in decision["mappings"])
                (candidate if decision["needs_review"] else equivalent).add(alternate)
    return {"status": "equivalent_available" if equivalent else "review_only" if candidate else "no_documented_alias",
            "equivalent_alternates": sorted(equivalent, key=lambda x: (normalize(x), x)),
            "review_alternates": sorted(candidate, key=lambda x: (normalize(x), x)),
            "mapping_ids": sorted(group_ids), "observed_catalog_group_ids": sorted(r["id"] for r in records)}


def load_catalog(path: Path) -> tuple[AliasCatalog, dict, str]:
    raw = path.read_bytes()
    data = json.loads(raw)
    return AliasCatalog(data, source_bytes=raw), data, digest(raw)


def write_json(path: Path, data: object) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def audit(corpus: Path, catalog_path: Path, baseline_path: Path | None, metadata_path: Path, output: Path) -> dict:
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    commit = metadata["commit"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("Source manifest requires a full lowercase Git commit SHA")
    if metadata.get("tree_truncated") is not False:
        raise ValueError("Source manifest must explicitly establish a nontruncated source tree")
    expected = {row["path"][len(SOURCE_PREFIX):]: row for row in metadata["files"]
                if row["path"].startswith(SOURCE_PREFIX) and row["path"].endswith(".json")}
    actual = {path.relative_to(corpus).as_posix(): path for path in corpus.rglob("*.json")}
    if expected.keys() != actual.keys():
        raise ValueError(f"Corpus does not match manifest: missing={len(expected.keys()-actual.keys())}, extra={len(actual.keys()-expected.keys())}")
    catalog, catalog_data, catalog_hash = load_catalog(catalog_path)
    if baseline_path:
        baseline, baseline_data, baseline_hash = load_catalog(baseline_path)
    else:
        baseline, baseline_data, baseline_hash = catalog, catalog_data, catalog_hash
    pairs, vendors = {}, {}
    files, issues, excluded, unusual_ids = [], [], [], []
    counts = Counter()
    kinds = Counter()
    years = Counter()
    advisory_ids = set()
    for relative, path in sorted(actual.items()):
        raw = path.read_bytes()
        blob_sha = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
        expected_size = expected[relative].get("size", expected[relative].get("size_bytes"))
        expected_sha = expected[relative].get("sha", expected[relative].get("git_blob_sha"))
        if len(raw) != expected_size or blob_sha != expected_sha:
            raise ValueError(f"Source bytes do not match pinned Git blob: {relative}")
        document = json.loads(raw)
        parsed = extract_document(document)
        source_path = SOURCE_PREFIX + relative
        url = f"https://raw.githubusercontent.com/cisagov/CSAF/{commit}/{source_path}"
        file_record = {"path": source_path, "sha256": digest(raw), "git_blob_sha": blob_sha,
                       "size_bytes": len(raw), "advisory_id": parsed["advisory_id"],
                       "included": parsed["included"]}
        files.append(file_record)
        if not parsed["included"]:
            excluded.append({"path": source_path, "reason": parsed["reason"]})
            continue
        if parsed["advisory_id"] in advisory_ids:
            counts["duplicate_advisory_ids"] += 1
        advisory_ids.add(parsed["advisory_id"])
        counts["advisory_files"] += 1
        core_id = bool(CORE_ADVISORY_ID.fullmatch(parsed["advisory_id"]))
        counts["advisories_with_current_runtime_id_format"] += core_id
        counts["advisories_outside_current_runtime_id_format"] += not core_id
        if not ADVISORY_ID.fullmatch(parsed["advisory_id"]):
            unusual_ids.append({"path": source_path, "advisory_id": parsed["advisory_id"]})
        counts["branch_product_definitions"] += parsed["branch_product_count"]
        counts["flat_product_definitions_not_interpreted"] += parsed["flat_product_count"]
        counts["relationship_definitions_not_interpreted"] += parsed["relationship_count"]
        counts["advisories_with_relationships"] += bool(parsed["relationship_count"])
        kinds[parsed["kind"]] += 1
        years[relative.split("/")[0]] += 1
        for label in parsed["vendor_labels"]:
            row = vendors.setdefault(normalize(label), {"labels": set(), "advisories": set(), "core_advisories": set()})
            row["labels"].add(label)
            row["advisories"].add(parsed["advisory_id"])
            if core_id:
                row["core_advisories"].add(parsed["advisory_id"])
        for pair in parsed["pairs"]:
            key = (normalize(pair["vendor"]), normalize(pair["product"]))
            row = pairs.setdefault(key, {"vendor_labels": set(), "product_labels": set(),
                                        "advisories": set(), "source_paths": set(), "extra_context_paths": set(),
                                        "branch_product_count": 0, "core_advisories": set()})
            row["vendor_labels"].add(pair["vendor"])
            row["product_labels"].add(pair["product"])
            row["advisories"].add(parsed["advisory_id"])
            if core_id:
                row["core_advisories"].add(parsed["advisory_id"])
            row["source_paths"].add(source_path)
            row["branch_product_count"] += 1
            if pair["extra_context"]:
                row["extra_context_paths"].add(source_path)
                counts["pair_definitions_with_additional_context"] += 1
        for issue in parsed["issues"]:
            issues.append({"advisory_id": parsed["advisory_id"], "source_path": source_path, **issue})
    product_rows = []
    touched = set()
    base_touched = set()
    for (vendor_key, product_key), value in sorted(pairs.items()):
        vendor_labels = sorted(value["vendor_labels"])
        product_labels = sorted(value["product_labels"])
        vendor, product = vendor_labels[0], product_labels[0]
        current = mapping_status(catalog, catalog_data, vendor, product)
        previous = mapping_status(baseline, baseline_data, vendor, product)
        touched.update(current["observed_catalog_group_ids"])
        base_touched.update(previous["observed_catalog_group_ids"])
        product_rows.append({"vendor": vendor, "product": product, "vendor_normalized": vendor_key,
                             "product_normalized": product_key, "observed_vendor_labels": vendor_labels,
                             "observed_product_labels": product_labels,
                             "advisory_count": len(value["advisories"]), "advisory_ids": sorted(value["advisories"]),
                             "current_runtime_id_advisory_count": len(value["core_advisories"]),
                             "fits_current_input_lengths": len(vendor.strip()) <= 120 and len(product.strip()) <= 160,
                             "source_paths": sorted(value["source_paths"]),
                             "branch_product_count": value["branch_product_count"],
                             "source_paths_with_additional_context": sorted(value["extra_context_paths"]),
                             "baseline": previous, "current": current})
    vendor_rows = []
    for vendor_key, value in sorted(vendors.items()):
        labels = sorted(value["labels"])
        current = mapping_status(catalog, catalog_data, labels[0])
        previous = mapping_status(baseline, baseline_data, labels[0])
        touched.update(current["observed_catalog_group_ids"])
        base_touched.update(previous["observed_catalog_group_ids"])
        vendor_rows.append({"vendor": labels[0], "vendor_normalized": vendor_key,
                            "observed_labels": labels, "advisory_count": len(value["advisories"]),
                            "current_runtime_id_advisory_count": len(value["core_advisories"]),
                            "fits_current_input_length": len(labels[0].strip()) <= 120,
                            "advisory_ids": sorted(value["advisories"]), "baseline": previous, "current": current})
    group_coverage = {}
    for stage, data, seen in (("baseline", baseline_data, base_touched), ("current", catalog_data, touched)):
        group_coverage[stage] = {category: {"groups_total": len(data[category]),
                                          "groups_with_observed_source_label": sum(r["id"] in seen for r in data[category]),
                                          "groups_without_observed_source_label": [r["id"] for r in data[category] if r["id"] not in seen]}
                                 for category in ("vendors", "products")}
    summary = {"schema_version": 1, "purpose": "Alias presence in observed source labels, not matching accuracy or supported-device coverage",
               "source_commit": commit, "source_retrieved_at": metadata.get("retrieved_at"),
               "source_commit_date": metadata.get("commit_date"),
               "scope": "All advisory JSON with a document tracking identity under csaf_files/OT/white at the pinned commit; feed metadata excluded. Unusual advisory ID shapes are included and listed separately.",
               "normalization": "Case folding and whitespace only; vendor/product pairs stay manufacturer-scoped",
               "denominator": "Distinct normalized vendor/product_name pairs at branch product definitions with exactly one vendor and one product_name in their ancestry. Additional context retained. Missing/ambiguous lineage, flat products and relationship-generated products are recorded separately.",
               "manifest_json_files": len(files), "excluded_non_advisory_files": excluded,
               "unusual_advisory_id_shapes": unusual_ids,
               "advisory_counts": dict(kinds), "advisory_year_counts": dict(sorted(years.items())),
               "unique_vendor_labels": len(vendor_rows), "raw_vendor_labels": sum(len(r["observed_labels"]) for r in vendor_rows),
               "unique_scoped_product_labels": len(product_rows),
               "raw_scoped_product_label_variants": sum(len(r["observed_product_labels"]) for r in product_rows),
               "source_counts": dict(sorted(counts.items())), "extraction_issue_count": len(issues),
               "extraction_issue_counts": dict(Counter(i["reason"] for i in issues)),
               "baseline_catalog": {"version": baseline_data["version"], "sha256": baseline_hash},
               "current_catalog": {"version": catalog_data["version"], "sha256": catalog_hash},
               "alias_presence": {stage: {"vendors": dict(Counter(r[stage]["status"] for r in vendor_rows)),
                                          "scoped_products": dict(Counter(r[stage]["status"] for r in product_rows))}
                                  for stage in ("baseline", "current")},
               "runtime_id_and_length_intersection": {
                   "definition": "Observed in at least one exact ICSA-NN-NNN-NN advisory and source name lengths fit manufacturer<=120/product<=160. This only checks ID/name shape, not runtime matchability, version support or advisory correctness.",
                   "unique_vendor_labels": sum(bool(r["current_runtime_id_advisory_count"]) and r["fits_current_input_length"] for r in vendor_rows),
                   "unique_scoped_product_labels": sum(bool(r["current_runtime_id_advisory_count"]) and r["fits_current_input_lengths"] for r in product_rows),
                   "scoped_product_labels_exceeding_input_lengths": sum(not r["fits_current_input_lengths"] for r in product_rows),
                   "alias_presence": {stage: {
                       "vendors": dict(Counter(r[stage]["status"] for r in vendor_rows if r["current_runtime_id_advisory_count"] and r["fits_current_input_length"])),
                       "scoped_products": dict(Counter(r[stage]["status"] for r in product_rows if r["current_runtime_id_advisory_count"] and r["fits_current_input_lengths"]))}
                       for stage in ("baseline", "current")}},
               "catalog_groups": group_coverage,
               "limitations": ["Unmapped names can still match exactly; this is not a missed-advisory rate.",
                               "Not every product has meaningful alternate names. No claim is made to enumerate all alternatives.",
                               "Labels in this source snapshot do not enumerate all ICS products or real-world inventory usage.",
                               "Catalog membership and pair consistency do not validate product versions, advisory applicability, precision or recall.",
                               "The runtime retains its own source parser, version grammar, discovery budget and relationship limitations."]}
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "coverage-summary.json", summary)
    write_json(output / "source-manifest.json", {k: v for k, v in metadata.items() if k != "files"} | {"files": files})
    write_json(output / "source-identities.json", {"source_commit": commit, "vendors": vendor_rows, "products": product_rows})
    write_json(output / "extraction-issues.json", {"source_commit": commit, "issues": issues})
    gaps = []
    for row in sorted(product_rows, key=lambda r: (-r["advisory_count"], normalize(r["vendor"]), normalize(r["product"]))):
        if row["current"]["status"] != "equivalent_available":
            gaps.append({"vendor": row["vendor"], "product": row["product"], "advisory_count": row["advisory_count"],
                         "alias_status": row["current"]["status"], "additional_context_in_some_sources": bool(row["source_paths_with_additional_context"]),
                         "sample_source_url": f"https://raw.githubusercontent.com/cisagov/CSAF/{commit}/{row['source_paths'][0]}"})
    write_csv(output / "product-alias-gaps.csv", gaps,
              ["vendor", "product", "advisory_count", "alias_status", "additional_context_in_some_sources", "sample_source_url"])
    write_csv(output / "manufacturer-alias-gaps.csv",
              [{"vendor": r["vendor"], "advisory_count": r["advisory_count"], "alias_status": r["current"]["status"]}
               for r in sorted(vendor_rows, key=lambda r: (-r["advisory_count"], normalize(r["vendor"])))
               if r["current"]["status"] != "equivalent_available"], ["vendor", "advisory_count", "alias_status"])
    write_report(output / "README.md", summary)
    return summary


def write_report(path: Path, summary: dict) -> None:
    c = summary
    lines = ["# CISA source-label and alias coverage audit", "",
             f"Source commit: `{c['source_commit']}`. Retrieved {c['source_retrieved_at']}.", "",
             f"The pinned OT/white snapshot contains **{c['source_counts']['advisory_files']:,} advisory files**: "
             f"{c['advisory_counts'].get('ICSA', 0):,} ICSA and {c['advisory_counts'].get('ICSMA', 0):,} ICSMA. "
             f"{len(c['excluded_non_advisory_files']):,} non-advisory feed metadata file is excluded. "
             f"{len(c['unusual_advisory_id_shapes']):,} advisory with an unusual ID shape is included and listed in coverage-summary.json. "
             f"All {c['manifest_json_files']:,} file bytes were checked against the pinned Git blob identifiers.", "",
             f"The audit found **{c['unique_vendor_labels']:,} distinct normalized manufacturer labels** and "
             f"**{c['unique_scoped_product_labels']:,} distinct manufacturer/product label pairs**. "
             "Case and whitespace are normalized. Different manufacturers, model qualifiers and editions remain separate.", "",
             "These counts measure how many source labels have at least one documented direct alternate in this package. "
             "They do not measure successful vulnerability matching. Exact names can work without an alias, and some products have no useful alternate name.", "",
             "| Source-label category | Baseline | Expanded |", "| --- | ---: | ---: |"]
    for category, label in (("vendors", "Manufacturer"), ("scoped_products", "Manufacturer/product")):
        for state, description in (("equivalent_available", "has a verified equivalent"), ("review_only", "has review-only alternatives"), ("no_documented_alias", "has no documented alternate")):
            lines.append(f"| {label}: {description} | {c['alias_presence']['baseline'][category].get(state, 0):,} | {c['alias_presence']['current'][category].get(state, 0):,} |")
    lines += ["", "The pair denominator requires exactly one distinct vendor and product_name in the branch ancestry of a product definition. "
              "Additional family or component context is retained. Missing or ambiguous lineage is recorded in extraction-issues.json, outside that denominator. "
              "Flat and relationship-generated products are not interpreted by this audit.", "",
              f"Extraction issues: {c['extraction_issue_count']:,}. Relationship definitions recorded but not interpreted: "
              f"{c['source_counts'].get('relationship_definitions_not_interpreted', 0):,}. "
              f"Product definitions with an additional family/component context: {c['source_counts'].get('pair_definitions_with_additional_context', 0):,}.", "",
              f"**Runtime scope remains narrower:** {c['source_counts']['advisories_with_current_runtime_id_format']:,} source advisories use the current exact ICSA-NN-NNN-NN input format. "
              f"{c['source_counts']['advisories_outside_current_runtime_id_format']:,} others, including ICSMA and suffix variants, do not. "
              f"{c['runtime_id_and_length_intersection']['scoped_product_labels_exceeding_input_lengths']:,} scoped source labels exceed the current manufacturer/product input lengths. "
              f"The ID-and-length intersection contains {c['runtime_id_and_length_intersection']['unique_scoped_product_labels']:,} scoped product labels; "
              "its separate baseline/current counts are in coverage-summary.json. This intersection still does not establish runtime matchability.", "",
              "## Files", "", "- coverage-summary.json: counts, definitions, limitations and both catalog hashes.",
              "- source-manifest.json: pinned commit, retrieval details and every source file hash.",
              "- source-identities.json: each observed label, source advisory IDs, paths and baseline/current mapping decisions.",
              "- product-alias-gaps.csv and manufacturer-alias-gaps.csv: research priorities, sorted by source advisory count. These are not confirmed matching failures.",
              "- extraction-issues.json: source lineage requiring separate handling.", "",
              "## Reproduce", "", "Download the public cisagov/CSAF archive for the exact source commit above. "
              "Extract its csaf_files/OT/white directory outside the runtime package. Run the offline audit with the original Git-tree metadata "
              "or the saved source manifest, the current catalog and a retained baseline catalog:", "", "```bash",
              "python scripts/audit_alias_coverage.py --corpus-dir /path/to/OT/white \\",
              "  --source-manifest docs/coverage/source-manifest.json \\",
              "  --catalog advisory_matcher/data/aliases.json \\",
              "  --baseline-catalog docs/coverage/baseline-aliases-v0.2.0.json \\",
              "  --output docs/coverage", "```", "",
              "The full source corpus is not shipped or loaded at runtime. This report adds no network destinations or automatic mapping behavior.", ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus-dir", type=Path, required=True)
    parser.add_argument("--source-manifest", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=ROOT / "advisory_matcher/data/aliases.json")
    parser.add_argument("--baseline-catalog", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "docs/coverage")
    args = parser.parse_args()
    summary = audit(args.corpus_dir, args.catalog, args.baseline_catalog, args.source_manifest, args.output)
    print(json.dumps({k: summary[k] for k in ("source_commit", "unique_vendor_labels", "unique_scoped_product_labels", "alias_presence")}, indent=2))


if __name__ == "__main__":
    main()
