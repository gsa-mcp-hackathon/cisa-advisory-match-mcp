"""Rebuild the readable alias tables and exact label counts from package data.

This is an offline maintenance command. It does not research or approve aliases.
Names are symmetric groups, so no label is counted as a universal canonical name.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from advisory_matcher.aliases import AliasCatalog, normalize


def statistics(data: dict, raw: bytes) -> dict:
    result = {"catalog_version": data["version"], "sha256": hashlib.sha256(raw).hexdigest()}
    combined = set()
    for category in ("vendors", "products"):
        rows = data[category]
        labels = {normalize(name) for row in rows for name in row["names"]}
        combined.update(labels)
        result[category] = {
            "groups": len(rows),
            "equivalent_groups": sum(row["mode"] == "equivalent" for row in rows),
            "candidate_groups": sum(row["mode"] == "candidate" for row in rows),
            "distinct_labels": len(labels),
            "label_entries": sum(len(row["names"]) for row in rows),
        }
    result["distinct_labels_across_both_categories"] = len(combined)
    result["distinct_source_urls"] = len({url for category in ("vendors", "products")
                                           for row in data[category] for url in row["source_urls"]})
    result["counting_note"] = ("Case and whitespace normalized. Counts include full and alternate names; "
                               "groups are symmetric and are not counts of devices, all possible "
                               "alternate names, or validated advisory matches.")
    return result


def cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recorded-at", required=True, help="Actual revision timestamp with time-zone offset")
    args = parser.parse_args()
    raw = (ROOT / "advisory_matcher/data/aliases.json").read_bytes()
    data = json.loads(raw)
    AliasCatalog(data, source_bytes=raw)
    stats = statistics(data, raw)
    (ROOT / "docs/alias-statistics.json").write_text(json.dumps(stats, indent=2) + "\n")
    fields = ["kind", "id", "mode", "vendors", "names", "source_title", "source_urls", "rationale"]
    with (ROOT / "docs/alias-reference.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for category in ("vendors", "products"):
            for row in data[category]:
                writer.writerow({"kind": category, "id": row["id"], "mode": row["mode"],
                                 "vendors": " | ".join(row.get("vendors", [])),
                                 "names": " | ".join(row["names"]),
                                 "source_title": row["source_title"],
                                 "source_urls": " | ".join(row["source_urls"]),
                                 "rationale": row["rationale"]})
    doc = ROOT / "docs/aliases.md"
    previous = doc.read_text()
    policy = previous[previous.index("## How names affect a result"):previous.index("## Manufacturer mappings")]
    glossary = previous[previous.index("## Generic ICS terminology"):]
    vendor, product = stats["vendors"], stats["products"]
    lead = (f"# Documented alternate names\n\nRevision recorded: {args.recorded_at}. "
            f"Change requested by Johnson Chen for GSA MCP Hackathon. Catalog version: {data['version']}.\n\n"
            f"The catalog has {vendor['groups']} manufacturer groups ({vendor['equivalent_groups']} equivalent, "
            f"{vendor['candidate_groups']} candidate) containing {vendor['distinct_labels']} distinct labels, and "
            f"{product['groups']} product groups ({product['equivalent_groups']} equivalent, "
            f"{product['candidate_groups']} candidate) containing {product['distinct_labels']} distinct labels. "
            f"There are {stats['distinct_labels_across_both_categories']} distinct labels across both categories "
            f"and {stats['distinct_source_urls']} distinct source URLs. These totals include full and alternate names. "
            "They do not count every possible alternate name or establish full product coverage.\n\n"
            "See [the corpus coverage audit](coverage/README.md) for the source snapshot, measured intersections, "
            "and remaining research queue. [Exact statistics](alias-statistics.json) and "
            "[the full reference CSV](alias-reference.csv) are generated from the same catalog.\n\n")
    tables = []
    for category, title in (("vendors", "Manufacturer mappings"), ("products", "Product mappings")):
        lines = [f"## {title}", "", "| ID | Policy | Manufacturer scope | Labels | Source |",
                 "|---|---|---|---|---|"]
        for row in data[category]:
            scope = " / ".join(row.get("vendors", [])) or "Manufacturer field"
            source = f"[{cell(row['source_title'])}]({row['source_urls'][0]})"
            lines.append(f"| {cell(row['id'])} | {row['mode']} | {cell(scope)} | "
                         f"{cell(' / '.join(row['names']))} | {source} |")
        tables.append("\n".join(lines) + "\n\n")
    doc.write_text(lead + policy + "".join(tables) + glossary)
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
