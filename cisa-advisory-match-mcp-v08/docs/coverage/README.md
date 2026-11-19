# CISA source-label and alias coverage audit

Source commit: `020f7c01c13b08df34a9557e734d76ed7943c537`. Retrieved 2026-11-06T18:19:25.935222+00:00.

The pinned OT/white snapshot contains **3,995 advisory files**: 3,804 ICSA and 191 ICSMA. 1 non-advisory feed metadata file is excluded. 1 advisory with an unusual ID shape is included and listed in coverage-summary.json. All 3,996 file bytes were checked against the pinned Git blob identifiers.

The audit found **881 distinct normalized manufacturer labels** and **12,030 distinct manufacturer/product label pairs**. Case and whitespace are normalized. Different manufacturers, model qualifiers and editions remain separate.

These counts measure how many source labels have at least one documented direct alternate in this package. They do not measure successful vulnerability matching. Exact names can work without an alias, and some products have no useful alternate name.

| Source-label category | Baseline | Expanded |
| --- | ---: | ---: |
| Manufacturer: has a verified equivalent | 34 | 87 |
| Manufacturer: has review-only alternatives | 9 | 9 |
| Manufacturer: has no documented alternate | 838 | 785 |
| Manufacturer/product: has a verified equivalent | 20 | 114 |
| Manufacturer/product: has review-only alternatives | 13 | 21 |
| Manufacturer/product: has no documented alternate | 11,997 | 11,895 |

The pair denominator requires exactly one distinct vendor and product_name in the branch ancestry of a product definition. Additional family or component context is retained. Missing or ambiguous lineage is recorded in extraction-issues.json, outside that denominator. Flat and relationship-generated products are not interpreted by this audit.

Extraction issues: 186. Relationship definitions recorded but not interpreted: 1,724. Product definitions with an additional family/component context: 308.

**Runtime scope remains narrower:** 3,685 source advisories use the current exact ICSA-NN-NNN-NN input format. 310 others, including ICSMA and suffix variants, do not. 6 scoped source labels exceed the current manufacturer/product input lengths. The ID-and-length intersection contains 10,988 scoped product labels; its separate baseline/current counts are in coverage-summary.json. This intersection still does not establish runtime matchability.

## Files

- coverage-summary.json: counts, definitions, limitations and both catalog hashes.
- source-manifest.json: pinned commit, retrieval details and every source file hash.
- source-identities.json: each observed label, source advisory IDs, paths and baseline/current mapping decisions.
- product-alias-gaps.csv and manufacturer-alias-gaps.csv: research priorities, sorted by source advisory count. These are not confirmed matching failures.
- extraction-issues.json: source lineage requiring separate handling.

## Reproduce

Download the public cisagov/CSAF archive for the exact source commit above. Extract its csaf_files/OT/white directory outside the runtime package. Run the offline audit with the original Git-tree metadata or the saved source manifest, the current catalog and a retained baseline catalog:

```bash
python scripts/audit_alias_coverage.py --corpus-dir /path/to/OT/white \
  --source-manifest docs/coverage/source-manifest.json \
  --catalog advisory_matcher/data/aliases.json \
  --baseline-catalog docs/coverage/baseline-aliases-v0.2.0.json \
  --output docs/coverage
```

The full source corpus is not shipped or loaded at runtime. This report adds no network destinations or automatic mapping behavior.
