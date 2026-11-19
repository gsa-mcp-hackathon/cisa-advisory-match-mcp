# Evaluation of version 0.3.0

Revision recorded: 2026-11-06T13:30:02-05:00. Change requested by Johnson Chen. GSA MCP Hackathon, ICS Product Advisory Match MCP. Tests below were observed in the Codex Python 3.12.14 environment. IBM VM and Orchestrate verification remain pending. No GitHub push or deployment occurred.

## Vocabulary expansion

The catalog grew from 188 to **565 distinct labels**, including full and alternate names: 201 manufacturer labels across 107 groups, and 364 product labels across 150 groups. Manufacturer policies comprise 74 equivalent and 33 review-only groups; product policies comprise 120 equivalent and 30 review-only groups. The catalog links 326 distinct source URLs.

The delivered catalog adds 55 manufacturer groups and 110 product groups to version 0.2, and expands several existing groups. One extra product group separates an ambiguous acronym from its verified full name. These totals are naming relationships, not numbers of supported devices or all possible synonyms. Exact capitalization and whitespace normalization remain unchanged. No new fuzzy, substring, punctuation-stripping or transitive acquisition rules were added.

Independent source checks kept Siemens PDM, Siemens ALM and bare AVEVA Historian review-only. FTAC was excluded because Rockwell uses the acronym for different products. Regional Siemens order numbers retain the complete model and region; software suites, components and editions stay separate. See [the catalog](aliases.md), [the reference CSV](alias-reference.csv), [exact counts](alias-statistics.json) and [independent review](expansion-independent-review.md).

## Measured source intersection

The offline audit checked all 3,996 JSON files against pinned CISA Git blob hashes, included **3,995 advisories**, and excluded one feed metadata file. The snapshot contains 881 normalized manufacturer labels and 12,030 distinct manufacturer/product label pairs under the audit's stated branch-lineage rules. Ambiguous source lineage and relationships are separately recorded.

| Source labels with a documented direct alternative | Version 0.2 | Version 0.3 |
|---|---:|---:|
| Manufacturer, verified equivalent available | 34 | 87 |
| Manufacturer, review-only alternatives available | 9 | 9 |
| Manufacturer/product pair, verified equivalent available | 20 | 114 |
| Manufacturer/product pair, review-only alternatives available | 13 | 21 |

The audit still finds 785 manufacturer labels and 11,895 manufacturer/product pairs without a documented alternative. This is a research queue, not a count of failed matches: exact names can work without aliases, and some names have no useful alternate. Some reviewed names are prospective vocabulary outside this source snapshot. Dictionary presence does not measure recall, precision, source version support or runtime discovery coverage. The current exact advisory-ID input format and name-length limits further narrow runtime scope. See [the full audit and reproduction instructions](coverage/README.md).

## Observed tests

| Check | Actual outcome | Record |
|---|---|---|
| Final automated suite | 612 tests and 61 subtests passed; 1.46 seconds | `test-results/v0.3.0-unit.xml` |
| Independent regression checks | 32 tests passed within that suite; 1,144 separate directional/scoped catalog comparisons found no policy discrepancies | `expansion-independent-review.md` |
| Corpus audit tests | 11 passed within the final suite; separate traversal reproduced source identity counts | `tests/test_coverage_audit.py` |
| Offline MCP protocol | 12/12 passed; 0.743 seconds | `test-results/v0.3.0-offline-protocol.json` |
| Live MCP protocol | 12/12 passed; 88.108 seconds | `test-results/v0.3.0-live-protocol.json` |
| Codex explanation trial | 4/4 hand-selected recorded-result explanations met the scoped criteria; no retries | `test-results/agent-trial/inputs.json`, `responses.json`, `review.json` |
| IBM VM and IBM agent behavior | Not executed | Prepared cases A1-A15 in `agent-benchmarks.md` |

The live checks used the explicitly selected trusted Codex platform-proxy harness. Production network controls and IBM runtime packaging are unchanged. This successful run does not establish sustained upstream reliability or IBM connectivity; version 0.2's recorded timeouts remain in the archived results. No new live full-corpus or discovery run is claimed for version 0.3.

The explanation trial used a fresh Codex subagent supplied only actual recorded matcher outputs, the user prompts and agent instructions. It preserved affected/version distinctions, rejected blanket safety claims, and requested clarification for PDM. It did not test autonomous MCP selection, argument generation, injection resistance, repeatability or IBM behavior. The root reviewer scored the saved responses; these are separate from protocol tests.

## Original advisory examples

Four new, unchanged CISA fixtures add Hitachi MSM numerical boundaries, Siemens regional order numbers, Yokogawa R-prefixed versions and Mitsubishi letter-suffixed versions. The latter two recognize product names but correctly require version review. The suite now has eight selected real advisory fixtures. Source URLs, revisions and SHA-256 values are retained; the four new fixtures also match their pinned Git blob hashes.

This remains a small selected set, not a representative accuracy study across the corpus. Source product-tree presence alone is insufficient: version and vulnerability-status links must also match. Candidate identities never receive confirmed affected status merely because an alias exists.

## Reproduce and continue

Run `BOB_START_HERE.md` Milestone 1 using this version in a separate IBM VM folder. Then run the IBM agent cases and verify the normal GitHub push to the selected repository. Do not overwrite the working starter.

Historical evaluations are in `evaluation-v0.2.0.md` and `evaluation-v0.1.0.md`; historical test outputs are in their respective `test-results/` version folders. They are not current-version results.
