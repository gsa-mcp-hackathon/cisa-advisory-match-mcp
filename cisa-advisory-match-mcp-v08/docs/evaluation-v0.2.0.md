# Evaluation of version 0.2.0

Revision recorded: 2026-11-06T10:45:39-05:00. Change requested by Johnson Chen. GSA MCP Hackathon, ICS Product Advisory Match MCP. These results were observed in the Codex Python 3.12.14 environment. IBM VM and Orchestrate agent testing remain pending. No GitHub push or public deployment occurred.

## Changes and coverage

The local, source-linked name catalog contains 52 manufacturer groups and 40 product groups, covering 94 distinct manufacturer labels and 94 distinct product labels. There are 30 equivalent/22 candidate manufacturer groups and 22 equivalent/18 candidate product groups. Names are scoped and direct, not a transitive graph. See `aliases.md` and `alias-reference.csv` for the 81 linked primary source URLs and record-level rationale.

The matching engine adds original-input preservation, applied mapping provenance, candidate review outcomes, input name hints, bounded discovery expansion, and catalog version/hash reporting. The original version-comparison limits remain unchanged. IQ4E without Firmware is now explicitly a review candidate. Honeywell International is now a verified manufacturer alias. Previous tests for those two absent mappings were updated to assert the new intended behavior while preserving adjacent-model rejection.

## Observed results

| Check | Actual outcome | Record |
|---|---|---|
| Final automated suite | 252 tests passed and 61 subtests passed; 1.14 seconds | `test-results/v0.2.0/v0.2.0-unit.xml` |
| Dependency consistency | `pip check`: no broken requirements | Pinned dependency environment |
| Offline MCP protocol | 12/12 checks passed; 0.798 seconds | `test-results/v0.2.0/v0.2.0-offline-protocol.json` |
| Live MCP protocol | 8/12 checks passed; 66.03 seconds | `test-results/v0.2.0/v0.2.0-live-protocol.json` |
| Live alias request | Honeywell International mapped to Honeywell; affected-range outcome and mapping provenance passed | Third trace in live protocol record |
| Live bounded alias discovery | Passed; 3 search requests, one advisory checked, 37 candidates explicitly unexamined; 52.081 seconds | `test-results/v0.2.0/v0.2.0-live-discovery.json` |
| Independent review | Six independent tests pass within the suite; reviewer also executed 360 directional catalog/scope consistency checks | `independent-alias-review.md` |
| IBM/Orchestrate agent behavior | Not executed | Cases A1-A12 in `agent-benchmarks.md` |

The live protocol run is **not an overall pass**. Its initial inventory call and explain call each returned sanitized `upstream_timeout` failure codes and review outcomes; their outcome and source checks failed. The third request, exercising the new manufacturer alias, succeeded. These failures remain counted and require IBM connectivity/reliability verification. No automatic retries or relaxed network controls were introduced. Live checks use the explicitly selected Codex platform-proxy harness, which is excluded from the IBM runtime.

## Real advisory fixtures versus synthetic coverage

The suite retains the Honeywell ICSA-26-069-03 revision 2 fixture and adds three unchanged public CSAF fixtures: Advantech ICSA-23-150-01, Rockwell ICSA-24-086-04, and Rockwell ICSA-25-028-04. Source URLs, revisions, retrieval timestamps and SHA-256 hashes are retained; the three additional hashes were independently checked before packaging. Tests exercise alternate names, a historical-name review, wrong manufacturers, and SE/ME or SCADA/CNC boundaries against these documents.

Other catalog checks and constructed malformed/large inputs are synthetic. Counts of passing catalog pairs do not measure real-world precision, recall or full-corpus coverage. Four hand-selected advisories are not representative validation of every name in the catalog. Generic terms such as PLC and HMI are explanatory documentation, not product aliases. NVD CPE identifiers are not imported.

## Review findings repaired

Independent review exposed name-order-dependent overlap resolution, large alias metadata bypassing the output fallback, and historical candidate groups contradicting verified current-name pairs. All were corrected and covered by tests. Source research also removed an unsupported Siemens legal-name variant. Documentation and runtime catalog are aligned with the reviewed records.

## Next milestone

Use the version 0.2.0 ZIP in a separate IBM VM folder. Read `BOB_START_HERE.md` and reproduce Milestone 1, including alias provenance and live discovery. Then execute the Orchestrate agent cases. Keep the repository private until submission access is deliberately configured. Use the selected repository https://github.com/jc-cisa/ics-product-advisory-match-mcp .

Version 0.1.0 results remain in `test-results/v0.1.0/` and `evaluation-v0.1.0.md` as historical results, not results for the revised code.
