# Candidate v0.7 evaluation

The catalog builder and sixth search tool were prepared from the v0.6 package on November 17, 2026. They are not yet tested against the real full CISA snapshot, actual MCP protocol, or IBM Orchestrate. No catalog database is included in the package.

Observed locally: 8 synthetic catalog tests, 4 shimmed wiring checks, 43 existing matching tests, and 11 feed tests passed. One archived original OT advisory fixture and one synthetic IT fixture were indexed with expected counts and an OT product candidate. Python compilation passed. The wiring checks use test-only stubs: they do not establish real MCP transport, network or IBM behavior. Search does not decide affected status, version applicability or KEV.

Bob reported v0.6 IBM unit and MCP results and agent experiments, but those do not establish v0.7 behavior. See [v0.6 evaluation](evaluation-v0.6.0.md) and the project build log for prior reported results. Full CISA corpus coverage, alias recall, completeness, freshness, precision, agent behavior and live integration remain unverified.

# Version 0.8.0 candidate evaluation

Recorded: 2026-11-17 to 2026-11-18. GSA MCP Hackathon, CISA Advisory Matching MCP.

## Changes from v0.7

Scoped alternate-name candidate discovery with review labels, distinct-advisory ordering, bounded flat names and longer product names, sanitized ingestion failure categories, source path checks, and commit-pinned links. The catalog must be built separately from the recorded public CSAF snapshot (`1cd0e9e91ab4a57d6e3631597fd0c06908b70bb2`); the builder script and expected output are in [CATALOG_BUILD.md](../CATALOG_BUILD.md).

## Observed results

All records are in [`test-results/`](../test-results/). The execution environment tag in the MCP records reads "caller runtime; see run record for IBM versus Codex". The records themselves do not independently establish whether the caller runtime was IBM or another environment.

| Check | Actual outcome | Record |
|---|---|---|
| Full automated test suite | 708 `<testcase>` elements, 0 failures, 0 errors, 0 skipped; `<testsuite tests="818">` (see note below) | `test-results/local-ibm-v08-unit.xml` |
| Test suite re-run after version bump | Same counts | `test-results/local-ibm-v08-unit-postbump.xml` |
| Offline MCP protocol | 18/18 checks passed | `test-results/ibm-v08-offline.json` |
| Live MCP protocol | 18/18 checks passed | `test-results/ibm-v08-live.json` |
| Catalog STDIO smoke test | 7 search cases + server initialization passed; ControlLogix returns 69 candidates (5 shown, 64 omitted) | `test-results/ibm-v08-stdio-catalog.json` |
| Agent behavior — basic ICS match (A) | Honeywell IQ4E Firmware 3.29 against ICSA-26-069-03: `affected_range_match`, KEV not listed, source sha256 reported | `test-results/ibm-v08-agent-tests.json` |
| Agent behavior — catalog routing (B) | Allen-Bradley ControlLogix via `search_product_catalog`: 69 found, 10 shown, 59 omitted; identity review and alias mode disclosed | `test-results/ibm-v08-agent-tests.json` |
| Agent behavior — missing identity (C) | "Fictional Schneider PLC": no tool called, agent requested manufacturer, model, and version | `test-results/ibm-v08-agent-tests.json` |
| Agent behavior — IT advisory read (D) | VA-26-295-01 (`read_cisa_it_advisory`): source summary returned, KEV `not_checked` preserved, no applicability claim | `test-results/ibm-v08-agent-tests.json` |
| ControlLogix catalog retest (instruction fix) | 69 found, 10 shown, 59 omitted; counts, alias mode, and identity review correctly disclosed | `test-results/ibm-v08-catalog-retest-controllogix.json` |
| ControlLogix catalog retest (count distinction) | Agent reported found=69, returned=10, omitted=59, displayed=3 correctly | `test-results/ibm-v08-catalog-retest-counts.json` |
| Catalog routing retest (without tool name) | Agent chose `search_product_catalog` without being prompted; counts and limits disclosed | `test-results/ibm-v08-routing-retest.json` |
| Catalog routing retest 2 (instruction correction) | Same counts; agent no longer conflates bounded search with full-corpus check | `test-results/ibm-v08-catalog-routing-retest-2.json` |

**Note on test count:** The JUnit XML files report `<testsuite tests="818">` but contain 708 `<testcase>` elements. `pytest --collect-only` reports 708 collected items. The reason for the difference between the `tests=` attribute and the element count has not been established from the available files. It is not described here as subtests.

## What remains unverified

Full CISA corpus coverage, alias recall, completeness, freshness, and representative precision/recall evaluation are not established. Live MCP results depend on the availability of the external upstream service (`cisa-cybersecurity.caseyjhand.com`) and `raw.githubusercontent.com`. The catalog covers only the pinned snapshot revision; it does not refresh automatically. The execution environment for the MCP and agent records is reported as "caller runtime" without independent confirmation of the specific platform.

