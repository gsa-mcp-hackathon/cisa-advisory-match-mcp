# Evaluation — first implementation

Revision recorded **November 5, 2026, 12:17:08 p.m. EST** (`2026-11-05T12:17:08-05:00`). Requested by Johnson Chen. Version 0.1.0. **IBM VM, IBM Orchestrate agent tests, and GitHub push are pending.**

## Overview and objectives

The wrapper turns a public advisory search into device-specific triage with the exact source rule and an explanation of uncertainty. The first milestone tests JSON inventory, exact product labels and a small supported version grammar. It does not establish full-corpus accuracy, operational exploitability or production readiness.

The actual public advisory is [ICSA-26-069-03](https://www.cisa.gov/news-events/ics-advisories/icsa-26-069-03), original CSAF revision 2. Five fictional inventory rows cover affected, boundary, missing-version, unsupported-version and nonexact-product outcomes. Synthetic cases exercise ranges, per-CVE status, relationships and failures.

## Methodology

Tests ran in the Codex executor with Python 3.12.14, MCP SDK 2.3.0 and the pinned dependency set. The source-file SHA manifest is `test-results/v0.1.0/source-manifest.json`; there is no Git commit or remote yet. The fixture's source URL, revision and hash are in `tests/fixtures/provenance.json`.

The offline protocol harness starts a separate STDIO process, initializes MCP, discovers tools and invokes both tools. The live harness uses the real hosted cyanheads MCP and original CISA GitHub CSAF. This executor needs its trusted platform proxy because direct DNS fails; the test-only proxy launcher is excluded from production packaging. Success here does not establish direct HTTPS access from IBM.

An independent review found and corrected product-family ambiguity, duplicate/malformed product identities, version-specific severity scope, malformed metadata and output-size bypasses. Initial protocol testing also caught a missing structured-output declaration; the corrected server returns structured results. Transport tests caught and corrected unsafe exception-group cleanup. These were defects fixed during development, not evidence of a flawless first attempt.

## Observed metrics and results

| Check | Observed result | Evidence |
|---|---|---|
| Final automated suite | **98 tests passed**, plus 32 passing subtests; 0.97 seconds | `test-results/v0.1.0/unit.xml` |
| Final offline MCP protocol | **9/9 checks passed**, 0.865 seconds | `test-results/v0.1.0/offline-protocol.json` |
| Earlier full live protocol run | **9/9 checks passed**, 64.973 seconds; match tool 32.691 seconds, explain tool 31.538 seconds | Observed execution output; earlier raw report was replaced by the later run below |
| Latest retained live protocol repeat | **7/9 checks passed**, 45.6 seconds. Five inventory classifications passed; a new connection for `explain_match` failed and returned `needs_review`, so expected outcome/source checks failed. | `test-results/v0.1.0/live-protocol.json` |
| Bounded live discovery | Passed; one Honeywell search returned 38 candidates, one original advisory checked, 37 explicitly unexamined; 35.69 seconds | `test-results/v0.1.0/live-discovery.json` |
| IBM VM / Orchestrate | **Not run** | Bob handoff prepared |
| Agent behavior | **Not run** | Seven benchmark cases defined |

The live repeat failure remains in the denominator and is a reliability gap for IBM testing. It did not yield a false clean inventory. A safe failure is still a failed functional check. The final change adds a sanitized failure code to help diagnose such failures; a new regression verifies it. No additional live success is claimed after that diagnostic-only change.

The original-source SHA-256 seen in live checks was `e4fe8ac356b7836d737b18444ea7ce16967886382f4b351a2c51f29066b23f1f`. The mirror reported 3,995 documents, a November 3 checkpoint, complete sync and zero failed documents. KEV catalog was `2026.11.04`, with 1,768 entries. These describe the observed snapshots, not future availability.

For the selected-advisory inventory call, expected classifications were 5/5: one affected, one outside the listed range, two needing review, and one nonexact label with no match in the checked advisory. This tiny hand-selected set does not establish corpus-wide precision/recall. No response-time improvement, production throughput, agent success rate or false-positive rate over a representative inventory has been established.

## Security considerations

Verified controls include input limits, fixed destinations, blocked redirects, bounded JSON/SSE responses, strict source ID/JSON checks, sanitized failures, partial-search disclosure, unknown KEV on failure and preservation of configuration caveats. Data-minimization regression confirms only manufacturer names are sent during discovery; versions and asset IDs remain local. The clean package uses an allowlist rather than copying the entire checkout.

A deterministic test inserts hostile instructions into advisory text and confirms the matcher treats them as data. **This does not test whether an SI agent resists those instructions.** Actual agent tool selection, faithful narration, source citation, uncertainty handling and source-instruction resistance remain pending.

## Lessons and next steps

1. Original CSAF is necessary: current upstream normalization omits some product statuses and entries without CVEs.
2. A published range is narrower than a safety conclusion: Honeywell's remediation contains a configuration caveat even for 3.30 or later.
3. Product-specific CVSS must be tied to the matching version; other scores are labelled source context.
4. Source limits must be visible: default discovery is bounded and exact labels can miss aliases.
5. Live service connections can fail. Reproduce on the assigned IBM VM and then in Orchestrate, preserving failed attempts and actual traces.
6. Expand beyond one real advisory before final submission; test more vendors, product structures and firmware formats with manually checked expected answers.

See `BOB_START_HERE.md` for the next small milestone and `docs/agent-benchmarks.md` for the remaining agent evaluation. Starter weather/joke/converter results are not used as wrapper scores.
