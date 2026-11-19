# Evaluation of version 0.4.0

Revision recorded: 2026-11-16T14:03:31-05:00. Change requested by Johnson Chen for the GSA MCP Hackathon. This is a candidate prototype; IBM VM, full pinned test suite and Orchestrate agent tests are pending. No new live MCP test or GitHub push is claimed.

## Mission and implementation review

The project remains an agent-facing workflow for fictional ICS inventory against selected or bounded CISA ICS advisory rules. Inventory-to-advisory matching and MCP vulnerability lookups exist in other projects. [The related-project review](mission-related-project-review.md) describes overlap and limitations, and [the demo plan](ibm-demo-plan.md) gives a reproducible, source-linked sequence. Neither establishes that this project is unique or operationally ready.

## Changes

- A row with a confirmed affected finding and a separate unresolved finding now preserves both. `assessment_counts`, `has_unresolved_findings`, and the review reason make the remaining work visible. If findings are dropped due to output limits, the counts and flag become unknown; an aborted call also returns unknown counts.
- Bounded vendor discovery is marked incomplete if the source index timestamp is missing, invalid, older than 48 hours, or more than one hour ahead. This window is a prototype policy, not a freshness guarantee. Explicitly selected original advisory checks retain the warning without being rejected solely for index age.
- Explicit contradictory search-page metadata also marks a query incomplete: not ready, unfinished sync, failed documents, or stale/future completion time. Checks retain conflicts across pagination. Optional page timestamps that are missing or unusable are reported as unknown, separately from general source metadata.
- When a CSAF document contains relationship-generated identities but would otherwise produce no matching finding, the source is marked unsupported and needs review. This is conservative: an unrelated relationship can also cause review. Existing associated relationship matches remain review-only; other positive findings are retained.
- Added a representative IBM demo plan, related-project comparison, A16 mixed-results agent case, and test-only guidance. The alias catalog is unchanged from v0.3.0 (565 names including full and alternate forms), and its snapshot audit remains historical.

## Observed checks here

| Check | Observed result | Limit |
|---|---|---|
| Targeted change tests | 23/23 passed | Real local service/matching code with recorded or synthetic fixtures; test-only pytest/UpstreamError shims. No MCP transport or live HTTP. `test-results/v0.4.0-targeted.json` |
| Existing matching tests | 43 unittest tests passed | Local fixture/unit tests, not IBM. `test-results/v0.4.0-targeted.json` |
| Existing alias tests | 32 unittest tests passed | Local tests, not an independent full catalog validity audit. `test-results/v0.4.0-targeted.json` |
| Existing service tests | 17 parameter-free test functions passed; one fixture-parameter test not run | Test-only shims and local fixtures; not an actual pytest run. |
| Compilation | Python compileall passed for code and targeted runner | Does not establish runtime dependencies. |
| Full pinned pytest, real MCP protocol, live source and IBM agent | Not run on v0.4.0 | Install pinned dependencies and run `BOB_START_HERE.md` Milestone 1 on IBM, then agent cases. |

The pinned dependencies `pytest`, `pytest-subtests`, and `httpx2` were not available in this local session. A no-index install and a package-index attempt did not supply them. The shimmed tests do not exercise actual upstream transport or protocol. Full v0.3.0 results (612 tests +61 subtests, offline12/12 and live12/12 in Codex) are archived in `evaluation-v0.3.0.md` and apply only to that earlier version.

## Remaining limitations

The code cannot determine whether input inventory is fictional; manufacturer names go to a third-party service during vendor discovery. Use fictional data only. Direct advisory IDs remain limited to the current ICSA input grammar; ICSMA and some suffix variants are excluded from direct selection, and numeric version grammar remains narrow. The third-party service and public network may be slow or unavailable. Optional search-page freshness metadata can be missing or malformed; it is then reported as unknown, and a healthy general timestamp does not prove the page is current. No-match is not a finding that the asset is safe. Test agent resistance to untrusted source instructions separately with a controlled fixture.

The organizer's Week 6 submission details, unknown exact midnight cutoff and organizer-provisioned GitHub destination require attention. No real-world precision/recall study has been run.
