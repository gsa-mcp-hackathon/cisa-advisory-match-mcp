# test-results

IBM MCP protocol checks, catalog verification, and agent behavior records for version 0.8.0 candidate.
See [`docs/evaluation.md`](../docs/evaluation.md) for the full results summary.

## JUnit XML test suite records

`local-ibm-v08-unit.xml` — full pytest suite run immediately before the IBM offline MCP check
(timestamp `2026-11-17T18:30:38`). Contains **708 `<testcase>` elements**, all passing;
0 failures, 0 errors, 0 skipped.

`local-ibm-v08-unit-postbump.xml` — same suite re-run after a version bump, immediately before
the IBM live MCP check (timestamp `2026-11-17T18:37:31`). Same counts.

**Note on `tests=` attribute:** Both files carry `<testsuite tests="818">`, which exceeds the
708 `<testcase>` element count by 110. `pytest --collect-only` reports 708 collected items.
The reason for the difference between the `tests=` attribute value and the number of
`<testcase>` elements has not been established from the available files. It is not described
here as subtests.

**Sanitization note:** The `hostname=` attribute in both files has been replaced with a
generic value. All testcase data, timing, test names, counts, and the `tests=` attribute
are unchanged. No other modifications were made.

| File | Original SHA-256 | Sanitized SHA-256 |
|---|---|---|
| `local-ibm-v08-unit.xml` | `b00706c9d0ee584e93b2f82946d75bb1efcf8a2b5128b5798dceb4f62f067156` | `f38a46b270fb061fc316a5be3a08d27d8f33ef5a5ce09b0ee911aec8518b80ca` |
| `local-ibm-v08-unit-postbump.xml` | `f0257e0415ef37a26aec40742973388def097e2ac687d750f949e259c1359fa1` | `b97fc8f1d0b1f18a2e695ab826eac1f00be5cb3b3acdb2397f54ee10fa71d3d1` |

## MCP protocol records

`ibm-v08-offline.json` — offline fixture MCP check: 18/18 passed (2026-11-17T18:31:48Z).
`ibm-v08-live.json` — live MCP check: 18/18 passed (2026-11-17T18:37:56Z).

Both records carry `"execution_environment": "caller runtime; see run record for IBM versus Codex"`.
They do not independently establish whether the caller runtime was IBM or another environment.

## Agent behavior records

`ibm-v08-agent-tests.json` — 4/4 agent behavior tests passed (A–D): ICS inventory match,
catalog routing for ControlLogix, missing-identity refusal, IT advisory reading.

`ibm-v08-catalog-retest-controllogix.json`, `ibm-v08-catalog-retest-counts.json`,
`ibm-v08-routing-retest.json`, `ibm-v08-catalog-routing-retest-2.json` — four focused
ControlLogix retests confirming the agent correctly distinguishes candidates found (69),
returned in the response (10), omitted (59), and displayed (3).

## Catalog STDIO smoke test

`ibm-v08-stdio-catalog.json` — 7 direct STDIO calls to `search_product_catalog` including
exact phrases, manufacturer-scoped aliases, bare product names, an IT example, a no-result
case, and a result-limit check. All cases returned expected structure.
