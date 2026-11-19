# Candidate v0.7 evaluation

The catalog builder and sixth search tool were prepared from the v0.6 package on November 17, 2026. They are not yet tested against the real full CISA snapshot, actual MCP protocol, or IBM Orchestrate. No catalog database is included in the package.

Observed locally: 8 synthetic catalog tests, 4 shimmed wiring checks, 43 existing matching tests, and 11 feed tests passed. One archived original OT advisory fixture and one synthetic IT fixture were indexed with expected counts and an OT product candidate. Python compilation passed. The wiring checks use test-only stubs: they do not establish real MCP transport, network or IBM behavior. Search does not decide affected status, version applicability or KEV.

Bob reported v0.6 IBM unit and MCP results and agent experiments, but those do not establish v0.7 behavior. See [v0.6 evaluation](evaluation-v0.6.0.md) and the project build log for prior reported results. Full CISA corpus coverage, alias recall, completeness, freshness, precision, agent behavior and live integration remain unverified.
