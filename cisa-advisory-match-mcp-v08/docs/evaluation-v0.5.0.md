# Evaluation of candidate version 0.5.0

This is an unfinished hackathon candidate, not a complete IT and OT product-matching service. The new IT tool reads one explicitly selected advisory. The local snapshot-search research module is not connected to an MCP tool, has no verified CISA data, and cannot be used for the demonstration. The broader IT search and matching requested by Johnson remain incomplete.

## Observed checks in this environment

- 23 targeted local fixture checks passed using test-only dependency shims; 43 matching unit tests and 32 alias unit tests passed.
- 16 selected IT reader and security tests, 6 local snapshot prototype tests, and 4 multi-release-line guard tests passed. Synthetic fixtures do not establish live source compatibility.
- Python compilation passed. No pinned full test suite, real MCP transport, live IT retrieval, IBM integration, or agent behavior tests were run for this candidate because required Python packages and public-source network access were unavailable here.

Earlier version 0.4 results are retained in [evaluation-v0.4.0.md](evaluation-v0.4.0.md). Results for v0.3 do not establish v0.5 behavior.

## Accuracy and safety limits

A guard sends multiple differing one-sided version limits for review rather than assuming they apply across all release lines. A single open-ended rule may also have unstated release context. The existing ICS matcher has bounded discovery and incomplete version grammar; absence of a match is not evidence of safety. IT product statuses are source data only, not an asset applicability assessment. The selected IT reader only supports VA-form identifiers and does not enumerate all CISA or vendor advisories. No corpus-wide coverage or accuracy measurement exists.

Read [security](security.md), [IT source analysis](it-source-analysis.md), [plain-language guide](plain-language-guide.md), and [IBM agent test cases](agent-benchmarks.md). Agent behavior and prompt-injection resistance have not been demonstrated. No GitHub push or submission is claimed.
