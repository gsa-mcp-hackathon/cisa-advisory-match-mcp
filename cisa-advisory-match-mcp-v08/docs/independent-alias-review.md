# Independent alias implementation review

Recorded 2026-11-06T10:43:53.151716-05:00. Requested by Johnson Chen as part of the GSA MCP Hackathon alias expansion.

## Findings repaired during review

1. Alias overlap resolution depended on name order: a shared abbreviation could be accepted if it appeared as a group's first label. The alias engine now treats overlapping equivalent groups with different nonshared members as ambiguous regardless of list order. The engine author added a permutation regression.
2. New alias hints and search-mapping metadata could exceed the response-size limit after findings were removed. The service now removes oversized mapping payloads from hints and expansions, retains counts, and returns review status. Independent valid-large-catalog regressions pass.
3. Historical candidate groups duplicated already verified current-name pairs for AutomationDirect and FactoryTalk View SE/ME. The source researchers narrowed those historical groups, retaining confirmed current names as equivalent and former names as review candidates.

## Independent observed checks

- tests/test_alias_review.py: 6 passed, 0.62 seconds. Checks expanded product hints, expanded vendor references, shared request budget, actual catalog PME manufacturer scope, FactoryTalk SE/ME separation, IQ4E firmware uncertainty and adjacent-model rejection.
- Executed 360 directional pair-and-manufacturer-scope checks across latest researched vendor and product catalogs: zero resolver/catalog policy discrepancies.
- Independently reopened official Schneider Electric FAQ FA363331 and Emerson PAC Machine Edition landing page. Both use PME for different products; manufacturer-scoped resolution is necessary and present.
- Independently reopened Weintek's software download page. EBPro filenames appear under EasyBuilder Pro and EB8000 under EasyBuilder8000. They remain separate catalog mappings.
- Inspected runtime packaging: aliases.json is explicitly copied alongside the alias module.

## Limits

These checks establish reviewed behavior and catalog consistency, not comprehensive ICS coverage, all-source verification, production exploitability, or successful IBM/Orchestrate execution. No GitHub push or live IBM operation was performed by this reviewer. No blocker remains from this review after the identified corrections.
