# Mission and related-project review

Reviewed November 16, 2026, for the GSA MCP Hackathon at Johnson Chen's request. Review compares public project documentation, not executed comparison products or independently verified vendor claims.

## Recommendation

Keep the ICS advisory matching prototype and tighten the user experience and source limitations. The user need is credible: an analyst with a fictional device inventory should be able to ask which checked advisory rules appear to apply, see the original product/version rule, identify incomplete information, and avoid treating absence of a match as safety. CISA's OT asset-inventory guidance identifies vulnerability management as a use for inventory data: https://www.cisa.gov/sites/default/files/2025-08/joint-guide-foundations-for-OT-cybersecurity-asset-inventory-guidance_508c.pdf . This is a prototype for public fictional data, not an operational assessment or network scanner.

## What already exists

| Project | What its public documentation describes | Relationship to this prototype |
|---|---|---|
| [Deadband](https://github.com/jmeltz/deadband) | ICS/OT asset inventories and firmware matched with CISA advisories, optional discovery, and reports | Closest overlap. We do not claim to invent inventory-to-advisory matching; no device discovery from Deadband is incorporated. |
| [Cyanheads CISA MCP](https://github.com/cyanheads/cisa-cybersecurity-mcp-server) | ICS advisory search/retrieval and KEV queries | Our existing third-party upstream. It already exposes rich advisory tools, so our contribution is the additional per-inventory-item rule comparison and explanation. |
| [Cyanheads NVD MCP](https://github.com/cyanheads/nist-nvd-mcp-server) | NVD CPE product/version audit and CVE lookup | Another MCP project already addresses product/version vulnerability discovery. Our scoped original CISA ICS CSAF checks and explicit review outcomes do not establish that no other similar MCP server exists. |
| [ICS Advisory Project](https://github.com/icsadvprj/ICS-Advisory-Project) | Community conversion of CISA ICS advisories into CSV for analysis | Demonstrates demand for machine-readable, analyst-friendly output. Our code does not import its datasets. |

Capabilities are based on the projects' own documentation. They are not endorsements, completed accuracy comparisons, licenses for copied code, or evidence of security review. The distinctive aspect we seek to test is the combination of a bounded read-only agent workflow, preserved inventory identity, original CISA product identifiers and version rules, visible uncertainty, and no device scanning. We have not established first-of-kind novelty.

## Lessons incorporated

- Show which advisories were actually checked, what was not checked, source dates, and search budgets. A no-match or outside-range result applies only to checked sources and does not establish safety.
- Report a confirmed match and any separate unresolved finding for the same asset. Do not replace a confirmed match with a single numerical confidence score.
- Keep source text untrusted, inputs validated, network destinations fixed, and output bounded. Distinguish deterministic code tests from agent behavior under prompt injection.
- Test with fictional public-data inputs: one affected product, an outside-range boundary, missing or unsupported version, wrong model and an incomplete source/search scenario. Use real checked source IDs and keep failures in the denominator.
- The current selection and version grammar, third-party index availability, source structures and finite catalog constrain coverage. A missing or unusable search-page timestamp is reported as unknown and does not independently establish freshness. Alias counts are not a measure of recall, precision or real installations. Discovery searches a maximum of three manufacturer terms per input and twelve requests, with at most twelve advisory documents checked.

## Decision and outstanding validation

No pivot or public deployment is needed for a credible hackathon demonstration. Prioritize IBM VM and Orchestrate agent testing, one clear bounded example, a judge-accessible organizer-provisioned repository, a real recorded demo, and measured evaluation. Our Codex protocol results do not establish IBM tool selection, network availability, agent correctness or production security. Preserve the original source/provenance, use synthetic inputs, do not collect operational inventory, and do not claim all products or advisories were evaluated.

The November 16 Week 6 email says organizers provision a GitHub organization repository after a username is sent, will send the Qualtrics form separately, and applies a 50 MB cap to demo videos while suggesting ZIP for oversized recordings. Confirm the ZIP limit and whether “Midnight EST on Friday, 11/20” means the start or end of Friday. Plan submission before Thursday November 19 ends until clarified.
