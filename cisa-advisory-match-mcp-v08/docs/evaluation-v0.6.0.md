# Evaluation of candidate version 0.6.0

Revision recorded 2026-11-16T14:53:31-05:00. Requested by Johnson Chen for GSA MCP Hackathon. This candidate is not a completed all-advisory IT/OT matching system. Five tools are defined; their actual MCP transport, IBM registration and agent behavior are not verified for this version.

## Changes

- `prepare_product_query` gives 23 broad IT/OT category cues, preserves separately supplied identity fields, and asks for missing or ambiguous information. It does not extract product identity from prose or search advisories. Category vocabulary is not a verified product-alias catalog.
- `search_advisory_candidates` searches literal phrases in title/summary metadata for one selected fixed CISA IT or OT feed. It returns leads, not product or version applicability. It reports incomplete coverage; inaccessible, malformed and oversized feeds are reported as failures, not no-match. It does not fetch source advisory bodies or follow feed links. The fixed transport accepts at most 2 MiB and could reject a large live feed.
- Malformed vulnerability entries and product-status IDs fail closed rather than silently becoming apparent no-matches.

## Observed local checks

| Check | Result | Scope |
| --- | --- | --- |
| Feed discovery | 11 tests passed | Synthetic feeds; not a live CISA feed. |
| Product context | 10 tests passed | Local deterministic utility; not an agent test. |
| Server function wiring | 3 tests passed | Test-only MCP/HTTP shims; not MCP protocol or HTTP. |
| Malformed status handling | 4 tests passed | Synthetic documents. |
| Earlier targeted regressions | 23 tests passed | Test-only shims and fixtures. |
| Matching, alias, IT reader/index and release-series tests | 43, 32, 22 and 4 tests passed respectively | Local unit and synthetic tests; the snapshot experiment remains unconnected. |
| Full pinned pytest, real MCP, live feed/source, IBM, agent behavior | Not run | Dependencies and direct public-source access unavailable in this workspace. Follow the Bob handoff and record actual results. |

Earlier results are preserved in [evaluation-v0.5.0.md](evaluation-v0.5.0.md) and prior evaluation files. Results for an earlier version do not establish v0.6 behavior.

## Interpretation limits

A search can miss advisories whose product names are absent from feed titles and summaries, use alternate names, lie on another page, or belong to other CISA collections. Feed completeness and freshness are not established. Product matches, release-line rules, and real-world applicability require source review. An empty result is not evidence of safety. The ordinary ICS matcher remains bounded by source, identity, version-grammar, and result limits. Agent resistance to hostile source text has not been tested. No GitHub push, IBM test or submission is claimed.
