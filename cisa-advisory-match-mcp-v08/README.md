# CISA advisory matching MCP

**Version 0.8.0 candidate:** Adds scoped alternate-name candidate discovery, diverse advisory ordering, safer ingestion and pinned source links to the 0.7 catalog prototype. The catalog must be built separately from a public snapshot. It returns candidates only, not product identity, vulnerability status, version applicability, KEV, safety or complete coverage. This revision requires IBM and agent verification. See [catalog handoff](PRODUCT_CATALOG_HANDOFF.md).

GSA MCP Hackathon · sandbox prototype · candidate version 0.8.0

Matches a fictional device inventory against a bounded selection of CISA ICS advisories and explains each match using product details, affected versions, and source links. It also reads a single explicitly identified CISA IT advisory and provides experimental candidate discovery from public IT and OT advisory feed titles and summaries. A local product-query helper identifies broad equipment categories and missing details. **Feed-title or summary leads are not product applicability assessments, and no full CISA coverage is established.**

This is an MCP wrapper: an IBM agent calls our tools; for ICS matching our server uses the public [cyanheads CISA MCP](https://github.com/cyanheads/cisa-cybersecurity-mcp-server) to discover advisories and check KEV, then compares product/version rules in original [CISA CSAF](https://github.com/cisagov/CSAF) documents. No model makes the version comparison. KEV means CISA's Known Exploited Vulnerabilities catalog; CSAF is the machine-readable advisory format.

**Earlier v0.6 status:** adds a product-query helper and experimental feed-title and summary discovery to the source reader, plain-language guidance and conservative version handling. The earlier v0.6 package was tested in IBM as reported by Bob; this changed v0.8 candidate has not been tested in IBM. The private working repository is https://github.com/jc-cisa/cisa-advisory-match-mcp . GSA now requests an organizer-provisioned hackathon repository; its URL and access remain unverified. See [the measured results](docs/evaluation.md) for what actually passed. The v0.6 ZIP was uploaded, and its toolkit and agent registered, per Bob; v0.8 source publication and IBM validation are pending. This is a sandbox prototype. Catalog intersection with a pinned source snapshot is measured separately from actual match accuracy and runtime discovery coverage.

The version 0.4 dictionary contains **565 distinct labels** across 107 manufacturer and 150 product groups, including both full and alternate names. The [audit of 3,995 source advisories](docs/coverage/README.md) identifies remaining naming gaps. A name in the dictionary does not establish version applicability or comprehensive discovery.

## Mission and related tools

This prototype helps an agent compare a fictional ICS inventory with selected or bounded CISA advisories and explain the original product/version rule and any uncertainty. Existing projects already offer ICS inventory matching and MCP vulnerability lookups; our contribution is a specific agent-facing combination, not a claim of being first. See the [related-project and mission review](docs/mission-related-project-review.md) and [IBM demo and evaluation plan](docs/ibm-demo-plan.md). The full workflow still requires IBM verification.

## First reproducible milestone

Use Python 3.12 in a new project environment. Do not modify the working IBM starter or its ADK environment.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.lock.txt
.venv/bin/python -m pytest -q
.venv/bin/python scripts/check_mcp.py --output test-results/local-offline.json
.venv/bin/python scripts/check_mcp.py --live --output test-results/local-live.json
```

The offline check, when run with the pinned dependencies, exercises the MCP handshake and all registered tools. The ICS test uses a recorded public advisory; the IT reader uses a clearly labeled synthetic fixture. Prepared checks are not observed results until they are run. Live mode uses the public upstream and CISA source. The production entry point is `.venv/bin/python server.py` using STDIO, a direct pipe between two programs. It does not open a public network port.

Live tests require outbound HTTPS to `cisa-cybersecurity.caseyjhand.com` and `raw.githubusercontent.com`. The production client does not inherit proxy settings. A separate, explicitly selected `--platform-proxy` test harness accommodates trusted Codex networking; it is excluded from IBM runtime packaging. A failure to connect must remain visible and is not a clean inventory result.

## Tools

| Tool | Input | Result |
|---|---|---|
| `match_inventory` | 1–20 fictional inventory rows; optional selected advisory IDs; advisory budget | One result per input, source rules and links, product-specific severity, KEV snapshot and coverage gaps |
| `explain_match` | One inventory item and ICS advisory ID | Rechecks that pair and shows its original product/version source details and mitigation context |
| `read_cisa_it_advisory` | One explicit CISA `VA-YY-DDD-NN` advisory ID | Bounded source summary with source URL, hash and retrieval time; no product match, KEV check or applicability decision |
| `prepare_product_query` | Optional question, manufacturer, product and version | Local category cues and clarification guidance; preserves structured fields, does not extract identity from the question, perform search, or assess applicability |
| `search_advisory_candidates` | Search phrase (2–120 characters), category `IT` or `OT`, optional result limit (1–30, default 10) | Experimental literal search of one selected CISA feed’s titles and summaries for candidate leads, not full product-tree search or affected-product determination; live feed behavior and completeness remain unverified |
| `search_product_catalog` | Product phrase, optional manufacturer and IT/OT scope | Candidates from an operator-built snapshot; missing, incomplete and stale catalog caveats; no applicability decision |

Example `match_inventory` arguments:

```json
{
  "inventory": [{"asset_id":"demo-controller-01","manufacturer":"Honeywell","product":"IQ4E Firmware","version":"3.29"}],
  "advisory_ids": ["ICSA-26-069-03"]
}
```

The [five-row sample](examples/inventory.json) contains fictional asset IDs and public product names. For the recorded advisory revision 2: 3.29 matches `<v3.30`; 3.30 is outside that listed range; missing and `3.30-beta` versions need review; `IQ4E` alone now surfaces `IQ4E Firmware` as a candidate requiring component confirmation, rather than silently establishing identity. The source still recommends a user-module configuration check for some devices running 3.30 or later. Outside a listed range never means safe or no action needed.

Version 0.4 accepts structured JSON inventory and documented, manufacturer-scoped alternate names. See [the alias catalog and sources](docs/aliases.md). A reproducible [coverage audit](docs/coverage/README.md) inventories actual source names and the remaining mapping queue. The [plain-language guide](docs/plain-language-guide.md) and query helper prepare the agent to interpret common requests and ask for missing details. Category cues are not verified product aliases, and free text is not automatically parsed into product identity. CSV/Sheet import, additional version schemes and representative precision/recall evaluation are not implemented.

## Supported comparisons and limits

- Exact names or documented equivalent aliases, scoped by manufacturer. General normalization ignores case and whitespace only. Candidate brand/history/component mappings require review. Product-family context and source relationships remain separate constraints.
- Numeric dotted versions with optional leading `v`; exact equality; `<`, `<=`, `>`, `>=`; one lower/upper interval expressed as `vers:intdot/...`; explicit `vers:all/*`. Numeric components are integers, so trailing zero components compare equally. This is a declared prototype policy, not universal firmware semantics.
- Multiple distinct one-sided affected version bounds in the same finding require review because they may describe separate release lines. A single open-ended rule can also hide release-line context; the guard does not prove universal correctness. Unsupported schemes, suffixes, free-text ranges, malformed trees, conflicting statuses and missing versions require review. Original CSAF statuses are inspected because upstream normalization omits some statuses and non-CVE entries.
- Up to four manufacturers, three documented names per manufacturer, two search pages per name, 50 candidates per page, and twelve search requests total. Eight checked advisories by default (at most 12). Candidates are interleaved across manufacturers. Unsearched names, unexamined candidates and failures are listed. Alias discovery is not exhaustive.
- One call has a 90-second budget. Network reads have a ten-second budget and 2 MiB limit. Finding and combined output budgets are 24 KiB and 256 KiB. Oversized output becomes explicit review, never a silently complete result.
- The experimental IT reader retrieves only a fixed CISA source path for the supplied `VA-` ID. It returns at most 20 product branches and 10 vulnerability entries, with at most 40 product IDs per status and omission counts. Source relationships and other complex structures are not interpreted. A `VA-` ID does not represent all IT advisory identifier forms.
- No inventory persistence, scanning, remediation, credential input, arbitrary URL fetching, full-corpus mirror or public hosting. Only manufacturer names leave during discovery; versions and asset IDs stay in this process. Advisory IDs and CVEs go upstream for retrieval/enrichment.

See [security](docs/security.md), [IBM/Bob handoff](BOB_START_HERE.md), [agent benchmarks](docs/agent-benchmarks.md), and [resource review](docs/resource-review.md).

## Repository guide

`server.py` defines the MCP tools listed above. `advisory_matcher/it_advisories.py` provides the limited IT source reader; it is not an IT product matcher. `advisory_matcher/aliases.py` applies the sourced local catalog; `advisory_matcher/models.py` validates inputs; `service.py` coordinates bounded searches and results; `matching.py` performs deterministic CSAF comparisons; `upstream.py` uses the official MCP client and constrained HTTPS. `tests/` contains regression tests and the public fixture. `scripts/package_runtime.py` creates a clean IBM package without tests, virtual environments, credentials or research transcripts. `scripts/audit_alias_coverage.py` analyzes a separately downloaded, pinned public CSAF snapshot offline; it is a maintenance tool, not a runtime full-corpus search. `scripts/render_alias_reference.py` regenerates the readable catalog and exact name counts.

The project applies the GSA template's separation of concerns, structured results, bounded requests, freshness reporting and evaluation guidance. It uses the official Python MCP SDK 2.3.0 with the demonstrated IBM STDIO deployment route. The template is guidance; the kickoff explicitly discusses using another project structure.

## Attribution and submission

Original matching/orchestration code is this project's contribution. The upstream service is third party, not CISA-operated. No upstream source code was copied. See [source attribution](THIRD_PARTY.md). Judges need a shareable GitHub repository plus presentation/demo and evaluation; do not assume they can sign into IBM. The November 16 organizer email says the form closes “Midnight EST on Friday, 11/20”; the precise interpretation is unconfirmed, so plan to submit before the end of Thursday, November 19. Runtime remains inside the sandbox.
