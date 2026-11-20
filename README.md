# CISA Advisory Matching MCP

**GSA MCP Hackathon submission — version 0.8.0 candidate**

CISA Advisory Matching MCP helps analysts explore public CISA IT and operational technology advisories using an MCP server and an IBM watsonx Orchestrate agent. It identifies product-name candidates for review and compares supported fictional ICS device inventory with published advisory version rules. Results include source links, identity-review information, and coverage limits.

## Quick start

The full source, setup, and build instructions are in the [`cisa-advisory-match-mcp-v08/`](cisa-advisory-match-mcp-v08/) directory.

| File | Purpose |
|---|---|
| [`cisa-advisory-match-mcp-v08/README.md`](cisa-advisory-match-mcp-v08/README.md) | Setup, tools, supported comparisons, and limits |
| [`cisa-advisory-match-mcp-v08/CATALOG_BUILD.md`](cisa-advisory-match-mcp-v08/CATALOG_BUILD.md) | How to build the product catalog from the pinned public CISA snapshot |
| [`cisa-advisory-match-mcp-v08/config/gsa_jc_inventory_agent_v08.yaml`](cisa-advisory-match-mcp-v08/config/gsa_jc_inventory_agent_v08.yaml) | IBM Orchestrate agent configuration |
| [`cisa-advisory-match-mcp-v08/server.py`](cisa-advisory-match-mcp-v08/server.py) | MCP server entry point (STDIO) |
| [`cisa-advisory-match-mcp-v08/test-results/`](cisa-advisory-match-mcp-v08/test-results/) | IBM verification and agent test records |

## Catalog database

The SQLite product catalog is **not included** in this repository. It is derived from public CISA data and must be built before running the full test suite or the catalog search tool. See [`CATALOG_BUILD.md`](cisa-advisory-match-mcp-v08/CATALOG_BUILD.md) for the exact steps, pinned source commit, and expected build output.

## Project summary

An MCP wrapper calls the public [cyanheads CISA MCP server](https://github.com/cyanheads/cisa-cybersecurity-mcp-server) to discover ICS advisories and check KEV, then compares product and version details against published version rules in original [CISA CSAF](https://github.com/cisagov/CSAF) documents using deterministic code — no model makes the version comparison. A local offline catalog of CSAF product names supports candidate discovery for both IT and OT advisories without a network call; returned candidates require identity review and do not establish version applicability or complete coverage. A selected IT advisory reader retrieves and summarises a single explicitly identified CISA advisory by ID; it explains the advisory content but does not perform an inventory applicability assessment for IT products. An IBM watsonx Orchestrate native agent calls the six MCP tools and reports findings with source citations, uncertainty labels, and coverage disclosures.

See [`docs/evaluation.md`](cisa-advisory-match-mcp-v08/docs/evaluation.md) for measured results and [`docs/aliases.md`](cisa-advisory-match-mcp-v08/docs/aliases.md) for the alternate-name catalog and sources.
