# Source attribution

- **CISA CSAF:** Original government advisory ICSA-26-069-03, revision 2, included unchanged as a test fixture with source URL and SHA-256 in `tests/fixtures/provenance.json`. Repository: https://github.com/cisagov/CSAF . The upstream repository does not declare a general repository license; preserve source attribution and verify terms for any other materials added later.
- **cyanheads/cisa-cybersecurity-mcp-server:** Third-party retrieval/enrichment service, Apache-2.0 project. Inspected commit `a0d08cbf67fdfa8d42bd25244afaeacd06d56208`, hosted version 0.4.0 on November 5, 2026. https://github.com/cyanheads/cisa-cybersecurity-mcp-server . No source code from that repository is copied here.
- **GSA template:** Guidance for structured tools, source freshness, security and evaluation. MIT-licensed template: https://github.com/GSA-TTS/mcp-hackathon-template . This implementation adapts design guidance; it is not an unchanged fork.
- **MCP Python SDK:** Official protocol implementation, https://github.com/modelcontextprotocol/python-sdk . Runtime dependencies are pinned in `requirements.lock.txt`; their individual licenses remain applicable.

IBM materials were reviewed for setup/testing guidance. No video transcripts, access codes, player configurations, private emails or credentials are included. Project source licensing has not been selected; do not imply that a third-party license automatically licenses this project's original code.

## Version 0.2 additions

Three additional unchanged CISA public advisory fixtures are included: ICSA-23-150-01, ICSA-24-086-04 and ICSA-25-028-04. URLs, revisions, retrieval timestamps and SHA-256 hashes are in `tests/fixtures/additional-fixture-provenance.json`.

The alias catalog records factual names and short original paraphrases with source links to official vendors and CISA. Vendor manuals, websites, logos and extended text are not bundled. Source links and rationale do not grant a license to third-party materials. NIST terminology links are in `docs/aliases.md`; the NVD CPE dictionary is not imported.

## Version 0.3 additions

The offline coverage audit uses public CISA CSAF commit `020f7c01c13b08df34a9557e734d76ed7943c537`, containing 3,995 advisories and one feed metadata JSON. The package retains factual product-name extracts, per-file hashes and source URLs, and a reproducible audit script. The complete downloaded corpus is not included and is not loaded by the runtime. The source corpus includes CISA partner republications; no general license is inferred from government hosting.

Four additional unchanged public CISA fixtures are retained under `tests/fixtures/expansion/`, with URLs, revisions and hashes in `expansion-fixture-provenance.json`. They are used for selected identity and version regression cases, with original attribution preserved. Manufacturer pages and manuals are referenced as sources for factual names and short original rationales; they are not reproduced as documents.
