# Security and scope

This prototype uses fictional inventory and public CISA government advisories. It is read-only. There is no device scanning, shell tool, remediation action, inventory database or user-selected destination.

The production transport has fixed HTTPS endpoints, TLS verification, no redirects, ten-second deadlines, 2 MiB prebuffer response limits and rejected non-identity compression. Official MCP SDK handles the protocol. Error messages use fixed codes; upstream response bodies, credentials and arbitrary exception strings are not returned. Raw CSAF JSON rejects duplicate members and nonfinite numbers, validates the requested advisory identity, and records SHA-256 plus revision and retrieval time.

Production ignores proxy environment variables. `tests/platform_proxy_server.py` is a separately selected test harness for a trusted executor's networking; it is excluded from the allowlisted IBM runtime. Direct IBM networking remains a separate test.

Inventory is bounded to 20 rows/four manufacturers. Versions and asset IDs are not sent to the upstream service; vendor names, advisory IDs and CVEs are. This data minimization is tested. Do not submit actual organizational inventory to the public service or vendor sandbox.

Source prose remains untrusted data even when returned from a legitimate tool. No code path executes it. The agent must also ignore any instructions embedded in it; that behavior needs separate model/agent tests. Our deterministic injection regression does not prove model resistance. Read-only MCP annotations are descriptive hints, not security enforcement.

Search pagination, document budgets, stale/unknown refresh information, source/index revision differences, unknown KEV and processing failures remain visible. A timestamp is not proof of current completeness. The 48-hour refresh warning is a project test policy, not a CISA service guarantee. Final output has a 256 KiB budget; omitted evidence produces review status.

Known limitations: exact labels can miss aliases; firmware naming semantics vary; product-family/component relationships and some CSAF structures are unsupported; no full CSAF schema validator is bundled. The hosted upstream is a third-party dependency with no availability guarantee established here. This release has no production authorization or public deployment.

## Alternate-name catalog

The versioned catalog is local operator-maintained package data. No advisory, user input or live page can modify it. Mapping source URLs are references only; runtime lookup does not fetch arbitrary alias-source URLs. Names are explicitly listed and manufacturer-scoped. Candidate relationships cannot become confirmed product identity, and mappings are not transitively closed. Discovery expands only manufacturer labels and remains bounded by a shared request budget. Input labels and provenance remain visible. Catalog load/validation errors fail closed rather than falling back to an untracked alias list.

## Version 0.4 review updates

For bounded discovery, an index refresh timestamp that is missing, malformed, stale by more than 48 hours, or over one hour in the future marks selection incomplete. This is a conservative prototype policy, not a guarantee of freshness within the threshold. Explicitly selected original advisories retain the timestamp warning without automatically being rejected solely due to index age.

Search-page metadata can also invalidate selection: an explicit not-ready flag, unfinished sync, positive failed-document count, or stale/future completion timestamp keeps that query incomplete even when the general source reference is healthy. A later healthy page does not erase an earlier conflict. Missing or unusable optional page timestamps are reported as unknown; they do not independently verify page freshness. Original-source positive findings remain visible alongside incomplete coverage.

Relationship-generated product identities cannot currently be interpreted fully. If a document contains relationships and would otherwise yield no applicable findings, it is flagged for review instead of a clean no-match. This can conservatively flag an unrelated relationship; nonempty findings still require their normal review.

The code cannot verify inputs are fictional. Manufacturer labels leave the process during public upstream discovery. Use only fictional inventory and public source material in the hackathon sandbox. Prompt-injection behavior of an IBM agent remains unverified.

A healthy reference timestamp alone does not prove that every search used a fresh index. Missing or unusable page timestamps are unknown. Treat discovery completeness as bounded and subject to this limitation. If the reference call itself fails, `source_freshness` may be absent; the overall candidate selection is marked incomplete.


## Candidate v0.5: IT source reader and version guard

`read_cisa_it_advisory` accepts one constrained `VA-YY-DDD-NN` identifier, constructs a fixed CISA GitHub source URL and rejects invalid dates, malformed IDs and a mismatched source tracking ID. It rejects duplicate, empty, overlong and control-character product IDs instead of truncating identifiers and accidentally associating different products. Duplicate JSON members and nonfinite values are rejected. The response preserves the distinction between source status and a decision: applicability is `not_assessed`, KEV is `not_checked`, and only the selected document was read.

The source request has a 20-second overall budget, ten-second network timeout and 2 MiB response limit. The summary is capped at 20 product branches, 10 vulnerabilities and 40 product IDs per status, with omitted counts. Deep or malformed structures fail closed; long source text can be truncated. Relationships and flat product structures are flagged rather than interpreted. This reader does not accept URLs, search all IT advisories, or determine whether an asset is affected. It supports only a subset of IT IDs; no exhaustive coverage claim is justified.

Multiple distinct one-sided affected version bounds within one ICS finding can describe different release lines. The matcher returns `needs_review` in that situation rather than relying on a numeric comparison. This conservative guard does not establish that a lone open-ended rule lacks release-line context. A person must review the source and mitigation guidance.

**Verification boundary:** deterministic fixture tests check source labeling and selected error cases, but do not demonstrate IBM agent resistance to prompt injection or live IT connectivity. Read-only tool annotations are hints rather than enforcement. Treat all source text as untrusted; keep keys and real inventory out of the sandbox. Do not publish the STDIO tool as a remote service without separate authentication, authorization, network, abuse and deployment reviews. The current local transport is not an authorization mechanism for a public endpoint. Relevant guidance includes [MCP security best practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices) and the [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html).


## Candidate v0.6: local clarification and experimental feed discovery

The product-query helper treats broad IT and OT equipment words as category cues and returns clarification questions. It preserves explicitly supplied identity fields but does not extract identity from user prose, assert aliases, contact sources, or evaluate applicability. Category cues cannot establish product identity. Malformed advisory vulnerability entries and product-status data are also sent for review instead of being silently discarded as a no-match; the focused local tests do not establish complete CSAF schema coverage.

The new discovery capability is designed to read titles and summaries from one selected CISA IT or OT feed at fixed public sources with bounded requests and no caller-specified URL. Feed titles are untrusted data and matches are leads only. The feed schema, availability, completeness and live behavior have not been verified in this environment. A failed, omitted or incomplete feed and an empty title or summary search cannot justify a safety claim. The agent must not follow instructions in titles or source text; controlled agent behavior testing in IBM remains pending. Do not submit real inventory or secrets in this public-data sandbox.
