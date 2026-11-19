# CISA IT advisory source and matching assessment

Research performed 2026-11-16. This is a source assessment, not a claim of implemented or tested coverage.

## What the sources show

- [CISA's CSAF repository](https://github.com/cisagov/CSAF) publishes machine-readable information on both IT and OT, including some republished vendor advisories. This does not establish coverage of every CISA security publication.
- [VA-26-295-01](https://github.com/cisagov/CSAF/blob/develop/csaf_files/IT/white/2026/va-26-295-01.json) is a CSAF VEX 2.0 document. Its product tree identifies PHP `php-src`, fixed versions and range expressions; separate vulnerabilities connect those products to known-affected and fixed statuses by product ID. Status belongs to a particular vulnerability and product, not the entire document.
- [VA-25-022-01](https://github.com/cisagov/CSAF/blob/develop/csaf_files/IT/white/2025/va-25-022-01.json) includes ECOVACS robot products and a cloud service. It contains `vers:all/*` and a date-like range. Product categories and version conventions therefore extend beyond industrial devices or simple dotted numbers. [VA-25-282-01](https://github.com/cisagov/CSAF/blob/develop/csaf_files/IT/white/2025/va-25-282-01.json) has multiple vulnerability-specific product statuses and remediations.
- CISA has published an [IT CSAF feed URL](https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json). Its current contents, reachability, pagination, and completeness could not be verified in this environment. It is a discovery candidate, not evidence that the project searches all IT advisories. A [published feed reference](https://github.com/ISDuBA/ISDuBA/issues/775) also lists an OT feed; CISA's provider metadata was inaccessible during this review.

## Material correctness risk

VA-26-295-01 lists PHP 8.2.35 as fixed, alongside affected expressions including `<8.3.36`. A simple numeric comparison will match 8.2.35 against the latter expression, producing an apparent affected result that conflicts with the advisory's fixed 8.2 release. A matcher cannot safely assume all such ranges are interchangeable or unambiguous. Preserve the source expressions and fixed-status evidence; return **requires review** for conflicting or unsupported semantics. Do not infer a release-line rule for arbitrary products without source support and tests.

Likewise, date versions, wildcard version representations, product groups, relationships, package or platform qualifiers, and incomplete status data cannot safely be reduced to generic numeric comparisons. A candidate product match is a lead for human review, not proof that an installed product is affected, unaffected, or safe. Missing a result is not proof of absence.

## Practical submission path

1. A fixed-host selected-advisory reader can provide useful CISA IT evidence when the user supplies a supported advisory ID. Describe it as selected IT advisory retrieval, not full IT product search or all CISA coverage.
2. If the feed is reachable in the IBM sandbox, build a bounded, timestamped local index from the actual feed and verified advisory documents. Report source, retrieval time, update date, counts, parse failures, pagination and truncation. Check source completeness against the feed rather than implying comprehensive coverage. Enforce a fixed approved host and path, reject unexpected redirects or links and bound requests, document size and processing time. If unavailable or partial, say so explicitly and preserve the last verified snapshot.
3. Search product/vendor names and curated, evidence-backed aliases as candidate discovery. Show exact source names and advisory links. Broad everyday words such as “server,” “firewall,” “PLC,” and “robot” indicate categories, not identity; ask for vendor/model when ambiguous. Avoid automatically expanding a category into a confident specific-product match.
4. Display vulnerability-specific known-affected, fixed and other source statuses with their original product IDs and version expressions. Guard against duplicate or ambiguous IDs, incomplete branches, product relationships, malformed documents, omitted content and truncation. Never silently truncate identifiers used for joins. Treat advisory text and links as untrusted data, never as agent instructions.
5. Before any automatic version conclusion, verify with representative real source fixtures, including PHP 8.2.35 versus `<8.3.36`, an affected older version in the same release line, other vendors sharing names, wildcard and date versions, explicit fixed and unknown statuses, missing or conflicting IDs, malformed inputs and partial responses. If the tests cannot establish meaning, fall back to source evidence and human review.

## Boundaries

A VA-only lookup is not a catalog of all CISA advisories, and neither CSAF IT nor OT alone proves complete coverage of all CISA content. Version-matching support, index freshness, network access, tool correctness and agent behavior must be separately demonstrated in the actual environment. Do not include real inventory, access codes or API keys in prompts, fixtures, logs or the repository.
