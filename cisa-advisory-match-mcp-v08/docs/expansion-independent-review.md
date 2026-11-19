# GSA MCP Hackathon: independent expansion review

Reviewed November 6, 2026. This review covers the v0.3 local name catalog, identity boundaries and selected unchanged CISA advisory examples. It is separate from the coordinating agent's full suite, corpus naming audit, live MCP checks and IBM evaluation.

## Findings and corrections

Three proposed automatic name relationships were made review-only following independent primary-source checks:

- **Siemens PDM:** Siemens also uses PDM for product data management. The catalog keeps `SIMATIC PDM` and `Process Device Manager` equivalent, but the bare `PDM` relationship requires identity review. It does not propagate through the equivalent pair to a third label. Sources: [Siemens PDM definition](https://www.siemens.com/en-gb/technology/product-data-management-pdm/) and the product-specific source retained in the catalog.
- **Siemens ALM:** Siemens also supplies Polarion application lifecycle management, so the bare `ALM` name cannot establish Automation License Manager identity from manufacturer alone. Sources: [Polarion](https://www.siemens.com/en-gb/products/polarion/) and [Siemens development white paper](https://static.sw.cdn.siemens.com/siemens-disw-assets/public/2bEgGR68qkb6UngKC5nkHP/en-US/Achieving-software-development-agilit-in-complex%2C-regulated-environments_tcm27-103296.pdf).
- **AVEVA Historian:** AVEVA uses Historian as shorthand and as an earlier product name, while offering other historian products. The bare name now prompts review. Sources: [Historian product page](https://www.aveva.com/en/products/historian/), [data-management portfolio](https://www.aveva.com/en/solutions/data-management/) and [PI Server](https://www.aveva.com/en/products/aveva-pi-server/).

No additional blocking defect was found in the checked paths after those changes. This is a scoped review, not independent verification of every source or every possible inventory label.

## Observed checks

`tests/test_expansion_review.py`: **32 passed in 0.07 seconds** using the local test environment after the final ALM correction.

The tests cover ambiguous acronyms, manufacturer scope, candidate relationships, product-family context, unchanged input/source data, provenance, regional part numbers, versions, wrong manufacturers, sibling models and editions, hardware/software boundaries, and successor relationships. Synthetic cases test implementation policy; they do not measure real-world matching accuracy.

A separate comparison of every directional pair in each documented group, in every declared product scope, found **zero policy discrepancies across 1,144 comparisons**. This checks consistency between catalog policy and engine output. It does not establish the factual accuracy of all mappings or search completeness.

Four new fixtures are original bytes from CISA CSAF commit `020f7c01c13b08df34a9557e734d76ed7943c537`. Their Git blob hashes were independently compared with the downloaded pinned repository tree. SHA-256 values, source URLs and revisions are recorded in `tests/fixtures/expansion-fixture-provenance.json`.

| Original advisory | Fictional input used in test | Observed result and boundary |
| --- | --- | --- |
| ICSA-22-242-03, revision 1 | Hitachi Energy, Modular Switchgear Monitoring | Source MSM `<= 2.2`: version 2.2 matches; 2.3 is outside that range. MSM-I and MSM-II do not inherit the parent name. |
| ICSA-25-072-07, revision 3 | Siemens, exact NAM article number `6GK5876-4AA00-2DA2` | Source rule `vers:intdot/<8.2.1`: 8.2 matches; 8.2.1 is outside. The EU article number selects a different source product ID. A generic M876-4 label and an altered SKU do not match. |
| ICSA-14-133-01, revision 2 | Yokogawa, Plant Resource Manager, version 3.11.20 | The PRM identity is recognized, but source rule `<=R3.11.20` remains unsupported; all four linked CVEs require review. |
| ICSA-20-212-04, revision 14 | Mitsubishi Electric, MELSOFT GX Developer, version 8.504A | The manufacturer-prefixed source identity is recognized, but the letter-suffixed version remains unsupported and requires review. |

An additional source candidate, ICSA-19-253-03, lists the NAM SKU in its product tree but links the vulnerability statuses to another product ID. It was not used as a positive match fixture. Product-tree presence alone does not establish a vulnerability association.

## Primary-source spot checks

These selected checks assess the meaning of the proposed labels and their exclusions, beyond testing the catalog against itself:

| Name relationship | Source finding and retained boundary |
| --- | --- |
| Yokogawa PRM | [Product page](https://www.yokogawa.com/solutions/products-and-services/information/asset-management/field-device-management-prm/) directly defines Plant Resource Manager. The alias remains manufacturer-scoped. |
| Yokogawa VDS | [Release-kit specification](https://library.yokogawa.com/document/download/AxkHnJ89/0000022517/15/EN/) distinguishes ASTMAC VDS from the separate ASTMAC application. Bare ASTMAC is excluded. |
| Honeywell SM | [Manufacturer page](https://process.honeywell.com/us/en/products/trainings/control-monitoring-and-safety-systems/safety-manager-sm) directly defines Safety Manager. Qualified SC/model names are not stripped. |
| Hitachi Energy MSM | [Product page](https://www.hitachienergy.com/us/en/products-and-solutions/high-voltage-switchgear-and-breakers/monitoring-and-controlled-switching/modular-switchgear-monitoring-msm) defines Modular Switchgear Monitoring and separately describes MSM-I and MSM-II. |
| Siemens regional article number | [Operating instructions](https://support.industry.siemens.com/cs/attachments/109988557/BA_SCALANCE-M87x_76_en-US.pdf?download=true) associates the complete article number with NAM and distinguishes the EU/worldwide variants. Search-indexed primary text was available; direct PDF fetch was blocked in this session. |
| Siemens Information Server | [Product documentation](https://docs.tia.siemens.cloud/r/en-us/v20/process-historian-and-information-server-rt-professional/basics-rt-professional/information-server-rt-professional) introduces SIMATIC Information Server and uses the shorter name. No concrete competing identity was found in this focused check. |
| Triangle MicroWorks Test Harness and DTM | [Support page](https://files.trianglemicroworks.com/support/test-harness) uses all three Test Harness labels for one application. [DTM page](https://www.trianglemicroworks.com/products/testing-and-configuration-tools/dtm-pages/overview) explicitly defines Distributed Test Manager; another manufacturer's DTM does not match. |
| SEL acSELerator RTAC | [Product page](https://selinc.com/products/5033/) identifies configuration software separately from the RTAC controller. Bare RTAC is excluded from the software group. |
| Moxa MXview | [Manufacturer replacement notice](https://moxa.com/en/products/industrial-network-infrastructure/network-management-software/mxview-series) identifies MXview One as a replacement. The successor relationship remains review-only. |
| Horner organizations | [About page](https://hornerautomation.com/about-us/) describes Horner Automation and other groups within Horner APG. Their relationship remains a candidate, while Automation/Automation Group remain the same documented label. |
| NI | [Imprint](https://www.ni.com/en/about-ni/legal/imprint.html/) identifies National Instruments Corporation and separately describes its Emerson ownership. The catalog does not automatically equate NI and Emerson. |
| Johnson Controls | [Company history](https://www.johnsoncontrols.com/building-insights/2021/history/this-month-in-history-october-2021) supports the Inc. name; punctuation variants are observed CISA labels. The International plc relationship remains a candidate. |

## Limits retained

- Matching recognizes documented direct relationships only. Candidate relationships never become automatic affected-range decisions, and relationships do not travel through a chain of names.
- Matching is still subject to the source's product IDs, vulnerability statuses, version grammar and additional product context. A recognized name is not proof that an installed asset is vulnerable or safe.
- Advisory discovery remains bounded: at most three manufacturer terms per input manufacturer and twelve total search requests, with omissions reported. More catalog names do not mean every alias or every advisory was searched.
- The corpus audit measures naming coverage separately. The four fixtures above are selected examples, not a representative accuracy sample or full-corpus vulnerability validation.
- No IBM runtime, IBM agent tool-selection test, user-system inventory or production device was accessed by this reviewer.
