# Product-name source research

Researched 2026-11-06 for the GSA MCP Hackathon ICS product advisory matching wrapper. This is a bounded seed vocabulary, not an exhaustive product register or a proof that an asset is vulnerable.

## Delivered data

- `product_aliases.json`: 40 manufacturer-scoped groups, 100 label entries, 94 distinct label strings; 22 equivalent groups and 18 candidate groups.
- `glossary.json`: eight NIST terminology expansions. These explain inventory terms only. A generic device class such as PLC, HMI, or RTU must not become a confirmed product-name alias.
- Three unchanged public CISA CSAF JSON fixtures plus `additional-fixture-provenance.json` with original URLs, retrieval timestamps, revision, and SHA-256.

Each product group records its source URL, source title, and a rationale. Equivalent groups cover supported acronyms, expanded names, or branded forms of the same named product. Candidate groups identify a possible historical or component relationship that needs review. Historical brand migration does not establish that all releases have identical version numbering, vulnerability applicability, or scope.

## Source observations and limits

- Schneider Electric documents Control Expert as formerly Unity Pro, Machine Expert as succeeding SoMachine and SoMachine Motion, Machine Expert Basic as succeeding SoMachine Basic, and Geo SCADA Expert as formerly ClearSCADA. These remain candidate relationships; Machine Expert Basic and full Machine Expert are separate products.
- AVEVA documents its Edge, Plant SCADA, InTouch HMI, System Platform, and Historian former names. Historical pairs remain candidates because deployment dates, release numbers, and editions matter. Current InTouch HMI branded forms and Operations Management Interface/OMI are separate equivalent groups.
- Rockwell documentation states Logix Designer is the v21 name for RSLogix 5000 and FactoryTalk Linx was called RSLinx Enterprise before v6. Studio 5000 as a whole is not an alias of Logix Designer, and RSLinx Classic is not an alias of RSLinx Enterprise. The FactoryTalk View installation guide supplies the RSView-to-FactoryTalk rename table. Site Edition, Machine Edition, Studio, Client, and Server stay separate. Current SE/ME full-name and acronym pairs are equivalent; former-name groups remain candidates.
- Siemens documentation expands TIA Portal and WinCC OA and uses SIMATIC PCS 7/PCS 7. WinCC OA is kept distinct from WinCC, WinCC Professional, WinCC Unified, and other editions. TIA Portal is not treated as equivalent to any individual engineering component.
- Honeywell explicitly expands EBI, PKS, DVM, and CCS. The existing CISA IQ4E Firmware example is linked to IQ4E only as a candidate because a device and a firmware component are different levels of specificity.
- Hitachi Energy expands PCM600, Mitsubishi supplies MELSOFT-prefixed GX Works2 and GX Works3 labels, Weintek download packages use EBPro and EB8000 alongside their product names, and Advantech uses WebAccess/SCADA and WebAccess SCADA. GX Works2/GX Works3 and EasyBuilder Pro/EasyBuilder8000 stay separate; WebAccess/CNC and WebAccess/NMS are not aliases of WebAccess/SCADA.
- PME has two distinct meanings in this dataset: Schneider Electric Power Monitoring Expert and Emerson PAC Machine Edition. Manufacturer scope is necessary. A global acronym dictionary would create false matches.
- PTC's February 2026 migration guide expands KSE and TKS and explains the move to Kepware Server 7.0. The rename/migration is candidate-only, while the documented acronym pairs are equivalent. Linux Kepware Edge is not added as an alias.

The Rockwell historical SE/ME candidate records deliberately contain only one current label each; the verified current full/short pair appears only in its equivalent record. This avoids contradicting equivalent evidence in a conservative engine. No generic product-family-to-model substitutions or unrestricted acronym expansions were added.

## Exact CSAF fixture anchors

| CISA ID | Exact manufacturer branch | Exact product branch | Source version branch | Baseline input checked |
| --- | --- | --- | --- | --- |
| ICSA-23-150-01 | Advantech | WebAccess/SCADA | 8.4.5 | Version 8.4.5 |
| ICSA-24-086-04 | Rockwell Automation | FactoryTalk View ME | <v14 | Version 13 |
| ICSA-25-028-04 | Rockwell Automation | FactoryTalk View Site Edition | <15.0 | Version 14.0 |

The original v0.1.0 matcher, loaded unchanged from the supplied ZIP, returned affected_range_match for each exact-label input. The third fixture contains two CVEs and returned affected_range_match for both. These baseline checks validate fixture usability; they do not establish that the updated alias engine passes. Integration tests belong to the implementation task.

Public original JSON sources:

- https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2023/icsa-23-150-01.json
- https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2024/icsa-24-086-04.json
- https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2025/icsa-25-028-04.json

## Maintenance

Prefer mappings tied to observed CISA product branches and an official manufacturer's naming evidence. Preserve source URLs and rationales. Recheck historical mappings against version and component data before promoting them to equivalent. Update fixture snapshots deliberately and retain their provenance. These three added fixtures cover specific cases, not every catalog entry or the complete CISA corpus.
