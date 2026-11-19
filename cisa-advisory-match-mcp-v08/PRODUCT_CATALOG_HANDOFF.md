# Product catalog candidate 0.8.0: IBM verification handoff

This is a separately prepared candidate. Do not overwrite the working v0.6 project, toolkit, agent, configuration or test records, and do not register this candidate until its tests pass. The ZIP has no generated catalog database or credentials.

Bob reported that v0.7 indexed 108 of 111 IT and 4,009 of 4,011 OT snapshot paths. Three documents had filename/tracking-ID disagreements, one contained duplicate JSON object keys and one had a 764-character product name. Those are reports from v0.7, not results for this revised candidate. The source revision was `1cd0e9e91ab4a57d6e3631597fd0c06908b70bb2`. Retain those original results.

## First task: verify locally on IBM, then report and stop

1. Check the ZIP SHA-256 supplied with the download and extract to a new directory. Use the existing local, verified CISA snapshot; do not redownload it. Verify its revision and source without revealing credentials. Record the actual path and commit. Use a separate Python environment or the existing v0.7 project environment only if compatible; do not alter the ADK or starter environments.
2. Run the full project test suite using the pinned development dependencies. Build a NEW catalog database using `scripts/build_product_catalog.py`, the existing snapshot and its full commit. The builder refuses to overwrite an existing database. Report index counts, failure reason counts, complex document counts, number of product rows and file size. In particular, test whether the 764-character name now indexes; do not assume the other failures disappeared. Keep filename/tracking ID mismatches and duplicate JSON keys rejected and visible.
3. Run the offline MCP check, plus real STDIO calls to `search_product_catalog` with the new database, including exact names, documented manufacturer-scoped aliases, bare product names, an IT example, a no-result case, and a result limit of 5. Capture actual call arguments, candidate_count, candidates array length, omission count, match basis, review flags, and source hashes. Compare original source files and pinned source links; report actual results. Candidate count is product rows, not distinct advisories. Results from different advisories are prioritized, but bounds can still hide leads.
4. Confirm catalog absence/failure and existing input/network security boundaries remain safe. Results are leads, not product applicability, affected status, KEV, or proof of safety. Report what's tested, failed and not tested, and stop.

## Later registration and agent testing

Once verification passes, build `dist/gsa_jc_inventory_advisory` with `scripts/package_runtime.py`; inspect the exact file list, catalog inclusion and size. Create a new, separately named six-tool MCP toolkit only after checking installed ADK help and current registrations. Do not overwrite the v0.6 toolkit or the starter. Do not retry an uncertain import until checking whether it succeeded.

Start from the existing live tested CISA agent configuration at `/home/itzuser/wxo-agentic-workflow/config/gsa_jc_inventory_agent_v01.yaml`, preserve it, and create a separate agent. Carefully merge the catalog instructions from `docs/agent-instructions.txt`; the package instructions are a reference, not a replacement for the live tested instructions. Verify manufacturer and component words are preserved and KEV true/false/unknown/not-checked distinctions, including CVE and catalog snapshot details. Test real tool calls, alternate names, missing identity, injection-like source text, IT limitations, and catalog failures. Capture tool traces and outputs without credentials.

## Scope and safeguards

Search is deterministic and bounded. It uses literal phrases and, when a manufacturer is supplied, bounded, direct, manufacturer-scoped mappings from the existing alias catalog. All alias results require identity review. It does not recursively infer aliases, establish applicability, or interpret CSAF relationships or product groups. Flat source names have no inferred manufacturer and cannot be found with a manufacturer filter. Counts are rows, not advisories; a 200,000-row scan cap and return limit apply. A missing result is not a safety result.

Source URLs use the supplied commit when one is supplied, but that operator-provided commit and local origin are not authenticated automatically. Source text is untrusted. Use public sources and fictional inventory only; never paste secrets, API keys or event codes into chat, logs, files or GitHub.
