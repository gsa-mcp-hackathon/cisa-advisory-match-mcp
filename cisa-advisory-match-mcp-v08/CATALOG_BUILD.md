# Rebuilding the product catalog

The `advisory_matcher/data/cisa_catalog.sqlite3` file is not committed. Build it from the public CISA CSAF repository at the recorded snapshot revision before running the full test suite or packaging the runtime.

## Recorded public snapshot

| Field | Value |
|---|---|
| Repository | `https://github.com/cisagov/CSAF` |
| Branch | `develop` |
| Verified commit | `1cd0e9e91ab4a57d6e3631597fd0c06908b70bb2` |
| Commit timestamp | 2026-11-17 10:10:51 -0700 |
| Commit message | Merge pull request #517 from cisagov/publish-2026-11-17 |
| IT index SHA-256 | `af00ccd619852042e4cc1c86eb251dcbf6a99f58ec20574cce0367cdfe5f3e3e` |
| OT index SHA-256 | `a86f125452643822f716a1a04f924a7ba0bbccea0f5c3b9f3234df73a68a8f4d` |

The index hashes identify the bytes of `csaf_files/IT/white/index.txt` and `csaf_files/OT/white/index.txt` at that commit. Verify them after checkout.

## Steps

```bash
# 1. Check out the public CSAF repository at the recorded commit
git clone https://github.com/cisagov/CSAF.git csaf-snapshot
git -C csaf-snapshot fetch --unshallow 2>/dev/null || true
git -C csaf-snapshot checkout 1cd0e9e91ab4a57d6e3631597fd0c06908b70bb2

# 2. Create and activate the project virtual environment
python3.12 -m venv .venv
.venv/bin/pip install -r requirements-dev.lock.txt

# 3. Build the catalog (output path must not already exist)
.venv/bin/python scripts/build_product_catalog.py \
  /path/to/csaf-snapshot \
  advisory_matcher/data/cisa_catalog.sqlite3 \
  --revision 1cd0e9e91ab4a57d6e3631597fd0c06908b70bb2

# 4. Run the full test suite
.venv/bin/python -m pytest -q

# 5. Run the offline and live MCP checks
.venv/bin/python scripts/check_mcp.py --output test-results/local-offline.json
.venv/bin/python scripts/check_mcp.py --live --output test-results/local-live.json
```

## Expected build output (IBM verification, 2026-11-17)

| Scope | Entries | Indexed | Failed | Failure reasons | Complex docs |
|---|---|---|---|---|---|
| IT | 111 | 108 | 3 | `id_filename_mismatch` ×3 | 1 |
| OT | 4011 | 4010 | 1 | `duplicate_json_member` ×1 | 52 |

Generated database: 28,713 product rows, 4,118 distinct advisories, 13.64 MiB.

The three IT failures and one OT failure are known source-data issues and are intentionally kept visible. An incomplete catalog cannot establish absence of advisories for unindexed paths.
