"""Build an allowlisted IBM package; never recurse through the whole checkout."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "dist" / "gsa_jc_inventory_advisory"
if DEST.exists():
    shutil.rmtree(DEST)
DEST.mkdir(parents=True)
shutil.copy2(ROOT / "server.py", DEST / "server.py")
shutil.copy2(ROOT / "requirements.lock.txt", DEST / "requirements.txt")
(DEST / "advisory_matcher").mkdir()
for source in sorted((ROOT / "advisory_matcher").glob("*.py")):
    shutil.copy2(source, DEST / "advisory_matcher" / source.name)
print(DEST)

# The reviewed local catalog is part of the runtime, never fetched from a caller URL.
(DEST / "advisory_matcher" / "data").mkdir()
shutil.copy2(ROOT / "advisory_matcher" / "data" / "aliases.json", DEST / "advisory_matcher" / "data" / "aliases.json")

# A separately generated catalog is optional; no runtime network fetch or user path.
catalog = ROOT / "advisory_matcher" / "data" / "cisa_catalog.sqlite3"
if catalog.exists():
    if catalog.is_symlink() or not catalog.is_file() or catalog.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Product catalog is unsafe or exceeds package limit")
    shutil.copy2(catalog, DEST / "advisory_matcher" / "data" / catalog.name)
