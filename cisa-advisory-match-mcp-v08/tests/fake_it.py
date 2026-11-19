"""Explicit local IT source fixture. Never used as a live fallback."""
import hashlib
import json
from pathlib import Path
from advisory_matcher.it_advisories import it_source_url

async def fake_fetch_it_csaf(advisory_id):
    fixture = Path(__file__).parent / "fixtures/it-source-synthetic.json"
    raw=fixture.read_bytes()
    return {"document":json.loads(raw), "source_url":it_source_url(advisory_id),
            "sha256":hashlib.sha256(raw).hexdigest(), "retrieved_at":"synthetic-fixture-not-live"}
