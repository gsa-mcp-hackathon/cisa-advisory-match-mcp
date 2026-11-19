"""Deterministic public-advisory fixture client; never a live-mode fallback."""
import copy
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from advisory_matcher.upstream import UpstreamError

FIXTURE = Path(__file__).parent / "fixtures" / "icsa-26-069-03.json"
ADVISORY_ID = "ICSA-26-069-03"


class FakeClient:
    data_mode = "recorded_public_fixture_not_live"

    def __init__(self):
        self.calls = []
        self.fail = set()
        self.pages = None
        self.document = json.loads(FIXTURE.read_text())

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        pass

    async def call_tool(self, name, args):
        self.calls.append((name, copy.deepcopy(args)))
        if name in self.fail:
            raise UpstreamError("Simulated unavailable source.")
        if name == "cisa_list_reference":
            return {"sources": {"csafMirror": {"ready": True, "syncStatus": "complete", "failedDocumentCount": 0,
                "checkpoint": "2026-11-03T06:00:00Z", "lastCompletedAt": datetime.now(timezone.utc).isoformat()}}}
        if name == "cisa_search_ics_advisories":
            if self.pages is not None:
                return self.pages[1 if args.get("cursor") else 0]
            return {"results": [{"advisoryId": ADVISORY_ID}], "hasMore": False, "totalCount": 1,
                    "mirror": {"checkpoint": "2026-11-03T06:00:00Z"}}
        if name == "cisa_get_advisory":
            return {"found": True, "advisory": {"advisoryId": args["advisoryId"], "revision": "2"}}
        if name == "cisa_check_cve_status":
            return {"results": [{"cveId": x, "inKev": False} for x in args["cveIds"]],
                    "catalog": {"catalogVersion": "fixture-2026.11.04"}}
        raise AssertionError(name)

    async def fetch_csaf(self, advisory_id):
        if "fetch_csaf" in self.fail:
            raise UpstreamError("Simulated source unavailable.")
        return {"document": copy.deepcopy(self.document),
                "source_url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/2026/icsa-26-069-03.json",
                "sha256": hashlib.sha256(FIXTURE.read_bytes()).hexdigest(), "retrieved_at": "fixture-not-a-live-fetch"}
