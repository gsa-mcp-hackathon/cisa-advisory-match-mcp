"""Offline protocol-test process, clearly labelled with recorded fixture mode."""
import sys
import json
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
import server
from fake_client import FakeClient
from fake_it import fake_fetch_it_csaf

async def fake_feed(category):
    return json.dumps({"feed": {"entry": [{"id": "SYNTHETIC-1", "title": "Acme fictional widget advisory", "summary": {"content": "Acme Widget"}}], "link": []}}).encode()

server.fetch_cisa_feed = fake_feed
server.UpstreamClient = FakeClient
server.fetch_it_csaf = fake_fetch_it_csaf
server.mcp.run(transport="stdio")
