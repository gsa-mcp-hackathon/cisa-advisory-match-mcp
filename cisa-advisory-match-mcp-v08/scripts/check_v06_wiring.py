"""Test server function wiring with test-only MCP/HTTP shims, not real protocol."""
import asyncio
import json
import sys
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
class FakeMCP:
    def __init__(self, *a, **kw): self.tools = {}
    def tool(self, **kw):
        def register(f): self.tools[f.__name__] = f; return f
        return register
class Annotations:
    def __init__(self, **kw): pass
class UpstreamError(Exception):
    def __init__(self, code='upstream_unavailable'): self.code=code
async def unused(*args, **kwargs): raise UpstreamError()
fake_mcp = types.ModuleType('mcp.server'); fake_mcp.MCPServer = FakeMCP
fake_types = types.ModuleType('mcp.types'); fake_types.ToolAnnotations = Annotations
fake_upstream = types.ModuleType('advisory_matcher.upstream')
fake_upstream.UpstreamError = UpstreamError
fake_upstream.UpstreamClient = object
fake_upstream.fetch_it_csaf = unused
fake_upstream.fetch_cisa_feed = unused
sys.modules['mcp.server'] = fake_mcp
sys.modules['mcp.types'] = fake_types
sys.modules['advisory_matcher.upstream'] = fake_upstream
import server

class WiringTests(unittest.IsolatedAsyncioTestCase):
    def test_expected_functions_registered(self):
        self.assertEqual(set(server.mcp.tools), {'match_inventory', 'explain_match', 'prepare_product_query', 'read_cisa_it_advisory', 'search_advisory_candidates', 'search_product_catalog'})
    async def test_context_routes_real_local_utility(self):
        result = await server.prepare_product_query(manufacturer='Schneider', product='PLC')
        self.assertTrue(result['product_is_generic_category'])
        self.assertFalse(result['advisories_searched'])
    async def test_catalog_unavailable_is_not_no_match(self):
        result = await server.search_product_catalog('Control Server')
        self.assertEqual(result['applicability'], 'not_assessed')
        self.assertFalse(result['coverage_complete'])
        self.assertIn('error', result)
    async def test_feed_result_and_sanitized_failure(self):
        async def fake(category):
            self.assertEqual(category, 'IT')
            return json.dumps({'feed': {'entry': [{'id': 'fictional', 'title': 'Acme widget'}]}}).encode()
        server.fetch_cisa_feed = fake
        result = await server.search_advisory_candidates('Acme', 'IT', 10)
        self.assertEqual(result['candidate_count'], 1)
        self.assertFalse(result['coverage_complete'])
        self.assertIn('retrieved_at', result)
        server.fetch_cisa_feed = unused
        result = await server.search_advisory_candidates('Acme', 'IT', 10)
        self.assertEqual(result['failure_code'], 'upstream_unavailable')
        self.assertFalse(result['coverage_complete'])
        self.assertEqual(result['applicability'], 'not_assessed')

if __name__ == '__main__': unittest.main(verbosity=2)
