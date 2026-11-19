"""Exercise the actual STDIO MCP protocol; --live uses public upstream services."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import time

from mcp.client import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def check(live: bool, platform_proxy: bool = False) -> dict:
    started = time.perf_counter()
    inventory = json.loads((ROOT / "examples" / "inventory.json").read_text())
    program = ROOT / ("tests/platform_proxy_server.py" if platform_proxy else "server.py" if live else "tests/fixture_server.py")
    proxy_env = None
    if platform_proxy:
        import os
        proxy_env = {key: os.environ[key] for key in ("HTTPS_PROXY", "HTTP_PROXY") if key in os.environ}
    params = StdioServerParameters(command=sys.executable, args=[str(program)], cwd=str(ROOT), env=proxy_env)
    checks = []
    traces = []
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=110) as session:
            init = await session.initialize()
            checks.append({"name": "initialize", "passed": init.server_info.name == "gsa_jc_inventory_advisory"})
            listing = await session.list_tools()
            tools = {t.name: t for t in listing.tools}
            checks.append({"name": "six_tools_discovered", "passed": set(tools) == {"match_inventory", "explain_match", "read_cisa_it_advisory", "prepare_product_query", "search_advisory_candidates", "search_product_catalog"}})
            checks.append({"name": "read_only_annotations", "passed": all(t.annotations.read_only_hint for t in tools.values())})
            for name, args in [
                ("match_inventory", {"inventory": inventory, "advisory_ids": ["ICSA-26-069-03"]}),
                ("explain_match", {"item": inventory[1], "advisory_id": "ICSA-26-069-03"}),
                ("match_inventory", {"inventory": [dict(inventory[0], manufacturer="Honeywell International")], "advisory_ids": ["ICSA-26-069-03"]}),
            ]:
                before = time.perf_counter()
                result = await session.call_tool(name, args)
                payload = result.structured_content
                traces.append({"tool": name, "arguments": args, "elapsed_seconds": round(time.perf_counter()-before, 3),
                               "is_error": result.is_error, "result": payload})
                expected = (["affected_range_match", "outside_checked_affected_ranges", "needs_review", "needs_review", "needs_review"]
                            if name == "match_inventory" and len(args["inventory"]) > 1 else
                            ["affected_range_match"] if name == "match_inventory" else ["outside_checked_affected_ranges"])
                actual = [r["outcome"] for r in payload.get("results", [])] if isinstance(payload, dict) else []
                checks.append({"name": name + ("_alias" if name == "match_inventory" and len(args["inventory"]) == 1 else "") + "_expected_outcomes", "passed": not result.is_error and actual == expected,
                               "expected": expected, "actual": actual})
                checks.append({"name": name + ("_alias" if name == "match_inventory" and len(args["inventory"]) == 1 else "") + "_source_evidence", "passed": bool(payload and payload.get("coverage", {}).get("advisories_checked"))})
            alias_result = traces[-1]["result"]
            alias_findings = alias_result.get("results", [{}])[0].get("findings", []) if isinstance(alias_result, dict) else []
            checks.append({"name": "alias_mapping_provenance", "passed": any(
                identity.get("match_type") == "verified_alias" and identity.get("mappings")
                for finding in alias_findings for entry in finding.get("evidence", [])
                for identity in entry.get("identity_matches", []))})
            it = await session.call_tool("read_cisa_it_advisory", {"advisory_id": "VA-26-295-01"})
            it_payload = it.structured_content
            checks.append({"name": "selected_it_source_only", "passed": bool(not it.is_error and isinstance(it_payload, dict) and it_payload.get("applicability") == "not_assessed" and it_payload.get("search_scope") == "one explicitly selected IT advisory only" and it_payload.get("source_url", "").startswith("https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/"))})
            traces.append({"tool": "read_cisa_it_advisory", "arguments": {"advisory_id": "VA-26-295-01"}, "is_error": it.is_error, "result": it_payload})
            bad_it = await session.call_tool("read_cisa_it_advisory", {"advisory_id": "https://127.0.0.1/private"})
            checks.append({"name": "it_caller_url_rejected", "passed": bool(bad_it.is_error)})
            context = await session.call_tool("prepare_product_query", {"manufacturer": "Schneider", "product": "PLC"})
            cp = context.structured_content
            checks.append({"name": "product_context_clarification", "passed": bool(not context.is_error and isinstance(cp, dict) and cp.get("product_is_generic_category") and not cp.get("advisories_searched") and any(q.get("field") == "product" for q in cp.get("clarifying_questions", [])))})
            traces.append({"tool": "prepare_product_query", "is_error": context.is_error, "result": cp})
            feed_result = await session.call_tool("search_advisory_candidates", {"query": "Acme" if not live else "PHP", "category": "IT"})
            fp = feed_result.structured_content
            checks.append({"name": "it_feed_metadata_search", "passed": bool(not feed_result.is_error and isinstance(fp, dict) and not fp.get("error") and fp.get("search_scope") == "feed title and summary only" and fp.get("coverage_complete") is False and fp.get("applicability") == "not_assessed")})
            traces.append({"tool": "search_advisory_candidates", "is_error": feed_result.is_error, "result": fp})
            invalid_feed = await session.call_tool("search_advisory_candidates", {"query": "Acme", "category": "https://127.0.0.1"})
            checks.append({"name": "feed_destination_rejected", "passed": bool(invalid_feed.is_error)})
            catalog = await session.call_tool("search_product_catalog", {"product": "fictional widget"})
            catalog_payload = catalog.structured_content
            checks.append({"name": "catalog_scope_or_unavailable", "passed": bool(not catalog.is_error and isinstance(catalog_payload, dict) and catalog_payload.get("applicability") == "not_assessed" and catalog_payload.get("coverage_complete") is False and (catalog_payload.get("error") or catalog_payload.get("manifest")))})
            traces.append({"tool": "search_product_catalog", "is_error": catalog.is_error, "result": catalog_payload})
            bad = await session.call_tool("match_inventory", {"inventory": []})
            checks.append({"name": "empty_inventory_rejected", "passed": bool(bad.is_error)})
            bad = await session.call_tool("explain_match", {"item": inventory[0], "advisory_id": "https://127.0.0.1/private"})
            checks.append({"name": "caller_url_rejected", "passed": bool(bad.is_error)})
    return {"recorded_at": datetime.now(timezone.utc).isoformat(),
            "execution_environment": "caller runtime; see run record for IBM versus Codex", "platform_proxy_test_harness": platform_proxy,
            "mode": "live" if live else "offline_fixture",
            "passed": all(c["passed"] for c in checks), "checks": checks, "traces": traces,
            "elapsed_seconds": round(time.perf_counter()-started, 3),
            "agent_behavior_tested": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Call the public CISA MCP and official CSAF source.")
    parser.add_argument("--platform-proxy", action="store_true", help="Test-only trusted platform HTTPS proxy; requires --live.")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.platform_proxy and not args.live:
        parser.error("--platform-proxy requires --live")
    report = asyncio.run(check(args.live, args.platform_proxy))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "traces"}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)


if __name__ == "__main__":
    main()
