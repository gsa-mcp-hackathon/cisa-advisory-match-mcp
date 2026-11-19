"""One bounded live discovery check; no corpus-completeness claim."""
import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time

from mcp.client import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


async def check(proxy):
    started = time.perf_counter()
    env = {k: os.environ[k] for k in ("HTTPS_PROXY", "HTTP_PROXY") if k in os.environ} if proxy else None
    program = ROOT / ("tests/platform_proxy_server.py" if proxy else "server.py")
    args = {"inventory": json.loads((ROOT / "examples/inventory.json").read_text()), "max_advisories": 1}
    async with stdio_client(StdioServerParameters(command=sys.executable, args=[str(program)], cwd=str(ROOT), env=env)) as (read, write):
        async with ClientSession(read, write, read_timeout_seconds=110) as session:
            await session.initialize()
            result = await session.call_tool("match_inventory", args)
            data = result.structured_content or {}
    coverage = data.get("coverage", {})
    passed = (not result.is_error and len(data.get("results", [])) == 5
              and len(coverage.get("advisories_checked", [])) == 1
              and bool(coverage.get("searches"))
              and bool(coverage.get("advisories_not_checked"))
              and coverage.get("candidate_selection_complete") is False)
    return {"recorded_at": datetime.now(timezone.utc).isoformat(), "passed": passed,
            "execution_environment": "caller runtime; see evaluation record", "platform_proxy_test_harness": proxy,
            "elapsed_seconds": round(time.perf_counter()-started, 3), "arguments": args, "result": data,
            "note": "This check expects Honeywell to have more than one candidate. Reconcile expected coverage if public data changes.",
            "agent_behavior_tested": False}


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--platform-proxy", action="store_true")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    report = asyncio.run(check(args.platform_proxy))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k:v for k,v in report.items() if k not in {"result", "arguments"}}, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
