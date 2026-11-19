"""
STDIO test harness for search_product_catalog — sends JSON-RPC 2.0 messages
to the MCP server via stdin/stdout without network access.
"""
import json
import subprocess
import sys
import time

VENV_PYTHON = sys.executable
PROJECT = __file__.replace("/scripts/stdio_catalog_test.py", "")

CASES = [
    # (label, args)
    # OT product — exact name from snapshot
    ("OT exact: S7-300",
     {"product": "S7-300", "scope": "OT", "limit": 5}),
    # OT manufacturer-scoped alias
    ("OT manufacturer alias: Siemens S7-1200",
     {"product": "S7-1200", "manufacturer": "Siemens", "scope": "OT", "limit": 5}),
    # OT bare product name without manufacturer
    ("OT bare product: SCALANCE",
     {"product": "SCALANCE", "scope": "OT", "limit": 5}),
    # IT product example
    ("IT product: Windows 10",
     {"product": "Windows 10", "scope": "IT", "limit": 5}),
    # No-result case — fictional name not in snapshot
    ("No-result: FictionalProduct XYZ-9999",
     {"product": "FictionalProduct XYZ-9999", "limit": 5}),
    # Result limit of 5 (verify limit honored)
    ("OT limit=5: Modicon",
     {"product": "Modicon", "scope": "OT", "limit": 5}),
]

def send(proc, msg):
    line = json.dumps(msg) + "\n"
    proc.stdin.write(line.encode())
    proc.stdin.flush()

def recv(proc):
    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line.decode())

def run():
    proc = subprocess.Popen(
        [VENV_PYTHON, "server.py"],
        cwd=PROJECT,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    results = []
    try:
        # Initialize
        send(proc, {"jsonrpc": "2.0", "id": 0, "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05",
                               "capabilities": {},
                               "clientInfo": {"name": "stdio-test", "version": "0"}}})
        init_resp = recv(proc)
        results.append({"step": "initialize", "ok": "result" in init_resp,
                        "server_info": init_resp.get("result", {}).get("serverInfo")})

        # Send initialized notification
        send(proc, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})

        # List tools
        send(proc, {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        list_resp = recv(proc)
        tool_names = [t["name"] for t in list_resp.get("result", {}).get("tools", [])]
        results.append({"step": "tools/list", "tools": tool_names,
                        "has_search_product_catalog": "search_product_catalog" in tool_names})

        # Run each search case
        for i, (label, args) in enumerate(CASES):
            msg_id = 100 + i
            send(proc, {
                "jsonrpc": "2.0",
                "id": msg_id,
                "method": "tools/call",
                "params": {"name": "search_product_catalog", "arguments": args}
            })
            resp = recv(proc)
            if "error" in resp:
                results.append({"case": label, "args": args,
                                 "error": resp["error"], "ok": False})
                continue
            content = resp.get("result", {}).get("content", [])
            text = content[0]["text"] if content else ""
            try:
                data = json.loads(text)
            except Exception:
                results.append({"case": label, "args": args,
                                 "raw_text": text[:200], "ok": False, "parse_error": True})
                continue
            candidates = data.get("candidates", [])
            results.append({
                "case": label,
                "args": args,
                "ok": True,
                "mode": data.get("mode"),
                "candidate_count": data.get("candidate_count"),
                "candidates_returned": len(candidates),
                "candidates_omitted": data.get("candidates_omitted"),
                "scan_truncated": data.get("scan_truncated"),
                "alias_expansion_omitted": data.get("alias_expansion_omitted"),
                "coverage_complete": data.get("coverage_complete"),
                "sample_candidates": [
                    {
                        "scope": c.get("scope"),
                        "advisory_id": c.get("advisory_id"),
                        "manufacturer": c.get("manufacturer"),
                        "product_family": c.get("product_family"),
                        "product_name": c.get("product_name")[:60] if c.get("product_name") else None,
                        "match_basis": c.get("match_basis"),
                        "source_sha256": c.get("source_sha256"),
                        "source_url": c.get("source_url"),
                        "identity_review_required": c.get("identity_review_required"),
                        "alias_mappings": c.get("alias_mappings"),
                    }
                    for c in candidates[:3]
                ],
            })
    finally:
        proc.stdin.close()
        proc.wait(timeout=5)

    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    run()
