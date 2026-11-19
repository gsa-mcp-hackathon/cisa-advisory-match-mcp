"""TEST HARNESS ONLY: run the real server through the trusted platform proxy.

Use only when HTTPS_PROXY was supplied by a trusted execution platform whose
network requires that proxy. This is not a production environment fallback.
The runtime package never reads these variables. Source destinations, byte
limits, timeouts, response hooks, TLS verification, and redirect rules remain
those of the production adapter. Never log the proxy URL or its credentials.
"""

import os
from pathlib import Path
import sys

import httpx2

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from advisory_matcher import upstream
import server


def main() -> None:
    proxy = os.environ.get("HTTPS_PROXY")
    if not proxy:
        raise SystemExit("This test harness requires the trusted platform HTTPS proxy.")
    try:
        parsed_proxy = httpx2.Proxy(proxy)
        if parsed_proxy.url.scheme not in {"http", "https"}:
            raise ValueError("Unsupported proxy transport")
    except Exception:
        raise SystemExit("The trusted platform proxy configuration is invalid.") from None

    production_factory = upstream._make_http_client

    def platform_test_client() -> httpx2.AsyncClient:
        transport = httpx2.AsyncHTTPTransport(proxy=parsed_proxy, trust_env=False)
        return production_factory(transport=transport)

    upstream._make_http_client = platform_test_client
    server.mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
