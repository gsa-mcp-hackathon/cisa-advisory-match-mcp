"""Protocol and bounded-source checks; no network requests leave these tests."""

import hashlib
import json

import anyio
import httpx2
import pytest

from advisory_matcher import upstream

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


class PublicSources:
    def __init__(self):
        self.requests = []
        self.tool_result = {"content": [], "structuredContent": {"results": [], "hasMore": False}}
        self.tool_error = None
        self.raw_response = None
        self.mcp_tool_response = None
        self.sse = False
        self.redirect_mcp = False

    def __call__(self, request):
        self.requests.append(request)
        if request.url.host == "raw.githubusercontent.com":
            if callable(self.raw_response):
                return self.raw_response(request)
            if self.raw_response is not None:
                return self.raw_response
            advisory_id = request.url.path.rsplit("/", 1)[1].removesuffix(".json").upper()
            return httpx2.Response(200, json={"document": {"tracking": {"id": advisory_id}}})
        assert str(request.url) == upstream.MCP_ENDPOINT
        if self.redirect_mcp:
            return httpx2.Response(307, headers={"Location": upstream.MCP_ENDPOINT + "/redirected"})
        if request.method == "GET":
            return httpx2.Response(405)
        payload = json.loads(request.content)
        method = payload["method"]
        if method.startswith("notifications/"):
            return httpx2.Response(202)
        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test-public-source", "version": "1"},
            }
        elif method == "tools/list":
            result = {
                "tools": [
                    {"name": name, "inputSchema": {"type": "object"}}
                    for name in sorted(upstream.ALLOWED_TOOLS)
                ]
            }
        elif method == "tools/call":
            if callable(self.mcp_tool_response):
                return self.mcp_tool_response(request)
            if self.mcp_tool_response is not None:
                return self.mcp_tool_response
            result = self.tool_result
        else:
            raise AssertionError("Unexpected MCP method")
        message = {"jsonrpc": "2.0", "id": payload["id"], "result": result}
        if method == "tools/call" and self.tool_error is not None:
            message = {"jsonrpc": "2.0", "id": payload["id"], "error": self.tool_error}
        if self.sse:
            return httpx2.Response(
                200,
                content="event: message\ndata: " + json.dumps(message) + "\n\n",
                headers={"Content-Type": "text/event-stream"},
            )
        return httpx2.Response(200, json=message)

    def tool_calls(self):
        return [
            json.loads(request.content)
            for request in self.requests
            if request.method == "POST" and json.loads(request.content)["method"] == "tools/call"
        ]


@pytest.fixture
def sources(monkeypatch):
    server = PublicSources()
    factory = upstream._make_http_client
    monkeypatch.setattr(
        upstream,
        "_make_http_client",
        lambda: factory(transport=httpx2.MockTransport(server)),
    )
    return server


@pytest.mark.parametrize("sse", [False, True])
async def test_official_sdk_handshake_and_structured_tool_result(sources, sse):
    sources.sse = sse
    sources.tool_result = {
        "content": [{"type": "text", "text": "This prose must never be parsed as the answer."}],
        "structuredContent": {"results": [{"advisoryId": "ICSA-26-069-03"}], "hasMore": True},
    }
    async with upstream.UpstreamClient() as client:
        result = await client.call_tool("cisa_search_ics_advisories", {"vendor": "Honeywell", "limit": 2})
    assert result == sources.tool_result["structuredContent"]
    methods = [json.loads(request.content)["method"] for request in sources.requests if request.method == "POST"]
    assert methods[:3] == ["initialize", "notifications/initialized", "tools/list"]
    assert sources.tool_calls()[0]["params"]["arguments"] == {"vendor": "Honeywell", "limit": 2}


@pytest.mark.parametrize(
    "tool_result",
    [
        {"content": [{"type": "text", "text": '{"results": []}'}]},
        {"content": [], "structuredContent": ["not", "an", "object"]},
        {"content": [], "structuredContent": {"error": {"message": "secret=example"}}},
        {"content": [{"type": "text", "text": "secret=example"}], "isError": True},
    ],
)
async def test_missing_malformed_or_error_results_are_not_answers(sources, tool_result):
    sources.tool_result = tool_result
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.call_tool("cisa_list_reference", {"topic": "sources"})
    assert "secret=example" not in str(failure.value)


async def test_json_rpc_error_is_sanitized(sources):
    sources.tool_error = {"code": -32007, "message": "private-key=example-do-not-echo"}
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.call_tool("cisa_get_advisory", {"advisoryId": "ICSA-26-069-03"})
    assert "private-key" not in str(failure.value)


async def test_tool_allowlist_and_json_argument_limit_before_request(sources):
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError, match="not allowed"):
            await client.call_tool("run_shell", {"command": "anything"})
        for arguments in [[], {"value": float("nan")}, {"q": "x" * (upstream.MAX_ARGUMENT_BYTES + 1)}]:
            with pytest.raises(upstream.UpstreamError):
                await client.call_tool("cisa_search_ics_advisories", arguments)
    assert sources.tool_calls() == []


@pytest.mark.parametrize("advisory_id", ["icsa-26-069-03", "ICSMA-26-253-02A", "ICSA-16-231-01-0", "ICSA-24-366-01"])
async def test_fixed_csaf_path_identity_and_retrieval_evidence(sources, advisory_id):
    async with upstream.UpstreamClient() as client:
        result = await client.fetch_csaf(advisory_id)
    normalized = advisory_id.upper()
    assert result["document"]["document"]["tracking"]["id"] == normalized
    assert result["source_url"] == f"{upstream.CSAF_BASE}/20{normalized.split('-')[1]}/{normalized.lower()}.json"
    expected = httpx2.Response(200, json=result["document"]).content
    assert result["sha256"] == hashlib.sha256(expected).hexdigest()
    assert result["retrieved_at"].endswith("Z")


@pytest.mark.parametrize(
    "advisory_id",
    ["../../etc/passwd", "https://example.com/a", "ICSA-26-069-03?token=x", "ICSA-26-000-01", "ICSA-26-366-01", "ICSA-26-367-01", "ICSA-26-069-03.json", "ICSA-26-069-03/extra", None],
)
async def test_invalid_ids_do_not_make_source_request(sources, advisory_id):
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf(advisory_id)
    assert failure.value.code == "invalid_advisory_id"
    assert not any(request.url.host == "raw.githubusercontent.com" for request in sources.requests)


@pytest.mark.parametrize(
    "raw",
    [
        b"not json",
        b"[]",
        b'{"document": {"tracking": {"id": "ICSA-26-069-03", "id": "ICSA-26-069-03"}}}',
        b'{"document": {"tracking": {"id": "ICSA-26-069-03"}}, "score": NaN}',
        b'{"document": {"tracking": {"id": "ICSA-26-069-03"}}, "score": 1e999}',
        b'{"document": {"tracking": {}}}',
    ],
)
async def test_malformed_raw_document_rejected(sources, raw):
    sources.raw_response = httpx2.Response(200, content=raw)
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "malformed_response"


async def test_document_for_different_advisory_rejected(sources):
    sources.raw_response = httpx2.Response(200, json={"document": {"tracking": {"id": "ICSA-26-048-04"}}})
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "advisory_id_mismatch"


async def test_raw_redirect_not_followed_even_to_same_host(sources):
    sources.raw_response = httpx2.Response(307, headers={"Location": upstream.CSAF_BASE + "/different.json"})
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "redirect_refused"
    assert len([request for request in sources.requests if request.url.host == "raw.githubusercontent.com"]) == 1


async def test_mcp_redirect_not_followed_by_sdk(sources):
    sources.redirect_mcp = True
    with pytest.raises(upstream.UpstreamError):
        async with upstream.UpstreamClient():
            pytest.fail("A redirect must not establish a connection")
    assert len(sources.requests) == 1


async def test_mcp_oversized_response_becomes_safe_error(sources):
    sources.mcp_tool_response = httpx2.Response(
        200,
        stream=Chunks(),
        headers={"Content-Type": "application/json"},
    )
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.call_tool("cisa_list_reference", {"topic": "sources"})
    assert failure.value.code == "response_too_large"


async def test_mcp_transport_timeout_becomes_safe_error(sources):
    def timed_out(request):
        raise httpx2.ReadTimeout("private-key=example-do-not-echo", request=request)

    sources.mcp_tool_response = timed_out
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.call_tool("cisa_list_reference", {"topic": "sources"})
    assert failure.value.code == "upstream_timeout"
    assert "private-key" not in str(failure.value)


async def test_caller_cancellation_remains_cancellation(monkeypatch):
    sources = PublicSources()

    async def slow_tool(request):
        if request.method == "POST" and json.loads(request.content)["method"] == "tools/call":
            await anyio.sleep_forever()
        return sources(request)

    factory = upstream._make_http_client
    monkeypatch.setattr(upstream, "_make_http_client", lambda: factory(transport=httpx2.MockTransport(slow_tool)))
    async with upstream.UpstreamClient() as client:
        with anyio.move_on_after(0.02) as cancellation:
            await client.call_tool("cisa_list_reference", {"topic": "sources"})
        assert cancellation.cancel_called


class Chunks(httpx2.AsyncByteStream):
    def __init__(self):
        self.closed = False
        self.yielded = 0

    async def __aiter__(self):
        for _ in range(40):
            self.yielded += 1
            yield b"x" * (64 * 1024)

    async def aclose(self):
        self.closed = True


async def test_chunked_source_stops_at_two_mib(sources):
    stream = Chunks()
    sources.raw_response = httpx2.Response(200, stream=stream)
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "response_too_large"
    assert stream.yielded == 33
    assert stream.closed


async def test_oversized_content_length_rejected_without_reading(sources):
    stream = Chunks()
    sources.raw_response = httpx2.Response(200, stream=stream, headers={"Content-Length": str(upstream.MAX_RESPONSE_BYTES + 1)})
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "response_too_large"
    assert stream.yielded == 0
    assert stream.closed


async def test_unrequested_compressed_response_refused(sources):
    sources.raw_response = httpx2.Response(200, stream=Chunks(), headers={"Content-Encoding": "gzip"})
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "encoded_response_refused"
    raw_request = [request for request in sources.requests if request.url.host == "raw.githubusercontent.com"][0]
    assert raw_request.headers["Accept-Encoding"] == "identity"


async def test_source_timeout_does_not_echo_request_or_exception(sources):
    def timed_out(request):
        raise httpx2.ReadTimeout("private-key=example-do-not-echo", request=request)

    sources.raw_response = timed_out
    async with upstream.UpstreamClient() as client:
        with pytest.raises(upstream.UpstreamError) as failure:
            await client.fetch_csaf("ICSA-26-069-03")
    assert failure.value.code == "upstream_timeout"
    assert "private-key" not in str(failure.value)


async def test_unconnected_client_fails_explicitly():
    client = upstream.UpstreamClient()
    with pytest.raises(upstream.UpstreamError) as failure:
        await client.call_tool("cisa_list_reference", {"topic": "sources"})
    assert failure.value.code == "not_connected"
