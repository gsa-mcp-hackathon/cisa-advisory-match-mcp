"""Read-only access to the public CISA MCP and original CISA CSAF documents.

The MCP SDK owns the protocol. This adapter supplies fixed destinations, bounded
HTTP reads, and errors that never echo a remote body or request arguments.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import AsyncExitStack
from datetime import date, datetime, timedelta, timezone
from typing import Any, Callable

import anyio
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult, Implementation

MCP_ENDPOINT = "https://cisa-cybersecurity.caseyjhand.com/mcp"
CSAF_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white"
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_ARGUMENT_BYTES = 64 * 1024
TIMEOUT_SECONDS = 10.0
ALLOWED_TOOLS = frozenset(
    {
        "cisa_search_ics_advisories",
        "cisa_get_advisory",
        "cisa_check_cve_status",
        "cisa_list_reference",
    }
)
_ADVISORY_ID = re.compile(
    r"ICS(?:A|MA)-(?P<year>[0-9]{2})-(?P<day>[0-9]{3})-[0-9]{2}(?:[A-Z]|-[0-9]+)?"
)
_ERROR_MESSAGES = {
    "not_connected": "The upstream client is not connected.",
    "connection_failed": "The public advisory service could not be connected.",
    "upstream_timeout": "The public advisory request timed out.",
    "upstream_unavailable": "The public advisory request could not be completed.",
    "tool_not_allowed": "This upstream tool is not allowed.",
    "invalid_arguments": "The upstream arguments are not a bounded JSON object.",
    "tool_failed": "The upstream tool reported an error.",
    "malformed_response": "The upstream response was not valid structured data.",
    "response_too_large": "The upstream response exceeded the size limit.",
    "redirect_refused": "The upstream request attempted a redirect.",
    "encoded_response_refused": "The upstream response used an unsupported content encoding.",
    "invalid_advisory_id": "The advisory identifier is not valid.",
    "advisory_id_mismatch": "The source document does not match the requested advisory.",
}


class UpstreamError(RuntimeError):
    """A stable code and safe message, without remote exception text."""

    def __init__(self, code: str = "upstream_unavailable") -> None:
        self.code = code if code in _ERROR_MESSAGES else "upstream_unavailable"
        super().__init__(_ERROR_MESSAGES[self.code])


class _LimitedStream(httpx2.AsyncByteStream):
    """Cap bytes before the HTTP library or MCP SDK buffers a response."""

    def __init__(self, stream: httpx2.AsyncByteStream, record_failure: Callable[[Exception], None]) -> None:
        self._stream = stream
        self._record_failure = record_failure

    async def __aiter__(self):
        received = 0
        try:
            async for chunk in self._stream:
                received += len(chunk)
                if received > MAX_RESPONSE_BYTES:
                    raise UpstreamError("response_too_large")
                yield chunk
        except Exception as exc:
            self._record_failure(exc)
            raise

    async def aclose(self) -> None:
        await self._stream.aclose()


async def _bound_response(response: httpx2.Response, record_failure: Callable[[Exception], None]) -> None:
    """Reject redirects and compression before SDK-specific response handling.

    Requesting identity encoding and refusing other encodings makes this byte
    cap apply to decoded JSON too, without allowing a compressed expansion.
    """
    if 300 <= response.status_code < 400:
        raise UpstreamError("redirect_refused")
    encoding = response.headers.get("content-encoding", "identity").strip().lower()
    if encoding not in {"", "identity"}:
        raise UpstreamError("encoded_response_refused")
    length = response.headers.get("content-length")
    if length is not None:
        try:
            size = int(length)
        except ValueError:
            raise UpstreamError("malformed_response") from None
        if size < 0:
            raise UpstreamError("malformed_response")
        if size > MAX_RESPONSE_BYTES:
            raise UpstreamError("response_too_large")
    response.stream = _LimitedStream(response.stream, record_failure)


class _BoundedHTTPClient(httpx2.AsyncClient):
    """Remember safe transport failures without confusing caller cancellation."""

    last_failure: UpstreamError | None = None

    def _record_failure(self, exc: Exception) -> None:
        self.last_failure = _safe_error(exc)

    async def _response_hook(self, response: httpx2.Response) -> None:
        await _bound_response(response, self._record_failure)

    async def send(self, request: httpx2.Request, **kwargs: Any) -> httpx2.Response:
        try:
            return await super().send(request, **kwargs)
        except Exception as exc:
            self._record_failure(exc)
            raise


def _make_http_client(*, transport: httpx2.AsyncBaseTransport | None = None) -> httpx2.AsyncClient:
    # Transport injection is an internal test seam, not a configurable URL.
    client = _BoundedHTTPClient(
        transport=transport,
        trust_env=False,
        follow_redirects=False,
        max_redirects=0,
        timeout=httpx2.Timeout(TIMEOUT_SECONDS),
        headers={
            "Accept-Encoding": "identity",
            "User-Agent": "GSA-MCP-Hackathon-cisa-advisory-match/0.7",
        },
    )
    client.event_hooks["response"].append(client._response_hook)
    return client


def _safe_error(exc: Exception, default: str = "upstream_unavailable") -> UpstreamError:
    if isinstance(exc, UpstreamError):
        return exc
    if isinstance(exc, (TimeoutError, httpx2.TimeoutException)):
        return UpstreamError("upstream_timeout")
    if isinstance(exc, ExceptionGroup):
        for child in exc.exceptions:
            if isinstance(child, Exception):
                sanitized = _safe_error(child, default)
                if sanitized.code != default:
                    return sanitized
    return UpstreamError(default)


def _normalized_advisory_id(advisory_id: str) -> str:
    if not isinstance(advisory_id, str) or len(advisory_id) > 32:
        raise UpstreamError("invalid_advisory_id")
    normalized = advisory_id.strip().upper()
    matched = _ADVISORY_ID.fullmatch(normalized)
    if not matched:
        raise UpstreamError("invalid_advisory_id")
    year, day_number = 2000 + int(matched["year"]), int(matched["day"])
    if day_number < 1 or (date(year, 1, 1) + timedelta(days=day_number - 1)).year != year:
        raise UpstreamError("invalid_advisory_id")
    return normalized


def _bounded_json(value: Any, *, limit: int, error: str) -> bytes:
    try:
        encoded = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError):
        raise UpstreamError(error) from None
    if len(encoded) > limit:
        raise UpstreamError(error)
    return encoded


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON member")
        result[key] = value
    return result


def _refuse_constant(value: str) -> None:
    raise ValueError("Non-finite JSON number")


class UpstreamClient:
    """Use ``async with UpstreamClient() as client`` in one owning task.

    ``call_tool`` returns structured content, never text scraped from an answer.
    ``fetch_csaf`` returns the original document and its retrieval evidence.
    No caller-supplied destination, credential, or environment override is used.
    """

    def __init__(self) -> None:
        self._stack: AsyncExitStack | None = None
        self._http: httpx2.AsyncClient | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> UpstreamClient:
        if self._stack is not None:
            raise UpstreamError("connection_failed")
        stack = AsyncExitStack()
        await stack.__aenter__()
        self._stack = stack
        try:
            self._http = await stack.enter_async_context(_make_http_client())
            read, write = await stack.enter_async_context(
                streamable_http_client(
                    MCP_ENDPOINT,
                    http_client=self._http,
                    max_sse_event_size=MAX_RESPONSE_BYTES,
                    terminate_on_close=False,
                )
            )
            self._session = await stack.enter_async_context(
                ClientSession(
                    read,
                    write,
                    read_timeout_seconds=TIMEOUT_SECONDS,
                    client_info=Implementation(name="inventory-advisory-mcp", version="0.7.0"),
                )
            )
            with anyio.fail_after(TIMEOUT_SECONDS):
                await self._session.initialize()
            with anyio.fail_after(TIMEOUT_SECONDS):
                await self._session.list_tools()
            return self
        except BaseException as exc:
            try:
                await stack.aclose()
            except Exception as cleanup_error:
                # SDK transport task failures first cancel the owning task;
                # closing its task group exposes the actual grouped failure.
                raise _safe_error(cleanup_error, "connection_failed") from None
            finally:
                self._stack = self._http = self._session = None
            if isinstance(exc, Exception):
                raise _safe_error(exc, "connection_failed") from None
            raise

    async def __aexit__(self, exc_type, exc, traceback) -> bool:
        stack = self._stack
        try:
            if stack is not None:
                await stack.aclose()
        except Exception:
            if exc is None:
                raise UpstreamError("connection_failed") from None
        finally:
            self._stack = self._http = self._session = None
        return False

    async def call_tool(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(name, str) or name not in ALLOWED_TOOLS:
            raise UpstreamError("tool_not_allowed")
        if not isinstance(args, dict):
            raise UpstreamError("invalid_arguments")
        _bounded_json(args, limit=MAX_ARGUMENT_BYTES, error="invalid_arguments")
        if self._session is None:
            raise UpstreamError("not_connected")
        if isinstance(self._http, _BoundedHTTPClient):
            self._http.last_failure = None
        try:
            with anyio.fail_after(TIMEOUT_SECONDS):
                result = await self._session.call_tool(name, args, read_timeout_seconds=TIMEOUT_SECONDS)
        except BaseException as exc:
            if isinstance(exc, Exception):
                raise _safe_error(exc) from None
            failure = self._http.last_failure if isinstance(self._http, _BoundedHTTPClient) else None
            if failure is None:
                # Caller cancellation is not an upstream failure. Its enclosing
                # cancel scope must unwind before the client context closes.
                raise
            # A failed SDK transport task can cancel this await. Unwind the
            # transport to distinguish that failure from caller cancellation.
            stack = self._stack
            try:
                if stack is not None:
                    await stack.aclose()
            except Exception as cleanup_error:
                raise _safe_error(cleanup_error) from None
            finally:
                self._stack = self._http = self._session = None
            raise failure from None
        if not isinstance(result, CallToolResult):
            raise UpstreamError("malformed_response")
        if result.is_error:
            raise UpstreamError("tool_failed")
        structured = result.structured_content
        if not isinstance(structured, dict):
            raise UpstreamError("malformed_response")
        if "error" in structured:
            raise UpstreamError("tool_failed")
        _bounded_json(structured, limit=MAX_RESPONSE_BYTES, error="malformed_response")
        return structured

    async def fetch_csaf(self, advisory_id: str) -> dict[str, Any]:
        normalized = _normalized_advisory_id(advisory_id)
        if self._http is None:
            raise UpstreamError("not_connected")
        year = "20" + normalized.split("-")[1]
        source_url = f"{CSAF_BASE}/{year}/{normalized.lower()}.json"
        try:
            with anyio.fail_after(TIMEOUT_SECONDS):
                async with self._http.stream("GET", source_url) as response:
                    if response.status_code != 200:
                        raise UpstreamError("upstream_unavailable")
                    raw = await response.aread()
        except Exception as exc:
            raise _safe_error(exc) from None
        if len(raw) > MAX_RESPONSE_BYTES:
            raise UpstreamError("response_too_large")
        try:
            document = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_refuse_constant)
            if not isinstance(document, dict):
                raise ValueError("JSON object required")
            source_id = document["document"]["tracking"]["id"]
            source_id = _normalized_advisory_id(source_id)
        except (ValueError, TypeError, KeyError, RecursionError, UnicodeError, UpstreamError):
            raise UpstreamError("malformed_response") from None
        if source_id != normalized:
            raise UpstreamError("advisory_id_mismatch")
        _bounded_json(document, limit=MAX_RESPONSE_BYTES, error="malformed_response")
        return {
            "document": document,
            "source_url": source_url,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }


async def fetch_it_csaf(advisory_id: str) -> dict[str, Any]:
    """Retrieve one fixed-host public IT CSAF; no user-supplied URLs or redirects."""
    from .it_advisories import normalize_it_id, it_source_url
    try:
        normalized = normalize_it_id(advisory_id)
    except ValueError:
        raise UpstreamError("invalid_advisory_id") from None
    url = it_source_url(normalized)
    try:
        async with _make_http_client() as client:
            with anyio.fail_after(TIMEOUT_SECONDS):
                async with client.stream("GET", url) as response:
                    if response.status_code != 200:
                        raise UpstreamError("upstream_unavailable")
                    raw = await response.aread()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise UpstreamError("response_too_large")
        document = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_refuse_constant)
        if normalize_it_id(document["document"]["tracking"]["id"]) != normalized:
            raise UpstreamError("advisory_id_mismatch")
        _bounded_json(document, limit=MAX_RESPONSE_BYTES, error="malformed_response")
        return {"document": document, "source_url": url, "sha256": hashlib.sha256(raw).hexdigest(),
                "retrieved_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")}
    except Exception as exc:
        raise _safe_error(exc, "malformed_response") from None


async def fetch_cisa_feed(category: str) -> bytes:
    """Fetch one hard-coded public CISA feed using the existing 2 MiB cap."""
    from .feed_discovery import FEEDS
    if category not in FEEDS:
        raise UpstreamError("invalid_arguments")
    try:
        async with _make_http_client() as client:
            with anyio.fail_after(TIMEOUT_SECONDS):
                async with client.stream("GET", FEEDS[category]) as response:
                    if response.status_code != 200:
                        raise UpstreamError("upstream_unavailable")
                    raw = await response.aread()
        if len(raw) > MAX_RESPONSE_BYTES:
            raise UpstreamError("response_too_large")
        return raw
    except Exception as exc:
        raise _safe_error(exc) from None
