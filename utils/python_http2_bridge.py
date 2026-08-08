"""
Lightweight Python HTTP/1.1 -> HTTP/2 reverse bridge.

This bridge is intentionally small and single-origin only. It accepts local
HTTP/1.1 requests and forwards them to one configured upstream origin over
HTTP/2 using HTTPX.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from http.cookies import SimpleCookie
import ipaddress
import socket
import threading
import time
from types import SimpleNamespace
from typing import Any, Awaitable, Callable, Mapping, Optional
from urllib.parse import urljoin

import httpx
import uvicorn

HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-connection",
    "host",
})

_HEX_DIGITS = frozenset(b"0123456789abcdefABCDEF")
LOCAL_ADAPTER_HEALTH_PATH = "/__vuln_manager_bridge_health__"
LOCAL_ADAPTER_HEALTH_REQUEST_HEADER = "x-vuln-manager-bridge-health"
LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER = "x-vuln-manager-bridge-health"
LOCAL_ADAPTER_HEALTH_VALUE = "ok"

# Backward-compatible aliases: the shared wire contract keeps the same
# path and header values for the local adapter health check.
BRIDGE_HEALTH_PATH = LOCAL_ADAPTER_HEALTH_PATH
BRIDGE_HEALTH_REQUEST_HEADER = LOCAL_ADAPTER_HEALTH_REQUEST_HEADER
BRIDGE_HEALTH_RESPONSE_HEADER = LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER
BRIDGE_HEALTH_VALUE = LOCAL_ADAPTER_HEALTH_VALUE
FORWARDED_HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
    "TRACE",
    "PROPFIND",
    "PROPPATCH",
    "MKCOL",
    "COPY",
    "MOVE",
    "LOCK",
    "UNLOCK",
    "SEARCH",
]

ASGIMessage = dict[str, Any]
ASGIReceive = Callable[[], Awaitable[ASGIMessage]]
ASGISend = Callable[[ASGIMessage], Awaitable[None]]


@dataclass(frozen=True)
class _BridgeClient:
    """Minimal client host info exposed to header-building helpers."""

    host: str
    port: Optional[int] = None


@dataclass(frozen=True)
class _BridgeRequest:
    """Minimal request object shared between the raw ASGI app and tests."""

    method: str
    headers: httpx.Headers
    scope: Mapping[str, Any]
    body: bytes
    cookies: Mapping[str, str]
    client: Optional[_BridgeClient] = None


class BridgeASGIApp:
    """Small single-origin ASGI app that forwards local HTTP to upstream HTTP/2."""

    def __init__(
        self,
        origin: str,
        timeout: float = 20.0,
        client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
    ) -> None:
        self.origin = str(httpx.URL(origin))
        self.timeout = timeout
        self.state = SimpleNamespace(origin=self.origin, timeout=timeout)
        self._client_factory = client_factory or self._default_client_factory

    def _default_client_factory(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(http2=True, timeout=self.timeout, follow_redirects=False)

    async def __call__(self, scope: Mapping[str, Any], receive: ASGIReceive, send: ASGISend) -> None:
        scope_type = scope.get("type")
        if scope_type == "lifespan":
            await self._handle_lifespan(receive, send)
            return
        if scope_type != "http":
            raise RuntimeError(f"Unsupported ASGI scope type for bridge app: {scope_type!r}")

        method = str(scope.get("method") or "GET").upper()
        if method not in FORWARDED_HTTP_METHODS:
            await _send_plain_text_response(
                send,
                405,
                "Method Not Allowed",
                headers={"allow": ", ".join(FORWARDED_HTTP_METHODS)},
            )
            return

        body = await _read_request_body(receive)
        request = _request_from_scope(scope, body, method=method)
        path = str(scope.get("path") or "/")

        if (
            path == LOCAL_ADAPTER_HEALTH_PATH
            and request.headers.get(LOCAL_ADAPTER_HEALTH_REQUEST_HEADER) == LOCAL_ADAPTER_HEALTH_VALUE
        ):
            await _send_response(
                send,
                204,
                headers={LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER: LOCAL_ADAPTER_HEALTH_VALUE},
                body=b"",
            )
            return

        raw_path = scope.get("raw_path") or path.encode("utf-8")
        raw_query = scope.get("query_string", b"")
        upstream_url = build_upstream_url(self.origin, raw_path, raw_query)
        headers = _build_forward_headers(request, self.origin)

        try:
            async with self._client_factory() as client:
                upstream_response = await client.request(
                    request.method,
                    upstream_url,
                    headers=headers,
                    content=request.body,
                    cookies=request.cookies,
                )
        except httpx.HTTPError as exc:
            await _send_plain_text_response(send, 502, f"Upstream bridge error: {exc}")
            return

        await _send_response(
            send,
            upstream_response.status_code,
            headers=_build_response_headers(upstream_response.headers),
            body=upstream_response.content,
        )

    async def _handle_lifespan(self, receive: ASGIReceive, send: ASGISend) -> None:
        while True:
            message = await receive()
            message_type = message.get("type")
            if message_type == "lifespan.startup":
                await send({"type": "lifespan.startup.complete"})
            elif message_type == "lifespan.shutdown":
                await send({"type": "lifespan.shutdown.complete"})
                return


class BackgroundBridgeServer:
    """Run the single-origin Python HTTP/2 bridge in a background thread."""

    def __init__(
        self,
        origin: str,
        listen_host: str = "127.0.0.1",
        listen_port: Optional[int] = None,
        timeout: float = 20.0,
        startup_timeout: float = 5.0,
    ) -> None:
        self.origin = origin
        self.listen_host = listen_host
        self.listen_port = listen_port or self._pick_free_port(listen_host)
        self.timeout = timeout
        self.startup_timeout = startup_timeout
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def _normalize_listen_host(host: str) -> str:
        """Return one listener host form suitable for sockets and Uvicorn."""
        value = str(host or "").strip()
        if value.startswith("[") and value.endswith("]"):
            return value[1:-1].strip()
        return value

    @classmethod
    def _socket_family_for_host(cls, host: str) -> socket.AddressFamily:
        """Choose the socket family that matches the configured listen host."""
        normalized_host = cls._normalize_listen_host(host)
        try:
            return (
                socket.AF_INET6
                if ipaddress.ip_address(normalized_host).version == 6
                else socket.AF_INET
            )
        except ValueError:
            return socket.AF_INET

    @classmethod
    def _pick_free_port(cls, host: str) -> int:
        """Reserve a free local port for the bridge listener."""
        normalized_host = cls._normalize_listen_host(host)
        family = cls._socket_family_for_host(normalized_host)
        with contextlib.closing(socket.socket(family, socket.SOCK_STREAM)) as sock:
            sock.bind((normalized_host, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return int(sock.getsockname()[1])

    @property
    def bridge_url(self) -> str:
        listen_host = self._normalize_listen_host(self.listen_host)
        if ":" in listen_host:
            listen_host = f"[{listen_host}]"
        return f"http://{listen_host}:{self.listen_port}"

    def start(self) -> str:
        """Start the bridge if needed and return its local URL."""
        if self._server is not None and self._thread is not None and self._thread.is_alive():
            return self.bridge_url

        app = create_bridge_app(self.origin, timeout=self.timeout)
        config = uvicorn.Config(
            app,
            host=self._normalize_listen_host(self.listen_host),
            port=self.listen_port,
            log_level="warning",
            access_log=False,
            server_header=False,
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, daemon=True)
        thread.start()

        deadline = time.time() + self.startup_timeout
        while time.time() < deadline:
            if getattr(server, "started", False):
                self._server = server
                self._thread = thread
                return self.bridge_url
            if not thread.is_alive():
                break
            time.sleep(0.05)

        server.should_exit = True
        thread.join(timeout=1.0)
        raise RuntimeError(
            f"Automatic HTTP/2 bridge failed to start for {self.origin} on {self.bridge_url}."
        )

    def stop(self) -> None:
        """Stop the bridge if it is running."""
        if self._server is None or self._thread is None:
            return

        self._server.should_exit = True
        self._thread.join(timeout=5.0)
        self._server = None
        self._thread = None


def _strip_hop_by_hop_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Drop hop-by-hop headers before forwarding a request or response."""
    return {
        key: value
        for key, value in headers.items()
        if key.lower() not in HOP_BY_HOP_HEADERS
    }


def _sanitize_raw_url_component(value: bytes) -> bytes:
    """
    Preserve existing percent-encoding and escape only unsafe raw bytes.

    HTTPX accepts raw-path bytes, but raw control characters and non-ASCII
    bytes must be percent-encoded first. Existing `%HH` sequences should pass
    through unchanged so scanner payloads keep their original encoding.
    """
    sanitized = bytearray()
    index = 0

    while index < len(value):
        current = value[index]

        if (
            current == 0x25
            and index + 2 < len(value)
            and value[index + 1] in _HEX_DIGITS
            and value[index + 2] in _HEX_DIGITS
        ):
            sanitized.extend(value[index:index + 3])
            index += 3
            continue

        if current < 0x20 or current == 0x7F or current >= 0x80:
            sanitized.extend(f"%{current:02X}".encode("ascii"))
        else:
            sanitized.append(current)

        index += 1

    return bytes(sanitized)


def build_upstream_url(origin: str, path: str | bytes, query_string: bytes = b"") -> str:
    """Join the configured origin with the incoming raw path and query string."""
    raw_path = path.encode("utf-8") if isinstance(path, str) else path
    raw_path = raw_path or b"/"
    if not raw_path.startswith(b"/"):
        raw_path = b"/" + raw_path

    sanitized_path = _sanitize_raw_url_component(raw_path)
    sanitized_query = _sanitize_raw_url_component(query_string)
    base = str(httpx.URL(origin)).rstrip("/") + "/"
    target = urljoin(base, sanitized_path.decode("ascii").lstrip("/"))

    if sanitized_query:
        return f"{target}?{sanitized_query.decode('ascii')}"
    return target


def _extract_authority_host(value: Any) -> str:
    """Parse a Host-style authority value into one host component."""
    authority = str(value or "").strip().rsplit("@", 1)[-1].strip()
    if not authority:
        return ""

    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket < 0:
            return ""
        remainder = authority[closing_bracket + 1:].strip()
        if remainder and not remainder.startswith(":"):
            return ""
        return authority[1:closing_bracket].strip()

    if authority.count(":") > 1:
        try:
            return str(ipaddress.ip_address(authority))
        except ValueError:
            return ""

    if ":" in authority:
        return authority.split(":", 1)[0].strip()

    return authority


def _is_loopback_host(value: Any) -> bool:
    """Return True when a host-like value points at loopback."""
    host = str(value or "").strip().strip("[]")
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _build_forward_headers(request: Any, origin: str) -> dict[str, str]:
    """Prepare upstream headers for a single-origin reverse bridge."""
    headers = _strip_hop_by_hop_headers(dict(request.headers))
    origin_url = httpx.URL(origin)
    origin_host = origin_url.netloc.decode("ascii")
    headers["host"] = origin_host
    client = getattr(request, "client", None)
    if client and getattr(client, "host", None):
        headers.setdefault("x-forwarded-for", client.host)

    scope = getattr(request, "scope", {}) or {}
    forwarded_host = request.headers.get("host")
    forwarded_host_name = _extract_authority_host(forwarded_host)
    if not forwarded_host:
        server = scope.get("server")
        if isinstance(server, tuple) and server and server[0]:
            server_host = str(server[0])
            server_port = server[1] if len(server) > 1 else None
            forwarded_host = f"{server_host}:{server_port}" if server_port else server_host
        else:
            forwarded_host = ""
        forwarded_host_name = _extract_authority_host(forwarded_host)
    elif not forwarded_host_name:
        server = scope.get("server")
        if isinstance(server, tuple) and server and server[0]:
            server_host = str(server[0])
            server_port = server[1] if len(server) > 1 else None
            forwarded_host = f"{server_host}:{server_port}" if server_port else server_host
            forwarded_host_name = _extract_authority_host(forwarded_host)

    bridge_forwarded_host = str(forwarded_host or "").strip()
    if _is_loopback_host(forwarded_host_name):
        bridge_forwarded_host = origin_host

    headers.setdefault("x-forwarded-proto", str(origin_url.scheme))
    headers.setdefault("x-forwarded-host", bridge_forwarded_host or origin_host)
    return headers


def _build_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Filter upstream response headers before returning to the scanner."""
    filtered = _strip_hop_by_hop_headers(headers)
    return {
        key: value
        for key, value in filtered.items()
        if key.lower() != "content-length"
    }


def _decode_scope_headers(scope: Mapping[str, Any]) -> httpx.Headers:
    """Build case-insensitive request headers from ASGI raw header bytes."""
    raw_headers = scope.get("headers") or []
    return httpx.Headers([
        (
            bytes(name).decode("latin-1"),
            bytes(value).decode("latin-1"),
        )
        for name, value in raw_headers
    ])


def _parse_cookie_header(value: str) -> dict[str, str]:
    """Parse the Cookie header into a plain mapping for HTTPX."""
    if not value:
        return {}

    parsed = SimpleCookie()
    with contextlib.suppress(Exception):
        parsed.load(value)
    return {
        key: morsel.value
        for key, morsel in parsed.items()
    }


def _request_from_scope(
    scope: Mapping[str, Any],
    body: bytes,
    *,
    method: Optional[str] = None,
) -> _BridgeRequest:
    """Create the minimal request shape needed by forwarding helpers."""
    headers = _decode_scope_headers(scope)
    client_info = scope.get("client")
    client = None
    if isinstance(client_info, tuple) and client_info and client_info[0]:
        client = _BridgeClient(
            host=str(client_info[0]),
            port=int(client_info[1]) if len(client_info) > 1 and client_info[1] is not None else None,
        )
    return _BridgeRequest(
        method=(method or str(scope.get("method") or "GET")).upper(),
        headers=headers,
        scope=scope,
        body=body,
        cookies=_parse_cookie_header(headers.get("cookie", "")),
        client=client,
    )


async def _read_request_body(receive: ASGIReceive) -> bytes:
    """Read the full incoming ASGI request body into memory."""
    chunks = []
    more_body = True

    while more_body:
        message = await receive()
        message_type = message.get("type")
        if message_type == "http.disconnect":
            break
        if message_type != "http.request":
            continue
        chunks.append(message.get("body", b""))
        more_body = bool(message.get("more_body", False))

    return b"".join(chunks)


def _encode_response_headers(headers: Mapping[str, str]) -> list[tuple[bytes, bytes]]:
    """Convert plain response headers into ASGI wire format."""
    return [
        (
            str(key).encode("latin-1"),
            str(value).encode("latin-1"),
        )
        for key, value in headers.items()
    ]


async def _send_response(
    send: ASGISend,
    status_code: int,
    headers: Mapping[str, str],
    body: bytes,
) -> None:
    """Send one complete HTTP response through ASGI."""
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": _encode_response_headers(headers),
        }
    )
    await send(
        {
            "type": "http.response.body",
            "body": body,
        }
    )


async def _send_plain_text_response(
    send: ASGISend,
    status_code: int,
    text: str,
    *,
    headers: Optional[Mapping[str, str]] = None,
) -> None:
    """Send a plain-text response with a UTF-8 content type."""
    response_headers = {
        "content-type": "text/plain; charset=utf-8",
    }
    if headers:
        response_headers.update(headers)
    await _send_response(send, status_code, response_headers, text.encode("utf-8"))


def create_bridge_app(
    origin: str,
    timeout: float = 20.0,
    client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
) -> BridgeASGIApp:
    """
    Create a single-origin HTTP/2 reverse bridge app.

    The app accepts plain HTTP locally and forwards all methods/paths to one
    upstream origin over HTTP/2.
    """
    return BridgeASGIApp(origin, timeout=timeout, client_factory=client_factory)
