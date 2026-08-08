import asyncio
import socket
from types import SimpleNamespace

import httpx

from utils.python_http2_bridge import (
    BackgroundBridgeServer,
    BRIDGE_HEALTH_PATH,
    BRIDGE_HEALTH_REQUEST_HEADER,
    BRIDGE_HEALTH_RESPONSE_HEADER,
    BRIDGE_HEALTH_VALUE,
    LOCAL_ADAPTER_HEALTH_PATH,
    LOCAL_ADAPTER_HEALTH_REQUEST_HEADER,
    LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER,
    LOCAL_ADAPTER_HEALTH_VALUE,
    _build_forward_headers,
    _build_response_headers,
    build_upstream_url,
    create_bridge_app,
)


def _request_from_scope(scope):
    headers = httpx.Headers([
        (name.decode("latin-1"), value.decode("latin-1"))
        for name, value in scope.get("headers", [])
    ])
    client = scope.get("client")
    client_info = None
    if isinstance(client, tuple) and client and client[0]:
        client_info = SimpleNamespace(host=client[0], port=client[1] if len(client) > 1 else None)
    return SimpleNamespace(headers=headers, scope=scope, client=client_info)


def test_background_bridge_server_formats_ipv4_bridge_url():
    server = BackgroundBridgeServer(
        "https://example.com",
        listen_host="127.0.0.1",
        listen_port=39013,
    )

    assert server.bridge_url == "http://127.0.0.1:39013"


def test_background_bridge_server_formats_ipv6_bridge_url_with_single_brackets():
    ipv6_server = BackgroundBridgeServer(
        "https://example.com",
        listen_host="::1",
        listen_port=39013,
    )
    bracketed_ipv6_server = BackgroundBridgeServer(
        "https://example.com",
        listen_host="[::1]",
        listen_port=39013,
    )

    assert ipv6_server.bridge_url == "http://[::1]:39013"
    assert bracketed_ipv6_server.bridge_url == "http://[::1]:39013"


def test_background_bridge_server_pick_free_port_uses_matching_socket_family(monkeypatch):
    created_sockets = []

    class FakeSocket:
        def __init__(self, family, socktype):
            self.family = family
            self.socktype = socktype
            self.bound = None
            created_sockets.append(self)

        def bind(self, address):
            self.bound = address

        def setsockopt(self, *args):
            return None

        def getsockname(self):
            if self.family == socket.AF_INET6:
                return (self.bound[0], 39013, 0, 0)
            return (self.bound[0], 39013)

        def close(self):
            return None

    monkeypatch.setattr("utils.python_http2_bridge.socket.socket", FakeSocket)

    assert BackgroundBridgeServer._pick_free_port("127.0.0.1") == 39013
    assert created_sockets[0].family == socket.AF_INET
    assert created_sockets[0].bound == ("127.0.0.1", 0)

    assert BackgroundBridgeServer._pick_free_port("[::1]") == 39013
    assert created_sockets[1].family == socket.AF_INET6
    assert created_sockets[1].bound == ("::1", 0)


def test_build_upstream_url_preserves_path_and_query():
    assert build_upstream_url("https://example.com", "/app/login", b"next=1") == "https://example.com/app/login?next=1"


def test_build_upstream_url_preserves_percent_encoded_probe_bytes():
    assert (
        build_upstream_url(
            "https://example.com",
            b"/cgi-bin/test%00.pl",
            b"payload=%00&ok=1",
        )
        == "https://example.com/cgi-bin/test%00.pl?payload=%00&ok=1"
    )


def test_build_upstream_url_percent_encodes_literal_non_printable_bytes():
    url = build_upstream_url(
        "https://example.com",
        b"/cgi-bin/test\x00.pl",
        b"payload=\x00",
    )

    assert url == "https://example.com/cgi-bin/test%00.pl?payload=%00"
    assert "\x00" not in url


def test_request_header_filtering_strips_hop_by_hop_headers():
    async def _run():
        request = httpx.Request(
            "GET",
            "http://127.0.0.1:3000/test",
            headers={
                "Host": "127.0.0.1:3000",
                "Connection": "keep-alive",
                "Proxy-Connection": "keep-alive",
                "User-Agent": "scanner",
            },
        )
        return _build_forward_headers(request, "https://example.com")

    headers = asyncio.run(_run())

    assert headers["host"] == "example.com"
    assert headers["user-agent"] == "scanner"
    assert "connection" not in headers
    assert "proxy-connection" not in headers
    assert headers["x-forwarded-proto"] == "https"
    assert headers["x-forwarded-host"] == "example.com"


def test_request_header_filtering_uses_scope_when_host_header_is_malformed():
    request = _request_from_scope({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [
            (b"host", b"[127.0.0.1:57983"),
            (b"user-agent", b"Nuclei"),
        ],
        "client": ("127.0.0.1", 45678),
        "server": ("127.0.0.1", 57983),
    })

    headers = _build_forward_headers(request, "https://example.com")

    assert headers["host"] == "example.com"
    assert headers["user-agent"] == "Nuclei"
    assert headers["x-forwarded-proto"] == "https"
    assert headers["x-forwarded-host"] == "example.com"


def test_request_header_filtering_treats_ipv6_loopback_host_as_origin_facing():
    request = _request_from_scope({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [
            (b"host", b"[::1]:39013"),
            (b"user-agent", b"Nikto/2.5.0"),
        ],
        "client": ("127.0.0.1", 45678),
        "server": ("::1", 39013),
    })

    headers = _build_forward_headers(request, "https://example.com")

    assert headers["host"] == "example.com"
    assert headers["user-agent"] == "Nikto/2.5.0"
    assert headers["x-forwarded-proto"] == "https"
    assert headers["x-forwarded-host"] == "example.com"


def test_response_header_filtering_strips_hop_by_hop_and_content_length():
    headers = _build_response_headers({
        "Content-Type": "text/plain",
        "Transfer-Encoding": "chunked",
        "Content-Length": "4",
    })

    assert headers["Content-Type"] == "text/plain"
    assert "Transfer-Encoding" not in headers
    assert "content-length" not in headers


def test_bridge_forwards_request_and_returns_upstream_status_and_body():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            captured["content"] = content
            return httpx.Response(
                201,
                headers={"Content-Type": "text/plain", "Transfer-Encoding": "chunked"},
                content=b"upstream ok",
            )

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.post(
                "/submit?next=1",
                headers={"Connection": "keep-alive", "User-Agent": "Wapiti"},
                content=b"payload",
            )

    response = asyncio.run(_run())

    assert response.status_code == 201
    assert response.text == "upstream ok"
    assert captured["method"] == "POST"
    assert captured["url"] == "https://example.com/submit?next=1"
    assert captured["headers"]["host"] == "example.com"
    assert "connection" not in captured["headers"]
    assert captured["content"] == b"payload"


def test_bridge_returns_502_on_upstream_error():
    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            raise httpx.ConnectError("boom")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get("/")

    response = asyncio.run(_run())

    assert response.status_code == 502
    assert "Upstream bridge error" in response.text


def test_bridge_health_check_short_circuits_upstream_only_with_header():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["url"] = url
            return httpx.Response(200, content=b"forwarded")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run_health():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get(
                LOCAL_ADAPTER_HEALTH_PATH,
                headers={LOCAL_ADAPTER_HEALTH_REQUEST_HEADER: LOCAL_ADAPTER_HEALTH_VALUE},
            )

    health_response = asyncio.run(_run_health())

    assert health_response.status_code == 204
    assert health_response.headers[LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER] == LOCAL_ADAPTER_HEALTH_VALUE
    assert captured == {}

    async def _run_without_header():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get(LOCAL_ADAPTER_HEALTH_PATH)

    normal_response = asyncio.run(_run_without_header())

    assert normal_response.status_code == 200
    assert normal_response.text == "forwarded"
    assert captured["url"] == f"https://example.com{LOCAL_ADAPTER_HEALTH_PATH}"


def test_local_adapter_health_aliases_preserve_existing_wire_contract():
    assert LOCAL_ADAPTER_HEALTH_PATH == BRIDGE_HEALTH_PATH
    assert LOCAL_ADAPTER_HEALTH_REQUEST_HEADER == BRIDGE_HEALTH_REQUEST_HEADER
    assert LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER == BRIDGE_HEALTH_RESPONSE_HEADER
    assert LOCAL_ADAPTER_HEALTH_VALUE == BRIDGE_HEALTH_VALUE


def test_bridge_preserves_percent_encoded_probe_payloads():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["method"] = method
            captured["url"] = url
            return httpx.Response(200, content=b"encoded ok")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get("/cgi-bin/test%00.pl?payload=%00&ok=1")

    response = asyncio.run(_run())

    assert response.status_code == 200
    assert response.text == "encoded ok"
    assert captured["method"] == "GET"
    assert captured["url"] == "https://example.com/cgi-bin/test%00.pl?payload=%00&ok=1"
    assert "\x00" not in captured["url"]


def test_bridge_handles_nikto_style_encoded_probe_without_invalid_url():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            return httpx.Response(200, content=b"nikto ok")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get(
                "/cgi-bin/nikto%00check.cgi?file=%00../winnt/win.ini",
                headers={"User-Agent": "Nikto/2.5.0"},
            )

    response = asyncio.run(_run())

    assert response.status_code == 200
    assert response.text == "nikto ok"
    assert captured["method"] == "GET"
    assert captured["headers"]["user-agent"] == "Nikto/2.5.0"
    assert captured["url"] == "https://example.com/cgi-bin/nikto%00check.cgi?file=%00../winnt/win.ini"
    assert "\x00" not in captured["url"]


def test_bridge_forwards_trace_requests_instead_of_returning_local_405():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            return httpx.Response(200, content=b"trace ok")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.request("TRACE", "/trace-check", headers={"Host": "127.0.0.1:39013"})

    response = asyncio.run(_run())

    assert response.status_code == 200
    assert response.text == "trace ok"
    assert captured["method"] == "TRACE"
    assert captured["url"] == "https://example.com/trace-check"
    assert captured["headers"]["host"] == "example.com"
    assert captured["headers"]["x-forwarded-proto"] == "https"
    assert captured["headers"]["x-forwarded-host"] == "example.com"


def test_bridge_preserves_origin_identity_for_ipv6_loopback_listener_requests():
    captured = {}

    class FakeClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return None

        async def request(self, method, url, headers=None, content=None, cookies=None):
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            return httpx.Response(200, content=b"nikto bridge ok")

    app = create_bridge_app(
        "https://example.com",
        client_factory=lambda: FakeClient(),
    )

    async def _run():
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://bridge.local") as client:
            return await client.get(
                "/cgi-bin/phpinfo.php?view=1",
                headers={
                    "Host": "[::1]:39013",
                    "User-Agent": "Nikto/2.5.0",
                },
            )

    response = asyncio.run(_run())

    assert response.status_code == 200
    assert response.text == "nikto bridge ok"
    assert captured["method"] == "GET"
    assert captured["url"] == "https://example.com/cgi-bin/phpinfo.php?view=1"
    assert captured["headers"]["host"] == "example.com"
    assert captured["headers"]["x-forwarded-proto"] == "https"
    assert captured["headers"]["x-forwarded-host"] == "example.com"
    assert captured["headers"]["user-agent"] == "Nikto/2.5.0"
