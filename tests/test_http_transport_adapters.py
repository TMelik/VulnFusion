from http.client import HTTPConnection

import pytest

from utils.http_transport_adapters import (
    CurrentBridgeAdapter,
    LocalTransportAdapterError,
    create_local_transport_adapter,
)
from utils.python_http2_bridge import (
    LOCAL_ADAPTER_HEALTH_PATH,
    LOCAL_ADAPTER_HEALTH_REQUEST_HEADER,
    LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER,
    LOCAL_ADAPTER_HEALTH_VALUE,
)


def test_create_local_transport_adapter_returns_bridge_adapter():
    adapter = create_local_transport_adapter("bridge", "https://example.com", listen_port=39030)

    assert isinstance(adapter, CurrentBridgeAdapter)
    assert adapter.details()["adapter_mode"] == "bridge"
    adapter.stop()


def test_create_local_transport_adapter_rejects_unknown_mode():
    with pytest.raises(ValueError, match="Unsupported local transport adapter mode"):
        create_local_transport_adapter("unknown", "https://example.com")


def test_bridge_adapter_wraps_bridge_start_failures(monkeypatch):
    adapter = CurrentBridgeAdapter("https://example.com", listen_port=39031)

    monkeypatch.setattr(adapter._bridge, "start", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    with pytest.raises(LocalTransportAdapterError, match="Current bridge could not start"):
        adapter.start()

    assert adapter.details()["adapter_status"] == "startup_failed"
    assert adapter.details()["transport_confidence"] == "failed"


def test_bridge_adapter_reports_listener_unreachable_after_start(monkeypatch):
    adapter = CurrentBridgeAdapter("https://example.com", listen_port=39032)

    monkeypatch.setattr(adapter._bridge, "start", lambda: adapter.adapter_url)
    monkeypatch.setattr(adapter, "_port_is_open", lambda: False)
    stopped = {"called": False}
    monkeypatch.setattr(adapter._bridge, "stop", lambda: stopped.__setitem__("called", True))

    with pytest.raises(LocalTransportAdapterError, match="local listener is not reachable"):
        adapter.start()

    assert stopped["called"] is True
    assert adapter.details()["adapter_status"] == "startup_failed"
    assert adapter.details()["transport_confidence"] == "failed"


def test_bridge_adapter_smoke_starts_and_answers_local_health():
    try:
        adapter = CurrentBridgeAdapter("https://example.com")
        adapter_url = adapter.start()
    except PermissionError as exc:
        pytest.skip(f"local loopback sockets are unavailable in this sandbox: {exc}")

    try:
        host = adapter_url.removeprefix("http://").split(":", 1)[0]
        port = int(adapter_url.rsplit(":", 1)[1])
        conn = HTTPConnection(host, port, timeout=3)
        conn.request(
            "GET",
            LOCAL_ADAPTER_HEALTH_PATH,
            headers={
                LOCAL_ADAPTER_HEALTH_REQUEST_HEADER: LOCAL_ADAPTER_HEALTH_VALUE,
                "Connection": "close",
            },
        )
        response = conn.getresponse()
        response.read()

        assert response.status == 204
        assert response.getheader(LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER) == LOCAL_ADAPTER_HEALTH_VALUE
        assert response.getheader("Server") in (None, "")
        assert adapter.details()["adapter_status"] == "ready"
        assert adapter.details()["transport_confidence"] == "normal"
    finally:
        adapter.stop()
