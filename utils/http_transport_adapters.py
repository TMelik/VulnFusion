"""
Shared local HTTP transport adapters for compatibility scanning.

These adapters expose a local HTTP/1.1 endpoint and forward requests to one
configured upstream origin. The orchestrator can use them as a scanner-agnostic
compatibility layer for web scanners that do not speak HTTP/2 directly.
"""

from __future__ import annotations

import contextlib
import socket
from http.client import HTTPConnection, HTTPException
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from utils.python_http2_bridge import (
    BackgroundBridgeServer,
    LOCAL_ADAPTER_HEALTH_PATH,
    LOCAL_ADAPTER_HEALTH_REQUEST_HEADER,
    LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER,
    LOCAL_ADAPTER_HEALTH_VALUE,
)


HTTP2_ADAPTER_MODE_AUTO = "auto"
HTTP2_ADAPTER_MODE_BRIDGE = "bridge"

SUPPORTED_HTTP2_ADAPTER_MODES = {
    HTTP2_ADAPTER_MODE_AUTO,
    HTTP2_ADAPTER_MODE_BRIDGE,
}

TRANSPORT_CONFIDENCE_NORMAL = "normal"
TRANSPORT_CONFIDENCE_FAILED = "failed"
ADAPTER_STATUS_IDLE = "idle"
ADAPTER_STATUS_STARTING = "starting"
ADAPTER_STATUS_READY = "ready"
ADAPTER_STATUS_STOPPED = "stopped"
ADAPTER_STATUS_STARTUP_FAILED = "startup_failed"
RUNTIME_STATE_INITIALIZING = "initializing"
RUNTIME_STATE_RUNNING = "running"
RUNTIME_STATE_STOPPED = "stopped"
RUNTIME_STATE_FAILED = "failed"


class LocalTransportAdapterError(RuntimeError):
    """Structured transport-adapter startup error used by orchestration/reporting."""

    def __init__(self, message: str, *, details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.details = dict(details or {})


class LocalTransportAdapter:
    """Interface for a single-origin local compatibility adapter."""

    kind = "adapter"

    def __init__(
        self,
        origin: str,
        listen_host: str = "127.0.0.1",
        listen_port: Optional[int] = None,
        startup_timeout: float = 5.0,
        health_check_timeout: float = 3.0,
    ) -> None:
        self.origin = origin
        self.listen_host = listen_host
        self.listen_port = listen_port or self._pick_free_port(listen_host)
        self.startup_timeout = startup_timeout
        self.health_check_timeout = health_check_timeout
        self._details: Dict[str, Any] = {
            "adapter_status": ADAPTER_STATUS_IDLE,
            "adapter_runtime_state": RUNTIME_STATE_STOPPED,
            "adapter_failure_reason": None,
            "adapter_diagnostics": None,
            "transport_confidence": None,
        }

    @staticmethod
    def _pick_free_port(host: str) -> int:
        """Reserve a free local port for the adapter listener."""
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.bind((host, 0))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return int(sock.getsockname()[1])

    @property
    def adapter_url(self) -> str:
        return f"http://{self.listen_host}:{self.listen_port}"

    def _port_is_open(self) -> bool:
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.2)
            return sock.connect_ex((self.listen_host, self.listen_port)) == 0

    def _http_listener_responds(self) -> tuple[bool, str]:
        """Return whether the adapter endpoint can complete an HTTP request."""
        parsed = urlparse(self.adapter_url)
        host = parsed.hostname or self.listen_host
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        conn = HTTPConnection(host, port, timeout=self.health_check_timeout)
        try:
            conn.request(
                "GET",
                LOCAL_ADAPTER_HEALTH_PATH,
                headers={
                    "Connection": "close",
                    "User-Agent": "vuln-manager-adapter-health/1.0",
                    LOCAL_ADAPTER_HEALTH_REQUEST_HEADER: LOCAL_ADAPTER_HEALTH_VALUE,
                },
            )
            response = conn.getresponse()
            response.read(1)
            response_marker = response.getheader(LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER)
            if response.status == 204 and response_marker == LOCAL_ADAPTER_HEALTH_VALUE:
                return True, (
                    "HTTP listener reached the local adapter health endpoint "
                    f"with status {response.status}"
                )
            return False, (
                "HTTP listener responded, but not with the expected local "
                f"adapter health marker: status={response.status}, "
                f"{LOCAL_ADAPTER_HEALTH_RESPONSE_HEADER}={response_marker!r}"
            )
        except Exception as exc:
            return False, str(exc)
        finally:
            with contextlib.suppress(OSError, HTTPException):
                conn.close()

    def _update_details(self, **kwargs: Any) -> None:
        self._details.update(kwargs)

    def start(self) -> str:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError

    def details(self) -> Dict[str, Optional[str]]:
        details = {
            "adapter_mode": self.kind,
            "adapter_url": self.adapter_url,
            "origin_target": self.origin,
            "listen_host": self.listen_host,
            "listen_port": str(self.listen_port),
        }
        details.update(self._details)
        return details


class CurrentBridgeAdapter(LocalTransportAdapter):
    """Wrap the existing lightweight Python HTTP/2 reverse bridge."""

    kind = HTTP2_ADAPTER_MODE_BRIDGE

    def __init__(
        self,
        origin: str,
        listen_host: str = "127.0.0.1",
        listen_port: Optional[int] = None,
        timeout: float = 20.0,
        startup_timeout: float = 5.0,
    ) -> None:
        super().__init__(
            origin=origin,
            listen_host=listen_host,
            listen_port=listen_port,
            startup_timeout=startup_timeout,
        )
        self.timeout = timeout
        self._update_details(
            adapter_runtime="python-bridge",
            adapter_translation_chain="python HTTP/2 bridge -> origin",
        )
        self._bridge = BackgroundBridgeServer(
            origin=origin,
            listen_host=listen_host,
            listen_port=self.listen_port,
            timeout=timeout,
            startup_timeout=startup_timeout,
        )

    def start(self) -> str:
        self._update_details(
            adapter_status=ADAPTER_STATUS_STARTING,
            adapter_runtime_state=RUNTIME_STATE_INITIALIZING,
            adapter_failure_reason=None,
            adapter_diagnostics=None,
            transport_confidence=None,
            adapter_upstream_url=self.origin,
        )
        try:
            adapter_url = self._bridge.start()
        except Exception as exc:
            self._update_details(
                adapter_status=ADAPTER_STATUS_STARTUP_FAILED,
                adapter_runtime_state=RUNTIME_STATE_FAILED,
                adapter_failure_reason=str(exc),
                transport_confidence=TRANSPORT_CONFIDENCE_FAILED,
            )
            raise LocalTransportAdapterError(
                f"Current bridge could not start for {self.origin}: {exc}",
                details=self.details(),
            ) from exc
        if not self._port_is_open():
            failure_reason = (
                f"Current bridge started for {self.origin}, but the local listener is not reachable on {adapter_url}."
            )
            self._bridge.stop()
            self._update_details(
                adapter_status=ADAPTER_STATUS_STARTUP_FAILED,
                adapter_runtime_state=RUNTIME_STATE_FAILED,
                adapter_failure_reason=failure_reason,
                transport_confidence=TRANSPORT_CONFIDENCE_FAILED,
            )
            raise LocalTransportAdapterError(failure_reason, details=self.details())
        self._update_details(
            adapter_status=ADAPTER_STATUS_READY,
            adapter_runtime_state=RUNTIME_STATE_RUNNING,
            adapter_failure_reason=None,
            adapter_diagnostics=None,
            transport_confidence=TRANSPORT_CONFIDENCE_NORMAL,
            adapter_upstream_url=self.origin,
        )
        return adapter_url

    def stop(self) -> None:
        self._bridge.stop()
        if self._details.get("adapter_status") != ADAPTER_STATUS_STARTUP_FAILED:
            self._update_details(
                adapter_status=ADAPTER_STATUS_STOPPED,
                adapter_runtime_state=RUNTIME_STATE_STOPPED,
                adapter_failure_reason=None,
                transport_confidence=TRANSPORT_CONFIDENCE_NORMAL,
            )


def create_local_transport_adapter(
    adapter_mode: str,
    origin: str,
    listen_host: str = "127.0.0.1",
    listen_port: Optional[int] = None,
) -> LocalTransportAdapter:
    """Build the requested local compatibility adapter."""
    if adapter_mode == HTTP2_ADAPTER_MODE_BRIDGE:
        return CurrentBridgeAdapter(
            origin=origin,
            listen_host=listen_host,
            listen_port=listen_port,
        )
    raise ValueError(f"Unsupported local transport adapter mode: {adapter_mode}")
