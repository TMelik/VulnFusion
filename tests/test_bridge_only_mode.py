from __future__ import annotations

from typing import Any, Dict

from orchestrator import ScannerOrchestrator
from scanners.base import BaseScanner


def _probe() -> Dict[str, Any]:
    return {
        "input_target": "https://target.example.com",
        "normalized_target": "https://target.example.com",
        "selected_scheme": "https",
        "supports_http2": True,
        "supports_http1_1": False,
        "reachable": True,
        "http2_only": True,
        "transport_detected": "http2_only",
        "detected_http_version": "HTTP/2",
        "probe_method": "python-httpx",
        "reason": "probe=http2_only",
    }


class DummyScanner(BaseScanner):
    def __init__(
        self,
        name: str,
        *,
        supports_http2_direct: bool = False,
        supports_proxy: bool = False,
        supports_http2_bridge: bool = False,
        assessment: Dict[str, Any] | None = None,
    ) -> None:
        super().__init__(name)
        self.scanner_type = "web"
        self.supports_http2_direct = supports_http2_direct
        self.supports_proxy = supports_proxy
        self.supports_http2_bridge = supports_http2_bridge
        self._assessment = dict(assessment or {})
        self.calls: list[Dict[str, Any]] = []

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.calls.append({"target": target, "options": dict(options or {})})
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-18T00:00:00Z",
            "findings": [],
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
        }

    def normalize(self, raw_results):
        return []

    def assess_execution(self, raw_results):
        return dict(self._assessment)

    def get_proxy_options(self, proxy_url: str):
        return {"proxy_url": proxy_url}


def test_bridge_mode_keeps_direct_http2_scanners_direct(monkeypatch, tmp_path):
    scanner = DummyScanner("direct-web", supports_http2_direct=True, supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("direct-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe())
    bridge_calls: list[str] = []
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda target: bridge_calls.append(target) or "http://127.0.0.1:39040",
    )

    result = orchestrator.run_scanner("direct-web", "https://target.example.com", save_raw=False)

    assert bridge_calls == []
    assert scanner.calls[0]["target"] == "https://target.example.com"
    assert scanner.calls[0]["options"]["force_http2"] is True
    assert result["scanner_execution"]["adapter_mode"] == "direct"


def test_bridge_mode_prefers_bridge_over_proxy_fallback(monkeypatch, tmp_path):
    scanner = DummyScanner("adapter-web", supports_proxy=True, supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(
        reports_dir=tmp_path,
        http2_proxy_url="http://proxy.internal:8080",
        http2_adapter_mode="bridge",
    )
    orchestrator.register_scanner("adapter-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe())
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda target: "http://127.0.0.1:39041",
    )

    result = orchestrator.run_scanner("adapter-web", "https://target.example.com", save_raw=False)

    assert scanner.calls[0]["target"] == "http://127.0.0.1:39041/"
    assert "proxy_url" not in scanner.calls[0]["options"]
    assert scanner.calls[0]["options"]["adapter_mode"] == "bridge"
    assert result["scanner_execution"]["adapter_mode"] == "bridge"
    assert result["scanner_execution"]["origin_target"] == "https://target.example.com"


def test_degraded_bridge_result_is_kept_without_retry(monkeypatch, tmp_path):
    scanner = DummyScanner(
        "adapter-web",
        supports_http2_bridge=True,
        assessment={
            "degraded_execution": True,
            "scanner_error": "Scanner execution was degraded.",
        },
    )
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("adapter-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe())
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda target: "http://127.0.0.1:39042",
    )

    result = orchestrator.run_scanner("adapter-web", "https://target.example.com", save_raw=False)

    assert len(scanner.calls) == 1
    assert result["scanner_execution"]["adapter_mode"] == "bridge"
    assert result["scanner_execution"]["degraded_execution"] is True
    assert result["error"] == "Scanner execution was degraded."


def test_orchestrator_no_longer_exposes_removed_adapter_paths():
    removed_names = [
        "_start_auto_http2_" + "mitm" + "proxy",
        "_" + "mitm" + "proxy" + "_route",
        "_retry_with_" + "mitm" + "proxy" + "_if_needed",
    ]

    for name in removed_names:
        assert not hasattr(ScannerOrchestrator, name)
