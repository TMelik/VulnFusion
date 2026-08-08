from __future__ import annotations

from typing import Any, Dict

from orchestrator import ScannerOrchestrator
from scanners.base import BaseScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from scanners.zap_scanner import ZapScanner
from utils.http_transport_adapters import LocalTransportAdapterError


def _probe(*, http2_only: bool = True) -> Dict[str, Any]:
    return {
        "input_target": "https://example.com",
        "normalized_target": "https://example.com",
        "selected_scheme": "https",
        "supports_http2": True,
        "supports_http1_1": not http2_only,
        "reachable": True,
        "http2_only": http2_only,
        "transport_detected": "http2_only" if http2_only else "http2_and_http1",
        "detected_http_version": "HTTP/2" if http2_only else "HTTP/1.1",
        "probe_method": "python-httpx",
        "reason": (
            "probe=http2_only"
            if http2_only
            else "probe=http2_and_http1; prefers_http1"
        ),
    }


class DummyWebScanner(BaseScanner):
    def __init__(
        self,
        name: str,
        *,
        supports_http2_direct: bool = False,
        supports_proxy: bool = False,
        supports_http2_bridge: bool = False,
    ) -> None:
        super().__init__(name)
        self.scanner_type = "web"
        self.supports_http2_direct = supports_http2_direct
        self.supports_proxy = supports_proxy
        self.supports_http2_bridge = supports_http2_bridge
        self.calls: list[Dict[str, Any]] = []

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
        self.calls.append({"target": target, "options": dict(options or {})})
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-18T00:00:00Z",
            "findings": [{"id": "raw"}],
            "exit_code": 0,
        }

    def normalize(self, raw_results):
        return [{
            "vulnerability_name": "Dummy finding",
            "severity": "medium",
            "asset_id": raw_results["target"],
            "description": "Dummy description",
            "remediation": "Dummy remediation",
            "meta": {"scanner": self.name},
        }]

    def get_proxy_options(self, proxy_url: str):
        return {"proxy_url": proxy_url}


def test_http2_capable_scanner_stays_direct_when_bridge_mode_is_requested(monkeypatch, tmp_path):
    scanner = DummyWebScanner("direct-web", supports_http2_direct=True, supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("direct-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=True))
    bridge_calls: list[str] = []
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: bridge_calls.append(origin_target) or "http://127.0.0.1:39051",
    )

    result = orchestrator.run_scanner("direct-web", "https://example.com", save_raw=False)

    assert bridge_calls == []
    assert scanner.calls[0]["target"] == "https://example.com"
    assert scanner.calls[0]["options"]["force_http2"] is True
    assert result["scanner_execution"]["adapter_mode"] == "direct"


def test_bridge_routing_is_used_for_adapter_scanner_on_http2_only_target(monkeypatch, tmp_path):
    scanner = DummyWebScanner("adapter-web", supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("adapter-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=True))
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:39052",
    )

    result = orchestrator.run_scanner("adapter-web", "https://example.com", save_raw=False)

    assert scanner.calls[0]["target"] == "http://127.0.0.1:39052/"
    assert scanner.calls[0]["options"]["adapter_mode"] == "bridge"
    assert scanner.calls[0]["options"]["origin_target"] == "https://example.com"
    assert result["scanner_execution"]["adapter_mode"] == "bridge"


def test_auto_route_prefers_http1_when_target_supports_both_protocols(monkeypatch, tmp_path):
    scanner = DummyWebScanner("dual-stack-web", supports_http2_direct=True, supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("dual-stack-web", scanner)

    bridge_calls: list[str] = []
    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=False))
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: bridge_calls.append(origin_target) or "http://127.0.0.1:39099",
    )

    result = orchestrator.run_scanner("dual-stack-web", "https://example.com", save_raw=False)

    assert bridge_calls == []
    assert scanner.calls[0]["target"] == "https://example.com"
    assert "force_http2" not in scanner.calls[0]["options"]
    assert result["scanner_execution"]["adapter_mode"] == "direct"
    assert result["scanner_execution"]["detected_http_version"] == "HTTP/1.1"
    assert "prefers HTTP/1.1" in result["scanner_execution"]["scanner_transport_notes"]


def test_manual_proxy_route_is_preserved_in_auto_mode(monkeypatch, tmp_path):
    scanner = DummyWebScanner("proxy-web", supports_proxy=True)
    orchestrator = ScannerOrchestrator(
        reports_dir=tmp_path,
        http2_proxy_url="http://proxy.internal:8080",
        http2_adapter_mode="auto",
    )
    orchestrator.register_scanner("proxy-web", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=True))

    result = orchestrator.run_scanner("proxy-web", "https://example.com", save_raw=False)

    assert scanner.calls[0]["target"] == "https://example.com"
    assert scanner.calls[0]["options"]["proxy_url"] == "http://proxy.internal:8080"
    assert result["scanner_execution"]["adapter_mode"] == "proxy"
    assert result["scanner_execution"]["scan_route"] == "proxied"


def test_forced_http2_route_uses_bridge_for_compatibility_scanner(monkeypatch, tmp_path):
    scanner = DummyWebScanner("bridge-web", supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("bridge-web", scanner)
    orchestrator.set_http_mode("http2")

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=True))
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:39053",
    )

    result = orchestrator.run_scanner("bridge-web", "https://example.com", save_raw=False)

    assert scanner.calls[0]["target"] == "http://127.0.0.1:39053/"
    assert result["scanner_execution"]["adapter_mode"] == "bridge"
    assert result["scanner_execution"]["requested_http_mode"] == "http2"


def test_bridge_start_failure_skips_scan_with_clear_reason(monkeypatch, tmp_path):
    scanner = DummyWebScanner("bridge-fail", supports_http2_bridge=True)
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("bridge-fail", scanner)

    monkeypatch.setattr(orchestrator, "probe_target", lambda target: _probe(http2_only=True))
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: (_ for _ in ()).throw(LocalTransportAdapterError("bridge startup failed")),
    )

    result = orchestrator.run_scanner("bridge-fail", "https://example.com", save_raw=False)

    assert scanner.calls == []
    assert result["scanner_execution"]["adapter_mode"] == "bridge"
    assert result["scanner_execution"]["adapter_status"] == "startup_failed"
    assert "automatic local HTTP/2 bridge could not be started" in result["error"]


def test_forced_http2_route_reuses_equivalent_successful_probe_for_real_scanners(monkeypatch, tmp_path):
    probe_calls: list[str] = []

    def fake_probe(target: str, timeout: int = 8) -> Dict[str, Any]:
        probe_calls.append(target)
        if target == "https://example.com":
            return {
                "input_target": target,
                "normalized_target": "https://example.com",
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
        return {
            "input_target": target,
            "normalized_target": target,
            "selected_scheme": "https",
            "supports_http2": False,
            "supports_http1_1": False,
            "reachable": False,
            "http2_only": False,
            "transport_detected": "unknown",
            "detected_http_version": "unknown",
            "probe_method": "python-httpx",
            "reason": "fragile re-probe failed",
        }

    monkeypatch.setattr("orchestrator.probe_http_transport", fake_probe)

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.set_http_mode("http2")

    scan_calls: Dict[str, list[Dict[str, Any]]] = {}
    for name, scanner in (
        ("nuclei", NucleiScanner()),
        ("wapiti", WapitiScanner()),
        ("zap", ZapScanner()),
        ("nikto", NiktoScanner()),
    ):
        orchestrator.register_scanner(name, scanner)
        scan_calls[name] = []
        monkeypatch.setattr(scanner, "is_available", lambda _scanner=scanner: True)
        monkeypatch.setattr(
            scanner,
            "scan",
            lambda target, options=None, *, _name=name: scan_calls[_name].append(
                {"target": target, "options": dict(options or {})}
            ) or {
                "scanner": _name,
                "target": target,
                "timestamp": "2026-04-18T00:00:00Z",
                "findings": [],
                "exit_code": 0,
            },
        )

    bridge_starts: list[str] = []
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: bridge_starts.append(origin_target) or "http://127.0.0.1:39061",
    )

    # Simulate main.py's successful pre-scan target probe on the original target string.
    initial_probe = orchestrator.probe_target("https://example.com")
    assert initial_probe["supports_http2"] is True
    assert initial_probe["http2_only"] is True

    nuclei_result = orchestrator.run_scanner("nuclei", "https://example.com:443", normalize=False, save_raw=False)
    wapiti_result = orchestrator.run_scanner("wapiti", "https://example.com:443", normalize=False, save_raw=False)
    zap_result = orchestrator.run_scanner("zap", "https://example.com:443", normalize=False, save_raw=False)
    nikto_result = orchestrator.run_scanner("nikto", "https://example.com:443", normalize=False, save_raw=False)

    assert probe_calls == ["https://example.com"]

    assert nuclei_result["scanner_execution"]["adapter_mode"] == "direct"
    assert nuclei_result["scanner_execution"]["transport_detected"] == "http2_only"
    assert scan_calls["nuclei"][0]["options"]["force_http2"] is True

    for scanner_name, result in (
        ("wapiti", wapiti_result),
        ("zap", zap_result),
        ("nikto", nikto_result),
    ):
        assert result["scanner_execution"]["adapter_mode"] == "bridge"
        assert result["scanner_execution"]["transport_detected"] == "http2_only"
        assert scan_calls[scanner_name][0]["target"] == "http://127.0.0.1:39061/"
        assert scan_calls[scanner_name][0]["options"]["origin_target"] == "https://example.com"

    assert len(bridge_starts) == 3
