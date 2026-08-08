import json
import sys
from urllib.parse import urlparse

import pytest

import main
from orchestrator import SCAN_MODE_AUTOMATIC, SCAN_MODE_MANUAL, ScannerOrchestrator
from scanners.base import BaseScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from scanners.zap_scanner import ZapScanner
from utils.normalizer import parse_target
from utils.schema import SCHEMA_VERSION


class FakeDiscoveryNmapScanner(BaseScanner):
    def __init__(self, discovered_services):
        super().__init__("nmap")
        self.scanner_type = "network"
        self._discovered_services = [dict(service) for service in discovered_services]
        self.calls = []

    def is_available(self) -> bool:
        return True

    def get_version(self):
        return "nmap-test"

    def scan(self, target: str, options=None):
        options = dict(options or {})
        self.calls.append({"target": target, "options": options})

        services = [dict(service) for service in self._discovered_services]
        ports_spec = options.get("ports")
        if ports_spec:
            selected = set(ScannerOrchestrator._parse_ports_spec(ports_spec))
            services = [service for service in services if service.get("port") in selected]

        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-10T00:00:00Z",
            "command": "nmap -sV",
            "raw_output": "",
            "stderr": "",
            "exit_code": 0,
            "discovered_services": services,
            "findings": [],
        }

    def normalize(self, raw_results):
        return []


class FakeWebScanner(BaseScanner):
    def __init__(
        self,
        name: str,
        *,
        supports_http2_direct: bool = True,
        supports_proxy: bool = True,
        supports_http2_bridge: bool = True,
    ):
        super().__init__(name)
        self.scanner_type = "web"
        self.supports_http2_direct = supports_http2_direct
        self.supports_proxy = supports_proxy
        self.supports_http2_bridge = supports_http2_bridge
        self.calls = []

    def is_available(self) -> bool:
        return True

    def get_version(self):
        return f"{self.name}-test"

    def scan(self, target: str, options=None):
        options = dict(options or {})
        self.calls.append({"target": target, "options": options})
        return {
            "scanner": self.name,
            "target": target,
            "timestamp": "2026-04-10T00:00:00Z",
            "command": self.name,
            "raw_output": "",
            "stderr": "",
            "exit_code": 0,
            "findings": [{"target": target}],
        }

    def normalize(self, raw_results):
        parsed = parse_target(raw_results["target"])
        return [
            {
                "vulnerability_name": f"{self.name} finding",
                "severity": "low",
                "asset_id": raw_results["target"],
                "description": "Synthetic finding for scan-mode tests.",
                "remediation": "Fix the test issue.",
                "meta": {
                    "scanner": self.name,
                    "timestamp": raw_results["timestamp"],
                    "host": parsed["host"],
                    "scheme": parsed["scheme"],
                    "path": parsed["path"],
                    "port": parsed["port"],
                },
            }
        ]


def _fake_probe(target: str, timeout: int = 8):
    normalized = target if "://" in target else f"https://{target}"
    parsed = urlparse(normalized)
    if parsed.scheme == "http":
        return {
            "input_target": target,
            "normalized_target": normalized,
            "selected_scheme": "http",
            "reachable": True,
            "supports_http2": False,
            "supports_http1_1": True,
            "http2_only": False,
            "transport_detected": "http1_only",
            "detected_http_version": "HTTP/1.1",
            "probe_method": "fake",
            "reason": "fake http probe",
            "attempts": [],
        }

    return {
        "input_target": target,
        "normalized_target": normalized,
        "selected_scheme": "https",
        "reachable": True,
        "supports_http2": True,
        "supports_http1_1": True,
        "http2_only": False,
        "transport_detected": "http2_and_http1",
        "detected_http_version": "HTTP/1.1",
        "probe_method": "fake",
        "reason": "fake https probe prefers http1 when both are available",
        "attempts": [],
    }


def _fake_probe_http2_only(target: str, timeout: int = 8):
    normalized = target if "://" in target else f"https://{target}"
    return {
        "input_target": target,
        "normalized_target": normalized,
        "selected_scheme": "https",
        "reachable": True,
        "supports_http2": True,
        "supports_http1_1": False,
        "http2_only": True,
        "transport_detected": "http2_only",
        "detected_http_version": "HTTP/2",
        "probe_method": "fake",
        "reason": "fake https http2-only probe",
        "attempts": [],
    }


def test_nmap_service_inventory_marks_http_https_and_non_web_ports():
    scanner = NmapScanner()
    xml_output = """
    <nmaprun>
      <host>
        <address addr="example.com" />
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" />
            <service name="ssh" product="OpenSSH" version="9.7" />
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" />
            <service name="http" product="nginx" version="1.25.4" />
          </port>
          <port protocol="tcp" portid="443">
            <state state="open" />
            <service name="http" tunnel="ssl" product="nginx" version="1.25.4" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """

    services = scanner._parse_service_inventory(xml_output, "example.com")

    assert [service["port"] for service in services] == [22, 80, 443]
    assert services[0]["is_web"] is False
    assert services[0]["web_scheme"] == ""
    assert services[1]["is_web"] is True
    assert services[1]["web_scheme"] == "http"
    assert services[2]["is_web"] is True
    assert services[2]["web_scheme"] == "https"


def test_run_all_automatic_mode_routes_web_scanners_only_to_discovered_web_ports(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 22,
            "port_text": "22",
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "service_version": "9.7",
            "is_web": False,
            "web_scheme": "",
        },
        {
            "host": "example.com",
            "port": 80,
            "port_text": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "http",
        },
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "https",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")
    web_b = FakeWebScanner("web-b")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.register_scanner("web-b", web_b)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe)

    results = orchestrator.run_all("example.com", save_raw=False)

    assert nmap_scanner.calls[0]["target"] == "example.com"
    assert [call["target"] for call in web_a.calls] == [
        "http://example.com:80",
        "https://example.com:443",
    ]
    assert [call["target"] for call in web_b.calls] == [
        "http://example.com:80",
        "https://example.com:443",
    ]
    assert results["scan_mode"] == "automatic"
    assert results["discovery"]["web_services"] == discovered_services[1:]
    assert len(results["scan_plan"]) == 4
    assert len(results["all_findings"]) == 4
    assert "web-a@example.com:80" in results["scanner_execution"]
    assert "web-a@example.com:443" in results["scanner_execution"]

    findings_by_instance = {
        finding["meta"].get("scanner_instance")
        for finding in results["all_findings"]
        if finding["meta"].get("scanner") == "web-a"
    }
    assert findings_by_instance == {"web-a@example.com:80", "web-a@example.com:443"}


def test_run_all_automatic_mode_uses_probe_fallback_when_nmap_finds_no_usable_web_service(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "ssl",
            "service_version": "unknown",
            "is_web": False,
            "web_scheme": "",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")
    web_b = FakeWebScanner("web-b")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.register_scanner("web-b", web_b)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)
    orchestrator.set_selected_ports("443")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe_http2_only)

    results = orchestrator.run_all("https://example.com", save_raw=False)

    assert nmap_scanner.calls[0]["options"]["ports"] == "443"
    assert [call["target"] for call in web_a.calls] == ["https://example.com"]
    assert [call["target"] for call in web_b.calls] == ["https://example.com"]
    assert results["discovery"]["web_services"] == []
    assert results["discovery"]["probe_fallback_service"]["planning_source"] == "target_probe"
    assert results["discovery"]["probe_fallback_service"]["web_target"] == "https://example.com"
    assert len(results["scan_plan"]) == 2
    assert {entry["planning_source"] for entry in results["scan_plan"]} == {"target_probe"}
    assert (orchestrator.current_run_folder / "scan_results.json").exists()


def test_run_all_automatic_mode_probe_fallback_routes_adapter_scanners_through_bridge(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "ssl",
            "service_version": "unknown",
            "is_web": False,
            "web_scheme": "",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    direct_web = FakeWebScanner("direct-web", supports_http2_direct=True)
    adapter_web = FakeWebScanner("adapter-web", supports_http2_direct=False)

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("direct-web", direct_web)
    orchestrator.register_scanner("adapter-web", adapter_web)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)
    orchestrator.set_selected_ports("443")
    orchestrator.set_http2_adapter_mode("bridge")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe_http2_only)
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:39010",
    )

    results = orchestrator.run_all("https://example.com", save_raw=False)

    assert direct_web.calls[0]["target"] == "https://example.com"
    assert adapter_web.calls[0]["target"] == "http://127.0.0.1:39010/"
    assert adapter_web.calls[0]["options"]["origin_target"] == "https://example.com"
    assert results["scanner_execution"]["direct-web"]["adapter_mode"] == "direct"
    assert results["scanner_execution"]["adapter-web"]["adapter_mode"] == "bridge"


def test_run_all_automatic_mode_does_not_duplicate_probe_fallback_when_nmap_already_found_web_service(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "https",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe_http2_only)

    results = orchestrator.run_all("https://example.com", save_raw=False)

    assert [call["target"] for call in web_a.calls] == ["https://example.com:443"]
    assert len(results["scan_plan"]) == 1
    assert results["discovery"]["probe_fallback_service"] is None
    assert results["scan_plan"][0]["planning_source"] == "nmap_discovery"


def test_run_all_automatic_mode_forced_http2_filters_non_https_discovery_targets(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 80,
            "port_text": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "http",
        },
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "https",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)
    orchestrator.set_http_mode("http2")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe_http2_only)

    results = orchestrator.run_all("https://example.com", save_raw=False)

    assert results["discovery"]["web_services"] == [discovered_services[1]]
    assert [entry["target"] for entry in results["scan_plan"]] == ["https://example.com:443"]
    assert [call["target"] for call in web_a.calls] == ["https://example.com:443"]
    assert all(not entry["target"].startswith("http://example.com:80") for entry in results["scan_plan"])


def test_run_all_automatic_mode_forced_http2_uses_probe_fallback_https_target_for_real_scanners(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 80,
            "port_text": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "http",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.set_scan_mode(SCAN_MODE_AUTOMATIC)
    orchestrator.set_http_mode("http2")

    scan_calls = {}
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

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe_http2_only)

    bridge_starts = []
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: bridge_starts.append(origin_target) or "http://127.0.0.1:39071",
    )

    results = orchestrator.run_all("https://example.com", normalize=False, save_raw=False)

    assert results["discovery"]["web_services"] == []
    assert results["discovery"]["probe_fallback_service"]["planning_source"] == "target_probe"
    assert results["discovery"]["probe_fallback_service"]["web_target"] == "https://example.com"
    assert {entry["planning_source"] for entry in results["scan_plan"]} == {"target_probe"}
    assert {entry["target"] for entry in results["scan_plan"]} == {"https://example.com"}
    assert all(not entry["target"].startswith("http://example.com:80") for entry in results["scan_plan"])

    assert scan_calls["nuclei"][0]["target"] == "https://example.com"
    assert scan_calls["nuclei"][0]["options"]["force_http2"] is True
    assert results["scanner_execution"]["nuclei"]["adapter_mode"] == "direct"

    for scanner_name in ("wapiti", "zap", "nikto"):
        assert scan_calls[scanner_name][0]["target"] == "http://127.0.0.1:39071/"
        assert scan_calls[scanner_name][0]["options"]["origin_target"] == "https://example.com"
        assert results["scanner_execution"][scanner_name]["adapter_mode"] == "bridge"

    assert bridge_starts == [
        "https://example.com",
        "https://example.com",
        "https://example.com",
    ]


def test_run_all_manual_mode_limits_follow_up_scans_to_selected_ports(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 80,
            "port_text": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "http",
        },
        {
            "host": "example.com",
            "port": 443,
            "port_text": "443",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "https",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")
    web_b = FakeWebScanner("web-b")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.register_scanner("web-b", web_b)
    orchestrator.set_scan_mode(SCAN_MODE_MANUAL)
    orchestrator.set_selected_ports("443")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe)

    results = orchestrator.run_all("example.com", save_raw=False)

    assert nmap_scanner.calls[0]["options"]["ports"] == "443"
    assert [call["target"] for call in web_a.calls] == ["https://example.com:443"]
    assert [call["target"] for call in web_b.calls] == ["https://example.com:443"]
    assert results["scan_mode"] == "manual"
    assert results["discovery"]["selected_ports"] == [443]
    assert len(results["scan_plan"]) == 2
    assert set(results["scanner_execution"]) == {"nmap", "web-a", "web-b"}


def test_run_all_manual_mode_warns_when_selected_ports_are_not_open(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 80,
            "port_text": "80",
            "protocol": "tcp",
            "state": "open",
            "service": "http",
            "service_version": "1.25.4",
            "is_web": True,
            "web_scheme": "http",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.set_scan_mode(SCAN_MODE_MANUAL)
    orchestrator.set_selected_ports("443")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe)

    results = orchestrator.run_all("example.com", save_raw=False)

    assert web_a.calls == []
    warnings = results.get("warnings", [])
    assert any("did not report as open" in warning["warning"] for warning in warnings)
    assert any("did not schedule web scanners" in warning["warning"] for warning in warnings)
    assert results["scan_plan"] == []


def test_run_all_manual_mode_reports_selected_open_non_web_ports_clearly(monkeypatch, tmp_path):
    discovered_services = [
        {
            "host": "example.com",
            "port": 22,
            "port_text": "22",
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "service_version": "9.7",
            "is_web": False,
            "web_scheme": "",
        },
    ]
    nmap_scanner = FakeDiscoveryNmapScanner(discovered_services)
    web_a = FakeWebScanner("web-a")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nmap", nmap_scanner)
    orchestrator.register_scanner("web-a", web_a)
    orchestrator.set_scan_mode(SCAN_MODE_MANUAL)
    orchestrator.set_selected_ports("22")

    monkeypatch.setattr("orchestrator.probe_http_transport", _fake_probe)

    results = orchestrator.run_all("example.com", save_raw=False)

    assert web_a.calls == []
    assert results["discovery"]["services"][0]["is_web"] is False
    warnings = results.get("warnings", [])
    assert any("did not schedule web scanners" in warning["warning"] for warning in warnings)
    assert results["scan_plan"] == []


def test_main_manual_mode_requires_ports(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "example.com", "--scanner", "all", "--scan-mode", "manual"],
    )

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    assert excinfo.value.code == 2


def test_main_passes_scan_mode_and_selected_ports_to_orchestrator(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def set_http_mode(self, value):
            captured["http_mode"] = value

        def set_scan_mode(self, value):
            captured["scan_mode"] = value

        def set_selected_ports(self, value):
            captured["selected_ports"] = value

        def set_http2_adapter_mode(self, value):
            captured["http2_adapter_mode"] = value

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["target"] = target
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-10T00:00:00Z",
                "scanners_run": ["nmap"],
                "all_findings": [],
                "findings_by_scanner": {"nmap": []},
                "errors": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {},
                    "by_scanner": {"nmap": 0},
                },
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results))
            return path

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-mode", "manual",
            "--ports", "80,443",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["http_mode"] == "auto"
    assert captured["scan_mode"] == "manual"
    assert captured["selected_ports"] == "80,443"
    assert captured["http2_adapter_mode"] == "auto"
    assert captured["options"]["nmap"] == {"ports": "80,443"}
