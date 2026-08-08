import json
import inspect
import os
import shutil
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import main
import pytest
import yaml
from orchestrator import ScannerOrchestrator
from scanners.base import BaseScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from scanners.zap_scanner import ZapScanner
from utils.normalizer import normalize_web_target
from utils.schema import SCHEMA_VERSION, validate_finding


@contextmanager
def _serve_zap_smoke_site():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = (
                "<html><body>"
                "<a href='/page'>page</a>"
                "<form action='/submit' method='post'>"
                "<input name='q' value='test' />"
                "</form>"
                "</body></html>"
            )
            if self.path.startswith("/page"):
                body = "<html><body><p>page</p></body></html>"
            payload = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        port = server.server_address[1]
        yield f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _zap_docker_smoke_enabled(pytestconfig) -> bool:
    return bool(
        pytestconfig.getoption("--run-zap-docker")
        or os.getenv("RUN_ZAP_DOCKER_SMOKE_TESTS") == "1"
    )


def _zap_docker_pull_enabled(pytestconfig) -> bool:
    return bool(
        pytestconfig.getoption("--zap-docker-pull-image")
        or os.getenv("ZAP_DOCKER_PULL_IMAGE") == "1"
    )


def _format_subprocess_error(result: subprocess.CompletedProcess[str]) -> str:
    output = (result.stderr or result.stdout or "").strip()
    return output or f"exit code {result.returncode}"


def _zap_smoke_debug_snapshot(result: dict) -> str:
    return json.dumps(
        {
            "error": result.get("error"),
            "stdout": result.get("stdout"),
            "stderr": result.get("stderr"),
            "exit_code": result.get("exit_code"),
            "report_load_issue": result.get("report_load_issue"),
            "expected_raw_output_path": result.get("expected_raw_output_path"),
            "raw_output_path": result.get("raw_output_path"),
            "raw_artifact_dir_entries": result.get("raw_artifact_dir_entries"),
            "command": result.get("command"),
        },
        indent=2,
        sort_keys=True,
        default=str,
    )


def _ensure_zap_docker_smoke_preconditions(pytestconfig) -> None:
    image = "ghcr.io/zaproxy/zaproxy:stable"
    if not _zap_docker_smoke_enabled(pytestconfig):
        pytest.skip(
            "Set RUN_ZAP_DOCKER_SMOKE_TESTS=1 or pass --run-zap-docker to enable real ZAP Docker smoke tests."
        )

    scanner = ZapScanner()
    if not scanner._check_docker():
        if shutil.which("docker") is None:
            pytest.skip("Docker CLI is not installed or not on PATH for the ZAP AF smoke test.")

        try:
            docker_info = subprocess.run(
                ["docker", "info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.TimeoutExpired:
            pytest.skip("Docker daemon probe timed out for the ZAP AF smoke test.")
        except OSError as exc:
            pytest.skip(f"Docker daemon probe failed for the ZAP AF smoke test: {exc}")
        if docker_info.returncode == 0:
            pass
        else:
            pytest.skip(
                "Docker daemon is unavailable for the ZAP AF smoke test: "
                f"{_format_subprocess_error(docker_info)}"
            )

    try:
        image_ready = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except subprocess.TimeoutExpired:
        pytest.skip("Docker image probe timed out for the ZAP AF smoke test.")
    except OSError as exc:
        pytest.skip(f"Docker image probe failed for the ZAP AF smoke test: {exc}")
    if image_ready.returncode == 0:
        return

    if not _zap_docker_pull_enabled(pytestconfig):
        pytest.skip(
            "ZAP Docker image ghcr.io/zaproxy/zaproxy:stable is not present locally. "
            "Pull it first or rerun with --zap-docker-pull-image / ZAP_DOCKER_PULL_IMAGE=1."
        )

    try:
        pull_result = subprocess.run(
            ["docker", "pull", image],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("Timed out while pulling ghcr.io/zaproxy/zaproxy:stable for the ZAP AF smoke test.")
    except OSError as exc:
        pytest.fail(f"Unable to start docker pull for the ZAP AF smoke test: {exc}")
    if pull_result.returncode != 0:
        pytest.fail(
            "Unable to pull ghcr.io/zaproxy/zaproxy:stable for the ZAP AF smoke test: "
            f"{_format_subprocess_error(pull_result)}"
        )


def test_main_passes_requested_severities_to_nuclei_and_wapiti(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["target"] = target
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["nuclei", "wapiti"],
                "all_findings": [],
                "findings_by_scanner": {"nuclei": [], "wapiti": []},
                "errors": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {},
                    "by_scanner": {"nuclei": 0, "wapiti": 0},
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
            "--severity", "high", "medium",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["target"] == "example.com"
    assert captured["options"]["nuclei"] == {"severity": ["high", "medium"]}
    assert captured["options"]["wapiti"] == {"severity": ["high", "medium"]}


def test_main_sets_requested_http2_adapter_mode(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def set_http_mode(self, value):
            captured["http_mode"] = value

        def set_http2_adapter_mode(self, value):
            captured["http2_adapter_mode"] = value

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["zap"],
                "all_findings": [],
                "findings_by_scanner": {"zap": []},
                "errors": [],
                "summary": {
                    "total_findings": 0,
                    "by_severity": {},
                    "by_scanner": {"zap": 0},
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
            "--target", "https://example.com",
            "--scanner", "all",
            "--http2-adapter-mode", "bridge",
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
    assert captured["http2_adapter_mode"] == "bridge"


def test_main_rejects_removed_http2_adapter_mode(monkeypatch, capsys):
    removed_mode = "mitm" + "proxy"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "zap",
            "--http2-adapter-mode", removed_mode,
            "--no-save",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "invalid choice" in captured.err
    assert removed_mode in captured.err


def test_main_list_scanners_shows_bridge_only_adapter_status(monkeypatch, tmp_path, capsys):
    class FakeOrchestrator:
        current_run_folder = None

        def set_http_mode(self, value):
            pass

        def set_http2_adapter_mode(self, value):
            pass

        def list_scanners(self):
            return []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(sys, "argv", ["main.py", "--list-scanners"])

    rc = main.main()

    captured = capsys.readouterr()
    assert rc == 0
    assert "HTTP/2 Compatibility Adapters" in captured.out
    assert "bridge: Available" in captured.out
    assert ("mitm" + "proxy") not in captured.out


def test_main_strips_comparison_and_scoring_context_from_exported_results(monkeypatch, tmp_path, capsys):

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-04T00:00:00Z",
                "scanners_run": ["nuclei"],
                "all_findings": [
                    {
                        "vulnerability_name": "Test finding",
                        "severity": "high",
                        "asset_id": "https://example.com",
                        "description": "desc",
                        "remediation": "fix",
                        "meta": {"scanner": "nuclei"},
                    }
                ],
                "errors": [],
                "summary": {"total_findings": 1, "by_severity": {"high": 1}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results))
            return path

    def fake_compare(results, data_dir):
        results = dict(results)
        results["previous_findings"] = [
            {
                "vulnerability_name": "Test finding",
                "severity": "high",
                "asset_id": "https://example.com",
                "description": "prev",
                "remediation": "fix",
                "meta": {"scanner": "nuclei"},
            }
        ]
        results["asset_criticality"] = {"https://example.com": "high"}
        results["business_context"] = {"environment": "production"}
        results["summary"]["by_priority"] = {"P0": 0, "P1": 1, "P2": 0, "P3": 0, "P4": 0}
        return results

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(main, "add_comparison_to_results", fake_compare)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--compare",
            "--json",
            "--no-dedupe",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()
    normalized = json.loads((tmp_path / "normalized.json").read_text())

    assert rc == 0
    assert "previous_findings" not in normalized
    assert "asset_criticality" not in normalized
    assert "business_context" not in normalized
    assert "by_priority" in normalized["summary"]
    assert "risk_score" in normalized["all_findings"][0]
    assert "priority" in normalized["all_findings"][0]


def test_main_exports_public_runtime_scoring_fields(monkeypatch, tmp_path, capsys):

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-04T00:00:00Z",
                "scanners_run": ["nuclei"],
                "all_findings": [
                    {
                        "vulnerability_name": "Enriched finding",
                        "severity": "high",
                        "asset_id": "https://example.com",
                        "description": "desc",
                        "remediation": "fix",
                        "priority": "P0",
                        "risk_score": 95,
                        "risk_rationale": "derived explanation",
                        "meta": {
                            "scanner": "nuclei",
                            "cve_id": "CVE-2024-1234",
                            "cvss_score": 9.8,
                            "epss_score": 0.91,
                            "kev_listed": True,
                            "business_context": {"environment": "production"},
                        },
                    }
                ],
                "errors": [],
                "summary": {
                    "total_findings": 1,
                    "by_severity": {"high": 1},
                    "by_priority": {"P0": 1, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
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
            "--json",
            "--no-dedupe",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()
    normalized = json.loads((tmp_path / "normalized.json").read_text())

    assert rc == 0
    finding = normalized["all_findings"][0]

    assert finding["priority"] == "P0"
    assert finding["risk_score"] == 85
    assert "Final score: 85/100 -> P0" in finding["risk_rationale"]
    assert isinstance(finding["risk_factors"], dict)
    assert finding["risk_factors"]["active_exploitation"]["kev_used"] is True
    assert "impact_for_developers" not in finding
    assert "cvss_score" not in finding["meta"]
    assert "epss_score" not in finding["meta"]
    assert "kev_listed" not in finding["meta"]
    assert "business_context" not in finding["meta"]
    assert normalized["summary"]["by_priority"]["P0"] == 1
    assert "knowledge_sync" not in normalized
    assert "knowledge_db_path" not in normalized


def test_main_maps_wapiti_and_nikto_cli_tuning_options(monkeypatch, tmp_path, capsys):
    captured = {}

    def fake_factory(reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8):
        captured["http_probe_timeout"] = http_probe_timeout
        return FakeOrchestrator()

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["target"] = target
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["wapiti", "nikto"],
                "all_findings": [],
                "findings_by_scanner": {"wapiti": [], "nikto": []},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {"wapiti": 0, "nikto": 0}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results))
            return path

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        fake_factory,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--severity", "high",
            "--wapiti-level", "1",
            "--wapiti-modules", "sql", "xss",
            "--wapiti-timeout", "120",
            "--wapiti-args", "--scope folder",
            "--nikto-timeout", "90",
            "--nikto-tuning", "123b",
            "--nikto-args", "-Plugins headers",
            "--http-probe-timeout", "5",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["target"] == "example.com"
    assert captured["http_probe_timeout"] == 5
    assert captured["options"]["wapiti"] == {
        "severity": ["high"],
        "level": 1,
        "modules": ["sql", "xss"],
        "timeout": 120,
        "args": ["--scope", "folder"],
    }
    assert captured["options"]["nikto"] == {
        "timeout": 90,
        "tuning": "123b",
        "args": ["-Plugins", "headers"],
    }


def test_main_maps_zap_proxy_cli_options(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["zap"],
                "all_findings": [],
                "findings_by_scanner": {"zap": []},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {"zap": 0}},
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
            "--target", "https://proxy.local",
            "--scanner", "all",
            "--zap-use-proxy",
            "--zap-proxy-url", "http://127.0.0.1:8081",
            "--zap-proxy-original-target", "https://example.com",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"] == {
        "timeout": 1200,
        "use_proxy": True,
        "proxy_url": "http://127.0.0.1:8081",
        "original_target": "https://example.com",
    }


def test_main_maps_zap_active_scan_cli_option(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["zap"],
                "all_findings": [],
                "findings_by_scanner": {"zap": []},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {"zap": 0}},
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
            "--target", "https://example.com",
            "--scanner", "all",
            "--zap-active-scan",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["active_scan"] is True
    assert captured["options"]["zap"]["timeout"] == 1200


def test_main_maps_zap_af_plan_cli_option(monkeypatch, tmp_path, capsys):
    captured = {}
    template_path = tmp_path / "zap-template.yaml"
    template_path.write_text("env: {}\njobs: []\n", encoding="utf-8")

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["zap"],
                "all_findings": [],
                "findings_by_scanner": {"zap": []},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {"zap": 0}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results))
            return path

    monkeypatch.setenv("HOME", str(tmp_path))
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
            "--target", "https://example.com",
            "--scanner", "all",
            "--zap-af-plan", "~/zap-template.yaml",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["af_plan_path"] == str(template_path)
    assert captured["options"]["zap"]["timeout"] == 1200


def test_main_requires_existing_zap_af_plan_path(monkeypatch, tmp_path, capsys):
    missing_path = tmp_path / "missing-zap-template.yaml"

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "zap",
            "--zap-af-plan", "~/missing-zap-template.yaml",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "--zap-af-plan does not exist:" in captured.err
    assert str(missing_path) in captured.err


def test_main_requires_zap_af_plan_to_be_regular_file(monkeypatch, tmp_path, capsys):
    plan_dir = tmp_path / "zap-plan-dir"
    plan_dir.mkdir()

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "zap",
            "--zap-af-plan", "~/zap-plan-dir",
        ],
    )

    with pytest.raises(SystemExit) as excinfo:
        main.main()

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "--zap-af-plan must point to a regular file:" in captured.err
    assert str(plan_dir) in captured.err


def test_main_probe_only_outputs_target_probe_json(monkeypatch, capsys):
    class FakeOrchestrator:
        scanners = {}

        def set_http_mode(self, http_mode):
            self.http_mode = http_mode

        def probe_target(self, target):
            return {
                "input_target": target,
                "normalized_target": "https://example.com",
                "selected_scheme": "https",
                "detected_http_version": "HTTP/1.1",
                "supports_http2": True,
                "supports_http1_1": True,
                "reason": "probe ok; prefers HTTP/1.1",
            }

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "example.com", "--probe-only", "--json"],
    )

    rc = main.main()
    captured = capsys.readouterr()

    assert rc == 0
    assert '"normalized_target": "https://example.com"' in captured.out
    assert '"detected_http_version": "HTTP/1.1"' in captured.out


def test_main_single_scanner_omits_probe_and_execution_metadata_from_exports(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    probe = {
        "input_target": "example.com",
        "normalized_target": "https://example.com",
        "selected_scheme": "https",
        "detected_http_version": "HTTP/2",
        "supports_http2": True,
        "supports_http1_1": False,
        "http2_only": True,
        "transport_detected": "http2_only",
        "reason": "probe ok",
    }

    class FakeScanner:
        def get_version(self):
            return "test-version"

        def get_default_options(self):
            return {}

        def validate_options(self, options):
            return options

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {"zap": FakeScanner()}

        def set_http_mode(self, http_mode):
            self.http_mode = http_mode

        def probe_target(self, target):
            return probe

        @staticmethod
        def _count_by_severity(findings):
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        def run_scanner(self, name, target, options=None, normalize=True, save_raw=True):
            return {
                "scanner": name,
                "target": "http://127.0.0.1:3000/",
                "timestamp": "2026-03-31T00:00:00Z",
                "findings": [],
                "target_probe": probe,
                "scanner_execution": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "proxied",
                    "adapter_mode": "bridge",
                    "execution_target": "http://127.0.0.1:3000/",
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
        ["main.py", "--target", "example.com", "--scanner", "zap", "--json", "--no-dedupe", "--no-score"],
    )

    rc = main.main()
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert rc == 0
    assert payload["target"] == "example.com"
    assert "target_probe" not in payload
    assert "scanner_execution" not in payload
    assert "transport_detected" not in payload


def test_main_defaults_zap_proxy_original_target_to_target(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["zap"],
                "all_findings": [],
                "findings_by_scanner": {"zap": []},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {"zap": 0}},
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
            "--target", "https://example.com",
            "--scanner", "all",
            "--zap-use-proxy",
            "--zap-proxy-url", "http://127.0.0.1:8081",
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["use_proxy"] is True
    assert captured["options"]["zap"]["proxy_url"] == "http://127.0.0.1:8081"
    assert captured["options"]["zap"]["original_target"] == "https://example.com"


def test_main_requires_zap_proxy_url_when_proxy_mode_enabled(monkeypatch):
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "https://example.com", "--scanner", "zap", "--zap-use-proxy"],
    )

    try:
        main.main()
        assert False, "Expected SystemExit"
    except SystemExit as exc:
        assert exc.code == 2


def test_main_omits_new_wapiti_and_nikto_tuning_options_when_flags_are_absent(monkeypatch, tmp_path, capsys):
    captured = {}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            captured["options"] = options or {}
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["all"],
                "all_findings": [],
                "findings_by_scanner": {},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {}},
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
            "--json",
            "--no-dedupe",
            "--no-score",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert "wapiti" not in captured["options"]
    assert "nikto" not in captured["options"]


def test_main_returns_clean_code_on_keyboard_interrupt(monkeypatch, capsys):
    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            raise KeyboardInterrupt

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "example.com", "--scanner", "all", "--no-save"],
    )

    rc = main.main()
    captured = capsys.readouterr()

    assert rc == 130
    assert "Scan cancelled by user." in captured.err


def test_main_shuts_down_background_services_after_success(monkeypatch, tmp_path, capsys):
    state = {"shutdown_calls": 0}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "scanners_run": ["all"],
                "all_findings": [],
                "findings_by_scanner": {},
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}, "by_scanner": {}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results))
            return path

        def shutdown_background_services(self):
            state["shutdown_calls"] += 1

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "example.com", "--scanner", "all", "--json", "--no-dedupe", "--no-score", "--no-save"],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert state["shutdown_calls"] == 1


def test_main_shuts_down_background_services_after_keyboard_interrupt(monkeypatch, capsys):
    state = {"shutdown_calls": 0}

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            raise KeyboardInterrupt

        def shutdown_background_services(self):
            state["shutdown_calls"] += 1

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "--target", "example.com", "--scanner", "all", "--no-save"],
    )

    rc = main.main()
    captured = capsys.readouterr()

    assert rc == 130
    assert "Scan cancelled by user." in captured.err
    assert state["shutdown_calls"] == 1


def test_main_single_scanner_error_does_not_print_success_like_no_findings(monkeypatch, tmp_path, capsys):
    class FakeScanner:
        def get_version(self):
            return "test-version"

        def get_default_options(self):
            return {}

        def validate_options(self, options):
            return options

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {"zap": FakeScanner()}

        @staticmethod
        def _count_by_severity(findings):
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        def run_scanner(self, name, target, options=None, normalize=True, save_raw=True):
            return {
                "scanner": name,
                "target": target,
                "timestamp": "2026-03-31T00:00:00Z",
                "error": "ZAP did not create the expected report file: /tmp/zap.json",
                "findings": [],
                "scanner_execution": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "direct",
                    "adapter_mode": "direct",
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
        ["main.py", "--target", "https://example.com", "--scanner", "zap", "--no-dedupe", "--no-score"],
    )

    rc = main.main()
    captured = capsys.readouterr()

    assert rc == 0
    assert "No findings were produced because the scan failed, timed out, or was degraded." in captured.out
    assert "No vulnerabilities found!" not in captured.out
    assert "Check the saved raw scanner output for full stdout/stderr details." in captured.out


def test_normalize_web_target_prepends_https_to_bare_targets():
    assert normalize_web_target("example.com") == "https://example.com"
    assert normalize_web_target("http://example.com") == "http://example.com"


def test_wapiti_scan_normalizes_bare_targets_to_https(monkeypatch, tmp_path):
    output_path = tmp_path / "wapiti.json"
    output_path.write_text(json.dumps({"vulnerabilities": {}}))

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    monkeypatch.setattr("scanners.wapiti_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr(
        "scanners.wapiti_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    scanner = WapitiScanner()
    result = scanner.scan("example.com")

    assert result["target"] == "https://example.com"
    assert " -u https://example.com " in f" {result['command']} "


def test_wapiti_scan_exposes_xml_report_as_defectdojo_raw_artifact(monkeypatch, tmp_path):
    raw_payload = {
        "classifications": {
            "SQL Injection": {
                "desc": "Possible SQL injection",
                "sol": "Use parameterized queries",
                "ref": {"OWASP": "https://owasp.org/"},
                "wstg": ["WSTG-INPV-05"],
            }
        },
        "vulnerabilities": {
            "SQL Injection": [
                {
                    "method": "GET",
                    "path": "/login",
                    "info": "SQL injection in id",
                    "level": 3,
                    "parameter": "id",
                    "referer": "",
                    "module": "sql",
                    "http_request": "GET /login?id=1 HTTP/1.1",
                    "curl_command": "curl https://example.com/login?id=1",
                    "wstg": ["WSTG-INPV-05"],
                }
            ]
        },
        "anomalies": {},
        "additionals": {},
        "infos": {
            "target": "https://example.com",
            "version": "Wapiti 3.2.4",
            "scope": "folder",
            "date": "Tue, 28 Apr 2026 00:00:00 +0000",
            "crawled_pages_nbr": 1,
        },
    }

    def fake_run(cmd, capture_output=True, text=True, timeout=1800):
        output_path = Path(cmd[cmd.index("-o") + 1])
        output_path.write_text(json.dumps(raw_payload), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.wapiti_scanner.subprocess.run", fake_run)

    scanner = WapitiScanner()
    result = scanner.scan("https://example.com", {"output_dir": tmp_path})

    artifact = result["defectdojo_raw_artifact"]
    assert artifact["artifact_format"] == "xml"
    assert artifact["native"] is True
    assert artifact["safe_importable"] is True
    assert artifact["role"] == "defectdojo-native-parser-input"
    assert Path(artifact["path"]).name.startswith("wapiti_")
    assert Path(artifact["path"]).suffix == ".xml"
    assert "<report type=\"security\"" in Path(artifact["path"]).read_text(encoding="utf-8")
    assert result["raw_output"]["vulnerabilities"]["SQL Injection"][0]["path"] == "/login"
    assert result["findings"][0]["_category"] == "SQL Injection"


def test_nikto_scan_normalizes_bare_targets_to_https(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr(
        "scanners.nikto_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )

    scanner = NiktoScanner()
    result = scanner.scan("example.com")

    assert result["target"] == "https://example.com"
    assert " -h https://example.com " in f" {result['command']} "


def test_nikto_scan_keeps_port_in_url_and_omits_legacy_port_flag(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.nikto_scanner.subprocess.run", fake_run)

    scanner = NiktoScanner()
    result = scanner.scan("http://cyberhayq.am:80", options={"port": 80})

    assert result["target"] == "http://cyberhayq.am:80"
    assert captured["cmd"][:2] == ["nikto", "-h"]
    assert captured["cmd"][2] == "http://cyberhayq.am:80"
    assert "-p" not in captured["cmd"]


def test_nikto_scan_preserves_local_adapter_http_scheme_even_with_ssl_option(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.nikto_scanner.subprocess.run", fake_run)

    scanner = NiktoScanner()
    result = scanner.scan(
        "http://127.0.0.1:39013/",
        options={
            "ssl": True,
            "adapter_mode": "bridge",
            "origin_target": "https://example.com",
        },
    )

    assert result["target"] == "http://127.0.0.1:39013/"
    assert captured["cmd"][2] == "http://127.0.0.1:39013/"
    assert "-vhost" in captured["cmd"]
    assert "example.com" in captured["cmd"]


def test_nikto_scan_preserves_user_supplied_vhost_through_bridge(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.nikto_scanner.subprocess.run", fake_run)

    scanner = NiktoScanner()
    result = scanner.scan(
        "http://127.0.0.1:39013/",
        options={
            "adapter_mode": "bridge",
            "origin_target": "https://example.com",
            "args": ["-vhost", "custom.example"],
        },
    )

    assert result["target"] == "http://127.0.0.1:39013/"
    assert captured["cmd"][:2] == ["nikto", "-h"]
    assert captured["cmd"][2] == "http://127.0.0.1:39013/"
    assert captured["cmd"].count("-vhost") == 1
    vhost_index = captured["cmd"].index("-vhost")
    assert captured["cmd"][vhost_index + 1] == "custom.example"
    assert "example.com" not in captured["cmd"][vhost_index + 2:]


def test_nikto_scan_auto_injected_bridge_vhost_keeps_non_default_origin_port(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.nikto_scanner.subprocess.run", fake_run)

    scanner = NiktoScanner()
    result = scanner.scan(
        "http://127.0.0.1:39013/",
        options={
            "adapter_mode": "bridge",
            "origin_target": "https://example.com:8443",
        },
    )

    assert result["target"] == "http://127.0.0.1:39013/"
    assert captured["cmd"][:2] == ["nikto", "-h"]
    assert captured["cmd"][2] == "http://127.0.0.1:39013/"
    assert "-vhost" in captured["cmd"]
    vhost_index = captured["cmd"].index("-vhost")
    assert captured["cmd"][vhost_index + 1] == "example.com:8443"


def test_run_all_http2_only_nikto_keeps_local_bridge_target_http(monkeypatch, tmp_path):
    output_path = tmp_path / "nikto.json"
    output_path.write_text(json.dumps({}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    class FakeDiscoveryNmapScanner(BaseScanner):
        def __init__(self):
            super().__init__("nmap")
            self.scanner_type = "network"

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": "2026-04-15T00:00:00Z",
                "findings": [],
                "discovered_services": [
                    {
                        "host": "example.com",
                        "port": 443,
                        "port_text": "443",
                        "protocol": "tcp",
                        "state": "open",
                        "service": "http",
                        "service_version": "nginx",
                        "is_web": True,
                        "web_scheme": "https",
                    }
                ],
            }

        def normalize(self, raw_results):
            return []

    def fake_run(cmd, *args, **kwargs):
        captured["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nikto_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.nikto_scanner.subprocess.run", fake_run)

    nikto = NiktoScanner()
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("nmap", FakeDiscoveryNmapScanner())
    orchestrator.register_scanner("nikto", nikto)
    orchestrator.set_scan_mode("automatic")

    monkeypatch.setattr(nikto, "is_available", lambda: True)
    monkeypatch.setattr(nikto, "get_version", lambda: "Nikto test")
    monkeypatch.setattr(
        "orchestrator.probe_http_transport",
        lambda target, timeout=8: {
            "input_target": target,
            "normalized_target": "https://example.com:443",
            "selected_scheme": "https",
            "supports_http2": True,
            "supports_http1_1": False,
            "reachable": True,
            "http2_only": True,
            "transport_detected": "http2_only",
            "detected_http_version": "HTTP/2",
            "probe_method": "python-httpx",
            "reason": "probe=http2_only",
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:39013",
    )

    results = orchestrator.run_all("https://example.com", save_raw=False)

    assert captured["cmd"][2] == "http://127.0.0.1:39013/"
    assert "-vhost" in captured["cmd"]
    assert "example.com" in captured["cmd"]
    assert results["scanner_execution"]["nikto"]["adapter_mode"] == "bridge"
    assert results["scanner_execution"]["nikto"]["effective_target"] == "http://127.0.0.1:39013/"


def test_wapiti_internal_server_error_without_context_is_not_normalized():
    scanner = WapitiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-08T00:00:00Z",
            "target": "https://example.com",
            "origin_target": "https://example.com",
            "raw_output": {"classifications": {}},
            "findings": [
                {
                    "_category": "Internal Server Error",
                    "_type": "anomalies",
                    "level": 3,
                    "info": "Internal Server Error",
                }
            ],
        }
    )

    assert normalized == []


def test_wapiti_internal_server_error_keeps_request_evidence():
    scanner = WapitiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-08T00:00:00Z",
            "target": "https://example.com",
            "origin_target": "https://example.com",
            "raw_output": {"classifications": {}},
            "findings": [
                {
                    "_category": "Internal Server Error",
                    "_type": "anomalies",
                    "level": 3,
                    "info": "The server responded with a 500 HTTP error code while attempting to inject a payload in the parameter id",
                    "path": "/db/get",
                    "method": "GET",
                    "parameter": "id",
                    "module": "exec",
                    "wstg": ["WSTG-ERRH-01"],
                    "http_request": "GET /db/get?id=%3B HTTP/1.1",
                    "curl_command": "curl 'https://example.com/db/get?id=%3B'",
                }
            ],
        }
    )

    assert len(normalized) == 1
    finding = normalized[0]
    assert finding["vulnerability_name"] == "Internal Server Error"
    assert finding["severity"] == "high"
    assert finding["asset_id"] == "https://example.com/db/get"
    assert "500 HTTP error" in finding["description"]
    assert finding["meta"]["parameter"] == "id"
    assert finding["meta"]["module"] == "exec"
    assert finding["meta"]["http_request"].startswith("GET /db/get")
    assert finding["meta"]["wstg"] == ["WSTG-ERRH-01"]


def test_wapiti_generic_internal_server_error_is_downgraded_to_low_confidence_candidate():
    scanner = WapitiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-08T00:00:00Z",
            "target": "https://example.com",
            "origin_target": "https://example.com",
            "raw_output": {"classifications": {}},
            "findings": [
                {
                    "_category": "Internal Server Error",
                    "_type": "anomalies",
                    "level": 3,
                    "info": "The server returned a 500 error while processing the request.",
                    "path": "/reports/view",
                    "method": "GET",
                    "parameter": "id",
                    "http_request": "GET /reports/view?id=1 HTTP/1.1",
                }
            ],
        }
    )

    assert len(normalized) == 1
    finding = normalized[0]
    assert finding["vulnerability_name"] == "Internal Server Error"
    assert finding["severity"] == "low"
    assert finding["asset_id"] == "https://example.com/reports/view"
    assert finding["meta"]["parameter"] == "id"
    assert finding["meta"]["internal_server_error_classification"] == "generic_input_triggered_server_error"
    assert finding["meta"]["reproducible"] is True
    assert finding["meta"]["response_error_pattern"] == "generic_500"
    assert finding["meta"]["confidence"] == "low"


def test_nikto_soft_failure_markers_are_reported_as_degraded_when_retry_cannot_start(monkeypatch, tmp_path):
    scanner = NiktoScanner()
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nikto", scanner)

    monkeypatch.setattr(scanner, "is_available", lambda: True)
    monkeypatch.setattr(
        orchestrator,
        "probe_target",
        lambda target: {
            "input_target": target,
            "normalized_target": "https://example.com",
            "selected_scheme": "https",
            "supports_http2": False,
            "supports_http1_1": True,
            "reachable": True,
            "http2_only": False,
            "transport_detected": "http1_only",
            "detected_http_version": "HTTP/1.1",
            "probe_method": "python-httpx",
            "reason": "probe=http1_only",
        },
    )
    monkeypatch.setattr(
        scanner,
        "scan",
        lambda target, options=None: {
            "scanner": "nikto",
            "target": target,
            "timestamp": "2026-04-05T00:00:00Z",
            "stdout": (
                "Error limit (20) reached\n"
                "Scan terminated: giving up\n"
                "0 items reported on the remote host\n"
                "Consider using the compatibility adapter\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        },
    )

    result = orchestrator.run_scanner("nikto", "https://example.com", save_raw=False)

    assert "error" in result
    assert "Nikto reported a degraded execution" in result["error"]
    assert result["scanner_execution"]["degraded_execution"] is True
    assert "compatibility adapter" not in result["scanner_execution"]["scanner_error"]
    assert result["findings"] == []


def test_nikto_degraded_direct_http1_result_is_kept_without_retry(monkeypatch, tmp_path):
    scanner = NiktoScanner()
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("nikto", scanner)
    calls = []

    monkeypatch.setattr(scanner, "is_available", lambda: True)
    monkeypatch.setattr(
        orchestrator,
        "probe_target",
        lambda target: {
            "input_target": target,
            "normalized_target": "https://example.com",
            "selected_scheme": "https",
            "supports_http2": False,
            "supports_http1_1": True,
            "reachable": True,
            "http2_only": False,
            "transport_detected": "http1_only",
            "detected_http_version": "HTTP/1.1",
            "probe_method": "python-httpx",
            "reason": "probe=http1_only",
        },
    )
    def fake_scan(target, options=None):
        opts = dict(options or {})
        calls.append({
            "target": target,
            "options": opts,
        })
        return {
            "scanner": "nikto",
            "target": target,
            "timestamp": "2026-04-10T00:00:00Z",
            "stdout": (
                "Error limit (20) reached\n"
                "Scan terminated: giving up\n"
                "0 items reported on the remote host\n"
                "Consider using the compatibility adapter\n"
            ),
            "stderr": "",
            "exit_code": 0,
            "findings": [{"msg": "Partial Nikto finding", "uri": "/admin"}],
        }

    monkeypatch.setattr(scanner, "scan", fake_scan)

    result = orchestrator.run_scanner("nikto", "https://example.com", save_raw=False)

    assert len(calls) == 1
    assert "adapter_mode" not in calls[0]["options"]
    assert result["scanner_execution"]["adapter_mode"] == "direct"
    assert result["warning"].startswith("Nikto reported a degraded execution")
    assert result["findings"][0]["asset_id"] == "https://example.com/admin"
    assert result["findings"][0]["meta"]["adapter_mode"] == "direct"


def test_nikto_removed_adapter_hint_alone_is_not_degradation():
    scanner = NiktoScanner()

    assessment = scanner.assess_execution(
        {
            "stdout": "0 items reported on the remote host\nConsider using the compatibility adapter\n",
            "stderr": "",
            "findings": [],
        }
    )

    assert assessment == {}


def test_nikto_bridge_degradation_reports_local_adapter_identity_limitation():
    scanner = NiktoScanner()

    assessment = scanner.assess_execution(
        {
            "target": "http://127.0.0.1:39013/",
            "origin_target": "https://example.com",
            "adapter_mode": "bridge",
            "raw_output": [
                {
                    "host": "127.0.0.1",
                    "ip": "127.0.0.1",
                }
            ],
            "stdout": (
                "+ Target Hostname: 127.0.0.1\n"
                "+ Server: uvicorn\n"
                "Error limit (20) reached\n"
                "Scan terminated: giving up\n"
                "0 items reported on the remote host\n"
            ),
            "stderr": "+ ERROR: *** Error limit (20) reached for host, giving up. Last error: . ***\n",
            "findings": [],
        }
    )

    assert assessment["degraded_execution"] is True
    assert "local compatibility adapter" in assessment["scanner_error"]
    assert "reported host 127.0.0.1" in assessment["scanner_error"]
    assert "reported ip 127.0.0.1" in assessment["scanner_error"]
    assert "server banner 'uvicorn'" in assessment["scanner_error"]
    assert "error limit (" in assessment["degraded_markers"]
    assert "scan terminated:" in assessment["degraded_markers"]
    assert assessment["adapter_identity_signals"] == [
        "reported host 127.0.0.1",
        "reported ip 127.0.0.1",
        "server banner 'uvicorn'",
    ]


def test_nikto_bridge_degradation_flags_loopback_ip_even_when_hostname_looks_clean():
    scanner = NiktoScanner()

    assessment = scanner.assess_execution(
        {
            "target": "http://127.0.0.1:39013/",
            "origin_target": "https://example.com",
            "adapter_mode": "bridge",
            "raw_output": [
                {
                    "host": "example.com",
                    "ip": "127.0.0.1",
                }
            ],
            "stdout": (
                "+ Target Hostname: example.com\n"
                "Error limit (20) reached\n"
                "Scan terminated: giving up\n"
                "0 items reported on the remote host\n"
            ),
            "stderr": "",
            "findings": [],
        }
    )

    assert assessment["degraded_execution"] is True
    assert "local compatibility adapter" in assessment["scanner_error"]
    assert "reported ip 127.0.0.1" in assessment["scanner_error"]
    assert assessment["adapter_identity_signals"] == [
        "reported ip 127.0.0.1",
    ]


def test_nikto_bridge_transport_target_alone_is_not_identity_leak():
    scanner = NiktoScanner()

    assessment = scanner.assess_execution(
        {
            "target": "http://127.0.0.1:39013/",
            "origin_target": "https://example.com",
            "adapter_mode": "bridge",
            "raw_output": [
                {
                    "host": "example.com",
                    "ip": "203.0.113.10",
                }
            ],
            "stdout": (
                "+ Target Hostname: example.com\n"
                "Error limit (20) reached\n"
                "Scan terminated: giving up\n"
                "0 items reported on the remote host\n"
            ),
            "stderr": "",
            "findings": [],
        }
    )

    assert assessment["degraded_execution"] is True
    assert "local compatibility adapter" not in assessment["scanner_error"]
    assert "adapter_identity_signals" not in assessment


def test_nuclei_scan_forces_http2_when_requested(monkeypatch):
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, timeout=600):
        captured["cmd"] = cmd
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nuclei_scanner.subprocess.run", fake_run)

    scanner = NucleiScanner()
    result = scanner.scan("example.com", options={"force_http2": True})

    assert result["target"] == "https://example.com"
    assert "-fh2" in captured["cmd"]
    assert "-duc" in captured["cmd"]


def test_nuclei_scan_keeps_partial_output_on_timeout(monkeypatch):
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["nuclei", "-u", "https://example.com"],
            timeout=600,
            output='partial stdout',
            stderr='partial stderr',
        )

    monkeypatch.setattr("scanners.nuclei_scanner.subprocess.run", fake_run)

    scanner = NucleiScanner()
    result = scanner.scan("https://example.com", options={"force_http2": True})

    assert result["error"] == "Scan timeout"
    assert result["raw_output"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    assert " -fh2 " in f" {result['command']} "


def test_wapiti_timeout_recovers_partial_results(monkeypatch, tmp_path):
    output_path = tmp_path / "wapiti-timeout.json"

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(*args, **kwargs):
        output_path.write_text(json.dumps({
            "vulnerabilities": {
                "SQL Injection": [{
                    "name": "SQL Injection",
                    "path": "/login",
                    "method": "GET",
                    "level": 3,
                }]
            },
            "classifications": {
                "SQL Injection": {
                    "desc": "Possible SQL injection",
                    "sol": "Use parameterized queries",
                }
            },
        }))
        raise subprocess.TimeoutExpired(
            cmd=["wapiti", "-u", "http://127.0.0.1:3000/"],
            timeout=3600,
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr("scanners.wapiti_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.wapiti_scanner.subprocess.run", fake_run)

    scanner = WapitiScanner()
    result = scanner.scan(
        "http://127.0.0.1:3000/",
        {"origin_target": "https://example.com"},
    )

    assert result["error"] == "Scan timeout"
    assert result["raw_output"]["vulnerabilities"]["SQL Injection"]
    assert result["findings"]
    assert result["stdout"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    assert result["exit_code"] is None
    assert result["partial_results"] is True


def test_wapiti_bridged_scan_uses_extended_default_timeout(monkeypatch, tmp_path):
    output_path = tmp_path / "wapiti.json"
    output_path.write_text(json.dumps({"vulnerabilities": {}}))
    captured = {}

    class DummyTempFile:
        name = str(output_path)

        @staticmethod
        def close():
            return None

    def fake_run(cmd, capture_output=True, text=True, timeout=1800):
        captured["timeout"] = timeout
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("scanners.wapiti_scanner.tempfile.NamedTemporaryFile", lambda **kwargs: DummyTempFile())
    monkeypatch.setattr("scanners.wapiti_scanner.subprocess.run", fake_run)

    scanner = WapitiScanner()
    scanner.scan("http://127.0.0.1:3000/", {"origin_target": "https://example.com"})

    assert captured["timeout"] == 3600


def test_orchestrator_preserves_findings_when_scanner_returns_partial_error(tmp_path):
    class PartialScanner(BaseScanner):
        def __init__(self):
            super().__init__("partial")
            self.scanner_type = "network"

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": "2026-04-04T00:00:00Z",
                "error": "Scan timeout",
                "findings": [{"id": "raw"}],
                "partial_results": True,
            }

        def normalize(self, raw_results):
            return [{
                "vulnerability_name": "Recovered finding",
                "severity": "medium",
                "asset_id": raw_results["target"],
                "description": "Recovered from partial scan output",
                "remediation": "Review manually",
                "meta": {"scanner": self.name},
            }]

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("partial", PartialScanner())

    result = orchestrator.run_scanner("partial", "192.168.1.10", save_raw=False)

    assert "error" not in result
    assert result["warning"] == "Scan timeout"
    assert result["partial_results"] is True
    assert len(result["findings"]) == 1
    assert result["scanner_execution"]["adapter_mode"] == "direct"


def test_orchestrator_keeps_partial_warning_even_without_recovered_findings(tmp_path):
    class PartialScanner(BaseScanner):
        def __init__(self):
            super().__init__("partial-empty")
            self.scanner_type = "network"

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": "2026-04-04T00:00:00Z",
                "error": "Timed out but recovered report shell",
                "findings": [],
                "partial_results": True,
                "raw_output": {"site": []},
            }

        def normalize(self, raw_results):
            return []

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("partial-empty", PartialScanner())

    result = orchestrator.run_scanner("partial-empty", "192.168.1.11", save_raw=False)

    assert "error" not in result
    assert result["warning"] == "Timed out but recovered report shell"
    assert result["partial_results"] is True
    assert result["findings"] == []
    assert result["scanner_execution"]["adapter_mode"] == "direct"


def test_zap_scan_requires_probed_target_url():
    scanner = ZapScanner()
    result = scanner.scan("example.com")

    assert "requires a normalized http:// or https:// target" in result["error"]


def test_wapiti_normalize_uses_origin_target_when_scanning_through_bridge():
    scanner = WapitiScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000",
            "origin_target": "https://example.com",
            "raw_output": {"classifications": {}},
            "findings": [{"name": "SQL Injection", "path": "/login", "_category": "sql", "_type": "vulnerabilities"}],
        }
    )

    assert normalized[0]["asset_id"] == "https://example.com/login"


def test_wapiti_normalize_remaps_absolute_bridge_url_to_origin_target():
    scanner = WapitiScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000",
            "origin_target": "https://example.com",
            "raw_output": {"classifications": {}},
            "findings": [{
                "name": "SQL Injection",
                "url": "http://127.0.0.1:3000/login?next=1",
                "_category": "sql",
                "_type": "vulnerabilities",
            }],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/login?next=1"
    assert finding["meta"]["host"] == "example.com"


def test_nikto_normalize_uses_origin_target_when_scanning_through_bridge():
    scanner = NiktoScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000",
            "origin_target": "https://example.com",
            "findings": [{"msg": "Test finding", "uri": "/admin"}],
        }
    )

    assert normalized[0]["asset_id"] == "https://example.com/admin"


def test_nikto_normalize_remaps_absolute_bridge_url_and_uses_asset_metadata():
    scanner = NiktoScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000",
            "origin_target": "https://example.com",
            "findings": [{"msg": "Test finding", "uri": "http://127.0.0.1:3000/admin"}],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/admin"
    assert finding["meta"]["host"] == "example.com"
    assert finding["meta"]["scheme"] == "https"
    assert finding["meta"]["path"] == "/admin"
    assert finding["meta"].get("port") is None


def test_nikto_normalize_preserves_origin_target_identity_through_bridge():
    scanner = NiktoScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:39012",
            "origin_target": "https://example.com",
            "original_target": "https://example.com",
            "adapter_mode": "bridge",
            "findings": [{"msg": "Test finding", "uri": "http://127.0.0.1:39012/admin"}],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/admin"
    assert finding["meta"]["adapter_mode"] == "bridge"
    assert finding["meta"]["origin_target"] == "https://example.com"
    assert finding["meta"]["effective_target"] == "http://127.0.0.1:39012"


def test_nuclei_normalize_uses_origin_target_when_scanning_through_bridge():
    scanner = NucleiScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000",
            "origin_target": "https://example.com",
            "findings": [{
                "template-id": "demo-template",
                "host": "http://127.0.0.1:3000",
                "matched-at": "http://127.0.0.1:3000/admin?next=1",
                "info": {"name": "Demo finding", "severity": "medium"},
            }],
        }
    )

    assert normalized[0]["asset_id"] == "https://example.com/admin?next=1"
    assert normalized[0]["meta"]["host"] == "example.com"
    assert normalized[0]["meta"]["origin_target"] == "https://example.com"


def test_adapter_local_connectivity_noise_is_warning_not_finding(monkeypatch, tmp_path):
    class AdapterNoiseScanner(BaseScanner):
        def __init__(self):
            super().__init__("adapter-noise")
            self.scanner_type = "web"
            self.supports_http2_bridge = True

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "origin_target": (options or {}).get("origin_target"),
                "original_target": (options or {}).get("original_target"),
                "adapter_mode": (options or {}).get("adapter_mode"),
                "timestamp": "2026-04-06T00:00:00Z",
                "findings": [{"msg": "Unable to connect to 127.0.0.1:53647."}],
                "exit_code": 0,
            }

        def normalize(self, raw_results):
            message = raw_results["findings"][0]["msg"]
            return [{
                "vulnerability_name": message,
                "severity": "info",
                "asset_id": raw_results["original_target"],
                "description": message,
                "remediation": "Review scanner execution logs.",
                "meta": {
                    "scanner": self.name,
                    "host": "example.com",
                    "scheme": "https",
                    "path": "",
                    "port": None,
                    "query_keys": [],
                    "effective_target": raw_results["target"],
                    "origin_target": raw_results["origin_target"],
                    "original_target": raw_results["original_target"],
                    "adapter_mode": raw_results["adapter_mode"],
                },
            }]

    scanner = AdapterNoiseScanner()
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("adapter-noise", scanner)

    monkeypatch.setattr(
        "orchestrator.probe_http_transport",
        lambda target, timeout=8: {
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
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:53647",
    )

    result = orchestrator.run_scanner("adapter-noise", "https://example.com", save_raw=False)

    assert result["findings"] == []
    assert result["raw_findings_count"] == 1
    assert result["normalized_findings_count"] == 0
    assert "Suppressed 1 adapter-local connectivity artifact" in result["warning"]
    assert "Unable to connect to 127.0.0.1:53647" in result["warning"]
    assert result["scanner_execution"]["degraded_execution"] is True
    assert "Unable to connect to 127.0.0.1:53647" in result["scanner_execution"]["scanner_error"]
    assert result["scanner_execution"]["original_target"] == "https://example.com"
    assert result["scanner_execution"]["effective_target"] == "http://127.0.0.1:53647/"


def test_adapter_banner_identity_noise_is_warning_not_finding(monkeypatch, tmp_path):
    class AdapterBannerScanner(BaseScanner):
        def __init__(self):
            super().__init__("adapter-banner")
            self.scanner_type = "web"
            self.supports_http2_bridge = True

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "origin_target": (options or {}).get("origin_target"),
                "original_target": (options or {}).get("original_target"),
                "adapter_mode": (options or {}).get("adapter_mode"),
                "timestamp": "2026-04-08T00:00:00Z",
                "findings": [
                    {
                        "msg": "Server banner changed from 'Apache/2.4.49' to 'uvicorn'.",
                    }
                ],
                "exit_code": 0,
            }

        def normalize(self, raw_results):
            message = raw_results["findings"][0]["msg"]
            return [{
                "vulnerability_name": message,
                "severity": "low",
                "asset_id": raw_results["original_target"],
                "description": message,
                "remediation": "Review the reported server banner.",
                "meta": {
                    "scanner": self.name,
                    "host": "example.com",
                    "scheme": "https",
                    "path": "",
                    "port": None,
                    "query_keys": [],
                    "effective_target": raw_results["target"],
                    "origin_target": raw_results["origin_target"],
                    "original_target": raw_results["original_target"],
                    "adapter_mode": raw_results["adapter_mode"],
                },
            }]

    scanner = AdapterBannerScanner()
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path, http2_adapter_mode="bridge")
    orchestrator.register_scanner("adapter-banner", scanner)

    monkeypatch.setattr(
        "orchestrator.probe_http_transport",
        lambda target, timeout=8: {
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
        },
    )
    monkeypatch.setattr(
        orchestrator,
        "_start_auto_http2_bridge",
        lambda origin_target: "http://127.0.0.1:53647",
    )

    result = orchestrator.run_scanner("adapter-banner", "https://example.com", save_raw=False)

    assert result["findings"] == []
    assert result["raw_findings_count"] == 1
    assert result["normalized_findings_count"] == 0
    assert "Suppressed 1 adapter-local transport artifact" in result["warning"]
    assert "uvicorn" in result["warning"]
    assert result["scanner_execution"]["degraded_execution"] is True


def test_zap_builds_baseline_automation_plan():
    scanner = ZapScanner()
    plan = scanner._build_automation_plan(
        target="https://example.com:443/app/login?next=1",
        report_filename="zap_report.json",
        active_scan=False,
        timeout=90,
    )

    assert plan["env"]["contexts"][0]["urls"] == ["https://example.com/app/login"]
    assert plan["env"]["contexts"][0]["includePaths"] == [r"^https://example\.com/app/login(?:/.*)?(?:\?.*)?$"]
    assert plan["env"]["parameters"]["failOnError"] is False
    assert plan["env"]["parameters"]["continueOnFailure"] is True
    spider_job = next(job for job in plan["jobs"] if job["type"] == "spider")
    spider_ajax_job = next(job for job in plan["jobs"] if job["type"] == "spiderAjax")
    assert spider_job["parameters"]["url"] == "https://example.com/app/login?next=1"
    assert spider_ajax_job["parameters"]["url"] == "https://example.com/app/login?next=1"
    assert scanner._context_url("http://example.com:80/app?view=1") == "http://example.com/app"
    assert scanner._scope_pattern("http://example.com:80/app?view=1") == (
        r"^http://example\.com/app(?:/.*)?(?:\?.*)?$"
    )
    assert [job["type"] for job in plan["jobs"]] == [
        "passiveScan-config",
        "spider",
        "spiderAjax",
        "passiveScan-wait",
        "report",
    ]
    assert plan["jobs"][-1]["parameters"]["template"] == "traditional-json"


def test_zap_local_binary_validation_requires_autorun_support(monkeypatch):
    scanner = ZapScanner()
    calls = {"count": 0}

    monkeypatch.setattr("scanners.zap_scanner.shutil.which", lambda name: "/usr/local/bin/zap.sh" if name == "zap.sh" else None)

    def fake_run(cmd, capture_output=True, text=True, timeout=10):
        calls["count"] += 1
        return SimpleNamespace(
            returncode=0,
            stdout="Usage: zap.sh -cmd -autorun plan.yaml",
            stderr="",
        )

    monkeypatch.setattr("scanners.zap_scanner.subprocess.run", fake_run)

    assert scanner._local_zap_binary() == "/usr/local/bin/zap.sh"
    assert scanner._local_zap_binary() == "/usr/local/bin/zap.sh"
    assert calls["count"] == 1


def test_zap_local_binary_validation_rejects_non_af_binary(monkeypatch):
    scanner = ZapScanner()

    monkeypatch.setattr("scanners.zap_scanner.shutil.which", lambda name: "/usr/local/bin/zap.sh" if name == "zap.sh" else None)
    monkeypatch.setattr(
        "scanners.zap_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="Usage: zap.sh -cmd -help",
            stderr="",
        ),
    )

    assert scanner._local_zap_binary() is None


def test_zap_scan_uses_default_template_when_target_is_already_normalized(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}
    default_template_path = scanner._default_automation_plan_template_path()

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(scanner, "_local_zap_binary", lambda: "/usr/local/bin/zap.sh")
    monkeypatch.setattr(
        scanner,
        "_scan_local",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("local ZAP binary should not be preferred when Docker is available")),
    )
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: captured.update({
            "target": target,
            "raw_dir": raw_dir,
            "plan_filename": plan_filename,
            "extra_args": list(extra_args),
        }) or {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan("https://example.com", {"output_dir": tmp_path})
    plan_path = Path(result["automation_plan_path"])
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))

    assert result["target"] == "https://example.com"
    assert captured["plan_filename"] == plan_path.name
    assert plan_path.parent == tmp_path
    assert "zap.sh -cmd -autorun" in result["command"]
    assert "zap-baseline.py" not in result["command"]
    assert "zap-full-scan.py" not in result["command"]
    assert result["automation_plan_source"] == "default template"
    assert result["automation_plan_template_path"] == str(default_template_path.resolve())
    assert [job["type"] for job in plan["jobs"]] == [
        "passiveScan-config",
        "spider",
        "spiderAjax",
        "passiveScan-wait",
        "report",
        "report",
    ]
    report_jobs = [job for job in plan["jobs"] if job["type"] == "report"]
    assert [job["parameters"]["template"] for job in report_jobs] == [
        "traditional-json",
        "traditional-xml",
    ]


def test_zap_expected_report_filename_matches_generated_plan(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: captured.update({
            "report_path": report_path,
        }) or {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {"site": []},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "http://127.0.0.1:3000/app",
        {
            "output_dir": tmp_path,
            "origin_target": "https://example.com",
        },
    )
    plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))
    report_jobs = [job for job in plan["jobs"] if job["type"] == "report"]
    report_params = report_jobs[0]["parameters"]
    xml_report_params = report_jobs[1]["parameters"]

    assert report_params["reportFile"] == captured["report_path"].name
    assert report_params["reportFile"] == Path(result["raw_output_path"]).name
    assert report_params["reportDir"] == "/zap/wrk"
    assert report_params["template"] == "traditional-json"
    assert xml_report_params["reportFile"] == Path(result["expected_zap_xml_report_path"]).name
    assert xml_report_params["template"] == "traditional-xml"


def test_zap_scan_exposes_xml_report_as_defectdojo_raw_artifact(monkeypatch, tmp_path):
    scanner = ZapScanner()

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)

    def fake_scan_docker(target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args):
        report_path.write_text('{"site":[]}\n', encoding="utf-8")
        xml_path = report_path.with_suffix(".xml")
        xml_path.write_text("<OWASPZAPReport></OWASPZAPReport>\n", encoding="utf-8")
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {"site": []},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        }

    monkeypatch.setattr(scanner, "_scan_docker", fake_scan_docker)

    result = scanner.scan("https://example.com", {"output_dir": tmp_path})

    artifact = result["defectdojo_raw_artifact"]
    assert artifact["artifact_format"] == "xml"
    assert artifact["native"] is True
    assert artifact["role"] == "defectdojo-native-parser-input"
    assert Path(artifact["path"]).name.startswith("zap_")
    assert Path(artifact["path"]).suffix == ".xml"
    assert Path(artifact["path"]).read_text(encoding="utf-8").startswith("<OWASPZAPReport")


def test_zap_scan_active_mode_changes_automation_plan_content(monkeypatch, tmp_path):
    scanner = ZapScanner()

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan("https://example.com", {"output_dir": tmp_path, "active_scan": True})
    plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))

    assert result["target"] == "https://example.com"
    assert result["scan_mode"] == "active"
    assert "zap.sh -cmd -autorun" in result["command"]
    assert [job["type"] for job in plan["jobs"]] == [
        "passiveScan-config",
        "spider",
        "spiderAjax",
        "passiveScan-wait",
        "activeScan",
        "passiveScan-wait",
        "report",
        "report",
    ]
    report_jobs = [job for job in plan["jobs"] if job["type"] == "report"]
    assert [job["parameters"]["template"] for job in report_jobs] == [
        "traditional-json",
        "traditional-xml",
    ]


def test_zap_scan_resolves_user_template_and_overrides_runtime_fields(monkeypatch, tmp_path):
    scanner = ZapScanner()
    template_path = tmp_path / "zap-custom.yaml"
    template_path.write_text(
        yaml.safe_dump(
            {
                "env": {
                    "contexts": [
                        {
                            "name": "wrong-context",
                            "urls": ["https://wrong.example/"],
                            "includePaths": [r"^https://wrong\.example/.*$"],
                            "authentication": {
                                "method": "form",
                                "parameters": {
                                    "loginPageUrl": "https://wrong.example/login",
                                },
                            },
                            "sessionManagement": {"method": "cookie"},
                            "users": [
                                {
                                    "name": "demo-user",
                                    "credentials": {"username": "demo"},
                                }
                            ],
                            "excludePaths": [r"^https://wrong\.example/logout$"],
                        }
                    ]
                },
                "jobs": [
                    {
                        "type": "spider",
                        "parameters": {
                            "context": "wrong-context",
                            "url": "https://wrong.example/login",
                            "maxDuration": 999,
                        },
                    },
                    {
                        "type": "spiderAjax",
                        "parameters": {
                            "context": "wrong-context",
                            "url": "https://wrong.example/ajax",
                            "maxDuration": 999,
                            "browserId": "firefox-headless",
                        },
                    },
                    {
                        "type": "passiveScan-wait",
                        "parameters": {"maxDuration": 999},
                    },
                    {
                        "type": "activeScan",
                        "parameters": {
                            "context": "wrong-context",
                            "url": "https://wrong.example/login",
                            "maxRuleDurationInMins": 999,
                            "maxScanDurationInMins": 999,
                        },
                    },
                    {
                        "type": "report",
                        "parameters": {
                            "template": "html",
                            "reportDir": "/tmp/report-dir",
                            "reportFile": "wrong.json",
                            "reportTitle": "Wrong Title",
                            "reportDescription": "Wrong description",
                        },
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "https://example.com/app/login?next=1",
        {
            "output_dir": tmp_path,
            "timeout": 90,
            "af_plan_path": str(template_path),
        },
    )
    plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))
    context = plan["env"]["contexts"][0]
    spider_job = next(job for job in plan["jobs"] if job["type"] == "spider")
    spider_ajax_job = next(job for job in plan["jobs"] if job["type"] == "spiderAjax")
    wait_job = next(job for job in plan["jobs"] if job["type"] == "passiveScan-wait")
    active_job = next(job for job in plan["jobs"] if job["type"] == "activeScan")
    report_job = next(job for job in plan["jobs"] if job["type"] == "report")

    assert result["automation_plan_source"] == "user template"
    assert result["automation_plan_template_path"] == str(template_path.resolve())
    assert result["automation_plan_runtime_controls"]["runtime_owned_fields"]["jobs.spiderAjax.parameters"] == [
        "context",
        "url",
        "maxDuration",
    ]
    assert result["scan_mode"] == "active"
    assert context["name"] == "scan-target"
    assert context["urls"] == ["https://example.com/app/login"]
    assert context["includePaths"] == [r"^https://example\.com/app/login(?:/.*)?(?:\?.*)?$"]
    assert context["authentication"] == {
        "method": "form",
        "parameters": {
            "loginPageUrl": "https://wrong.example/login",
        },
    }
    assert context["sessionManagement"] == {"method": "cookie"}
    assert context["users"] == [
        {
            "name": "demo-user",
            "credentials": {"username": "demo"},
        }
    ]
    assert context["excludePaths"] == [r"^https://wrong\.example/logout$"]
    assert spider_job["parameters"]["context"] == "scan-target"
    assert spider_job["parameters"]["url"] == "https://example.com/app/login?next=1"
    assert spider_job["parameters"]["maxDuration"] == 2
    assert spider_ajax_job["parameters"]["context"] == "scan-target"
    assert spider_ajax_job["parameters"]["url"] == "https://example.com/app/login?next=1"
    assert spider_ajax_job["parameters"]["maxDuration"] == 2
    assert spider_ajax_job["parameters"]["browserId"] == "firefox-headless"
    assert wait_job["parameters"]["maxDuration"] == 2
    assert active_job["parameters"]["context"] == "scan-target"
    assert active_job["parameters"]["url"] == "https://example.com/app/login?next=1"
    assert active_job["parameters"]["maxRuleDurationInMins"] == 2
    assert active_job["parameters"]["maxScanDurationInMins"] == 2
    assert report_job["parameters"]["template"] == "traditional-json"
    assert report_job["parameters"]["reportDir"] == "/zap/wrk"
    assert report_job["parameters"]["reportFile"] == Path(result["raw_output_path"]).name
    assert report_job["parameters"]["reportTitle"] == "ZAP active scan for https://example.com/app/login"
    assert report_job["parameters"]["reportDescription"] == (
        "Generated by vuln-manager using the ZAP Automation Framework."
    )


def test_zap_scan_preserves_additional_template_contexts_after_managed_primary(monkeypatch, tmp_path):
    scanner = ZapScanner()
    template_path = tmp_path / "zap-multi-context.yaml"
    template_path.write_text(
        yaml.safe_dump(
            {
                "env": {
                    "contexts": [
                        {
                            "name": "template-primary",
                            "urls": ["https://template.example/app"],
                            "includePaths": [r"^https://template\.example/app(?:/.*)?$"],
                            "excludePaths": [r"^https://template\.example/logout$"],
                        },
                        {
                            "name": "secondary-context",
                            "urls": ["https://admin.example/"],
                            "includePaths": [r"^https://admin\.example(?:/.*)?$"],
                            "users": [{"name": "auditor"}],
                        },
                    ]
                },
                "jobs": [
                    {
                        "type": "spider",
                        "parameters": {
                            "context": "secondary-context",
                            "url": "https://admin.example/",
                            "maxDuration": 999,
                        },
                    },
                    {
                        "type": "activeScan",
                        "parameters": {
                            "context": "secondary-context",
                            "url": "https://admin.example/",
                            "maxRuleDurationInMins": 999,
                            "maxScanDurationInMins": 999,
                        },
                    },
                    {
                        "type": "report",
                        "parameters": {
                            "template": "html",
                            "reportDir": "/tmp/report-dir",
                            "reportFile": "wrong.json",
                        },
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "https://example.com/app",
        {
            "output_dir": tmp_path,
            "timeout": 90,
            "af_plan_path": str(template_path),
        },
    )
    plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))
    contexts = plan["env"]["contexts"]
    spider_job = next(job for job in plan["jobs"] if job["type"] == "spider")
    active_job = next(job for job in plan["jobs"] if job["type"] == "activeScan")

    assert [context["name"] for context in contexts] == ["scan-target", "secondary-context"]
    assert contexts[0]["urls"] == ["https://example.com/app"]
    assert contexts[0]["includePaths"] == [r"^https://example\.com/app(?:/.*)?(?:\?.*)?$"]
    assert contexts[0]["excludePaths"] == [r"^https://template\.example/logout$"]
    assert contexts[1] == {
        "name": "secondary-context",
        "urls": ["https://admin.example/"],
        "includePaths": [r"^https://admin\.example(?:/.*)?$"],
        "users": [{"name": "auditor"}],
    }
    assert spider_job["parameters"]["context"] == "scan-target"
    assert spider_job["parameters"]["url"] == "https://example.com/app"
    assert active_job["parameters"]["context"] == "scan-target"
    assert active_job["parameters"]["url"] == "https://example.com/app"
    assert active_job["parameters"]["maxRuleDurationInMins"] == 2
    assert active_job["parameters"]["maxScanDurationInMins"] == 2


def test_zap_scan_adds_missing_report_and_active_scan_jobs_for_user_template(monkeypatch, tmp_path):
    scanner = ZapScanner()
    template_path = tmp_path / "zap-minimal.yaml"
    template_path.write_text(
        yaml.safe_dump(
            {
                "env": {"parameters": {"progressToStdout": False}},
                "jobs": [
                    {
                        "type": "spider",
                        "parameters": {
                            "context": "ignored",
                            "url": "https://ignored.example/",
                        },
                    },
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "https://example.com",
        {
            "output_dir": tmp_path,
            "timeout": 75,
            "active_scan": True,
            "af_plan_path": str(template_path),
        },
    )
    plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))
    job_types = [job["type"] for job in plan["jobs"] if isinstance(job, dict) and "type" in job]

    assert result["scan_mode"] == "active"
    assert job_types == ["spider", "activeScan", "passiveScan-wait", "report", "report"]
    report_jobs = [job for job in plan["jobs"] if isinstance(job, dict) and job.get("type") == "report"]
    assert report_jobs[0]["parameters"]["reportFile"] == Path(result["raw_output_path"]).name
    assert report_jobs[0]["parameters"]["reportDir"] == "/zap/wrk"
    assert report_jobs[0]["parameters"]["template"] == "traditional-json"
    assert report_jobs[1]["parameters"]["reportFile"] == Path(result["expected_zap_xml_report_path"]).name
    assert report_jobs[1]["parameters"]["reportDir"] == "/zap/wrk"
    assert report_jobs[1]["parameters"]["template"] == "traditional-xml"
    assert plan["jobs"][1]["parameters"]["context"] == "scan-target"
    assert plan["jobs"][1]["parameters"]["maxScanDurationInMins"] == 2
    assert plan["jobs"][2]["parameters"]["maxDuration"] == 2
    assert plan["env"]["parameters"]["progressToStdout"] is False
    assert plan["env"]["parameters"]["continueOnFailure"] is True


def test_zap_scan_returns_clear_error_for_invalid_user_template_yaml(monkeypatch, tmp_path):
    scanner = ZapScanner()
    template_path = tmp_path / "zap-invalid.yaml"
    template_path.write_text("env: [\njobs:\n  - type: spider\n", encoding="utf-8")

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)

    result = scanner.scan(
        "https://example.com",
        {
            "output_dir": tmp_path,
            "af_plan_path": str(template_path),
        },
    )

    assert "Could not parse ZAP AF plan template YAML" in result["error"]
    assert str(template_path) in result["error"]
    assert result["automation_plan_source"] == "user template"
    assert result["automation_plan_template_path"] == str(template_path.resolve())
    assert result["findings"] == []


def test_zap_scan_rejects_user_template_with_non_list_jobs(monkeypatch, tmp_path):
    scanner = ZapScanner()
    template_path = tmp_path / "zap-invalid-jobs.yaml"
    template_path.write_text("jobs: {}\n", encoding="utf-8")

    monkeypatch.setattr(scanner, "_check_docker", lambda: False)

    result = scanner.scan(
        "https://example.com",
        {
            "output_dir": tmp_path,
            "af_plan_path": str(template_path),
        },
    )

    assert result["error"] == "ZAP AF plan template 'jobs' must be a YAML list."
    assert result["automation_plan_source"] == "user template"
    assert result["automation_plan_template_path"] == str(template_path.resolve())


def test_zap_uses_local_automation_binary_when_docker_is_unavailable(monkeypatch, tmp_path):
    scanner = ZapScanner()

    monkeypatch.setattr(scanner, "_check_docker", lambda: False)
    monkeypatch.setattr(scanner, "_local_zap_binary", lambda: "/usr/local/bin/zap.sh")
    monkeypatch.setattr(
        scanner,
        "_scan_local",
        lambda binary, target, plan_path, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"{binary} {' '.join(extra_args)} -cmd -autorun {plan_path}".strip(),
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "https://example.com",
        {
            "output_dir": tmp_path,
            "args": "-config api.disablekey=true",
        },
    )

    assert result["target"] == "https://example.com"
    assert "/usr/local/bin/zap.sh -config api.disablekey=true -cmd -autorun" in result["command"]
    assert "zap-baseline.py" not in result["command"]
    assert "zap-full-scan.py" not in result["command"]


def test_zap_scan_preserves_proxy_metadata_in_raw_results(monkeypatch, tmp_path):
    scanner = ZapScanner()

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "https://proxy.local",
        {
            "output_dir": tmp_path,
            "use_proxy": True,
            "proxy_url": "http://127.0.0.1:8081",
            "original_target": "https://example.com",
        },
    )

    assert result["target"] == "http://127.0.0.1:8081"
    assert result["original_target"] == "https://example.com"
    assert result["proxy_mode"] is True
    assert result["proxy_url"] == "http://127.0.0.1:8081"
    assert result["scan_mode"] == "baseline"


def test_zap_scan_preserves_bridge_metadata_in_raw_results(monkeypatch, tmp_path):
    scanner = ZapScanner()

    monkeypatch.setattr(scanner, "_check_docker", lambda: True)
    monkeypatch.setattr(
        scanner,
        "_scan_docker",
        lambda target, raw_dir, plan_filename, report_path, timestamp, timeout, extra_args: {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "raw_output": {},
            "raw_output_path": str(report_path),
            "findings": [],
            "command": f"docker run ... zap.sh -cmd -autorun /zap/wrk/{plan_filename}",
            "exit_code": 0,
        },
    )

    result = scanner.scan(
        "http://127.0.0.1:3000/app/login?next=1",
        {
            "output_dir": tmp_path,
            "origin_target": "https://example.com",
        },
    )

    assert result["target"] == "http://127.0.0.1:3000/app/login?next=1"
    assert result["original_target"] == "https://example.com"
    assert result["origin_target"] == "https://example.com"
    assert result["bridge_mode"] is True
    assert result["proxy_mode"] is False
    assert result["scan_mode"] == "baseline"


def test_zap_docker_scan_builds_headless_command(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}

    monkeypatch.setattr(
        ZapScanner,
        "_selinux_enforce_path",
        staticmethod(lambda: tmp_path / "missing-selinux-enforce"),
    )

    def fake_run_subprocess(cmd, target, report_path, timestamp, timeout):
        captured["cmd"] = cmd
        captured["target"] = target
        captured["report_path"] = report_path
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "command": " ".join(cmd),
            "findings": [],
            "exit_code": 0,
        }

    monkeypatch.setattr(scanner, "_run_subprocess", fake_run_subprocess)

    result = scanner._scan_docker(
        target="https://example.com",
        raw_dir=tmp_path,
        plan_filename="zap_plan.yaml",
        report_path=tmp_path / "zap_report.json",
        timestamp="2026-04-01T00:00:00Z",
        timeout=60,
        extra_args=["-config", "api.disablekey=true"],
    )

    assert result["target"] == "https://example.com"
    assert captured["cmd"][:4] == ["docker", "run", "--rm", "-v"]
    assert f"{tmp_path.resolve()}:/zap/wrk:rw" in captured["cmd"]
    assert "-t" in captured["cmd"]
    assert "zap.sh" in captured["cmd"]
    assert captured["cmd"][-2:] == ["-autorun", "/zap/wrk/zap_plan.yaml"]
    assert "-config" in captured["cmd"]
    assert "api.disablekey=true" in captured["cmd"]
    assert "zap-baseline.py" not in captured["cmd"]
    assert "zap-full-scan.py" not in captured["cmd"]


def test_zap_docker_scan_adds_selinux_relabel_mount_on_linux(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}
    enforce_path = tmp_path / "selinux-enforce"
    enforce_path.write_text("1", encoding="utf-8")

    def fake_run_subprocess(cmd, target, report_path, timestamp, timeout):
        captured["cmd"] = cmd
        captured["target"] = target
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "command": " ".join(cmd),
            "findings": [],
            "exit_code": 0,
        }

    monkeypatch.setattr("scanners.zap_scanner.sys.platform", "linux")
    monkeypatch.setattr(
        ZapScanner,
        "_selinux_enforce_path",
        staticmethod(lambda: enforce_path),
    )
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run_subprocess)

    scanner._scan_docker(
        target="https://example.com",
        raw_dir=tmp_path,
        plan_filename="zap_plan.yaml",
        report_path=tmp_path / "zap_report.json",
        timestamp="2026-04-02T00:00:00Z",
        timeout=60,
        extra_args=[],
    )

    assert f"{tmp_path.resolve()}:/zap/wrk:rw,Z" in captured["cmd"]
    assert "zap.sh" in captured["cmd"]
    assert "/zap/wrk/zap_plan.yaml" in captured["cmd"]


def test_zap_docker_scan_uses_host_network_for_loopback_proxy_on_linux(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}

    def fake_run_subprocess(cmd, target, report_path, timestamp, timeout):
        captured["cmd"] = cmd
        captured["target"] = target
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "command": " ".join(cmd),
            "findings": [],
            "exit_code": 0,
        }

    monkeypatch.setattr("scanners.zap_scanner.sys.platform", "linux")
    monkeypatch.setattr(ZapScanner, "_pick_unused_loopback_port", staticmethod(lambda: 43123))
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run_subprocess)

    result = scanner._scan_docker(
        target="http://127.0.0.1:8081",
        raw_dir=tmp_path,
        plan_filename="zap_plan.yaml",
        report_path=tmp_path / "zap_report.json",
        timestamp="2026-04-02T00:00:00Z",
        timeout=60,
        extra_args=[],
    )

    assert result["target"] == "http://127.0.0.1:8081"
    assert "--network" in captured["cmd"]
    assert "host" in captured["cmd"]
    assert "-config" in captured["cmd"]
    assert "proxy.port=43123" in captured["cmd"]
    assert "zap.sh" in captured["cmd"]
    assert "/zap/wrk/zap_plan.yaml" in captured["cmd"]


def test_zap_docker_scan_rewrites_loopback_proxy_for_non_linux(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}

    def fake_run_subprocess(cmd, target, report_path, timestamp, timeout):
        captured["cmd"] = cmd
        captured["target"] = target
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "command": " ".join(cmd),
            "findings": [],
            "exit_code": 0,
        }

    monkeypatch.setattr("scanners.zap_scanner.sys.platform", "darwin")
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run_subprocess)

    result = scanner._scan_docker(
        target="http://127.0.0.1:8081",
        raw_dir=tmp_path,
        plan_filename="zap_plan.yaml",
        report_path=tmp_path / "zap_report.json",
        timestamp="2026-04-02T00:00:00Z",
        timeout=60,
        extra_args=[],
    )

    assert result["target"] == "http://host.docker.internal:8081"
    assert "--network" not in captured["cmd"]
    assert "zap.sh" in captured["cmd"]


def test_zap_docker_scan_preserves_explicit_proxy_port_override_on_host_network(monkeypatch, tmp_path):
    scanner = ZapScanner()
    captured = {}

    def fake_run_subprocess(cmd, target, report_path, timestamp, timeout):
        captured["cmd"] = cmd
        captured["target"] = target
        return {
            "scanner": "zap",
            "target": target,
            "timestamp": timestamp,
            "command": " ".join(cmd),
            "findings": [],
            "exit_code": 0,
        }

    monkeypatch.setattr("scanners.zap_scanner.sys.platform", "linux")
    monkeypatch.setattr(ZapScanner, "_pick_unused_loopback_port", staticmethod(lambda: 43123))
    monkeypatch.setattr(scanner, "_run_subprocess", fake_run_subprocess)

    scanner._scan_docker(
        target="http://127.0.0.1:8081",
        raw_dir=tmp_path,
        plan_filename="zap_plan.yaml",
        report_path=tmp_path / "zap_report.json",
        timestamp="2026-04-02T00:00:00Z",
        timeout=60,
        extra_args=["-config", "proxy.port=49000"],
    )

    assert "--network" in captured["cmd"]
    assert "host" in captured["cmd"]
    assert "proxy.port=49000" in captured["cmd"]
    assert "proxy.port=43123" not in captured["cmd"]


def test_zap_get_proxy_options_enables_proxy_mode():
    scanner = ZapScanner()

    assert scanner.get_proxy_options("http://127.0.0.1:8081") == {
        "use_proxy": True,
        "proxy_url": "http://127.0.0.1:8081",
    }


def test_active_runtime_uses_repo_zap_scanner_module():
    source_file = inspect.getsourcefile(ZapScanner)

    assert source_file is not None
    assert source_file.endswith("/scanners/zap_scanner.py")


def test_zap_uses_report_when_baseline_exits_with_warning_code(monkeypatch, tmp_path):
    scanner = ZapScanner()
    report_path = tmp_path / "zap_report.json"
    report_path.write_text(json.dumps({
        "site": [{
            "@name": "https://example.com",
            "alerts": [{
                "name": "Test Alert",
                "riskdesc": "Low",
                "desc": "desc",
                "solution": "fix",
                "instances": [{"uri": "https://example.com/test"}],
            }],
        }],
    }))

    monkeypatch.setattr(
        "scanners.zap_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=2, stdout="warn", stderr=""),
    )

    result = scanner._run_subprocess(
        ["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
        "https://example.com",
        report_path,
        "2026-04-01T00:00:00Z",
        60,
    )

    assert result["exit_code"] == 0
    assert result["raw_exit_code"] == 2
    assert result["degraded_execution"] is True
    assert result["scanner_error"] == result["error"]
    assert len(result["findings"]) == 1
    assert "reported warnings but still produced a report" in result["error"]
    assert result["raw_output"]["site"][0]["@name"] == "https://example.com"


def test_zap_existing_report_import_needs_no_runtime_or_target_probe(monkeypatch, tmp_path):
    report_path = tmp_path / "manual-zap-report.json"
    report_path.write_text(json.dumps({
        "@version": "2.17.0",
        "site": [{
            "@name": "https://example.com",
            "alerts": [{
                "name": "Missing Content Security Policy",
                "riskdesc": "Medium",
                "desc": "The response does not define a Content Security Policy.",
                "solution": "Define an appropriate Content-Security-Policy header.",
                "instances": [{"uri": "https://example.com/login", "method": "GET"}],
            }],
        }],
    }), encoding="utf-8")

    scanner = ZapScanner()
    monkeypatch.setattr(
        scanner,
        "is_available",
        lambda: pytest.fail("ZAP availability must not be checked for --zap-report"),
    )
    monkeypatch.setattr(
        "scanners.zap_scanner.subprocess.run",
        lambda *args, **kwargs: pytest.fail("ZAP subprocess must not run for --zap-report"),
    )

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "runs")
    orchestrator.register_scanner("zap", scanner)
    monkeypatch.setattr(
        orchestrator,
        "probe_target",
        lambda target: pytest.fail("Target probing must not run for an imported report"),
    )

    result = orchestrator.run_scanner(
        "zap",
        "example.com",
        options={"report_path": str(report_path)},
        normalize=True,
        save_raw=True,
    )

    assert result["scan_route"] == "imported_report"
    assert result["transport_detected"] == "not_contacted"
    assert result["normalized_findings_count"] == 1
    assert result["findings"][0]["vulnerability_name"] == "Missing Content Security Policy"
    assert result["findings"][0]["meta"]["scanner"] == "zap"
    imported_path = Path(result["imported_report_path"])
    assert imported_path != report_path.resolve()
    assert imported_path.parent.name == "raw"
    assert imported_path.read_text(encoding="utf-8") == report_path.read_text(encoding="utf-8")
    assert imported_path.with_suffix(".xml").is_file()
    assert not report_path.with_suffix(".xml").exists()
    assert result["imported_report"] is True
    assert result["report_format"] == "traditional-json"
    assert result["scanner_execution"]["scan_route"] == "imported_report"


def test_discovery_mode_imports_one_zap_report_once_for_multiple_web_services(monkeypatch, tmp_path):
    report_path = tmp_path / "manual-zap-report.json"
    report_path.write_text(json.dumps({
        "site": [{
            "@name": "https://example.com",
            "alerts": [{
                "name": "Test Alert",
                "riskdesc": "Low",
                "desc": "Imported once.",
                "solution": "Review.",
                "instances": [{"uri": "https://example.com/test"}],
            }],
        }],
    }), encoding="utf-8")

    class TwoServiceNmap(BaseScanner):
        def __init__(self):
            super().__init__("nmap")
            self.scanner_type = "network"

        def is_available(self):
            return True

        def scan(self, target, options=None):
            return {
                "scanner": "nmap",
                "target": target,
                "timestamp": "2026-08-08T12:00:00Z",
                "raw_output": "",
                "exit_code": 0,
                "findings": [],
                "discovered_services": [
                    {
                        "host": "example.com", "port": 80, "protocol": "tcp",
                        "state": "open", "service": "http", "service_version": "nginx",
                        "is_web": True, "web_scheme": "http",
                    },
                    {
                        "host": "example.com", "port": 443, "protocol": "tcp",
                        "state": "open", "service": "https", "service_version": "nginx",
                        "is_web": True, "web_scheme": "https",
                    },
                ],
            }

        def normalize(self, raw_results):
            return []

    zap = ZapScanner()
    monkeypatch.setattr(zap, "is_available", lambda: False)
    monkeypatch.setattr(zap, "get_version", lambda: "imported-report")
    import_calls = []
    original_import = zap._import_existing_report

    def recording_import(**kwargs):
        import_calls.append(kwargs["report_path"])
        return original_import(**kwargs)

    monkeypatch.setattr(zap, "_import_existing_report", recording_import)

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path / "runs")
    orchestrator.register_scanner("nmap", TwoServiceNmap())
    orchestrator.register_scanner("zap", zap)
    orchestrator.set_scan_mode("automatic")

    results = orchestrator.run_all(
        "example.com",
        options={"zap": {"report_path": str(report_path)}},
        save_raw=False,
    )

    assert import_calls == [report_path.resolve()]
    assert results["scanners_run"].count("zap") == 1
    assert results["imported_reports"] == [{
        "scanner": "zap",
        "execution_key": "zap",
        "path": str((Path(results["run_folder"]) / "raw" / "zap_imported_manual-zap-report.json").resolve()),
        "format": "traditional-json",
    }]
    assert results["summary"]["total_findings"] == 1
    assert len(results["findings_by_scanner"]["zap"]) == 1


def test_zap_report_import_rejects_malformed_shape_and_wrong_target(tmp_path):
    scanner = ZapScanner()
    malformed_path = tmp_path / "malformed.json"
    malformed_path.write_text(json.dumps({"site": "not-an-array"}), encoding="utf-8")

    with pytest.raises(ValueError, match="field 'site' must be an object or array"):
        scanner.validate_options({"report_path": str(malformed_path)})

    wrong_target_path = tmp_path / "wrong-target.json"
    wrong_target_path.write_text(
        json.dumps({"site": [{"@name": "https://other.example", "alerts": []}]}),
        encoding="utf-8",
    )
    result = scanner.scan(
        "example.com",
        {"report_path": str(wrong_target_path)},
    )

    assert result["findings"] == []
    assert "does not contain the requested target host 'example.com'" in result["error"]


def test_zap_process_output_summary_prefers_signal_lines_over_boot_logs():
    scanner = ZapScanner()

    summary = scanner._summarize_process_output(
        stdout=(
            "Found Java version 17.0.18\n"
            "Available memory: 15373 MB\n"
            "Using JVM args: -Xmx3843m\n"
            "417 [main] INFO org.parosproxy.paros.Constant - "
            "Copying default configuration to /home/zap/.ZAP/config.xml\n"
            "912 [main] ERROR org.zaproxy.addon.automation.ExtensionAutomation - "
            "Job spider failed for https://example.com\n"
        )
    )

    assert "stdout: 912 [main] ERROR" in summary
    assert "Job spider failed for https://example.com" in summary
    assert "Found Java version" not in summary
    assert "Copying default configuration" not in summary


def test_zap_process_output_summary_omits_pure_boot_logs():
    scanner = ZapScanner()

    summary = scanner._summarize_process_output(
        stdout=(
            "Found Java version 17.0.18\n"
            "Available memory: 15373 MB\n"
            "Using JVM args: -Xmx3843m\n"
            "417 [main] INFO org.parosproxy.paros.Constant - "
            "Copying default configuration to /home/zap/.ZAP/config.xml\n"
        )
    )

    assert summary == ""


def test_zap_recovers_alternate_valid_report_file(monkeypatch, tmp_path):
    scanner = ZapScanner()
    expected_report_path = tmp_path / "zap_expected.json"
    alternate_report_path = tmp_path / "zap_actual.json"

    def fake_run(*args, **kwargs):
        alternate_report_path.write_text(json.dumps({
            "site": [{
                "@name": "https://example.com",
                "alerts": [{
                    "name": "Recovered Alternate Alert",
                    "riskdesc": "Low",
                    "desc": "desc",
                    "solution": "fix",
                    "instances": [{"uri": "https://example.com/recovered"}],
                }],
            }],
        }))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr("scanners.zap_scanner.subprocess.run", fake_run)

    result = scanner._run_subprocess(
        ["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
        "https://example.com",
        expected_report_path,
        "2026-04-01T00:00:00Z",
        60,
    )

    assert result["raw_output_path"] == str(alternate_report_path)
    assert result["expected_raw_output_path"] == str(expected_report_path)
    assert result["report_recovered"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0]["name"] == "Recovered Alternate Alert"
    assert "error" not in result


def test_zap_timeout_recovers_partial_report(monkeypatch, tmp_path):
    scanner = ZapScanner()
    report_path = tmp_path / "zap_timeout_report.json"

    def fake_run(*args, **kwargs):
        report_path.write_text(json.dumps({
            "site": [{
                "@name": "https://example.com",
                "alerts": [{
                    "name": "Recovered Alert",
                    "riskdesc": "Low",
                    "desc": "desc",
                    "solution": "fix",
                    "instances": [{"uri": "https://example.com/recovered"}],
                }],
            }],
        }))
        raise subprocess.TimeoutExpired(
            cmd=["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
            timeout=30,
            output="partial stdout",
            stderr="partial stderr",
        )

    monkeypatch.setattr("scanners.zap_scanner.subprocess.run", fake_run)

    result = scanner._run_subprocess(
        ["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
        "https://example.com",
        report_path,
        "2026-04-01T00:00:00Z",
        30,
    )

    assert result["partial_results"] is True
    assert result["raw_output_path"] == str(report_path)
    assert result["raw_output"]["site"][0]["@name"] == "https://example.com"
    assert len(result["findings"]) == 1
    assert result["stdout"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    assert result["exit_code"] is None
    assert "partial results were recovered" in result["error"]


def test_zap_timeout_without_report_keeps_timeout_details(monkeypatch, tmp_path):
    scanner = ZapScanner()
    report_path = tmp_path / "missing_timeout_report.json"

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
            timeout=45,
            output=b"partial stdout",
            stderr=b"partial stderr",
        )

    monkeypatch.setattr("scanners.zap_scanner.subprocess.run", fake_run)

    result = scanner._run_subprocess(
        ["zap.sh", "-cmd", "-autorun", str(tmp_path / "zap_plan.yaml")],
        "https://example.com",
        report_path,
        "2026-04-01T00:00:00Z",
        45,
    )

    assert "Scan timed out after 45 seconds." in result["error"]
    assert "Report file does not exist" in result["error"]
    assert result["raw_output"] is None
    assert result["raw_output_path"] is None
    assert result["findings"] == []
    assert result["stdout"] == "partial stdout"
    assert result["stderr"] == "partial stderr"
    assert result["expected_raw_output_path"] == str(report_path)
    assert "partial_results" not in result


def test_zap_returns_clear_error_when_report_file_is_missing(monkeypatch, tmp_path):
    scanner = ZapScanner()
    report_path = tmp_path / "missing.json"
    sibling_plan = tmp_path / "zap_plan.yaml"
    sibling_plan.write_text("jobs: []\n", encoding="utf-8")

    monkeypatch.setattr(
        "scanners.zap_scanner.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=3,
            stdout="",
            stderr="Failed to access summary file /home/zap/zap_out.json",
        ),
    )

    result = scanner._run_subprocess(
        ["docker", "run", "ghcr.io/zaproxy/zaproxy:stable", "zap.sh", "-cmd", "-autorun", "/zap/wrk/zap_plan.yaml"],
        "https://example.com",
        report_path,
        "2026-04-01T00:00:00Z",
        60,
    )

    assert result["exit_code"] == 3
    assert "did not create the expected report file" in result["error"]
    assert str(report_path) in result["error"]
    assert "Failed to access summary file /home/zap/zap_out.json" in result["error"]
    assert result["scanner_error"] == result["error"]
    assert result["degraded_execution"] is True
    assert result["report_load_issue"]
    assert result["expected_raw_output_path"] == str(report_path)
    assert "zap_plan.yaml" in result["raw_artifact_dir_entries"]
    assert result["stderr"] == "Failed to access summary file /home/zap/zap_out.json"
    assert result["stdout"] == ""


def test_orchestrator_keeps_report_backed_degraded_scan_as_warning(tmp_path):
    class FakeScanner(BaseScanner):
        def __init__(self):
            super().__init__("fake")

        def scan(self, target, options=None):
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": "2026-04-10T00:00:00Z",
                "error": "scanner produced a degraded report",
                "scanner_error": "scanner produced a degraded report",
                "raw_output": {},
                "raw_output_path": str(tmp_path / "fake.json"),
                "findings": [],
                "exit_code": 0,
            }

        def normalize(self, raw_results):
            return []

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("fake", FakeScanner())

    result = orchestrator.run_scanner("fake", "example.com", save_raw=False)

    assert "error" not in result
    assert result["warning"] == "scanner produced a degraded report"
    assert result["findings"] == []


def test_main_single_scanner_warning_does_not_print_clean_success(monkeypatch, tmp_path, capsys):
    class FakeScanner:
        def get_version(self):
            return "test-version"

        def get_default_options(self):
            return {}

        def validate_options(self, options):
            return options

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {"zap": FakeScanner()}

        @staticmethod
        def _count_by_severity(findings):
            return {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        def run_scanner(self, name, target, options=None, normalize=True, save_raw=True):
            return {
                "scanner": name,
                "target": target,
                "timestamp": "2026-04-10T00:00:00Z",
                "warning": "ZAP produced a degraded report after spider errors.",
                "findings": [],
                "scanner_execution": {
                    "scanner_type": "web",
                    "transport_detected": "http1_only",
                    "scan_route": "direct",
                    "adapter_mode": "direct",
                    "degraded_execution": True,
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
        ["main.py", "--target", "https://example.com", "--scanner", "zap", "--no-dedupe", "--no-score"],
    )

    rc = main.main()
    captured = capsys.readouterr()

    assert rc == 0
    assert "Warnings:" in captured.out
    assert "ZAP produced a degraded report after spider errors." in captured.out
    assert "No findings were produced because the scan failed, timed out, or was degraded." in captured.out
    assert "No vulnerabilities found!" not in captured.out


def test_zap_execution_path_and_source_do_not_reference_old_packaged_scripts():
    source = inspect.getsource(ZapScanner)
    scanner = ZapScanner()
    plan = scanner._build_automation_plan(
        target="https://example.com/",
        report_filename="zap_report.json",
        active_scan=True,
        timeout=120,
    )

    assert "zap-baseline.py" not in source
    assert "zap-full-scan.py" not in source
    assert "zap-baseline.py" not in json.dumps(plan)
    assert "zap-full-scan.py" not in json.dumps(plan)


@pytest.mark.zap_docker
def test_zap_docker_automation_smoke_end_to_end(tmp_path, pytestconfig):
    _ensure_zap_docker_smoke_preconditions(pytestconfig)
    scanner = ZapScanner()

    with _serve_zap_smoke_site() as target:
        result = scanner.scan(
            target,
            {
                "output_dir": tmp_path,
                "timeout": 120,
            },
        )

    debug_snapshot = _zap_smoke_debug_snapshot(result)
    assert result["command"] is not None
    assert result["command"].startswith("docker run --rm"), result["command"]
    assert "ghcr.io/zaproxy/zaproxy:stable" in result["command"]
    assert "zap.sh" in result["command"]
    assert "-cmd" in result["command"]
    assert "-autorun" in result["command"]
    assert "zap-baseline.py" not in result["command"]
    assert "zap-full-scan.py" not in result["command"]
    assert Path(result["automation_plan_path"]).exists()
    automation_plan = yaml.safe_load(Path(result["automation_plan_path"]).read_text(encoding="utf-8"))
    assert isinstance(automation_plan, dict)
    assert isinstance(automation_plan.get("jobs"), list)
    assert result["raw_output_path"] is not None, debug_snapshot
    assert Path(result["raw_output_path"]).exists(), debug_snapshot

    with open(result["raw_output_path"], "r", encoding="utf-8") as fh:
        raw_report = json.load(fh)

    findings = scanner._extract_findings_from_raw(raw_report)
    assert isinstance(raw_report, dict)
    assert "site" in raw_report
    assert isinstance(findings, list)
    assert result["raw_output"] == raw_report
    assert result["findings"] == findings
    assert result["exit_code"] in (0, None)
    if findings:
        normalized = scanner.normalize(result)
        assert len(normalized) == len(findings), debug_snapshot
        for finding in normalized:
            ok, errors = validate_finding(finding)
            assert ok, errors
    if result.get("error"):
        assert "reported" in result["error"] or "partial results were recovered" in result["error"]


def test_zap_normalize_proxy_mode_preserves_original_target_identity():
    scanner = ZapScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:8081",
            "original_target": "https://example.com",
            "proxy_mode": True,
            "proxy_url": "http://127.0.0.1:8081",
            "findings": [{
                "name": "Proxy-safe ZAP alert",
                "riskdesc": "Low",
                "desc": "desc",
                "solution": "fix",
                "_site_url": "http://127.0.0.1:8081",
                "instances": [{
                    "uri": "http://127.0.0.1:8081/login?next=1",
                    "method": "GET",
                    "param": "next",
                }],
            }],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/login?next=1"
    assert finding["meta"]["host"] == "example.com"
    assert finding["meta"]["scheme"] == "https"
    assert finding["meta"]["path"] == "/login"
    assert finding["meta"]["query_keys"] == ["next"]
    assert finding["meta"]["proxy_mode"] is True
    assert finding["meta"]["effective_target"] == "http://127.0.0.1:8081"
    assert finding["meta"]["original_target"] == "https://example.com"
    assert finding["meta"]["proxy_url"] == "http://127.0.0.1:8081"


def test_zap_normalize_bridge_mode_preserves_origin_target_identity():
    scanner = ZapScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:3000/login?next=1",
            "origin_target": "https://example.com",
            "findings": [{
                "name": "Bridge-safe ZAP alert",
                "riskdesc": "Low",
                "desc": "desc",
                "solution": "fix",
                "_site_url": "http://127.0.0.1:3000",
                "instances": [{
                    "uri": "http://127.0.0.1:3000/login?next=1&lang=en",
                    "method": "GET",
                    "param": "next",
                }],
            }],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/login?next=1&lang=en"
    assert finding["meta"]["host"] == "example.com"
    assert finding["meta"]["scheme"] == "https"
    assert finding["meta"].get("port") is None
    assert finding["meta"]["path"] == "/login"
    assert finding["meta"]["query_keys"] == ["lang", "next"]
    assert finding["meta"]["bridge_mode"] is True
    assert finding["meta"]["origin_target"] == "https://example.com"
    assert finding["meta"]["original_target"] == "https://example.com"
    assert finding["meta"]["effective_target"] == "http://127.0.0.1:3000/login?next=1"
    assert "127.0.0.1" not in finding["fp_strict"]


def test_zap_normalize_proxy_mode_rewrites_loopback_instance_urls():
    scanner = ZapScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "http://127.0.0.1:8081",
            "original_target": "https://example.com",
            "proxy_mode": True,
            "proxy_url": "http://127.0.0.1:8081",
            "findings": [{
                "name": "Proxy-safe ZAP alert",
                "riskdesc": "Low",
                "desc": "desc",
                "solution": "fix",
                "_site_url": "http://127.0.0.1:8081",
                "instances": [{
                    "uri": "http://localhost:8081/login?next=1&lang=en",
                    "method": "GET",
                    "param": "next",
                }],
            }],
        }
    )

    finding = normalized[0]
    assert finding["asset_id"] == "https://example.com/login?next=1&lang=en"
    assert finding["meta"]["host"] == "example.com"
    assert finding["meta"]["scheme"] == "https"
    assert finding["meta"].get("port") is None
    assert finding["meta"]["path"] == "/login"
    assert finding["meta"]["query_keys"] == ["lang", "next"]
    assert "127.0.0.1" not in finding["fp_strict"]
    assert "localhost" not in finding["fp_strict"]


def test_zap_normalize_non_proxy_mode_keeps_direct_target_identity():
    scanner = ZapScanner()
    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-01T00:00:00Z",
            "target": "https://example.com",
            "findings": [{
                "name": "Direct ZAP alert",
                "riskdesc": "Low",
                "desc": "desc",
                "solution": "fix",
                "_site_url": "https://example.com",
                "instances": [{"uri": "https://example.com/admin"}],
            }],
        }
    )

    assert normalized[0]["asset_id"] == "https://example.com/admin"
    assert normalized[0]["meta"]["host"] == "example.com"
    assert "proxy_mode" not in normalized[0]["meta"] or normalized[0]["meta"]["proxy_mode"] is False


def test_wapiti_filters_findings_by_requested_severity():
    scanner = WapitiScanner()
    findings = [
        {"name": "Info", "level": 0},
        {"name": "Low", "level": 1},
        {"name": "Medium", "level": 2},
        {"name": "High", "level": 3},
    ]

    filtered = scanner._filter_findings_by_severity(findings, ["high", "medium"])

    assert [finding["name"] for finding in filtered] == ["Medium", "High"]


def test_nikto_severity_mapping_is_conservative_and_explicit():
    scanner = NiktoScanner()

    assert scanner._normalize_severity({"msg": "Remote code execution vulnerability"}) == "critical"
    assert scanner._normalize_severity({"msg": "Cross-site scripting detected"}) == "high"
    assert scanner._normalize_severity({"msg": "Outdated software detected"}) == "medium"
    assert scanner._normalize_severity({"msg": "Server banner exposes version information"}) == "low"
    assert scanner._normalize_severity({"msg": "Interesting response observed"}) == "info"


def test_nmap_non_cve_findings_preserve_scanner_output_without_synthetic_text():
    scanner = NmapScanner()
    raw_results = {
        "timestamp": "2026-03-31T00:00:00Z",
        "target": "example.com",
        "findings": [
            {
                "host": "example.com",
                "port": "80",
                "protocol": "tcp",
                "service": "http",
                "service_version": "Apache",
                "script": "http-title",
                "output": "Sample title",
                "cve_id": None,
                "cvss": None,
            }
        ],
    }

    normalized = scanner.normalize(raw_results)

    assert normalized[0]["description"] == "Sample title"
    assert normalized[0]["remediation"] == ""
    assert "raw_id" not in normalized[0]["meta"]
    assert "cve_id" not in normalized[0]["meta"]


def test_nmap_non_cve_findings_omit_optional_null_meta_and_validate():
    scanner = NmapScanner()
    raw_results = {
        "timestamp": "2026-03-31T00:00:00Z",
        "target": "example.com",
        "findings": [
            {
                "host": "example.com",
                "port": "443",
                "protocol": "tcp",
                "service": "https",
                "service_version": "nginx",
                "script": "ssl-cert",
                "output": "certificate details",
                "cve_id": None,
                "cvss": None,
            }
        ],
    }

    normalized = scanner.normalize(raw_results)
    ok, errors = validate_finding(normalized[0])

    assert ok, errors
    assert normalized[0]["meta"]["cve_ids"] == []
    assert "raw_id" not in normalized[0]["meta"]
    assert "cve_id" not in normalized[0]["meta"]
