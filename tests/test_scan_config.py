import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import main
from orchestrator import ScannerOrchestrator
from scanners.base import BaseScanner
from scanners.nikto_scanner import NiktoScanner
from scanners.nmap_scanner import NmapScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from scanners.zap_scanner import ZapScanner
from utils.scan_config import SCAN_CONFIG_ENABLED_KEY
from utils.schema import SCHEMA_VERSION

ROOT = Path(__file__).resolve().parent.parent


def _minimal_results(target: str, scanners_run: list[str]) -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "timestamp": "2026-04-14T00:00:00Z",
        "scanners_run": list(scanners_run),
        "all_findings": [],
        "findings_by_scanner": {name: [] for name in scanners_run},
        "errors": [],
        "summary": {
            "total_findings": 0,
            "by_severity": {},
            "by_scanner": {name: 0 for name in scanners_run},
        },
    }


def _scanner_registry() -> dict[str, BaseScanner]:
    return {
        "nmap": NmapScanner(),
        "nuclei": NucleiScanner(),
        "wapiti": WapitiScanner(),
        "nikto": NiktoScanner(),
        "zap": ZapScanner(),
    }


def test_main_help_lists_scan_config_flag():
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "--scan-config" in result.stdout
    assert "--no-report" in result.stdout
    assert "--normalize" in result.stdout
    assert "--no-normalize" in result.stdout
    assert "--risk-scoring" in result.stdout
    assert "--no-risk-scoring" in result.stdout
    assert "--no-score" in result.stdout
    assert "--with-zap" in result.stdout
    assert "--scanners" in result.stdout
    assert "--zap-report" in result.stdout


class _ConfigCaptureOrchestrator:
    def __init__(self, run_root: Path, captured: dict):
        self.scanners = _scanner_registry()
        self.current_run_folder = None
        self._run_root = run_root
        self._captured = captured

    def ensure_run_folder(self, target, timestamp=None):
        run_folder = self._run_root / "run"
        run_folder.mkdir(parents=True, exist_ok=True)
        (run_folder / "raw").mkdir(parents=True, exist_ok=True)
        self.current_run_folder = run_folder
        self._captured["run_target"] = target
        return run_folder

    def set_http_mode(self, value):
        self._captured["http_mode"] = value

    def set_scan_mode(self, value):
        self._captured["scan_mode"] = value

    def set_selected_ports(self, value):
        self._captured["selected_ports"] = value

    def set_http2_adapter_mode(self, value):
        self._captured["http2_adapter_mode"] = value

    def probe_target(self, target):
        self._captured["probe_target"] = target
        return {
            "input_target": target,
            "normalized_target": f"https://{target}" if "://" not in target else target,
            "selected_scheme": "https",
            "reachable": True,
            "supports_http2": True,
            "supports_http1_1": True,
            "http2_only": False,
            "transport_detected": "http2_and_http1",
            "detected_http_version": "HTTP/1.1",
            "probe_method": "fake",
            "reason": "fake target probe",
            "attempts": [],
        }

    def run_all(self, target, options=None, normalize=True, save_raw=True):
        run_folder = self._run_root / "run"
        run_folder.mkdir(parents=True, exist_ok=True)
        self.current_run_folder = run_folder
        self._captured["target"] = target
        self._captured["options"] = options or {}
        self._captured["normalize"] = normalize
        self._captured["save_raw"] = save_raw
        scanners_run = [
            name
            for name, opts in (options or {}).items()
            if opts.get(SCAN_CONFIG_ENABLED_KEY, True)
        ] or ["nmap"]
        return _minimal_results(target, scanners_run)

    def run_selected(self, target, scanner_names, options=None, normalize=True, save_raw=True):
        run_folder = self._run_root / "run"
        run_folder.mkdir(parents=True, exist_ok=True)
        self.current_run_folder = run_folder
        self._captured["target"] = target
        self._captured["selected_scanners"] = list(scanner_names)
        self._captured["options"] = options or {}
        self._captured["normalize"] = normalize
        self._captured["save_raw"] = save_raw
        return _minimal_results(target, list(scanner_names))

    def run_scanner(self, scanner_name, target, options=None, normalize=True, save_raw=True):
        run_folder = self._run_root / "run"
        run_folder.mkdir(parents=True, exist_ok=True)
        self.current_run_folder = run_folder
        self._captured["scanner"] = scanner_name
        self._captured["target"] = target
        self._captured["options"] = options or {}
        self._captured["normalize"] = normalize
        self._captured["save_raw"] = save_raw
        return {
            "scanner": scanner_name,
            "target": target,
            "timestamp": "2026-04-14T00:00:00Z",
            "command": scanner_name,
            "raw_output": "",
            "stderr": "",
            "exit_code": 0,
            "findings": [],
        }

    @staticmethod
    def _count_by_severity(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = str(finding.get("severity") or "info").lower()
            counts[severity if severity in counts else "info"] += 1
        return counts

    def save_results(self, results, output=None):
        if self.current_run_folder is None:
            self.current_run_folder = self._run_root / "run"
            self.current_run_folder.mkdir(parents=True, exist_ok=True)
        path = self.current_run_folder / "normalized.json"
        path.write_text(json.dumps(results), encoding="utf-8")
        return path


def _run_main_with_fake_orchestrator(
    monkeypatch,
    tmp_path: Path,
    argv: list[str],
) -> tuple[int, dict]:
    captured: dict = {}
    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _ConfigCaptureOrchestrator(tmp_path, captured),
    )
    monkeypatch.setattr(sys, "argv", argv)
    rc = main.main()
    return rc, captured


def test_main_generates_report_by_default_for_normal_scan_runs(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["target"] == "example.com"
    assert (tmp_path / "run" / "report.html").exists()

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["global"]["report"] is True


def test_main_probe_only_does_not_generate_report_by_default(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--probe-only",
            "--json",
        ],
    )
    output = capsys.readouterr()

    assert rc == 0
    assert captured["probe_target"] == "example.com"
    assert not (tmp_path / "run").exists()
    assert "normalized_target" in output.out


def test_main_runs_explicit_scanner_subset_and_persists_selection(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanners", "nmap,nuclei,nmap",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["selected_scanners"] == ["nmap", "nuclei"]
    effective = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert effective["selected_scanners"] == ["nmap", "nuclei"]
    assert effective["scanners"]["nmap"]["enabled"] is True
    assert effective["scanners"]["nuclei"]["enabled"] is True
    assert effective["scanners"]["zap"]["enabled"] is False


def test_main_accepts_valid_yaml_scan_config_and_saves_effective_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  scan_mode: automatic
  http_mode: auto
  save_raw: true
scanners:
  nmap:
    options:
      ports: "80,443"
  nuclei:
    options:
      severity:
        - high
  nikto:
    enabled: false
  zap:
    options:
      timeout: 1800
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["scan_mode"] == "automatic"
    assert captured["save_raw"] is True
    assert captured["options"]["nmap"]["ports"] == "80,443"
    assert captured["options"]["nuclei"]["severity"] == ["high"]
    assert captured["options"]["nikto"][SCAN_CONFIG_ENABLED_KEY] is False
    assert captured["options"]["zap"]["timeout"] == 1800

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    assert effective_path.exists()
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["global"]["report"] is True
    assert payload["scanners"]["nikto"]["enabled"] is False
    assert payload["scanners"]["zap"]["options"]["timeout"] == 1800
    assert (tmp_path / "run" / "report.html").exists()


def test_effective_scan_config_includes_scanner_defaults(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  nmap:
    options:
      ports: "80,443"
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["nmap"]["ports"] == "80,443"
    assert "scripts" not in captured["options"]["nmap"]
    assert "timeout" not in captured["options"]["nmap"]

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["nmap"]["options"]["ports"] == "80,443"
    assert payload["scanners"]["nmap"]["options"]["scripts"] == ["vulners"]
    assert payload["scanners"]["nmap"]["options"]["timeout"] == 300
    assert payload["scanners"]["nuclei"]["options"]["timeout"] == 600
    assert payload["scanners"]["wapiti"]["options"]["timeout"] == 1800
    assert payload["scanners"]["nikto"]["options"]["timeout"] == 1800
    assert payload["scanners"]["zap"]["options"]["timeout"] == 1200
    assert payload["scanners"]["zap"]["options"]["use_proxy"] is False


def test_main_applies_nmap_cli_options(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--ports", "80,443",
            "--nmap-timeout", "45",
            "--nmap-scripts", "http-title", "vulners",
            "--nmap-args", "--host-timeout 30s --max-retries 1",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["nmap"]["ports"] == "80,443"
    assert captured["options"]["nmap"]["timeout"] == 45
    assert captured["options"]["nmap"]["scripts"] == ["http-title", "vulners"]
    assert captured["options"]["nmap"]["args"] == [
        "--host-timeout",
        "30s",
        "--max-retries",
        "1",
    ]


def test_main_allows_empty_nmap_scripts_from_cli_for_fast_testing(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--nmap-scripts",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["nmap"]["scripts"] == []

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["nmap"]["options"]["scripts"] == []


def test_fast_web_smoke_example_config_is_valid(monkeypatch, tmp_path, capsys):
    config_path = ROOT / "configs" / "examples" / "fast_web_smoke_config.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["nmap"]["scripts"] == []
    assert captured["options"]["nmap"]["timeout"] == 60
    assert captured["options"]["nmap"]["args"] == [
        "--host-timeout",
        "30s",
        "--max-retries",
        "1",
    ]
    assert captured["options"]["wapiti"][SCAN_CONFIG_ENABLED_KEY] is False
    assert captured["options"]["nikto"][SCAN_CONFIG_ENABLED_KEY] is False
    assert captured["options"]["zap"][SCAN_CONFIG_ENABLED_KEY] is False


def test_polite_demo_example_config_is_valid(monkeypatch, tmp_path, capsys):
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["nmap"] == {
        "ports": "80,443,8080,8443",
        "scripts": [],
        "timeout": 240,
        "args": [
            "--host-timeout",
            "120s",
            "--max-retries",
            "1",
            "--max-rate",
            "20",
            "--scan-delay",
            "50ms",
        ],
    }
    assert captured["options"]["nuclei"] == {
        "severity": ["medium", "high", "critical"],
        "rate_limit": 5,
        "timeout": 600,
        "args": ["-c", "2", "-bs", "1", "-retries", "0"],
    }
    assert captured["options"]["wapiti"][SCAN_CONFIG_ENABLED_KEY] is False
    assert captured["options"]["nikto"][SCAN_CONFIG_ENABLED_KEY] is False
    assert captured["options"]["zap"][SCAN_CONFIG_ENABLED_KEY] is False

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["nuclei"]["options"]["rate_limit"] == 5
    assert payload["scanners"]["nuclei"]["options"]["extra_args"] == [
        "-c", "2", "-bs", "1", "-retries", "0",
    ]
    assert payload["scanners"]["wapiti"]["enabled"] is False


def test_polite_demo_profile_builds_rate_limited_scanner_commands(monkeypatch):
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"
    profile = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    captured = {}

    def fake_run(cmd, capture_output=True, text=True, timeout=None):
        captured[cmd[0]] = {"cmd": list(cmd), "timeout": timeout}
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("scanners.nmap_scanner.subprocess.run", fake_run)
    monkeypatch.setattr("scanners.nuclei_scanner.subprocess.run", fake_run)

    nmap = NmapScanner()
    nmap_options = nmap.validate_options(profile["scanners"]["nmap"]["options"])
    nmap.scan("example.com", nmap_options)

    nuclei = NucleiScanner()
    nuclei_options = nuclei.validate_options(profile["scanners"]["nuclei"]["options"])
    nuclei.scan("https://example.com", nuclei_options)

    assert captured["nmap"]["timeout"] == 240
    assert captured["nmap"]["cmd"][-1] == "example.com"
    assert captured["nmap"]["cmd"].count("--max-rate") == 1
    assert captured["nmap"]["cmd"][captured["nmap"]["cmd"].index("--max-rate") + 1] == "20"
    assert captured["nuclei"]["timeout"] == 600
    assert captured["nuclei"]["cmd"].count("-rate-limit") == 1
    assert captured["nuclei"]["cmd"][captured["nuclei"]["cmd"].index("-rate-limit") + 1] == "5"
    assert captured["nuclei"]["cmd"][-6:] == ["-c", "2", "-bs", "1", "-retries", "0"]


def test_zap_report_enables_offline_import_with_polite_profile(monkeypatch, tmp_path, capsys):
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"
    report_path = tmp_path / "manual-zap-report.json"
    report_path.write_text(
        json.dumps(
            {
                "@version": "2.17.0",
                "site": [
                    {
                        "@name": "https://example.com",
                        "alerts": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--zap-report", str(report_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["report_path"] == str(report_path.resolve())
    assert captured["options"]["zap"]["timeout"] == 1200
    assert captured["options"]["zap"]["use_proxy"] is False
    assert SCAN_CONFIG_ENABLED_KEY not in captured["options"]["zap"]

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["zap"]["enabled"] is True
    assert payload["scanners"]["zap"]["options"]["report_path"] == str(report_path.resolve())


def test_zap_report_rejects_live_zap_execution_flags(monkeypatch, tmp_path, capsys):
    report_path = tmp_path / "manual-zap-report.json"
    report_path.write_text(json.dumps({"site": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "example.com",
                "--scanner", "zap",
                "--zap-report", str(report_path),
                "--zap-active-scan",
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "cannot be combined with ZAP execution options" in captured.err


def test_with_zap_enables_disabled_zap_from_polite_profile(monkeypatch, tmp_path, capsys):
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"
    plan_path = ROOT / "configs" / "examples" / "polite_zap_template.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--with-zap",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"] == {
        "timeout": 120,
        "af_plan_path": str(plan_path.resolve()),
        "use_proxy": False,
    }
    assert SCAN_CONFIG_ENABLED_KEY not in captured["options"]["zap"]

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["zap"]["enabled"] is True
    assert payload["scanners"]["zap"]["options"]["timeout"] == 120
    assert payload["scanners"]["zap"]["options"]["af_plan_path"] == str(plan_path.resolve())


def test_with_zap_is_conservative_without_a_scan_config(monkeypatch, tmp_path, capsys):
    plan_path = ROOT / "configs" / "examples" / "polite_zap_template.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--with-zap",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["timeout"] == 120
    assert captured["options"]["zap"]["af_plan_path"] == str(plan_path.resolve())
    assert captured["options"]["zap"]["use_proxy"] is False

    payload = json.loads(
        (tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8")
    )
    assert payload["scanners"]["zap"]["enabled"] is True
    assert payload["scanners"]["zap"]["options"]["timeout"] == 120
    assert payload["scanners"]["zap"]["options"]["af_plan_path"] == str(plan_path.resolve())


def test_with_zap_does_not_inherit_config_owned_active_plan(monkeypatch, tmp_path, capsys):
    unsafe_plan = tmp_path / "active-plan.yaml"
    unsafe_plan.write_text(
        "env:\n  contexts: []\njobs:\n  - type: activeScan\n    parameters: {}\n",
        encoding="utf-8",
    )
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        "version: 1\nscanners:\n  zap:\n    enabled: false\n    options:\n"
        "      active_scan: true\n      af_plan_path: active-plan.yaml\n      timeout: 900\n",
        encoding="utf-8",
    )
    polite_plan = ROOT / "configs" / "examples" / "polite_zap_template.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--with-zap",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["af_plan_path"] == str(polite_plan.resolve())
    assert captured["options"]["zap"]["timeout"] == 120
    assert "active_scan" not in captured["options"]["zap"]


def test_with_zap_rejects_custom_af_plan(monkeypatch, tmp_path, capsys):
    custom_plan = tmp_path / "custom.yaml"
    custom_plan.write_text("env: {}\njobs: []\n", encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "https://example.com",
                "--scanner", "all",
                "--with-zap",
                "--zap-af-plan", str(custom_plan),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "cannot be combined with --zap-af-plan" in captured.err


@pytest.mark.parametrize("scanner", ["zap", "nmap", "nuclei"])
def test_with_zap_requires_scanner_all(monkeypatch, tmp_path, capsys, scanner):
    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "https://example.com",
                "--scanner", scanner,
                "--with-zap",
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "--with-zap requires --scanner all" in captured.err


def test_with_zap_rejects_offline_report(monkeypatch, tmp_path, capsys):
    report_path = tmp_path / "manual-zap-report.json"
    report_path.write_text(json.dumps({"site": []}), encoding="utf-8")

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "https://example.com",
                "--scanner", "all",
                "--with-zap",
                "--zap-report", str(report_path),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "--with-zap cannot be combined with --zap-report" in captured.err


def test_with_zap_accepts_explicit_active_scan(monkeypatch, tmp_path, capsys):
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"
    plan_path = ROOT / "configs" / "examples" / "polite_zap_template.yaml"

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--with-zap",
            "--zap-active-scan",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["active_scan"] is True
    assert captured["options"]["zap"]["timeout"] == 120
    assert captured["options"]["zap"]["af_plan_path"] == str(plan_path.resolve())


def test_polite_zap_template_is_bounded_and_passive_by_default():
    config_path = ROOT / "configs" / "examples" / "polite_demo_config.yaml"
    plan_path = ROOT / "configs" / "examples" / "polite_zap_template.yaml"
    profile = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    plan = yaml.safe_load(plan_path.read_text(encoding="utf-8"))

    assert profile["scanners"]["zap"] == {
        "enabled": False,
        "options": {
            "timeout": 120,
            "af_plan_path": "polite_zap_template.yaml",
        },
    }

    jobs = plan["jobs"]
    job_types = [job["type"] for job in jobs]
    assert job_types == ["passiveScan-config", "spider", "passiveScan-wait", "report"]
    assert "activeScan" not in job_types
    assert "spiderAjax" not in job_types

    spider = next(job for job in jobs if job["type"] == "spider")["parameters"]
    assert spider["maxDuration"] == 2
    assert spider["maxDepth"] == 2
    assert spider["maxChildren"] == 10
    assert spider["threadCount"] == 1
    assert spider["postForm"] is False
    assert spider["processForm"] is False
    passive_wait = next(job for job in jobs if job["type"] == "passiveScan-wait")["parameters"]
    assert passive_wait["maxDuration"] == 2


def test_main_runs_advisory_ai_after_scoring_and_before_export(
    monkeypatch, tmp_path, capsys
):
    events = []
    original_sanitizer = main.sanitize_results_for_export

    def fake_score(results, context=None):
        events.append("score")
        return results

    class FakeAnalyzer:
        def __init__(self, config, *, database=None):
            assert config.enabled is True
            assert config.model_name == "demo-model"
            assert config.limit == 3

        def apply(self, results, *, asset_knowledge=None):
            events.append("ai")
            results["ai_analysis_summary"] = {
                "status": "completed",
                "model": "demo-model",
                "prompt_version": "finding-analysis-v1",
                "limit": 3,
                "selected_count": 0,
                "analyzed_count": 0,
                "cached_count": 0,
                "unavailable_count": 0,
                "skipped_limit_count": 0,
                "needs_review_count": 0,
                "redaction_count": 0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "latency_ms": 0.0,
                "estimated_cost_usd": None,
            }
            return results

    def tracking_sanitizer(results):
        events.append("sanitize")
        return original_sanitizer(results)

    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "test-secret")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "demo-model")
    monkeypatch.setattr(main, "score_vulnerabilities", fake_score)
    monkeypatch.setattr(main, "LLMFindingAnalyzer", FakeAnalyzer)
    monkeypatch.setattr(main, "sanitize_results_for_export", tracking_sanitizer)

    rc, _ = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--data-dir", str(tmp_path / "data"),
            "--no-dedupe",
            "--ai-analysis-limit", "3",
            "--no-report",
            "--json",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert events == ["score", "ai", "sanitize"]
    payload = json.loads((tmp_path / "run" / "normalized.json").read_text(encoding="utf-8"))
    assert payload["ai_analysis_summary"]["model"] == "demo-model"
    assert (tmp_path / "run" / "ai_analysis_metrics.json").is_file()


def test_main_reuses_confirmed_site_risk_context_for_scoring(
    monkeypatch, tmp_path, capsys
):
    captured_context = {}
    profile = {
        "description": "Confirmed public account portal.",
        "reviewer": "demo-user",
        "profile_revision": "b" * 64,
        "analysis_source": "llm",
        "business_processes": ["Account management"],
        "risk_context": {
            "asset_criticality": "high",
            "environment": "production",
            "sensitive_data": True,
            "requires_auth": True,
            "confidence": 0.91,
            "reason": "Confirmed account and sign-in workflows.",
            "evidence_ids": ["page-1"],
        },
        "profile_path": "/private/runtime/profile.md",
        "stale": False,
    }

    def fake_score(results, context=None):
        captured_context.update(context or {})
        return results

    monkeypatch.setattr(main, "load_site_okf_bundle", lambda *args, **kwargs: profile)
    monkeypatch.setattr(main, "score_vulnerabilities", fake_score)

    rc, _ = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--data-dir", str(tmp_path / "data"),
            "--no-dedupe",
            "--no-ai-analysis",
            "--no-report",
            "--json",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured_context["asset_criticality"] == "high"
    assert captured_context["environment"] == "production"
    assert captured_context["sensitive_data"] is True
    assert captured_context["requires_auth"] is True
    payload = json.loads((tmp_path / "run" / "normalized.json").read_text(encoding="utf-8"))
    assert payload["asset_knowledge"]["profile_revision"] == "b" * 64
    assert "profile_path" not in payload["asset_knowledge"]


def test_main_accepts_valid_json_scan_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.json"
    config_path.write_text(
        json.dumps(
            {
                "version": 1,
                "global": {
                    "http_mode": "http2",
                    "save_raw": False,
                },
                "scanners": {
                    "zap": {
                        "options": {
                            "timeout": 1500,
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["http_mode"] == "http2"
    assert captured["save_raw"] is False
    assert captured["options"]["zap"]["timeout"] == 1500


def test_main_rejects_unknown_scanner_name_in_scan_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  imaginary:
    enabled: true
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "example.com",
                "--scan-config", str(config_path),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "Unknown scanner name(s) in scan config: imaginary" in captured.err


def test_main_rejects_invalid_option_type_in_scan_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  nmap:
    options:
      ports:
        - 80
        - 443
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "example.com",
                "--scan-config", str(config_path),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "nmap option 'ports' must be a non-empty string" in captured.err


def test_main_rejects_forbidden_extra_args_in_scan_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  nuclei:
    options:
      extra_args:
        - -o
        - findings.json
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "https://example.com",
                "--scan-config", str(config_path),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "nuclei passthrough args cannot override reserved/internal flag '-o'" in captured.err


def test_config_disabled_scanner_cannot_be_selected_explicitly(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  zap:
    enabled: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "https://example.com",
                "--scanner", "zap",
                "--scan-config", str(config_path),
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "Scanner 'zap' is disabled by scan config and cannot be selected explicitly." in captured.err


def test_main_merges_scan_config_with_cli_precedence(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  scan_mode: manual
  report: false
scanners:
  nmap:
    options:
      ports: "80"
  zap:
    options:
      timeout: 1800
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--scan-mode", "automatic",
            "--ports", "443",
            "--zap-timeout", "2400",
            "--report",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["scan_mode"] == "automatic"
    assert captured["selected_ports"] == "443"
    assert captured["options"]["nmap"]["ports"] == "443"
    assert captured["options"]["zap"]["timeout"] == 2400
    assert (tmp_path / "run" / "report.html").exists()


def test_main_respects_explicit_report_disable_from_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  report: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["target"] == "example.com"
    assert not (tmp_path / "run" / "report.html").exists()

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["global"]["report"] is False


def test_main_cli_no_report_overrides_default(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--no-report",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["target"] == "example.com"
    assert not (tmp_path / "run" / "report.html").exists()

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["global"]["report"] is False


def test_main_no_risk_scoring_skips_runtime_scoring(monkeypatch, tmp_path, capsys):
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, _captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--no-risk-scoring",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert calls["score"] == 0
    payload = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert payload["global"]["risk_scoring"] is False


def test_main_no_risk_scoring_strips_stale_runtime_scoring_fields(monkeypatch, tmp_path, capsys):
    class StaleScoringOrchestrator(_ConfigCaptureOrchestrator):
        def run_all(self, target, options=None, normalize=True, save_raw=True):
            self.ensure_run_folder(target)
            self._captured["normalize"] = normalize
            finding = {
                "vulnerability_name": "Stale score",
                "severity": "high",
                "asset_id": "https://example.com",
                "description": "desc",
                "remediation": "fix",
                "risk_score": 99,
                "priority": "P0",
                "risk_factors": {"final_score": 99},
                "risk_rationale": "stale runtime value",
                "meta": {"scanner": "nuclei"},
            }
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-14T00:00:00Z",
                "scanners_run": ["nuclei"],
                "all_findings": [finding],
                "findings_by_scanner": {"nuclei": [finding]},
                "errors": [],
                "summary": {
                    "total_findings": 1,
                    "by_severity": {"high": 1},
                    "by_scanner": {"nuclei": 1},
                    "by_priority": {"P0": 1},
                },
            }

    captured: dict = {}
    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: StaleScoringOrchestrator(tmp_path, captured),
    )
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: pytest.fail("score_vulnerabilities should not run"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--no-risk-scoring",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )

    rc = main.main()
    capsys.readouterr()
    normalized = json.loads((tmp_path / "run" / "normalized.json").read_text(encoding="utf-8"))

    assert rc == 0
    finding = normalized["all_findings"][0]
    for field in ("risk_score", "priority", "risk_factors", "risk_rationale"):
        assert field not in finding
    assert "by_priority" not in normalized["summary"]


def test_main_no_score_alias_skips_runtime_scoring(monkeypatch, tmp_path, capsys):
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, _captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--no-score",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert calls["score"] == 0


def test_main_config_risk_scoring_false_skips_runtime_scoring(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  risk_scoring: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, _captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert calls["score"] == 0


def test_main_cli_risk_scoring_overrides_config_false(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  risk_scoring: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, _captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--risk-scoring",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert calls["score"] == 1
    payload = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert payload["global"]["risk_scoring"] is True


def test_main_cli_no_risk_scoring_overrides_config_true(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  risk_scoring: true
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, _captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--no-risk-scoring",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert calls["score"] == 0
    payload = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert payload["global"]["risk_scoring"] is False


def test_main_cli_normalize_overrides_config_false(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  normalize: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--normalize",
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-risk-scoring",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["normalize"] is True
    payload = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert payload["global"]["normalize"] is True


def test_main_normalize_false_runs_raw_mode_and_saves_effective_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  normalize: false
        """.strip()
        + "\n",
        encoding="utf-8",
    )
    calls = {"score": 0}
    monkeypatch.setattr(
        main,
        "score_vulnerabilities",
        lambda results, context=None: calls.__setitem__("score", calls["score"] + 1) or results,
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["normalize"] is False
    assert calls["score"] == 0
    assert (tmp_path / "run" / "scan_results.json").exists()
    assert not (tmp_path / "run" / "report.html").exists()
    payload = json.loads((tmp_path / "run" / "effective_scan_config.json").read_text(encoding="utf-8"))
    assert payload["global"]["normalize"] is False
    assert payload["global"]["risk_scoring"] is False


def test_main_no_normalize_passes_false_to_single_scanner(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "nmap",
            "--no-normalize",
            "--no-report",
            "--data-dir", str(tmp_path / "data"),
            "--json",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["scanner"] == "nmap"
    assert captured["normalize"] is False


@pytest.mark.parametrize(
    ("extra_args", "expected_error"),
    [
        (
            ["--report"],
            "HTML report requires normalized findings. Remove --no-normalize or add --no-report.",
        ),
        (
            ["--compare"],
            "Comparison requires normalized findings. Remove --no-normalize or remove --compare.",
        ),
        (
            ["--defectdojo-export"],
            "Merged DefectDojo export requires normalized findings. Use raw-per-scan upload or enable normalization.",
        ),
        (
            ["--defectdojo-upload-mode", "merged"],
            "Merged DefectDojo export requires normalized findings. Use raw-per-scan upload or enable normalization.",
        ),
    ],
)
def test_main_no_normalize_rejects_normalized_only_outputs(
    monkeypatch,
    tmp_path,
    capsys,
    extra_args,
    expected_error,
):
    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "example.com",
                "--scanner", "all",
                "--no-normalize",
                "--data-dir", str(tmp_path / "data"),
                "--json",
                *extra_args,
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert expected_error in captured.err


def test_main_no_normalize_allows_raw_per_scan_defectdojo_upload(monkeypatch, tmp_path, capsys):
    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--no-normalize",
            "--no-report",
            "--defectdojo-upload",
            "--defectdojo-upload-mode", "raw-per-scan",
            "--defectdojo-url", "https://dojo.example",
            "--defectdojo-api-token", "secret-token",
            "--defectdojo-product-type", "Applications",
            "--defectdojo-product", "Checkout",
            "--defectdojo-engagement", "Nightly",
            "--data-dir", str(tmp_path / "data"),
            "--json",
        ],
    )
    output = capsys.readouterr()

    assert rc == 0
    assert captured["normalize"] is False
    assert "DefectDojo raw upload skipped" in output.err


def test_main_rejects_non_boolean_risk_scoring_in_scan_config(monkeypatch, tmp_path, capsys):
    config_path = tmp_path / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
global:
  risk_scoring: "false"
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as excinfo:
        _run_main_with_fake_orchestrator(
            monkeypatch,
            tmp_path,
            [
                "main.py",
                "--target", "example.com",
                "--scanner", "all",
                "--scan-config", str(config_path),
                "--data-dir", str(tmp_path / "data"),
                "--json",
            ],
        )

    captured = capsys.readouterr()
    assert excinfo.value.code == 2
    assert "global.risk_scoring must be a boolean" in captured.err


def test_main_resolves_config_relative_path_options(monkeypatch, tmp_path, capsys):
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    plan_path = tmp_path / "zap-template.yaml"
    plan_path.write_text("env: {}\n", encoding="utf-8")
    config_path = config_dir / "scan-config.yaml"
    config_path.write_text(
        """
version: 1
scanners:
  zap:
    options:
      af_plan_path: ../zap-template.yaml
        """.strip()
        + "\n",
        encoding="utf-8",
    )

    rc, captured = _run_main_with_fake_orchestrator(
        monkeypatch,
        tmp_path,
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "all",
            "--scan-config", str(config_path),
            "--data-dir", str(tmp_path / "data"),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["options"]["zap"]["af_plan_path"] == str(plan_path.resolve())

    effective_path = tmp_path / "run" / "effective_scan_config.json"
    payload = json.loads(effective_path.read_text(encoding="utf-8"))
    assert payload["scanners"]["zap"]["options"]["af_plan_path"] == str(plan_path.resolve())


def test_effective_scan_config_is_saved_on_real_skip_path(monkeypatch, tmp_path, capsys):
    data_dir = tmp_path / "data"
    monkeypatch.setattr(
        main,
        "generate_html_report",
        lambda results, path: path.write_text("<html></html>", encoding="utf-8"),
    )
    monkeypatch.setattr(
        "orchestrator.probe_http_transport",
        lambda target, timeout=8: {
            "input_target": target,
            "normalized_target": "https://example.com",
            "selected_scheme": "https",
            "reachable": False,
            "supports_http2": False,
            "supports_http1_1": False,
            "http2_only": False,
            "probe_method": "mocked-unreachable",
            "transport_detected": "unreachable",
            "reason": "mocked probe failure",
        },
    )
    monkeypatch.setattr(NiktoScanner, "is_available", lambda self: True)
    monkeypatch.setattr(
        NiktoScanner,
        "scan",
        lambda self, target, options=None: pytest.fail("Nikto scan() should not run when routing skips the target"),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "https://example.com",
            "--scanner", "nikto",
            "--data-dir", str(data_dir),
            "--json",
            "--no-dedupe",
            "--no-score",
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    effective_configs = sorted(data_dir.glob("**/effective_scan_config.json"))
    assert len(effective_configs) == 1
    payload = json.loads(effective_configs[0].read_text(encoding="utf-8"))
    assert payload["requested_scanner"] == "nikto"
    assert payload["scanners"]["nikto"]["enabled"] is True


def test_orchestrator_skips_disabled_scanners_in_run_all(tmp_path):
    class RecordingScanner(BaseScanner):
        def __init__(self, name: str):
            super().__init__(name)
            self.calls = []

        def is_available(self) -> bool:
            return True

        def scan(self, target: str, options=None):
            self.calls.append({"target": target, "options": dict(options or {})})
            return {
                "scanner": self.name,
                "target": target,
                "timestamp": "2026-04-14T00:00:00Z",
                "command": self.name,
                "raw_output": "",
                "stderr": "",
                "exit_code": 0,
                "findings": [],
            }

        def normalize(self, raw_results):
            return []

    disabled = RecordingScanner("disabled")
    enabled = RecordingScanner("enabled")
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.register_scanner("disabled", disabled)
    orchestrator.register_scanner("enabled", enabled)

    results = orchestrator.run_all(
        "example.com",
        options={
            "disabled": {SCAN_CONFIG_ENABLED_KEY: False},
            "enabled": {},
        },
        save_raw=False,
    )

    assert disabled.calls == []
    assert len(enabled.calls) == 1
    assert results["scanners_run"] == ["enabled"]


def test_multi_scanner_parser_and_orchestrator_selection(monkeypatch, tmp_path):
    assert main._parse_scanner_subset("nmap,nuclei,nmap") == ["nmap", "nuclei"]
    with pytest.raises(ValueError, match="Unknown scanner"):
        main._parse_scanner_subset("nmap,unknown")

    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    orchestrator.scanners = {name: object() for name in ("nmap", "nuclei", "zap")}
    captured = {}

    def discovery(target, options, normalize, save_raw):
        captured.update(target=target, options=options, normalize=normalize, save_raw=save_raw)
        return {"ok": True}

    monkeypatch.setattr(orchestrator, "_run_all_discovery_mode", discovery)
    result = orchestrator.run_selected(
        "https://example.com/",
        ["nmap", "nuclei"],
        options={"nuclei": {"severity": ["high"]}},
        save_raw=False,
    )

    assert result == {"ok": True}
    assert captured["options"]["nuclei"]["severity"] == ["high"]
    assert captured["options"]["zap"][SCAN_CONFIG_ENABLED_KEY] is False


@pytest.mark.parametrize(
    ("scanner", "options"),
    [
        (NmapScanner(), {"extra_args": ["-oX", "-"]}),
        (NucleiScanner(), {"extra_args": ["-o", "findings.json"]}),
        (WapitiScanner(), {"extra_args": ["-o", "findings.json"]}),
        (NiktoScanner(), {"extra_args": ["-output", "findings.json"]}),
        (ZapScanner(), {"extra_args": ["-cmd"]}),
    ],
)
def test_scanner_validation_rejects_reserved_internal_passthrough_args(scanner, options):
    with pytest.raises(ValueError):
        scanner.validate_options(options)
