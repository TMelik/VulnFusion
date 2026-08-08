import argparse
import json
import os
import sys
from pathlib import Path

import pytest

import main
from scanners.base import BaseScanner
from utils.schema import SCHEMA_VERSION


@pytest.fixture(autouse=True)
def _isolate_default_config_lookup(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    for name in list(os.environ):
        if name.startswith("VULN_MANAGER_DEFECTDOJO_"):
            monkeypatch.delenv(name, raising=False)


def _finding():
    return {
        "vulnerability_name": "SQL Injection",
        "severity": "high",
        "asset_id": "https://example.com/search?q=1",
        "description": "Scanner observed injectable input handling.",
        "remediation": "Use parameterized queries.",
        "meta": {
            "timestamp": "2026-04-21T12:30:00Z",
            "cwe": "CWE-89",
            "cve_id": "CVE-2026-0001",
            "host": "example.com",
            "port": 443,
            "path": "/search",
            "scheme": "https",
            "parameter": "q",
            "method": "GET",
            "query_keys": ["q"],
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
        },
        "found_by": ["zap"],
        "source_findings": [{"references": ["https://scanner.example/zap"]}],
    }


def _minimal_results(target: str) -> dict:
    finding = _finding()
    return {
        "schema_version": SCHEMA_VERSION,
        "target": target,
        "timestamp": "2026-04-14T00:00:00Z",
        "scanners_run": ["nmap"],
        "all_findings": [finding],
        "findings_by_scanner": {"nmap": [finding]},
        "errors": [],
        "summary": {
            "total_findings": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "by_scanner": {"nmap": 1},
        },
    }


class _AvailableScanner(BaseScanner):
    def __init__(self, name: str):
        super().__init__(name)

    def is_available(self) -> bool:
        return True

    def scan(self, target: str, options=None):
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


class _FakeOrchestrator:
    def __init__(self, run_root: Path):
        self.scanners = {"nmap": _AvailableScanner("nmap")}
        self.current_run_folder = None
        self._run_root = run_root

    def ensure_run_folder(self, target, timestamp=None):
        run_folder = self._run_root / "run"
        run_folder.mkdir(parents=True, exist_ok=True)
        (run_folder / "raw").mkdir(parents=True, exist_ok=True)
        self.current_run_folder = run_folder
        return run_folder

    def set_http_mode(self, value):
        self.http_mode = value

    def set_scan_mode(self, value):
        self.scan_mode = value

    def set_selected_ports(self, value):
        self.selected_ports = value

    def set_http2_adapter_mode(self, value):
        self.http2_adapter_mode = value

    @staticmethod
    def _count_by_severity(findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = str(finding.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
        return counts

    def run_all(self, target, options=None, normalize=True, save_raw=True):
        self.ensure_run_folder(target)
        return _minimal_results(target)

    def run_scanner(self, scanner_name, target, options=None, normalize=True, save_raw=True):
        self.ensure_run_folder(target)
        return {
            "scanner": scanner_name,
            "target": target,
            "timestamp": "2026-04-14T00:00:00Z",
            "command": scanner_name,
            "raw_output": "",
            "stderr": "",
            "exit_code": 0,
            "findings": [_finding()],
        }

    def save_results(self, results, output=None):
        if self.current_run_folder is None:
            self.ensure_run_folder(results.get("target", "example.com"))
        path = self.current_run_folder / "normalized.json"
        path.write_text(json.dumps(results), encoding="utf-8")
        return path


class _RawUploadOrchestrator(_FakeOrchestrator):
    def __init__(self, run_root: Path, raw_uploads: list[dict]):
        super().__init__(run_root)
        self._raw_uploads = raw_uploads

    def run_all(self, target, options=None, normalize=True, save_raw=True):
        self.ensure_run_folder(target)
        prepared_uploads = []
        for entry in self._raw_uploads:
            prepared = dict(entry)
            artifact_name = prepared.pop("_artifact_name", None)
            artifact_text = prepared.pop("_artifact_text", "")
            if artifact_name:
                artifact_path = self.current_run_folder / "raw" / artifact_name
                artifact_path.write_text(artifact_text, encoding="utf-8")
                prepared["raw_artifact_path"] = str(artifact_path)
            prepared_uploads.append(prepared)

        results = _minimal_results(target)
        results["defectdojo_raw_uploads"] = prepared_uploads
        return results


class _SingleScannerRawUploadOrchestrator(_FakeOrchestrator):
    def __init__(
        self,
        run_root: Path,
        *,
        scanner_name: str = "nmap",
        artifact_name: str = "nmap.xml",
        artifact_text: str = '<?xml version="1.0"?><nmaprun></nmaprun>\n',
        artifact_format: str = "xml",
    ):
        super().__init__(run_root)
        self.scanners = {scanner_name: _AvailableScanner(scanner_name)}
        self._scanner_name = scanner_name
        self._artifact_name = artifact_name
        self._artifact_text = artifact_text
        self._artifact_format = artifact_format

    def run_scanner(self, scanner_name, target, options=None, normalize=True, save_raw=True):
        self.ensure_run_folder(target)
        artifact_path = self.current_run_folder / "raw" / self._artifact_name
        artifact_path.write_text(self._artifact_text, encoding="utf-8")
        return {
            "scanner": scanner_name,
            "target": target,
            "timestamp": "2026-04-14T00:00:00Z",
            "command": scanner_name,
            "raw_output": self._artifact_text,
            "stderr": "",
            "exit_code": 0,
            "findings": [_finding()],
            "defectdojo_raw_artifact": {
                "path": str(artifact_path),
                "artifact_format": self._artifact_format,
                "native": True,
                "role": "defectdojo-native-parser-input",
                "source": "test-fixture",
            },
        }


def _run_main(monkeypatch, tmp_path: Path, argv: list[str]) -> int:
    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _FakeOrchestrator(tmp_path),
    )
    monkeypatch.setattr(
        main,
        "generate_html_report",
        lambda results, path: path.write_text("<html></html>", encoding="utf-8"),
    )
    monkeypatch.setattr(sys, "argv", argv)
    return main.main()


def _write_defectdojo_config(
    tmp_path: Path,
    *,
    enabled: bool = True,
    upload_mode: str = "raw-per-scan",
    scan_types: dict[str, str] | None = None,
    test_titles: dict[str, str] | None = None,
) -> Path:
    scan_types = scan_types or {
        "nmap": "Nmap Scan",
        "nuclei": "Nuclei Scan",
        "nikto": "Nikto Scan",
        "zap": "ZAP Scan",
        "wapiti": "Wapiti Scan",
    }
    test_titles = test_titles or {
        scanner: f"{scanner} | {{target}}"
        for scanner in scan_types
    }
    path = tmp_path / "defectdojo.config"
    path.write_text(
        "\n".join(
            [
                "[defectdojo]",
                f"enabled = {'true' if enabled else 'false'}",
                "base_url = https://dojo.config",
                "api_token_env = DD_TOKEN",
                "product_type = Config Product Type",
                "product = Config Product",
                "engagement = Config Engagement",
                f"upload_mode = {upload_mode}",
                "auto_create_context = true",
                "minimum_severity = Low",
                "active = true",
                "verified = true",
                "verify_ssl = false",
                "timeout_seconds = 60",
                "",
                "[defectdojo.scan_types]",
                *[f"{scanner} = {scan_type}" for scanner, scan_type in scan_types.items()],
                "",
                "[defectdojo.test_titles]",
                *[f"{scanner} = {template}" for scanner, template in test_titles.items()],
                "",
                "[defectdojo.artifacts]",
                "nmap = xml",
                "nuclei = native_jsonl,jsonl,json",
                "nikto = json,xml",
                "zap = xml",
                "wapiti = xml",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return path


def _defectdojo_args(**overrides) -> argparse.Namespace:
    values = {
        "defectdojo_upload": False,
        "no_defectdojo_upload": False,
        "defectdojo_upload_mode": None,
        "defectdojo_url": None,
        "defectdojo_api_token": None,
        "defectdojo_product_type": None,
        "defectdojo_product_type_id": None,
        "defectdojo_product": None,
        "defectdojo_product_id": None,
        "defectdojo_engagement": None,
        "defectdojo_test_id": None,
        "defectdojo_engagement_id": None,
        "defectdojo_test_title": None,
        "defectdojo_minimum_severity": None,
        "defectdojo_active": None,
        "defectdojo_verified": None,
        "defectdojo_no_auto_create_context": False,
        "defectdojo_auto_create_context": False,
        "defectdojo_do_not_reactivate": False,
        "defectdojo_close_old_findings": False,
        "defectdojo_environment": None,
        "defectdojo_background_import": False,
        "defectdojo_strict_names": False,
        "defectdojo_verify_ssl": False,
        "defectdojo_insecure": False,
        "defectdojo_timeout_seconds": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def _defectdojo_precedence_config(tmp_path: Path) -> main.DefectDojoFileConfig:
    config_path = tmp_path / "precedence.config"
    config_path.write_text(
        "\n".join(
            [
                "[defectdojo]",
                "enabled = true",
                "base_url = https://dojo.config",
                "api_token_env = DD_TOKEN",
                "product_type = Config Product Type",
                "product_type_id = 11",
                "product = Config Product",
                "product_id = 22",
                "engagement = Config Engagement",
                "engagement_id = 33",
                "test_id = 44",
                "upload_mode = raw-per-scan",
                "minimum_severity = Low",
                "active = false",
                "verified = false",
                "auto_create_context = false",
                "verify_ssl = false",
                "timeout_seconds = 60",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return main.load_defectdojo_config(config_path)


def test_main_help_lists_defectdojo_flags(monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["main.py", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        main.main()

    output = capsys.readouterr()
    assert exc_info.value.code == 0
    assert "--defectdojo-export" in output.out
    assert "--defectdojo-upload" in output.out
    assert "--defectdojo-url" in output.out
    assert "--defectdojo-test-id" in output.out
    assert "--defectdojo-engagement-id" in output.out
    assert "--defectdojo-background-import" in output.out
    assert "--defectdojo-strict-names" in output.out
    assert "--defectdojo-upload-mode" in output.out
    assert "--defectdojo-scan-type-nuclei" in output.out
    assert "--config" in output.out
    assert "--no-defectdojo-upload" in output.out
    assert "--defectdojo-verify-ssl" in output.out
    assert "--defectdojo-timeout-seconds" in output.out


def test_defectdojo_config_only_uses_config_values(monkeypatch, tmp_path):
    file_config = _defectdojo_precedence_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")

    config = main._resolve_defectdojo_config(_defectdojo_args(), file_config)

    assert main._resolve_defectdojo_upload_requested(_defectdojo_args(), file_config) is True
    assert main._resolve_defectdojo_upload_mode(_defectdojo_args(), file_config) == main.DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN
    assert config.base_url == "https://dojo.config"
    assert config.normalized_api_token == "config-token"
    assert config.product_type_name == "Config Product Type"
    assert config.product_type_id == 11
    assert config.product_name == "Config Product"
    assert config.product_id == 22
    assert config.engagement_name == "Config Engagement"
    assert config.engagement_id == 33
    assert config.test_id == 44
    assert config.minimum_severity == "Low"
    assert config.active is False
    assert config.verified is False
    assert config.auto_create_context is False
    assert config.verify_tls is False
    assert config.timeout_seconds == 60.0


def test_cli_defectdojo_overrides_config_for_all_merge_fields(monkeypatch, tmp_path):
    file_config = _defectdojo_precedence_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    args = _defectdojo_args(
        defectdojo_upload=True,
        defectdojo_upload_mode="generic",
        defectdojo_url="https://dojo.cli",
        defectdojo_api_token="cli-token",
        defectdojo_product_type="CLI Product Type",
        defectdojo_product_type_id=111,
        defectdojo_product="CLI Product",
        defectdojo_product_id=222,
        defectdojo_engagement="CLI Engagement",
        defectdojo_engagement_id=333,
        defectdojo_test_id=444,
        defectdojo_minimum_severity="Critical",
        defectdojo_active=True,
        defectdojo_verified=True,
        defectdojo_auto_create_context=True,
        defectdojo_verify_ssl=True,
        defectdojo_timeout_seconds=12.5,
    )

    config = main._resolve_defectdojo_config(args, file_config)

    assert main._resolve_defectdojo_upload_requested(args, file_config) is True
    assert main._resolve_defectdojo_upload_mode(args, file_config) == main.DEFECTDOJO_UPLOAD_MODE_MERGED
    assert config.base_url == "https://dojo.cli"
    assert config.normalized_api_token == "cli-token"
    assert config.product_type_name == "CLI Product Type"
    assert config.product_type_id == 111
    assert config.product_name == "CLI Product"
    assert config.product_id == 222
    assert config.engagement_name == "CLI Engagement"
    assert config.engagement_id == 333
    assert config.test_id == 444
    assert config.minimum_severity == "Critical"
    assert config.active is True
    assert config.verified is True
    assert config.auto_create_context is True
    assert config.verify_tls is True
    assert config.timeout_seconds == 12.5


def test_cli_defectdojo_names_and_engagement_id_suppress_lower_priority_ids(monkeypatch, tmp_path):
    file_config = _defectdojo_precedence_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    args = _defectdojo_args(
        defectdojo_product_type="CLI Product Type",
        defectdojo_product="CLI Product",
        defectdojo_engagement_id=333,
    )

    config = main._resolve_defectdojo_config(args, file_config)

    assert config.product_type_name == "CLI Product Type"
    assert config.product_type_id is None
    assert config.product_name == "CLI Product"
    assert config.product_id is None
    assert config.engagement_id == 333
    assert config.test_id is None


def test_cli_no_defectdojo_upload_overrides_enabled_config(tmp_path):
    file_config = _defectdojo_precedence_config(tmp_path)

    assert main._resolve_defectdojo_upload_requested(
        _defectdojo_args(no_defectdojo_upload=True),
        file_config,
    ) is False


def test_env_defectdojo_values_override_config(monkeypatch, tmp_path):
    file_config = _defectdojo_precedence_config(tmp_path)
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_URL", "https://dojo.env")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_PRODUCT", "Env Product")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_ACTIVE", "true")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_VERIFY_TLS", "true")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_TIMEOUT_SECONDS", "45")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_UPLOAD_MODE", "merged")

    config = main._resolve_defectdojo_config(_defectdojo_args(), file_config)

    assert main._resolve_defectdojo_upload_mode(_defectdojo_args(), file_config) == main.DEFECTDOJO_UPLOAD_MODE_MERGED
    assert config.base_url == "https://dojo.env"
    assert config.product_name == "Env Product"
    assert config.active is True
    assert config.verify_tls is True
    assert config.timeout_seconds == 45.0


def test_no_defectdojo_flags_keep_behavior_unchanged(monkeypatch, tmp_path, capsys):
    called = {"upload": 0}
    monkeypatch.setattr(main, "upload_defectdojo_report", lambda *args, **kwargs: called.__setitem__("upload", called["upload"] + 1))

    rc = _run_main(
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
    assert called["upload"] == 0
    assert (tmp_path / "run" / "normalized.json").exists()
    assert (tmp_path / "run" / "report.html").exists()
    assert not (tmp_path / "run" / "defectdojo_generic.json").exists()


def test_config_enabled_true_enables_raw_defectdojo_upload(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    raw_uploads = [
        {
            "scanner": "nmap",
            "execution_key": "nmap",
            "target": "ga.map.cyberhayq.am",
            "_artifact_name": "nmap.xml",
            "_artifact_text": "<nmaprun></nmaprun>\n",
            "artifact_format": "xml",
            "native": True,
            "safe_importable": True,
        }
    ]
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "base_url": config.base_url,
                "api_token": config.normalized_api_token,
                "product_type": config.product_type_name,
                "product": config.product_name,
                "engagement": config.engagement_name,
                "verify_tls": config.verify_tls,
                "timeout_seconds": config.timeout_seconds,
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "ga.map.cyberhayq.am",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "base_url": "https://dojo.config",
            "api_token": "config-token",
            "product_type": "Config Product Type",
            "product": "Config Product",
            "engagement": "Config Engagement",
            "verify_tls": False,
            "timeout_seconds": 60.0,
            "scan_type": "Nmap Scan",
            "test_title": "nmap | ga.map.cyberhayq.am",
        }
    ]
    assert f"[*] Loaded config: {config_path}" in output.out
    assert "[*] DefectDojo enabled from config" in output.out
    assert "[*] DefectDojo upload mode: raw-per-scan" in output.out
    assert "[*] Scanner nmap uses scan type: Nmap Scan" in output.out
    assert "[*] Generated test title: nmap | ga.map.cyberhayq.am" in output.out


def test_config_enabled_false_does_not_upload_without_cli(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path, enabled=False)
    called = {"raw_upload": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "nmap",
                    "execution_key": "nmap",
                    "target": "example.com",
                    "_artifact_name": "nmap.xml",
                    "_artifact_text": "<nmaprun></nmaprun>\n",
                    "artifact_format": "xml",
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(main, "upload_defectdojo_raw_artifact", lambda *args, **kwargs: called.__setitem__("raw_upload", called["raw_upload"] + 1))
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert called["raw_upload"] == 0


def test_config_enabled_false_uploads_when_cli_explicitly_enables(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path, enabled=False)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    captured: list[str] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "nmap",
                    "execution_key": "nmap",
                    "target": "example.com",
                    "_artifact_name": "nmap.xml",
                    "_artifact_text": "<nmaprun></nmaprun>\n",
                    "artifact_format": "xml",
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(test_title) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == ["nmap | example.com"]


def test_cli_defectdojo_values_override_config(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(
        tmp_path,
        scan_types={"nmap": "Wrong Config Scan"},
        test_titles={"nmap": "config | {target}"},
    )
    monkeypatch.setenv("DD_TOKEN", "config-token")
    captured: dict = {}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "nmap",
                    "execution_key": "nmap",
                    "target": "example.com",
                    "_artifact_name": "nmap.xml",
                    "_artifact_text": "<nmaprun></nmaprun>\n",
                    "artifact_format": "xml",
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.update(
            {
                "base_url": config.base_url,
                "product": config.product_name,
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
        "--defectdojo-url", "https://dojo.cli",
        "--defectdojo-product", "CLI Product",
        "--defectdojo-scan-type-nmap", "CLI Nmap Scan",
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == {
        "base_url": "https://dojo.cli",
        "product": "CLI Product",
        "scan_type": "CLI Nmap Scan",
        "test_title": "config | example.com",
    }


def test_config_raw_per_scan_uploads_all_scanners_with_config_mappings(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    target = "ga.map.cyberhayq.am"
    raw_uploads = [
        ("nmap", "nmap.xml", "<nmaprun></nmaprun>\n", "xml"),
        ("nuclei", "nuclei.jsonl", "{}\n", "jsonl"),
        ("nikto", "nikto.json", "{}\n", "json"),
        ("zap", "zap.xml", "<OWASPZAPReport></OWASPZAPReport>\n", "xml"),
        ("wapiti", "wapiti.xml", "<report></report>\n", "xml"),
    ]
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": scanner,
                    "execution_key": scanner,
                    "target": target,
                    "_artifact_name": artifact_name,
                    "_artifact_text": artifact_text,
                    "artifact_format": artifact_format,
                    "native": True,
                    "safe_importable": True,
                }
                for scanner, artifact_name, artifact_text, artifact_format in raw_uploads
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {"scan_type": scan_type, "test_title": test_title}
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [
        {"scan_type": "Nmap Scan", "test_title": f"nmap | {target}"},
        {"scan_type": "Nuclei Scan", "test_title": f"nuclei | {target}"},
        {"scan_type": "Nikto Scan", "test_title": f"nikto | {target}"},
        {"scan_type": "ZAP Scan", "test_title": f"zap | {target}"},
        {"scan_type": "Wapiti Scan", "test_title": f"wapiti | {target}"},
    ]


@pytest.mark.parametrize(
    ("scanner", "artifact_name", "artifact_text", "artifact_format"),
    [
        ("nuclei", "nuclei.jsonl", "{}\n", "jsonl"),
        ("nikto", "nikto.json", "{}\n", "json"),
        ("zap", "zap.xml", "<OWASPZAPReport></OWASPZAPReport>\n", "xml"),
        ("wapiti", "wapiti.xml", "<report></report>\n", "xml"),
    ],
)
def test_raw_per_scan_titles_use_original_target_by_default(
    monkeypatch,
    tmp_path,
    capsys,
    scanner,
    artifact_name,
    artifact_text,
    artifact_format,
):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    original_target = "ga.map.cyberhayq.am"
    execution_target = "http://ga.map.cyberhayq.am:80"
    captured: list[str] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": scanner,
                    "execution_key": scanner,
                    "target": execution_target,
                    "_artifact_name": artifact_name,
                    "_artifact_text": artifact_text,
                    "artifact_format": artifact_format,
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(test_title) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", original_target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [f"{scanner} | {original_target}"]


def test_raw_per_scan_execution_target_placeholder_remains_available(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(
        tmp_path,
        test_titles={"zap": "zap | {execution_target}"},
    )
    monkeypatch.setenv("DD_TOKEN", "config-token")
    original_target = "ga.map.cyberhayq.am"
    execution_target = "http://ga.map.cyberhayq.am:80"
    captured: list[str] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "zap",
                    "execution_key": "zap",
                    "target": execution_target,
                    "_artifact_name": "zap.xml",
                    "_artifact_text": "<OWASPZAPReport></OWASPZAPReport>\n",
                    "artifact_format": "xml",
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(test_title) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", original_target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [f"zap | {execution_target}"]


@pytest.mark.parametrize("scanner", ["zap", "wapiti"])
def test_raw_upload_selects_xml_when_json_and_xml_are_available(monkeypatch, tmp_path, capsys, scanner):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    target = "ga.map.cyberhayq.am"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    json_path = artifact_dir / f"{scanner}.json"
    xml_path = artifact_dir / f"{scanner}.xml"
    json_path.write_text("{}\n", encoding="utf-8")
    xml_path.write_text("<report></report>\n", encoding="utf-8")
    captured: list[Path] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": scanner,
                    "execution_key": scanner,
                    "target": f"http://{target}:80",
                    "raw_artifact_path": str(json_path),
                    "artifact_format": "json",
                    "native": True,
                    "safe_importable": True,
                    "raw_artifacts": [
                        {"path": str(json_path), "artifact_format": "json", "native": True},
                        {"path": str(xml_path), "artifact_format": "xml", "native": True},
                    ],
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(Path(artifact_path)) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [xml_path]


def test_config_wapiti_xml_uploads_xml_artifact_and_does_not_skip(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    target = "ga.map.cyberhayq.am"
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir()
    json_path = artifact_dir / "wapiti.json"
    xml_path = artifact_dir / "wapiti.xml"
    json_path.write_text('{"vulnerabilities":{}}\n', encoding="utf-8")
    xml_path.write_text("<report type=\"security\"></report>\n", encoding="utf-8")
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "wapiti",
                    "execution_key": "wapiti",
                    "target": f"http://{target}:80",
                    "raw_artifact_path": str(xml_path),
                    "artifact_format": "xml",
                    "native": True,
                    "safe_importable": True,
                    "raw_artifacts": [
                        {"path": str(json_path), "artifact_format": "json", "native": True},
                        {"path": str(xml_path), "artifact_format": "xml", "native": True},
                    ],
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "artifact_path": Path(artifact_path),
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "artifact_path": xml_path,
            "scan_type": "Wapiti Scan",
            "test_title": f"wapiti | {target}",
        }
    ]
    assert "[*] Scanner wapiti uses scan type: Wapiti Scan" in output.out
    assert f"[*] Generated test title: wapiti | {target}" in output.out
    assert "[+] DefectDojo raw upload completed: wapiti -> Wapiti Scan" in output.out
    assert "DefectDojo raw upload skipped: wapiti" not in output.err


def test_config_wapiti_xml_skips_when_only_json_exists(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    target = "ga.map.cyberhayq.am"
    json_path = tmp_path / "wapiti.json"
    json_path.write_text('{"vulnerabilities":{}}\n', encoding="utf-8")
    calls = {"count": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "wapiti",
                    "execution_key": "wapiti",
                    "target": f"http://{target}:80",
                    "raw_artifact_path": str(json_path),
                    "artifact_format": "json",
                    "native": True,
                    "safe_importable": True,
                    "raw_artifacts": [
                        {"path": str(json_path), "artifact_format": "json", "native": True},
                    ],
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda *args, **kwargs: calls.__setitem__("count", calls["count"] + 1),
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert calls["count"] == 0
    assert (
        "Wapiti XML artifact missing; cannot upload to DefectDojo Wapiti Scan."
        in output.err
    )
    assert "available native formats: json" not in output.err


def test_wapiti_json_requires_explicit_json_artifact_preference(tmp_path):
    json_path = tmp_path / "wapiti.json"
    json_path.write_text('{"vulnerabilities":{}}\n', encoding="utf-8")
    entry = {
        "scanner": "wapiti",
        "execution_key": "wapiti",
        "target": "https://example.com",
        "raw_artifacts": [
            {"path": str(json_path), "artifact_format": "json", "native": True},
        ],
    }

    selected, error = main._select_raw_upload_artifact(
        entry,
        scanner_name="wapiti",
        preferred_formats=("json",),
    )

    assert error is None
    assert Path(selected["raw_artifact_path"]) == json_path


def test_raw_upload_skips_when_only_unsupported_format_exists(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path)
    monkeypatch.setenv("DD_TOKEN", "config-token")
    target = "ga.map.cyberhayq.am"
    json_path = tmp_path / "zap.json"
    json_path.write_text('{"site":[]}\n', encoding="utf-8")
    calls = {"count": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "zap",
                    "execution_key": "zap",
                    "target": f"http://{target}:80",
                    "raw_artifact_path": str(json_path),
                    "artifact_format": "json",
                    "native": True,
                    "safe_importable": True,
                    "raw_artifacts": [
                        {"path": str(json_path), "artifact_format": "json", "native": True},
                    ],
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda *args, **kwargs: calls.__setitem__("count", calls["count"] + 1),
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert calls["count"] == 0
    assert "no scanner-native raw artifact matches configured formats" in output.err
    assert "configured formats: xml" in output.err


def test_config_missing_scan_type_mapping_fails_for_scanner(monkeypatch, tmp_path, capsys):
    config_path = _write_defectdojo_config(tmp_path, scan_types={"nmap": "Nmap Scan"})
    monkeypatch.setenv("DD_TOKEN", "config-token")

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(
            tmp_path,
            [
                {
                    "scanner": "zap",
                    "execution_key": "zap",
                    "target": "example.com",
                    "_artifact_name": "zap.json",
                    "_artifact_text": '{"site":[]}\n',
                    "artifact_format": "json",
                    "native": True,
                    "safe_importable": True,
                }
            ],
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--config", str(config_path),
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 1
    assert "Missing DefectDojo scan type mapping for scanner: zap" in output.err


def test_defectdojo_export_only_writes_generic_json(monkeypatch, tmp_path, capsys):
    rc = _run_main(
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
            "--defectdojo-export",
        ],
    )
    capsys.readouterr()

    export_path = tmp_path / "run" / "defectdojo_generic.json"
    payload = json.loads(export_path.read_text(encoding="utf-8"))

    assert rc == 0
    assert export_path.exists()
    assert payload["findings"][0]["title"] == "SQL Injection"


def test_explicit_merged_defectdojo_upload_triggers_export_and_client_call(monkeypatch, tmp_path, capsys):
    captured: dict = {}

    def fake_upload(report_path, config, *, scan_date=None):
        captured["report_path"] = report_path
        captured["scan_date"] = scan_date
        captured["config"] = config
        return {"message": "ok"}

    monkeypatch.setattr(main, "upload_defectdojo_report", fake_upload)
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("raw upload should not run")),
    )

    rc = _run_main(
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
            "--defectdojo-upload",
            "--defectdojo-upload-mode", "merged",
            "--defectdojo-url", "https://dojo.example",
            "--defectdojo-api-token", "secret-token",
            "--defectdojo-product-type", "Applications",
            "--defectdojo-product", "Checkout",
            "--defectdojo-engagement", "Nightly",
            "--defectdojo-test-id", "77",
            "--defectdojo-engagement-id", "55",
            "--defectdojo-background-import",
            "--defectdojo-scan-date", "2026-04-23",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["report_path"] == tmp_path / "run" / "defectdojo_generic.json"
    assert captured["report_path"].exists()
    assert captured["scan_date"] == "2026-04-23"
    assert captured["config"].product_name == "Checkout"
    assert captured["config"].scan_type == "Generic Findings Import"
    assert captured["config"].test_id == 77
    assert captured["config"].engagement_id == 55
    assert captured["config"].background_import is True


def test_explicit_merged_defectdojo_upload_normalizes_cli_iso_scan_date_before_client_call(monkeypatch, tmp_path, capsys):
    captured: dict = {}

    def fake_upload(report_path, config, *, scan_date=None):
        captured["scan_date"] = scan_date
        return {"message": "ok"}

    monkeypatch.setattr(main, "upload_defectdojo_report", fake_upload)

    rc = _run_main(
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
            "--defectdojo-upload",
            "--defectdojo-upload-mode", "merged",
            "--defectdojo-url", "https://dojo.example",
            "--defectdojo-api-token", "secret-token",
            "--defectdojo-product-type", "Applications",
            "--defectdojo-product", "Checkout",
            "--defectdojo-engagement", "Nightly",
            "--defectdojo-scan-date", "2026-04-22T01:02:03Z",
        ],
    )
    capsys.readouterr()

    assert rc == 0
    assert captured["scan_date"] == "2026-04-22"


def test_defectdojo_upload_defaults_to_raw_per_scan_for_single_nmap_scanner(monkeypatch, tmp_path, capsys):
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _SingleScannerRawUploadOrchestrator(tmp_path),
    )
    monkeypatch.setattr(
        main,
        "generate_html_report",
        lambda results, path: path.write_text("<html></html>", encoding="utf-8"),
    )
    monkeypatch.setattr(
        main,
        "write_defectdojo_generic_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged export should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged upload should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "artifact_path": artifact_path,
                "scan_type": scan_type,
                "test_title": test_title,
                "scan_date": scan_date,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "ga.map.cyberhayq.am",
        "--scanner", "nmap",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
        "--defectdojo-scan-date", "2026-04-23",
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "artifact_path": tmp_path / "run" / "raw" / "nmap.xml",
            "scan_type": "Nmap Scan",
            "test_title": "nmap | ga.map.cyberhayq.am",
            "scan_date": "2026-04-23",
        }
    ]
    assert not (tmp_path / "run" / "defectdojo_generic.json").exists()


@pytest.mark.parametrize(
    ("scanner_name", "artifact_name", "artifact_text", "artifact_format", "expected_scan_type"),
    [
        ("zap", "zap.json", '{"site":[]}\n', "json", "ZAP Scan"),
        ("wapiti", "wapiti.xml", "<report type=\"security\"></report>\n", "xml", "Wapiti Scan"),
    ],
)
def test_raw_per_scan_single_web_scanner_uses_scanner_specific_test(
    monkeypatch,
    tmp_path,
    capsys,
    scanner_name,
    artifact_name,
    artifact_text,
    artifact_format,
    expected_scan_type,
):
    captured: list[dict] = []
    target = "https://example.com"

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _SingleScannerRawUploadOrchestrator(
            tmp_path,
            scanner_name=scanner_name,
            artifact_name=artifact_name,
            artifact_text=artifact_text,
            artifact_format=artifact_format,
        ),
    )
    monkeypatch.setattr(
        main,
        "generate_html_report",
        lambda results, path: path.write_text("<html></html>", encoding="utf-8"),
    )
    monkeypatch.setattr(
        main,
        "write_defectdojo_generic_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged export should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged upload should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "artifact_path": artifact_path,
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", scanner_name,
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-upload-mode", "raw-per-scan",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Research and Development",
        "--defectdojo-product", "Test",
        "--defectdojo-engagement", "Test engagement",
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "artifact_path": tmp_path / "run" / "raw" / artifact_name,
            "scan_type": expected_scan_type,
            "test_title": f"{scanner_name} | {target}",
        }
    ]


def test_defectdojo_upload_defaults_to_raw_per_scan_for_multi_scanner_manifest(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "nuclei",
            "execution_key": "nuclei@example.com:80",
            "target": "http://example.com:80",
            "_artifact_name": "nuclei.jsonl",
            "_artifact_text": '{"template-id":"x"}\n',
            "artifact_format": "jsonl",
            "native": True,
            "safe_importable": True,
            "test_title": "nuclei | http://example.com:80",
        },
        {
            "scanner": "zap",
            "execution_key": "zap@example.com:80",
            "target": "http://example.com:80",
            "_artifact_name": "zap.json",
            "_artifact_text": '{"site":[]}\n',
            "artifact_format": "json",
            "native": True,
            "safe_importable": True,
            "test_title": "zap | http://example.com:80",
        },
    ]
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(
        main,
        "generate_html_report",
        lambda results, path: path.write_text("<html></html>", encoding="utf-8"),
    )
    monkeypatch.setattr(
        main,
        "write_defectdojo_generic_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged export should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged upload should not run")),
    )

    def fake_raw_upload(artifact_path, config, *, scan_type, test_title, scan_date=None):
        captured.append(
            {
                "artifact_path": artifact_path,
                "scan_type": scan_type,
                "test_title": test_title,
                "scan_date": scan_date,
            }
        )
        return {"message": "ok"}

    monkeypatch.setattr(main, "upload_defectdojo_raw_artifact", fake_raw_upload)
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
        "--defectdojo-scan-date", "2026-04-23T08:10:28Z",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert len(captured) == 2
    assert [item["scan_type"] for item in captured] == ["Nuclei Scan", "ZAP Scan"]
    assert [item["test_title"] for item in captured] == [
        "nuclei | example.com",
        "zap | example.com",
    ]
    assert all(item["scan_date"] == "2026-04-23" for item in captured)
    assert not (tmp_path / "run" / "defectdojo_generic.json").exists()
    assert "uploaded=2, skipped=0, failed=0" in output.out


def test_raw_per_scan_mixed_zap_and_wapiti_uploads_each_scanner_separately(monkeypatch, tmp_path, capsys):
    target = "https://example.com"
    raw_uploads = [
        {
            "scanner": "zap",
            "execution_key": "zap",
            "target": target,
            "_artifact_name": "zap.json",
            "_artifact_text": '{"site":[]}\n',
            "artifact_format": "json",
            "native": True,
            "safe_importable": True,
            "test_title": "All scanners findings",
        },
        {
            "scanner": "wapiti",
            "execution_key": "wapiti",
            "target": target,
            "_artifact_name": "wapiti.xml",
            "_artifact_text": "<report type=\"security\"></report>\n",
            "artifact_format": "xml",
            "native": True,
            "safe_importable": True,
            "test_title": "All scanners findings",
        },
    ]
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "write_defectdojo_generic_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged export should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged upload should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-upload-mode", "raw-per-scan",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Research and Development",
        "--defectdojo-product", "Test",
        "--defectdojo-engagement", "Test engagement",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert captured == [
        {"scan_type": "ZAP Scan", "test_title": f"zap | {target}"},
        {"scan_type": "Wapiti Scan", "test_title": f"wapiti | {target}"},
    ]
    assert all(item["scan_type"] != "Generic Findings Import" for item in captured)
    assert "uploaded=2, skipped=0, failed=0" in output.out


def test_raw_per_scan_mode_defaults_discovery_executions_to_stable_scanner_title(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "nuclei",
            "execution_key": "nuclei@example.com:80",
            "target": "http://example.com:80",
            "_artifact_name": "nuclei-80.jsonl",
            "_artifact_text": "{}\n",
            "artifact_format": "jsonl",
            "native": True,
            "safe_importable": True,
        },
        {
            "scanner": "nuclei",
            "execution_key": "nuclei@example.com:443",
            "target": "https://example.com:443",
            "_artifact_name": "nuclei-443.jsonl",
            "_artifact_text": "{}\n",
            "artifact_format": "jsonl",
            "native": True,
            "safe_importable": True,
        },
    ]
    titles: list[str] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: titles.append(test_title) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert titles == [
        "nuclei | example.com",
        "nuclei | example.com",
    ]
    assert len(set(titles)) == 1


def test_raw_per_scan_mode_skips_unsupported_scanner_without_crashing(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "custom",
            "execution_key": "custom",
            "target": "example.com",
            "_artifact_name": "custom.json",
            "_artifact_text": "{}\n",
            "artifact_format": "json",
            "native": True,
            "safe_importable": True,
        },
    ]
    called = {"raw_upload": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(main, "upload_defectdojo_raw_artifact", lambda *args, **kwargs: called.__setitem__("raw_upload", called["raw_upload"] + 1))
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert called["raw_upload"] == 0
    assert "custom -> no configured native parser mapping" in output.err
    assert "uploaded=0, skipped=1, failed=0" in output.out


def test_raw_per_scan_mode_skips_missing_artifact_path(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "nmap",
            "execution_key": "nmap",
            "target": "example.com",
            "raw_artifact_path": str(tmp_path / "missing.xml"),
            "artifact_format": "xml",
            "native": True,
            "safe_importable": True,
        },
    ]
    called = {"raw_upload": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(main, "upload_defectdojo_raw_artifact", lambda *args, **kwargs: called.__setitem__("raw_upload", called["raw_upload"] + 1))
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert called["raw_upload"] == 0
    assert "scanner-native raw artifact does not exist" in output.err


def test_raw_per_scan_mode_skips_entry_without_raw_artifact_path(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "zap",
            "execution_key": "zap",
            "target": "https://example.com",
            "artifact_format": "json",
            "native": True,
            "safe_importable": True,
        },
    ]
    called = {"raw_upload": 0}

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(main, "upload_defectdojo_raw_artifact", lambda *args, **kwargs: called.__setitem__("raw_upload", called["raw_upload"] + 1))
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "https://example.com",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-upload-mode", "raw-per-scan",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert called["raw_upload"] == 0
    assert "zap -> scanner-native raw artifact path is missing" in output.err


def test_missing_raw_output_for_one_scanner_does_not_block_other_raw_uploads(monkeypatch, tmp_path, capsys):
    raw_uploads = [
        {
            "scanner": "nmap",
            "execution_key": "nmap",
            "target": "ga.map.cyberhayq.am",
            "_artifact_name": "nmap.xml",
            "_artifact_text": '<?xml version="1.0"?><nmaprun></nmaprun>\n',
            "artifact_format": "xml",
            "native": True,
            "safe_importable": True,
        },
        {
            "scanner": "zap",
            "execution_key": "zap",
            "target": "https://ga.map.cyberhayq.am",
            "raw_artifact_path": str(tmp_path / "missing-zap.json"),
            "artifact_format": "json",
            "native": True,
            "safe_importable": True,
        },
    ]
    captured: list[dict] = []

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _RawUploadOrchestrator(tmp_path, raw_uploads),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "artifact_path": artifact_path,
                "scan_type": scan_type,
                "test_title": test_title,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", "ga.map.cyberhayq.am",
        "--scanner", "all",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Applications",
        "--defectdojo-product", "Checkout",
        "--defectdojo-engagement", "Nightly",
    ])

    rc = main.main()
    output = capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "artifact_path": tmp_path / "run" / "raw" / "nmap.xml",
            "scan_type": "Nmap Scan",
            "test_title": "nmap | ga.map.cyberhayq.am",
        }
    ]
    assert "zap -> scanner-native raw artifact does not exist" in output.err
    assert "uploaded=1, skipped=1, failed=0" in output.out


def test_cli_raw_per_scan_overrides_env_merged_and_global_test_title(monkeypatch, tmp_path, capsys):
    captured: list[dict] = []
    target = "https://example.com"

    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_UPLOAD_MODE", "merged")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_TEST_TITLE", "All scanners findings")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_TEST_ID", "123")
    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: _SingleScannerRawUploadOrchestrator(
            tmp_path,
            scanner_name="zap",
            artifact_name="zap.json",
            artifact_text='{"site":[]}\n',
            artifact_format="json",
        ),
    )
    monkeypatch.setattr(main, "generate_html_report", lambda results, path: path.write_text("<html></html>", encoding="utf-8"))
    monkeypatch.setattr(
        main,
        "write_defectdojo_generic_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged export should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_report",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("merged upload should not run")),
    )
    monkeypatch.setattr(
        main,
        "upload_defectdojo_raw_artifact",
        lambda artifact_path, config, *, scan_type, test_title, scan_date=None: captured.append(
            {
                "scan_type": scan_type,
                "test_title": test_title,
                "config_test_title": config.test_title,
                "config_test_id": config.test_id,
            }
        ) or {"message": "ok"},
    )
    monkeypatch.setattr(sys, "argv", [
        "main.py",
        "--target", target,
        "--scanner", "zap",
        "--data-dir", str(tmp_path / "data"),
        "--json",
        "--no-dedupe",
        "--no-score",
        "--defectdojo-upload",
        "--defectdojo-upload-mode", "raw-per-scan",
        "--defectdojo-url", "https://dojo.example",
        "--defectdojo-api-token", "secret-token",
        "--defectdojo-product-type", "Research and Development",
        "--defectdojo-product", "Test",
        "--defectdojo-engagement", "Test engagement",
    ])

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert captured == [
        {
            "scan_type": "ZAP Scan",
            "test_title": f"zap | {target}",
            "config_test_title": None,
            "config_test_id": None,
        }
    ]


def test_defectdojo_env_wires_new_targeting_options(monkeypatch):
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_URL", "https://dojo.example")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_API_TOKEN", "secret-token")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_TEST_ID", "77")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_ENGAGEMENT_ID", "55")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_BACKGROUND_IMPORT", "true")
    monkeypatch.setenv("VULN_MANAGER_DEFECTDOJO_STRICT_NAMES", "true")

    args = argparse.Namespace(
        defectdojo_url=None,
        defectdojo_api_token=None,
        defectdojo_product_type=None,
        defectdojo_product=None,
        defectdojo_engagement=None,
        defectdojo_test_id=None,
        defectdojo_engagement_id=None,
        defectdojo_test_title=None,
        defectdojo_minimum_severity=None,
        defectdojo_no_auto_create_context=False,
        defectdojo_do_not_reactivate=False,
        defectdojo_close_old_findings=False,
        defectdojo_environment=None,
        defectdojo_background_import=False,
        defectdojo_strict_names=False,
        defectdojo_insecure=False,
    )

    config = main._resolve_defectdojo_config(args)

    assert config.test_id == 77
    assert config.engagement_id == 55
    assert config.background_import is True
    assert config.strict_names is True


def test_upload_failure_returns_non_zero_but_normal_results_still_saved(monkeypatch, tmp_path, capsys):
    def failing_upload(report_path, config, *, scan_date=None):
        raise RuntimeError("upload failed")

    monkeypatch.setattr(main, "upload_defectdojo_report", failing_upload)

    rc = _run_main(
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
            "--defectdojo-upload",
            "--defectdojo-upload-mode", "merged",
            "--defectdojo-url", "https://dojo.example",
            "--defectdojo-api-token", "secret-token",
            "--defectdojo-product-type", "Applications",
            "--defectdojo-product", "Checkout",
            "--defectdojo-engagement", "Nightly",
        ],
    )
    output = capsys.readouterr()

    assert rc == 1
    assert "DefectDojo upload failed: upload failed" in output.err
    assert "Final scan results and defectdojo_generic.json were kept" in output.err
    assert (tmp_path / "run" / "normalized.json").exists()
    assert (tmp_path / "run" / "report.html").exists()
    assert (tmp_path / "run" / "defectdojo_generic.json").exists()
