import copy
import json
import sys

import main
import pytest

from utils.asset_context import apply_asset_context, load_asset_context_file
from utils.risk_scorer import calculate_risk_score
from utils.schema import SCHEMA_VERSION


def _finding(asset_id: str = "https://app.example.com/login", meta_extra: dict | None = None) -> dict:
    meta = {
        "scanner": "nuclei",
        "host": "app.example.com",
        "path": "/login",
    }
    if meta_extra:
        meta.update(meta_extra)
    return {
        "vulnerability_name": "SQL Injection",
        "severity": "medium",
        "asset_id": asset_id,
        "description": "The issue is reproducible before authentication.",
        "remediation": "Sanitize the input.",
        "meta": meta,
    }


def test_exact_host_match_applies_business_context(tmp_path):
    asset_context_file = tmp_path / "asset-context.yaml"
    asset_context_file.write_text(
        """
rules:
  - host: app.example.com
    asset_criticality: high
    environment: production
    sensitive_data: true
""".strip(),
        encoding="utf-8",
    )

    rules = load_asset_context_file(asset_context_file)
    finding = _finding()

    apply_asset_context([finding], rules)

    assert finding["meta"]["business_context"] == {
        "asset_criticality": "high",
        "environment": "production",
        "sensitive_data": True,
    }


def test_domain_suffix_match_applies_business_context(tmp_path):
    asset_context_file = tmp_path / "asset-context.json"
    asset_context_file.write_text(
        json.dumps(
            {
                "rules": [
                    {
                        "host_suffix": "example.com",
                        "path_prefix": "/pay",
                        "internet_exposed": True,
                        "environment": "production",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    rules = load_asset_context_file(asset_context_file)
    finding = _finding(
        asset_id="https://billing.api.example.com/pay/invoice",
        meta_extra={"host": "billing.api.example.com", "path": "/pay/invoice"},
    )

    apply_asset_context([finding], rules)

    assert finding["meta"]["business_context"]["internet_exposed"] is True
    assert finding["meta"]["business_context"]["environment"] == "production"


def test_existing_explicit_business_context_is_preserved_and_missing_fields_are_filled(tmp_path):
    asset_context_file = tmp_path / "asset-context.yaml"
    asset_context_file.write_text(
        """
rules:
  - host: app.example.com
    asset_criticality: high
    environment: production
    internet_exposed: true
    sensitive_data: true
""".strip(),
        encoding="utf-8",
    )

    rules = load_asset_context_file(asset_context_file)
    finding = _finding(
        meta_extra={
            "business_context": {
                "environment": "staging",
                "internet_exposed": False,
            }
        }
    )

    apply_asset_context([finding], rules)

    assert finding["meta"]["business_context"] == {
        "asset_criticality": "high",
        "environment": "staging",
        "internet_exposed": False,
        "sensitive_data": True,
    }


def test_applied_asset_context_changes_risk_score_and_priority(tmp_path):
    asset_context_file = tmp_path / "asset-context.yaml"
    asset_context_file.write_text(
        """
rules:
  - host: app.example.com
    asset_criticality: high
    environment: production
""".strip(),
        encoding="utf-8",
    )

    rules = load_asset_context_file(asset_context_file)
    plain_finding = _finding()
    contextual_finding = copy.deepcopy(plain_finding)

    plain_result = calculate_risk_score(plain_finding)
    apply_asset_context([contextual_finding], rules)
    contextual_result = calculate_risk_score(contextual_finding)

    assert contextual_finding["meta"]["business_context"]["asset_criticality"] == "high"
    assert contextual_finding["meta"]["business_context"]["environment"] == "production"
    assert contextual_result["risk_score"] > plain_result["risk_score"]
    assert plain_result["priority"] in {"P2", "P1"}  # SQLi class floor + internet exposure can reach P1
    assert contextual_result["risk_score"] - plain_result["risk_score"] >= 5  # high+production adds at least 5 pts
    assert contextual_result["priority"] in {"P2", "P1", "P0"}


def test_main_accepts_asset_context_file_flag_and_applies_runtime_scoring(monkeypatch, tmp_path, capsys):
    asset_context_file = tmp_path / "asset-context.yaml"
    asset_context_file.write_text(
        """
rules:
  - host: app.example.com
    asset_criticality: high
    environment: production
    internet_exposed: true
""".strip(),
        encoding="utf-8",
    )

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-05T10:00:00Z",
                "scanners_run": ["nuclei"],
                "all_findings": [_finding()],
                "errors": [],
                "summary": {"total_findings": 1, "by_severity": {"medium": 1}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results), encoding="utf-8")
            return path

    plain_result = calculate_risk_score(copy.deepcopy(_finding()))

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
            "--asset-context-file", str(asset_context_file),
            "--json",
            "--no-dedupe",
            "--no-save",
        ],
    )

    rc = main.main()
    capsys.readouterr()
    normalized = json.loads((tmp_path / "normalized.json").read_text(encoding="utf-8"))

    assert rc == 0
    finding = normalized["all_findings"][0]
    assert finding["risk_score"] > plain_result["risk_score"]
    assert finding["priority"] in {"P2", "P1", "P0"}
    assert isinstance(finding["risk_factors"], dict)
    assert "impact_for_developers" not in finding
    assert normalized["summary"]["by_priority"][finding["priority"]] == 1


def test_missing_asset_context_file_flag_is_optional(monkeypatch, tmp_path, capsys):
    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": SCHEMA_VERSION,
                "target": target,
                "timestamp": "2026-04-05T10:00:00Z",
                "scanners_run": ["nuclei"],
                "all_findings": [_finding()],
                "errors": [],
                "summary": {"total_findings": 1, "by_severity": {"medium": 1}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results), encoding="utf-8")
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

    assert rc == 0


def test_invalid_asset_context_file_fails_clearly(monkeypatch, tmp_path, capsys):
    asset_context_file = tmp_path / "asset-context.yaml"
    asset_context_file.write_text(
        """
rules:
  - host: app.example.com
    asset_criticality: 123
""".strip(),
        encoding="utf-8",
    )

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--asset-context-file", str(asset_context_file),
        ],
    )

    with pytest.raises(SystemExit) as exc:
        main.main()

    captured = capsys.readouterr()
    assert exc.value.code == 2
    assert "asset_criticality" in captured.err
