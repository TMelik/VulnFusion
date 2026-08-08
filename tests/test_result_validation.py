from datetime import datetime, timezone

import pytest

from orchestrator import ScannerOrchestrator
from utils.report_generator import generate_html_report
from utils.schema import SCHEMA_VERSION, assert_valid_results


def _minimal_finding():
    return {
        "vulnerability_name": "Test Vuln",
        "severity": "medium",
        "asset_id": "https://example.com",
        "description": "A test vulnerability.",
        "remediation": "Fix it.",
        "meta": {},
    }


def _now_z():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _valid_post_normalize(findings=None):
    return {
        "schema_version": SCHEMA_VERSION,
        "target": "example.com",
        "all_findings": findings if findings is not None else [_minimal_finding()],
    }


def _valid_final(findings=None):
    results = _valid_post_normalize(findings)
    results["generated_at"] = _now_z()
    return results


def test_post_normalize_accepts_missing_generated_at():
    assert_valid_results(_valid_post_normalize(), stage="post_normalize")


def test_final_requires_generated_at():
    with pytest.raises(ValueError, match="generated_at"):
        assert_valid_results(_valid_post_normalize(), stage="final")


@pytest.mark.parametrize(
    "bad_ts",
    ["2026-03-30T10:00:00", "2026-03-30T10:00:00+04:00", "2026-03-30"],
)
def test_final_rejects_non_utc_generated_at(bad_ts):
    results = _valid_final()
    results["generated_at"] = bad_ts
    with pytest.raises(ValueError, match="generated_at"):
        assert_valid_results(results, stage="final")


def test_invalid_finding_bubbles_up_from_results_validation():
    finding = _minimal_finding()
    finding["severity"] = "critical_extreme"
    with pytest.raises(ValueError, match="Finding #1"):
        assert_valid_results(_valid_final([finding]), stage="final")


def test_save_results_rejects_missing_generated_at(tmp_path):
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    with pytest.raises(ValueError, match="generated_at"):
        orchestrator.save_results(_valid_post_normalize())


def test_save_results_writes_valid_payload(tmp_path):
    orchestrator = ScannerOrchestrator(reports_dir=tmp_path)
    path = orchestrator.save_results(_valid_final())
    assert path.exists()
    assert path.name.startswith("normalized_")
    assert not path.name.startswith("scan_results_")


def test_generate_html_report_rejects_invalid_results():
    with pytest.raises(ValueError, match="generated_at"):
        generate_html_report({"schema_version": SCHEMA_VERSION, "target": "x", "all_findings": []})


def test_final_accepts_optional_transport_execution_metadata():
    results = _valid_final()
    results["transport_detected"] = {
        "transport_detected": "http2_only",
        "http2_only": True,
    }
    results["scanner_execution"] = {
        "direct-web": {
            "scanner_type": "web",
            "supports_http2_direct": True,
            "supports_proxy": False,
            "transport_detected": "http2_only",
            "scan_route": "direct",
            "adapter_mode": "direct",
            "skip_reason": None,
            "scanner_transport_notes": "Direct HTTP/2 scan.",
            "supports_http2": True,
            "supports_http1_1": False,
            "http2_only": True,
            "probe_method": "python-httpx",
            "adapter_status": None,
            "adapter_runtime_state": None,
            "adapter_failure_reason": None,
            "adapter_diagnostics": None,
            "adapter_runtime": None,
            "adapter_upstream_url": None,
            "adapter_translation_chain": None,
            "transport_confidence": "normal",
            "adapter_shutdown_reason": None,
            "adapter_shutdown_clean": None,
            "execution_target": "https://example.com",
            "effective_target": "https://example.com",
            "original_target": "https://example.com",
            "scanner_error": None,
            "partial_results": False,
            "degraded_execution": False,
        }
    }

    assert_valid_results(results, stage="final")


def test_final_accepts_bridge_adapter_metadata():
    results = _valid_final()
    results["scanner_execution"] = {
        "nikto": {
            "scanner_type": "web",
            "transport_detected": "http2_only",
            "scan_route": "proxied",
            "adapter_mode": "bridge",
            "scanner_transport_notes": "Scanner was routed through the local bridge.",
            "adapter_status": "ready",
            "adapter_runtime_state": "running",
            "adapter_failure_reason": None,
            "adapter_diagnostics": "bridge runtime reported running",
            "adapter_runtime": "python-bridge",
            "adapter_upstream_url": "https://example.com",
            "adapter_translation_chain": "python HTTP/2 bridge -> origin",
            "transport_confidence": "degraded",
            "adapter_shutdown_reason": None,
            "adapter_shutdown_clean": None,
            "execution_target": "http://127.0.0.1:39012/admin",
            "effective_target": "http://127.0.0.1:39012/admin",
            "origin_target": "https://example.com",
            "original_target": "https://example.com/admin",
            "scanner_error": "Nikto degraded softly.",
            "partial_results": True,
            "degraded_execution": True,
        }
    }

    assert_valid_results(results, stage="final")


def test_final_rejects_invalid_transport_scan_route():
    results = _valid_final()
    results["scanner_execution"] = {
        "wapiti": {
            "scanner_type": "web",
            "scan_route": "tunneled",
        }
    }

    with pytest.raises(ValueError, match="scan_route"):
        assert_valid_results(results, stage="final")


def test_final_rejects_invalid_transport_adapter_mode():
    results = _valid_final()
    results["scanner_execution"] = {
        "wapiti": {
            "scanner_type": "web",
            "scan_route": "proxied",
            "adapter_mode": "tunneled",
        }
    }

    with pytest.raises(ValueError, match="adapter_mode"):
        assert_valid_results(results, stage="final")


def test_final_accepts_public_risk_fields_on_findings():
    finding = _minimal_finding()
    finding.update(
        {
            "risk_score": 88,
            "priority": "P0",
            "risk_factors": {"final_score": 88, "final_priority": "P0"},
            "risk_rationale": "Active exploitation signals and production exposure increased priority.",
        }
    )

    assert_valid_results(_valid_final([finding]), stage="final")


def test_final_rejects_unsupported_impact_for_developers():
    finding = _minimal_finding()
    finding["impact_for_developers"] = "Deprecated generated prose."

    with pytest.raises(ValueError, match="impact_for_developers"):
        assert_valid_results(_valid_final([finding]), stage="final")
