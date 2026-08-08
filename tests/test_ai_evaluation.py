import json

import pytest

from utils.ai_evaluation import (
    build_label_template,
    evaluate_ai_analysis,
    finding_evaluation_key,
    main,
)


def _finding(title, asset, status="completed", predicted="likely_valid", scanner="zap"):
    finding = {
        "vulnerability_name": title,
        "severity": "high",
        "asset_id": asset,
        "description": "Evidence",
        "remediation": "Scanner remediation",
        "meta": {"scanner": scanner},
        "ai_analysis_status": status,
    }
    if status in {"completed", "cached"}:
        finding["applicability"] = {
            "status": predicted,
            "confidence": 0.8,
            "reason": "Reason",
            "evidence_ids": ["finding-description"],
        }
        finding["ai_remediation"] = {
            "steps": ["Fix it"],
            "verification": ["Verify it"],
        }
    return finding


def _label(finding, expected, **review):
    return {
        "finding_key": finding_evaluation_key(finding),
        "expected_applicability_status": expected,
        "remediation_review": {
            "supported": review.get("supported"),
            "actionable": review.get("actionable"),
            "verifiable": review.get("verifiable"),
        },
    }


def test_evaluation_reports_real_agreement_coverage_failures_and_rubric():
    valid = _finding("SQL Injection", "https://example.com/search")
    wrong = _finding(
        "Header issue",
        "https://example.com/",
        predicted="likely_false_positive",
        scanner="nuclei",
    )
    unavailable = _finding("TLS issue", "example.com:443", status="unavailable", scanner="nmap")
    results = {
        "target": "example.com",
        "generated_at": "2026-08-07T23:00:00Z",
        "asset_knowledge": {"profile_revision": "context-revision-1"},
        "ai_analysis_summary": {
            "status": "partial",
            "model": "demo-model",
            "prompt_version": "finding-analysis-v1",
            "limit": 10,
            "selected_count": 3,
            "analyzed_count": 2,
            "cached_count": 0,
            "unavailable_count": 1,
            "skipped_limit_count": 0,
            "prompt_tokens": 100,
            "completion_tokens": 40,
            "total_tokens": 140,
            "redaction_count": 0,
            "latency_ms": 20.0,
            "estimated_cost_usd": 0.001,
        },
        "all_findings": [valid, wrong, unavailable],
    }
    labels = {
        "version": 1,
        "cases": [
            _label(valid, "likely_valid", supported=True, actionable=True, verifiable=False),
            _label(wrong, "likely_valid", supported=False, actionable=True, verifiable=True),
            _label(unavailable, "needs_review"),
        ],
    }

    evaluation = evaluate_ai_analysis(results, labels, generated_at="2026-08-08T00:00:00Z")

    metrics = evaluation["metrics"]
    assert metrics["labeled_cases"] == 3
    assert metrics["matched_cases"] == 3
    assert metrics["analyzed_cases"] == 2
    assert metrics["analysis_coverage"] == 0.6667
    assert metrics["applicability_agreement"] == 0.5
    assert metrics["unavailable_count"] == 1
    assert metrics["wrong_false_positive_decisions"] == 1
    assert metrics["remediation_supported_rate"] == 0.5
    assert metrics["remediation_actionable_rate"] == 1.0
    assert metrics["remediation_verifiable_rate"] == 0.5
    assert evaluation["confusion"] == {
        "likely_valid->likely_false_positive": 1,
        "likely_valid->likely_valid": 1,
    }
    assert evaluation["source_generated_at"] == "2026-08-07T23:00:00Z"
    assert evaluation["analysis_run"]["model"] == "demo-model"
    assert evaluation["analysis_run"]["prompt_version"] == "finding-analysis-v1"
    assert evaluation["analysis_run"]["context_revision"] == "context-revision-1"


def test_remediation_rubric_excludes_unavailable_findings():
    unavailable = _finding("TLS issue", "example.com:443", status="unavailable")
    labels = {
        "version": 1,
        "cases": [
            _label(
                unavailable,
                "needs_review",
                supported=True,
                actionable=True,
                verifiable=True,
            )
        ],
    }

    metrics = evaluate_ai_analysis(
        {"all_findings": [unavailable]}, labels, generated_at="2026-08-08T00:00:00Z"
    )["metrics"]

    assert metrics["remediation_supported_rate"] is None
    assert metrics["remediation_actionable_rate"] is None
    assert metrics["remediation_verifiable_rate"] is None


def test_label_template_is_stable_and_human_fillable():
    finding = _finding("SQL Injection", "https://example.com/search")

    template = build_label_template({"all_findings": [finding]})

    assert template["version"] == 1
    assert template["cases"][0]["finding_key"] == finding_evaluation_key(finding)
    assert template["cases"][0]["expected_applicability_status"] is None
    assert template["cases"][0]["remediation_review"] == {
        "supported": None,
        "actionable": None,
        "verifiable": None,
    }


def test_evaluation_keys_distinguish_same_title_asset_and_scanner_by_parameter():
    first = _finding("SQL Injection", "https://example.com/search")
    second = _finding("SQL Injection", "https://example.com/search")
    first["meta"].update({"method": "GET", "path": "/search", "parameter": "q"})
    second["meta"].update({"method": "GET", "path": "/search", "parameter": "category"})

    template = build_label_template({"all_findings": [first, second]})

    assert len({case["finding_key"] for case in template["cases"]}) == 2
    assert {case["instance_anchors"]["parameter"] for case in template["cases"]} == {
        "q", "category"
    }


def test_evaluation_rejects_truly_indistinguishable_duplicate_findings():
    finding = _finding("SQL Injection", "https://example.com/search")

    with pytest.raises(ValueError, match="indistinguishable"):
        build_label_template({"all_findings": [finding, dict(finding)]})


def test_invalid_labels_are_rejected():
    finding = _finding("SQL Injection", "https://example.com/search")
    labels = {
        "version": 1,
        "cases": [_label(finding, "invented")],
    }

    with pytest.raises(ValueError, match="expected_applicability_status"):
        evaluate_ai_analysis({"all_findings": [finding]}, labels)

    labels = {
        "version": 1,
        "cases": [_label(finding, "likely_valid", supported=1)],
    }
    with pytest.raises(ValueError, match="supported must be bool or null"):
        evaluate_ai_analysis({"all_findings": [finding]}, labels)


def test_cli_writes_template_and_evaluation(tmp_path):
    finding = _finding("SQL Injection", "https://example.com/search")
    results_path = tmp_path / "normalized.json"
    results_path.write_text(json.dumps({"target": "example.com", "all_findings": [finding]}))
    template_path = tmp_path / "labels.json"

    assert main(["--results", str(results_path), "--write-label-template", str(template_path)]) == 0
    labels = json.loads(template_path.read_text())
    labels["cases"][0]["expected_applicability_status"] = "likely_valid"
    labels["cases"][0]["remediation_review"] = {
        "supported": True,
        "actionable": True,
        "verifiable": True,
    }
    template_path.write_text(json.dumps(labels))
    output_path = tmp_path / "metrics.json"

    assert main([
        "--results", str(results_path),
        "--labels", str(template_path),
        "--output", str(output_path),
    ]) == 0
    payload = json.loads(output_path.read_text())
    assert payload["metrics"]["applicability_agreement"] == 1.0
