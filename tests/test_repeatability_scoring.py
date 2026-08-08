import json

from utils.comparator import ComparisonResult, add_comparison_to_results, compare_with_previous
from utils.risk_scorer import _is_repeatable, calculate_risk_score, score_vulnerabilities
from utils.run_folder import create_target_slug


def _finding(fp_strict="fp-abc", fp_general="fp-gen-abc", **kwargs) -> dict:
    base = {
        "vulnerability_name": "Test Vuln",
        "severity": "medium",
        "asset_id": "10.0.0.1",
        "description": "Test.",
        "remediation": "Fix it.",
        "meta": {},
        "fp_strict": fp_strict,
        "fp_general": fp_general,
    }
    base.update(kwargs)
    return base


def _make_scan_json(findings: list, target: str = "example.com", scanners_run: list | None = None) -> str:
    return json.dumps({
        "schema_version": "2.0",
        "target": target,
        "timestamp": "2026-01-01T00:00:00Z",
        "scanners_run": scanners_run or ["nuclei"],
        "all_findings": findings,
        "summary": {"total_findings": len(findings)},
    })


def test_is_repeatable_uses_strict_and_general_fallback():
    previous = _finding(fp_strict="fp-same", fp_general="fp-gen-same")
    assert _is_repeatable(_finding(fp_strict="fp-same", fp_general="fp-gen-diff"), {"previous_findings": [previous]})
    assert _is_repeatable(_finding(fp_strict="", fp_general="fp-gen-same"), {"previous_findings": [previous]})
    assert not _is_repeatable(_finding(fp_strict="fp-X"), {"previous_findings": [_finding(fp_strict="fp-Y")]})


def test_calculate_risk_score_adds_repeatability_bonus():
    finding = _finding(fp_strict="fp-repeat", meta={"confidence": "high"})
    score_with = calculate_risk_score(finding, {"previous_findings": [_finding(fp_strict="fp-repeat", meta={"confidence": "high"})]})
    score_without = calculate_risk_score(finding, {"previous_findings": []})

    assert score_with["risk_factors"]["repeatability"] == 4
    assert score_without["risk_factors"]["repeatability"] == 0
    assert score_with["risk_score"] - score_without["risk_score"] == 4
    assert "repeatable" in score_with["risk_rationale"]


def test_comparison_result_default_previous_findings():
    result = ComparisonResult()
    assert result.previous_findings == []


def test_compare_with_previous_keeps_baseline_findings_available_for_internal_scoring(tmp_path):
    target = "prev-test.example.com"
    slug = create_target_slug(target)
    run_dir = tmp_path / slug / "20260101_120000"
    run_dir.mkdir(parents=True)
    (run_dir / "normalized.json").write_text(json.dumps(json.loads(_make_scan_json([_finding(fp_strict="fp-old")], target=target))))

    results = {
        "schema_version": "2.0",
        "target": target,
        "timestamp": "2026-03-30T10:00:00Z",
        "scanners_run": ["nuclei"],
        "all_findings": [_finding(fp_strict="fp-old")],
        "summary": {"total_findings": 1},
    }
    comparison = compare_with_previous(results, tmp_path)

    assert len(comparison.previous_findings) > 0

    scored = score_vulnerabilities(results, {"previous_findings": comparison.previous_findings})
    assert scored["all_findings"][0]["risk_factors"]["repeatability"] > 0
