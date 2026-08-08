from utils.export_sanitizer import (
    iter_forbidden_export_fields,
    sanitize_results_for_export,
)


def _finding(**overrides):
    finding = {
        "vulnerability_name": "SQL Injection",
        "severity": "high",
        "asset_id": "https://example.com/login?id=1",
        "description": "Scanner observed injectable input handling.",
        "remediation": "Use parameterized queries.",
        "status": "CHANGED",
        "changed_fields": ["severity"],
        "change_details": {
            "changed_fields": ["severity"],
            "changes": {
                "severity": {
                    "previous": ["medium"],
                    "current": ["high"],
                }
            },
        },
        "comparison_mode": "partial",
        "priority": "P0",
        "risk_score": 97,
        "risk_rationale": "derived explanation",
        "risk_factors": {"final_score": 97, "final_priority": "P0"},
        "impact_for_developers": "SQL injection affects the login handler and should be fixed in code.",
        "duplicate_count": 2,
        "merge_confidence": 1.0,
        "match_level": "strict",
        "found_by": ["zap", "nuclei"],
        "source_findings": [
            {
                "scanner": "zap",
                "vulnerability_name": "SQL Injection",
                "severity": "high",
                "asset_id": "https://example.com/login?id=1",
                "description": "ZAP observed injectable input handling.",
                "remediation": "Use parameterized queries.",
                "comparison_mode": "partial",
                "degraded_execution": True,
                "fp_strict": "strict-fingerprint",
                "meta": {
                    "scanner": "zap",
                    "scanner_instance": "web-a",
                    "cve_id": "CVE-2024-1111",
                    "cvss": 8.1,
                    "cvss_score": 9.8,
                    "degraded_execution": True,
                },
                "references": ["https://scanner.example/zap"],
            }
        ],
        "meta": {
            "scanner": "nuclei",
            "scanner_instance": "web-a",
            "cve_id": "CVE-2024-1111",
            "cve_ids": ["CVE-2024-1111"],
            "cvss": 8.1,
            "cvss_score": 9.8,
            "epss_score": 0.91,
            "kev_listed": True,
            "business_context": {"environment": "production"},
            "degraded_execution": True,
        },
    }
    finding.update(overrides)
    return finding


def test_sanitize_results_for_export_removes_internal_fields_and_generated_developer_prose():
    raw_finding = _finding()
    results = {
        "schema_version": "2.0",
        "target": "example.com",
        "generated_at": "2026-04-17T08:00:00Z",
        "timestamp": "2026-04-17T07:59:00Z",
        "scanners_run": ["nuclei", "zap"],
        "tool_versions": {"nuclei": "3.2.0", "zap": "2.16.1"},
        "summary": {
            "total_findings": 1,
            "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
            "by_priority": {"P0": 1, "P1": 0, "P2": 0, "P3": 0, "P4": 0},
        },
        "scanner_execution": {"zap": {"execution_target": "http://127.0.0.1:3000/"}},
        "target_probe": {"normalized_target": "https://example.com"},
        "transport_detected": {"transport_detected": "http2_only"},
        "duplicate_analysis": {"mode": "llm"},
        "llm_duplicate_comparisons": [{"comparison_status": "compared_with_llm"}],
        "all_findings": [raw_finding],
        "findings_by_scanner": {"nuclei": [raw_finding]},
        "changed_findings": [raw_finding],
        "partial_unmatched_current_findings": [raw_finding],
    }

    exported = sanitize_results_for_export(results)

    assert list(iter_forbidden_export_fields(exported)) == []
    assert "scanner_execution" not in exported
    assert "target_probe" not in exported
    assert "transport_detected" not in exported
    assert "duplicate_analysis" not in exported
    assert "llm_duplicate_comparisons" not in exported
    assert exported["summary"]["by_priority"] == {"P0": 1, "P1": 0, "P2": 0, "P3": 0, "P4": 0}

    finding = exported["all_findings"][0]
    assert finding["priority"] == "P0"
    assert finding["risk_score"] == 97
    assert finding["risk_rationale"] == "derived explanation"
    assert finding["risk_factors"] == {"final_score": 97, "final_priority": "P0"}
    assert "impact_for_developers" not in finding
    assert "duplicate_count" not in finding
    assert "merge_confidence" not in finding
    assert "match_level" not in finding
    assert "comparison_mode" not in finding
    assert "change_details" not in finding
    assert "cvss_score" not in finding["meta"]
    assert "epss_score" not in finding["meta"]
    assert "kev_listed" not in finding["meta"]
    assert "business_context" not in finding["meta"]
    assert "scanner_instance" not in finding["meta"]
    assert "degraded_execution" not in finding["meta"]

    source = finding["source_findings"][0]
    assert "comparison_mode" not in source
    assert "degraded_execution" not in source
    assert "fp_strict" not in source
    assert "scanner_instance" not in source["meta"]
    assert "cvss_score" not in source["meta"]
    assert "degraded_execution" not in source["meta"]


def test_sanitize_results_for_export_preserves_scanner_data_and_comparison_labels():
    exported = sanitize_results_for_export(
        {
            "schema_version": "2.0",
            "target": "example.com",
            "generated_at": "2026-04-17T08:00:00Z",
            "tool_versions": {"nuclei": "3.2.0"},
            "summary": {"total_findings": 1, "by_severity": {"high": 1}},
            "comparison": {"comparison_mode": "full", "summary": {"changed": 1}},
            "all_findings": [_finding()],
            "changed_findings": [_finding()],
        }
    )

    finding = exported["all_findings"][0]
    changed = exported["changed_findings"][0]

    assert exported["tool_versions"] == {"nuclei": "3.2.0"}
    assert exported["comparison"]["comparison_mode"] == "full"
    assert finding["vulnerability_name"] == "SQL Injection"
    assert finding["description"] == "Scanner observed injectable input handling."
    assert finding["remediation"] == "Use parameterized queries."
    assert finding["found_by"] == ["zap", "nuclei"]
    assert finding["meta"]["scanner"] == "nuclei"
    assert finding["meta"]["cve_id"] == "CVE-2024-1111"
    assert finding["meta"]["cve_ids"] == ["CVE-2024-1111"]
    assert finding["meta"]["cvss"] == 8.1
    assert finding["source_findings"][0]["references"] == ["https://scanner.example/zap"]
    assert changed["status"] == "CHANGED"
    assert changed["changed_fields"] == ["severity"]
    assert "change_details" not in changed


def test_sanitize_results_for_export_preserves_only_safe_structured_correlation():
    correlation = {
        "status": "merged",
        "source": "llm",
        "confidence": 0.92,
        "reason": "Same endpoint, method and vulnerable parameter",
        "canonical_title": "SQL Injection in application lookup",
        "needs_review": True,
        "review_candidates": [
            {
                "finding_id": "finding-b",
                "vulnerability_name": "Potential SQL Injection",
                "scanners": ["wapiti"],
                "confidence": 0.81,
                "reason": "Same path but weaker parameter evidence",
                "canonical_title": "Potential SQL Injection in lookup",
                "provider_payload": {"must": "not leak"},
            }
        ],
        "raw_response": "must not leak",
    }
    exported = sanitize_results_for_export(
        {"all_findings": [_finding(correlation=correlation)]}
    )

    assert exported["all_findings"][0]["correlation"] == {
        "status": "merged",
        "source": "llm",
        "confidence": 0.92,
        "reason": "Same endpoint, method and vulnerable parameter",
        "canonical_title": "SQL Injection in application lookup",
        "needs_review": True,
        "review_candidates": [
            {
                "finding_id": "finding-b",
                "vulnerability_name": "Potential SQL Injection",
                "scanners": ["wapiti"],
                "confidence": 0.81,
                "reason": "Same path but weaker parameter evidence",
                "canonical_title": "Potential SQL Injection in lookup",
            }
        ],
    }


def test_sanitize_results_preserves_strict_ai_advice_and_safe_summary():
    finding = _finding(
        ai_analysis_status="completed",
        applicability={
            "status": "likely_valid",
            "confidence": 0.88,
            "reason": "The endpoint and parameter are identified.",
            "evidence_ids": ["finding-description", "finding-evidence"],
        },
        ai_remediation={
            "steps": ["Use parameterized queries."],
            "verification": ["Repeat the request with safe SQL metacharacters."],
        },
    )
    exported = sanitize_results_for_export(
        {
            "all_findings": [finding],
            "ai_analysis_summary": {
                "status": "completed",
                "model": "demo-model",
                "prompt_version": "finding-analysis-v1",
                "limit": 10,
                "selected_count": 1,
                "analyzed_count": 1,
                "cached_count": 0,
                "unavailable_count": 0,
                "skipped_limit_count": 0,
                "needs_review_count": 0,
                "redaction_count": 2,
                "latency_ms": 125.6789,
                "prompt_tokens": 120,
                "completion_tokens": 42,
                "total_tokens": 162,
                "estimated_cost_usd": 0.00123456789,
                "provider_debug": {"secret": "must not leak"},
            },
        }
    )

    cleaned = exported["all_findings"][0]
    assert cleaned["ai_analysis_status"] == "completed"
    assert cleaned["applicability"]["confidence"] == 0.88
    assert cleaned["ai_remediation"]["steps"] == ["Use parameterized queries."]
    assert exported["ai_analysis_summary"] == {
        "status": "completed",
        "model": "demo-model",
        "prompt_version": "finding-analysis-v1",
        "limit": 10,
        "selected_count": 1,
        "analyzed_count": 1,
        "cached_count": 0,
        "unavailable_count": 0,
        "skipped_limit_count": 0,
        "needs_review_count": 0,
        "redaction_count": 2,
        "prompt_tokens": 120,
        "completion_tokens": 42,
        "total_tokens": 162,
        "latency_ms": 125.679,
        "estimated_cost_usd": 0.00123457,
    }


def test_sanitize_results_drops_malformed_ai_advice_instead_of_leaking_it():
    exported = sanitize_results_for_export(
        {
            "all_findings": [
                _finding(
                    ai_analysis_status="completed",
                    applicability={
                        "status": "likely_valid",
                        "confidence": 4.2,
                        "reason": "bad confidence",
                        "evidence_ids": ["finding-description"],
                        "raw_provider_payload": "must not leak",
                    },
                    ai_remediation={
                        "steps": ["Do something"],
                        "verification": ["Verify it"],
                    },
                )
            ],
            "ai_analysis_summary": {"status": "invented", "raw": "must not leak"},
        }
    )

    finding = exported["all_findings"][0]
    assert "ai_analysis_status" not in finding
    assert "applicability" not in finding
    assert "ai_remediation" not in finding
    assert "ai_analysis_summary" not in exported


def test_sanitize_results_whitelists_public_site_context_and_drops_local_paths():
    exported = sanitize_results_for_export(
        {
            "all_findings": [],
            "asset_knowledge": {
                "description": "Public appointment portal",
                "reviewer": "demo-user",
                "profile_revision": "a" * 64,
                "analysis_source": "llm",
                "business_processes": ["Appointment booking"],
                "risk_context": {
                    "asset_criticality": "medium",
                    "environment": "production",
                    "sensitive_data": None,
                    "requires_auth": True,
                    "confidence": 0.72,
                    "reason": "The public pages link to sign-in and booking flows.",
                    "evidence_ids": ["page-1"],
                },
                "bundle_path": "/home/private/data/asset_knowledge/example",
                "profile_path": "/home/private/data/asset_knowledge/example/profile.md",
                "raw_osint": {"authorization": "Bearer secret-token"},
                "unexpected": "must not reach the UI",
            },
        }
    )

    assert exported["asset_knowledge"] == {
        "description": "Public appointment portal",
        "reviewer": "demo-user",
        "profile_revision": "a" * 64,
        "analysis_source": "llm",
        "business_processes": ["Appointment booking"],
        "risk_context": {
            "asset_criticality": "medium",
            "environment": "production",
            "sensitive_data": None,
            "requires_auth": True,
            "confidence": 0.72,
            "reason": "The public pages link to sign-in and booking flows.",
            "evidence_ids": ["page-1"],
        },
    }
