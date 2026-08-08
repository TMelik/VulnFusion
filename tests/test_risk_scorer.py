import pytest

from utils.risk_scorer import (
    _get_confidence,
    _has_known_exploit,
    assign_priority_bucket,
    calculate_risk_score,
)


def _finding(meta: dict, **extra) -> dict:
    return {
        "vulnerability_name": "Test",
        "severity": "medium",
        "asset_id": "https://example.com",
        "description": "Test finding",
        "remediation": "Fix it",
        "meta": meta,
        **extra,
    }


@pytest.mark.parametrize(
    ("meta", "expected"),
    [
        ({"references": ["https://www.exploit-db.com/exploits/12345"]}, True),
        ({"reference": "See https://metasploit.com/modules/exploit/x"}, True),
        ({"reference": "https://github.com/user/poc-exploit"}, True),
        ({"references": ["https://docs.example.com/poc/usage-guide"]}, False),
        ({"exploit_available": True}, True),
        ({"exploit_db": "https://www.exploit-db.com/exploits/99999"}, True),
        ({"references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-1234"]}, False),
        ({}, False),
    ],
)
def test_has_known_exploit(meta, expected):
    assert _has_known_exploit(_finding(meta)) is expected


@pytest.mark.parametrize(
    ("confidence", "expected"),
    [
        ("high", "high"),
        ("certain", "high"),
        ("confirmed", "high"),
        ("low", "low"),
        ("tentative", "low"),
        ("possible", "low"),
        (3, "high"),
        ("3", "high"),
        (2, "medium"),
        ("2", "medium"),
        (1, "low"),
        ("1", "low"),
        (0, "low"),
        ("0", "low"),
        ("unknown_garbage", "medium"),
        (True, "medium"),
    ],
)
def test_get_confidence(confidence, expected):
    assert _get_confidence(_finding({"confidence": confidence})) == expected


def test_get_confidence_defaults_to_medium():
    assert _get_confidence(_finding({})) == "medium"


def test_calculate_risk_score_prefers_cvss_v4_and_applies_epss_and_kev():
    finding = _finding(
        {
            "cvss_v4_score": 9.8,
            "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "epss_score": 0.72,
            "epss_percentile": 0.99,
            "kev_listed": True,
            "kev_source": "CISA KEV",
            "kev_due_date": "2026-05-01",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
            },
        },
        severity="low",
        asset_id="https://payments.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P0"
    assert result["risk_factors"]["severity_source"] == "CVSS v4.0"
    assert result["risk_factors"]["epss_used"] is True
    assert result["risk_factors"]["kev_used"] is True
    assert result["risk_factors"]["active_exploitation"]["floor_score"] == 85
    assert finding["meta"]["cvss_score"] == 9.8
    assert finding["meta"]["cvss_version"] == "4.0"
    assert finding["meta"]["kev_listed"] is True


def test_calculate_risk_score_uses_cvss_v31_when_v4_missing():
    finding = _finding(
        {
            "cvss": 8.8,
            "epss_score": 0.20,
            "epss_percentile": 0.92,
        },
        asset_id="https://app.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["severity_source"] == "CVSS v3.1"
    assert result["risk_factors"]["epss_used"] is True
    assert result["risk_factors"]["kev_used"] is False
    assert result["priority"] == "P1"
    assert result["risk_factors"]["exploit_likelihood"] == 3


def test_calculate_risk_score_falls_back_to_scanner_severity_without_cvss():
    finding = _finding(
        {},
        severity="high",
        asset_id="https://portal.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["severity_source"] == "scanner severity fallback"
    assert result["risk_factors"]["technical_severity"] == 49
    assert result["risk_score"] >= 40


def test_cve_identifier_alone_does_not_change_score_without_intel():
    without_cve = _finding({}, severity="high", asset_id="https://portal.example.com")
    with_cve = _finding({"cve_id": "CVE-2024-1234"}, severity="high", asset_id="https://portal.example.com")

    result_without_cve = calculate_risk_score(without_cve)
    result_with_cve = calculate_risk_score(with_cve)

    assert result_with_cve["risk_score"] == result_without_cve["risk_score"]
    assert result_with_cve["priority"] == result_without_cve["priority"]
    assert result_with_cve["risk_factors"]["severity_source"] == result_without_cve["risk_factors"]["severity_source"]


def test_kev_finding_is_floored_to_at_least_p1():
    finding = _finding(
        {
            "kev_listed": True,
        },
        severity="low",
        asset_id="10.0.0.10",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P1"
    assert result["risk_score"] >= 70


def test_kev_exposed_critical_asset_becomes_p0():
    finding = _finding(
        {
            "kev_listed": True,
            "business_context": {
                "asset_criticality": "high",
            },
        },
        severity="low",
        asset_id="https://auth.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P0"
    assert result["risk_score"] >= 85


def test_kev_production_only_stays_below_p0():
    finding = _finding(
        {
            "kev_listed": True,
            "business_context": {
                "environment": "production",
                "internet_exposed": False,
            },
        },
        severity="low",
        asset_id="10.0.0.15",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P1"
    assert result["risk_score"] >= 70
    assert result["risk_score"] < 80


def test_kev_internet_exposed_becomes_p0_without_other_context():
    finding = _finding(
        {
            "kev_listed": True,
        },
        severity="low",
        asset_id="https://edge.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P0"
    assert result["risk_score"] >= 85


def test_kev_high_criticality_and_production_becomes_p0():
    finding = _finding(
        {
            "kev_listed": True,
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
                "internet_exposed": False,
            },
        },
        severity="low",
        asset_id="10.10.10.10",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P0"
    assert result["risk_score"] >= 85


@pytest.mark.parametrize("scanner", ["zap", "wapiti", "nikto"])
def test_non_cve_web_finding_uses_fallback_model(scanner):
    finding = _finding(
        {
            "scanner": scanner,
            "confidence": "high",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
                "sensitive_data": True,
                "requires_auth": False,
            },
        },
        severity="high",
        asset_id="https://public.example.com/login",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["severity_source"] == "scanner severity fallback"
    assert result["risk_factors"]["epss_used"] is False
    assert result["risk_factors"]["kev_used"] is False
    assert result["priority"] in {"P0", "P1"}


def test_low_confidence_serious_finding_is_reduced_only_moderately():
    finding = _finding(
        {
            "confidence": "low",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
            },
        },
        severity="critical",
        asset_id="https://api.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["evidence_quality_inputs"]["confidence"] == "low"
    assert result["risk_factors"]["confidence_adjustment"] == -5
    assert result["risk_score"] >= 60
    assert result["priority"] in {"P0", "P1"}


def test_canonical_meta_fields_overwrite_stale_values():
    finding = _finding(
        {
            "cvss_score": 1.0,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N",
            "cvss_v4_score": 9.3,
            "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L",
            "epss_score": 0.01,
            "epss": 0.84,
            "epss_percentile": 0.22,
            "kev_listed": True,
            "kev_source": "Old Source",
            "kev_due_date": "2020-01-01",
            "kev": {"listed": False},
        }
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["severity_source"] == "CVSS v4.0"
    assert finding["meta"]["cvss_score"] == 9.3
    assert finding["meta"]["cvss_version"] == "4.0"
    assert finding["meta"]["cvss_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L"
    assert finding["meta"]["epss_score"] == 0.84
    assert finding["meta"]["epss_percentile"] == 0.22
    assert finding["meta"]["kev_listed"] is False
    assert "kev_source" not in finding["meta"]
    assert "kev_due_date" not in finding["meta"]


def test_explicit_internet_exposed_false_is_respected():
    finding = _finding(
        {
            "business_context": {
                "internet_exposed": False,
            },
        },
        severity="high",
        asset_id="https://public.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["business_context_inputs"]["internet_exposed"] is False
    assert result["risk_factors"]["internet_exposed"] == 0


def test_degraded_finding_lowers_confidence_and_risk_score():
    clean = _finding(
        {
            "scanner": "nikto",
            "confidence": "high",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
            },
        },
        severity="high",
        asset_id="https://example.com/admin",
    )
    degraded = _finding(
        {
            "scanner": "nikto",
            "confidence": "high",
            "degraded_execution": True,
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
            },
        },
        severity="high",
        asset_id="https://example.com/admin",
    )

    clean_result = calculate_risk_score(clean)
    degraded_result = calculate_risk_score(degraded)

    assert clean_result["risk_score"] > degraded_result["risk_score"]
    assert degraded_result["risk_factors"]["evidence_quality_inputs"]["degraded_execution"] is True
    assert degraded_result["risk_factors"]["degraded_execution_adjustment"] < 0
    assert degraded["meta"]["evidence_quality"]["confidence"] == "low"


def test_unauthenticated_description_is_not_mistaken_for_auth_required():
    finding = _finding(
        {"confidence": "high"},
        vulnerability_name="Remote Code Execution",
        severity="critical",
        description="Unauthenticated remote code execution in the web admin console.",
        asset_id="https://admin.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["requires_auth"] == 0
    assert result["risk_factors"]["business_context_inputs"]["requires_auth"] is False
    assert "authentication required" not in result["risk_rationale"]


def test_confirmed_global_requires_auth_context_overrides_text_heuristic():
    finding = _finding(
        {"confidence": "high"},
        vulnerability_name="Administrative endpoint exposed",
        severity="high",
        description="The administrative endpoint appears reachable without authentication.",
        asset_id="https://admin.example.com",
    )

    result = calculate_risk_score(finding, {"requires_auth": True})

    assert result["risk_factors"]["business_context_inputs"]["requires_auth"] is True
    assert result["risk_factors"]["requires_auth"] < 0
    assert "authentication required" in result["risk_rationale"]


def test_low_signal_header_finding_stays_low_priority_even_with_strong_context():
    finding = _finding(
        {
            "confidence": "high",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
                "sensitive_data": True,
            },
        },
        vulnerability_name="Server Header Exposed",
        severity="info",
        description="The response includes the default Server header.",
        asset_id="https://prod.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P4"
    assert result["risk_score"] < 20
    assert result["risk_factors"]["business_context_cap"] == 12
    assert result["risk_factors"]["business_context_raw"] > result["risk_factors"]["business_context"]
    assert "low-signal contextual cap +12" in result["risk_factors"]["business_context_applied"]


def test_high_severity_header_finding_is_capped_below_high_priority():
    finding = _finding(
        {
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
                "sensitive_data": True,
            },
        },
        vulnerability_name="X-Powered-By Header Present",
        severity="high",
        description="The X-Powered-By header reveals the technology stack.",
        asset_id="https://prod.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P3"
    assert result["risk_score"] == 35
    assert result["risk_factors"]["low_signal_cap"] == 35
    assert result["risk_factors"]["low_signal_cap_applied"] > 0
    assert "Scoring guardrail:" in result["risk_rationale"]


def test_exploitable_class_outranks_low_signal_contextual_issue():
    high_risk = _finding(
        {
            "confidence": "high",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
            },
        },
        vulnerability_name="SQL Injection",
        severity="medium",
        description="Authenticated SQL injection after login.",
        asset_id="10.0.0.5",
    )
    low_signal = _finding(
        {
            "confidence": "high",
            "business_context": {
                "asset_criticality": "high",
                "environment": "production",
                "sensitive_data": True,
            },
        },
        vulnerability_name="Server Header Exposed",
        severity="info",
        description="The response includes the default Server header.",
        asset_id="https://prod.example.com",
    )

    high_result = calculate_risk_score(high_risk)
    low_result = calculate_risk_score(low_signal)

    assert high_result["risk_score"] > low_result["risk_score"]
    assert high_result["priority"] in {"P2", "P1", "P0"}
    assert low_result["priority"] == "P4"


def test_public_remote_code_execution_reaches_p0_without_cvss():
    finding = _finding(
        {"confidence": "high"},
        vulnerability_name="Remote Code Execution",
        severity="critical",
        description="Unauthenticated remote code execution in the public admin console.",
        asset_id="https://admin.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P0"
    assert result["risk_score"] >= 85


def test_medium_authenticated_sqli_uses_class_floor_and_stays_above_low_signal_noise():
    finding = _finding(
        {"confidence": "high"},
        vulnerability_name="SQL Injection",
        severity="medium",
        description="Authenticated SQL injection after login.",
        asset_id="10.0.0.5",
    )

    result = calculate_risk_score(finding)

    assert result["priority"] == "P2"
    assert result["risk_score"] >= 50
    assert result["risk_factors"]["technical_floor"] == 60
    assert result["risk_factors"]["technical_floor_applied"] > 0
    assert "class floor" in result["risk_rationale"]


def test_public_exploit_evidence_is_only_mentioned_when_it_changes_score():
    finding = _finding(
        {
            "confidence": "high",
            "references": ["https://www.exploit-db.com/exploits/12345"],
        },
        vulnerability_name="Path Traversal",
        severity="medium",
        description="Path traversal with public PoC.",
        asset_id="https://files.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["known_exploit"] == 8
    assert "public exploit evidence -> floor +8" in result["risk_rationale"]


def test_risk_rationale_mentions_real_drivers_only():
    finding = _finding(
        {"confidence": "high"},
        vulnerability_name="SQL Injection",
        severity="high",
        description="SQL injection in the login form.",
        asset_id="https://auth.example.com",
    )

    result = calculate_risk_score(finding)
    rationale = result["risk_rationale"]

    assert "Technical severity:" in rationale
    assert "SQL injection class" in rationale
    assert "Exposure and reachability:" in rationale
    assert "Exploit likelihood:" not in rationale
    assert "Active exploitation:" not in rationale
    assert "KEV not present" not in rationale


def test_missing_confidence_is_neutral_and_not_called_out_in_rationale():
    finding = _finding(
        {},
        vulnerability_name="Generic Finding",
        severity="high",
        description="A generic high-severity finding without an explicit confidence label.",
        asset_id="https://portal.example.com",
    )

    result = calculate_risk_score(finding)

    assert result["risk_factors"]["confidence_adjustment"] == 0
    assert result["risk_factors"]["evidence_quality_inputs"]["confidence"] == "medium"
    assert result["risk_factors"]["evidence_quality_inputs"]["confidence_provided"] is False
    assert "Evidence quality:" not in result["risk_rationale"]


def test_priority_bucket_boundaries_are_stable():
    assert assign_priority_bucket(0) == "P4"
    assert assign_priority_bucket(24) == "P4"
    assert assign_priority_bucket(25) == "P3"
    assert assign_priority_bucket(44) == "P3"
    assert assign_priority_bucket(45) == "P2"
    assert assign_priority_bucket(64) == "P2"
    assert assign_priority_bucket(65) == "P1"
    assert assign_priority_bucket(84) == "P1"
    assert assign_priority_bucket(85) == "P0"
    assert assign_priority_bucket(100) == "P0"


def test_mixed_findings_order_consistency_matches_risk_intuition():
    findings = [
        _finding(
            {"confidence": "high"},
            vulnerability_name="Server Header Exposed",
            severity="info",
            description="The response includes the default Server header.",
            asset_id="https://prod.example.com",
        ),
        _finding(
            {"confidence": "high"},
            vulnerability_name="SQL Injection",
            severity="medium",
            description="Authenticated SQL injection after login.",
            asset_id="10.0.0.5",
        ),
        _finding(
            {"confidence": "high"},
            vulnerability_name="Remote Code Execution",
            severity="critical",
            description="Unauthenticated remote code execution in the public admin console.",
            asset_id="https://admin.example.com",
        ),
    ]

    scored = [calculate_risk_score(finding) for finding in findings]

    assert scored[2]["risk_score"] > scored[1]["risk_score"] > scored[0]["risk_score"]
    assert scored[2]["priority"] == "P0"
    assert scored[1]["priority"] == "P2"
    assert scored[0]["priority"] == "P4"
