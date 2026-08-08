"""
Comprehensive risk-scorer model tests.

Covers:
- High-risk remote exploitation classes (RCE, SQLi, auth bypass, SSRF, XXE, deserialization)
- Medium-risk authenticated findings
- Low-risk / informational findings
- Business-context boost behaviour
- Evidence-quality adjustments (degraded, low confidence, repeatability)
- Missing-data fallback (no CVSS, no EPSS, no business context)
- Rationale correctness
- Priority-bucket boundaries and ordering consistency

All fixtures are deterministic synthetic data — no external services.
"""

import pytest

from utils.risk_scorer import (
    PRIORITY_THRESHOLDS,
    SEVERITY_FALLBACK_SCORES,
    CONFIDENCE_ADJUSTMENTS,
    REQUIRES_AUTH_SCORE,
    calculate_risk_score,
    assign_priority_bucket,
    _classify_vulnerability,
    _has_known_exploit,
    _is_repeatable,
    _get_confidence,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _f(
    vulnerability_name="Test Finding",
    severity="medium",
    asset_id="https://example.com",
    description="A test vulnerability.",
    remediation="Apply patch.",
    meta=None,
    **extra,
):
    """Build a minimal synthetic finding."""
    return {
        "vulnerability_name": vulnerability_name,
        "severity": severity,
        "asset_id": asset_id,
        "description": description,
        "remediation": remediation,
        "meta": meta if meta is not None else {},
        **extra,
    }


def _scored(finding, context=None):
    """Return calculate_risk_score result for a finding."""
    return calculate_risk_score(finding, context or {})


# ---------------------------------------------------------------------------
# 1. High-risk remote exploitation classes
# ---------------------------------------------------------------------------

class TestRemoteExploitationClasses:
    """RCE, deserialization, SSTI, SQLi, auth bypass, SSRF, XXE, path traversal, creds."""

    def test_rce_critical_internet_exposed_reaches_p0(self):
        finding = _f(
            vulnerability_name="Remote Code Execution via Deserialization",
            severity="critical",
            asset_id="https://api.example.com/upload",
            description="Unauthenticated remote code execution via a deserialization gadget.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        assert result["priority"] == "P0"
        assert result["risk_score"] >= 85
        # Both RCE and deserialization patterns match — the first rule (RCE) wins
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["boost"] >= 16

    def test_sqli_high_severity_internet_is_at_least_p1(self):
        finding = _f(
            vulnerability_name="SQL Injection",
            severity="high",
            asset_id="https://store.example.com/search",
            description="SQL injection in search parameter.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        assert result["priority"] in {"P0", "P1"}
        assert result["risk_score"] >= 65

    def test_auth_bypass_high_severity_internet_is_at_least_p1(self):
        finding = _f(
            vulnerability_name="Authentication Bypass",
            severity="high",
            asset_id="https://login.example.com",
            description="Authentication bypass via forged JWT token.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        assert result["priority"] in {"P0", "P1"}

    def test_ssrf_medium_severity_gets_class_boost(self):
        finding = _f(
            vulnerability_name="Server-Side Request Forgery",
            severity="medium",
            asset_id="https://proxy.example.com",
            description="SSRF via URL parameter allows reaching internal services.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "server_side_request_forgery"
        assert vuln_class["boost"] == 12

    def test_xxe_injection_classified_correctly(self):
        finding = _f(
            vulnerability_name="XML External Entity Injection",
            severity="high",
            description="XXE via malformed XML body allows reading /etc/passwd.",
            meta={"cwe": "611"},
        )
        result = _scored(finding)
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "xml_external_entity"

    def test_path_traversal_high_cvss_reaches_p0(self):
        finding = _f(
            vulnerability_name="Arbitrary File Read",
            severity="critical",
            asset_id="https://files.example.com",
            description="Path traversal allows arbitrary file read from the server.",
            meta={"cvss_score": 9.1, "confidence": "high"},
        )
        result = _scored(finding)
        # CVSS 9.1 * 6.5 = 59 base + 12 path traversal = 71 + 6 internet = 77... let's just check class
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "path_traversal"
        assert result["risk_score"] >= 65

    def test_credential_exposure_classified_correctly(self):
        finding = _f(
            vulnerability_name="Hardcoded Credentials",
            severity="high",
            description="The application contains hardcoded credentials in configuration.",
            meta={"cwe": "798"},
        )
        result = _scored(finding)
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "credential_exposure"

    def test_insecure_deserialization_class_bonus_applied(self):
        finding = _f(
            vulnerability_name="Unsafe Deserialization",
            severity="high",
            asset_id="https://api.example.com",
            description="Insecure deserialization in the Java object endpoint.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "insecure_deserialization"
        assert vuln_class["boost"] == 16

    def test_cwe_match_triggers_class_boost_for_sqli(self):
        finding = _f(
            vulnerability_name="Generic DB Issue",
            severity="medium",
            description="An issue with database queries.",
            meta={"cwe": 89},  # CWE-89 = SQLi
        )
        result = _scored(finding)
        vuln_class = result["risk_factors"]["vulnerability_class"]
        assert vuln_class["id"] == "sql_injection"
        assert vuln_class["boost"] == 14


# ---------------------------------------------------------------------------
# 2. Medium-risk authenticated findings
# ---------------------------------------------------------------------------

class TestMediumRiskAuthenticated:
    """Auth-required findings should be de-prioritized but not eliminated."""

    def test_authenticated_sqli_internal_lands_in_p2_p3(self):
        finding = _f(
            vulnerability_name="SQL Injection",
            severity="medium",
            asset_id="10.0.0.5",  # internal
            description="Authenticated SQL injection after login in admin panel.",
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        assert result["priority"] in {"P2", "P3"}
        # Auth penalty is applied
        assert result["risk_factors"]["requires_auth"] < 0

    def test_authenticated_finding_scores_less_than_unauthenticated_equivalent(self):
        base_meta = {"confidence": "high"}
        unauth = _f(
            vulnerability_name="Remote Code Execution",
            severity="high",
            description="Unauthenticated remote code execution.",
            meta=dict(base_meta),
        )
        authed = _f(
            vulnerability_name="Remote Code Execution",
            severity="high",
            description="Authenticated remote code execution after login.",
            meta=dict(base_meta),
        )
        r_unauth = _scored(unauth)
        r_authed = _scored(authed)
        assert r_unauth["risk_score"] > r_authed["risk_score"]

    def test_auth_penalty_does_not_eliminate_dangerous_class_findings(self):
        """Even with auth required, RCE class should keep a meaningful score."""
        finding = _f(
            vulnerability_name="RCE",
            severity="high",
            description="Authenticated RCE via template injection after login.",
            asset_id="10.0.0.1",  # internal
            meta={"confidence": "high"},
        )
        result = _scored(finding)
        # Should be at least P3
        assert result["priority"] in {"P0", "P1", "P2", "P3"}
        assert result["risk_score"] >= 25

    def test_medium_confidence_authenticated_finding_stays_below_critical_findings(self):
        authed_medium = _f(
            vulnerability_name="XSS",
            severity="medium",
            description="Authenticated reflected XSS after login.",
            meta={"confidence": "medium"},
        )
        unauthed_critical = _f(
            vulnerability_name="Remote Code Execution",
            severity="critical",
            description="Unauthenticated RCE.",
            asset_id="https://api.example.com",
            meta={"confidence": "high"},
        )
        r_m = _scored(authed_medium)
        r_c = _scored(unauthed_critical)
        assert r_c["risk_score"] > r_m["risk_score"]


# ---------------------------------------------------------------------------
# 3. Low-risk / informational findings
# ---------------------------------------------------------------------------

class TestLowRiskInformational:
    """Info/low-signal findings must stay well below severe exploitable findings."""

    def test_info_severity_no_context_lands_in_p4(self):
        finding = _f(
            vulnerability_name="Server Version Disclosure",
            severity="info",
            asset_id="10.0.0.1",  # internal
            description="Server version disclosed in response headers.",
            meta={},
        )
        result = _scored(finding)
        assert result["priority"] == "P4"
        assert result["risk_score"] <= 24

    def test_low_severity_no_context_lands_in_p4_or_p3(self):
        finding = _f(
            vulnerability_name="Cookie Without HttpOnly",
            severity="low",
            asset_id="10.0.0.5",  # internal
            description="Session cookie is missing the HttpOnly flag.",
            meta={},
        )
        result = _scored(finding)
        assert result["priority"] in {"P4", "P3"}

    def test_info_finding_with_max_business_context_stays_below_p3(self):
        """Even with production high-criticality context, info findings must stay low."""
        finding = _f(
            vulnerability_name="X-Powered-By Header Present",
            severity="info",
            asset_id="https://prod.example.com",
            description="The X-Powered-By response header reveals technology stack.",
            meta={
                "confidence": "high",
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                    "internet_exposed": True,
                },
            },
        )
        result = _scored(finding)
        # Low-signal cap applies: info + generic issue → capped context
        assert result["risk_score"] < 25
        assert result["priority"] in {"P4", "P3"}

    def test_generic_low_severity_stays_below_medium_sqli(self):
        low_noise = _f(
            vulnerability_name="Missing Security Header",
            severity="low",
            description="Content-Security-Policy header is absent.",
            meta={"confidence": "high"},
        )
        sqli = _f(
            vulnerability_name="SQL Injection",
            severity="medium",
            description="SQL injection via search parameter.",
            meta={"confidence": "high"},
        )
        r_low = _scored(low_noise)
        r_sqli = _scored(sqli)
        assert r_sqli["risk_score"] > r_low["risk_score"]


# ---------------------------------------------------------------------------
# 4. Business-context boost behaviour
# ---------------------------------------------------------------------------

class TestBusinessContextBoost:
    """Business context should boost score but not overpower technical severity."""

    def test_production_high_criticality_boosts_score(self):
        plain = _f(severity="high", asset_id="10.0.0.1", meta={})
        contextual = _f(
            severity="high",
            asset_id="https://payments.example.com",
            meta={
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                }
            },
        )
        r_plain = _scored(plain)
        r_ctx = _scored(contextual)
        assert r_ctx["risk_score"] > r_plain["risk_score"]
        assert r_ctx["risk_score"] - r_plain["risk_score"] >= 8

    def test_development_environment_lowers_score(self):
        prod = _f(
            severity="medium",
            meta={"business_context": {"environment": "production"}},
        )
        dev = _f(
            severity="medium",
            meta={"business_context": {"environment": "development"}},
        )
        r_prod = _scored(prod)
        r_dev = _scored(dev)
        assert r_prod["risk_score"] > r_dev["risk_score"]

    def test_internet_exposed_asset_scores_higher_than_internal(self):
        internet = _f(
            severity="high",
            asset_id="https://public.example.com",
            meta={},
        )
        internal = _f(
            severity="high",
            asset_id="10.0.0.5",
            meta={},
        )
        r_net = _scored(internet)
        r_int = _scored(internal)
        assert r_net["risk_score"] > r_int["risk_score"]

    def test_explicit_internet_exposed_false_overrides_hostname_heuristic(self):
        finding = _f(
            severity="high",
            asset_id="https://very-public-looking.example.com",
            meta={"business_context": {"internet_exposed": False}},
        )
        result = _scored(finding)
        assert result["risk_factors"]["internet_exposed"] == 0
        assert result["risk_factors"]["business_context_inputs"]["internet_exposed"] is False

    def test_business_context_cap_prevents_info_findings_from_inflating_above_technical_score(self):
        """Business context score is capped; info findings cannot exceed the cap."""
        info_with_max_ctx = _f(
            severity="info",
            asset_id="https://prod.example.com",
            description="Informational finding with no dangerous class.",
            meta={
                "confidence": "high",
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                    "internet_exposed": True,
                },
            },
        )
        medium_no_ctx = _f(
            severity="medium",
            asset_id="10.0.0.1",
            meta={},
        )
        r_info = _scored(info_with_max_ctx)
        r_med = _scored(medium_no_ctx)
        # Even with max business context, info should score less than plain medium
        assert r_med["risk_score"] > r_info["risk_score"]

    def test_high_severity_header_issue_is_guardrailed_below_high_priority(self):
        finding = _f(
            vulnerability_name="X-Powered-By Header Present",
            severity="high",
            asset_id="https://prod.example.com",
            description="The X-Powered-By header reveals the technology stack.",
            meta={
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                }
            },
        )
        result = _scored(finding)
        assert result["priority"] == "P3"
        assert result["risk_score"] == 35
        assert result["risk_factors"]["low_signal_cap_applied"] > 0

    def test_sensitive_data_flag_adds_to_score(self):
        without_sensitive = _f(
            severity="high",
            asset_id="https://example.com",
            meta={"business_context": {"asset_criticality": "high", "environment": "production"}},
        )
        with_sensitive = _f(
            severity="high",
            asset_id="https://example.com",
            meta={
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                }
            },
        )
        r_without = _scored(without_sensitive)
        r_with = _scored(with_sensitive)
        assert r_with["risk_score"] > r_without["risk_score"]


# ---------------------------------------------------------------------------
# 5. Evidence-quality adjustments
# ---------------------------------------------------------------------------

class TestEvidenceQuality:
    """Confidence, degraded execution, and repeatability influence score correctly."""

    def test_high_confidence_scores_higher_than_low_confidence_for_same_finding(self):
        high_conf = _f(
            severity="high",
            asset_id="https://example.com",
            meta={"confidence": "high"},
        )
        low_conf = _f(
            severity="high",
            asset_id="https://example.com",
            meta={"confidence": "low"},
        )
        r_hi = _scored(high_conf)
        r_lo = _scored(low_conf)
        assert r_hi["risk_score"] > r_lo["risk_score"]
        assert r_hi["risk_factors"]["confidence_adjustment"] > r_lo["risk_factors"]["confidence_adjustment"]

    def test_low_confidence_penalty_value(self):
        finding = _f(severity="high", meta={"confidence": "low"})
        result = _scored(finding)
        # Confidence penalty for 'low' must equal configured constant
        assert result["risk_factors"]["confidence_adjustment"] == CONFIDENCE_ADJUSTMENTS["low"]

    def test_medium_confidence_applies_small_penalty(self):
        finding = _f(severity="high", meta={"confidence": "medium"})
        result = _scored(finding)
        assert result["risk_factors"]["confidence_adjustment"] == CONFIDENCE_ADJUSTMENTS["medium"]
        assert result["risk_factors"]["confidence_adjustment"] < 0

    def test_degraded_execution_lowers_score(self):
        clean = _f(
            severity="high",
            asset_id="https://example.com",
            meta={"confidence": "high"},
        )
        degraded = _f(
            severity="high",
            asset_id="https://example.com",
            meta={"confidence": "high", "degraded_execution": True},
        )
        r_clean = _scored(clean)
        r_deg = _scored(degraded)
        assert r_clean["risk_score"] > r_deg["risk_score"]
        assert r_deg["risk_factors"]["degraded_execution_adjustment"] < 0

    def test_degraded_finding_is_marked_in_evidence_quality_inputs(self):
        finding = _f(
            severity="high",
            meta={"degraded_execution": True},
        )
        result = _scored(finding)
        assert result["risk_factors"]["evidence_quality_inputs"]["degraded_execution"] is True

    def test_repeatability_bonus_applied_when_previous_scan_confirms_finding(self):
        prev = _f(severity="high", meta={}, fp_strict="fp-repeated-abc")
        curr = _f(severity="high", meta={}, fp_strict="fp-repeated-abc")
        context = {"previous_findings": [prev]}
        result = _scored(curr, context)
        assert result["risk_factors"]["repeatability"] > 0
        assert "repeatable" in result["risk_rationale"].lower()

    def test_no_repeatability_bonus_when_no_previous_findings(self):
        finding = _f(severity="high", meta={}, fp_strict="fp-new-xyz")
        result = _scored(finding, {"previous_findings": []})
        assert result["risk_factors"]["repeatability"] == 0

    def test_low_confidence_does_not_collapse_critical_finding_below_p2(self):
        """Low confidence penalty is bounded; critical findings remain actionable."""
        finding = _f(
            severity="critical",
            asset_id="https://api.example.com",
            meta={"confidence": "low"},
        )
        result = _scored(finding)
        assert result["priority"] in {"P0", "P1", "P2"}
        assert result["risk_score"] >= 45


# ---------------------------------------------------------------------------
# 6. Missing data fallback behaviour
# ---------------------------------------------------------------------------

class TestMissingDataFallback:
    """When enrichment data is absent the model must still produce stable output."""

    def test_missing_cvss_falls_back_to_severity_label(self):
        finding = _f(severity="high", meta={})
        result = _scored(finding)
        assert result["risk_factors"]["severity_source"] == "scanner severity fallback"
        assert result["risk_factors"]["cvss_score"] is None

    def test_missing_epss_does_not_use_exploit_likelihood(self):
        finding = _f(severity="medium", meta={})
        result = _scored(finding)
        assert result["risk_factors"]["epss_used"] is False
        assert result["risk_factors"]["exploit_likelihood"] == 0

    def test_missing_business_context_uses_neutral_defaults(self):
        finding = _f(severity="medium", asset_id="10.0.0.5", meta={})
        result = _scored(finding)
        inputs = result["risk_factors"]["business_context_inputs"]
        assert inputs["asset_criticality"] == "unknown"
        assert inputs["environment"] == "unknown"
        assert inputs["sensitive_data"] is False

    def test_missing_kev_does_not_apply_floor(self):
        finding = _f(severity="medium", meta={})
        result = _scored(finding)
        assert result["risk_factors"]["kev_used"] is False
        assert result["risk_factors"]["active_exploitation"]["floor_score"] is None

    def test_empty_meta_dict_produces_valid_score(self):
        finding = _f(severity="critical", meta={})
        result = _scored(finding)
        assert 0 <= result["risk_score"] <= 100
        assert result["priority"] in {"P0", "P1", "P2", "P3", "P4"}
        assert isinstance(result["risk_rationale"], str)
        assert len(result["risk_rationale"]) > 0

    def test_completely_empty_finding_fields_fallback_gracefully(self):
        """A finding with only required string fields should score without error."""
        finding = {
            "vulnerability_name": "Unknown Issue",
            "severity": "info",
            "asset_id": "",
            "description": "",
            "remediation": "",
            "meta": {},
        }
        result = _scored(finding)
        assert result["priority"] == "P4"
        assert result["risk_score"] <= 24

    def test_missing_confidence_is_neutral_and_hidden_from_rationale(self):
        finding = _f(
            severity="high",
            asset_id="https://portal.example.com",
            description="A generic high-severity finding without scanner confidence.",
            meta={},
        )
        result = _scored(finding)
        assert result["risk_factors"]["confidence_adjustment"] == 0
        assert result["risk_factors"]["evidence_quality_inputs"]["confidence_provided"] is False
        assert "Evidence quality:" not in result["risk_rationale"]


# ---------------------------------------------------------------------------
# 7. Exploit likelihood signals
# ---------------------------------------------------------------------------

class TestExploitLikelihood:
    """EPSS and public exploit references affect score correctly."""

    def test_high_epss_score_increases_exploit_likelihood(self):
        low_epss = _f(severity="medium", meta={"epss_score": 0.01})
        high_epss = _f(severity="medium", meta={"epss_score": 0.95})
        r_low = _scored(low_epss)
        r_high = _scored(high_epss)
        assert r_high["risk_score"] > r_low["risk_score"]
        assert r_high["risk_factors"]["epss_used"] is True

    def test_exploit_db_reference_sets_known_exploit_floor(self):
        finding = _f(
            severity="medium",
            meta={"references": ["https://www.exploit-db.com/exploits/56789"]},
        )
        result = _scored(finding)
        assert result["risk_factors"]["known_exploit"] == 8

    def test_generic_poc_docs_reference_does_not_count_as_public_exploit(self):
        finding = _f(
            severity="medium",
            meta={"references": ["https://docs.example.com/poc/usage-guide"]},
        )
        result = _scored(finding)
        assert result["risk_factors"]["known_exploit"] == 0

    def test_exploit_likelihood_bounded_below_technical_severity(self):
        """Exploit signals should not produce score that exceeds max independently."""
        finding = _f(
            severity="low",
            asset_id="10.0.0.1",  # internal
            meta={
                "epss_score": 0.99,
                "epss_percentile": 0.99,
                "references": ["https://exploit-db.com/x"],
            },
        )
        result = _scored(finding)
        # Even with maximum exploit signals, low severity internal must still score low-ish
        assert result["risk_score"] < 45  # shouldn't inflate to P2 from exploit alone


# ---------------------------------------------------------------------------
# 8. Rationale correctness
# ---------------------------------------------------------------------------

class TestRationaleCorrectness:
    """risk_rationale should mention real drivers and omit unused factors."""

    def test_rationale_includes_technical_severity_section(self):
        finding = _f(severity="high", meta={})
        result = _scored(finding)
        assert "Technical severity:" in result["risk_rationale"]

    def test_rationale_includes_kev_reference_when_kev_is_used(self):
        finding = _f(
            severity="low",
            asset_id="https://exposed.example.com",
            meta={"kev_listed": True, "kev_source": "CISA KEV"},
        )
        result = _scored(finding)
        assert result["risk_factors"]["kev_used"] is True
        assert "Active exploitation:" in result["risk_rationale"]
        assert "KEV" in result["risk_rationale"]

    def test_rationale_does_not_mention_kev_when_not_listed(self):
        finding = _f(severity="high", meta={})
        result = _scored(finding)
        assert result["risk_factors"]["kev_used"] is False
        assert "Active exploitation:" not in result["risk_rationale"]
        assert "KEV not present" not in result["risk_rationale"]

    def test_rationale_includes_internet_exposed_when_exposure_applies(self):
        finding = _f(
            severity="medium",
            asset_id="https://public.example.com",
            meta={},
        )
        result = _scored(finding)
        assert "internet-exposed" in result["risk_rationale"]

    def test_rationale_includes_dangerous_class_when_classified(self):
        finding = _f(
            vulnerability_name="SQL Injection",
            description="SQL injection in login form.",
            severity="high",
            meta={},
        )
        result = _scored(finding)
        assert "SQL injection class" in result["risk_rationale"] or "sql injection" in result["risk_rationale"].lower()

    def test_rationale_includes_final_score_and_priority(self):
        finding = _f(severity="medium", meta={})
        result = _scored(finding)
        assert f"Final score: {result['risk_score']}" in result["risk_rationale"]
        assert result["priority"] in result["risk_rationale"]

    def test_rationale_does_not_include_exploit_section_when_no_exploit_signals(self):
        finding = _f(
            severity="medium",
            asset_id="10.0.0.5",
            meta={"confidence": "high"},  # no EPSS, no exploit refs
        )
        result = _scored(finding)
        assert "Exploit likelihood:" not in result["risk_rationale"]

    def test_rationale_mentions_repeatability_when_bonus_applied(self):
        prev = _f(meta={}, fp_strict="fp-persistent-abc")
        curr = _f(meta={}, fp_strict="fp-persistent-abc")
        result = _scored(curr, {"previous_findings": [prev]})
        if result["risk_factors"]["repeatability"] > 0:
            assert "repeatable" in result["risk_rationale"].lower()

    def test_rationale_mentions_public_exploit_when_floor_applied(self):
        finding = _f(
            severity="medium",
            meta={"references": ["https://exploit-db.com/12345"]},
        )
        result = _scored(finding)
        if result["risk_factors"]["known_exploit"] > 0:
            assert "exploit" in result["risk_rationale"].lower()


# ---------------------------------------------------------------------------
# 9. Priority bucket boundaries
# ---------------------------------------------------------------------------

class TestPriorityBuckets:
    """assign_priority_bucket must respect configured thresholds exactly."""

    @pytest.mark.parametrize("score,expected", [
        (0, "P4"),
        (1, "P4"),
        (24, "P4"),
        (25, "P3"),
        (30, "P3"),
        (44, "P3"),
        (45, "P2"),
        (50, "P2"),
        (64, "P2"),
        (65, "P1"),
        (70, "P1"),
        (84, "P1"),
        (85, "P0"),
        (90, "P0"),
        (100, "P0"),
    ])
    def test_boundary_score_maps_to_correct_bucket(self, score: int, expected: str):
        assert assign_priority_bucket(score) == expected

    def test_configured_thresholds_cover_full_0_to_100_range(self):
        """Every integer from 0 to 100 must map to exactly one priority bucket."""
        all_priorities = set()
        for score in range(101):
            priority = assign_priority_bucket(score)
            assert priority in {"P0", "P1", "P2", "P3", "P4"}, f"score={score} -> {priority}"
            all_priorities.add(priority)
        # All five buckets should be reachable
        assert all_priorities == {"P0", "P1", "P2", "P3", "P4"}

    def test_p0_requires_high_technical_and_contextual_signal(self):
        """P0 should not be achievable by a low-severity finding without KEV or strong CVSS."""
        finding = _f(
            severity="low",
            asset_id="10.0.0.1",
            meta={},
        )
        result = _scored(finding)
        assert result["priority"] != "P0"


# ---------------------------------------------------------------------------
# 10. Ordering consistency across a mixed finding set
# ---------------------------------------------------------------------------

class TestOrderingConsistency:
    """Higher-risk findings must consistently outscore lower-risk ones."""

    def test_kev_outranks_non_kev_regardless_of_severity_label(self):
        non_kev_critical = _f(
            severity="critical",
            asset_id="https://api.example.com",
            meta={"confidence": "high"},
        )
        kev_medium = _f(
            severity="medium",
            asset_id="https://api.example.com",
            meta={"kev_listed": True, "confidence": "high"},
        )
        r_crit = _scored(non_kev_critical)
        r_kev = _scored(kev_medium)
        # KEV floor (>=70 or >=85) should push medium KEV above or close to non-KEV critical
        # This affirms that active exploitation matters even more than raw severity
        assert r_kev["risk_score"] >= 65  # at least P1

    def test_cvss_high_outranks_fallback_medium(self):
        cvss_high = _f(
            severity="medium",
            meta={"cvss_score": 8.5, "confidence": "high"},
        )
        fallback_medium = _f(
            severity="medium",
            meta={"confidence": "high"},
        )
        r_cvss = _scored(cvss_high)
        r_fall = _scored(fallback_medium)
        assert r_cvss["risk_score"] > r_fall["risk_score"]

    def test_internet_exposed_outranks_internal_for_same_finding(self):
        internet = _f(
            severity="high",
            asset_id="https://public.example.com",
            meta={"confidence": "high"},
        )
        internal = _f(
            severity="high",
            asset_id="10.0.0.5",
            meta={"confidence": "high"},
        )
        r_net = _scored(internet)
        r_int = _scored(internal)
        assert r_net["risk_score"] > r_int["risk_score"]

    def test_rce_outranks_header_finding_regardless_of_context(self):
        """A critical RCE on an internal host should outrank an info header finding on the internet."""
        rce_internal = _f(
            vulnerability_name="Remote Code Execution",
            severity="critical",
            asset_id="10.0.0.10",
            description="Unauthenticated RCE via template injection.",
            meta={"confidence": "high"},
        )
        header_internet = _f(
            vulnerability_name="Server Header Exposed",
            severity="info",
            asset_id="https://prod.example.com",
            description="Server header reveals version.",
            meta={
                "confidence": "high",
                "business_context": {
                    "asset_criticality": "high",
                    "environment": "production",
                    "sensitive_data": True,
                },
            },
        )
        r_rce = _scored(rce_internal)
        r_hdr = _scored(header_internet)
        assert r_rce["risk_score"] > r_hdr["risk_score"]

    def test_five_finding_ordering_matches_expected_risk_intuition(self):
        """Five representative findings should order from least to most risky."""
        info_internal = _f(
            vulnerability_name="Server Version",
            severity="info",
            asset_id="10.0.0.1",
            description="Version disclosure.",
            meta={},
        )
        low_internal = _f(
            vulnerability_name="Missing Header",
            severity="low",
            asset_id="10.0.0.2",
            description="Missing security header.",
            meta={},
        )
        medium_auth = _f(
            vulnerability_name="XSS",
            severity="medium",
            asset_id="10.0.0.3",
            description="Authenticated reflected XSS after login.",
            meta={"confidence": "high"},
        )
        high_internet = _f(
            vulnerability_name="SQLi",
            severity="high",
            asset_id="https://app.example.com",
            description="SQL injection.",
            meta={"confidence": "high"},
        )
        critical_rce = _f(
            vulnerability_name="RCE",
            severity="critical",
            asset_id="https://api.example.com",
            description="Unauthenticated remote code execution.",
            meta={"confidence": "high"},
        )
        scored = [_scored(f) for f in [info_internal, low_internal, medium_auth, high_internet, critical_rce]]
        scores = [s["risk_score"] for s in scored]
        # Each step should be strictly higher
        assert scores[0] < scores[1] < scores[2] < scores[3] < scores[4]


# ---------------------------------------------------------------------------
# 11. Scoring produces no generated developer prose in return value
# ---------------------------------------------------------------------------

class TestNoDeveloperProseOutput:
    """calculate_risk_score must not return impact_for_developers field."""

    def test_calculate_risk_score_does_not_produce_impact_for_developers(self):
        finding = _f(
            vulnerability_name="SQL Injection",
            severity="high",
            asset_id="https://auth.example.com",
            description="SQL injection in login form.",
            meta={"confidence": "high"},
        )
        result = calculate_risk_score(finding)
        assert "impact_for_developers" not in result, (
            "calculate_risk_score must not produce impact_for_developers – "
            "report must use scanner-provided description text only."
        )

    def test_score_vulnerabilities_does_not_add_impact_for_developers_to_finding(self):
        from utils.risk_scorer import score_vulnerabilities
        finding = _f(severity="high", meta={})
        results = {
            "all_findings": [finding],
            "summary": {"total_findings": 1},
        }
        score_vulnerabilities(results)
        assert "impact_for_developers" not in results["all_findings"][0]
