import pytest

from utils.normalizer import upgrade_schema
from utils.schema import PRIORITY_LEVELS, VulnerabilitySchema, validate_finding


def _valid_base() -> dict:
    return {
        "vulnerability_name": "SQL Injection",
        "severity": "high",
        "asset_id": "https://example.com/search",
        "description": "Input not sanitised",
        "remediation": "Use parameterised queries",
        "meta": {"scanner": "nuclei"},
    }


def test_minimal_valid_finding_passes():
    ok, errs = validate_finding(_valid_base())
    assert ok is True
    assert errs == []


def test_missing_required_field_fails():
    finding = _valid_base()
    del finding["remediation"]
    ok, errs = validate_finding(finding)
    assert ok is False
    assert any("remediation" in err for err in errs)


def test_empty_description_and_remediation_are_allowed_when_scanner_provides_no_text():
    finding = _valid_base()
    finding["description"] = ""
    finding["remediation"] = ""

    ok, errs = validate_finding(finding)

    assert ok is True, errs


@pytest.mark.parametrize(
    ("field", "value", "error_fragment"),
    [
        ("severity", "urgent", "Invalid severity"),
        ("fp_strict", "", "fp_strict"),
        ("fp_general", 123, "fp_general"),
        ("merge_confidence", 1.5, "merge_confidence"),
        ("match_level", "fuzzy", "match_level"),
        ("priority", "P9", "Invalid priority"),
        ("risk_score", 9.5, "risk_score"),
        ("risk_rationale", 123, "risk_rationale"),
        ("impact_for_developers", "deprecated text", "impact_for_developers"),
        ("duplicate_count", 0, "duplicate_count"),
    ],
)
def test_invalid_optional_fields_are_rejected(field, value, error_fragment):
    finding = _valid_base()
    finding[field] = value
    ok, errs = validate_finding(finding)
    assert ok is False
    assert any(error_fragment in err for err in errs)


def test_meta_type_constraints_are_enforced():
    finding = _valid_base()
    finding["meta"]["port"] = "8080"
    ok, errs = validate_finding(finding)
    assert ok is False
    assert any("meta.port" in err for err in errs)

    finding = _valid_base()
    finding["meta"]["query_keys"] = ["id", 42]
    ok, errs = validate_finding(finding)
    assert ok is False
    assert any("meta.query_keys" in err for err in errs)

    finding = _valid_base()
    finding["meta"]["cve_ids"] = "CVE-2023-1234"
    ok, errs = validate_finding(finding)
    assert ok is False
    assert any("meta.cve_ids" in err for err in errs)


def test_valid_priority_levels_pass():
    for priority in PRIORITY_LEVELS:
        finding = _valid_base()
        finding["priority"] = priority
        ok, errs = validate_finding(finding)
        assert ok is True, errs


def test_public_risk_fields_pass_validation():
    finding = _valid_base()
    finding["risk_score"] = 72
    finding["priority"] = "P1"
    finding["risk_factors"] = {"final_score": 72, "final_priority": "P1"}
    finding["risk_rationale"] = "Exploit evidence and production exposure increased priority."

    ok, errs = validate_finding(finding)

    assert ok is True, errs


def test_impact_for_developers_is_rejected_even_when_string_typed():
    finding = _valid_base()
    finding["impact_for_developers"] = "Deprecated generated prose."

    ok, errs = validate_finding(finding)

    assert ok is False
    assert "'impact_for_developers' is no longer supported" in errs


def test_legacy_upgraded_record_still_valid():
    old_report = {
        "schema_version": "1.0",
        "target": "example.com",
        "all_findings": [
            {
                "vulnerability_name": "Open Port",
                "severity": "info",
                "asset_id": "https://example.com:443/login",
                "description": "Port is open",
                "remediation": "Close unused ports",
                "meta": {"scanner": "nmap"},
            }
        ],
    }
    upgraded = upgrade_schema(old_report)
    ok, errs = validate_finding(upgraded["all_findings"][0])
    assert ok is True, errs


def test_schema_definition_includes_expected_properties():
    props = VulnerabilitySchema.get_schema_definition()["properties"]
    for field in (
        "source_findings",
        "references",
        "found_by",
        "status",
        "changed_fields",
        "risk_score",
        "priority",
        "risk_factors",
        "risk_rationale",
    ):
        assert field in props
    for removed in (
        "change_details",
        "fp_strict",
        "fp_general",
        "fp_host_only",
        "duplicate_count",
        "merge_confidence",
        "normalized_name",
        "vuln_key",
        "vuln_type",
        "dev_guidance",
        "evidence",
        "cwe",
        "owasp",
        "cto_summary",
    ):
        assert removed not in props


def test_schema_definition_includes_merged_provenance_meta_properties():
    meta_props = VulnerabilitySchema.get_schema_definition()["properties"]["meta"]["properties"]

    for field in (
        "raw_ids",
        "references",
        "paths",
        "parameters",
        "ports",
        "methods",
        "matcher_names",
        "cvss",
    ):
        assert field in meta_props


def test_schema_definition_omits_removed_enrichment_meta_properties():
    meta_props = VulnerabilitySchema.get_schema_definition()["properties"]["meta"]["properties"]

    for field in (
        "cvss_score",
        "cvss_version",
        "cvss_vector",
        "cvss_source",
        "epss_score",
        "epss_percentile",
        "epss_source",
        "kev_listed",
        "kev_source",
        "kev_due_date",
        "cve_intelligence_candidates",
        "business_context",
        "evidence_quality",
        "merged",
        "original_findings_count",
        "scanners",
        "has_multi_scanner_confirmation",
    ):
        assert field not in meta_props


def test_merged_source_evidence_structure_is_schema_compatible():
    finding = _valid_base()
    finding.update(
        {
            "found_by": ["zap", "nuclei"],
            "duplicate_count": 2,
            "merge_confidence": 0.85,
            "match_level": "general",
            "source_findings": [
                {
                    "scanner": "zap",
                    "vulnerability_name": "SQL Injection",
                    "severity": "high",
                    "asset_id": "https://example.com/search?q=test",
                    "description": "ZAP evidence",
                    "remediation": "Fix the query handling",
                    "meta": {
                        "scanner": "zap",
                        "path": "/search",
                        "parameter": "q",
                        "method": "GET",
                        "raw_id": "zap-40018",
                    },
                    "fp_strict": "sql injection::example.com::443::/search::q::q::GET",
                    "fp_general": "sql injection::example.com::/search",
                    "fp_host_only": "sql injection::example.com",
                    "references": ["https://alerts.example/zap"],
                },
                {
                    "scanner": "nuclei",
                    "vulnerability_name": "SQL Injection",
                    "severity": "high",
                    "asset_id": "https://example.com/search?q=test",
                    "description": "Nuclei evidence",
                    "remediation": "Apply the permanent fix",
                    "meta": {
                        "scanner": "nuclei",
                        "path": "/search",
                        "matcher_name": "body",
                        "cve_id": "CVE-2024-1111",
                    },
                    "fp_strict": "sql injection::example.com::443::/search::q::q::GET",
                    "fp_general": "sql injection::example.com::/search",
                    "fp_host_only": "sql injection::example.com",
                },
            ],
        }
    )
    finding["meta"].update(
        {
            "merged": True,
            "original_findings_count": 2,
            "scanners": ["zap", "nuclei"],
            "has_multi_scanner_confirmation": True,
            "raw_ids": ["zap-40018", "nuclei-sqli-template"],
            "references": ["https://alerts.example/zap", "https://nuclei.example/template"],
            "paths": ["/search"],
            "parameters": ["q"],
            "ports": [443],
            "methods": ["GET"],
            "matcher_names": ["body"],
        }
    )

    ok, errs = validate_finding(finding)

    assert ok is True, errs


def test_invalid_cvss_version_is_rejected():
    finding = _valid_base()
    finding["meta"]["cvss_version"] = "2.0"

    ok, errs = validate_finding(finding)

    assert ok is False
    assert any("meta.cvss_version" in err for err in errs)
