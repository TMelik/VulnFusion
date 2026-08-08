from utils.deduplicator import (
    deduplicate_scan_results,
    merge_deterministic_cluster,
    merge_vulnerabilities,
)
from utils.risk_scorer import score_vulnerabilities
from utils.schema import validate_finding


def _finding(
    scanner: str,
    *,
    severity: str = "medium",
    description: str,
    remediation: str,
    meta_extra: dict | None = None,
    references: list[str] | None = None,
) -> dict:
    meta = {
        "scanner": scanner,
        "host": "example.com",
        "scheme": "https",
        "port": 443,
        "path": "/login",
        "parameter": "q",
        "method": "GET",
    }
    if meta_extra:
        meta.update(meta_extra)

    finding = {
        "vulnerability_name": "SQL Injection",
        "severity": severity,
        "asset_id": "https://example.com/login?q=search",
        "description": description,
        "remediation": remediation,
        "meta": meta,
    }
    if references is not None:
        finding["references"] = references
    return finding


def test_merge_preserves_source_findings_and_canonical_fields():
    zap_finding = _finding(
        "zap",
        severity="medium",
        description="ZAP detected injectable input on the login page.",
        remediation="Validate user input.",
        meta_extra={
            "raw_id": "zap-40018",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        },
        references=["https://alerts.example/zap"],
    )
    nuclei_finding = _finding(
        "nuclei",
        severity="high",
        description="Nuclei matched SQL error leakage at the same endpoint.",
        remediation="Use parameterised queries.",
        meta_extra={
            "raw_id": "nuclei-sqli-template",
            "matcher_name": "body",
            "references": ["https://nuclei.projectdiscovery.io/templates/sql"],
        },
    )

    merged = merge_vulnerabilities([zap_finding, nuclei_finding])

    assert len(merged) == 1

    finding = merged[0]
    assert finding["severity"] == "high"
    assert finding["found_by"] == ["zap", "nuclei"]
    assert finding["duplicate_count"] == 2
    assert finding["match_level"] == "strict"
    assert finding["description"] == "Nuclei matched SQL error leakage at the same endpoint."
    assert finding["remediation"] == "Use parameterised queries."
    assert "---" not in finding["description"]

    assert finding["meta"]["merged"] is True
    assert finding["meta"]["original_findings_count"] == 2
    assert finding["meta"]["scanners"] == ["zap", "nuclei"]
    assert finding["meta"]["has_multi_scanner_confirmation"] is True

    assert len(finding["source_findings"]) == 2
    assert finding["source_findings"][0]["scanner"] == "zap"
    assert finding["source_findings"][0]["meta"]["raw_id"] == "zap-40018"
    assert finding["source_findings"][0]["references"] == ["https://alerts.example/zap"]
    assert finding["source_findings"][1]["scanner"] == "nuclei"
    assert finding["source_findings"][1]["meta"]["matcher_name"] == "body"
    assert finding["source_findings"][1]["fp_strict"]


def test_merge_preserves_safe_metadata_unions_and_schema_compatibility():
    first = _finding(
        "zap",
        severity="medium",
        description="ZAP source record.",
        remediation="Apply a fix.",
        meta_extra={
            "raw_id": "zap-40018",
            "cve_id": "CVE-2024-1111",
            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
        },
        references=["https://alerts.example/zap"],
    )
    second = _finding(
        "nuclei",
        severity="high",
        description="Nuclei source record.",
        remediation="Apply the permanent fix.",
        meta_extra={
            "raw_id": "nuclei-sqli-template",
            "cve_ids": ["CVE-2024-1111", "CVE-2024-2222"],
            "references": ["https://nuclei.projectdiscovery.io/templates/sql"],
            "method": "POST",
            "port": 8443,
            "matcher_name": "body",
        },
    )

    merged_results = merge_vulnerabilities([first, second])

    assert len(merged_results) == 1
    merged = merged_results[0]

    assert merged["meta"]["raw_ids"] == ["zap-40018", "nuclei-sqli-template"]
    assert merged["meta"]["cve_ids"] == ["CVE-2024-1111", "CVE-2024-2222"]
    assert merged["meta"]["references"] == [
        "https://owasp.org/www-community/attacks/SQL_Injection",
        "https://alerts.example/zap",
        "https://nuclei.projectdiscovery.io/templates/sql",
    ]
    assert merged["meta"]["paths"] == ["/login"]
    assert merged["meta"]["parameters"] == ["q"]
    assert merged["meta"]["ports"] == [443, 8443]
    assert merged["meta"]["methods"] == ["GET", "POST"]
    assert merged["meta"]["matcher_names"] == ["body"]

    ok, errors = validate_finding(merged)
    assert ok is True, errors


def test_merge_retains_existing_plural_raw_ids_when_remerging():
    first = _finding(
        "zap",
        severity="medium",
        description="Previously merged source record.",
        remediation="Apply a fix.",
        meta_extra={
            "raw_ids": ["zap-40018", "zap-40019"],
        },
    )
    second = _finding(
        "nuclei",
        severity="high",
        description="Nuclei source record.",
        remediation="Apply the permanent fix.",
        meta_extra={
            "raw_id": "nuclei-sqli-template",
        },
    )

    merged = merge_vulnerabilities([first, second])[0]

    assert merged["meta"]["raw_ids"] == [
        "zap-40018",
        "zap-40019",
        "nuclei-sqli-template",
    ]


def test_merge_deterministic_cluster_preserves_resolution_details_and_provenance():
    zap_finding = _finding(
        "zap",
        severity="medium",
        description="ZAP detected injectable input on the login page.",
        remediation="Validate user input.",
        meta_extra={
            "raw_id": "zap-40018",
            "cve_id": "CVE-2024-1111",
        },
    )
    nuclei_finding = _finding(
        "nuclei",
        severity="high",
        description="Nuclei matched the same SQL injection issue.",
        remediation="Use parameterised queries.",
        meta_extra={
            "raw_id": "nuclei-sqli-template",
            "cve_ids": ["CVE-2024-1111"],
        },
    )

    merged = merge_deterministic_cluster(
        [zap_finding, nuclei_finding],
        reason="cross_scanner_obvious_duplicate",
        duplicate_resolution_extra={
            "stage": "pre_llm",
            "rules": ["same_cve_same_effective_target"],
            "shared_cves": ["CVE-2024-1111"],
        },
    )

    assert merged["duplicate_count"] == 2
    assert merged["found_by"] == ["zap", "nuclei"]
    assert len(merged["source_findings"]) == 2
    assert merged["meta"]["duplicate_resolution_mode"] == "deterministic"
    assert merged["duplicate_resolution"] == {
        "mode": "deterministic",
        "reason": "cross_scanner_obvious_duplicate",
        "stage": "pre_llm",
        "rules": ["same_cve_same_effective_target"],
        "shared_cves": ["CVE-2024-1111"],
    }


def test_singleton_merge_result_does_not_share_nested_meta_with_source():
    source = _finding(
        "zap",
        severity="medium",
        description="Single source record.",
        remediation="Apply a fix.",
        meta_extra={
            "business_context": {"environment": "production"},
        },
    )

    merged = merge_vulnerabilities([source])[0]
    source["meta"]["business_context"]["environment"] = "staging"

    assert merged["meta"]["business_context"]["environment"] == "production"


def test_deduplicate_refreshes_summary_from_final_finding_set():
    zap = _finding(
        "zap",
        severity="high",
        description="ZAP found SQL injection.",
        remediation="Fix SQL injection.",
    )
    nuclei = _finding(
        "nuclei",
        severity="medium",
        description="Nuclei found the same SQL injection.",
        remediation="Fix SQL injection permanently.",
    )
    wapiti = _finding(
        "wapiti",
        severity="low",
        description="Wapiti found a distinct issue.",
        remediation="Fix the header.",
        meta_extra={"path": "/admin", "parameter": "", "method": "GET"},
    )
    wapiti["vulnerability_name"] = "X-Content-Type-Options Header Missing"
    wapiti["asset_id"] = "https://example.com/admin"

    results = {
        "all_findings": [zap, nuclei, wapiti],
        "summary": {
            "total_findings": 29,
            "by_severity": {"critical": 0, "high": 8, "medium": 3, "low": 10, "info": 8},
            "by_scanner": {"zap": 1, "nuclei": 1, "wapiti": 1},
        },
    }

    deduped = deduplicate_scan_results(results)

    assert len(deduped["all_findings"]) == 2
    assert deduped["summary"]["total_findings"] == 2
    assert deduped["summary"]["by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }


def test_risk_scoring_refreshes_stale_priority_and_severity_summary():
    findings = [
        _finding("zap", severity="high", description="High issue.", remediation="Fix it."),
        _finding(
            "wapiti",
            severity="low",
            description="Low issue.",
            remediation="Fix it too.",
            meta_extra={"path": "/headers", "parameter": "", "method": "GET"},
        ),
    ]
    findings[1]["vulnerability_name"] = "X-Content-Type-Options Header Missing"
    findings[1]["asset_id"] = "https://example.com/headers"
    results = {
        "all_findings": findings,
        "summary": {
            "total_findings": 29,
            "by_severity": {"critical": 0, "high": 8, "medium": 3, "low": 10, "info": 8},
            "by_priority": {"P0": 0, "P1": 0, "P2": 1, "P3": 13, "P4": 8},
        },
    }

    scored = score_vulnerabilities(results)

    assert scored["summary"]["total_findings"] == len(scored["all_findings"])
    assert sum(scored["summary"]["by_severity"].values()) == len(scored["all_findings"])
    assert sum(scored["summary"]["by_priority"].values()) == len(scored["all_findings"])


def test_deduplicate_suppresses_adapter_banner_artifacts_from_final_findings():
    artifact = {
        "vulnerability_name": "Server banner changed from 'Apache/2.4.49' to 'uvicorn'.",
        "severity": "low",
        "asset_id": "https://example.com",
        "description": "Server banner changed from 'Apache/2.4.49' to 'uvicorn'.",
        "remediation": "Review banner.",
        "meta": {
            "scanner": "nikto",
            "host": "example.com",
            "scheme": "https",
            "path": "",
            "port": None,
            "effective_target": "http://127.0.0.1:53647/",
            "origin_target": "https://example.com",
            "original_target": "https://example.com",
            "adapter_mode": "bridge",
        },
    }
    real_finding = _finding(
        "zap",
        severity="medium",
        description="A real finding.",
        remediation="Fix it.",
    )
    results = {
        "all_findings": [artifact, real_finding],
        "summary": {
            "total_findings": 2,
            "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 1, "info": 0},
        },
    }

    deduped = deduplicate_scan_results(results)

    assert deduped["summary"]["total_findings"] == 1
    assert deduped["summary"]["suppressed_adapter_findings_count"] == 1
    assert all("uvicorn" not in f["vulnerability_name"].lower() for f in deduped["all_findings"])


def _header_finding(scanner: str, name: str, *, severity: str = "low", parameter: str = "") -> dict:
    return {
        "vulnerability_name": name,
        "severity": severity,
        "asset_id": "https://example.com/",
        "description": name,
        "remediation": "Set the missing security header.",
        "meta": {
            "scanner": scanner,
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": "/",
            "parameter": parameter,
            "method": "GET",
        },
    }


def test_security_header_variants_merge_by_semantic_header_family():
    findings = [
        _header_finding("zap", "Content Security Policy (CSP) Header Not Set", severity="medium"),
        _header_finding("wapiti", "Content Security Policy Configuration"),
        _header_finding("nikto", "Suggested security header missing: content-security-policy."),
        _header_finding("zap", "X-Content-Type-Options Header Missing", parameter="x-content-type-options"),
        _header_finding("nikto", "Suggested security header missing: x-content-type-options."),
        _header_finding("zap", "Missing Anti-clickjacking Header", severity="medium", parameter="x-frame-options"),
        _header_finding("wapiti", "Clickjacking Protection"),
    ]

    merged = merge_vulnerabilities(findings)

    assert len(merged) == 3
    normalized_names = {finding["normalized_name"] for finding in merged}
    assert normalized_names == {
        "missing content security policy header",
        "missing x content type options header",
        "missing clickjacking protection header",
    }
    assert any(set(finding["found_by"]) == {"zap", "wapiti", "nikto"} for finding in merged)


def test_repeated_internal_server_error_findings_merge_by_endpoint_ignoring_query_only_differences():
    repeated = [
        {
            "finding_id": "zap-ise-1",
            "vulnerability_name": "Internal Server Error",
            "severity": "low",
            "asset_id": "https://example.com/api/items?id=1",
            "description": "GET /api/items?id=1 returned HTTP 500.",
            "remediation": "Review server-side error handling.",
            "meta": {
                "scanner": "zap",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "path": "/api/items",
                "parameter": "id",
                "method": "GET",
            },
        },
        {
            "finding_id": "zap-ise-2",
            "vulnerability_name": "Internal Server Error",
            "severity": "low",
            "asset_id": "https://example.com/api/items?id=2",
            "description": "GET /api/items?id=2 returned HTTP 500.",
            "remediation": "Review server-side error handling.",
            "meta": {
                "scanner": "zap",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "path": "/api/items",
                "parameter": "id",
                "method": "GET",
            },
        },
        {
            "finding_id": "nuclei-ise-1",
            "vulnerability_name": "Internal Server Error",
            "severity": "medium",
            "asset_id": "https://example.com/api/items?debug=1",
            "description": "Nuclei observed a 500 response on the same handler.",
            "remediation": "Review server-side error handling.",
            "meta": {
                "scanner": "nuclei",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "path": "/api/items",
                "parameter": "debug",
                "method": "GET",
            },
        },
        {
            "finding_id": "zap-ise-post",
            "vulnerability_name": "Internal Server Error",
            "severity": "low",
            "asset_id": "https://example.com/api/items",
            "description": "POST /api/items returned HTTP 500.",
            "remediation": "Review server-side error handling.",
            "meta": {
                "scanner": "zap",
                "host": "example.com",
                "scheme": "https",
                "port": 443,
                "path": "/api/items",
                "method": "POST",
            },
        },
    ]

    merged = merge_vulnerabilities(repeated)

    assert len(merged) == 2

    get_finding = next(
        finding for finding in merged
        if finding["meta"].get("method") == "GET"
    )
    assert get_finding["duplicate_count"] == 3
    assert get_finding["found_by"] == ["zap", "nuclei"]
    assert get_finding["match_level"] == "general"
    assert get_finding["meta"]["merged"] is True
    assert get_finding["meta"]["scanners"] == ["zap", "nuclei"]
    assert get_finding["meta"]["confirmation_scanners"] == ["zap", "nuclei"]
    assert get_finding["meta"]["has_multi_scanner_confirmation"] is True
    assert len(get_finding["source_findings"]) == 3
    assert [source["finding_id"] for source in get_finding["source_findings"]] == [
        "zap-ise-1",
        "zap-ise-2",
        "nuclei-ise-1",
    ]


def test_degraded_scanner_findings_do_not_count_as_clean_multi_scanner_confirmation():
    clean = _finding(
        "zap",
        severity="high",
        description="ZAP found injectable input.",
        remediation="Validate and parameterize input.",
    )
    degraded = _finding(
        "nikto",
        severity="high",
        description="Nikto reported the same endpoint during a degraded run.",
        remediation="Validate and parameterize input.",
        meta_extra={"degraded_execution": True},
    )

    merged = merge_vulnerabilities([clean, degraded])

    assert len(merged) == 1
    finding = merged[0]
    assert finding["found_by"] == ["zap", "nikto"]
    assert finding["meta"]["scanners"] == ["zap", "nikto"]
    assert finding["meta"]["confirmation_scanners"] == ["zap"]
    assert finding["meta"]["has_multi_scanner_confirmation"] is False
    assert finding["meta"]["degraded_scanners"] == ["nikto"]
    assert finding["meta"]["degraded_execution"] is True
    assert any(
        source["scanner"] == "nikto" and source["meta"].get("degraded_execution") is True
        for source in finding["source_findings"]
    )
