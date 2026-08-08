import pytest

from utils.comparator import _build_comparison_profile
from utils.report_generator import (
    _extract_cve_ids,
    _group_findings_by_cve,
    generate_html_report,
    generate_modern_html_report,
)


def _minimal_finding(**extra) -> dict:
    finding = {
        "vulnerability_name": "Test Vuln",
        "severity": "high",
        "asset_id": "https://example.com",
        "description": "A test vulnerability.",
        "remediation": "Fix it.",
        "meta": {},
    }
    finding.update(extra)
    return finding


def _results(*findings) -> dict:
    return {
        "schema_version": "2.0",
        "target": "https://example.com",
        "generated_at": "2026-03-30T15:00:00Z",
        "all_findings": list(findings),
        "summary": {"by_severity": {}, "by_priority": {}},
    }


def test_extract_cve_ids_collects_metadata_sources_in_order():
    finding = _minimal_finding(
        vulnerability_name="Generic CMS issue",
        meta={
            "cve_ids": ["cve-2024-1111", "CVE-2024-2222", "CVE-2024-1111"],
            "cve_id": "cve-2024-3333",
            "cve": "CVE-2024-4444",
            "raw_id": "CVE-2024-5555",
        },
    )

    assert _extract_cve_ids(finding) == [
        "CVE-2024-1111",
        "CVE-2024-2222",
        "CVE-2024-3333",
        "CVE-2024-4444",
        "CVE-2024-5555",
    ]


def test_extract_cve_ids_uses_exact_raw_id_match():
    finding = _minimal_finding(
        vulnerability_name="Service finding",
        meta={"raw_id": "cve-2024-8888"},
    )

    assert _extract_cve_ids(finding) == ["CVE-2024-8888"]


def test_extract_cve_ids_uses_exact_vulnerability_name_match():
    finding = _minimal_finding(
        vulnerability_name="cve-2024-9999",
        meta={"raw_id": "plugin-1"},
    )

    assert _extract_cve_ids(finding) == ["CVE-2024-9999"]


def test_extract_cve_ids_returns_empty_without_cve():
    finding = _minimal_finding(
        vulnerability_name="Missing Security Header",
        meta={"raw_id": "zap-40018"},
    )

    assert _extract_cve_ids(finding) == []


@pytest.mark.parametrize(
    ("meta", "vulnerability_name", "expected"),
    [
        ({"cve_ids": ["CVE-2024-1001", "cve-2024-1002"]}, "Generic finding", ["CVE-2024-1001", "CVE-2024-1002"]),
        ({"cve_id": "cve-2024-2001"}, "Generic finding", ["CVE-2024-2001"]),
        ({"cve": "CVE-2024-3001"}, "Generic finding", ["CVE-2024-3001"]),
        ({"raw_id": "CVE-2024-4001"}, "Generic finding", ["CVE-2024-4001"]),
        ({"raw_id": "plugin-1"}, "cve-2024-5001", ["CVE-2024-5001"]),
    ],
)
def test_report_cve_extraction_matches_comparator_profile(meta, vulnerability_name, expected):
    finding = _minimal_finding(vulnerability_name=vulnerability_name, meta=meta)

    assert _extract_cve_ids(finding) == expected
    assert set(_build_comparison_profile(0, finding).cves) == set(expected)


def test_non_cve_raw_id_is_ignored_by_report_and_comparator():
    finding = _minimal_finding(
        vulnerability_name="Generic finding",
        meta={"raw_id": "template-CVE-2024-9999"},
    )

    assert _extract_cve_ids(finding) == []
    assert _build_comparison_profile(0, finding).cves == set()


def test_group_findings_by_cve_duplicates_multi_cve_findings_and_keeps_no_cve():
    multi_cve = _minimal_finding(
        vulnerability_name="Multi-CVE finding",
        meta={"cve_ids": ["CVE-2024-1001", "CVE-2024-1002"]},
    )
    raw_id_cve = _minimal_finding(
        vulnerability_name="Raw ID finding",
        meta={"raw_id": "CVE-2024-1002"},
    )
    no_cve = _minimal_finding(
        vulnerability_name="Security Header Missing",
        meta={"scanner": "zap"},
    )

    grouped, without_cve = _group_findings_by_cve([multi_cve, raw_id_cve, no_cve])

    assert list(grouped) == ["CVE-2024-1001", "CVE-2024-1002"]
    assert grouped["CVE-2024-1001"] == [multi_cve]
    assert grouped["CVE-2024-1002"] == [multi_cve, raw_id_cve]
    assert without_cve == [no_cve]


def test_report_keeps_all_findings_primary_when_findings_have_no_cve():
    findings = [
        _minimal_finding(
            vulnerability_name=f"Header Finding {index}",
            severity="low",
            asset_id=f"https://example.com/{index}",
            meta={"scanner": "zap"},
        )
        for index in range(22)
    ]

    html = generate_html_report(_results(*findings))

    assert 'id="findingsCount">22</span>' in html
    assert "Findings by CVE" not in html
    assert "Findings without CVE" in html
    assert html.find("All Findings") < html.find("Findings without CVE")
    assert 'class="filter-btn active" data-filter="status" data-value="all">All</button>' in html
    assert 'class="filter-btn active" data-filter="status" data-value="persistent"' not in html
    assert "No findings match the selected filters." in html
    assert 'id="emptyClearFilters">Clear filters</button>' in html


def test_report_renders_findings_by_cve_section_and_escapes_grouped_values():
    html = generate_html_report(
        _results(
            _minimal_finding(
                vulnerability_name="CVE-2024-3000",
                severity="critical",
                asset_id="https://prod.example",
                description="<script>alert(1)</script> critical issue",
                meta={"scanner": "nmap"},
            ),
            _minimal_finding(
                vulnerability_name="CMS remote code execution",
                severity="high",
                asset_id="https://prod.example/admin",
                description="Matched through raw CVE identifier.",
                meta={"scanner": "nuclei", "raw_id": "CVE-2024-3000"},
            ),
            _minimal_finding(
                vulnerability_name="Template finding",
                severity="medium",
                asset_id="https://staging.example",
                description="Linked to two CVEs in nuclei metadata.",
                meta={"scanner": "nuclei", "cve_ids": ["CVE-2024-1111", "CVE-2024-2222"]},
            ),
            _minimal_finding(
                vulnerability_name="Missing CSP Header",
                severity="low",
                asset_id="https://no-cve.example",
                description="No CVE assigned.",
                meta={"scanner": "zap"},
            ),
        )
    )

    assert "Findings by CVE" in html
    assert "Findings without CVE" in html
    assert "2 linked findings" in html
    assert "CVE-2024-3000" in html
    assert "nmap" in html
    assert "nuclei" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt; critical issue" in html
    assert "<script>alert(1)</script>" not in html
    assert html.find("CVE-2024-3000") < html.find("CVE-2024-1111")
    assert html.find("All Findings") < html.find("Findings by CVE")
    assert html.find("Findings by CVE") < html.find("Findings without CVE")


def test_generate_modern_report_cve_section_handles_missing_optional_values():
    html = generate_modern_html_report(
        {
            "target": "https://example.com",
            "timestamp": "2026-04-12T00:00:00Z",
            "all_findings": [
                {
                    "vulnerability_name": "CVE-2024-5000",
                },
                {
                    "vulnerability_name": "Header Missing",
                },
            ],
            "summary": {"by_severity": {}, "by_priority": {}},
        }
    )

    assert "Findings by CVE" in html
    assert "Unknown asset" in html
    assert "No description provided." in html
    assert "Findings without CVE" in html


def test_report_renders_public_risk_fields_and_priority_distribution():
    html = generate_html_report(
        {
            **_results(
                _minimal_finding(
                    priority="P1",
                    risk_score=72,
                    risk_rationale="High severity with known exploit increases risk significantly.",
                )
            ),
            "summary": {"by_severity": {}, "by_priority": {"P1": 1}},
        }
    )

    assert "Priority Distribution" in html
    assert "Risk 72/100" in html
    assert "High severity with known exploit increases risk significantly." in html
    assert "Why this is prioritized:" in html


def test_report_keeps_severity_filter_row_without_duplicate_distribution_section():
    html = generate_html_report(
        {
            **_results(
                _minimal_finding(
                    priority="P1",
                    risk_score=72,
                )
            ),
            "summary": {
                "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 1},
                "by_priority": {"P1": 1},
            },
        }
    )

    assert html.count('id="severityFilters"') == 1
    assert 'data-filter="severity" data-value="all">All</button>' in html
    assert 'data-filter="severity" data-value="critical">Critical</button>' in html
    assert 'data-filter="severity" data-value="high">High</button>' in html
    assert 'data-filter="severity" data-value="medium">Medium</button>' in html
    assert 'data-filter="severity" data-value="low">Low</button>' in html
    assert 'data-filter="severity" data-value="info">Info</button>' in html
    assert html.count('id="statusFilters"') == 1
    assert 'data-filter="status" data-value="all">All</button>' in html
    assert 'data-filter="status" data-value="fixed">Fixed</button>' in html
    assert "All Status" not in html
    assert 'id="clearFilters">Clear filters</button>' in html
    assert "Severity Distribution" not in html
    assert "Priority Distribution" in html
    assert "Findings by CVE" not in html
    assert "Findings without CVE" in html
    priority_section = html.split("Priority Distribution", 1)[1].split("All Findings", 1)[0]
    assert "P1 Priority" not in priority_section
    assert "1 finding" in priority_section
    assert "Critical business priority" in priority_section


def test_report_renders_priority_badges_without_dumping_raw_meta_enrichment():
    html = generate_html_report(
        {
            **_results(
                _minimal_finding(
                    priority="P0",
                    risk_score=91,
                    risk_rationale="CVSS and KEV drove this finding to the top priority.",
                    meta={
                        "cvss_score": 9.8,
                        "cvss_version": "4.0",
                        "epss_score": 0.72,
                        "epss_percentile": 0.99,
                        "kev_listed": True,
                        "kev_source": "CISA KEV",
                    },
                )
            ),
            "summary": {"by_severity": {}, "by_priority": {"P0": 1}},
        }
    )

    assert "P0" in html
    assert "Risk 91/100" in html
    assert "CVSS and KEV drove this finding to the top priority." in html
    assert "CVSS:" not in html
    assert "EPSS:" not in html
    assert "KEV:" not in html
    assert "CISA KEV" not in html


def test_report_sorts_by_priority_before_severity():
    html = generate_html_report(
        {
            **_results(
                _minimal_finding(vulnerability_name="P1Critical", severity="critical", priority="P1", risk_score=95),
                _minimal_finding(vulnerability_name="P0Low", severity="low", priority="P0", risk_score=60),
            ),
            "summary": {"by_severity": {}, "by_priority": {"P0": 1, "P1": 1}},
        }
    )

    all_findings_html = html.split("All Findings", 1)[1]

    assert all_findings_html.find("P0Low") < all_findings_html.find("P1Critical")


def test_report_uses_scanner_native_description_without_developer_impact_block():
    html = generate_html_report(
        _results(
            _minimal_finding(
                priority="P1",
                risk_score=80,
                risk_rationale="Production exposure and exploit likelihood increased priority.",
                description="Scanner-native description should remain visible.",
            )
        )
    )

    assert "Developer Impact:" not in html
    assert "Scanner-native description should remain visible." in html


def test_report_uses_normalized_description_and_remediation_without_kb_sections():
    html = generate_html_report(
        _results(
            _minimal_finding(
                description="Scanner-normalized description from the adapter.",
                remediation="Scanner-normalized remediation from the adapter.",
                priority="P1",
                risk_score=80,
            )
        )
    )

    assert "Scanner-normalized description from the adapter." in html
    assert "Developer Guidance" not in html
    assert "Scanner-normalized remediation from the adapter." in html
    assert "Executive Summary" not in html


def test_report_wraps_long_vulnerability_text_without_clipping_css():
    long_token = "a" * 220
    long_title = f"Very long vulnerability title {long_token}"
    long_url = f"https://example.com/{long_token}/details?redirect=https://{long_token}.example/{long_token}"
    long_description = (
        "Scanner description must remain complete and readable even when it contains "
        f"an uninterrupted token {long_token} and enough surrounding prose to span "
        "multiple visual lines in the vulnerability card."
    )
    long_impact = (
        "Impact text must remain visible for operators reviewing the report, including "
        f"long affected-resource identifiers like {long_url}."
    )
    long_remediation = (
        "Apply the recommended fix and verify the affected URL after deployment. "
        f"Use the full endpoint path {long_url} when validating the remediation."
    )

    html = generate_html_report(
        _results(
            _minimal_finding(
                vulnerability_name=long_title,
                asset_id=long_url,
                description=long_description,
                impact=long_impact,
                remediation=long_remediation,
                meta={"cve_id": "CVE-2026-1234"},
            )
        )
    )

    cve_section_html = html.split("Findings by CVE", 1)[1]

    assert long_title in html
    assert long_url in html
    assert long_description in html
    assert long_description in cve_section_html
    assert long_impact in html
    assert long_remediation in html
    assert "overflow: hidden;" not in html
    assert "text-overflow: ellipsis;" not in html
    assert "white-space: nowrap;" not in html
    assert "overflow-wrap: anywhere;" in html
    assert "word-break: break-word;" in html
    assert html.find("All Findings") < html.find("Findings by CVE")


def test_report_prefers_source_findings_over_top_level_merged_narrative():
    html = generate_html_report(
        _results(
            _minimal_finding(
                description="Synthetic merged summary that should stay hidden.",
                remediation="Synthetic merged remediation that should stay hidden.",
                found_by=["zap", "nuclei"],
                duplicate_count=2,
                meta={"merged": True, "scanners": ["zap", "nuclei"]},
                source_findings=[
                    {
                        "scanner": "zap",
                        "vulnerability_name": "SQL Injection",
                        "severity": "high",
                        "asset_id": "https://example.com/login?id=1",
                        "description": "ZAP observed injectable parameter handling.",
                        "remediation": "Sanitise request parameters.",
                        "meta": {"scanner": "zap", "path": "/login", "parameter": "id"},
                    },
                    {
                        "scanner": "nuclei",
                        "vulnerability_name": "SQL Injection",
                        "severity": "high",
                        "asset_id": "https://example.com/login?id=1",
                        "description": "Nuclei matched the same issue.",
                        "remediation": "",
                        "meta": {"scanner": "nuclei", "matcher_name": "body"},
                    },
                ],
            )
        )
    )

    assert "Source Evidence" in html
    assert "ZAP observed injectable parameter handling." in html
    assert "Nuclei matched the same issue." in html
    assert "Synthetic merged summary that should stay hidden." not in html
    assert "Synthetic merged remediation that should stay hidden." not in html


def test_report_writes_file(tmp_path):
    output_path = tmp_path / "report.html"
    html = generate_html_report(
        _results(_minimal_finding()),
        output_path,
    )

    assert isinstance(html, str)
    assert len(html) > 100
    assert output_path.exists()
    assert output_path.read_text(encoding="utf-8") == html


def test_report_omits_transport_section_and_skip_reason_from_html_exports():
    html = generate_html_report(
        {
            **_results(_minimal_finding(meta={"scanner": "direct-web"})),
            "scanner_execution": {
                "direct-web": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "direct",
                    "adapter_mode": "direct",
                    "scanner_transport_notes": "Scanner supports HTTP/2 directly.",
                },
                "nikto": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "skipped",
                    "adapter_mode": "skipped",
                    "skip_reason": "Target is HTTP/2-only and no proxy was configured.",
                    "scanner_transport_notes": "Scanner was skipped safely.",
                },
            },
        }
    )

    assert "Scanner Transport" not in html
    assert "Target is HTTP/2-only and no proxy was configured." not in html
    assert "Route:" not in html
    assert "Adapter:" not in html


def test_report_omits_degraded_transport_state_from_html_exports():
    html = generate_html_report(
        {
            **_results(_minimal_finding(meta={"scanner": "nikto"})),
            "scanner_execution": {
                "nikto": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "proxied",
                    "adapter_mode": "bridge",
                    "scanner_transport_notes": "Scanner was routed through the local bridge.",
                    "adapter_status": "ready",
                    "adapter_runtime_state": "running",
                    "adapter_runtime": "python-bridge",
                    "adapter_upstream_url": "https://example.com",
                    "adapter_translation_chain": "python HTTP/2 bridge -> origin",
                    "transport_confidence": "degraded",
                    "degraded_execution": True,
                    "partial_results": False,
                    "scanner_error": "Nikto reported a degraded execution and the result is not trustworthy as a clean scan.",
                },
            },
        }
    )

    assert "Degraded" not in html
    assert "Bridge" not in html
    assert "not trustworthy as a clean scan" not in html


def test_report_omits_transport_startup_failure_details_from_html_exports():
    html = generate_html_report(
        {
            **_results(_minimal_finding(meta={"scanner": "wapiti"})),
            "scanner_execution": {
                "wapiti": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "skipped",
                    "adapter_mode": "bridge",
                    "skip_reason": "Target appears HTTP/2-only, but the automatic local HTTP/2 bridge could not be started.",
                    "scanner_transport_notes": "The scan did not start because the compatibility adapter failed during startup.",
                    "adapter_status": "startup_failed",
                    "adapter_runtime_state": "failed",
                    "adapter_failure_reason": "Current bridge could not start for https://example.com: port in use",
                    "adapter_runtime": "python-bridge",
                    "adapter_upstream_url": "https://example.com",
                    "adapter_translation_chain": "python HTTP/2 bridge -> origin",
                    "transport_confidence": "failed",
                    "adapter_diagnostics": "bridge failed to listen on 127.0.0.1:39018",
                },
            },
        }
    )

    assert "Startup Failed" not in html
    assert "compatibility adapter failed during startup" not in html
    assert "bridge failed to listen" not in html


def test_report_omits_transport_runtime_path_and_diagnostics_from_html_exports():
    html = generate_html_report(
        {
            **_results(_minimal_finding(meta={"scanner": "nikto"})),
            "scanner_execution": {
                "nikto": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "proxied",
                    "adapter_mode": "bridge",
                    "scanner_transport_notes": "Scanner was routed through the local bridge.",
                    "adapter_status": "ready",
                    "adapter_runtime_state": "running",
                    "adapter_runtime": "python-bridge",
                    "adapter_upstream_url": "https://example.com",
                    "adapter_translation_chain": "python HTTP/2 bridge -> origin",
                    "transport_confidence": "normal",
                    "adapter_diagnostics": "bridge runtime reported running\nflow error for https://example.com: upstream closed",
                },
                "zap": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "proxied",
                    "adapter_mode": "bridge",
                    "scanner_transport_notes": "Scanner was routed through the local bridge.",
                    "adapter_status": "ready",
                    "adapter_runtime_state": "running",
                    "adapter_runtime": "python-bridge",
                    "adapter_upstream_url": "https://example.com",
                    "adapter_translation_chain": "python HTTP/2 bridge -> origin",
                    "transport_confidence": "normal",
                },
            },
        }
    )

    assert "Reverse Upstream" not in html
    assert "python-bridge" not in html
    assert "python HTTP/2 bridge -&gt; origin" not in html
    assert "<details class=\"transport-diagnostics\">" not in html
    assert "flow error for https://example.com: upstream closed" not in html


def test_report_omits_transport_notes_when_runtime_metadata_is_present():
    html = generate_html_report(
        {
            **_results(_minimal_finding(meta={"scanner": "direct-web"})),
            "scanner_execution": {
                "direct-web": {
                    "scanner_type": "web",
                    "transport_detected": "http2_only",
                    "scan_route": "direct",
                    "adapter_mode": "direct",
                    "scanner_transport_notes": "Scanner supports HTTP/2 directly.",
                    "transport_confidence": "normal",
                },
            },
        }
    )

    assert "Scanner supports HTTP/2 directly." not in html
    assert "<details class=\"transport-diagnostics\">" not in html


def test_report_shows_comparison_skipped_notice_without_misleading_summary():
    html = generate_html_report(
        {
            **_results(_minimal_finding()),
            "comparison": {
                "compatible_baseline_used": False,
                "comparison_mode": "skipped",
                "compatibility_reason": "Comparison skipped because scanner coverage had no overlap between scans.",
                "current_scanners_run": ["nuclei", "zap"],
                "previous_scanners_run": ["nmap"],
                "overlapping_scanners": [],
                "missing_from_current": ["nmap"],
                "missing_from_previous": ["nuclei", "zap"],
                "summary": {},
            },
        }
    )

    assert "Historical Comparison" in html
    assert "Comparison unavailable" in html
    assert "scanner coverage had no overlap between scans" in html
    assert "Current scanners:" in html
    assert "Previous scanners:" in html
    assert "Comparison Summary" not in html


def test_report_shows_partial_comparison_notice_when_scanner_overlap_is_limited():
    html = generate_html_report(
        {
            **_results(_minimal_finding()),
            "comparison": {
                "compatible_baseline_used": True,
                "comparison_mode": "partial",
                "compatibility_reason": "Compared against the most recent previous scan with partial scanner overlap. Overlapping scanners: nuclei.",
                "current_scanners_run": ["nikto", "nuclei"],
                "previous_scanners_run": ["nuclei", "zap"],
                "overlapping_scanners": ["nuclei"],
                "missing_from_current": ["zap"],
                "missing_from_previous": ["nikto"],
                "partial_comparison_limitations": [
                    "Partial comparison used overlapping scanner coverage only.",
                    "Unmatched findings were not classified as fixed/new because scanner coverage differed.",
                ],
                "summary": {
                    "fixed": 0,
                    "new": 0,
                    "persistent": 1,
                    "changed": 0,
                    "partial_unmatched_current": 2,
                    "partial_unmatched_previous": 1,
                    "total_current": 1,
                },
            },
        }
    )

    assert "Historical Comparison" in html
    assert "Shows how findings changed compared with the previous report." in html
    assert "Partial comparison details" in html
    assert "partial scanner overlap" in html
    assert "Overlap:" in html
    assert "nuclei" in html
    assert "Missing from current:" in html
    assert "Missing from previous:" in html
    assert "Unmatched findings were not classified as fixed/new because scanner coverage differed." in html
    assert "Unclassified current findings:" in html
    assert "Unclassified previous findings:" in html
    assert "Comparison Summary" not in html


def test_report_renders_changed_field_labels_without_detail_values():
    html = generate_html_report(
        _results(
            _minimal_finding(
                status="CHANGED",
                changed_fields=["source_scanners", "remediation_available", "endpoint_scope"],
                change_details={
                    "changes": {
                        "source_scanners": {
                            "previous": ["nuclei"],
                            "current": ["nuclei", "zap"],
                        },
                        "remediation_available": {
                            "previous": False,
                            "current": True,
                        },
                        "endpoint_scope": {
                            "previous": {"endpoint_families": [], "has_path": False},
                            "current": {
                                "endpoint_families": ["/login"],
                                "has_path": True,
                                "has_parameter": True,
                            },
                        },
                    }
                },
                found_by=["nuclei", "zap"],
            )
        )
    )

    assert "Changed Vulnerabilities" not in html
    assert "Changes Detected" in html
    assert "Source Scanners" in html
    assert "Remediation Available" in html
    assert "Endpoint Scope" in html
    assert "Changed in scanner output" in html
    assert "/login" not in html


def test_report_renders_compact_source_evidence_for_merged_findings():
    html = generate_html_report(
        _results(
            _minimal_finding(
                found_by=["zap", "nuclei"],
                duplicate_count=2,
                meta={
                    "merged": True,
                    "scanners": ["zap", "nuclei"],
                    "has_multi_scanner_confirmation": True,
                },
                source_findings=[
                    {
                        "scanner": "zap",
                        "vulnerability_name": "Test Vuln",
                        "severity": "high",
                        "asset_id": "https://example.com/login?id=1",
                        "description": "ZAP observed injectable parameter handling.",
                        "remediation": "Sanitise request parameters.",
                        "meta": {
                            "scanner": "zap",
                            "path": "/login",
                            "parameter": "id",
                            "method": "GET",
                            "raw_id": "zap-40018",
                            "evidence": "SQL syntax error near '1' was reflected in the response.",
                            "http_request": "GET /login?id=1%27 HTTP/1.1",
                            "curl_command": "curl 'https://example.com/login?id=1%27'",
                        },
                        "fp_strict": "test vuln::example.com::443::/login::id::id::GET",
                        "fp_general": "test vuln::example.com::/login",
                        "fp_host_only": "test vuln::example.com",
                        "references": ["https://alerts.example/zap"],
                    },
                    {
                        "scanner": "nuclei",
                        "vulnerability_name": "Test Vuln",
                        "severity": "high",
                        "asset_id": "https://example.com/login?id=1",
                        "description": "Nuclei matched the same issue.",
                        "remediation": "Deploy the application fix.",
                        "meta": {
                            "scanner": "nuclei",
                            "path": "/login",
                            "matcher_name": "body",
                            "cve_id": "CVE-2024-1111",
                        },
                        "fp_strict": "test vuln::example.com::443::/login::id::id::GET",
                        "fp_general": "test vuln::example.com::/login",
                        "fp_host_only": "test vuln::example.com",
                    },
                ],
            )
        )
    )

    assert "Confirmed by:" in html
    assert "zap, nuclei" in html
    assert "Source Evidence" in html
    assert "ZAP observed injectable parameter handling." in html
    assert "CVE-2024-1111" in html
    assert "Request Example" in html
    assert "Curl Replay" in html
    assert "SQL syntax error near" in html


def test_report_renders_provenance_from_meta_scanner():
    html = generate_html_report(
        _results(_minimal_finding(meta={"scanner": "nuclei"}))
    )

    assert "Found by: nuclei" in html


def test_report_renders_provenance_from_found_by():
    html = generate_html_report(
        _results(_minimal_finding(found_by=["nuclei"]))
    )

    assert "Found by: nuclei" in html


def test_report_renders_provenance_for_merged_findings():
    html = generate_html_report(
        _results(_minimal_finding(found_by=["zap", "nuclei"]))
    )

    assert "Found by: zap, nuclei" in html


def test_report_renders_provenance_from_source_findings_scanners():
    html = generate_html_report(
        _results(
            _minimal_finding(
                source_findings=[
                    {"scanner": "zap"},
                    {"scanner": "nuclei"},
                    {"scanner": "zap"},
                ]
            )
        )
    )

    assert "Found by: zap, nuclei" in html


def test_report_renders_unknown_provenance_when_scanner_metadata_missing():
    html = generate_html_report(
        _results(_minimal_finding())
    )

    assert "Found by: unknown" in html
