import json
import pytest

from utils.comparator import (
    _build_comparison_profile,
    add_comparison_to_results,
    compare_scans,
    compare_with_previous,
    print_comparison_summary,
)
from utils.report_generator import _extract_cve_ids
from utils.run_folder import create_target_slug


def _source_record(
    scanner: str,
    asset_id: str,
    vulnerability_name: str = "XSS",
    severity: str = "high",
    description: str = "desc",
    remediation: str = "fix",
    meta: dict | None = None,
    **extra,
) -> dict:
    record = {
        "scanner": scanner,
        "vulnerability_name": vulnerability_name,
        "severity": severity,
        "asset_id": asset_id,
        "description": description,
        "remediation": remediation,
        "meta": {"scanner": scanner, **(meta or {})},
    }
    record.update(extra)
    return record


def _finding(
    asset_id: str,
    scanner: str = "nuclei",
    vulnerability_name: str = "XSS",
    severity: str = "high",
    description: str = "desc",
    remediation: str = "fix",
    meta: dict | None = None,
    found_by: list[str] | None = None,
    source_findings: list[dict] | None = None,
    **extra,
) -> dict:
    finding = {
        "vulnerability_name": vulnerability_name,
        "severity": severity,
        "asset_id": asset_id,
        "description": description,
        "remediation": remediation,
        "meta": {"scanner": scanner, **(meta or {})},
    }
    if found_by is not None:
        finding["found_by"] = found_by
    if source_findings is not None:
        finding["source_findings"] = source_findings
    finding.update(extra)
    return finding


def _results(target: str, findings: list[dict], scanners_run: list[str]) -> dict:
    return {
        "schema_version": "2.0",
        "target": target,
        "timestamp": "2026-04-05T10:00:00Z",
        "scanners_run": scanners_run,
        "all_findings": findings,
        "summary": {"total_findings": len(findings)},
    }


def _write_run(base_dir, target: str, run_name: str, findings: list[dict], scanners_run: list[str]):
    run_dir = base_dir / create_target_slug(target) / run_name
    run_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "2.0",
        "target": target,
        "timestamp": f"{run_name}Z",
        "scanners_run": scanners_run,
        "all_findings": findings,
        "summary": {"total_findings": len(findings)},
    }
    path = run_dir / "normalized.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_compare_scans_tracks_fixed_when_one_of_multiple_paths_disappears():
    previous = [
        _finding("https://example.com/a"),
        _finding("https://example.com/b"),
    ]
    current = [
        _finding("https://example.com/b"),
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert len(fixed) == 1
    assert fixed[0]["asset_id"] == "https://example.com/a"
    assert len(new) == 0
    assert len(changed) == 0
    assert len(persistent) == 1
    assert persistent[0]["asset_id"] == "https://example.com/b"


@pytest.mark.parametrize(
    ("meta", "vulnerability_name", "expected"),
    [
        ({"cve_ids": ["cve-2024-1111", "CVE-2024-2222"]}, "Test Vuln", ["CVE-2024-1111", "CVE-2024-2222"]),
        ({"cve_id": "cve-2024-3333"}, "Test Vuln", ["CVE-2024-3333"]),
        ({"cve": "CVE-2024-4444"}, "Test Vuln", ["CVE-2024-4444"]),
        ({"raw_id": "cve-2024-5555"}, "Test Vuln", ["CVE-2024-5555"]),
        ({"raw_id": "plugin-1"}, "cve-2024-6666", ["CVE-2024-6666"]),
    ],
)
def test_comparator_profile_and_report_agree_on_exact_cve_sources(meta, vulnerability_name, expected):
    finding = _finding(
        "https://example.com",
        vulnerability_name=vulnerability_name,
        meta=meta,
    )

    profile = _build_comparison_profile(0, finding)

    assert _extract_cve_ids(finding) == expected
    assert set(profile.cves) == set(expected)


def test_comparator_and_report_ignore_non_exact_cve_raw_id():
    finding = _finding(
        "https://example.com",
        vulnerability_name="Generic finding",
        meta={"raw_id": "plugin-CVE-2024-7777"},
    )

    profile = _build_comparison_profile(0, finding)

    assert _extract_cve_ids(finding) == []
    assert profile.cves == set()


def test_compare_scans_matches_same_logical_vulnerability_despite_title_wording_drift():
    previous = [
        _finding(
            "https://example.com/search?q=test",
            vulnerability_name="Cross-site scripting",
            meta={"cwe": "CWE-79", "path": "/search", "parameter": "q"},
        )
    ]
    current = [
        _finding(
            "https://example.com/search?query=test",
            vulnerability_name="Reflected XSS",
            description="Different wording from another scanner.",
            remediation="Different remediation prose.",
            meta={"cwe": "CWE-79", "path": "/search", "parameter": "query"},
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert changed == []
    assert len(persistent) == 1
    assert persistent[0]["status"] == "PERSISTENT"


def test_compare_scans_matches_same_web_issue_despite_minor_path_query_and_parameter_drift():
    previous = [
        _finding(
            "https://example.com/app/search?q=test",
            vulnerability_name="SQL injection",
            meta={"cwe": "CWE-89", "path": "/app/search", "parameter": "q", "query_keys": ["q"]},
        )
    ]
    current = [
        _finding(
            "https://example.com/app/search/results?term=test",
            vulnerability_name="Blind SQL injection",
            meta={"cwe": "CWE-89", "path": "/app/search/results", "parameter": "term", "query_keys": ["term"]},
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert changed == []
    assert len(persistent) == 1


def test_compare_scans_matches_merged_cluster_even_when_base_scanner_changes():
    previous = [
        _finding(
            "https://example.com/login",
            scanner="nuclei",
            vulnerability_name="Cross-site scripting",
            severity="high",
            found_by=["nuclei", "zap"],
            source_findings=[
                _source_record(
                    "nuclei",
                    "https://example.com/login",
                    vulnerability_name="Cross-site scripting",
                    severity="high",
                    meta={"template_id": "xss-login", "path": "/login"},
                ),
                _source_record(
                    "zap",
                    "https://example.com/login?next=/admin",
                    vulnerability_name="Reflected XSS",
                    severity="medium",
                    meta={"raw_id": "zap-40012", "cwe": "CWE-79", "path": "/login", "parameter": "next"},
                ),
            ],
        )
    ]
    current = [
        _finding(
            "https://example.com/login?return=/admin",
            scanner="zap",
            vulnerability_name="Reflected XSS",
            severity="medium",
            found_by=["zap", "nuclei"],
            source_findings=[
                _source_record(
                    "zap",
                    "https://example.com/login?return=/admin",
                    vulnerability_name="Reflected XSS",
                    severity="medium",
                    meta={"raw_id": "zap-40012", "cwe": "CWE-79", "path": "/login", "parameter": "return"},
                ),
                _source_record(
                    "nuclei",
                    "https://example.com/login",
                    vulnerability_name="Cross-site scripting",
                    severity="high",
                    meta={"template_id": "xss-login", "path": "/login"},
                ),
            ],
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert changed == []
    assert len(persistent) == 1
    assert persistent[0]["status"] == "PERSISTENT"


def test_compare_scans_uses_shared_template_or_raw_id_as_strong_match_signal():
    previous = [
        _finding(
            "https://example.com/admin",
            vulnerability_name="Generic template finding",
            meta={"template_id": "exposed-admin-panel", "path": "/admin"},
        )
    ]
    current = [
        _finding(
            "https://example.com/admin/",
            vulnerability_name="Completely different title wording",
            meta={"template_id": "exposed-admin-panel", "path": "/admin/"},
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert changed == []
    assert len(persistent) == 1


def test_compare_scans_does_not_match_findings_on_different_hosts():
    previous = [
        _finding(
            "https://old.example.com/login",
            vulnerability_name="Cross-site scripting",
            meta={"cwe": "CWE-79", "path": "/login"},
        )
    ]
    current = [
        _finding(
            "https://new.example.com/login",
            vulnerability_name="Cross-site scripting",
            meta={"cwe": "CWE-79", "path": "/login"},
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert len(fixed) == 1
    assert len(new) == 1
    assert persistent == []
    assert changed == []


def test_compare_scans_marks_meaningful_severity_confidence_and_source_changes_as_changed():
    previous = [
        _finding(
            "https://example.com/app",
            vulnerability_name="SQL injection",
            severity="medium",
            remediation="",
            found_by=["nuclei"],
            source_findings=[
                _source_record(
                    "nuclei",
                    "https://example.com/app",
                    vulnerability_name="SQL injection",
                    severity="medium",
                    remediation="",
                    meta={"template_id": "sqli-template", "cwe": "CWE-89", "confidence": "low", "path": "/app"},
                )
            ],
        )
    ]
    current = [
        _finding(
            "https://example.com/app",
            vulnerability_name="Blind SQL injection",
            severity="high",
            remediation="Rotate credentials and parameterize queries.",
            found_by=["nuclei", "zap"],
            source_findings=[
                _source_record(
                    "nuclei",
                    "https://example.com/app",
                    vulnerability_name="Blind SQL injection",
                    severity="high",
                    remediation="Rotate credentials and parameterize queries.",
                    meta={"template_id": "sqli-template", "cwe": "CWE-89", "confidence": "high", "path": "/app"},
                ),
                _source_record(
                    "zap",
                    "https://example.com/app?id=1",
                    vulnerability_name="SQL injection",
                    severity="high",
                    remediation="Rotate credentials and parameterize queries.",
                    meta={"raw_id": "zap-40018", "cwe": "CWE-89", "confidence": "medium", "path": "/app", "parameter": "id"},
                ),
            ],
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert persistent == []
    assert len(changed) == 1
    assert changed[0]["status"] == "CHANGED"
    assert set(changed[0]["changed_fields"]) >= {
        "severity",
        "confidence",
        "source_scanners",
        "remediation_available",
    }


def test_compare_scans_ignores_description_and_base_source_wording_drift_when_nothing_meaningful_changed():
    previous = [
        _finding(
            "https://example.com/profile",
            scanner="nuclei",
            vulnerability_name="Cross-site scripting",
            description="Old description.",
            remediation="Old remediation.",
            found_by=["nuclei", "zap"],
            source_findings=[
                _source_record(
                    "nuclei",
                    "https://example.com/profile",
                    vulnerability_name="Cross-site scripting",
                    severity="high",
                    description="Old description.",
                    remediation="Old remediation.",
                    meta={"template_id": "profile-xss", "cwe": "CWE-79", "path": "/profile"},
                ),
                _source_record(
                    "zap",
                    "https://example.com/profile?name=test",
                    vulnerability_name="Reflected XSS",
                    severity="medium",
                    description="Scanner-specific text.",
                    remediation="Scanner-specific fix.",
                    meta={"raw_id": "zap-40012", "cwe": "CWE-79", "path": "/profile", "parameter": "name"},
                ),
            ],
        )
    ]
    current = [
        _finding(
            "https://example.com/profile?username=test",
            scanner="zap",
            vulnerability_name="Reflected XSS",
            description="Whitespace and wording changed only.",
            remediation="Another wording of the same fix.",
            found_by=["zap", "nuclei"],
            source_findings=[
                _source_record(
                    "zap",
                    "https://example.com/profile?username=test",
                    vulnerability_name="Reflected XSS",
                    severity="medium",
                    description="Scanner-specific text with different wording.",
                    remediation="Scanner-specific fix with different wording.",
                    meta={"raw_id": "zap-40012", "cwe": "CWE-79", "path": "/profile", "parameter": "username"},
                ),
                _source_record(
                    "nuclei",
                    "https://example.com/profile",
                    vulnerability_name="Cross-site scripting",
                    severity="high",
                    description="Old description, reformatted.",
                    remediation="Old remediation, reformatted.",
                    meta={"template_id": "profile-xss", "cwe": "CWE-79", "path": "/profile"},
                ),
            ],
        )
    ]

    fixed, new, persistent, changed = compare_scans(current, previous)

    assert fixed == []
    assert new == []
    assert changed == []
    assert len(persistent) == 1


def test_compare_with_previous_proceeds_for_identical_scanner_sets(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "zap"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["zap", "nuclei"])

    comparison = compare_with_previous(current, tmp_path, baseline_path)
    payload = comparison.to_dict()["comparison"]

    assert payload["compatible_baseline_used"] is True
    assert payload["comparison_mode"] == "full"
    assert payload["old_scan"] == str(baseline_path)
    assert payload["current_scanners_run"] == ["nuclei", "zap"]
    assert payload["previous_scanners_run"] == ["nuclei", "zap"]
    assert payload["overlapping_scanners"] == ["nuclei", "zap"]
    assert payload["missing_from_current"] == []
    assert payload["missing_from_previous"] == []
    assert payload["summary"]["persistent"] == 1
    assert comparison.persistent[0]["status"] == "PERSISTENT"


def test_compare_with_previous_allows_partial_scanner_overlap_with_clear_metadata(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "zap"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["nuclei", "nikto"])

    comparison = compare_with_previous(current, tmp_path, baseline_path)
    payload = comparison.to_dict()["comparison"]

    assert payload["compatible_baseline_used"] is True
    assert payload["comparison_mode"] == "partial"
    assert "partial scanner overlap" in payload["compatibility_reason"].lower()
    assert payload["overlapping_scanners"] == ["nuclei"]
    assert payload["missing_from_current"] == ["zap"]
    assert payload["missing_from_previous"] == ["nikto"]
    assert payload["summary"]["fixed"] == 0
    assert payload["summary"]["new"] == 0
    assert payload["summary"]["persistent"] == 1
    assert payload["summary"]["partial_unmatched_current"] == 0
    assert payload["summary"]["partial_unmatched_previous"] == 0
    assert comparison.persistent[0]["status"] == "PERSISTENT"


def test_partial_mode_does_not_mark_missing_previous_finding_as_fixed_when_coverage_differs(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [
            _finding("https://example.com/shared", scanner="nuclei"),
            _finding("https://example.com/zap-only", scanner="zap"),
        ],
        ["nuclei", "zap"],
    )
    current = _results(target, [_finding("https://example.com/shared", scanner="nuclei")], ["nuclei"])

    comparison = compare_with_previous(current, tmp_path, baseline_path)
    payload = comparison.to_dict()["comparison"]

    assert payload["comparison_mode"] == "partial"
    assert comparison.fixed == []
    assert payload["summary"]["fixed"] == 0
    assert payload["summary"]["partial_unmatched_previous"] == 1
    assert len(comparison.partial_unmatched_previous) == 1
    assert comparison.partial_unmatched_previous[0]["asset_id"] == "https://example.com/zap-only"
    assert comparison.partial_unmatched_previous[0]["comparison_mode"] == "partial"


def test_partial_mode_does_not_mark_missing_current_finding_as_new_when_coverage_differs(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/shared", scanner="nuclei")],
        ["nuclei"],
    )
    current = _results(
        target,
        [
            _finding("https://example.com/shared", scanner="nuclei"),
            _finding("https://example.com/nikto-only", scanner="nikto"),
        ],
        ["nuclei", "nikto"],
    )

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["comparison_mode"] == "partial"
    assert compared["comparison"]["summary"]["new"] == 0
    assert compared["fixed_findings"] == []
    assert len(compared["partial_unmatched_current_findings"]) == 1
    assert compared["partial_unmatched_current_findings"][0]["asset_id"] == "https://example.com/nikto-only"
    assert compared["partial_unmatched_current_findings"][0]["comparison_mode"] == "partial"
    assert "status" not in compared["all_findings"][1]


def test_partial_mode_still_allows_changed_matching_for_confident_match(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a", severity="medium")],
        ["nuclei", "zap"],
    )
    current = _results(target, [_finding("https://example.com/a", severity="high")], ["nuclei", "nikto"])

    comparison = compare_with_previous(current, tmp_path, baseline_path)

    assert comparison.comparison_mode == "partial"
    assert comparison.fixed == []
    assert comparison.new == []
    assert comparison.persistent == []
    assert len(comparison.changed) == 1
    assert comparison.changed[0]["status"] == "CHANGED"
    assert "severity" in comparison.changed[0]["changed_fields"]


def test_changed_and_persistent_findings_do_not_expose_internal_match_diagnostics(tmp_path):
    target = "example.com"
    baseline_path = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a", severity="medium")],
        ["nuclei"],
    )
    current = _results(target, [_finding("https://example.com/a", severity="high")], ["nuclei"])

    compared = add_comparison_to_results(current, tmp_path)
    changed = compared["all_findings"][0]

    assert changed["status"] == "CHANGED"
    assert "comparison_match_score" not in changed
    assert "comparison_match_reasons" not in changed
    assert "previous_match_id" not in changed
    assert "status_info" not in changed
    assert "previous_values" not in changed


def test_add_comparison_skips_incompatible_scanner_set(tmp_path):
    target = "example.com"
    _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a", scanner="nmap")],
        ["nmap"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["nuclei", "zap"])

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["compatible_baseline_used"] is False
    assert compared["comparison"]["comparison_mode"] == "skipped"
    assert "no overlap" in compared["comparison"]["compatibility_reason"].lower()
    assert compared["comparison"]["current_scanners_run"] == ["nuclei", "zap"]
    assert compared["comparison"]["previous_scanners_run"] == ["nmap"]
    assert compared["comparison"]["overlapping_scanners"] == []
    assert compared["comparison"]["summary"] == {}
    assert compared["fixed_findings"] == []
    assert compared["changed_findings"] == []
    assert "status" not in compared["all_findings"][0]


def test_add_comparison_uses_older_compatible_baseline_when_latest_is_incompatible(tmp_path):
    target = "example.com"
    older_compatible = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "zap"],
    )
    _write_run(
        tmp_path,
        target,
        "20260402_100000",
        [_finding("https://example.com/a", scanner="nmap")],
        ["nmap"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["zap", "nuclei"])

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["compatible_baseline_used"] is True
    assert compared["comparison"]["comparison_mode"] == "full"
    assert compared["comparison"]["old_scan"] == str(older_compatible)
    assert compared["comparison"]["previous_scanners_run"] == ["nuclei", "zap"]
    assert compared["comparison"]["summary"]["persistent"] == 1
    assert compared["all_findings"][0]["status"] == "PERSISTENT"


def test_add_comparison_prefers_newest_full_baseline_over_newer_partial_baseline(tmp_path):
    target = "example.com"
    older_full = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "zap"],
    )
    _write_run(
        tmp_path,
        target,
        "20260402_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "nikto"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["zap", "nuclei"])

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["compatible_baseline_used"] is True
    assert compared["comparison"]["comparison_mode"] == "full"
    assert compared["comparison"]["old_scan"] == str(older_full)


def test_add_comparison_uses_older_partially_compatible_baseline_when_latest_has_no_overlap(tmp_path):
    target = "example.com"
    older_partial = _write_run(
        tmp_path,
        target,
        "20260401_100000",
        [_finding("https://example.com/a")],
        ["nuclei", "zap"],
    )
    _write_run(
        tmp_path,
        target,
        "20260402_100000",
        [_finding("https://example.com/a", scanner="nmap")],
        ["nmap"],
    )
    current = _results(target, [_finding("https://example.com/a")], ["nuclei", "nikto"])

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["compatible_baseline_used"] is True
    assert compared["comparison"]["comparison_mode"] == "partial"
    assert compared["comparison"]["old_scan"] == str(older_partial)
    assert compared["comparison"]["overlapping_scanners"] == ["nuclei"]
    assert compared["comparison"]["summary"]["persistent"] == 1
    assert compared["comparison"]["summary"]["fixed"] == 0
    assert compared["comparison"]["summary"]["new"] == 0
    assert compared["all_findings"][0]["status"] == "PERSISTENT"


def test_add_comparison_uses_safe_no_baseline_behavior_when_no_compatible_history_exists(tmp_path):
    target = "example.com"
    _write_run(tmp_path, target, "20260401_100000", [_finding("https://example.com/a", scanner="nmap")], ["nmap"])
    _write_run(tmp_path, target, "20260402_100000", [_finding("https://example.com/a", scanner="wapiti")], ["wapiti"])
    current = _results(target, [_finding("https://example.com/a")], ["nuclei", "zap"])

    compared = add_comparison_to_results(current, tmp_path)

    assert compared["comparison"]["compatible_baseline_used"] is False
    assert compared["comparison"]["comparison_mode"] == "skipped"
    assert compared["comparison"]["summary"] == {}
    assert "status" not in compared["all_findings"][0]


def test_print_comparison_summary_skipped_incompatible_baseline_is_clear(capsys):
    print_comparison_summary(
        {
            "comparison": {
                "compatible_baseline_used": False,
                "comparison_mode": "skipped",
                "compatibility_reason": "Comparison skipped because scanner coverage had no overlap between scans.",
                "current_scanners_run": ["nuclei", "zap"],
                "previous_scanners_run": ["nmap"],
                "summary": {},
            }
        }
    )

    out = capsys.readouterr().out
    assert "Comparison skipped because scanner coverage had no overlap between scans." in out
    assert "Current scanners: nuclei, zap" in out
    assert "Previous scanners: nmap" in out
    assert "FIXED" not in out


def test_print_comparison_summary_partial_baseline_shows_overlap_details(capsys):
    print_comparison_summary(
        {
            "comparison": {
                "compatible_baseline_used": True,
                "comparison_mode": "partial",
                "old_scan": "/tmp/example/normalized.json",
                "old_scan_timestamp": "2026-04-10T00:00:00Z",
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
                    "partial_unmatched_current": 1,
                    "partial_unmatched_previous": 2,
                    "total_current": 1,
                },
            }
        }
    )

    out = capsys.readouterr().out
    assert "partial scanner overlap" in out.lower()
    assert "Overlapping scanners: nuclei" in out
    assert "Missing from current: zap" in out
    assert "Missing from previous: nikto" in out
    assert "not classified as fixed/new" in out.lower()
    assert "CURRENT UNCERTAIN" in out


def test_compare_with_previous_rejects_explicit_wrong_target_baseline(tmp_path):
    baseline_path = _write_run(
        tmp_path,
        "other.example.com",
        "20260401_100000",
        [_finding("https://other.example.com/a")],
        ["nuclei"],
    )
    current = _results("example.com", [_finding("https://example.com/a")], ["nuclei"])

    with pytest.raises(ValueError, match="COMPARATOR SAFETY CHECK FAILED"):
        compare_with_previous(current, tmp_path, baseline_path)
