import json

from utils.defectdojo_export import (
    build_defectdojo_generic_report,
    write_defectdojo_generic_report,
)


def _finding(**overrides):
    finding = {
        "vulnerability_name": "SQL Injection",
        "severity": "high",
        "asset_id": "https://example.com/search?q=1",
        "description": "Scanner observed injectable input handling. à",
        "remediation": "Use parameterized queries.",
        "priority": "P1",
        "risk_score": 88,
        "risk_rationale": "Final score: 88. Priority: P1.",
        "status": "CHANGED",
        "found_by": ["zap", "nuclei"],
        "meta": {
            "timestamp": "2026-04-21T12:30:00Z",
            "cwe": "CWE-89",
            "cve_id": "CVE-2026-0001",
            "references": ["https://cwe.mitre.org/data/definitions/89.html"],
            "host": "example.com",
            "port": 443,
            "path": "/search",
            "scheme": "https",
            "parameter": "q",
            "method": "GET",
            "query_keys": ["q"],
            "scanner": "zap",
        },
        "source_findings": [
            {"references": ["https://nuclei.example/template"]},
            {"references": ["https://cwe.mitre.org/data/definitions/89.html"]},
        ],
    }
    finding.update(overrides)
    if "meta" in overrides:
        finding["meta"] = overrides["meta"]
    return finding


def _results(*findings):
    return {
        "schema_version": "2.0",
        "target": "example.com",
        "generated_at": "2026-04-22T00:00:00Z",
        "all_findings": list(findings),
    }


def test_build_defectdojo_generic_report_maps_one_valid_finding():
    report = build_defectdojo_generic_report(_results(_finding()))

    assert list(report.keys()) == ["name", "findings"]
    assert "type" not in report
    assert report["name"] == "Vuln Manager findings for example.com at 2026-04-22T00:00:00Z"

    finding = report["findings"][0]
    assert finding["title"] == "SQL Injection"
    assert finding["severity"] == "High"
    assert finding["description"] == "Scanner observed injectable input handling. à"
    assert finding["mitigation"] == "Use parameterized queries."
    assert finding["date"] == "2026-04-21"
    assert finding["cwe"] == 89
    assert finding["cve"] == "CVE-2026-0001"
    assert finding["severity_justification"] == "Final score: 88. Priority: P1."
    assert finding["impact"] == "Risk score: 88\nPriority: P1\nRationale: Final score: 88. Priority: P1."
    assert finding["tags"] == [
        "priority:P1",
        "scanner:nuclei",
        "scanner:zap",
        "source:vuln-manager",
        "status:CHANGED",
    ]
    assert finding["references"] == (
        "https://cwe.mitre.org/data/definitions/89.html\n"
        "https://nuclei.example/template"
    )
    assert finding["endpoints"] == ["https://example.com/search?q=1"]
    assert finding["static_finding"] is False
    assert finding["dynamic_finding"] is True
    assert finding["unique_id_from_tool"].startswith("vm-")


def test_export_uses_deterministic_fallbacks_and_cwe_integer_support():
    report = build_defectdojo_generic_report(
        _results(
            _finding(
                description="",
                remediation="",
                asset_id="db.internal",
                meta={
                    "cwe": 79,
                    "cve_ids": ["CVE-2026-0002"],
                    "host": "db.internal",
                    "port": 8443,
                    "path": "/admin",
                    "scheme": "https",
                },
                found_by=["nmap"],
                source_findings=[],
            )
        )
    )

    finding = report["findings"][0]
    assert finding["description"] == "No scanner description was provided. Affected asset: db.internal."
    assert finding["mitigation"] == "No scanner remediation was provided."
    assert finding["cwe"] == 79
    assert finding["cve"] == "CVE-2026-0002"
    assert finding["date"] == "2026-04-22"
    assert finding["endpoints"] == [{"host": "db.internal", "port": 8443, "path": "/admin", "protocol": "https"}]


def test_unique_id_from_tool_is_stable_for_same_input():
    results = _results(_finding())

    first = build_defectdojo_generic_report(results)
    second = build_defectdojo_generic_report(results)

    assert first["findings"][0]["unique_id_from_tool"] == second["findings"][0]["unique_id_from_tool"]
    assert json.dumps(first, ensure_ascii=False) == json.dumps(second, ensure_ascii=False)


def test_export_omits_unsupported_fields_instead_of_inventing_values():
    report = build_defectdojo_generic_report(
        _results(
            {
                "vulnerability_name": "Open Port",
                "severity": "info",
                "asset_id": "10.0.0.5",
                "description": "Port 22 is open.",
                "remediation": "Close unused ports.",
                "meta": {},
            }
        )
    )

    finding = report["findings"][0]
    assert finding["severity"] == "Info"
    assert finding["date"] == "2026-04-22"
    assert "cwe" not in finding
    assert "cve" not in finding
    assert "impact" not in finding
    assert "severity_justification" not in finding
    assert "references" not in finding
    assert "endpoints" not in finding
    assert "static_finding" not in finding
    assert "dynamic_finding" not in finding
    assert "cvssv3" not in finding


def test_write_defectdojo_generic_report_preserves_unicode_and_structure(tmp_path):
    output_path = tmp_path / "defectdojo_generic.json"
    write_defectdojo_generic_report(_results(_finding()), output_path)

    text = output_path.read_text(encoding="utf-8")
    payload = json.loads(text)

    assert output_path.exists()
    assert "à" in text
    assert list(payload.keys()) == ["name", "findings"]
    assert list(payload["findings"][0].keys()) == [
        "title",
        "severity",
        "description",
        "mitigation",
        "date",
        "cwe",
        "cve",
        "severity_justification",
        "impact",
        "tags",
        "unique_id_from_tool",
        "references",
        "endpoints",
        "static_finding",
        "dynamic_finding",
    ]
