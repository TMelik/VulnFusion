from scanners.nikto_scanner import NiktoScanner
from scanners.nuclei_scanner import NucleiScanner
from scanners.wapiti_scanner import WapitiScanner
from utils.schema import validate_finding


def test_nuclei_normalize_preserves_scanner_description_remediation_and_evidence_fields():
    scanner = NucleiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-15T00:00:00Z",
            "target": "https://example.com",
            "findings": [
                {
                    "template-id": "panel-detect",
                    "matched-at": "https://example.com/admin",
                    "matcher-name": "word",
                    "extracted-results": ["admin"],
                    "info": {
                        "name": "Exposed Admin Panel",
                        "severity": "medium",
                        "description": "Scanner-reported description.",
                        "remediation": "Scanner-reported remediation.",
                    },
                }
            ],
        }
    )

    finding = normalized[0]
    assert finding["description"] == "Scanner-reported description."
    assert finding["remediation"] == "Scanner-reported remediation."
    assert finding["meta"]["matcher_name"] == "word"
    assert finding["meta"]["extracted_results"] == ["admin"]
    assert "Matcher:" not in finding["description"]
    assert "Extracted:" not in finding["description"]


def test_nuclei_normalize_leaves_missing_text_empty():
    scanner = NucleiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-15T00:00:00Z",
            "target": "https://example.com",
            "findings": [
                {
                    "template-id": "panel-detect",
                    "matched-at": "https://example.com/admin",
                    "info": {
                        "name": "Exposed Admin Panel",
                        "severity": "medium",
                    },
                }
            ],
        }
    )

    finding = normalized[0]
    ok, errors = validate_finding(finding)

    assert ok, errors
    assert finding["description"] == ""
    assert finding["remediation"] == ""


def test_wapiti_normalize_keeps_missing_text_empty_and_preserves_classification_metadata():
    scanner = WapitiScanner()

    normalized = scanner.normalize(
        {
            "timestamp": "2026-04-15T00:00:00Z",
            "target": "https://example.com",
            "raw_output": {
                "target": "https://example.com",
                "classifications": {
                    "sql": {
                        "desc": "Classification description",
                        "sol": "Classification solution",
                    }
                },
            },
            "findings": [
                {
                    "name": "SQL Injection",
                    "path": "/login",
                    "_category": "sql",
                    "_type": "vulnerabilities",
                }
            ],
        }
    )

    finding = normalized[0]
    ok, errors = validate_finding(finding)

    assert ok, errors
    assert finding["description"] == ""
    assert finding["remediation"] == ""
    assert finding["meta"]["classification_description"] == "Classification description"
    assert finding["meta"]["classification_solution"] == "Classification solution"


def test_nikto_normalize_preserves_scanner_text_and_leaves_missing_remediation_empty():
    scanner = NiktoScanner()

    preserved = scanner.normalize(
        {
            "timestamp": "2026-04-15T00:00:00Z",
            "target": "https://example.com",
            "findings": [
                {
                    "msg": "Nikto title",
                    "description": "Nikto scanner description",
                    "solution": "Nikto scanner fix",
                    "uri": "/admin",
                }
            ],
        }
    )[0]

    missing = scanner.normalize(
        {
            "timestamp": "2026-04-15T00:00:00Z",
            "target": "https://example.com",
            "findings": [
                {
                    "msg": "Nikto title",
                    "uri": "/admin",
                }
            ],
        }
    )[0]

    ok, errors = validate_finding(missing)

    assert preserved["description"] == "Nikto scanner description"
    assert preserved["remediation"] == "Nikto scanner fix"
    assert missing["description"] == "Nikto title"
    assert missing["remediation"] == ""
    assert ok, errors
