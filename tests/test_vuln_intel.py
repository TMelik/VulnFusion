import builtins
import json

from utils.schema import validate_finding
from utils.vuln_intel import (
    clear_vuln_intel_caches,
    enrich_findings_with_vuln_intel,
    extract_cve_ids,
    load_vulnerability_intelligence,
)


def _finding(**meta) -> dict:
    return {
        "vulnerability_name": "Test Vuln",
        "severity": "high",
        "asset_id": "https://example.com",
        "description": "A test vulnerability.",
        "remediation": "Fix it.",
        "meta": meta,
    }


def test_single_cve_gets_enriched_with_cvss_epss_and_kev(tmp_path):
    cvss_file = tmp_path / "cvss.json"
    epss_file = tmp_path / "epss.json"
    kev_file = tmp_path / "kev.json"

    cvss_file.write_text(json.dumps({
        "CVE-2024-1001": {
            "cvss_v4_score": 9.8,
            "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "source": "offline-cvss",
        }
    }))
    epss_file.write_text(json.dumps({
        "CVE-2024-1001": {
            "epss": 0.81,
            "percentile": 0.97,
            "source": "offline-epss",
        }
    }))
    kev_file.write_text(json.dumps({
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-1001",
                "dueDate": "2026-06-01",
                "source": "CISA KEV",
            }
        ]
    }))

    finding = _finding(cve_id="cve-2024-1001")

    enrich_findings_with_vuln_intel(
        [finding],
        cvss_file=str(cvss_file),
        epss_file=str(epss_file),
        kev_file=str(kev_file),
    )

    meta = finding["meta"]
    assert meta["cve_id"] == "CVE-2024-1001"
    assert meta["cve_ids"] == ["CVE-2024-1001"]
    assert meta["cvss_score"] == 9.8
    assert meta["cvss_version"] == "4.0"
    assert meta["cvss_source"] == "offline-cvss"
    assert meta["epss_score"] == 0.81
    assert meta["epss_percentile"] == 0.97
    assert meta["epss_source"] == "offline-epss"
    assert meta["kev_listed"] is True
    assert meta["kev_source"] == "CISA KEV"
    assert meta["kev_due_date"] == "2026-06-01"
    assert meta["cve_intelligence_candidates"][0]["cve_id"] == "CVE-2024-1001"

    ok, errs = validate_finding(finding)
    assert ok is True, errs


def test_multiple_cves_select_highest_risk_candidate(tmp_path):
    cvss_file = tmp_path / "cvss.json"
    kev_file = tmp_path / "kev.json"

    cvss_file.write_text(json.dumps({
        "CVE-2024-2001": {"cvss_score": 8.2, "cvss_version": "3.1"},
        "CVE-2024-2002": {"cvss_score": 8.8, "cvss_version": "3.1"},
    }))
    kev_file.write_text(json.dumps({
        "vulnerabilities": [
            {"cveID": "CVE-2024-2002", "dueDate": "2026-07-01", "source": "CISA KEV"}
        ]
    }))

    finding = _finding(cve_ids=["cve-2024-2001", "CVE-2024-2002"])

    enrich_findings_with_vuln_intel(
        [finding],
        cvss_file=str(cvss_file),
        kev_file=str(kev_file),
    )

    meta = finding["meta"]
    assert meta["cve_ids"] == ["CVE-2024-2001", "CVE-2024-2002"]
    assert meta["cve_id"] == "CVE-2024-2002"
    assert meta["cvss_score"] == 8.8
    assert meta["kev_listed"] is True


def test_malformed_cves_are_ignored_safely():
    finding = _finding(
        scanner="nuclei",
        host="example.com",
        path="/login",
        business_context={"environment": "production"},
        evidence_quality={"confidence": "high", "repeatable": True},
        cve_id="not-a-cve",
        cve_ids=["broken", "CVE2024-9999"],
        cvss=8.2,
        cvss_score=8.2,
        cvss_version="3.1",
        cvss_vector="stale-vector",
        cvss_source="stale-cvss",
        epss_score=0.75,
        epss_percentile=0.92,
        epss_source="stale-epss",
        kev_listed=True,
        kev_source="stale-kev",
        kev_due_date="2020-01-01",
        cve_intelligence_candidates=[
            {
                "cve_id": "CVE-2024-9999",
                "cvss_score": 8.2,
                "cvss_version": "3.1",
                "cvss_source": "stale-cvss",
                "epss_score": 0.75,
                "epss_source": "stale-epss",
                "kev_listed": True,
                "kev_source": "stale-kev",
                "kev_due_date": "2020-01-01",
            }
        ],
    )

    enrich_findings_with_vuln_intel([finding])

    meta = finding["meta"]
    assert extract_cve_ids(finding) == []
    assert meta["cve_ids"] == []
    assert "cve_id" not in meta
    for field in (
        "cve_intelligence_candidates",
        "cvss",
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
    ):
        assert field not in meta
    assert meta["scanner"] == "nuclei"
    assert meta["host"] == "example.com"
    assert meta["path"] == "/login"
    assert meta["business_context"] == {"environment": "production"}
    assert meta["evidence_quality"] == {"confidence": "high", "repeatable": True}
    ok, errs = validate_finding(finding)
    assert ok is True, errs


def test_findings_without_cves_remain_valid_and_unchanged():
    expected_meta = {
        "scanner": "zap",
        "host": "example.com",
        "path": "/",
        "business_context": {
            "asset_criticality": "medium",
            "internet_exposed": True,
            "environment": "production",
            "sensitive_data": False,
            "requires_auth": False,
        },
        "evidence_quality": {
            "confidence": "medium",
            "repeatable": True,
        },
    }
    finding = _finding(**expected_meta)

    enrich_findings_with_vuln_intel([finding])

    assert finding["meta"] == expected_meta
    ok, errs = validate_finding(finding)
    assert ok is True, errs


def test_cached_intelligence_loading_avoids_repeated_file_reads(tmp_path, monkeypatch):
    clear_vuln_intel_caches()
    cvss_file = tmp_path / "cvss.json"
    cvss_file.write_text(json.dumps({"CVE-2024-3001": {"cvss_score": 7.5, "cvss_version": "3.1"}}))

    counter = {"opens": 0}

    def counting_open(*args, **kwargs):
        if args and str(args[0]) == str(cvss_file.resolve()):
            counter["opens"] += 1
        return builtins.open(*args, **kwargs)

    monkeypatch.setattr("utils.vuln_intel.open", counting_open, raising=False)

    load_vulnerability_intelligence(cvss_file=str(cvss_file))
    load_vulnerability_intelligence(cvss_file=str(cvss_file))

    assert counter["opens"] == 1


def test_external_enrichment_replaces_weaker_stale_canonical_fields(tmp_path):
    cvss_file = tmp_path / "cvss.json"
    epss_file = tmp_path / "epss.json"
    kev_file = tmp_path / "kev.json"

    cvss_file.write_text(json.dumps({
        "CVE-2024-4001": {
            "cvss_v4_score": 9.9,
            "cvss_v4_vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H",
            "source": "better-cvss",
        }
    }))
    epss_file.write_text(json.dumps({
        "CVE-2024-4001": {"epss": 0.91, "percentile": 0.99}
    }))
    kev_file.write_text(json.dumps({
        "vulnerabilities": [{"cveID": "CVE-2024-4001", "source": "CISA KEV"}]
    }))

    finding = _finding(
        cve_id="CVE-2024-4001",
        cvss_score=4.0,
        cvss_version="3.1",
        cvss_vector="old-vector",
        epss_score=0.05,
        epss_percentile=0.10,
        kev_listed=False,
    )

    enrich_findings_with_vuln_intel(
        [finding],
        cvss_file=str(cvss_file),
        epss_file=str(epss_file),
        kev_file=str(kev_file),
    )

    meta = finding["meta"]
    assert meta["cvss_score"] == 9.9
    assert meta["cvss_version"] == "4.0"
    assert meta["cvss_vector"] == "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H"
    assert meta["epss_score"] == 0.91
    assert meta["epss_percentile"] == 0.99
    assert meta["kev_listed"] is True


def test_external_kev_data_clears_stale_nonmatching_kev_fields(tmp_path):
    kev_file = tmp_path / "kev.json"
    kev_file.write_text(json.dumps({"vulnerabilities": []}))

    finding = _finding(
        cve_id="CVE-2024-5001",
        kev_listed=True,
        kev_source="stale",
        kev_due_date="2020-01-01",
    )

    enrich_findings_with_vuln_intel([finding], kev_file=str(kev_file))

    meta = finding["meta"]
    assert meta["kev_listed"] is False
    assert "kev_source" not in meta
    assert "kev_due_date" not in meta
