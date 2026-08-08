from utils.risk_scorer import score_vulnerabilities


def _finding() -> dict:
    return {
        "vulnerability_name": "XSS",
        "severity": "high",
        "asset_id": "https://example.com/a",
        "description": "desc",
        "remediation": "fix",
        "meta": {"scanner": "nuclei"},
    }


def test_repeatability_bonus_works_without_precomputed_fingerprints():
    current = {"all_findings": [_finding()], "summary": {}}
    previous = [_finding()]

    scored = score_vulnerabilities(current, {"previous_findings": previous})

    finding = scored["all_findings"][0]
    assert finding["risk_factors"]["repeatability"] == 4
