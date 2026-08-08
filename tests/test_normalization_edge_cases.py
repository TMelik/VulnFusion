from utils.normalizer import (
    canonical_path,
    canonical_query,
    create_fingerprints,
    is_adapter_local_connectivity_artifact,
    parse_target,
    upgrade_schema,
)
from utils.schema import SCHEMA_VERSION


def _make_finding(name: str, asset_id: str, scanner: str = "nuclei", query_keys=None) -> dict:
    meta = {"scanner": scanner}
    if query_keys is not None:
        meta["query_keys"] = query_keys
    return {
        "vulnerability_name": name,
        "severity": "medium",
        "asset_id": asset_id,
        "description": "desc",
        "remediation": "fix",
        "meta": meta,
    }


def _make_meta_finding(
    name: str,
    host: str,
    scheme: str,
    path: str,
    port=None,
    scanner: str = "nuclei",
) -> dict:
    meta = {
        "scanner": scanner,
        "host": host,
        "scheme": scheme,
        "path": path,
        "port": port,
    }
    return {
        "vulnerability_name": name,
        "severity": "medium",
        "asset_id": "meta-driven-finding",
        "description": "desc",
        "remediation": "fix",
        "meta": meta,
    }


def test_fingerprints_differ_for_same_vuln_different_paths():
    login = create_fingerprints(_make_finding("XSS", "https://example.com/login"))
    register = create_fingerprints(_make_finding("XSS", "https://example.com/register"))

    assert login["fp_strict"] != register["fp_strict"]
    assert login["fp_general"] != register["fp_general"]
    assert login["fp_host_only"] == register["fp_host_only"]


def test_fingerprints_match_for_root_assets_with_and_without_trailing_slash():
    bare = create_fingerprints(_make_finding("XSS", "https://example.com"))
    slash = create_fingerprints(_make_finding("XSS", "https://example.com/"))

    assert bare["fp_strict"] == slash["fp_strict"]
    assert bare["fp_general"] == slash["fp_general"]
    assert bare["fp_host_only"] == slash["fp_host_only"]


def test_fingerprints_differ_for_same_vuln_different_ports_without_path():
    http = create_fingerprints(_make_finding("CVE-2023-0001", "10.0.0.5:80", scanner="nmap"))
    https = create_fingerprints(_make_finding("CVE-2023-0001", "10.0.0.5:443", scanner="nmap"))

    assert http["fp_strict"] != https["fp_strict"]
    assert http["fp_general"] != https["fp_general"]
    assert http["fp_host_only"] == https["fp_host_only"]


def test_fingerprints_differ_for_same_vuln_different_ports_with_scheme_and_no_path():
    a = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com:8443"))
    b = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com:9443"))

    assert a["fp_strict"] != b["fp_strict"]
    assert a["fp_general"] != b["fp_general"]
    assert a["fp_host_only"] == b["fp_host_only"]


def test_fingerprints_match_for_https_root_with_and_without_default_port():
    bare = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com"))
    default_port = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com:443"))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_match_for_http_root_with_and_without_default_port():
    bare = create_fingerprints(_make_finding("Server Banner", "http://example.com"))
    default_port = create_fingerprints(_make_finding("Server Banner", "http://example.com:80"))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_differ_for_https_root_and_non_default_port():
    bare = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com"))
    alt = create_fingerprints(_make_finding("TLS Weak Cipher", "https://example.com:8443"))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_differ_for_http_root_and_non_default_port():
    bare = create_fingerprints(_make_finding("Server Banner", "http://example.com"))
    alt = create_fingerprints(_make_finding("Server Banner", "http://example.com:8080"))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_match_for_https_path_with_and_without_default_port():
    bare = create_fingerprints(_make_finding("Admin Panel Exposure", "https://example.com/admin"))
    default_port = create_fingerprints(_make_finding("Admin Panel Exposure", "https://example.com:443/admin"))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_match_for_http_path_with_and_without_default_port():
    bare = create_fingerprints(_make_finding("Login Page Exposure", "http://example.com/login"))
    default_port = create_fingerprints(_make_finding("Login Page Exposure", "http://example.com:80/login"))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_differ_for_https_path_and_non_default_port():
    bare = create_fingerprints(_make_finding("Admin Panel Exposure", "https://example.com/admin"))
    alt = create_fingerprints(_make_finding("Admin Panel Exposure", "https://example.com:8443/admin"))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_differ_for_http_path_and_non_default_port():
    bare = create_fingerprints(_make_finding("Login Page Exposure", "http://example.com/login"))
    alt = create_fingerprints(_make_finding("Login Page Exposure", "http://example.com:8080/login"))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_match_for_https_path_with_and_without_default_port_from_meta():
    bare = create_fingerprints(_make_meta_finding("Admin Panel Exposure", "example.com", "https", "/admin"))
    default_port = create_fingerprints(_make_meta_finding("Admin Panel Exposure", "example.com", "https", "/admin", port=443))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_match_for_http_path_with_and_without_default_port_from_meta():
    bare = create_fingerprints(_make_meta_finding("Login Page Exposure", "example.com", "http", "/login"))
    default_port = create_fingerprints(_make_meta_finding("Login Page Exposure", "example.com", "http", "/login", port=80))

    assert bare["fp_strict"] == default_port["fp_strict"]
    assert bare["fp_general"] == default_port["fp_general"]
    assert bare["fp_host_only"] == default_port["fp_host_only"]


def test_fingerprints_differ_for_https_path_and_non_default_port_from_meta():
    bare = create_fingerprints(_make_meta_finding("Admin Panel Exposure", "example.com", "https", "/admin"))
    alt = create_fingerprints(_make_meta_finding("Admin Panel Exposure", "example.com", "https", "/admin", port=8443))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_differ_for_http_path_and_non_default_port_from_meta():
    bare = create_fingerprints(_make_meta_finding("Login Page Exposure", "example.com", "http", "/login"))
    alt = create_fingerprints(_make_meta_finding("Login Page Exposure", "example.com", "http", "/login", port=8080))

    assert bare["fp_strict"] != alt["fp_strict"]
    assert bare["fp_general"] != alt["fp_general"]
    assert bare["fp_host_only"] == alt["fp_host_only"]


def test_fingerprints_differ_for_different_query_keys_but_match_generally():
    by_id = create_fingerprints(_make_finding("SQL Injection", "https://example.com/search?id=1", query_keys=["id"]))
    by_lang = create_fingerprints(_make_finding("SQL Injection", "https://example.com/search?lang=en", query_keys=["lang"]))

    assert by_id["fp_strict"] != by_lang["fp_strict"]
    assert by_id["fp_general"] == by_lang["fp_general"]
    assert "id" in by_id["fp_strict"]
    assert "lang" in by_lang["fp_strict"]


def test_fingerprint_asset_id_structural_fields_override_conflicting_meta():
    canonical = _make_finding("SQL Injection", "https://example.com/login?q=search", query_keys=["q"])
    conflicting_meta = _make_finding("SQL Injection", "https://example.com/login?q=search", query_keys=["different"])
    conflicting_meta["meta"].update(
        {
            "host": "example.com",
            "scheme": "https",
            "path": "/login",
            "port": 8443,
            "parameter": "q",
            "method": "GET",
        }
    )
    canonical["meta"].update(
        {
            "host": "example.com",
            "scheme": "https",
            "path": "/login",
            "port": 443,
            "parameter": "q",
            "method": "GET",
        }
    )

    assert create_fingerprints(canonical) == create_fingerprints(conflicting_meta)


def test_path_and_query_canonicalization_helpers():
    assert canonical_path("/admin/") == "/admin"
    assert canonical_path("//api//v1") == "/api/v1"
    assert canonical_path("/") == "/"
    assert canonical_path("") == ""
    assert canonical_query({"page": ["1"], "id": ["2"], "lang": ["en"]}) == "id&lang&page"
    assert canonical_query({}) == ""


def test_parse_target_handles_bracketed_ipv6_host_port():
    parsed = parse_target("[2001:db8::1]:443")

    assert parsed["host"] == "2001:db8::1"
    assert parsed["port"] == 443
    assert parsed["scheme"] == ""
    assert parsed["path"] == ""


def test_parse_target_handles_bracketed_ipv6_url():
    parsed = parse_target("http://[2001:db8::1]:8443/path?next=1")

    assert parsed["host"] == "2001:db8::1"
    assert parsed["port"] == 8443
    assert parsed["scheme"] == "http"
    assert parsed["path"] == "/path"
    assert parsed["query"] == {"next": ["1"]}


def test_upgrade_schema_backfills_structured_fields_safely():
    old_report = {
        "schema_version": "1.0",
        "target": "example.com",
        "generated_at": "2025-01-01T00:00:00Z",
        "all_findings": [
            {
                "vulnerability_name": "Open Port",
                "severity": "info",
                "asset_id": "https://example.com:443/login?id=1&page=2",
                "description": "Port is open",
                "remediation": "Close unused ports",
                "meta": {"scanner": "nmap"},
            }
        ],
    }

    upgraded = upgrade_schema(old_report)
    finding = upgraded["all_findings"][0]
    meta = finding["meta"]
    fps = create_fingerprints(finding)

    assert upgraded["schema_version"] == SCHEMA_VERSION
    assert meta["host"] == "example.com"
    assert meta["scheme"] == "https"
    assert meta["path"] == "/login"
    assert meta["port"] == 443
    assert meta["query_keys"] == ["id", "page"]
    assert "id&page" in fps["fp_strict"]


def test_adapter_local_connectivity_artifact_filter_respects_loopback_original_targets():
    finding = {
        "vulnerability_name": "Unable to connect to 127.0.0.1:53647.",
        "severity": "info",
        "asset_id": "http://127.0.0.1:8080",
        "description": "Unable to connect to 127.0.0.1:53647.",
        "remediation": "Review scanner execution logs.",
        "meta": {"adapter_mode": "bridge", "effective_target": "http://127.0.0.1:53647"},
    }

    assert not is_adapter_local_connectivity_artifact(
        finding,
        effective_target="http://127.0.0.1:53647",
        original_target="http://127.0.0.1:8080",
        adapter_mode="bridge",
    )
