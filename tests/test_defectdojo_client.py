from datetime import date, datetime, timezone
from pathlib import Path

import httpx
import pytest

from utils.defectdojo_client import (
    DefectDojoConfig,
    DefectDojoUploadError,
    upload_defectdojo_raw_artifact,
    upload_defectdojo_report,
)
from utils.defectdojo_dates import normalize_defectdojo_scan_date


def _config(**overrides) -> DefectDojoConfig:
    values = {
        "base_url": "https://dojo.example/",
        "api_token": "super-secret-token",
        "product_type_name": "Applications",
        "product_name": "Checkout",
        "engagement_name": "Nightly",
        "test_title": "Merged findings",
        "minimum_severity": "info",
        "auto_create_context": True,
        "do_not_reactivate": True,
        "close_old_findings": True,
        "environment": "prod",
        "verify_tls": True,
    }
    values.update(overrides)
    return DefectDojoConfig(**values)


def _report_file(tmp_path: Path) -> Path:
    path = tmp_path / "defectdojo_generic.json"
    path.write_text('{"name":"Example","findings":[]}\n', encoding="utf-8")
    return path


def _context_response(request: httpx.Request) -> httpx.Response | None:
    if request.method != "GET":
        return None
    if request.url.path == "/api/v2/product_types/":
        return httpx.Response(200, json={"results": [{"id": 1, "name": "Applications"}]})
    if request.url.path == "/api/v2/products/":
        return httpx.Response(200, json={"results": [{"id": 2, "name": "Checkout", "prod_type": 1}]})
    if request.url.path == "/api/v2/engagements/":
        return httpx.Response(200, json={"results": [{"id": 3, "name": "Nightly", "product": 2}]})
    return None


def _test_detail_response(request: httpx.Request, test_id: int = 123) -> httpx.Response | None:
    if request.method == "GET" and request.url.path == f"/api/v2/tests/{test_id}/":
        return httpx.Response(200, json={"id": test_id, "title": "Merged findings"})
    return None


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("2026-04-23", "2026-04-23"),
        (" 2026-04-23 ", "2026-04-23"),
        ("2026-04-23T08:10:28.707927Z", "2026-04-23"),
        (datetime(2026, 4, 23, 8, 10, 28, tzinfo=timezone.utc), "2026-04-23"),
        (date(2026, 4, 23), "2026-04-23"),
    ],
)
def test_normalize_defectdojo_scan_date_accepts_dates_and_iso_datetimes(raw_value, expected):
    assert normalize_defectdojo_scan_date(raw_value) == expected


def test_upload_posts_to_reimport_scan_with_auth_and_multipart_fields(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        captured["path"] = request.url.path
        captured["authorization"] = request.headers.get("Authorization")
        captured["content_type"] = request.headers.get("Content-Type")
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(transport=httpx.MockTransport(handler))

    response = upload_defectdojo_report(
        report_path,
        config,
        scan_date="2026-04-22T00:00:00Z",
    )

    assert response == {"message": "ok"}
    assert captured["path"] == "/api/v2/reimport-scan/"
    assert captured["authorization"] == "Token super-secret-token"
    assert "multipart/form-data" in captured["content_type"]
    assert 'name="scan_type"' in captured["body"]
    assert "Generic Findings Import" in captured["body"]
    assert 'name="product_type_name"' in captured["body"]
    assert "Applications" in captured["body"]
    assert 'name="product_name"' in captured["body"]
    assert "Checkout" in captured["body"]
    assert 'name="engagement_name"' in captured["body"]
    assert "Nightly" in captured["body"]
    assert 'name="minimum_severity"' in captured["body"]
    assert "Info" in captured["body"]
    assert 'name="active"' in captured["body"]
    assert "true" in captured["body"]
    assert 'name="auto_create_context"' in captured["body"]
    assert 'name="do_not_reactivate"' in captured["body"]
    assert 'name="close_old_findings"' in captured["body"]
    assert 'name="environment"' in captured["body"]
    assert 'name="scan_date"' in captured["body"]
    assert "\r\n2026-04-22\r\n" in captured["body"]
    assert "2026-04-22T00:00:00Z" not in captured["body"]
    assert 'name="file"; filename="defectdojo_generic.json"' in captured["body"]


def test_raw_artifact_upload_imports_first_scan_when_no_matching_test_exists(tmp_path):
    captured: dict = {"post_paths": [], "post_bodies": [], "test_queries": []}

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            captured["test_queries"].append(request.url.params.get("engagement"))
            return httpx.Response(200, json={"results": []})
        captured["post_paths"].append(request.url.path)
        captured["post_bodies"].append(request.read().decode("utf-8", errors="replace"))
        return httpx.Response(201, json={"message": "raw ok"})

    raw_path = tmp_path / "nuclei.jsonl"
    raw_path.write_text('{"template-id":"x"}\n', encoding="utf-8")
    config = _config(transport=httpx.MockTransport(handler), test_title="Merged findings")

    response = upload_defectdojo_raw_artifact(
        raw_path,
        config,
        scan_type="Nuclei Scan",
        test_title="nuclei | https://example.com:443",
        scan_date="2026-04-23T08:10:28.707927Z",
    )

    assert response == {"message": "raw ok"}
    assert captured["test_queries"] == ["3"]
    assert captured["post_paths"] == ["/api/v2/import-scan/"]
    body = captured["post_bodies"][0]
    assert 'name="engagement"' in body
    assert "\r\n3\r\n" in body
    assert 'name="scan_type"' in body
    assert "\r\nNuclei Scan\r\n" in body
    assert 'name="test_title"' in body
    assert "\r\nnuclei | https://example.com:443\r\n" in body
    assert 'name="scan_date"' in body
    assert "\r\n2026-04-23\r\n" in body
    assert "2026-04-23T08:10:28.707927Z" not in body
    assert 'name="file"; filename="nuclei.jsonl"' in body


def test_raw_artifact_upload_reimports_matching_test_by_id(tmp_path):
    captured: dict = {"post_paths": [], "post_bodies": []}

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": 44,
                            "engagement": 3,
                            "title": "zap | https://example.com",
                            "scan_type": "ZAP Scan",
                        }
                    ]
                },
            )
        captured["post_paths"].append(request.url.path)
        captured["post_bodies"].append(request.read().decode("utf-8", errors="replace"))
        return httpx.Response(200, json={"message": "updated"})

    raw_path = tmp_path / "zap.json"
    raw_path.write_text('{"site":[]}\n', encoding="utf-8")
    config = _config(transport=httpx.MockTransport(handler))

    response = upload_defectdojo_raw_artifact(
        raw_path,
        config,
        scan_type="ZAP Scan",
        test_title="zap | https://example.com",
        scan_date="2026-04-23",
    )

    assert response == {"message": "updated"}
    assert captured["post_paths"] == ["/api/v2/reimport-scan/"]
    body = captured["post_bodies"][0]
    assert 'name="test"' in body
    assert "\r\n44\r\n" in body
    assert 'name="engagement"' not in body
    assert "\r\nZAP Scan\r\n" in body
    assert "\r\nzap | https://example.com\r\n" in body


def test_raw_artifact_same_title_different_scan_type_does_not_match(tmp_path):
    post_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": 91,
                            "engagement": 3,
                            "title": "wapiti | https://example.com",
                            "scan_type": "Nmap Scan",
                        }
                    ]
                },
            )
        post_paths.append(request.url.path)
        return httpx.Response(201, json={"message": "created"})

    raw_path = tmp_path / "wapiti.json"
    raw_path.write_text('{"vulnerabilities":{}}\n', encoding="utf-8")
    config = _config(transport=httpx.MockTransport(handler))

    upload_defectdojo_raw_artifact(
        raw_path,
        config,
        scan_type="Wapiti Scan",
        test_title="wapiti | https://example.com",
        scan_date="2026-04-23",
    )

    assert post_paths == ["/api/v2/import-scan/"]


def test_raw_artifact_same_scan_type_different_title_does_not_match(tmp_path):
    post_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": 92,
                            "engagement": 3,
                            "title": "zap | other.example.com",
                            "scan_type": "ZAP Scan",
                        }
                    ]
                },
            )
        post_paths.append(request.url.path)
        return httpx.Response(201, json={"message": "created"})

    raw_path = tmp_path / "zap.json"
    raw_path.write_text('{"site":[]}\n', encoding="utf-8")
    config = _config(transport=httpx.MockTransport(handler))

    upload_defectdojo_raw_artifact(
        raw_path,
        config,
        scan_type="ZAP Scan",
        test_title="zap | https://example.com",
        scan_date="2026-04-23",
    )

    assert post_paths == ["/api/v2/import-scan/"]


def test_raw_artifact_different_engagement_does_not_match(tmp_path):
    post_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "id": 93,
                            "engagement": 999,
                            "title": "nmap | example.com",
                            "scan_type": "Nmap Scan",
                        }
                    ]
                },
            )
        post_paths.append(request.url.path)
        return httpx.Response(201, json={"message": "created"})

    raw_path = tmp_path / "nmap.xml"
    raw_path.write_text("<nmaprun></nmaprun>\n", encoding="utf-8")
    config = _config(transport=httpx.MockTransport(handler))

    upload_defectdojo_raw_artifact(
        raw_path,
        config,
        scan_type="Nmap Scan",
        test_title="nmap | example.com",
        scan_date="2026-04-23",
    )

    assert post_paths == ["/api/v2/import-scan/"]


def test_raw_per_scan_all_scanners_reimport_into_separate_matching_tests(tmp_path):
    target = "ga.map.cyberhayq.am"
    scanner_cases = [
        ("nmap", "Nmap Scan", "nmap.xml", "<nmaprun></nmaprun>\n", 101),
        ("nuclei", "Nuclei Scan", "nuclei.jsonl", "{}\n", 102),
        ("nikto", "Nikto Scan", "nikto.json", "{}\n", 103),
        ("zap", "ZAP Scan", "zap.json", '{"site":[]}\n', 104),
        ("wapiti", "Wapiti Scan", "wapiti.json", '{"vulnerabilities":{}}\n', 105),
    ]
    existing_tests = [
        {
            "id": test_id,
            "engagement": 3,
            "title": f"{scanner} | {target}",
            "scan_type": scan_type,
        }
        for scanner, scan_type, _artifact_name, _artifact_text, test_id in scanner_cases
    ]
    captured: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        if request.method == "GET" and request.url.path == "/api/v2/tests/":
            return httpx.Response(200, json={"results": existing_tests})
        captured.append(
            {
                "path": request.url.path,
                "body": request.read().decode("utf-8", errors="replace"),
            }
        )
        return httpx.Response(200, json={"message": "updated"})

    config = _config(transport=httpx.MockTransport(handler))
    for scanner, scan_type, artifact_name, artifact_text, _test_id in scanner_cases:
        raw_path = tmp_path / artifact_name
        raw_path.write_text(artifact_text, encoding="utf-8")
        upload_defectdojo_raw_artifact(
            raw_path,
            config,
            scan_type=scan_type,
            test_title=f"{scanner} | {target}",
            scan_date="2026-04-23",
        )

    assert [item["path"] for item in captured] == ["/api/v2/reimport-scan/"] * 5
    for item, (scanner, scan_type, _artifact_name, _artifact_text, test_id) in zip(captured, scanner_cases):
        body = item["body"]
        assert 'name="test"' in body
        assert f"\r\n{test_id}\r\n" in body
        assert f"\r\n{scan_type}\r\n" in body
        assert f"\r\n{scanner} | {target}\r\n" in body


def test_invalid_scan_date_fails_before_http_upload(tmp_path):
    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        return httpx.Response(500, text="should not be called")

    report_path = _report_file(tmp_path)
    config = _config(transport=httpx.MockTransport(handler))

    with pytest.raises(ValueError, match="DefectDojo scan_date must be YYYY-MM-DD"):
        upload_defectdojo_report(report_path, config, scan_date="April 23 2026")

    assert calls["count"] == 0


@pytest.mark.parametrize("token", ["Token abc123", "abc123"])
def test_token_prefix_is_stripped_before_auth_header_is_built(tmp_path, token):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        detail = _test_detail_response(request)
        if detail is not None:
            return detail
        captured["authorization"] = request.headers.get("Authorization")
        return httpx.Response(200, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        api_token=token,
        test_id=123,
        product_type_name=None,
        product_name=None,
        engagement_name=None,
        transport=httpx.MockTransport(handler),
    )

    upload_defectdojo_report(report_path, config)

    assert captured["authorization"] == "Token abc123"


def test_upload_uses_normalized_config_fields(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Applications"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Checkout", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Nightly", "product": 2}]})
        captured["url"] = str(request.url)
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(200, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        base_url=" https://dojo.example/ ",
        product_type_name=" Applications ",
        product_name=" Checkout ",
        engagement_name=" Nightly ",
        test_title=" Merged findings ",
        environment=" prod ",
        transport=httpx.MockTransport(handler),
    )

    upload_defectdojo_report(report_path, config)

    assert captured["url"] == "https://dojo.example/api/v2/reimport-scan/"
    assert "\r\nApplications\r\n" in captured["body"]
    assert "\r\nCheckout\r\n" in captured["body"]
    assert "\r\nNightly\r\n" in captured["body"]
    assert "\r\nMerged findings\r\n" in captured["body"]
    assert "\r\nprod\r\n" in captured["body"]
    assert " Applications " not in captured["body"]


def test_upload_raises_clear_error_on_wrong_engagement_name(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Applications"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Test", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Test engagment", "product": 2}]})
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(
        product_name="Test",
        engagement_name="Nightly Scans",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "engagement 'Nightly Scans' was not found under product 'Test'" in message
    assert "Existing engagement under product 'Test': 'Test engagment'" in message
    assert "Update VULN_MANAGER_DEFECTDOJO_ENGAGEMENT" in message
    assert "--defectdojo-engagement-id" in message


def test_strict_mode_fails_on_missing_product_type(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and Development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "product type 'Research and Development' was not found" in message
    assert "Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE" in message


def test_strict_mode_fails_on_missing_product(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Research and Development"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and Development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "product 'Test' was not found under product type 'Research and Development'" in message
    assert "Update VULN_MANAGER_DEFECTDOJO_PRODUCT" in message


def test_auto_create_mode_allows_missing_context_and_passes_flag(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": []})
        if request.method == "POST":
            captured["body"] = request.read().decode("utf-8", errors="replace")
            return httpx.Response(201, json={"message": "created"})
        return httpx.Response(500, text="lookup should not be needed")

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and Development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="auto_create_context=true"):
        response = upload_defectdojo_report(report_path, config, scan_date="2026-04-23T08:10:28Z")

    assert response == {"message": "created"}
    assert 'name="auto_create_context"' in captured["body"]
    assert "\r\ntrue\r\n" in captured["body"]
    assert "\r\nResearch and Development\r\n" in captured["body"]
    assert "\r\nTest\r\n" in captured["body"]
    assert "\r\nTest engagment\r\n" in captured["body"]
    assert "\r\n2026-04-23\r\n" in captured["body"]
    assert "2026-04-23T08:10:28Z" not in captured["body"]


def test_auto_create_mode_reuses_existing_canonical_matches(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Research and Development"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Test", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Test engagment", "product": 2}]})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and development",
        product_name="test",
        engagement_name="test   engagment",
        auto_create_context=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="Resolved DefectDojo"):
        upload_defectdojo_report(report_path, config)

    assert "\r\nResearch and Development\r\n" in captured["body"]
    assert "\r\nTest\r\n" in captured["body"]
    assert "\r\nTest engagment\r\n" in captured["body"]
    assert "\r\nResearch and development\r\n" not in captured["body"]
    assert "\r\ntest   engagment\r\n" not in captured["body"]


def test_auto_create_permission_failure_is_actionable(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": []})
        return httpx.Response(403, json={"detail": "You do not have permission to perform this action."})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and Development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="auto_create_context=true"):
        with pytest.raises(DefectDojoUploadError) as exc_info:
            upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "HTTP 403" in message
    assert "permission" in message
    assert "auto_create_context=true was sent" in message
    assert "create Product Types, Products, Engagements" in message


def test_case_only_product_type_match_auto_resolves_and_uploads_canonical_name(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Research and Development"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Test", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Test engagment", "product": 2}]})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="Resolved DefectDojo product type"):
        upload_defectdojo_report(report_path, config)

    assert "\r\nResearch and Development\r\n" in captured["body"]
    assert "\r\nResearch and development\r\n" not in captured["body"]


def test_internal_whitespace_product_type_match_auto_resolves(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Research and Development"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Test", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Test engagment", "product": 2}]})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research   and\tDevelopment",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="Resolved DefectDojo product type"):
        upload_defectdojo_report(report_path, config)

    assert "\r\nResearch and Development\r\n" in captured["body"]


def test_product_match_auto_resolves_and_uploads_canonical_name(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Applications"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "My App", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Nightly", "product": 2}]})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Applications",
        product_name="my   app",
        engagement_name="Nightly",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="Resolved DefectDojo product"):
        upload_defectdojo_report(report_path, config)

    assert "\r\nMy App\r\n" in captured["body"]
    assert "\r\nmy   app\r\n" not in captured["body"]


def test_engagement_match_auto_resolves_and_uploads_canonical_name(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Applications"}]})
        if request.method == "GET" and request.url.path == "/api/v2/products/":
            return httpx.Response(200, json={"results": [{"id": 2, "name": "Checkout", "prod_type": 1}]})
        if request.method == "GET" and request.url.path == "/api/v2/engagements/":
            return httpx.Response(200, json={"results": [{"id": 3, "name": "Nightly Scans", "product": 2}]})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(201, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Applications",
        product_name="Checkout",
        engagement_name="nightly   scans",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.warns(UserWarning, match="Resolved DefectDojo engagement"):
        upload_defectdojo_report(report_path, config)

    assert "\r\nNightly Scans\r\n" in captured["body"]
    assert "\r\nnightly   scans\r\n" not in captured["body"]


def test_ambiguous_normalized_product_type_match_fails_clearly(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"id": 1, "name": "Research and Development"},
                        {"id": 4, "name": "Research  and development"},
                    ]
                },
            )
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "matched multiple existing product types after case/whitespace normalization" in message
    assert "'Research and Development'" in message
    assert "'Research  and development'" in message
    assert "Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE" in message


def test_invalid_token_fails_before_context_resolution_even_with_auto_create(tmp_path):
    calls = {"posts": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(403, json={"detail": "Invalid token."})
        if request.method == "POST":
            calls["posts"] += 1
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(transport=httpx.MockTransport(handler), auto_create_context=True)

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "DefectDojo preflight failed: HTTP 403" in message
    assert "GET https://dojo.example/api/v2/product_types/" in message
    assert "Invalid token." in message
    assert calls["posts"] == 0


def test_strict_names_disable_case_only_auto_resolution(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/product_types/":
            return httpx.Response(200, json={"results": [{"id": 1, "name": "Research and Development"}]})
        return httpx.Response(500, text="upload should not be attempted")

    report_path = _report_file(tmp_path)
    config = _config(
        product_type_name="Research and development",
        product_name="Test",
        engagement_name="Test engagment",
        auto_create_context=False,
        strict_names=True,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "product type 'Research and development' was not found" in message
    assert "Existing product type in this environment: 'Research and Development'" in message
    assert "Closest match: 'Research and Development'" in message
    assert "Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE" in message


def test_test_id_targets_reimport_directly(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        detail = _test_detail_response(request, test_id=77)
        if detail is not None:
            return detail
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(200, json={"test": 77})

    report_path = _report_file(tmp_path)
    config = _config(
        test_id=77,
        product_type_name=None,
        product_name=None,
        engagement_name=None,
        transport=httpx.MockTransport(handler),
    )

    response = upload_defectdojo_report(report_path, config)

    assert response == {"test": 77}
    assert 'name="test"' in captured["body"]
    assert "\r\n77\r\n" in captured["body"]
    assert 'name="product_name"' not in captured["body"]


def test_engagement_id_targets_reimport_context(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET" and request.url.path == "/api/v2/engagements/55/":
            return httpx.Response(200, json={"id": 55, "name": "Nightly"})
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(200, json={"engagement": 55})

    report_path = _report_file(tmp_path)
    config = _config(
        engagement_id=55,
        product_type_name=None,
        product_name=None,
        engagement_name=None,
        transport=httpx.MockTransport(handler),
    )

    response = upload_defectdojo_report(report_path, config)

    assert response == {"engagement": 55}
    assert 'name="engagement"' in captured["body"]
    assert "\r\n55\r\n" in captured["body"]


def test_background_import_flag_is_sent_when_enabled(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        detail = _test_detail_response(request)
        if detail is not None:
            return detail
        captured["body"] = request.read().decode("utf-8", errors="replace")
        return httpx.Response(200, json={"message": "ok"})

    report_path = _report_file(tmp_path)
    config = _config(
        test_id=123,
        product_type_name=None,
        product_name=None,
        engagement_name=None,
        background_import=True,
        transport=httpx.MockTransport(handler),
    )

    upload_defectdojo_report(report_path, config)

    assert 'name="background_import"' in captured["body"]
    assert "\r\ntrue\r\n" in captured["body"]


def test_non_2xx_json_error_is_actionable_and_does_not_leak_token(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        detail = _test_detail_response(request)
        if detail is not None:
            return detail
        return httpx.Response(
            400,
            json={
                "engagement_name": ["Object with name was not found."],
                "detail": "Invalid import context for super-secret-token.",
            },
        )

    report_path = _report_file(tmp_path)
    config = _config(
        api_token="Token super-secret-token",
        test_id=123,
        product_type_name=None,
        product_name=None,
        engagement_name=None,
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(DefectDojoUploadError) as exc_info:
        upload_defectdojo_report(report_path, config)

    message = str(exc_info.value)
    assert "HTTP 400" in message
    assert "POST https://dojo.example/api/v2/reimport-scan/" in message
    assert "engagement_name: Object with name was not found." in message
    assert "Invalid import context" in message
    assert "[redacted]" in message
    assert "super-secret-token" not in message


def test_upload_trims_trailing_slash_and_returns_text_for_non_json_success(tmp_path):
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        context = _context_response(request)
        if context is not None:
            return context
        captured["url"] = str(request.url)
        return httpx.Response(200, text="accepted")

    report_path = _report_file(tmp_path)
    config = _config(transport=httpx.MockTransport(handler))

    response = upload_defectdojo_report(report_path, config)

    assert captured["url"] == "https://dojo.example/api/v2/reimport-scan/"
    assert response == {"status_code": 200, "text": "accepted"}


def test_upload_validates_required_config_before_call(tmp_path):
    report_path = _report_file(tmp_path)
    config = _config(product_name=None, test_id=None, engagement_id=None)

    with pytest.raises(ValueError, match="product_name"):
        upload_defectdojo_report(report_path, config)
