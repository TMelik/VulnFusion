import httpx
import pytest

from utils.target_probe import (
    PROBE_METHOD_PYTHON_HTTPX,
    _python_probe_http_mode,
    probe_web_target,
)


def _probe_response(
    *,
    reachable: bool,
    negotiated_http_version: str = "",
    status_code: int | None = None,
    error: str = "",
):
    return {
        "reachable": reachable,
        "negotiated_http_version": negotiated_http_version,
        "status_code": status_code,
        "error": error,
    }


def _patch_python_probe(monkeypatch, responses):
    calls = []

    def fake_probe(url, *, http2, timeout):
        key = (url, http2)
        assert key in responses, f"unexpected probe call: {key}"
        calls.append({"url": url, "http2": http2, "timeout": timeout})
        return dict(responses[key])

    monkeypatch.setattr("utils.target_probe._python_probe_http_mode", fake_probe)
    return calls


def test_python_probe_http_mode_uses_httpx_client_and_returns_response_metadata(monkeypatch):
    observed = {}

    class FakeClient:
        def __init__(self, *, http2, verify, timeout, follow_redirects):
            observed["init"] = {
                "http2": http2,
                "verify": verify,
                "timeout": timeout,
                "follow_redirects": follow_redirects,
            }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            observed["url"] = url
            return type(
                "Response",
                (),
                {"http_version": "HTTP/2", "status_code": 404},
            )()

    monkeypatch.setattr("utils.target_probe.httpx.Client", FakeClient)

    probe = _python_probe_http_mode("https://example.com", http2=True, timeout=7)

    assert observed == {
        "init": {
            "http2": True,
            "verify": False,
            "timeout": 7,
            "follow_redirects": False,
        },
        "url": "https://example.com",
    }
    assert probe == {
        "reachable": True,
        "negotiated_http_version": "HTTP/2",
        "status_code": 404,
        "error": "",
    }


def test_python_probe_http_mode_formats_httpx_errors(monkeypatch):
    class FakeClient:
        def __init__(self, *, http2, verify, timeout, follow_redirects):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def get(self, url):
            raise httpx.ConnectError("connection refused")

    monkeypatch.setattr("utils.target_probe.httpx.Client", FakeClient)

    probe = _python_probe_http_mode("https://example.com", http2=False, timeout=4)

    assert probe == {
        "reachable": False,
        "negotiated_http_version": "",
        "status_code": None,
        "error": "ConnectError: connection refused",
    }


def test_probe_bare_target_prefers_https_and_checks_http11_separately(monkeypatch):
    calls = _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/2",
                status_code=200,
            ),
            ("https://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=403,
            ),
        },
    )

    probe = probe_web_target("example.com", timeout=5)

    assert calls == [
        {"url": "https://example.com", "http2": True, "timeout": 5},
        {"url": "https://example.com", "http2": False, "timeout": 5},
    ]
    assert probe["normalized_target"] == "https://example.com"
    assert probe["selected_scheme"] == "https"
    assert probe["reachable"] is True
    assert probe["supports_http2"] is True
    assert probe["supports_http1_1"] is True
    assert probe["http2_only"] is False
    assert probe["transport_detected"] == "http2_and_http1"
    assert probe["detected_http_version"] == "HTTP/1.1"
    assert probe["probe_method"] == PROBE_METHOD_PYTHON_HTTPX
    assert "prefers HTTP/1.1" in probe["reason"]
    assert probe["attempts"] == [
        {
            "url": "https://example.com",
            "scheme": "https",
            "requested_mode": "http2",
            "requested_http_version": "HTTP/2",
            "reachable": True,
            "negotiated_http_version": "HTTP/2",
            "status_code": 200,
            "error": "",
        },
        {
            "url": "https://example.com",
            "scheme": "https",
            "requested_mode": "http1_1",
            "requested_http_version": "HTTP/1.1",
            "reachable": True,
            "negotiated_http_version": "HTTP/1.1",
            "status_code": 403,
            "error": "",
        },
    ]


def test_probe_bare_target_falls_back_to_http_when_https_fails(monkeypatch):
    calls = _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=False,
                error="ConnectError: connection refused",
            ),
            ("https://example.com", False): _probe_response(
                reachable=False,
                error="ReadTimeout: timed out",
            ),
            ("http://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=200,
            ),
        },
    )

    probe = probe_web_target("example.com", timeout=6)

    assert calls == [
        {"url": "https://example.com", "http2": True, "timeout": 6},
        {"url": "https://example.com", "http2": False, "timeout": 6},
        {"url": "http://example.com", "http2": False, "timeout": 6},
    ]
    assert probe["normalized_target"] == "http://example.com"
    assert probe["selected_scheme"] == "http"
    assert probe["reachable"] is True
    assert probe["supports_http2"] is False
    assert probe["supports_http1_1"] is True
    assert probe["http2_only"] is False
    assert probe["transport_detected"] == "http1_only"
    assert probe["detected_http_version"] == "HTTP/1.1"
    assert probe["probe_method"] == PROBE_METHOD_PYTHON_HTTPX
    assert "fell back to HTTP" in probe["reason"]
    assert [attempt["requested_mode"] for attempt in probe["attempts"]] == [
        "http2",
        "http1_1",
        "http1_1",
    ]


def test_probe_https_target_supports_only_http2(monkeypatch):
    _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/2",
                status_code=200,
            ),
            ("https://example.com", False): _probe_response(
                reachable=False,
                error="ConnectError: connection reset",
            ),
        },
    )

    probe = probe_web_target("https://example.com")

    assert probe["reachable"] is True
    assert probe["supports_http2"] is True
    assert probe["supports_http1_1"] is False
    assert probe["http2_only"] is True
    assert probe["transport_detected"] == "http2_only"
    assert probe["detected_http_version"] == "HTTP/2"
    assert probe["probe_method"] == PROBE_METHOD_PYTHON_HTTPX


def test_probe_https_target_supports_both_http2_and_http11(monkeypatch):
    _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/2",
                status_code=200,
            ),
            ("https://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=200,
            ),
        },
    )

    probe = probe_web_target("https://example.com")

    assert probe["reachable"] is True
    assert probe["supports_http2"] is True
    assert probe["supports_http1_1"] is True
    assert probe["http2_only"] is False
    assert probe["transport_detected"] == "http2_and_http1"
    assert probe["detected_http_version"] == "HTTP/1.1"


def test_probe_https_target_supports_only_http11_when_http2_client_negotiates_http11(monkeypatch):
    _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=404,
            ),
            ("https://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=404,
            ),
        },
    )

    probe = probe_web_target("https://example.com")

    assert probe["reachable"] is True
    assert probe["supports_http2"] is False
    assert probe["supports_http1_1"] is True
    assert probe["http2_only"] is False
    assert probe["transport_detected"] == "http1_only"
    assert probe["detected_http_version"] == "HTTP/1.1"
    assert probe["attempts"][0]["requested_mode"] == "http2"
    assert probe["attempts"][0]["negotiated_http_version"] == "HTTP/1.1"
    assert probe["attempts"][1]["requested_mode"] == "http1_1"
    assert probe["attempts"][1]["negotiated_http_version"] == "HTTP/1.1"


def test_probe_http_target_confirms_http11_without_claiming_http2(monkeypatch):
    calls = _patch_python_probe(
        monkeypatch,
        {
            ("http://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=200,
            ),
        },
    )

    probe = probe_web_target("http://example.com")

    assert calls == [{"url": "http://example.com", "http2": False, "timeout": 8}]
    assert probe["selected_scheme"] == "http"
    assert probe["reachable"] is True
    assert probe["supports_http2"] is False
    assert probe["supports_http1_1"] is True
    assert probe["http2_only"] is False
    assert probe["transport_detected"] == "http1_only"
    assert probe["detected_http_version"] == "HTTP/1.1"
    assert probe["probe_method"] == PROBE_METHOD_PYTHON_HTTPX


@pytest.mark.parametrize("status_code", [403, 404, 500])
def test_probe_counts_http_error_statuses_as_reachable(monkeypatch, status_code):
    _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=False,
                error="ConnectError: protocol not supported",
            ),
            ("https://example.com", False): _probe_response(
                reachable=True,
                negotiated_http_version="HTTP/1.1",
                status_code=status_code,
            ),
        },
    )

    probe = probe_web_target("https://example.com")

    assert probe["reachable"] is True
    assert probe["supports_http2"] is False
    assert probe["supports_http1_1"] is True
    assert probe["transport_detected"] == "http1_only"
    assert probe["attempts"][1]["status_code"] == status_code


def test_probe_reports_network_errors_with_python_httpx_reason(monkeypatch):
    _patch_python_probe(
        monkeypatch,
        {
            ("https://example.com", True): _probe_response(
                reachable=False,
                error="ConnectError: connection refused",
            ),
            ("https://example.com", False): _probe_response(
                reachable=False,
                error="ReadTimeout: timed out",
            ),
        },
    )

    probe = probe_web_target("https://example.com")

    assert probe["reachable"] is False
    assert probe["supports_http2"] is False
    assert probe["supports_http1_1"] is False
    assert probe["http2_only"] is False
    assert probe["probe_method"] == PROBE_METHOD_PYTHON_HTTPX
    assert "python-httpx http2=True failed: ConnectError: connection refused" in probe["reason"]
    assert "python-httpx http2=False failed: ReadTimeout: timed out" in probe["reason"]
    assert "curl" not in probe["reason"]


def test_probe_unsupported_scheme_remains_unsupported():
    probe = probe_web_target("ftp://example.com")

    assert probe["normalized_target"] == "ftp://example.com"
    assert probe["selected_scheme"] == "ftp"
    assert probe["reachable"] is False
    assert probe["probe_method"] == "unsupported_scheme"
    assert "Unsupported scheme 'ftp'" in probe["reason"]
