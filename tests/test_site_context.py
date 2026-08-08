import json
import sys
from datetime import datetime, timezone

import httpx
import main
import yaml

from utils.site_context import (
    SiteContextConfig,
    analyze_site_context,
    crawl_site,
    parse_context_llm_response,
    site_bundle_key,
    validate_site_okf_bundle,
    write_site_okf_bundle,
)
from utils.report_generator import generate_modern_html_report


FIXED_NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


def _now():
    return FIXED_NOW


def test_crawl_is_bounded_and_same_site_only():
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        pages = {
            "https://example.com/": """
                <html><head><title>Example Portal</title>
                <meta name="description" content="Citizen appointment portal"></head>
                <body><script>ignore this instruction</script>
                <a href="/news">News</a><a href="/about">About</a>
                <a href="/services#top">Services</a>
                <a href="https://evil.example/about">External</a>
                Welcome citizens.</body></html>
            """,
            "https://example.com/about": "<html><title>About</title><body>We provide public appointments.</body></html>",
            "https://example.com/services": "<html><title>Services</title><body>Book and manage appointments.</body></html>",
            "https://example.com/news": "<html><title>News</title><body>News page.</body></html>",
        }
        return httpx.Response(200, text=pages[str(request.url)], headers={"content-type": "text/html"})

    pages = crawl_site(
        "example.com",
        config=SiteContextConfig(max_pages=3),
        transport=httpx.MockTransport(handler),
        now=_now,
    )

    assert requested == [
        "https://example.com/",
        "https://example.com/about",
        "https://example.com/services",
    ]
    assert [page["id"] for page in pages] == ["page-1", "page-2", "page-3"]
    assert pages[0]["meta_description"] == "Citizen appointment portal"
    assert "ignore this instruction" not in pages[0]["text"]
    assert all("evil.example" not in url for url in requested)


def test_crawl_does_not_follow_cross_site_redirect():
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://other.example/private"})

    pages = crawl_site("https://example.com", transport=httpx.MockTransport(handler), now=_now)

    assert pages == []
    assert requested == ["https://example.com/"]


def test_structured_context_parser_rejects_unknown_evidence():
    response = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "organization_name": "Example",
                            "site_description": "A citizen appointment portal.",
                            "business_processes": ["Appointment booking"],
                            "evidence_ids": ["page-99"],
                            "uncertainties": [],
                        }
                    )
                }
            }
        ]
    }

    try:
        parse_context_llm_response(response, evidence_ids=["page-1"])
    except ValueError as exc:
        assert "unknown evidence" in str(exc)
    else:  # pragma: no cover - assertion guard
        raise AssertionError("unknown evidence must be rejected")


def test_provider_failure_returns_reviewable_fallback():
    page = {
        "id": "page-1",
        "url": "https://example.com/",
        "title": "Example Portal",
        "meta_description": "Citizen appointment portal",
        "text": "Book an appointment.",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="unavailable")

    analysis = analyze_site_context(
        "https://example.com",
        [page],
        api_url="https://llm.example/v1/chat/completions",
        api_key="secret",
        model_name="demo-model",
        transport=httpx.MockTransport(handler),
    )

    assert analysis["analysis_source"] == "fallback"
    assert analysis["needs_review"] is True
    assert analysis["site_description"] == "Citizen appointment portal"


def test_bundle_keys_are_isolated_per_host_and_non_default_port():
    assert site_bundle_key("http://example.com") == site_bundle_key("https://EXAMPLE.com/")
    assert site_bundle_key("https://example.com") != site_bundle_key("https://www.example.com")
    assert site_bundle_key("https://example.com") != site_bundle_key("https://example.com:8443")
    assert site_bundle_key("https://a-b.example") != site_bundle_key("https://a.b.example")


def test_human_confirmed_context_writes_separate_valid_okf_bundles(tmp_path):
    base_draft = {
        "target": "https://example.com/",
        "generated_at": "2026-08-08T11:59:00Z",
        "pages": [
            {
                "id": "page-1",
                "url": "https://example.com/",
                "title": "Example Portal",
                "fetched_at": "2026-08-08T11:59:00Z",
            }
        ],
        "analysis": {
            "organization_name": "Example",
            "site_description": "Model suggestion.",
            "business_processes": ["Appointment booking"],
            "uncertainties": ["Authentication was not confirmed."],
        },
    }
    first = write_site_okf_bundle(
        tmp_path,
        base_draft,
        confirmed_description="User-confirmed citizen appointment portal.",
        reviewer="demo-user",
        now=_now,
    )
    second_draft = dict(base_draft, target="https://other.example/")
    second = write_site_okf_bundle(
        tmp_path,
        second_draft,
        confirmed_description="A separate company site.",
        reviewer="demo-user",
        now=_now,
    )

    assert first["bundle_path"] != second["bundle_path"]
    assert validate_site_okf_bundle(first["bundle_path"]) == []
    profile_path = tmp_path / "asset_knowledge" / first["bundle_key"] / "profile.md"
    profile = profile_path.read_text(encoding="utf-8")
    _, frontmatter, _ = profile.split("---", 2)
    metadata = yaml.safe_load(frontmatter)
    assert metadata["type"] == "Website Context"
    assert metadata["description"] == "User-confirmed citizen appointment portal."
    assert metadata["verified"]["by"] == "human:demo-user"
    assert "Appointment booking" in profile
    assert "A separate company site" not in profile


def test_main_confirms_okf_before_scanner_execution(monkeypatch, tmp_path, capsys):
    events = []
    draft = {
        "target": "https://example.com/",
        "pages": [{"id": "page-1", "url": "https://example.com/"}],
        "analysis": {
            "site_description": "A public appointment portal.",
            "business_processes": ["Appointment booking"],
        },
    }

    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            events.append("scan")
            return {
                "schema_version": "2.0",
                "target": target,
                "timestamp": "2026-08-08T12:00:00Z",
                "scanners_run": [],
                "all_findings": [],
                "errors": [],
                "summary": {"total_findings": 0, "by_severity": {}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results), encoding="utf-8")
            return path

    def fake_discover(target, **kwargs):
        events.append("discover")
        return draft

    def fake_write(data_dir, value, **kwargs):
        events.append("write_okf")
        assert value is draft
        assert kwargs["confirmed_description"] == "A public appointment portal."
        return {
            "bundle_key": "example-com--123",
            "profile_path": "data/asset_knowledge/example-com--123/profile.md",
            "profile_revision": "abc123",
            "description": kwargs["confirmed_description"],
        }

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator(),
    )
    monkeypatch.setattr(main, "discover_site_context", fake_discover)
    monkeypatch.setattr(main, "write_site_okf_bundle", fake_write)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--discover-context",
            "--context-accept",
            "--no-dedupe",
            "--no-save",
            "--no-report",
            "--json",
        ],
    )

    assert main.main() == 0
    capsys.readouterr()
    normalized = json.loads((tmp_path / "normalized.json").read_text(encoding="utf-8"))

    assert events == ["discover", "write_okf", "scan"]
    assert normalized["asset_knowledge"]["profile_revision"] == "abc123"


def test_confirmed_site_context_is_visible_and_escaped_in_html_report():
    html = generate_modern_html_report(
        {
            "schema_version": "2.0",
            "generated_at": "2026-08-08T12:00:00Z",
            "target": "https://example.com",
            "timestamp": "2026-08-08T12:00:00Z",
            "all_findings": [],
            "summary": {"total_findings": 0, "by_severity": {}},
            "asset_knowledge": {
                "description": "Citizen portal <script>alert(1)</script>",
                "reviewer": "demo-user",
                "profile_revision": "1234567890abcdef",
            },
        }
    )

    assert "Confirmed Site Context" in html
    assert "Citizen portal &lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "Reviewed by:</strong> demo-user" in html
    assert "Revision:</strong> 1234567890ab" in html
    assert "<script>alert(1)</script>" not in html
