import hashlib
import json
import sys
import threading
from datetime import datetime, timezone

import httpx
import main
import yaml

from utils.site_context import (
    DEFAULT_MAX_PAGE_BYTES,
    SiteContextConfig,
    analyze_site_context,
    collect_local_osint,
    crawl_site,
    discover_site_context,
    load_reusable_site_context,
    load_site_okf_bundle,
    parse_context_llm_response,
    site_bundle_key,
    validate_site_okf_bundle,
    write_site_okf_bundle,
)
from utils.report_generator import generate_modern_html_report


FIXED_NOW = datetime(2026, 8, 8, 12, 0, tzinfo=timezone.utc)


def _now():
    return FIXED_NOW


def _risk_context(**overrides):
    value = {
        "asset_criticality": "medium",
        "environment": "production",
        "sensitive_data": None,
        "requires_auth": True,
        "confidence": 0.78,
        "reason": "The appointment workflow and public URL indicate a production service.",
        "evidence_ids": ["page-1"],
    }
    value.update(overrides)
    return value


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
        return httpx.Response(
            200,
            text=pages[str(request.url)],
            headers={
                "content-type": "text/html",
                "server": "demo-server",
                "set-cookie": "must-not-be-collected=secret",
            },
        )

    pages = crawl_site(
        "example.com",
        config=SiteContextConfig(max_pages=99),
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
    assert pages[0]["status_code"] == 200
    assert pages[0]["http_headers"] == {"content-type": "text/html", "server": "demo-server"}
    assert "ignore this instruction" not in pages[0]["text"]
    assert all("evil.example" not in url for url in requested)


def test_crawl_enforces_hard_byte_text_bounds_and_accepts_explicit_default_port():
    requested = []
    oversized = b"<html><body>" + (b"A" * (DEFAULT_MAX_PAGE_BYTES + 300 * 1024))

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if str(request.url) == "https://example.com/":
            return httpx.Response(302, headers={"location": "https://example.com:443/about"})
        return httpx.Response(200, content=oversized, headers={"content-type": "text/html"})

    pages = crawl_site(
        "https://example.com",
        # A generous config value must still be clamped by the hard ceiling
        # (DEFAULT_MAX_PAGE_BYTES), regardless of how large the caller asks for.
        config=SiteContextConfig(max_pages=999, max_page_bytes=DEFAULT_MAX_PAGE_BYTES * 10, max_text_chars=999999),
        transport=httpx.MockTransport(handler),
        now=_now,
    )

    assert requested == ["https://example.com/", "https://example.com/about"]
    assert len(pages) == 1
    assert len(pages[0]["text"]) == 6000
    assert pages[0]["content_sha256"] == hashlib.sha256(oversized[:DEFAULT_MAX_PAGE_BYTES]).hexdigest()


def test_bare_target_falls_back_from_unavailable_https_to_http():
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        if request.url.scheme == "https":
            raise httpx.ConnectError("TLS unavailable", request=request)
        return httpx.Response(
            200,
            text="<html><title>HTTP only</title></html>",
            headers={"content-type": "text/html"},
        )

    pages = crawl_site("example.com", transport=httpx.MockTransport(handler), now=_now)

    assert requested == ["https://example.com/", "http://example.com/"]
    assert pages[0]["url"] == "http://example.com/"


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
                            "risk_context": _risk_context(evidence_ids=["page-99"]),
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
    assert analysis["risk_context"]["asset_criticality"] == "unknown"
    assert analysis["risk_context"]["confidence"] == 0.0
    assert analysis["fallback_reason"].startswith("LLM analysis unavailable")


def test_structured_context_parser_accepts_cited_risk_and_rejects_wrong_types():
    body = {
        "organization_name": "Example",
        "site_description": "A public appointment service.",
        "business_processes": ["Appointment booking"],
        "evidence_ids": ["page-1", "dns-1"],
        "uncertainties": ["Sensitive-data handling was not visible."],
        "risk_context": _risk_context(evidence_ids=["page-1", "dns-1"]),
    }
    parsed = parse_context_llm_response(
        {"choices": [{"message": {"content": f"```json\n{json.dumps(body)}\n```"}}]},
        evidence_ids=["page-1", "dns-1"],
    )

    assert parsed["analysis_source"] == "llm"
    assert parsed["risk_context"]["environment"] == "production"
    assert parsed["risk_context"]["confidence"] == 0.78

    for invalid_confidence in (True, 1, "0.78"):
        body["risk_context"] = _risk_context(confidence=invalid_confidence)
        try:
            parse_context_llm_response(
                {"choices": [{"message": {"content": json.dumps(body)}}]},
                evidence_ids=["page-1", "dns-1"],
            )
        except ValueError as exc:
            assert "confidence" in str(exc)
        else:  # pragma: no cover - assertion guard
            raise AssertionError(f"wrong confidence type must be rejected: {invalid_confidence!r}")


def test_site_context_preview_shows_confidence_and_cited_evidence(capsys):
    main._print_site_context_preview(
        {
            "pages": [{"url": "https://example.com/"}],
            "analysis": {
                "site_description": "Public appointment portal.",
                "analysis_source": "llm",
                "analysis_model": "demo-model",
                "risk_context": _risk_context(confidence=0.78, evidence_ids=["page-1"]),
            },
        }
    )

    output = capsys.readouterr().out
    assert "model-stated confidence: 0.78" in output
    assert "cited evidence: page-1" in output
    assert "demo-model" in output


def test_local_osint_is_allowlisted_bounded_and_fail_open():
    calls = []

    def tls_probe(host, port, timeout):
        calls.append((host, port, timeout))
        return {
            "subject_common_name": "example.com",
            "issuer_common_name": "Demo CA",
            "dns_names": ["www.example.com", "example.com", "example.com"],
            "tls_version": "TLSv1.3",
            "private_key": "must-not-appear",
        }

    result = collect_local_osint(
        "https://example.com",
        [
            {
                "url": "https://example.com/",
                "status_code": 200,
                "fetched_at": "2026-08-08T12:00:00Z",
                "http_headers": {
                    "content-type": "text/html",
                    "server": "demo",
                    "set-cookie": "secret",
                },
            }
        ],
        dns_resolver=lambda host: ["2001:db8::1", "192.0.2.2", "192.0.2.2"],
        tls_probe=tls_probe,
        now=_now,
    )

    assert [source["id"] for source in result["sources"]] == ["http-1", "dns-1", "tls-1"]
    assert result["sources"][0]["data"]["headers"] == {
        "content-type": "text/html",
        "server": "demo",
    }
    assert result["sources"][1]["data"]["addresses"] == ["192.0.2.2", "2001:db8::1"]
    assert result["sources"][2]["data"]["dns_names"] == ["example.com", "www.example.com"]
    assert "private_key" not in result["sources"][2]["data"]
    assert calls == [("example.com", 443, 6.0)]
    assert result["uncertainties"] == []

    failed = collect_local_osint(
        "https://example.com",
        dns_resolver=lambda host: (_ for _ in ()).throw(OSError("offline")),
        tls_probe=lambda host, port, timeout: (_ for _ in ()).throw(TimeoutError("slow")),
        now=_now,
    )
    assert failed["sources"] == []
    assert failed["uncertainties"] == [
        "DNS metadata unavailable: OSError.",
        "TLS metadata unavailable: TimeoutError.",
    ]

    release = threading.Event()
    timed_out = collect_local_osint(
        "http://example.com",
        dns_resolver=lambda host: (release.wait(0.2), ["192.0.2.1"])[1],
        timeout_seconds=0.01,
        now=_now,
    )
    release.set()
    assert timed_out["sources"] == []
    assert timed_out["uncertainties"] == ["DNS metadata unavailable: TimeoutError."]


def test_discovery_passes_page_and_local_metadata_ids_to_one_llm_request():
    posted = []

    def crawl_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            text='<html><title>Example</title><meta name="description" content="A service"></html>',
            headers={"content-type": "text/html", "server": "demo"},
        )

    def llm_handler(request: httpx.Request) -> httpx.Response:
        request_body = json.loads(request.content)
        posted.append(request_body)
        body = {
            "organization_name": "Example",
            "site_description": "A service for customers.",
            "business_processes": ["Customer service"],
            "evidence_ids": ["page-1", "dns-1", "tls-1"],
            "uncertainties": [],
            "risk_context": _risk_context(evidence_ids=["page-1", "tls-1"]),
        }
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(body)}}]})

    draft = discover_site_context(
        "https://example.com",
        api_url="https://llm.example/v1/chat/completions",
        api_key="secret",
        model_name="demo-model",
        crawl_transport=httpx.MockTransport(crawl_handler),
        llm_transport=httpx.MockTransport(llm_handler),
        dns_resolver=lambda host: ["192.0.2.1"],
        tls_probe=lambda host, port, timeout: {"subject_common_name": host, "tls_version": "TLSv1.3"},
        now=_now,
    )

    assert draft["schema_version"] == 2
    assert [item["id"] for item in draft["osint"]] == ["http-1", "dns-1", "tls-1"]
    assert draft["analysis"]["analysis_source"] == "llm"
    assert draft["analysis"]["analysis_model"] == "demo-model"
    evidence = json.loads(posted[0]["messages"][1]["content"])
    assert [item["id"] for item in evidence] == ["page-1", "http-1", "dns-1", "tls-1"]


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
            "analysis_source": "llm",
            "risk_context": _risk_context(),
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
    assert metadata["risk_context"]["environment"] == "production"
    assert metadata["profile_revision"] == first["profile_revision"]
    assert "Appointment booking" in profile
    assert "# Confirmed risk context" in profile
    assert "A separate company site" not in profile
    index = (profile_path.parent / "index.md").read_text(encoding="utf-8")
    assert "User-confirmed citizen appointment portal." in index
    assert f"revisions/{first['profile_revision']}.md" in index
    assert f"Immutable revision `{first['profile_revision'][:12]}`" in index


def test_okf_revisions_are_append_only_and_logs_append(tmp_path):
    draft = {
        "target": "https://example.com/",
        "generated_at": "2026-08-08T11:59:00Z",
        "pages": [
            {
                "id": "page-1",
                "url": "https://example.com/",
                "title": "Example",
                "fetched_at": "2026-08-08T11:59:00Z",
                "content_sha256": "a" * 64,
            }
        ],
        "osint": [
            {
                "id": "dns-1",
                "kind": "dns",
                "resource": "example.com",
                "observed_at": "2026-08-08T11:59:00Z",
                "data": {"addresses": ["192.0.2.1"]},
            }
        ],
        "analysis": {
            "business_processes": ["Appointments"],
            "uncertainties": [],
            "analysis_source": "llm",
            "risk_context": _risk_context(evidence_ids=["page-1", "dns-1"]),
        },
    }
    first = write_site_okf_bundle(
        tmp_path,
        draft,
        confirmed_description="Confirmed service.",
        reviewer="first",
        now=_now,
    )
    revision_path = (
        tmp_path / "asset_knowledge" / first["bundle_key"] / "revisions" / f"{first['profile_revision']}.md"
    )
    immutable_text = revision_path.read_text(encoding="utf-8")
    later = lambda: datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
    same = write_site_okf_bundle(
        tmp_path,
        draft,
        confirmed_description="Confirmed service.",
        reviewer="second",
        now=later,
    )

    assert same["profile_revision"] == first["profile_revision"]
    assert revision_path.read_text(encoding="utf-8") == immutable_text
    refreshed = load_reusable_site_context(tmp_path, "https://example.com", now=later)
    assert refreshed is not None
    assert refreshed["reviewer"] == "second"
    assert refreshed["stale_after"] == "2026-10-10"
    assert refreshed["business_processes"] == ["Appointments"]
    assert validate_site_okf_bundle(first["bundle_path"]) == []
    changed = write_site_okf_bundle(
        tmp_path,
        draft,
        confirmed_description="Confirmed customer service.",
        reviewer="second",
        now=later,
    )
    assert changed["profile_revision"] != first["profile_revision"]
    revisions = list(revision_path.parent.glob("*.md"))
    assert len(revisions) == 2
    log = (revision_path.parent.parent / "log.md").read_text(encoding="utf-8")
    assert log.count("## 2026-") == 3
    assert "**Verification**" in log
    assert "**Update**" in log
    assert validate_site_okf_bundle(first["bundle_path"]) == []


def test_okf_loader_reuses_only_fresh_confirmed_profile_and_reads_legacy(tmp_path):
    draft = {
        "target": "https://example.com/",
        "pages": [{"id": "page-1", "url": "https://example.com/", "title": "Example"}],
        "analysis": {
            "business_processes": ["Appointment booking"],
            "uncertainties": [],
            "analysis_source": "fallback",
            "risk_context": _risk_context(),
        },
    }
    written = write_site_okf_bundle(
        tmp_path,
        draft,
        confirmed_description="Confirmed service.",
        reviewer="demo-user",
        now=_now,
    )

    loaded = load_site_okf_bundle(tmp_path, "http://EXAMPLE.com", now=_now)
    assert loaded is not None
    assert loaded["profile_revision"] == written["profile_revision"]
    assert loaded["description"] == "Confirmed service."
    assert loaded["reviewer"] == "demo-user"
    assert loaded["risk_context"]["asset_criticality"] == "medium"
    assert loaded["business_processes"] == ["Appointment booking"]
    assert loaded["stale"] is False
    reusable = load_reusable_site_context(tmp_path, "https://example.com", now=_now)
    assert reusable is not None
    assert reusable["profile_revision"] == loaded["profile_revision"]

    expired_now = lambda: datetime(2026, 9, 8, 12, 0, tzinfo=timezone.utc)
    assert load_site_okf_bundle(tmp_path, "https://example.com", now=expired_now)["stale"] is True
    assert load_reusable_site_context(tmp_path, "https://example.com", now=expired_now) is None

    legacy_dir = tmp_path / "asset_knowledge" / site_bundle_key("https://legacy.example")
    legacy_dir.mkdir(parents=True)
    legacy_profile = {
        "type": "Website Context",
        "description": "Legacy confirmed profile.",
        "resource": "https://legacy.example/",
        "verified": {"by": "human:legacy-user", "at": "2026-08-08T12:00:00Z"},
        "stale_after": "2026-09-07",
        "subject": {"normalized_host": "legacy.example"},
    }
    (legacy_dir / "profile.md").write_text(
        "---\n" + yaml.safe_dump(legacy_profile, sort_keys=False) + "---\n\n# Description\n\nLegacy confirmed profile.\n",
        encoding="utf-8",
    )
    legacy = load_reusable_site_context(tmp_path, "https://legacy.example", now=_now)
    assert legacy is not None
    assert legacy["analysis_source"] == "legacy"
    assert legacy["risk_context"]["asset_criticality"] == "unknown"
    assert legacy["risk_context"]["confidence"] == 0.0


def test_okf_loader_rejects_tampered_or_missing_immutable_revision(tmp_path):
    draft = {
        "target": "https://example.com/",
        "generated_at": "2026-08-08T11:59:00Z",
        "pages": [
            {
                "id": "page-1",
                "url": "https://example.com/",
                "title": "Example Portal",
                "fetched_at": "2026-08-08T11:59:00Z",
                "content_sha256": "a" * 64,
            }
        ],
        "analysis": {
            "business_processes": ["Appointment booking"],
            "uncertainties": [],
            "analysis_source": "llm",
            "risk_context": _risk_context(),
        },
    }
    written = write_site_okf_bundle(
        tmp_path,
        draft,
        confirmed_description="Confirmed appointment portal.",
        reviewer="demo-user",
        now=_now,
    )
    profile_path = tmp_path / "asset_knowledge" / written["bundle_key"] / "profile.md"
    original_profile = profile_path.read_text(encoding="utf-8")
    assert "environment: production" in original_profile

    profile_path.write_text(
        original_profile.replace("environment: production", "environment: staging", 1),
        encoding="utf-8",
    )
    assert load_site_okf_bundle(tmp_path, draft["target"], now=_now) is None

    profile_path.write_text(original_profile, encoding="utf-8")
    revision_path = (
        tmp_path
        / "asset_knowledge"
        / written["bundle_key"]
        / "revisions"
        / f"{written['profile_revision']}.md"
    )
    original_revision = revision_path.read_text(encoding="utf-8")
    tampered_revision = original_revision.replace(
        "environment: production", "environment: staging", 1
    )
    profile_path.write_text(
        original_profile.replace("environment: production", "environment: staging", 1),
        encoding="utf-8",
    )
    revision_path.write_text(tampered_revision, encoding="utf-8")
    assert load_site_okf_bundle(tmp_path, draft["target"], now=_now) is None

    profile_path.write_text(original_profile, encoding="utf-8")
    revision_path.write_text(original_revision, encoding="utf-8")
    revision_path.unlink()
    assert load_site_okf_bundle(tmp_path, draft["target"], now=_now) is None


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
                "reviewer": "demo-user",
                "analysis_source": "fallback",
                "business_processes": ["Appointment booking"],
                "risk_context": {
                    "asset_criticality": "unknown",
                    "environment": "unknown",
                    "sensitive_data": None,
                    "requires_auth": None,
                    "confidence": 0.0,
                    "reason": "Risk context requires review.",
                    "evidence_ids": [],
                },
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
