"""Tests for the human-triage web UI wrapper (utils/triage_ui.py)."""

import asyncio
import json

import httpx
import pytest

from utils.run_folder import create_target_slug
from utils.finding_annotations import site_bundle_key
from utils import triage_ui


TOKEN = "test-token-123"
TARGET = "https://example.com"


# ---------------------------------------------------------------------------
# Pure validators (the subprocess-injection boundary)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("good", [
    "example.com", "https://example.com", "https://example.com/app",
    "10.0.0.5", "192.168.0.0/24", "sub.domain.example.org", "example.com:8080",
])
def test_validate_target_accepts_reasonable_targets(good):
    assert triage_ui.validate_target(good) == good


@pytest.mark.parametrize("bad", [
    "; rm -rf /", "--data-dir=/etc", "-oProxyCommand=x", "$(whoami)", "a`b`",
    "http://ex ample.com", "ftp://example.com", "a" * 300, "", "  ",
    "example.com;curl evil", "example.com|nc", "http://example.com/?q=1",
])
def test_validate_target_rejects_dangerous_input(bad):
    with pytest.raises(ValueError):
        triage_ui.validate_target(bad)


def test_validate_scanner():
    assert triage_ui.validate_scanner("all") == "all"
    for name in ("nmap", "nuclei", "wapiti", "nikto", "zap"):
        assert triage_ui.validate_scanner(name) == name
    with pytest.raises(ValueError):
        triage_ui.validate_scanner("evil")


def test_build_scan_argv_is_a_safe_list(tmp_path):
    argv = triage_ui.build_scan_argv("/repo/main.py", tmp_path, "example.com", "all")
    assert isinstance(argv, list)
    assert argv[2:] == [
        "--target", "example.com", "--scanner", "all",
        "--ai-analysis-limit", "25", "--data-dir", str(tmp_path),
        "--apply-annotations",
    ]
    # Injection attempts never reach argv construction.
    with pytest.raises(ValueError):
        triage_ui.build_scan_argv("/repo/main.py", tmp_path, "; rm -rf /", "all")


def test_safe_scan_dir_rejects_traversal(tmp_path):
    slug_dir = tmp_path / "example_com" / "20260101_000000"
    slug_dir.mkdir(parents=True)
    assert triage_ui.safe_scan_dir(tmp_path, "example_com", "20260101_000000") == slug_dir.resolve()
    for slug, ts in [("../../etc", "20260101_000000"), ("example_com", "../.."),
                     ("Example_Com", "20260101_000000"), ("example_com", "not-a-ts")]:
        with pytest.raises(ValueError):
            triage_ui.safe_scan_dir(tmp_path, slug, ts)


# ---------------------------------------------------------------------------
# App integration
# ---------------------------------------------------------------------------

def _write_scan(data_dir, ts="20260101_000000"):
    findings = [
        {"vulnerability_name": "SQL Injection", "severity": "high",
         "asset_id": "https://example.com/login", "description": "d", "remediation": "r",
         "meta": {"host": "example.com", "scheme": "https", "port": 443, "path": "/login",
                  "parameter": "user", "method": "POST"}},
        {"vulnerability_name": "Reflected XSS", "severity": "medium",
         "asset_id": "https://example.com/search", "description": "d", "remediation": "r",
         "meta": {"host": "example.com", "scheme": "https", "port": 443, "path": "/search"}},
    ]
    run = data_dir / create_target_slug(TARGET) / ts
    run.mkdir(parents=True)
    (run / "normalized.json").write_text(json.dumps({
        "schema_version": "2.0", "target": TARGET, "generated_at": "2026-01-01T00:00:00Z",
        "all_findings": findings,
    }), encoding="utf-8")
    return ts


class _ASGIClient:
    """Small synchronous facade over HTTPX's network-free ASGI transport."""

    def __init__(self, app):
        self.app = app

    def request(self, method, path, **kwargs):
        async def send():
            transport = httpx.ASGITransport(app=self.app)
            async with httpx.AsyncClient(
                transport=transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def patch(self, path, **kwargs):
        return self.request("PATCH", path, **kwargs)


def _client(tmp_path):
    app = triage_ui.create_app(
        data_dir=tmp_path,
        main_py=tmp_path / "main.py",
        token=TOKEN,
        host="127.0.0.1",
    )
    return _ASGIClient(app)


def _auth(extra=None):
    headers = {"X-Triage-Token": TOKEN}
    if extra:
        headers.update(extra)
    return headers


def test_index_serves_spa_with_embedded_token(tmp_path):
    client = _client(tmp_path)
    res = client.get("/")
    assert res.status_code == 200
    assert TOKEN in res.text
    assert "__TRIAGE_TOKEN__" not in res.text  # placeholder fully substituted
    assert "Content-Security-Policy" in res.headers


def test_api_requires_token(tmp_path):
    client = _client(tmp_path)
    assert client.get("/api/sites").status_code == 403
    assert client.get("/api/sites", headers=_auth()).status_code == 200


def test_sites_and_scan_and_annotate_roundtrip(tmp_path):
    ts = _write_scan(tmp_path)
    client = _client(tmp_path)

    sites = client.get("/api/sites", headers=_auth()).json()["sites"]
    assert len(sites) == 1 and sites[0]["target"] == TARGET
    slug = sites[0]["slug"]

    scan = client.get(f"/api/scan?slug={slug}&ts={ts}", headers=_auth()).json()
    assert len(scan["findings"]) == 2
    first = scan["findings"][0]
    assert first["finding_key"] and first["site_key"]
    assert first["triage"] is None

    # Annotate finding 0 as a false positive with a secret in the comment.
    res = client.post("/api/annotate", headers=_auth({"Content-Type": "application/json"}), json={
        "slug": slug, "ts": ts, "index": 0, "status": "false_positive",
        "scope": "finding", "comment": "not exploitable; token=ghp_ABCDEFGHIJKLMNOPQRST",
    })
    assert res.status_code == 200, res.text
    entry = res.json()["entry"]
    assert entry["status"] == "false_positive"
    assert "ghp_" not in entry["comment"]  # secret scrubbed on write

    # It persisted to the per-site OKF bundle, not the discovery files.
    bundle = tmp_path / "asset_knowledge" / site_bundle_key(TARGET)
    assert (bundle / "annotations.md").exists()
    assert not (bundle / "profile.md").exists()

    # Re-reading the scan reflects the decision immediately.
    scan2 = client.get(f"/api/scan?slug={slug}&ts={ts}", headers=_auth()).json()
    assert scan2["findings"][0]["triage"]["status"] == "false_positive"
    assert scan2["findings"][1]["triage"] is None


def test_annotate_rejects_bad_index_and_status(tmp_path):
    ts = _write_scan(tmp_path)
    client = _client(tmp_path)
    slug = create_target_slug(TARGET)
    bad_status = client.post("/api/annotate", headers=_auth({"Content-Type": "application/json"}),
                             json={"slug": slug, "ts": ts, "index": 0, "status": "bogus"})
    assert bad_status.status_code == 400
    bad_index = client.post("/api/annotate", headers=_auth({"Content-Type": "application/json"}),
                            json={"slug": slug, "ts": ts, "index": 99, "status": "confirmed"})
    assert bad_index.status_code == 400


def test_run_scan_rejects_injection_and_cross_origin(tmp_path):
    client = _client(tmp_path)
    # Malicious target never launches a subprocess.
    bad = client.post("/api/run-scan", headers=_auth({"Content-Type": "application/json"}),
                      json={"target": "; rm -rf /", "scanner": "all"})
    assert bad.status_code == 400
    # Cross-origin POST is refused even with a valid token.
    cross = client.post("/api/run-scan",
                        headers=_auth({"Content-Type": "application/json", "Origin": "http://evil.example.com"}),
                        json={"target": "example.com", "scanner": "all"})
    assert cross.status_code == 403


def test_project_create_list_and_multi_scanner_argv(tmp_path):
    client = _client(tmp_path)
    rejected = client.post(
        "/api/projects",
        headers=_auth({"Content-Type": "application/json"}),
        json={"name": "Customer portal", "target": TARGET},
    )
    assert rejected.status_code == 400

    created = client.post(
        "/api/projects",
        headers=_auth({"Content-Type": "application/json"}),
        json={
            "name": "Customer portal",
            "target": TARGET,
            "default_scanners": ["nmap", "nuclei", "zap"],
            "ai_analysis_limit": 37,
            "authorization_confirmed": True,
        },
    )
    assert created.status_code == 201, created.text
    project = created.json()
    assert project["target"] == "https://example.com/"
    assert project["default_scanners"] == ["nmap", "nuclei", "zap"]
    assert project["ai_analysis_limit"] == 37

    listed = client.get("/api/projects", headers=_auth()).json()["projects"]
    assert [item["project_id"] for item in listed] == [project["project_id"]]
    bundle = tmp_path / "asset_knowledge" / project["project_id"]
    assert (bundle / "project.md").is_file()
    assert "project.md" in (bundle / "index.md").read_text(encoding="utf-8")

    argv = triage_ui.build_scan_argv(
        "/repo/main.py",
        tmp_path,
        project["target"],
        scanners=["nmap", "nuclei", "zap"],
        ai_analysis_limit=37,
    )
    assert "--scanners" in argv
    assert argv[argv.index("--scanners") + 1] == "nmap,nuclei,zap"
    assert argv[argv.index("--ai-analysis-limit") + 1] == "37"


def test_project_scan_endpoint_passes_review_workflow_settings_without_launching(monkeypatch, tmp_path):
    seen = {}

    class FakeJobs:
        def __init__(self, data_dir):
            seen["data_dir"] = data_dir

        def start_project(self, **kwargs):
            seen.update(kwargs)
            return "job-safe"

        def get(self, job_id):
            return None

    monkeypatch.setattr(triage_ui, "JobManager", FakeJobs)
    client = _client(tmp_path)
    project = client.post(
        "/api/projects",
        headers=_auth({"Content-Type": "application/json"}),
        json={
            "name": "Payments",
            "target": TARGET,
            "authorization_confirmed": True,
        },
    ).json()

    rejected = client.post(
        f"/api/projects/{project['project_id']}/scan",
        headers=_auth({"Content-Type": "application/json"}),
        json={"scanners": ["nuclei"]},
    )
    assert rejected.status_code == 400
    started = client.post(
        f"/api/projects/{project['project_id']}/scan",
        headers=_auth({"Content-Type": "application/json"}),
        json={
            "scanners": ["nmap", "nuclei"],
            "ai_analysis_limit": 31,
            "authorization_confirmed": True,
        },
    )
    assert started.status_code == 200
    assert started.json() == {"job_id": "job-safe"}
    assert seen["scanners"] == ["nmap", "nuclei"]
    assert seen["ai_analysis_limit"] == 31


def test_context_review_validates_evidence_before_releasing_job(tmp_path):
    manager = triage_ui.JobManager(tmp_path)
    job = triage_ui.Job(
        id="job-review",
        argv=[],
        target=TARGET,
        scanner="nuclei",
        phase="awaiting_context_review",
        context_draft={
            "pages": [{"id": "page-1"}],
            "osint": [],
            "analysis": {},
        },
    )
    manager._jobs[job.id] = job
    invalid = {
        "description": "Customer portal",
        "business_processes": ["Customer sign-in"],
        "risk_context": {
            "asset_criticality": "high",
            "environment": "production",
            "sensitive_data": True,
            "requires_auth": True,
            "confidence": 0.9,
            "reason": "Confirmed by the reviewer.",
            "evidence_ids": ["invented-source"],
        },
    }
    with pytest.raises(ValueError, match="unknown evidence"):
        manager.review_context(job.id, action="accept", reviewed=invalid)
    assert not job.review_event.is_set()

    valid = json.loads(json.dumps(invalid).replace("invented-source", "page-1"))
    manager.review_context(job.id, action="accept", reviewed=valid)
    assert job.review_event.is_set()
    assert job.reviewed_context["risk_context"]["evidence_ids"] == ["page-1"]


def test_project_workflow_offers_manual_review_when_context_discovery_fails(monkeypatch, tmp_path):
    manager = triage_ui.JobManager(tmp_path)
    job = triage_ui.Job(
        id="job-fallback",
        argv=["safe-command"],
        target=TARGET,
        scanner="nuclei",
        phase="queued",
    )
    job.context_action = "skip"
    job.review_event.set()
    monkeypatch.setattr(
        triage_ui,
        "discover_site_context",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("offline")),
    )

    def complete_without_process(current, cwd):
        current.phase = "success"
        current.status = "success"
        current.returncode = 0

    monkeypatch.setattr(manager, "_run_process", complete_without_process)
    manager._run_project(job, tmp_path, "reviewer")

    assert job.status == "success"
    assert job.context_draft["analysis"]["analysis_source"] == "manual_fallback"
    assert job.context_draft["analysis"]["risk_context"]["confidence"] == 0.0
    assert any("manual review is required" in line for line in job.log)


def test_job_manager_serializes_one_scan(tmp_path):
    mgr = triage_ui.JobManager(tmp_path)
    # A never-terminating command keeps the slot busy so the second start is refused.
    jid = mgr.start(["sleep", "5"], cwd=tmp_path, target="example.com", scanner="all", now=0.0)
    assert mgr.get(jid)["status"] == "running"
    with pytest.raises(RuntimeError):
        mgr.start(["sleep", "5"], cwd=tmp_path, target="example.com", scanner="all", now=0.0)
