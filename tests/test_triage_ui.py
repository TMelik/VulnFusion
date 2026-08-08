"""Tests for the human-triage web UI wrapper (utils/triage_ui.py)."""

import json

import pytest

from fastapi.testclient import TestClient

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
    assert argv[2:] == ["--target", "example.com", "--scanner", "all", "--data-dir", str(tmp_path), "--apply-annotations"]
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


def _client(tmp_path):
    app = triage_ui.create_app(data_dir=tmp_path, main_py=tmp_path / "main.py", token=TOKEN, host="127.0.0.1")
    return TestClient(app)


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


def test_job_manager_serializes_one_scan(tmp_path):
    mgr = triage_ui.JobManager(tmp_path)
    # A never-terminating command keeps the slot busy so the second start is refused.
    jid = mgr.start(["sleep", "5"], cwd=tmp_path, target="example.com", scanner="all", now=0.0)
    assert mgr.get(jid)["status"] == "running"
    with pytest.raises(RuntimeError):
        mgr.start(["sleep", "5"], cwd=tmp_path, target="example.com", scanner="all", now=0.0)
