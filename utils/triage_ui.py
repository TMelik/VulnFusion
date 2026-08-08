"""Local web UI for human triage of scan findings — a thin wrapper over the CLI.

The UI deliberately does NOT reimplement scanning. It:

* launches the existing ``main.py`` CLI as a subprocess to run scans (the wrapper
  seam — argv is a validated allowlist, never a shell string),
* reads the JSON artifacts the CLI writes under ``data/<slug>/<ts>/``, and
* persists human triage decisions through ``utils.finding_annotations`` (the same
  core the scan pipeline uses to re-apply them on later runs).

Security posture: loopback bind by default; every ``/api/*`` call requires a
random per-process token (embedded in the served page, so a cross-origin site
cannot read it); state-changing POSTs additionally require a same-origin/loopback
Origin; a strict CSP; annotation keys are always recomputed server-side from the
finding (never trusted from the client); scan artifact paths are realpath-confined
to the data directory.
"""

import ipaddress
import json
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlsplit

from utils.finding_annotations import (
    HUMAN_TRIAGE_SCOPES,
    HUMAN_TRIAGE_STATUSES,
    annotation_key,
    load_annotations,
    record_annotation,
)
from utils.run_folder import create_target_slug, parse_timestamp

# Must match the CLI's own --scanner choice set (main.py).
SCANNER_CHOICES: Tuple[str, ...] = ("nmap", "nuclei", "wapiti", "nikto", "zap", "all")
_LOOPBACK_HOST_NAMES = {"localhost", "127.0.0.1", "::1"}
_SLUG_RE = re.compile(r"^[a-z0-9_]+$")
_TARGET_CHARSET_RE = re.compile(r"^[A-Za-z0-9.:/_\-\[\]]+$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_ARTIFACT_NAMES = ("normalized.json", "scan_results.json")


# ---------------------------------------------------------------------------
# Networking helpers
# ---------------------------------------------------------------------------

def _is_loopback(host: str) -> bool:
    host = (host or "").strip().strip("[]")
    if host in _LOOPBACK_HOST_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _pick_free_port(host: str) -> int:
    family = socket.AF_INET6 if ":" in host and host not in _LOOPBACK_HOST_NAMES or host == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, 0))
        except OSError:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as fallback:
                fallback.bind(("127.0.0.1", 0))
                return fallback.getsockname()[1]
        return sock.getsockname()[1]


# ---------------------------------------------------------------------------
# Input validation (the subprocess injection boundary)
# ---------------------------------------------------------------------------

def validate_scanner(scanner: Any) -> str:
    if scanner not in SCANNER_CHOICES:
        raise ValueError(f"scanner must be one of: {', '.join(SCANNER_CHOICES)}")
    return str(scanner)


def validate_target(raw: Any) -> str:
    """Validate a browser-supplied scan target before it becomes an argv element.

    Rejects flag-like values (leading '-'), shell metacharacters (charset
    allowlist), and anything that is not a plausible http(s) URL / hostname /
    IP / CIDR. Combined with list-argv + shell=False this makes injection and
    flag-smuggling impossible.
    """
    if not isinstance(raw, str):
        raise ValueError("target must be a string")
    target = raw.strip()
    if not 1 <= len(target) <= 255:
        raise ValueError("target length must be 1..255")
    if target.startswith("-"):
        raise ValueError("target must not start with '-'")
    if not _TARGET_CHARSET_RE.match(target):
        raise ValueError("target contains invalid characters")

    if "://" in target:
        parsed = urlsplit(target)
        if parsed.scheme not in ("http", "https"):
            raise ValueError("only http/https URLs are allowed")
        candidate = parsed.hostname or ""
    else:
        candidate = urlsplit("//" + target).hostname or target

    if not candidate:
        raise ValueError("could not determine a host from the target")
    if _hostname_or_ip_ok(candidate):
        return target
    raise ValueError("target is not a valid hostname, IP address, or CIDR")


def _hostname_or_ip_ok(candidate: str) -> bool:
    try:
        ipaddress.ip_network(candidate, strict=False)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME_RE.match(candidate))


def build_scan_argv(main_py: Union[str, Path], data_dir: Union[str, Path], target: str, scanner: str) -> List[str]:
    """Construct the CLI invocation from validated primitives (no arbitrary flags)."""
    return [
        sys.executable,
        str(main_py),
        "--target", validate_target(target),
        "--scanner", validate_scanner(scanner),
        "--data-dir", str(data_dir),
        "--apply-annotations",
    ]


# ---------------------------------------------------------------------------
# Scan artifact discovery (path-traversal safe)
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        if path.stat().st_size > 64 * 1024 * 1024:
            return None
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _read_scan_file(scan_dir: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Prefer the final normalized.json; fall back to the raw scan_results.json."""
    for name in _ARTIFACT_NAMES:
        path = scan_dir / name
        if path.exists():
            data = _read_json(path)
            if data is not None:
                return data, name
    return None, None


def safe_scan_dir(data_dir: Union[str, Path], slug: str, ts: str) -> Path:
    """Resolve ``<data_dir>/<slug>/<ts>`` and confirm it stays inside data_dir."""
    if not isinstance(slug, str) or not _SLUG_RE.match(slug):
        raise ValueError("invalid site slug")
    if not isinstance(ts, str) or parse_timestamp(ts) is None:
        raise ValueError("invalid scan timestamp")
    base = Path(data_dir).resolve()
    resolved = (base / slug / ts).resolve()
    if base != resolved and base not in resolved.parents:
        raise ValueError("resolved path escapes the data directory")
    if not resolved.is_dir():
        raise ValueError("scan folder not found")
    return resolved


def list_sites(data_dir: Union[str, Path]) -> List[Dict[str, Any]]:
    """Enumerate scanned sites and their runs, newest first."""
    base = Path(data_dir)
    sites: List[Dict[str, Any]] = []
    if not base.is_dir():
        return sites
    for slug_dir in base.iterdir():
        if not slug_dir.is_dir() or slug_dir.name == "asset_knowledge" or not _SLUG_RE.match(slug_dir.name):
            continue
        scans: List[Dict[str, str]] = []
        for ts_dir in slug_dir.iterdir():
            if not ts_dir.is_dir() or parse_timestamp(ts_dir.name) is None:
                continue
            for name in _ARTIFACT_NAMES:
                if (ts_dir / name).exists():
                    scans.append({"ts": ts_dir.name, "artifact": name})
                    break
        if not scans:
            continue
        scans.sort(key=lambda item: item["ts"], reverse=True)
        data, _ = _read_scan_file(slug_dir / scans[0]["ts"])
        target = str((data or {}).get("target") or slug_dir.name)
        sites.append({"slug": slug_dir.name, "target": target, "scans": scans})
    sites.sort(key=lambda site: site["scans"][0]["ts"], reverse=True)
    return sites


def _finding_view(finding: Dict[str, Any], index: int, annotations: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Project one finding to the compact shape the UI renders, with current triage."""
    finding_key = annotation_key(finding, "finding")
    site_key = annotation_key(finding, "site_vuln")
    meta = finding.get("meta") if isinstance(finding.get("meta"), dict) else {}
    entry = None
    if finding_key:
        entry = annotations.get(f"finding::{finding_key}")
    if entry is None and site_key:
        entry = annotations.get(f"site_vuln::{site_key}")
    triage = None
    if isinstance(entry, dict):
        triage = {
            "status": entry.get("status"),
            "scope": entry.get("scope"),
            "comment": entry.get("comment") or "",
            "reviewer": entry.get("reviewer"),
            "updated_at": entry.get("updated_at") or entry.get("decided_at"),
            "revision": entry.get("revision"),
        }
    applicability = finding.get("applicability") if isinstance(finding.get("applicability"), dict) else None
    return {
        "index": index,
        "vulnerability_name": str(finding.get("vulnerability_name") or "Unknown"),
        "severity": str(finding.get("severity") or "info"),
        "asset_id": str(finding.get("asset_id") or ""),
        "host": str((meta or {}).get("host") or ""),
        "path": str((meta or {}).get("path") or ""),
        "priority": finding.get("priority"),
        "risk_score": finding.get("risk_score"),
        "finding_key": finding_key,
        "site_key": site_key,
        "reattachable": bool(site_key),
        "ai_applicability": (applicability or {}).get("status"),
        "triage": triage,
    }


# ---------------------------------------------------------------------------
# Scan job manager (one scan at a time)
# ---------------------------------------------------------------------------

@dataclass
class Job:
    id: str
    argv: List[str]
    target: str
    scanner: str
    status: str = "running"  # running | success | failed
    returncode: Optional[int] = None
    started_at: float = 0.0
    log: List[str] = field(default_factory=list)
    artifact: Optional[Dict[str, str]] = None


class JobManager:
    def __init__(self, data_dir: Union[str, Path]):
        self.data_dir = Path(data_dir)
        self._jobs: Dict[str, Job] = {}
        self._lock = threading.Lock()
        self._running: Optional[str] = None
        self._counter = 0

    def start(self, argv: List[str], cwd: Union[str, Path], target: str, scanner: str, *, now: float) -> str:
        with self._lock:
            if self._running and self._jobs[self._running].status == "running":
                raise RuntimeError("a scan is already running")
            self._counter += 1
            job = Job(id=f"job-{self._counter}", argv=list(argv), target=target, scanner=scanner, started_at=now)
            self._jobs[job.id] = job
            self._running = job.id
        threading.Thread(target=self._run, args=(job, Path(cwd)), daemon=True).start()
        return job.id

    def _run(self, job: Job, cwd: Path) -> None:
        try:
            proc = subprocess.Popen(
                job.argv, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                if len(job.log) < 3000:
                    job.log.append(line.rstrip("\n"))
            proc.wait()
            job.returncode = proc.returncode
            job.status = "success" if proc.returncode == 0 else "failed"
            job.artifact = self._resolve_artifact(job)
        except Exception as exc:  # pragma: no cover - defensive
            job.status = "failed"
            job.log.append(f"[ui] failed to launch scan: {type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                if self._running == job.id:
                    self._running = None

    def _resolve_artifact(self, job: Job) -> Optional[Dict[str, str]]:
        base = self.data_dir / create_target_slug(job.target)
        if not base.is_dir():
            return None
        best: Optional[Dict[str, str]] = None
        best_mtime = -1.0
        for ts_dir in base.iterdir():
            if not ts_dir.is_dir() or parse_timestamp(ts_dir.name) is None:
                continue
            for name in _ARTIFACT_NAMES:
                path = ts_dir / name
                if path.exists() and path.stat().st_mtime >= job.started_at - 2:
                    mtime = path.stat().st_mtime
                    if mtime > best_mtime:
                        best_mtime = mtime
                        best = {"slug": base.name, "ts": ts_dir.name, "artifact": name}
        return best

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return None
            return {
                "id": job.id, "status": job.status, "returncode": job.returncode,
                "target": job.target, "scanner": job.scanner,
                "log": job.log[-120:], "artifact": job.artifact,
            }


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

def create_app(
    *,
    data_dir: Union[str, Path],
    main_py: Union[str, Path],
    reviewer: str = "local-user",
    token: str,
    host: str = "127.0.0.1",
):
    from fastapi import Depends, FastAPI, HTTPException, Request
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel

    data_dir = Path(data_dir)
    main_py = Path(main_py)
    jobs = JobManager(data_dir)
    scanners_cache: Dict[str, Any] = {}

    class AnnotateBody(BaseModel):
        slug: str
        ts: str
        index: int
        status: str
        scope: str = "finding"
        comment: str = ""
        reviewer: Optional[str] = None

    class RunScanBody(BaseModel):
        target: str
        scanner: str = "all"

    async def require_auth(request: Request) -> None:
        if not secrets.compare_digest(request.headers.get("x-triage-token", ""), token):
            raise HTTPException(status_code=403, detail="missing or invalid triage token")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin:
                origin_host = urlsplit(origin).hostname or ""
                if not (_is_loopback(origin_host) or origin_host == host):
                    raise HTTPException(status_code=403, detail="cross-origin request refused")

    app = FastAPI(title="VulnFusion Triage UI", docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/", response_class=HTMLResponse)
    async def index():
        html = _render_spa(token=token, statuses=HUMAN_TRIAGE_STATUSES, scopes=HUMAN_TRIAGE_SCOPES, scanners=SCANNER_CHOICES)
        return HTMLResponse(
            content=html,
            headers={
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": (
                    "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
                    "connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'"
                ),
            },
        )

    @app.get("/api/scanners", dependencies=[Depends(require_auth)])
    async def api_scanners():
        if "list" not in scanners_cache:
            scanners_cache["list"] = _list_scanner_availability()
        return JSONResponse({"scanners": scanners_cache["list"], "choices": list(SCANNER_CHOICES)})

    @app.get("/api/sites", dependencies=[Depends(require_auth)])
    async def api_sites():
        return JSONResponse({"sites": list_sites(data_dir)})

    @app.get("/api/scan", dependencies=[Depends(require_auth)])
    async def api_scan(slug: str, ts: str):
        try:
            scan_dir = safe_scan_dir(data_dir, slug, ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        data, artifact = _read_scan_file(scan_dir)
        if data is None:
            raise HTTPException(status_code=404, detail="no readable scan artifact in this run")
        target = str(data.get("target") or "")
        annotations = load_annotations(data_dir, target) if target else {}
        raw_findings = data.get("all_findings")
        findings = [
            _finding_view(item, i, annotations)
            for i, item in enumerate(raw_findings if isinstance(raw_findings, list) else [])
            if isinstance(item, dict)
        ]
        return JSONResponse({
            "slug": slug, "ts": ts, "artifact": artifact, "target": target,
            "generated_at": data.get("generated_at"), "findings": findings,
        })

    @app.post("/api/annotate", dependencies=[Depends(require_auth)])
    async def api_annotate(body: AnnotateBody):
        if body.status not in HUMAN_TRIAGE_STATUSES:
            raise HTTPException(status_code=400, detail="invalid triage status")
        if body.scope not in HUMAN_TRIAGE_SCOPES:
            raise HTTPException(status_code=400, detail="invalid triage scope")
        try:
            scan_dir = safe_scan_dir(data_dir, body.slug, body.ts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        data, _ = _read_scan_file(scan_dir)
        if data is None:
            raise HTTPException(status_code=404, detail="no readable scan artifact in this run")
        target = str(data.get("target") or "")
        raw_findings = data.get("all_findings")
        findings = raw_findings if isinstance(raw_findings, list) else []
        if not target or not (0 <= body.index < len(findings)) or not isinstance(findings[body.index], dict):
            raise HTTPException(status_code=400, detail="finding index out of range")
        # The annotation key is recomputed server-side from the finding — a
        # client-supplied key is never trusted.
        try:
            entry = record_annotation(
                data_dir, target, findings[body.index],
                status=body.status, comment=body.comment or "",
                reviewer=(body.reviewer or reviewer), scope=body.scope,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return JSONResponse({"ok": True, "entry": entry})

    @app.post("/api/run-scan", dependencies=[Depends(require_auth)])
    async def api_run_scan(body: RunScanBody):
        try:
            argv = build_scan_argv(main_py, data_dir, body.target, body.scanner)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        try:
            job_id = jobs.start(argv, cwd=main_py.parent, target=body.target, scanner=body.scanner, now=time.time())
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return JSONResponse({"job_id": job_id})

    @app.get("/api/jobs/{job_id}", dependencies=[Depends(require_auth)])
    async def api_job(job_id: str):
        info = jobs.get(job_id)
        if info is None:
            raise HTTPException(status_code=404, detail="unknown job")
        return JSONResponse(info)

    return app


def _list_scanner_availability() -> List[Dict[str, Any]]:
    """Best-effort scanner availability for the dropdown (never fatal)."""
    try:
        from orchestrator import create_default_orchestrator
        orchestrator = create_default_orchestrator()
        result = []
        for scanner in orchestrator.list_scanners():
            result.append({"name": scanner.get("name"), "available": bool(scanner.get("available"))})
        return result
    except Exception:  # pragma: no cover - availability is advisory only
        return [{"name": name, "available": None} for name in SCANNER_CHOICES if name != "all"]


def serve(
    *,
    data_dir: Union[str, Path],
    main_py: Union[str, Path],
    host: str = "127.0.0.1",
    port: int = 8765,
    reviewer: Optional[str] = None,
    allow_remote: bool = False,
) -> None:
    """Start the triage UI (blocking). Loopback-only unless allow_remote."""
    import uvicorn

    host = host or "127.0.0.1"
    if not _is_loopback(host) and not allow_remote:
        raise SystemExit(
            f"Refusing to bind non-loopback host {host!r}. The triage UI can trigger scans and "
            f"write annotations; pass --allow-remote only on a trusted, isolated network."
        )
    if port in (0, None):
        port = _pick_free_port(host)
    token = secrets.token_urlsafe(24)
    app = create_app(data_dir=Path(data_dir), main_py=Path(main_py), reviewer=(reviewer or "local-user"), token=token, host=host)

    if not _is_loopback(host):
        print(f"\n  ⚠  WARNING: binding to non-loopback host {host} — scan control is exposed to the network.\n")
    print("\n  VulnFusion — Human Triage UI")
    print(f"    URL:   http://{host}:{port}/")
    print(f"    Token: {token}   (auto-embedded in the page; needed for API calls)\n")
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ---------------------------------------------------------------------------
# Single-page app (self-contained; no external assets)
# ---------------------------------------------------------------------------

def _render_spa(*, token: str, statuses: List[str], scopes: List[str], scanners: Tuple[str, ...]) -> str:
    """Return the inline SPA with the per-process token and enums embedded."""
    replacements = {
        "__TRIAGE_TOKEN__": token,
        "__STATUSES__": json.dumps(list(statuses)),
        "__SCOPES__": json.dumps(list(scopes)),
        "__SCANNERS__": json.dumps(list(scanners)),
    }
    html = _SPA_TEMPLATE
    for needle, value in replacements.items():
        html = html.replace(needle, value)
    return html


_SPA_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>VulnFusion — Human Triage</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
         background: #0b1020; color: #e5e7eb; }
  header { padding: 1rem 1.25rem; background: #111827; border-bottom: 1px solid #1f2937;
           display: flex; gap: 1rem; align-items: center; flex-wrap: wrap; }
  header h1 { font-size: 1.05rem; margin: 0; font-weight: 700; }
  header .spacer { flex: 1; }
  .runbar { display: flex; gap: 0.5rem; align-items: center; flex-wrap: wrap; }
  input, select, textarea, button { font: inherit; }
  input, select, textarea { background: #0b1020; color: #e5e7eb; border: 1px solid #374151;
           border-radius: 0.4rem; padding: 0.4rem 0.55rem; }
  button { background: #4f46e5; color: #fff; border: 0; border-radius: 0.4rem;
           padding: 0.45rem 0.8rem; cursor: pointer; }
  button.secondary { background: #374151; }
  button:disabled { opacity: 0.5; cursor: not-allowed; }
  .layout { display: grid; grid-template-columns: 300px 1fr; min-height: calc(100vh - 60px); }
  .sidebar { border-right: 1px solid #1f2937; padding: 0.75rem; overflow-y: auto; max-height: calc(100vh - 60px); }
  .main { padding: 1rem 1.25rem; overflow-y: auto; max-height: calc(100vh - 60px); }
  .site { margin-bottom: 0.5rem; }
  .site-name { font-weight: 700; font-size: 0.85rem; color: #93c5fd; word-break: break-all; }
  .scan { padding: 0.3rem 0.5rem; margin: 0.15rem 0; border-radius: 0.35rem; cursor: pointer;
          font-size: 0.8rem; color: #cbd5e1; border: 1px solid transparent; }
  .scan:hover { background: #1f2937; }
  .scan.active { background: #1e293b; border-color: #4f46e5; }
  .muted { color: #94a3b8; font-size: 0.85rem; }
  .finding { border: 1px solid #1f2937; border-radius: 0.6rem; padding: 0.85rem; margin-bottom: 0.8rem;
             background: #0f172a; }
  .finding-top { display: flex; gap: 0.5rem; align-items: baseline; flex-wrap: wrap; }
  .finding-name { font-weight: 700; }
  .badge { font-size: 0.72rem; padding: 0.12rem 0.45rem; border-radius: 999px; border: 1px solid #374151; }
  .sev-critical { background: #7f1d1d; } .sev-high { background: #9a3412; }
  .sev-medium { background: #854d0e; } .sev-low { background: #1e40af; } .sev-info { background: #334155; }
  .asset { font-family: ui-monospace, Menlo, monospace; color: #a5b4fc; font-size: 0.8rem; word-break: break-all; }
  .triage-now { font-size: 0.8rem; margin: 0.4rem 0; }
  .t-false_positive, .t-not_applicable { color: #94a3b8; }
  .t-confirmed { color: #fca5a5; } .t-needs_review { color: #fcd34d; }
  .controls { display: flex; gap: 0.4rem; align-items: flex-start; flex-wrap: wrap; margin-top: 0.5rem; }
  .controls textarea { flex: 1; min-width: 220px; min-height: 2.2rem; }
  .toast { position: fixed; bottom: 1rem; right: 1rem; background: #065f46; color: #fff;
           padding: 0.6rem 0.9rem; border-radius: 0.5rem; opacity: 0; transition: opacity 0.2s; }
  .toast.show { opacity: 1; }
  .toast.err { background: #7f1d1d; }
  #joblog { white-space: pre-wrap; font-family: ui-monospace, Menlo, monospace; font-size: 0.75rem;
            background: #020617; border: 1px solid #1f2937; border-radius: 0.5rem; padding: 0.6rem;
            max-height: 180px; overflow: auto; margin-top: 0.5rem; display: none; }
</style>
</head>
<body>
<header>
  <h1>VulnFusion · Human Triage</h1>
  <div class="spacer"></div>
  <div class="runbar">
    <input id="scanTarget" placeholder="example.com" size="18" />
    <select id="scanScanner"></select>
    <button id="runBtn">Run scan</button>
  </div>
</header>
<div class="layout">
  <aside class="sidebar">
    <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;">
      <strong style="font-size:.8rem;">Sites</strong>
      <button class="secondary" id="refreshBtn" style="padding:.2rem .5rem;font-size:.75rem;">Refresh</button>
    </div>
    <div id="sites"><div class="muted">Loading…</div></div>
    <div id="joblog"></div>
  </aside>
  <main class="main">
    <div id="scanHeader" class="muted">Select a scan on the left to triage its findings.</div>
    <div id="findings"></div>
  </main>
</div>
<div id="toast" class="toast"></div>
<script>
const TOKEN = "__TRIAGE_TOKEN__";
const STATUSES = __STATUSES__;
const SCOPES = __SCOPES__;
const SCANNERS = __SCANNERS__;
const STATUS_LABELS = { confirmed: "Confirmed", false_positive: "False positive",
  not_applicable: "Not applicable", needs_review: "Needs review" };

let current = null; // {slug, ts}

async function api(path, opts) {
  opts = opts || {};
  opts.headers = Object.assign({ "X-Triage-Token": TOKEN }, opts.headers || {});
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.status + "";
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    throw new Error(detail);
  }
  return res.json();
}

function toast(msg, isErr) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast show" + (isErr ? " err" : "");
  setTimeout(() => { el.className = "toast"; }, 2600);
}

function el(tag, props, children) {
  const node = document.createElement(tag);
  if (props) for (const k in props) {
    if (k === "class") node.className = props[k];
    else if (k === "text") node.textContent = props[k];
    else node.setAttribute(k, props[k]);
  }
  (children || []).forEach(c => c && node.appendChild(c));
  return node;
}

function initScanners() {
  const sel = document.getElementById("scanScanner");
  SCANNERS.forEach(s => sel.appendChild(el("option", { value: s, text: s })));
  sel.value = "all";
}

async function loadSites() {
  const box = document.getElementById("sites");
  box.textContent = "";
  let data;
  try { data = await api("/api/sites"); }
  catch (e) { box.appendChild(el("div", { class: "muted", text: "Error: " + e.message })); return; }
  if (!data.sites.length) { box.appendChild(el("div", { class: "muted", text: "No scans found yet." })); return; }
  data.sites.forEach(site => {
    const wrap = el("div", { class: "site" });
    wrap.appendChild(el("div", { class: "site-name", text: site.target }));
    site.scans.forEach(scan => {
      const row = el("div", { class: "scan", text: scan.ts + "  ·  " + scan.artifact.replace(".json", "") });
      row.addEventListener("click", () => selectScan(site.slug, scan.ts, row));
      wrap.appendChild(row);
    });
    box.appendChild(wrap);
  });
}

async function selectScan(slug, ts, row) {
  document.querySelectorAll(".scan.active").forEach(n => n.classList.remove("active"));
  if (row) row.classList.add("active");
  current = { slug, ts };
  const header = document.getElementById("scanHeader");
  const box = document.getElementById("findings");
  header.textContent = "Loading…";
  box.textContent = "";
  let data;
  try { data = await api("/api/scan?slug=" + encodeURIComponent(slug) + "&ts=" + encodeURIComponent(ts)); }
  catch (e) { header.textContent = "Error: " + e.message; return; }
  header.textContent = "";
  header.appendChild(el("div", {}, [
    el("strong", { text: data.target || slug }),
    el("span", { class: "muted", text: "  ·  " + ts + "  ·  " + data.findings.length + " findings" })
  ]));
  if (!data.findings.length) { box.appendChild(el("div", { class: "muted", text: "No findings in this scan." })); return; }
  data.findings.forEach(f => box.appendChild(renderFinding(f)));
}

function renderFinding(f) {
  const card = el("div", { class: "finding" });
  const top = el("div", { class: "finding-top" }, [
    el("span", { class: "badge sev-" + f.severity, text: f.severity.toUpperCase() }),
    el("span", { class: "finding-name", text: f.vulnerability_name }),
  ]);
  if (f.priority) top.appendChild(el("span", { class: "badge", text: f.priority }));
  card.appendChild(top);
  if (f.asset_id) card.appendChild(el("div", { class: "asset", text: f.asset_id }));

  const nowLine = el("div", { class: "triage-now" });
  function paintNow(t) {
    nowLine.textContent = "";
    if (t && t.status) {
      nowLine.appendChild(el("span", { class: "t-" + t.status,
        text: "Triage: " + (STATUS_LABELS[t.status] || t.status) + (t.scope === "site_vuln" ? " (site-wide)" : "") }));
      if (t.comment) nowLine.appendChild(el("span", { class: "muted", text: "  — " + t.comment }));
    } else {
      nowLine.appendChild(el("span", { class: "muted", text: "Untriaged" }));
    }
  }
  paintNow(f.triage);
  card.appendChild(nowLine);
  if (f.ai_applicability) card.appendChild(el("div", { class: "muted", text: "AI advisory: " + f.ai_applicability }));

  const statusSel = el("select");
  STATUSES.forEach(s => statusSel.appendChild(el("option", { value: s, text: STATUS_LABELS[s] || s })));
  if (f.triage && f.triage.status) statusSel.value = f.triage.status;
  const scopeSel = el("select");
  SCOPES.forEach(s => {
    if (s === "site_vuln" && !f.reattachable) return;
    scopeSel.appendChild(el("option", { value: s, text: s === "finding" ? "This finding" : "This vuln, site-wide" }));
  });
  const comment = el("textarea", { placeholder: "Optional comment (why FP / not applicable)…" });
  if (f.triage && f.triage.comment) comment.value = f.triage.comment;
  const saveBtn = el("button", { text: "Save" });

  saveBtn.addEventListener("click", async () => {
    saveBtn.disabled = true;
    try {
      const res = await api("/api/annotate", {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ slug: current.slug, ts: current.ts, index: f.index,
          status: statusSel.value, scope: scopeSel.value, comment: comment.value }),
      });
      paintNow({ status: res.entry.status, scope: res.entry.scope, comment: res.entry.comment });
      f.triage = { status: res.entry.status, scope: res.entry.scope, comment: res.entry.comment };
      toast("Saved — will re-apply on the next scan of this site.");
    } catch (e) { toast("Save failed: " + e.message, true); }
    finally { saveBtn.disabled = false; }
  });

  if (scopeSel.options.length) {
    card.appendChild(el("div", { class: "controls" }, [statusSel, scopeSel, comment, saveBtn]));
  } else {
    card.appendChild(el("div", { class: "controls" }, [statusSel, comment, saveBtn]));
  }
  return card;
}

let pollTimer = null;
async function runScan() {
  const target = document.getElementById("scanTarget").value.trim();
  const scanner = document.getElementById("scanScanner").value;
  if (!target) { toast("Enter a target first.", true); return; }
  const btn = document.getElementById("runBtn");
  const logBox = document.getElementById("joblog");
  btn.disabled = true;
  logBox.style.display = "block";
  logBox.textContent = "Starting scan…\\n";
  let job;
  try {
    job = await api("/api/run-scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, scanner }) });
  } catch (e) { toast("Could not start: " + e.message, true); btn.disabled = false; return; }
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    let info;
    try { info = await api("/api/jobs/" + encodeURIComponent(job.job_id)); }
    catch (e) { return; }
    logBox.textContent = info.log.join("\\n");
    logBox.scrollTop = logBox.scrollHeight;
    if (info.status !== "running") {
      clearInterval(pollTimer); pollTimer = null; btn.disabled = false;
      toast("Scan " + info.status + (info.returncode != null ? " (exit " + info.returncode + ")" : ""), info.status !== "success");
      await loadSites();
      if (info.artifact) selectScan(info.artifact.slug, info.artifact.ts, null);
    }
  }, 1500);
}

document.getElementById("runBtn").addEventListener("click", runScan);
document.getElementById("refreshBtn").addEventListener("click", loadSites);
initScanners();
loadSites();
</script>
</body>
</html>
"""
