"""Local project, scanning, reporting, and human-triage UI over the CLI.

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
import copy
import json
import os
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
from utils.project_store import (
    DEFAULT_AI_ANALYSIS_LIMIT,
    DEFAULT_SCANNERS,
    SCANNER_NAMES,
    list_projects,
    load_project,
    project_runs,
    save_project,
)
from utils.llm_duplicate_resolver import resolve_llm_duplicate_provider_settings
from utils.site_context import (
    CONTEXT_SCHEMA_VERSION,
    _normalize_risk_context,
    discover_site_context,
    load_site_okf_bundle,
    normalize_site_url,
    site_bundle_key,
    write_site_okf_bundle,
)

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


def build_scan_argv(
    main_py: Union[str, Path],
    data_dir: Union[str, Path],
    target: str,
    scanner: str = "all",
    *,
    scanners: Optional[List[str]] = None,
    ai_analysis_limit: int = DEFAULT_AI_ANALYSIS_LIMIT,
) -> List[str]:
    """Construct the CLI invocation from validated primitives (no arbitrary flags)."""
    argv = [
        sys.executable,
        str(main_py),
        "--target", validate_target(target),
    ]
    if scanners is not None:
        selected = []
        for name in scanners:
            selected.append(validate_scanner(name))
        if not selected or "all" in selected:
            raise ValueError("scanners must contain one or more concrete scanner names")
        argv.extend(["--scanners", ",".join(dict.fromkeys(selected))])
    else:
        argv.extend(["--scanner", validate_scanner(scanner)])
    if isinstance(ai_analysis_limit, bool) or not isinstance(ai_analysis_limit, int) or not 1 <= ai_analysis_limit <= 100:
        raise ValueError("ai_analysis_limit must be between 1 and 100")
    argv.extend([
        "--ai-analysis-limit", str(ai_analysis_limit),
        "--data-dir", str(data_dir),
        "--apply-annotations",
    ])
    return argv


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
        "ai_priority": finding.get("ai_priority") if isinstance(finding.get("ai_priority"), dict) else None,
        "ai_summary": finding.get("ai_summary") if isinstance(finding.get("ai_summary"), dict) else None,
        "ai_remediation": finding.get("ai_remediation") if isinstance(finding.get("ai_remediation"), dict) else None,
        "risk_rationale": finding.get("risk_rationale"),
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
    phase: str = "scanning"
    project_id: Optional[str] = None
    scanners: List[str] = field(default_factory=list)
    context_draft: Optional[Dict[str, Any]] = None
    context_action: Optional[str] = None
    reviewed_context: Optional[Dict[str, Any]] = None
    review_event: threading.Event = field(default_factory=threading.Event, repr=False)


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
            self._run_process(job, cwd)
        except Exception as exc:  # pragma: no cover - defensive
            job.status = "failed"
            job.log.append(f"[ui] failed to launch scan: {type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                if self._running == job.id:
                    self._running = None

    def _run_process(self, job: Job, cwd: Path) -> None:
        job.phase = "scanning"
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
        job.phase = "postprocessing" if proc.returncode == 0 else "failed"
        job.status = "success" if proc.returncode == 0 else "failed"
        job.artifact = self._resolve_artifact(job)
        if job.status == "success":
            job.phase = "success"

    def start_project(
        self,
        *,
        project: Dict[str, Any],
        scanners: List[str],
        ai_analysis_limit: int,
        main_py: Path,
        cwd: Path,
        reviewer: str,
        now: float,
    ) -> str:
        argv = build_scan_argv(
            main_py,
            self.data_dir,
            project["target"],
            scanners=scanners,
            ai_analysis_limit=ai_analysis_limit,
        )
        with self._lock:
            if self._running and self._jobs[self._running].status == "running":
                raise RuntimeError("a scan is already running")
            self._counter += 1
            job = Job(
                id=f"job-{self._counter}",
                argv=argv,
                target=project["target"],
                scanner=",".join(scanners),
                scanners=list(scanners),
                project_id=project["project_id"],
                phase="queued",
                started_at=now,
            )
            self._jobs[job.id] = job
            self._running = job.id
        threading.Thread(
            target=self._run_project,
            args=(job, cwd, reviewer),
            daemon=True,
        ).start()
        return job.id

    def _run_project(self, job: Job, cwd: Path, reviewer: str) -> None:
        try:
            existing = load_site_okf_bundle(self.data_dir, job.target)
            if existing is None or existing.get("stale"):
                job.phase = "discovering_context"
                job.log.append("[ui] Discovering site context before scanning…")
                settings = resolve_llm_duplicate_provider_settings(
                    cli_api_url=None,
                    cli_api_key=None,
                    cli_model_name=None,
                    env=os.environ,
                )
                try:
                    job.context_draft = discover_site_context(
                        job.target,
                        api_url=settings["api_url"],
                        api_key=settings["api_key"],
                        model_name=settings["model_name"],
                    )
                except Exception as exc:
                    job.log.append(
                        f"[ui] Automated context discovery unavailable ({type(exc).__name__}); manual review is required."
                    )
                    job.context_draft = {
                        "schema_version": CONTEXT_SCHEMA_VERSION,
                        "target": normalize_site_url(job.target),
                        "generated_at": "",
                        "pages": [],
                        "osint": [],
                        "osint_uncertainties": ["Automated context discovery was unavailable."],
                        "analysis": {
                            "site_description": "",
                            "business_processes": [],
                            "uncertainties": ["Enter and confirm the site context manually."],
                            "risk_context": {
                                "asset_criticality": "unknown",
                                "environment": "unknown",
                                "sensitive_data": None,
                                "requires_auth": None,
                                "confidence": 0.0,
                                "reason": "No crawl evidence was collected; human review is required.",
                                "evidence_ids": [],
                            },
                            "analysis_source": "manual_fallback",
                            "needs_review": True,
                        },
                    }
                job.phase = "awaiting_context_review"
                job.log.append("[ui] Context proposal is ready for review.")
                job.review_event.wait()
                if job.context_action == "cancel":
                    job.phase = "cancelled"
                    job.status = "cancelled"
                    return
                if job.context_action == "accept":
                    draft = copy.deepcopy(job.context_draft)
                    reviewed = job.reviewed_context or {}
                    analysis = draft.get("analysis") if isinstance(draft.get("analysis"), dict) else {}
                    analysis["business_processes"] = list(reviewed.get("business_processes") or [])
                    analysis["risk_context"] = dict(reviewed.get("risk_context") or {})
                    draft["analysis"] = analysis
                    write_site_okf_bundle(
                        self.data_dir,
                        draft,
                        confirmed_description=str(reviewed.get("description") or ""),
                        reviewer=reviewer,
                    )
                    job.log.append("[ui] Confirmed context saved to the project OKF bundle.")
                else:
                    job.log.append("[ui] Continuing without confirmed site context.")
            else:
                job.log.append("[ui] Reusing fresh confirmed site context.")
            self._run_process(job, cwd)
        except Exception as exc:
            job.status = "failed"
            job.phase = "failed"
            job.log.append(f"[ui] workflow failed: {type(exc).__name__}: {exc}")
        finally:
            with self._lock:
                if self._running == job.id:
                    self._running = None

    def review_context(self, job_id: str, *, action: str, reviewed: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise ValueError("unknown job")
            if job.phase != "awaiting_context_review":
                raise ValueError("job is not awaiting context review")
            if action not in {"accept", "skip", "cancel"}:
                raise ValueError("invalid context action")
            if action == "accept":
                value = reviewed or {}
                description = " ".join(str(value.get("description") or "").split())
                processes = value.get("business_processes")
                risk = value.get("risk_context")
                if not description or len(description) > 500:
                    raise ValueError("reviewed description must contain 1 to 500 characters")
                if not isinstance(processes, list) or len(processes) > 5 or not all(isinstance(item, str) and item.strip() for item in processes):
                    raise ValueError("business_processes must contain at most five strings")
                if not isinstance(risk, dict):
                    raise ValueError("risk_context must be an object")
                risk = dict(risk)
                confidence = risk.get("confidence")
                if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
                    risk["confidence"] = float(confidence)
                draft = job.context_draft or {}
                source_ids = {
                    str(item.get("id"))
                    for collection in (draft.get("pages"), draft.get("osint"))
                    if isinstance(collection, list)
                    for item in collection
                    if isinstance(item, dict) and item.get("id")
                }
                normalized_risk = _normalize_risk_context(
                    risk,
                    allowed_evidence_ids=source_ids,
                )
                job.reviewed_context = {
                    "description": description,
                    "business_processes": [" ".join(item.split())[:160] for item in processes],
                    "risk_context": normalized_risk,
                }
            job.context_action = action
            job.review_event.set()

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
                "scanners": list(job.scanners), "project_id": job.project_id,
                "phase": job.phase, "log": job.log[-120:], "artifact": job.artifact,
                "context_draft": copy.deepcopy(job.context_draft) if job.phase == "awaiting_context_review" else None,
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
    from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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

    class ProjectBody(BaseModel):
        name: str
        target: str
        default_scanners: List[str] = list(DEFAULT_SCANNERS)
        ai_analysis_limit: int = DEFAULT_AI_ANALYSIS_LIMIT
        authorization_confirmed: bool = False

    class ProjectUpdateBody(BaseModel):
        name: Optional[str] = None
        default_scanners: Optional[List[str]] = None
        ai_analysis_limit: Optional[int] = None
        authorization_confirmed: bool = False

    class ProjectScanBody(BaseModel):
        scanners: Optional[List[str]] = None
        ai_analysis_limit: Optional[int] = None
        authorization_confirmed: bool = False

    class ContextReviewBody(BaseModel):
        action: str
        description: Optional[str] = None
        business_processes: Optional[List[str]] = None
        risk_context: Optional[Dict[str, Any]] = None

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

    @app.get("/api/projects", dependencies=[Depends(require_auth)])
    async def api_projects():
        projects = list_projects(data_dir)
        known_targets = {item["target"] for item in projects}
        for site in list_sites(data_dir):
            target = str(site.get("target") or "")
            if not target or target in known_targets:
                continue
            try:
                has_context = load_site_okf_bundle(data_dir, target) is not None
            except (OSError, ValueError):
                has_context = False
            projects.append({
                "project_id": site_bundle_key(target),
                "name": target,
                "target": target,
                "default_scanners": list(DEFAULT_SCANNERS),
                "ai_analysis_limit": DEFAULT_AI_ANALYSIS_LIMIT,
                "created_at": "",
                "updated_at": "",
                "authorization": {},
                "runs": site.get("scans") or [],
                "slug": site.get("slug"),
                "has_context": has_context,
                "legacy": True,
            })
        return JSONResponse({"projects": projects})

    @app.post("/api/projects", dependencies=[Depends(require_auth)])
    async def api_create_project(body: ProjectBody):
        try:
            project = save_project(
                data_dir,
                name=body.name,
                target=validate_target(body.target),
                default_scanners=body.default_scanners,
                ai_analysis_limit=body.ai_analysis_limit,
                reviewer=reviewer,
                authorization_confirmed=body.authorization_confirmed,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        project["runs"] = project_runs(data_dir, project["target"])
        project["slug"] = create_target_slug(project["target"])
        project["has_context"] = False
        return JSONResponse(project, status_code=201)

    @app.patch("/api/projects/{project_id}", dependencies=[Depends(require_auth)])
    async def api_update_project(project_id: str, body: ProjectUpdateBody):
        try:
            current = load_project(data_dir, project_id)
            project = save_project(
                data_dir,
                name=body.name if body.name is not None else current["name"],
                target=current["target"],
                default_scanners=body.default_scanners if body.default_scanners is not None else current["default_scanners"],
                ai_analysis_limit=body.ai_analysis_limit if body.ai_analysis_limit is not None else current["ai_analysis_limit"],
                reviewer=reviewer,
                authorization_confirmed=body.authorization_confirmed,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return JSONResponse(project)

    @app.get("/api/projects/{project_id}/runs", dependencies=[Depends(require_auth)])
    async def api_project_runs(project_id: str):
        try:
            project = load_project(data_dir, project_id)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        return JSONResponse({"runs": project_runs(data_dir, project["target"])})

    @app.post("/api/projects/{project_id}/scan", dependencies=[Depends(require_auth)])
    async def api_project_scan(project_id: str, body: ProjectScanBody):
        if body.authorization_confirmed is not True:
            raise HTTPException(status_code=400, detail="explicit scan authorization confirmation is required")
        try:
            try:
                project = load_project(data_dir, project_id)
            except ValueError:
                legacy_site = next(
                    (
                        site for site in list_sites(data_dir)
                        if site_bundle_key(str(site.get("target") or "")) == project_id
                    ),
                    None,
                )
                if legacy_site is None:
                    raise
                project = save_project(
                    data_dir,
                    name=str(legacy_site.get("target") or project_id),
                    target=str(legacy_site.get("target") or ""),
                    reviewer=reviewer,
                    authorization_confirmed=True,
                )
            scanners = body.scanners if body.scanners is not None else project["default_scanners"]
            scanners = list(dict.fromkeys(str(name).strip().lower() for name in scanners))
            if not scanners or any(name not in SCANNER_NAMES for name in scanners):
                raise ValueError("one or more selected scanners are invalid")
            limit = body.ai_analysis_limit if body.ai_analysis_limit is not None else project["ai_analysis_limit"]
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
                raise ValueError("ai_analysis_limit must be between 1 and 100")
            job_id = jobs.start_project(
                project=project,
                scanners=scanners,
                ai_analysis_limit=limit,
                main_py=main_py,
                cwd=main_py.parent,
                reviewer=reviewer,
                now=time.time(),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        except RuntimeError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        return JSONResponse({"job_id": job_id})

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
            "summary": data.get("summary") if isinstance(data.get("summary"), dict) else {},
            "ai_analysis_summary": data.get("ai_analysis_summary") if isinstance(data.get("ai_analysis_summary"), dict) else {},
            "asset_knowledge": data.get("asset_knowledge") if isinstance(data.get("asset_knowledge"), dict) else None,
            "report_available": (scan_dir / "report.html").is_file(),
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

    @app.post("/api/jobs/{job_id}/context", dependencies=[Depends(require_auth)])
    async def api_review_context(job_id: str, body: ContextReviewBody):
        reviewed = None
        if body.action == "accept":
            reviewed = {
                "description": body.description,
                "business_processes": body.business_processes or [],
                "risk_context": body.risk_context,
            }
        try:
            jobs.review_context(job_id, action=body.action, reviewed=reviewed)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return JSONResponse({"ok": True})

    @app.get("/api/projects/{project_id}/runs/{ts}/report", dependencies=[Depends(require_auth)])
    async def api_report(project_id: str, ts: str):
        try:
            try:
                target = load_project(data_dir, project_id)["target"]
            except ValueError:
                legacy_site = next(
                    (
                        site for site in list_sites(data_dir)
                        if site_bundle_key(str(site.get("target") or "")) == project_id
                    ),
                    None,
                )
                if legacy_site is None:
                    raise
                target = str(legacy_site.get("target") or "")
            scan_dir = safe_scan_dir(data_dir, create_target_slug(target), ts)
        except ValueError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        report_path = scan_dir / "report.html"
        if not report_path.is_file():
            raise HTTPException(status_code=404, detail="report not found")
        return FileResponse(
            report_path,
            media_type="text/html",
            headers={"X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer"},
        )

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
    print("\n  VulnFusion — Projects & Scans UI")
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
<title>VulnFusion — Projects &amp; Scans</title>
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
  .panel { border:1px solid #1f2937; border-radius:.6rem; padding:.7rem; margin-bottom:.75rem; background:#0f172a; }
  .scanner-grid { display:flex; gap:.55rem; flex-wrap:wrap; margin:.5rem 0; }
  .scanner-grid label { font-size:.8rem; }
  .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(120px,1fr)); gap:.6rem; margin:.8rem 0; }
  .metric { padding:.7rem; border:1px solid #1f2937; border-radius:.5rem; background:#111827; }
  .metric strong { display:block; font-size:1.25rem; }
  .distribution { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:.6rem; margin:.7rem 0; }
  .distribution-row { display:grid; grid-template-columns:5rem 1fr 2rem; gap:.45rem; align-items:center; font-size:.78rem; margin:.28rem 0; }
  .distribution-track { height:.45rem; border-radius:999px; background:#1f2937; overflow:hidden; }
  .distribution-fill { height:100%; background:#6366f1; border-radius:999px; }
  .source-list { font-size:.78rem; color:#cbd5e1; margin:-.25rem 0 .8rem; word-break:break-all; }
  .modal { position:fixed; inset:0; background:#020617e8; display:none; align-items:center; justify-content:center; z-index:20; }
  .modal.show { display:flex; }
  .modal-card { width:min(760px,94vw); max-height:90vh; overflow:auto; background:#111827; border:1px solid #374151; border-radius:.8rem; padding:1rem; }
  .form-grid { display:grid; grid-template-columns:1fr 1fr; gap:.6rem; }
  .form-grid label { display:flex; flex-direction:column; gap:.25rem; }
  .form-grid .wide { grid-column:1/-1; }
  @media(max-width:760px) { .layout{grid-template-columns:1fr}.sidebar{max-height:none}.form-grid{grid-template-columns:1fr} }
</style>
</head>
<body>
<header>
  <h1>VulnFusion · Projects &amp; Scans</h1>
  <div class="spacer"></div>
  <div class="runbar">
    <select id="projectSelect"><option value="">Select project…</option></select>
    <button class="secondary" id="newProjectBtn">New project</button>
  </div>
</header>
<div class="layout">
  <aside class="sidebar">
    <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem;">
      <strong style="font-size:.8rem;">Projects</strong>
      <button class="secondary" id="refreshBtn" style="padding:.2rem .5rem;font-size:.75rem;">Refresh</button>
    </div>
    <div id="projects"><div class="muted">Loading…</div></div>
    <div class="panel" id="scanPanel" style="display:none">
      <strong>Scanners</strong><div class="scanner-grid" id="scannerChecks"></div>
      <button class="secondary" id="safePreset">Safe</button> <button class="secondary" id="fullPreset">Full</button>
      <p><label class="muted">AI limit <input id="aiLimit" type="number" min="1" max="100" value="25" style="width:5rem"></label></p>
      <label style="display:block;margin:.6rem 0;font-size:.78rem"><input id="authorized" type="checkbox"> I confirm authorization to scan</label>
      <button id="runBtn">Run selected scan</button>
    </div>
    <div id="joblog"></div>
  </aside>
  <main class="main">
    <div id="scanHeader" class="muted">Select or create a project.</div>
    <div id="dashboard"></div>
    <div id="findings"></div>
  </main>
</div>
<div id="toast" class="toast"></div>
<div id="projectModal" class="modal"><div class="modal-card">
  <h2>New project</h2><div class="form-grid">
  <label>Name<input id="projectName"></label><label>Target<input id="projectTarget" placeholder="https://example.com"></label>
  <label>AI limit<input id="projectLimit" type="number" min="1" max="100" value="25"></label>
  <label class="wide"><span><input id="projectAuthorized" type="checkbox"> I confirm authorization to scan this target</span></label></div>
  <p><button id="createProjectBtn">Create</button> <button class="secondary" id="closeProjectBtn">Cancel</button></p>
</div></div>
<div id="contextModal" class="modal"><div class="modal-card">
  <h2>Review site context</h2><p class="muted" id="contextSources"></p><div class="source-list" id="contextSourceList"></div><div class="form-grid">
  <label class="wide">Description<textarea id="contextDescription"></textarea></label>
  <label class="wide">Business processes (one per line)<textarea id="contextProcesses"></textarea></label>
  <label>Criticality<select id="contextCriticality"><option>unknown</option><option>low</option><option>medium</option><option>high</option></select></label>
  <label>Environment<select id="contextEnvironment"><option>unknown</option><option>development</option><option>test</option><option>staging</option><option>production</option></select></label>
  <label>Sensitive data<select id="contextSensitive"><option value="unknown">unknown</option><option value="true">yes</option><option value="false">no</option></select></label>
  <label>Authentication<select id="contextAuth"><option value="unknown">unknown</option><option value="true">required</option><option value="false">not required</option></select></label>
  <label class="wide">Reason<textarea id="contextReason"></textarea></label></div>
  <p><button id="acceptContextBtn">Accept & continue</button> <button class="secondary" id="skipContextBtn">Continue without context</button> <button class="secondary" id="cancelJobBtn">Cancel scan</button></p>
</div></div>
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

let projects = [];
let currentProject = null;
let currentJob = null;

function initScanners(defaults) {
  const box = document.getElementById("scannerChecks"); box.textContent = "";
  SCANNERS.filter(s => s !== "all").forEach(s => {
    const input = el("input", { type: "checkbox", value: s });
    input.checked = (defaults || ["nmap", "nuclei"]).includes(s);
    box.appendChild(el("label", {}, [input, document.createTextNode(" " + s)]));
  });
}

function selectProject(project) {
  currentProject = project;
  document.getElementById("projectSelect").value = project.project_id;
  document.getElementById("scanPanel").style.display = "block";
  document.getElementById("aiLimit").value = project.ai_analysis_limit || 25;
  document.getElementById("authorized").checked = false;
  initScanners(project.default_scanners);
  document.getElementById("scanHeader").textContent = project.name + " · " + project.target;
}

async function loadProjects() {
  const box = document.getElementById("projects");
  box.textContent = "";
  let data;
  try { data = await api("/api/projects"); }
  catch (e) { box.appendChild(el("div", { class: "muted", text: "Error: " + e.message })); return; }
  projects = data.projects;
  const select = document.getElementById("projectSelect");
  select.innerHTML = '<option value="">Select project…</option>';
  if (!projects.length) { box.appendChild(el("div", { class: "muted", text: "No projects yet." })); return; }
  projects.forEach(project => {
    select.appendChild(el("option", { value: project.project_id, text: project.name }));
    const wrap = el("div", { class: "site" });
    const name = el("div", { class: "site-name", text: project.name });
    name.addEventListener("click", () => selectProject(project)); wrap.appendChild(name);
    (project.runs || []).forEach(scan => {
      const row = el("div", { class: "scan", text: scan.ts + "  ·  " + scan.artifact.replace(".json", "") });
      row.addEventListener("click", () => { selectProject(project); selectScan(project.slug, scan.ts, row); });
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
  const dashboard = document.getElementById("dashboard"); dashboard.textContent = "";
  const summary = data.summary || {};
  const metrics = [["Findings", summary.total_findings || data.findings.length], ["AI analyzed", (data.ai_analysis_summary || {}).analyzed_count || 0], ["AI needs review", (data.ai_analysis_summary || {}).needs_review_count || 0], ["Priority disagreements", (data.ai_analysis_summary || {}).priority_disagreement_count || 0]];
  const grid = el("div", { class: "summary-grid" });
  metrics.forEach(m => grid.appendChild(el("div", { class: "metric" }, [el("strong", { text: String(m[1]) }), el("span", { class: "muted", text: m[0] })])));
  dashboard.appendChild(grid);
  const distributions = el("div", { class: "distribution" });
  [["Severity", summary.by_severity || {}], ["Deterministic priority", summary.by_priority || {}]].forEach(group => {
    const values = Object.entries(group[1]).filter(item => Number(item[1]) > 0);
    if (!values.length) return;
    const panel = el("div", { class: "panel" }, [el("strong", { text: group[0] })]);
    const max = Math.max(...values.map(item => Number(item[1])));
    values.forEach(item => {
      const fill = el("div", { class: "distribution-fill", style: "width:" + Math.round(Number(item[1]) * 100 / max) + "%" });
      panel.appendChild(el("div", { class: "distribution-row" }, [
        el("span", { text: item[0] }), el("div", { class: "distribution-track" }, [fill]), el("span", { text: String(item[1]) })
      ]));
    });
    distributions.appendChild(panel);
  });
  dashboard.appendChild(distributions);
  if (data.report_available && currentProject) {
    const reportBtn = el("button", { text: "Open full report" });
    reportBtn.addEventListener("click", async () => {
      try {
        const res = await fetch("/api/projects/" + encodeURIComponent(currentProject.project_id) + "/runs/" + encodeURIComponent(ts) + "/report", { headers: { "X-Triage-Token": TOKEN } });
        if (!res.ok) throw new Error(String(res.status));
        window.open(URL.createObjectURL(await res.blob()), "_blank", "noopener");
      } catch (e) { toast("Report failed: " + e.message, true); }
    });
    dashboard.appendChild(reportBtn);
  }
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
  if (f.ai_priority && f.ai_priority.recommended_priority) top.appendChild(el("span", { class: "badge", text: "AI " + f.ai_priority.recommended_priority }));
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
  if (f.ai_summary) {
    card.appendChild(el("p", { text: f.ai_summary.description || "" }));
    card.appendChild(el("div", { class: "muted", text: "Business impact: " + (f.ai_summary.business_impact || "") }));
  }

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
  if (!currentProject) { toast("Select a project first.", true); return; }
  const scanners = Array.from(document.querySelectorAll('#scannerChecks input:checked')).map(n => n.value);
  if (!scanners.length) { toast("Select at least one scanner.", true); return; }
  if (!document.getElementById("authorized").checked) { toast("Confirm scan authorization first.", true); return; }
  const btn = document.getElementById("runBtn");
  const logBox = document.getElementById("joblog");
  btn.disabled = true;
  logBox.style.display = "block";
  logBox.textContent = "Starting scan…\\n";
  let job;
  try {
    job = await api("/api/projects/" + encodeURIComponent(currentProject.project_id) + "/scan", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scanners, ai_analysis_limit: Number(document.getElementById("aiLimit").value), authorization_confirmed: true }) });
  } catch (e) { toast("Could not start: " + e.message, true); btn.disabled = false; return; }
  currentJob = job.job_id;
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    let info;
    try { info = await api("/api/jobs/" + encodeURIComponent(job.job_id)); }
    catch (e) { return; }
    logBox.textContent = info.log.join("\\n");
    logBox.scrollTop = logBox.scrollHeight;
    if (info.phase === "awaiting_context_review" && info.context_draft && !document.getElementById("contextModal").classList.contains("show")) showContextReview(info.context_draft);
    if (info.status !== "running") {
      clearInterval(pollTimer); pollTimer = null; btn.disabled = false;
      toast("Scan " + info.status + (info.returncode != null ? " (exit " + info.returncode + ")" : ""), info.status !== "success");
      document.getElementById("contextModal").classList.remove("show");
      await loadProjects();
      if (info.artifact) selectScan(info.artifact.slug, info.artifact.ts, null);
    }
  }, 1500);
}

function boolValue(id) { const v = document.getElementById(id).value; return v === "unknown" ? null : v === "true"; }
function showContextReview(draft) {
  const analysis = draft.analysis || {}; const risk = analysis.risk_context || {};
  document.getElementById("contextDescription").value = analysis.site_description || "";
  document.getElementById("contextProcesses").value = (analysis.business_processes || []).join("\\n");
  document.getElementById("contextCriticality").value = risk.asset_criticality || "unknown";
  document.getElementById("contextEnvironment").value = risk.environment || "unknown";
  document.getElementById("contextSensitive").value = risk.sensitive_data == null ? "unknown" : String(risk.sensitive_data);
  document.getElementById("contextAuth").value = risk.requires_auth == null ? "unknown" : String(risk.requires_auth);
  document.getElementById("contextReason").value = risk.reason || "Needs human review.";
  document.getElementById("contextSources").textContent = (draft.pages || []).length + " pages · analysis source: " + (analysis.analysis_source || "fallback") + " · review before scoring";
  const sourceList = document.getElementById("contextSourceList"); sourceList.textContent = "";
  [].concat(draft.pages || [], draft.osint || []).forEach(source => {
    sourceList.appendChild(el("div", { text: (source.id || "source") + " · " + (source.url || source.resource || source.kind || "local evidence") }));
  });
  document.getElementById("contextModal").classList.add("show");
}

async function submitContext(action) {
  const body = { action };
  if (action === "accept") {
    try {
      const info = await api("/api/jobs/" + encodeURIComponent(currentJob));
      const draft = info.context_draft || {}; const proposed = (draft.analysis || {}).risk_context || {};
      const available = [].concat(draft.pages || [], draft.osint || []).map(item => item.id).filter(Boolean);
      const cited = (proposed.evidence_ids || []).filter(id => available.includes(id));
      body.description = document.getElementById("contextDescription").value;
      body.business_processes = document.getElementById("contextProcesses").value.split("\\n").map(s => s.trim()).filter(Boolean);
      body.risk_context = {
        asset_criticality: document.getElementById("contextCriticality").value,
        environment: document.getElementById("contextEnvironment").value,
        sensitive_data: boolValue("contextSensitive"), requires_auth: boolValue("contextAuth"),
        confidence: available.length ? Number(proposed.confidence || 0.5) : 0,
        reason: document.getElementById("contextReason").value,
        evidence_ids: cited.length ? cited : available.slice(0, 1),
      };
    } catch (e) { toast("Context review failed: " + e.message, true); return; }
  }
  try { await api("/api/jobs/" + encodeURIComponent(currentJob) + "/context", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) }); document.getElementById("contextModal").classList.remove("show"); }
  catch (e) { toast("Context review failed: " + e.message, true); }
}

async function createProject() {
  try {
    const project = await api("/api/projects", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({
      name:document.getElementById("projectName").value, target:document.getElementById("projectTarget").value,
      default_scanners:["nmap","nuclei"], ai_analysis_limit:Number(document.getElementById("projectLimit").value),
      authorization_confirmed:document.getElementById("projectAuthorized").checked }) });
    document.getElementById("projectModal").classList.remove("show"); await loadProjects(); selectProject(project); toast("Project created.");
  } catch (e) { toast("Could not create project: " + e.message, true); }
}

document.getElementById("runBtn").addEventListener("click", runScan);
document.getElementById("refreshBtn").addEventListener("click", loadProjects);
document.getElementById("projectSelect").addEventListener("change", e => { const p = projects.find(x => x.project_id === e.target.value); if (p) selectProject(p); });
document.getElementById("newProjectBtn").addEventListener("click", () => document.getElementById("projectModal").classList.add("show"));
document.getElementById("closeProjectBtn").addEventListener("click", () => document.getElementById("projectModal").classList.remove("show"));
document.getElementById("createProjectBtn").addEventListener("click", createProject);
document.getElementById("safePreset").addEventListener("click", () => initScanners(["nmap","nuclei"]));
document.getElementById("fullPreset").addEventListener("click", () => initScanners(["nmap","nuclei","wapiti","nikto","zap"]));
document.getElementById("acceptContextBtn").addEventListener("click", () => submitContext("accept"));
document.getElementById("skipContextBtn").addEventListener("click", () => submitContext("skip"));
document.getElementById("cancelJobBtn").addEventListener("click", () => submitContext("cancel"));
loadProjects();
</script>
</body>
</html>
"""
