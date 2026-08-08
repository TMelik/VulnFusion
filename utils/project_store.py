"""Per-site project records stored inside the runtime OKF knowledge bundle."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from utils.run_folder import create_target_slug, parse_timestamp
from utils.site_context import (
    _atomic_write,
    _markdown_text,
    _parse_frontmatter,
    _yaml_frontmatter,
    normalize_site_url,
    site_bundle_key,
)


PROJECT_SCHEMA_VERSION = 1
PROJECT_FILENAME = "project.md"
SCANNER_NAMES = ("nmap", "nuclei", "wapiti", "nikto", "zap")
DEFAULT_SCANNERS = ("nmap", "nuclei")
DEFAULT_AI_ANALYSIS_LIMIT = 25


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _clean_name(value: Any) -> str:
    name = " ".join(str(value or "").split())
    if not name or len(name) > 120:
        raise ValueError("project name must contain 1 to 120 characters")
    return name


def _clean_reviewer(value: Any) -> str:
    reviewer = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(value or "local-user")).strip("-")
    return (reviewer or "local-user")[:100]


def _clean_scanners(values: Iterable[Any]) -> List[str]:
    scanners: List[str] = []
    for value in values:
        scanner = str(value or "").strip().lower()
        if scanner not in SCANNER_NAMES:
            raise ValueError(f"unknown scanner: {scanner or value!r}")
        if scanner not in scanners:
            scanners.append(scanner)
    if not scanners:
        raise ValueError("at least one scanner must be selected")
    return scanners


def _clean_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100:
        raise ValueError("ai_analysis_limit must be an integer between 1 and 100")
    return value


def project_bundle_dir(data_dir: str | Path, target: str) -> Path:
    return Path(data_dir) / "asset_knowledge" / site_bundle_key(target)


def refresh_bundle_index(bundle_dir: Path, *, target: str, title: str) -> Path:
    """Regenerate the bounded OKF index while retaining current-profile context."""
    entries: List[str] = []
    if (bundle_dir / PROJECT_FILENAME).is_file():
        entries.append(f"- [Project settings]({PROJECT_FILENAME})")

    profile_path = bundle_dir / "profile.md"
    current_revision = ""
    if profile_path.is_file():
        preview = ""
        try:
            metadata, _ = _parse_frontmatter(profile_path.read_text(encoding="utf-8"))
            preview = _markdown_text(metadata.get("description"))
            revision_value = str(metadata.get("profile_revision") or "")
            if re.fullmatch(r"[0-9a-f]{64}", revision_value):
                current_revision = revision_value
        except (OSError, ValueError):
            pass
        suffix = f" — {preview}" if preview else ""
        entries.append(f"- [Current site profile](profile.md){suffix}")
        revision_path = bundle_dir / "revisions" / f"{current_revision}.md"
        if current_revision and revision_path.is_file():
            entries.append(
                f"- [Immutable revision `{current_revision[:12]}`](revisions/{current_revision}.md)"
            )

    if (bundle_dir / "annotations.md").is_file():
        entries.append("- [Human finding triage](annotations.md)")
    if (bundle_dir / "log.md").is_file():
        entries.append("- [Update log](log.md)")
    revisions = bundle_dir / "revisions"
    if not current_revision and revisions.is_dir() and any(revisions.glob("*.md")):
        entries.append("- [Immutable context revisions](revisions/)")
    metadata = {"okf_version": "0.2", "type": "Index", "title": title, "resource": target}
    text = _yaml_frontmatter(metadata) + f"\n# {_markdown_text(title)}\n\n" + "\n".join(entries or ["- No concepts recorded yet."]) + "\n"
    path = bundle_dir / "index.md"
    _atomic_write(path, text)
    return path


def save_project(
    data_dir: str | Path,
    *,
    name: str,
    target: str,
    default_scanners: Iterable[str] = DEFAULT_SCANNERS,
    ai_analysis_limit: int = DEFAULT_AI_ANALYSIS_LIMIT,
    reviewer: str = "local-user",
    authorization_confirmed: bool,
    now: Optional[str] = None,
) -> Dict[str, Any]:
    """Create or update one project, requiring an explicit authorization assertion."""
    if authorization_confirmed is not True:
        raise ValueError("explicit scan authorization confirmation is required")
    canonical_target = normalize_site_url(target)
    project_id = site_bundle_key(canonical_target)
    bundle_dir = project_bundle_dir(data_dir, canonical_target)
    project_path = bundle_dir / PROJECT_FILENAME
    existing = load_project_path(project_path) if project_path.is_file() else None
    timestamp = now or _now_iso()
    reviewer_id = _clean_reviewer(reviewer)
    record = {
        "project_schema_version": PROJECT_SCHEMA_VERSION,
        "project_id": project_id,
        "name": _clean_name(name),
        "target": canonical_target,
        "default_scanners": _clean_scanners(default_scanners),
        "ai_analysis_limit": _clean_limit(ai_analysis_limit),
        "created_at": (existing or {}).get("created_at") or timestamp,
        "updated_at": timestamp,
        "authorization": {"confirmed": True, "by": reviewer_id, "at": timestamp},
    }
    frontmatter = {
        "type": "Project",
        "title": record["name"],
        "description": f"Vulnerability scanning project for {canonical_target}",
        "resource": canonical_target,
        "project_schema_version": PROJECT_SCHEMA_VERSION,
        "project_id": project_id,
        "default_scanners": record["default_scanners"],
        "ai_analysis_limit": record["ai_analysis_limit"],
        "status": "stable",
        "generated": {"by": "vulnfusion-ui/1", "at": record["created_at"]},
        "verified": {"by": f"human:{reviewer_id}", "at": timestamp},
        "authorization": record["authorization"],
        "updated_at": timestamp,
    }
    body = (
        f"# Project\n\n{record['name']}\n\n"
        f"- Target: `{canonical_target}`\n"
        f"- Default scanners: {', '.join(record['default_scanners'])}\n"
        f"- Advisory AI limit: {record['ai_analysis_limit']}\n"
    )
    _atomic_write(project_path, _yaml_frontmatter(frontmatter) + "\n" + body)
    refresh_bundle_index(bundle_dir, target=canonical_target, title=record["name"])
    return record


def load_project_path(path: Path) -> Dict[str, Any]:
    if path.stat().st_size > 256 * 1024:
        raise ValueError("project.md exceeds the safe size limit")
    metadata, _ = _parse_frontmatter(path.read_text(encoding="utf-8"))
    target = normalize_site_url(str(metadata.get("resource") or ""))
    project_id = site_bundle_key(target)
    if metadata.get("project_id") not in (None, project_id):
        raise ValueError("project id does not match its target")
    generated = metadata.get("generated") if isinstance(metadata.get("generated"), Mapping) else {}
    authorization = metadata.get("authorization") if isinstance(metadata.get("authorization"), Mapping) else {}
    return {
        "project_schema_version": int(metadata.get("project_schema_version") or PROJECT_SCHEMA_VERSION),
        "project_id": project_id,
        "name": _clean_name(metadata.get("title")),
        "target": target,
        "default_scanners": _clean_scanners(metadata.get("default_scanners") or DEFAULT_SCANNERS),
        "ai_analysis_limit": _clean_limit(metadata.get("ai_analysis_limit") or DEFAULT_AI_ANALYSIS_LIMIT),
        "created_at": str(generated.get("at") or metadata.get("updated_at") or ""),
        "updated_at": str(metadata.get("updated_at") or generated.get("at") or ""),
        "authorization": dict(authorization),
    }


def load_project(data_dir: str | Path, project_id: str) -> Dict[str, Any]:
    if not re.fullmatch(r"[a-z0-9-]+--[0-9a-f]{12}", str(project_id or "")):
        raise ValueError("invalid project id")
    path = Path(data_dir) / "asset_knowledge" / project_id / PROJECT_FILENAME
    if not path.is_file():
        raise ValueError("project not found")
    project = load_project_path(path)
    if project["project_id"] != project_id:
        raise ValueError("project target does not match its bundle directory")
    return project


def project_runs(data_dir: str | Path, target: str) -> List[Dict[str, Any]]:
    target_dir = Path(data_dir) / create_target_slug(target)
    runs: List[Dict[str, Any]] = []
    if not target_dir.is_dir():
        return runs
    for run_dir in target_dir.iterdir():
        if not run_dir.is_dir() or parse_timestamp(run_dir.name) is None:
            continue
        artifact = next((name for name in ("normalized.json", "scan_results.json") if (run_dir / name).is_file()), None)
        if artifact:
            runs.append({"ts": run_dir.name, "artifact": artifact, "report_available": (run_dir / "report.html").is_file()})
    return sorted(runs, key=lambda item: item["ts"], reverse=True)


def list_projects(data_dir: str | Path) -> List[Dict[str, Any]]:
    root = Path(data_dir) / "asset_knowledge"
    projects: List[Dict[str, Any]] = []
    if root.is_dir():
        for bundle_dir in root.iterdir():
            path = bundle_dir / PROJECT_FILENAME
            if not path.is_file():
                continue
            try:
                project = load_project_path(path)
            except (OSError, ValueError):
                continue
            project["runs"] = project_runs(data_dir, project["target"])
            project["slug"] = create_target_slug(project["target"])
            project["has_context"] = (bundle_dir / "profile.md").is_file()
            projects.append(project)
    return sorted(projects, key=lambda item: (item.get("updated_at") or "", item["name"]), reverse=True)
