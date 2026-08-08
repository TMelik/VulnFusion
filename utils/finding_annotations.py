"""Human triage annotations persisted into the per-site OKF knowledge bundle.

This is the shared core used by BOTH the scan pipeline (``main.py``) and the
triage web UI (``utils/triage_ui.py``). A human marks a finding as
``false_positive`` / ``not_applicable`` / ``confirmed`` / ``needs_review`` and
optionally leaves a comment; the decision is stored per-site and re-attached to
matching findings on every future scan so the noise does not come back.

Design constraints (see plan):

* Storage lives beside the discovery bundle at
  ``data/asset_knowledge/<site-key>/annotations.md`` but is a **self-contained**
  OKF-flavored artifact. It never creates or edits the discovery bundle's
  ``index.md`` / ``profile.md`` / ``log.md`` (that would clobber the pre-scan
  context flow and race its log).
* Re-attach identity uses ``normalizer.create_fingerprints`` — deterministic and
  computed only from fields that survive export, so a key derived on the
  exported ``scan_results.json`` (UI) equals the key derived pre-sanitize (CLI).
* ``apply_annotations`` is strictly read-only, so a running scan never contends
  with an interactive writer.
"""

from __future__ import annotations

import re
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Mapping, Optional, Tuple, Union
from urllib.parse import urlsplit

try:  # POSIX advisory locking; best-effort cross-process guard.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

from utils.schema import HUMAN_TRIAGE_SCOPES, HUMAN_TRIAGE_STATUSES
from utils.normalizer import create_fingerprints
from utils.secret_sanitizer import sanitize_secrets
# These OKF I/O helpers are shared, package-internal utilities. Reused rather
# than duplicated so the annotation file reads as a sibling of the discovery
# bundle and uses the exact same atomic-write / frontmatter conventions.
from utils.site_context import (
    _atomic_write,
    _iso_utc,
    _parse_frontmatter,
    _utc_now,
    _yaml_frontmatter,
    normalize_site_url,
    site_bundle_key,
)

__all__ = [
    "HUMAN_TRIAGE_STATUSES",
    "HUMAN_TRIAGE_SCOPES",
    "ANNOTATIONS_SCHEMA_VERSION",
    "annotation_key",
    "record_annotation",
    "load_annotations",
    "apply_annotations",
]

ANNOTATIONS_SCHEMA_VERSION = 1
ANNOTATIONS_FILENAME = "annotations.md"
_TRIAGE_LOG_HEADER = "# Finding Triage Log"

_MAX_ANNOTATIONS_BYTES = 2 * 1024 * 1024
_MAX_COMMENT_CHARS = 2000
_MAX_REVIEWER_CHARS = 100
_MAX_KEY_CHARS = 512


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------

def _reattachable(fingerprints: Mapping[str, str]) -> bool:
    """Return True when a finding carries a host anchor.

    ``fp_host_only`` is ``norm_name::host``; without a host it collapses to a
    bare ``norm_name`` (no ``::``), which would blanket-match unrelated
    findings. Such findings get a stricter key and cannot use site scope.
    """
    return "::" in (fingerprints.get("fp_host_only") or "")


def _finding_scope_key(fingerprints: Mapping[str, str]) -> str:
    if _reattachable(fingerprints):
        return fingerprints.get("fp_general") or ""
    # No stable host anchor: fall back to the most specific key so a weak
    # annotation only re-attaches to a structurally identical finding.
    return fingerprints.get("fp_strict") or ""


def _site_scope_key(fingerprints: Mapping[str, str]) -> Optional[str]:
    if _reattachable(fingerprints):
        return fingerprints.get("fp_host_only") or ""
    return None


def _scope_key(fingerprints: Mapping[str, str], scope: str) -> Optional[str]:
    if scope == "site_vuln":
        return _site_scope_key(fingerprints)
    return _finding_scope_key(fingerprints)


def annotation_key(finding: Mapping[str, Any], scope: str = "finding") -> str:
    """Return the stable re-attach key for ``finding`` at ``scope``.

    Returns ``""`` when the scope cannot be represented (e.g. ``site_vuln`` on a
    finding with no host anchor). Pure function of export-surviving fields.
    """
    if scope not in HUMAN_TRIAGE_SCOPES:
        raise ValueError(f"Unknown triage scope: {scope!r}")
    fingerprints = create_fingerprints(dict(finding) if isinstance(finding, Mapping) else {})
    return _scope_key(fingerprints, scope) or ""


# ---------------------------------------------------------------------------
# Small text helpers
# ---------------------------------------------------------------------------

def _sanitize_reviewer(reviewer: Any) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(reviewer or "local-user")).strip("-")
    return (cleaned or "local-user")[:_MAX_REVIEWER_CHARS]


def _clean_comment(comment: Any) -> str:
    text = str(comment or "")
    if not text.strip():
        return ""
    # Scrub secrets first (the bundle may be committed to git), then collapse
    # whitespace to a single line and bound the length.
    scrubbed = sanitize_secrets(text).value
    return " ".join(str(scrubbed).split())[:_MAX_COMMENT_CHARS]


def _target_host(target: str) -> str:
    try:
        return str(urlsplit(normalize_site_url(target)).hostname or "")
    except Exception:  # pragma: no cover - defensive
        return ""


# ---------------------------------------------------------------------------
# Bundle locking
# ---------------------------------------------------------------------------

_LOCKS_GUARD = threading.Lock()
_LOCKS: Dict[str, threading.Lock] = {}


def _bundle_threadlock(bundle_dir: Path) -> threading.Lock:
    key = str(bundle_dir)
    with _LOCKS_GUARD:
        lock = _LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[key] = lock
        return lock


@contextmanager
def _bundle_lock(bundle_dir: Path) -> Generator[None, None, None]:
    """Serialize read-modify-write on one bundle (in-process + cross-process)."""
    thread_lock = _bundle_threadlock(bundle_dir)
    thread_lock.acquire()
    flock_handle = None
    try:
        if fcntl is not None:
            bundle_dir.mkdir(parents=True, exist_ok=True)
            flock_handle = open(bundle_dir / ".annotations.lock", "w", encoding="utf-8")
            fcntl.flock(flock_handle.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if flock_handle is not None and fcntl is not None:
            try:
                fcntl.flock(flock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                flock_handle.close()
        thread_lock.release()


# ---------------------------------------------------------------------------
# File I/O
# ---------------------------------------------------------------------------

def _bundle_dir(data_dir: Union[str, Path], target: str) -> Path:
    return Path(data_dir) / "asset_knowledge" / site_bundle_key(target)


def _read_annotations_file(bundle_dir: Path) -> Tuple[List[Dict[str, Any]], str]:
    """Return ``(entries, body)`` for an existing annotations file.

    ``([], "")`` when the file is absent. Raises ``ValueError`` on an oversized
    or malformed file (callers that must not crash a scan catch it).
    """
    path = bundle_dir / ANNOTATIONS_FILENAME
    if not path.exists():
        return [], ""
    if path.stat().st_size > _MAX_ANNOTATIONS_BYTES:
        raise ValueError("annotations.md exceeds the safe size limit")
    metadata, body = _parse_frontmatter(path.read_text(encoding="utf-8"))
    raw = metadata.get("annotations")
    entries = [dict(item) for item in raw if isinstance(item, Mapping)] if isinstance(raw, list) else []
    return entries, body


def _format_log_line(entry: Mapping[str, Any]) -> str:
    comment = entry.get("comment") or ""
    suffix = f' — "{comment}"' if comment else ""
    return (
        f"- {entry.get('updated_at') or entry.get('decided_at')} "
        f"**{entry.get('status')}** by `human:{entry.get('reviewer')}` "
        f"on `{entry.get('scope')}::{entry.get('key')}`{suffix}"
    )


def _render_annotations_md(
    *,
    target: str,
    bundle_key: str,
    target_host: str,
    reviewer_id: str,
    timestamp: str,
    entries: List[Dict[str, Any]],
    existing_body: str,
    latest_entry: Mapping[str, Any],
) -> str:
    frontmatter = {
        "okf_version": "0.2",
        "type": "Finding Triage",
        "title": target_host or target,
        "resource": target,
        "subject": {"id": bundle_key, "kind": "website", "normalized_host": target_host},
        "annotations_schema_version": ANNOTATIONS_SCHEMA_VERSION,
        "generated": {"by": "vulnfusion-triage/1", "at": timestamp},
        # Provenance of the most recent human edit; mirrors the discovery
        # bundle's ``verified: human:<reviewer>`` convention.
        "verified": {"by": f"human:{reviewer_id}", "at": timestamp},
        "annotations": entries,
    }
    body = existing_body.strip()
    if not body:
        body = _TRIAGE_LOG_HEADER
    body = f"{body}\n{_format_log_line(latest_entry)}\n"
    return _yaml_frontmatter(frontmatter) + "\n" + body


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def record_annotation(
    data_dir: Union[str, Path],
    target: str,
    finding_or_key: Union[Mapping[str, Any], str],
    *,
    status: str,
    comment: str = "",
    reviewer: str = "local-user",
    scope: str = "finding",
    now: Callable[[], datetime] = _utc_now,
) -> Dict[str, Any]:
    """Upsert one human triage decision for ``target`` into its OKF bundle.

    ``finding_or_key`` is normally the finding dict (server derives the key so a
    client can never forge it); a pre-computed ``scope::``-less key string is
    also accepted for the headless CLI path. Returns the stored entry.
    """
    if status not in HUMAN_TRIAGE_STATUSES:
        raise ValueError(f"Unknown triage status: {status!r}")
    if scope not in HUMAN_TRIAGE_SCOPES:
        raise ValueError(f"Unknown triage scope: {scope!r}")

    vulnerability_name = ""
    host = ""
    if isinstance(finding_or_key, Mapping):
        fingerprints = create_fingerprints(dict(finding_or_key))
        reattachable = _reattachable(fingerprints)
        if scope == "site_vuln" and not reattachable:
            raise ValueError("site_vuln scope requires a finding with a host anchor")
        key = _scope_key(fingerprints, scope) or ""
        vulnerability_name = str(finding_or_key.get("vulnerability_name") or "")
        meta = finding_or_key.get("meta")
        host = str((meta or {}).get("host") or "") if isinstance(meta, Mapping) else ""
    else:
        key = str(finding_or_key or "")
        reattachable = "::" in key
        if scope == "site_vuln" and not reattachable:
            raise ValueError("site_vuln scope requires a host-anchored key")

    if not key:
        raise ValueError("Could not derive a stable annotation key for this finding")
    key = key[:_MAX_KEY_CHARS]

    reviewer_id = _sanitize_reviewer(reviewer)
    comment_clean = _clean_comment(comment)
    timestamp = _iso_utc(now())
    map_key = f"{scope}::{key}"

    bundle_dir = _bundle_dir(data_dir, target)
    with _bundle_lock(bundle_dir):
        entries, existing_body = _read_annotations_file(bundle_dir)
        index = {f"{item.get('scope')}::{item.get('key')}": pos for pos, item in enumerate(entries)}
        if map_key in index:
            entry = entries[index[map_key]]
            entry["status"] = status
            entry["comment"] = comment_clean
            entry["reviewer"] = reviewer_id
            entry["updated_at"] = timestamp
            entry["revision"] = int(entry.get("revision") or 1) + 1
            entry["reattachable"] = reattachable
            if vulnerability_name:
                entry["vulnerability_name"] = vulnerability_name
            if host:
                entry["host"] = host
        else:
            entry = {
                "scope": scope,
                "key": key,
                "status": status,
                "vulnerability_name": vulnerability_name,
                "host": host,
                "comment": comment_clean,
                "reviewer": reviewer_id,
                "decided_at": timestamp,
                "updated_at": timestamp,
                "revision": 1,
                "reattachable": reattachable,
            }
            entries.append(entry)

        text = _render_annotations_md(
            target=normalize_site_url(target),
            bundle_key=bundle_dir.name,
            target_host=_target_host(target),
            reviewer_id=reviewer_id,
            timestamp=timestamp,
            entries=entries,
            existing_body=existing_body,
            latest_entry=entry,
        )
        _atomic_write(bundle_dir / ANNOTATIONS_FILENAME, text)
    return dict(entry)


def load_annotations(data_dir: Union[str, Path], target: str) -> Dict[str, Dict[str, Any]]:
    """Return stored decisions keyed by ``"<scope>::<key>"`` (``{}`` if none).

    Defensive: a missing, oversized, or malformed file yields ``{}`` so a scan
    never fails because of the annotation store.
    """
    bundle_dir = _bundle_dir(data_dir, target)
    try:
        entries, _ = _read_annotations_file(bundle_dir)
    except (OSError, ValueError):
        return {}
    result: Dict[str, Dict[str, Any]] = {}
    for entry in entries:
        scope = entry.get("scope")
        key = entry.get("key")
        status = entry.get("status")
        if scope in HUMAN_TRIAGE_SCOPES and status in HUMAN_TRIAGE_STATUSES and isinstance(key, str) and key:
            result[f"{scope}::{key}"] = entry
    return result


def _stamp_from_entry(entry: Mapping[str, Any]) -> Dict[str, Any]:
    """Project a stored entry to the public ``human_triage`` finding shape."""
    stamped: Dict[str, Any] = {
        "status": entry.get("status"),
        "scope": entry.get("scope"),
        "key": str(entry.get("key") or "")[:_MAX_KEY_CHARS],
        "reviewer": str(entry.get("reviewer") or "local-user")[:_MAX_REVIEWER_CHARS],
        "decided_at": entry.get("decided_at") or entry.get("updated_at"),
    }
    comment = entry.get("comment")
    if comment:
        stamped["comment"] = str(comment)[:_MAX_COMMENT_CHARS]
    if entry.get("updated_at"):
        stamped["updated_at"] = entry.get("updated_at")
    revision = entry.get("revision")
    if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1:
        stamped["revision"] = revision
    return stamped


def apply_annotations(results: Dict[str, Any], *, data_dir: Union[str, Path]) -> Dict[str, Any]:
    """Stamp ``human_triage`` onto findings that match a stored decision.

    Read-only with respect to the store. Matches finding scope first, then site
    scope. Never raises: any failure leaves ``results`` unchanged.
    """
    if not isinstance(results, dict):
        return results
    target = results.get("target")
    if not target:
        return results
    try:
        annotations = load_annotations(data_dir, target)
    except Exception:  # pragma: no cover - defensive
        return results
    if not annotations:
        return results

    for list_key in ("all_findings", "changed_findings", "fixed_findings"):
        findings = results.get(list_key)
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            try:
                fingerprints = create_fingerprints(finding)
            except Exception:  # pragma: no cover - defensive
                continue
            entry = None
            finding_key = _finding_scope_key(fingerprints)
            if finding_key:
                entry = annotations.get(f"finding::{finding_key}")
            if entry is None:
                site_key = _site_scope_key(fingerprints)
                if site_key:
                    entry = annotations.get(f"site_vuln::{site_key}")
            if entry is None:
                continue
            finding["human_triage"] = _stamp_from_entry(entry)
    return results
