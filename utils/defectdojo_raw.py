"""
Helpers for DefectDojo raw per-scanner upload planning.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


DEFECTDOJO_UPLOAD_MODE_MERGED = "merged"
DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN = "raw-per-scan"
DEFAULT_DEFECTDOJO_UPLOAD_MODE = DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN
SUPPORTED_DEFECTDOJO_UPLOAD_MODES = {
    DEFECTDOJO_UPLOAD_MODE_MERGED,
    DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN,
}


DEFAULT_RAW_SCAN_TYPES = {
    "nmap": "Nmap Scan",
    "nuclei": "Nuclei Scan",
    "wapiti": "Wapiti Scan",
    "nikto": "Nikto Scan",
    "zap": "ZAP Scan",
}


def normalize_defectdojo_upload_mode(value: Any) -> str:
    """Return a supported DefectDojo upload mode."""
    mode = str(value or DEFAULT_DEFECTDOJO_UPLOAD_MODE).strip().lower()
    if mode not in SUPPORTED_DEFECTDOJO_UPLOAD_MODES:
        supported = ", ".join(sorted(SUPPORTED_DEFECTDOJO_UPLOAD_MODES))
        raise ValueError(f"DefectDojo upload mode must be one of: {supported}")
    return mode


def resolve_raw_scan_type(scanner_name: str, overrides: dict[str, str | None] | None = None) -> str | None:
    """Return the DefectDojo parser name for one scanner, honoring overrides."""
    scanner_key = str(scanner_name or "").strip().lower()
    if not scanner_key:
        return None

    overrides = overrides or {}
    override = overrides.get(scanner_key)
    if isinstance(override, str):
        override = override.strip()
        if override:
            return override

    return DEFAULT_RAW_SCAN_TYPES.get(scanner_key)


def build_raw_test_title(scanner_name: str, target: str) -> str:
    """Return a stable DefectDojo test title for one scanner execution."""
    scanner = str(scanner_name or "scanner").strip() or "scanner"
    target_text = str(target or "unknown target").strip() or "unknown target"
    return f"{scanner} | {target_text}"


def artifact_format_from_path(path: Any) -> str | None:
    """Infer a compact artifact format label from one path."""
    suffix = Path(str(path or "")).suffix.lower().lstrip(".")
    return suffix or None


def _manifest_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    artifact_path = artifact.get("path") or artifact.get("raw_artifact_path")
    normalized = dict(artifact)
    if artifact_path:
        normalized["path"] = str(artifact_path)
        normalized["raw_artifact_path"] = str(artifact_path)
    normalized["artifact_format"] = artifact.get("artifact_format") or artifact_format_from_path(artifact_path)
    normalized["native"] = bool(artifact.get("native"))
    return normalized


def _append_unique_manifest_artifact(artifacts: list[dict[str, Any]], artifact: dict[str, Any]) -> None:
    artifact_path = str(artifact.get("path") or artifact.get("raw_artifact_path") or "")
    for existing in artifacts:
        existing_path = str(existing.get("path") or existing.get("raw_artifact_path") or "")
        if artifact_path and existing_path == artifact_path:
            existing.update(artifact)
            return
    artifacts.append(artifact)


def build_raw_upload_manifest_entry(
    *,
    scanner_name: str,
    execution_key: str,
    target: str,
    artifact: dict[str, Any] | None,
    scan_type: str | None,
    raw_artifacts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one aggregate manifest entry for raw DefectDojo upload mode."""
    title_target = str(target or "").strip() or "unknown target"
    entry: dict[str, Any] = {
        "scanner": scanner_name,
        "execution_key": execution_key,
        "target": title_target,
        "raw_artifact_path": None,
        "artifact_format": None,
        "scan_type": scan_type,
        "native": False,
        "safe_importable": False,
        "test_title": build_raw_test_title(scanner_name, title_target),
        "skip_reason": None,
        "raw_artifacts": [],
    }

    if not scan_type:
        entry["skip_reason"] = "no configured native parser mapping"

    if raw_artifacts:
        for candidate in raw_artifacts:
            if isinstance(candidate, dict):
                _append_unique_manifest_artifact(entry["raw_artifacts"], _manifest_artifact(candidate))

    if not artifact:
        entry["skip_reason"] = entry["skip_reason"] or "no scanner-native raw artifact was produced"
        return entry

    normalized_artifact = _manifest_artifact(artifact)
    _append_unique_manifest_artifact(entry["raw_artifacts"], normalized_artifact)

    artifact_path = normalized_artifact.get("path")
    entry.update(
        {
            "raw_artifact_path": str(artifact_path) if artifact_path else None,
            "artifact_format": normalized_artifact.get("artifact_format"),
            "native": bool(normalized_artifact.get("native")),
            "role": normalized_artifact.get("role"),
            "artifact_role": normalized_artifact.get("role"),
            "source": normalized_artifact.get("source"),
            "artifact_source": normalized_artifact.get("source"),
        }
    )

    if not entry["raw_artifact_path"]:
        entry["skip_reason"] = entry["skip_reason"] or "scanner-native raw artifact path is missing"
    elif not entry["native"]:
        entry["skip_reason"] = entry["skip_reason"] or "raw artifact is not scanner-native parser input"
    elif scan_type:
        entry["safe_importable"] = True

    return entry
