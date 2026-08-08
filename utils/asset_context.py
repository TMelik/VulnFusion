"""
Asset Context Loader and Applicator

Loads deterministic local asset/business context rules from JSON or YAML and
applies them to findings before risk scoring.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import yaml

from utils.normalizer import canonical_path, parse_target

BUSINESS_CONTEXT_FIELDS = (
    "asset_criticality",
    "internet_exposed",
    "environment",
    "sensitive_data",
    "requires_auth",
)
_BOOLEAN_CONTEXT_FIELDS = {"internet_exposed", "sensitive_data", "requires_auth"}
_STRING_CONTEXT_FIELDS = {"asset_criticality", "environment"}
_MATCH_FIELDS = ("asset_id", "host", "host_suffix", "path_prefix")
_OPTIONAL_RULE_FIELDS = {"id", "name"}


def _is_present(value: Any) -> bool:
    """Treat False as present while ignoring empty strings and None."""
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def _normalize_host(value: str) -> str:
    """Normalize a host rule for deterministic matching."""
    return value.strip().lower()


def _normalize_host_suffix(value: str) -> str:
    """Normalize a suffix rule while accepting an optional leading dot."""
    return value.strip().lower().lstrip(".")


def _normalize_path_prefix(value: str) -> str:
    """Normalize a path prefix and accept values without a leading slash."""
    stripped = value.strip()
    if not stripped:
        return ""
    if not stripped.startswith("/"):
        stripped = f"/{stripped}"
    return canonical_path(stripped)


def _load_raw_asset_context(path: Path) -> Any:
    """Load JSON or YAML text from disk."""
    text = path.read_text(encoding="utf-8")
    suffix = path.suffix.lower()
    try:
        if suffix == ".json":
            return json.loads(text)
        if suffix in {".yaml", ".yml"}:
            return yaml.safe_load(text)
        # YAML is a superset of JSON; use it as the generic fallback.
        return yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid asset-context file {path}: {exc}") from exc


def _normalize_context_value(key: str, value: Any, index: int) -> Any:
    """Validate a business-context value and return it unchanged when valid."""
    if key in _BOOLEAN_CONTEXT_FIELDS:
        if not isinstance(value, bool):
            raise ValueError(
                f"Asset-context rule #{index} field '{key}' must be a boolean, "
                f"got {type(value).__name__}"
            )
        return value

    if key in _STRING_CONTEXT_FIELDS:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(
                f"Asset-context rule #{index} field '{key}' must be a non-empty string"
            )
        return value.strip()

    raise ValueError(f"Unsupported asset-context field '{key}'")


def _compile_rule(rule: Dict[str, Any], index: int) -> Dict[str, Any]:
    """Validate and normalize one asset-context rule."""
    if not isinstance(rule, dict):
        raise ValueError(f"Asset-context rule #{index} must be an object")

    unknown_fields = set(rule) - set(_MATCH_FIELDS) - set(BUSINESS_CONTEXT_FIELDS) - _OPTIONAL_RULE_FIELDS
    if unknown_fields:
        unknown = ", ".join(sorted(unknown_fields))
        raise ValueError(f"Asset-context rule #{index} has unsupported field(s): {unknown}")

    if not any(_is_present(rule.get(field)) for field in ("asset_id", "host", "host_suffix")):
        raise ValueError(
            f"Asset-context rule #{index} must define at least one of: asset_id, host, host_suffix"
        )

    context: Dict[str, Any] = {}
    for field in BUSINESS_CONTEXT_FIELDS:
        if field in rule:
            context[field] = _normalize_context_value(field, rule[field], index)
    if not context:
        raise ValueError(
            f"Asset-context rule #{index} must define at least one business context field"
        )

    compiled: Dict[str, Any] = {
        "index": index,
        "context": context,
        "specificity": 0,
    }

    if "asset_id" in rule:
        asset_id = rule["asset_id"]
        if not isinstance(asset_id, str) or not asset_id.strip():
            raise ValueError(f"Asset-context rule #{index} field 'asset_id' must be a non-empty string")
        compiled["asset_id"] = asset_id.strip()
        compiled["specificity"] += 100

    if "host" in rule:
        host = rule["host"]
        if not isinstance(host, str) or not host.strip():
            raise ValueError(f"Asset-context rule #{index} field 'host' must be a non-empty string")
        compiled["host"] = _normalize_host(host)
        compiled["specificity"] += 60

    if "host_suffix" in rule:
        host_suffix = rule["host_suffix"]
        if not isinstance(host_suffix, str) or not host_suffix.strip():
            raise ValueError(f"Asset-context rule #{index} field 'host_suffix' must be a non-empty string")
        compiled["host_suffix"] = _normalize_host_suffix(host_suffix)
        compiled["specificity"] += 30

    if "path_prefix" in rule:
        path_prefix = rule["path_prefix"]
        if not isinstance(path_prefix, str) or not path_prefix.strip():
            raise ValueError(f"Asset-context rule #{index} field 'path_prefix' must be a non-empty string")
        compiled["path_prefix"] = _normalize_path_prefix(path_prefix)
        compiled["specificity"] += 10

    return compiled


def load_asset_context_file(path: str | Path) -> List[Dict[str, Any]]:
    """
    Load and validate an asset-context inventory file.

    Supported input shapes:
      - {"rules": [ ... ]}
      - [ ... ]
    """
    path = Path(path).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"Asset-context file does not exist: {path}")

    raw = _load_raw_asset_context(path)
    if raw is None:
        raise ValueError(f"Asset-context file {path} is empty")

    if isinstance(raw, dict):
        if "rules" not in raw:
            raise ValueError(f"Asset-context file {path} must contain a top-level 'rules' list")
        rules = raw["rules"]
    elif isinstance(raw, list):
        rules = raw
    else:
        raise ValueError(f"Asset-context file {path} must contain a list of rules")

    if not isinstance(rules, list):
        raise ValueError(f"Asset-context file {path} field 'rules' must be a list")

    return [_compile_rule(rule, index + 1) for index, rule in enumerate(rules)]


def _extract_finding_target(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Extract deterministic host/path matching inputs from a finding."""
    asset_id = str(finding.get("asset_id", "") or "").strip()
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    parsed = parse_target(asset_id)
    host = str(meta.get("host") or parsed.get("host") or "").strip().lower()

    path_candidates: List[str] = []
    meta_paths = meta.get("paths")
    if isinstance(meta_paths, list):
        for item in meta_paths:
            if isinstance(item, str) and item.strip():
                normalized = _normalize_path_prefix(item)
                if normalized and normalized not in path_candidates:
                    path_candidates.append(normalized)

    for path_value in (meta.get("path"), parsed.get("path")):
        if isinstance(path_value, str) and path_value.strip():
            normalized = _normalize_path_prefix(path_value)
            if normalized and normalized not in path_candidates:
                path_candidates.append(normalized)

    return {
        "asset_id": asset_id,
        "host": host,
        "paths": path_candidates,
    }


def _host_matches_suffix(host: str, suffix: str) -> bool:
    """Match suffixes on dot boundaries only."""
    return bool(host) and (host == suffix or host.endswith(f".{suffix}"))


def _rule_matches(rule: Dict[str, Any], target: Dict[str, Any]) -> bool:
    """Return True when a compiled rule matches the finding target."""
    asset_id = target.get("asset_id", "")
    host = target.get("host", "")
    paths = target.get("paths", [])

    if "asset_id" in rule and asset_id != rule["asset_id"]:
        return False
    if "host" in rule and host != rule["host"]:
        return False
    if "host_suffix" in rule and not _host_matches_suffix(host, rule["host_suffix"]):
        return False
    if "path_prefix" in rule and not any(path.startswith(rule["path_prefix"]) for path in paths):
        return False

    return True


def _get_explicit_context_value(finding: Dict[str, Any], key: str) -> Any:
    """Preserve existing explicit values from business_context, finding, or meta."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    business_context = meta.get("business_context")
    if not isinstance(business_context, dict):
        business_context = {}

    for container in (business_context, finding, meta):
        value = container.get(key) if isinstance(container, dict) else None
        if not _is_present(value):
            continue
        if key in _BOOLEAN_CONTEXT_FIELDS and isinstance(value, bool):
            return value
        if key in _STRING_CONTEXT_FIELDS and isinstance(value, str) and value.strip():
            return value.strip()
    return None


def apply_asset_context(
    findings: List[Dict[str, Any]],
    rules: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Apply asset-context rules to findings in place.

    Precedence:
      1. Explicit values already present on the finding are preserved.
      2. Matching inventory rules are applied from most specific to least specific.
      3. File order breaks ties between equally specific rules.
      4. Inventory rules only fill missing supported fields.
    """
    if not rules:
        return findings

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        meta = finding.get("meta")
        if not isinstance(meta, dict):
            meta = {}
            finding["meta"] = meta

        existing = meta.get("business_context")
        resolved_context = {
            key: value
            for key, value in (existing.items() if isinstance(existing, dict) else [])
            if key not in BUSINESS_CONTEXT_FIELDS
        }

        for field in BUSINESS_CONTEXT_FIELDS:
            explicit = _get_explicit_context_value(finding, field)
            if explicit is not None:
                resolved_context[field] = explicit

        target = _extract_finding_target(finding)
        matching_rules = [
            rule for rule in rules
            if _rule_matches(rule, target)
        ]
        matching_rules.sort(key=lambda rule: (-rule["specificity"], rule["index"]))

        for rule in matching_rules:
            for field, value in rule["context"].items():
                if field not in resolved_context:
                    resolved_context[field] = value

        if resolved_context:
            meta["business_context"] = resolved_context

    return findings
