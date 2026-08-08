"""
Scan config loading, validation, and merge helpers.

This module keeps scanner-specific config logic out of main.py while preserving
the current orchestrator flow and scanner option dictionaries.
"""

from __future__ import annotations

import argparse
import json
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence

import yaml

from scanners.base import BaseScanner

SCAN_CONFIG_VERSION = 1
SCAN_CONFIG_ENABLED_KEY = "__scan_enabled__"

DEFAULT_GLOBAL_SETTINGS: Dict[str, Any] = {
    "scan_mode": "automatic",
    "http_mode": "auto",
    "save_raw": True,
    "normalize": True,
    "risk_scoring": True,
    "report": True,
}

SUPPORTED_GLOBAL_SETTINGS = {
    "scan_mode",
    "http_mode",
    "save_raw",
    "normalize",
    "risk_scoring",
    "report",
}
SUPPORTED_SCAN_MODES = {"automatic", "manual"}
SUPPORTED_HTTP_MODES = {"auto", "http1", "http2"}


@dataclass
class ResolvedScanConfig:
    """Normalized scan config ready for main/orchestrator integration."""

    source_path: Optional[str]
    global_settings: Dict[str, Any]
    scanner_enabled: Dict[str, bool]
    # Sparse scan-time overrides passed into orchestrator/scanners.
    scanner_options: Dict[str, Dict[str, Any]]
    # Full defaults + config + CLI view persisted for traceability.
    effective_scanner_options: Dict[str, Dict[str, Any]]
    requested_scanner: str
    effective_config: Dict[str, Any]

    @property
    def active_scanners(self) -> list[str]:
        """Return the scanners active for this run in registry order."""
        if self.requested_scanner != "all":
            return [self.requested_scanner]
        return [
            name
            for name, enabled in self.scanner_enabled.items()
            if enabled
        ]

    @property
    def selected_ports_spec(self) -> Optional[str]:
        """Return the effective nmap port selection when present."""
        nmap_options = self.scanner_options.get("nmap", {})
        value = nmap_options.get("ports")
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None


def load_scan_config_file(path: str | Path) -> Dict[str, Any]:
    """Load one YAML or JSON scan config file into a dict."""
    config_path = Path(path).expanduser()
    suffix = config_path.suffix.lower()
    if suffix not in {".yaml", ".yml", ".json"}:
        raise ValueError("--scan-config must point to a YAML or JSON file")

    try:
        text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"Could not read scan config: {config_path}: {exc}") from exc

    try:
        if suffix == ".json":
            payload = json.loads(text) if text.strip() else {}
        else:
            payload = yaml.safe_load(text) if text.strip() else {}
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Could not parse scan config: {config_path}: {exc}") from exc

    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise ValueError("Scan config must be a JSON/YAML object at the top level")
    return payload


def resolve_scan_config(
    *,
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    scanners: Mapping[str, BaseScanner],
    argv: Sequence[str],
) -> ResolvedScanConfig:
    """
    Load, merge, validate, and normalize scan settings from config + CLI.
    """
    explicit_cli = _collect_explicit_cli_dests(parser, argv)
    raw_config: Dict[str, Any] = {}
    config_path: Optional[Path] = None
    if getattr(args, "scan_config", None):
        config_path = Path(str(args.scan_config)).expanduser()
        raw_config = load_scan_config_file(config_path)

    version = raw_config.get("version", SCAN_CONFIG_VERSION)
    if version != SCAN_CONFIG_VERSION:
        raise ValueError(
            f"Unsupported scan config version '{version}'. Expected version {SCAN_CONFIG_VERSION}."
        )

    allowed_top_level = {"version", "global", "scanners"}
    unknown_top_level = sorted(key for key in raw_config if key not in allowed_top_level)
    if unknown_top_level:
        joined = ", ".join(unknown_top_level)
        raise ValueError(f"Unknown scan config top-level field(s): {joined}")

    global_config = raw_config.get("global") or {}
    if not isinstance(global_config, dict):
        raise ValueError("Scan config field 'global' must be an object when provided")

    raw_scanners = raw_config.get("scanners") or {}
    if not isinstance(raw_scanners, dict):
        raise ValueError("Scan config field 'scanners' must be an object when provided")

    known_scanners = set(scanners.keys())
    unknown_scanners = sorted(name for name in raw_scanners if name not in known_scanners)
    if unknown_scanners:
        joined = ", ".join(unknown_scanners)
        raise ValueError(f"Unknown scanner name(s) in scan config: {joined}")

    global_settings = _resolve_global_settings(args, explicit_cli, global_config)
    scanner_enabled, config_disabled_scanners, config_scanner_options = _load_scanner_config_entries(
        raw_scanners,
        scanners,
        config_path,
    )

    scanner_options = _build_scan_time_scanner_options(
        args,
        explicit_cli,
        scanners,
        config_scanner_options,
    )
    effective_scanner_options = _build_effective_scanner_options(
        args,
        explicit_cli,
        scanners,
        config_scanner_options,
    )

    _validate_run_selection(
        args,
        global_settings,
        scanner_enabled,
        scanner_options,
        config_disabled_scanners,
    )

    if args.scanner != "all":
        scanner_enabled = {
            name: (name == args.scanner)
            for name in scanners
        }

    for name, enabled in scanner_enabled.items():
        if not enabled:
            scanner_options.setdefault(name, {})[SCAN_CONFIG_ENABLED_KEY] = False

    effective_config = _build_effective_config(
        source_path=str(config_path) if config_path is not None else None,
        global_settings=global_settings,
        scanner_enabled=scanner_enabled,
        effective_scanner_options=effective_scanner_options,
        requested_scanner=args.scanner,
    )

    return ResolvedScanConfig(
        source_path=str(config_path) if config_path is not None else None,
        global_settings=global_settings,
        scanner_enabled=scanner_enabled,
        scanner_options=scanner_options,
        effective_scanner_options=effective_scanner_options,
        requested_scanner=args.scanner,
        effective_config=effective_config,
    )


def save_effective_scan_config(run_folder: Path, resolved: ResolvedScanConfig) -> Path:
    """Persist the effective merged scan config into one run folder."""
    output_path = run_folder / "effective_scan_config.json"
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(resolved.effective_config, fh, indent=2, sort_keys=False)
    return output_path


def _collect_explicit_cli_dests(
    parser: argparse.ArgumentParser,
    argv: Sequence[str],
) -> set[str]:
    """Return argparse dest names that were explicitly present in argv."""
    option_to_action = {}
    for action in parser._actions:
        for option_string in action.option_strings:
            option_to_action[option_string] = action

    explicit: set[str] = set()
    index = 0
    argv_list = list(argv)
    while index < len(argv_list):
        token = argv_list[index]
        if token == "--":
            break

        action = None
        if token.startswith("--"):
            option = token.split("=", 1)[0]
            action = option_to_action.get(option)
        elif token.startswith("-") and token != "-":
            action = option_to_action.get(token)

        if action is None:
            index += 1
            continue

        explicit.add(action.dest)
        if token.startswith("--") and "=" in token:
            index += 1
            continue

        index += 1 + _consumed_value_count(action, argv_list[index + 1 :], option_to_action)

    return explicit


def _consumed_value_count(
    action: argparse.Action,
    remaining: Sequence[str],
    option_to_action: Mapping[str, argparse.Action],
) -> int:
    """Return how many argv items belong to this action's value(s)."""
    nargs = action.nargs
    if nargs == 0:
        return 0
    if nargs is None:
        return 1 if remaining else 0
    if isinstance(nargs, int):
        return min(nargs, len(remaining))
    if nargs == "?":
        return 0 if not remaining or _looks_like_option(remaining[0], option_to_action) else 1
    if nargs in {"*", "+"}:
        consumed = 0
        for token in remaining:
            if _looks_like_option(token, option_to_action):
                break
            consumed += 1
        if nargs == "+" and consumed == 0 and remaining:
            return 1
        return consumed
    return 0


def _looks_like_option(token: str, option_to_action: Mapping[str, argparse.Action]) -> bool:
    """Return True when token is one of the parser's known option strings."""
    if token in option_to_action:
        return True
    if token.startswith("--") and "=" in token:
        return token.split("=", 1)[0] in option_to_action
    return False


def _resolve_global_settings(
    args: argparse.Namespace,
    explicit_cli: set[str],
    global_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Merge supported global settings from defaults, config, and CLI."""
    unknown = sorted(key for key in global_config if key not in SUPPORTED_GLOBAL_SETTINGS)
    if unknown:
        joined = ", ".join(unknown)
        raise ValueError(f"Unknown global scan config field(s): {joined}")

    resolved = dict(DEFAULT_GLOBAL_SETTINGS)
    resolved.update(global_config)

    if "scan_mode" in resolved:
        value = resolved["scan_mode"]
        if not isinstance(value, str) or value not in SUPPORTED_SCAN_MODES:
            supported = ", ".join(sorted(SUPPORTED_SCAN_MODES))
            raise ValueError(f"global.scan_mode must be one of: {supported}")
    if "http_mode" in resolved:
        value = resolved["http_mode"]
        if not isinstance(value, str) or value not in SUPPORTED_HTTP_MODES:
            supported = ", ".join(sorted(SUPPORTED_HTTP_MODES))
            raise ValueError(f"global.http_mode must be one of: {supported}")
    for key in ("save_raw", "normalize", "risk_scoring", "report"):
        value = resolved.get(key)
        if not isinstance(value, bool):
            raise ValueError(f"global.{key} must be a boolean")

    if "scan_mode" in explicit_cli:
        resolved["scan_mode"] = args.scan_mode
    if "http_mode" in explicit_cli:
        resolved["http_mode"] = args.http_mode
    if args.no_save:
        resolved["save_raw"] = False
    if "normalize" in explicit_cli:
        resolved["normalize"] = bool(args.normalize)
    if "risk_scoring" in explicit_cli:
        resolved["risk_scoring"] = bool(args.risk_scoring)
    if "report" in explicit_cli:
        resolved["report"] = bool(args.report)

    return resolved


def _load_scanner_config_entries(
    raw_scanners: Dict[str, Any],
    scanners: Mapping[str, BaseScanner],
    config_path: Optional[Path],
) -> tuple[Dict[str, bool], set[str], Dict[str, Dict[str, Any]]]:
    """Parse per-scanner config sections without injecting scanner defaults yet."""
    scanner_enabled = {name: True for name in scanners}
    config_disabled_scanners: set[str] = set()
    config_scanner_options: Dict[str, Dict[str, Any]] = {}

    for name, scanner in scanners.items():
        config_entry = raw_scanners.get(name)
        if config_entry is None:
            continue
        if not isinstance(config_entry, dict):
            raise ValueError(f"scanners.{name} must be an object")

        unknown_fields = sorted(key for key in config_entry if key not in {"enabled", "options"})
        if unknown_fields:
            joined = ", ".join(unknown_fields)
            raise ValueError(f"scanners.{name} contains unknown field(s): {joined}")

        if "enabled" in config_entry:
            enabled = config_entry["enabled"]
            if not isinstance(enabled, bool):
                raise ValueError(f"scanners.{name}.enabled must be a boolean")
            scanner_enabled[name] = enabled
            if not enabled:
                config_disabled_scanners.add(name)

        option_block = config_entry.get("options") or {}
        if not isinstance(option_block, dict):
            raise ValueError(f"scanners.{name}.options must be an object when provided")

        option_block = _resolve_path_options(scanner, option_block, config_path)
        config_scanner_options[name] = scanner.validate_options(option_block)

    return scanner_enabled, config_disabled_scanners, config_scanner_options


def _resolve_path_options(
    scanner: BaseScanner,
    options: Dict[str, Any],
    config_path: Optional[Path],
) -> Dict[str, Any]:
    """Resolve config-relative path options before scanner validation."""
    resolved = dict(options)
    path_keys = set(scanner.get_path_option_keys())
    if not path_keys or config_path is None:
        return resolved

    for key in path_keys:
        value = resolved.get(key)
        if value is None:
            continue
        if not isinstance(value, (str, Path)):
            continue
        path = Path(str(value)).expanduser()
        if not path.is_absolute():
            path = (config_path.parent / path).resolve()
        resolved[key] = str(path)

    return resolved


def _build_scan_time_scanner_options(
    args: argparse.Namespace,
    explicit_cli: set[str],
    scanners: Mapping[str, BaseScanner],
    config_scanner_options: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Build the sparse option maps passed into the orchestrator/scanners."""
    scanner_options = {
        name: dict(options)
        for name, options in config_scanner_options.items()
    }
    _apply_cli_scanner_overrides(
        args,
        explicit_cli,
        scanner_options,
        scanners,
        preserve_legacy_scan_defaults=True,
    )
    return scanner_options


def _build_effective_scanner_options(
    args: argparse.Namespace,
    explicit_cli: set[str],
    scanners: Mapping[str, BaseScanner],
    config_scanner_options: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """Build the full defaults + config + CLI view saved to the artifact."""
    effective_scanner_options: Dict[str, Dict[str, Any]] = {}
    for name, scanner in scanners.items():
        merged = dict(scanner.get_default_options())
        merged.update(config_scanner_options.get(name, {}))
        effective_scanner_options[name] = merged

    _apply_cli_scanner_overrides(
        args,
        explicit_cli,
        effective_scanner_options,
        scanners,
        preserve_legacy_scan_defaults=False,
    )
    return effective_scanner_options


def _apply_cli_scanner_overrides(
    args: argparse.Namespace,
    explicit_cli: set[str],
    scanner_options: Dict[str, Dict[str, Any]],
    scanners: Mapping[str, BaseScanner],
    *,
    preserve_legacy_scan_defaults: bool,
) -> None:
    """Apply explicit CLI scanner settings over config-file values."""
    if args.ports:
        scanner_options["nmap"] = {
            **scanner_options.get("nmap", {}),
            "ports": args.ports,
        }
    if getattr(args, "nmap_timeout", None) is not None:
        scanner_options["nmap"] = {
            **scanner_options.get("nmap", {}),
            "timeout": args.nmap_timeout,
        }
    if "nmap_scripts" in explicit_cli:
        scanner_options["nmap"] = {
            **scanner_options.get("nmap", {}),
            "scripts": list(args.nmap_scripts or []),
        }
    if getattr(args, "nmap_args", ""):
        scanner_options["nmap"] = {
            **scanner_options.get("nmap", {}),
            "args": shlex.split(args.nmap_args),
        }

    if args.severity:
        for name in ("nuclei", "wapiti"):
            scanner_options[name] = {
                **scanner_options.get(name, {}),
                "severity": list(args.severity),
            }

    if args.wapiti_level is not None:
        scanner_options["wapiti"] = {
            **scanner_options.get("wapiti", {}),
            "level": args.wapiti_level,
        }
    if args.wapiti_modules:
        scanner_options["wapiti"] = {
            **scanner_options.get("wapiti", {}),
            "modules": list(args.wapiti_modules),
        }
    if args.wapiti_timeout is not None:
        scanner_options["wapiti"] = {
            **scanner_options.get("wapiti", {}),
            "timeout": args.wapiti_timeout,
        }
    if args.wapiti_args:
        scanner_options["wapiti"] = {
            **scanner_options.get("wapiti", {}),
            "args": shlex.split(args.wapiti_args),
        }

    if args.nikto_timeout is not None:
        scanner_options["nikto"] = {
            **scanner_options.get("nikto", {}),
            "timeout": args.nikto_timeout,
        }
    if args.nikto_tuning:
        scanner_options["nikto"] = {
            **scanner_options.get("nikto", {}),
            "tuning": args.nikto_tuning,
        }
    if args.nikto_args:
        scanner_options["nikto"] = {
            **scanner_options.get("nikto", {}),
            "args": shlex.split(args.nikto_args),
        }

    zap_options = dict(scanner_options.get("zap", {}))
    if preserve_legacy_scan_defaults:
        zap_options.setdefault("timeout", args.zap_timeout)
        zap_options.setdefault("use_proxy", False)
        zap_options.setdefault("proxy_url", None)
        zap_options.setdefault("original_target", None)

    if "zap_timeout" in explicit_cli:
        zap_options["timeout"] = args.zap_timeout
    if args.zap_active_scan:
        zap_options["active_scan"] = True
    if args.zap_args:
        zap_options["args"] = shlex.split(args.zap_args)
    if args.zap_af_plan:
        zap_options["af_plan_path"] = args.zap_af_plan
    if args.zap_use_proxy:
        zap_options["use_proxy"] = True
    if args.zap_proxy_url and (args.zap_use_proxy or zap_options.get("use_proxy")):
        zap_options["proxy_url"] = args.zap_proxy_url
    if args.zap_proxy_original_target and (args.zap_use_proxy or zap_options.get("use_proxy")):
        zap_options["original_target"] = args.zap_proxy_original_target
    if zap_options.get("use_proxy") and not zap_options.get("original_target") and args.target:
        zap_options["original_target"] = args.target

    if zap_options:
        scanner_options["zap"] = zap_options

    for name, scanner in scanners.items():
        if name not in scanner_options:
            continue
        scanner_options[name] = scanner.validate_options(scanner_options[name])


def _validate_run_selection(
    args: argparse.Namespace,
    global_settings: Dict[str, Any],
    scanner_enabled: Dict[str, bool],
    scanner_options: Dict[str, Dict[str, Any]],
    config_disabled_scanners: set[str],
) -> None:
    """Validate merged run-wide selection constraints."""
    if args.scanner != "all" and args.scanner in config_disabled_scanners:
        raise ValueError(
            f"Scanner '{args.scanner}' is disabled by scan config and cannot be selected explicitly."
        )

    if global_settings["scan_mode"] == "manual" and args.scanner != "all":
        raise ValueError("--scan-mode manual currently requires --scanner all")

    if global_settings["scan_mode"] == "manual":
        ports = scanner_options.get("nmap", {}).get("ports")
        if not isinstance(ports, str) or not ports.strip():
            raise ValueError("--scan-mode manual requires nmap ports via --ports or scanners.nmap.options.ports")

    if args.scanner == "all" and not scanner_enabled.get("nmap", True):
        raise ValueError("scanners.nmap.enabled=false is not supported with --scanner all because discovery mode requires nmap")

    zap_options = scanner_options.get("zap", {})
    if zap_options.get("use_proxy") and not zap_options.get("proxy_url"):
        raise ValueError("ZAP proxy mode requires proxy_url in the scan config or --zap-proxy-url")


def _build_effective_config(
    *,
    source_path: Optional[str],
    global_settings: Dict[str, Any],
    scanner_enabled: Dict[str, bool],
    effective_scanner_options: Dict[str, Dict[str, Any]],
    requested_scanner: str,
) -> Dict[str, Any]:
    """Build a user-facing effective config artifact."""
    scanners_payload: Dict[str, Any] = {}
    for name, enabled in scanner_enabled.items():
        options = {
            ("extra_args" if key == "args" else key): value
            for key, value in effective_scanner_options.get(name, {}).items()
            if key != SCAN_CONFIG_ENABLED_KEY
        }
        scanners_payload[name] = {
            "enabled": enabled,
            "options": options,
        }

    return {
        "version": SCAN_CONFIG_VERSION,
        "requested_scanner": requested_scanner,
        "source_path": source_path,
        "global": dict(global_settings),
        "scanners": scanners_payload,
    }
