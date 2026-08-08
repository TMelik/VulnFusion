"""
INI-style project configuration loading.
"""

from __future__ import annotations

from configparser import ConfigParser, Error as ConfigParserError
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


DEFAULT_DEFECTDOJO_CONFIG_PATH = Path("defectdojo.config")
_DEFECTDOJO_SECTION = "defectdojo"
_SCAN_TYPES_SECTION = "defectdojo.scan_types"
_TEST_TITLES_SECTION = "defectdojo.test_titles"
_ARTIFACTS_SECTION = "defectdojo.artifacts"


@dataclass(slots=True)
class DefectDojoFileConfig:
    """DefectDojo settings loaded from an optional INI file."""

    path: Path
    loaded: bool = False
    enabled: bool | None = None
    base_url: str | None = None
    api_token: str | None = None
    api_token_env: str | None = None
    product_type_name: str | None = None
    product_type_id: int | None = None
    product_name: str | None = None
    product_id: int | None = None
    engagement_name: str | None = None
    engagement_id: int | None = None
    test_id: int | None = None
    upload_mode: str | None = None
    minimum_severity: str | None = None
    active: bool | None = None
    verified: bool | None = None
    auto_create_context: bool | None = None
    do_not_reactivate: bool | None = None
    close_old_findings: bool | None = None
    environment: str | None = None
    background_import: bool | None = None
    strict_names: bool | None = None
    verify_tls: bool | None = None
    timeout_seconds: float | None = None
    scan_types: dict[str, str] = field(default_factory=dict)
    test_titles: dict[str, str] = field(default_factory=dict)
    artifact_formats: dict[str, tuple[str, ...]] = field(default_factory=dict)
    has_scan_types_section: bool = False
    has_inline_api_token: bool = False


def load_defectdojo_config(path: str | Path | None = None, *, require: bool = False) -> DefectDojoFileConfig:
    """Load DefectDojo config from an INI file, returning an empty config when absent."""
    config_path = Path(path or DEFAULT_DEFECTDOJO_CONFIG_PATH)
    if not config_path.exists():
        if require:
            raise FileNotFoundError(f"Config file does not exist: {config_path}")
        return DefectDojoFileConfig(path=config_path)
    if not config_path.is_file():
        raise ValueError(f"Config path is not a file: {config_path}")

    parser = ConfigParser(interpolation=None)
    try:
        with config_path.open("r", encoding="utf-8") as handle:
            parser.read_file(handle)
    except ConfigParserError as exc:
        raise ValueError(f"Could not parse config file {config_path}: {exc}") from exc

    section = parser[_DEFECTDOJO_SECTION] if parser.has_section(_DEFECTDOJO_SECTION) else {}
    api_token = _optional_text(section.get("api_token"))

    return DefectDojoFileConfig(
        path=config_path,
        loaded=True,
        enabled=_optional_bool(section, "enabled"),
        base_url=_optional_text(section.get("base_url")),
        api_token=api_token,
        api_token_env=_optional_text(section.get("api_token_env")),
        product_type_name=_optional_text(section.get("product_type") or section.get("product_type_name")),
        product_type_id=_optional_int(section.get("product_type_id"), "product_type_id"),
        product_name=_optional_text(section.get("product") or section.get("product_name")),
        product_id=_optional_int(section.get("product_id"), "product_id"),
        engagement_name=_optional_text(section.get("engagement") or section.get("engagement_name")),
        engagement_id=_optional_int(section.get("engagement_id"), "engagement_id"),
        test_id=_optional_int(section.get("test_id"), "test_id"),
        upload_mode=_optional_text(section.get("upload_mode")),
        minimum_severity=_optional_text(section.get("minimum_severity")),
        active=_optional_bool(section, "active"),
        verified=_optional_bool(section, "verified"),
        auto_create_context=_optional_bool(section, "auto_create_context"),
        do_not_reactivate=_optional_bool(section, "do_not_reactivate"),
        close_old_findings=_optional_bool(section, "close_old_findings"),
        environment=_optional_text(section.get("environment")),
        background_import=_optional_bool(section, "background_import"),
        strict_names=_optional_bool(section, "strict_names"),
        verify_tls=_optional_bool(section, "verify_ssl", fallback_key="verify_tls"),
        timeout_seconds=_optional_float(section.get("timeout_seconds"), "timeout_seconds"),
        scan_types=_read_text_mapping(parser, _SCAN_TYPES_SECTION),
        test_titles=_read_text_mapping(parser, _TEST_TITLES_SECTION),
        artifact_formats=_read_artifact_mapping(parser, _ARTIFACTS_SECTION),
        has_scan_types_section=parser.has_section(_SCAN_TYPES_SECTION),
        has_inline_api_token=api_token is not None,
    )


def _read_text_mapping(parser: ConfigParser, section_name: str) -> dict[str, str]:
    if not parser.has_section(section_name):
        return {}
    values: dict[str, str] = {}
    for key, value in parser.items(section_name):
        text = _optional_text(value)
        if text:
            values[key.strip().lower()] = text
    return values


def _read_artifact_mapping(parser: ConfigParser, section_name: str) -> dict[str, tuple[str, ...]]:
    raw_values = _read_text_mapping(parser, section_name)
    parsed: dict[str, tuple[str, ...]] = {}
    for scanner_name, value in raw_values.items():
        formats = tuple(
            item.strip().lower()
            for item in value.split(",")
            if item.strip()
        )
        if formats:
            parsed[scanner_name] = formats
    return parsed


def _optional_bool(section: Any, key: str, *, fallback_key: str | None = None) -> bool | None:
    raw_value = section.get(key)
    if raw_value is None and fallback_key:
        raw_value = section.get(fallback_key)
    text = _optional_text(raw_value)
    if text is None:
        return None
    normalized = text.lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Config value {key} must be a boolean.")


def _optional_int(value: Any, field_name: str) -> int | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"Config value {field_name} must be an integer.") from exc


def _optional_float(value: Any, field_name: str) -> float | None:
    text = _optional_text(value)
    if text is None:
        return None
    try:
        return float(text)
    except ValueError as exc:
        raise ValueError(f"Config value {field_name} must be a number.") from exc


def _optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None
