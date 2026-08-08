"""
HTTP client for uploading Generic Findings Import reports to DefectDojo.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from difflib import get_close_matches
from pathlib import Path
from typing import Any
import json
import logging
import re
import warnings

import httpx

from utils.defectdojo_dates import normalize_defectdojo_scan_date


_PRODUCT_TYPE_ENDPOINT = "/api/v2/product_types/"
_PRODUCT_ENDPOINT = "/api/v2/products/"
_ENGAGEMENT_ENDPOINT = "/api/v2/engagements/"
_TEST_ENDPOINT = "/api/v2/tests/"
_LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class DefectDojoConfig:
    """Connection and upload settings for DefectDojo reimport."""

    base_url: str | None
    api_token: str | None = field(repr=False)
    product_type_name: str | None = None
    product_type_id: int | None = None
    product_name: str | None = None
    product_id: int | None = None
    engagement_name: str | None = None
    scan_type: str = "Generic Findings Import"
    test_title: str | None = None
    minimum_severity: str = "Info"
    active: bool = True
    verified: bool = True
    auto_create_context: bool = True
    do_not_reactivate: bool = False
    close_old_findings: bool = False
    environment: str | None = None
    test_id: int | None = None
    engagement_id: int | None = None
    background_import: bool = False
    strict_names: bool = False
    verify_tls: bool = True
    timeout_seconds: float = 30.0
    transport: httpx.BaseTransport | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        for field_name in (
            "base_url",
            "api_token",
            "product_type_name",
            "product_name",
            "engagement_name",
            "test_title",
            "environment",
        ):
            setattr(self, field_name, _normalize_optional_text(getattr(self, field_name)))

        self.scan_type = _normalize_optional_text(self.scan_type) or "Generic Findings Import"
        self.minimum_severity = _normalize_optional_text(self.minimum_severity) or "Info"
        self.product_type_id = _normalize_optional_int(self.product_type_id, "product_type_id")
        self.product_id = _normalize_optional_int(self.product_id, "product_id")
        self.test_id = _normalize_optional_int(self.test_id, "test_id")
        self.engagement_id = _normalize_optional_int(self.engagement_id, "engagement_id")
        self.strict_names = bool(self.strict_names)

    def validate(self) -> None:
        missing: list[str] = []
        if not self.normalized_base_url:
            missing.append("base_url")
        if not self.normalized_api_token:
            missing.append("api_token")
        if self.test_id is None and self.engagement_id is None:
            if self.product_type_id is None and not _normalize_optional_text(self.product_type_name):
                missing.append("product_type_name")
            if self.product_id is None and not _normalize_optional_text(self.product_name):
                missing.append("product_name")
            if not _normalize_optional_text(self.engagement_name):
                missing.append("engagement_name")
        if missing:
            joined = ", ".join(missing)
            raise ValueError(f"DefectDojo upload requires configuration for: {joined}")

    @property
    def normalized_base_url(self) -> str:
        return str(self.base_url or "").rstrip("/")

    @property
    def normalized_api_token(self) -> str:
        return _normalize_api_token(self.api_token) or ""


class DefectDojoUploadError(RuntimeError):
    """Raised when one DefectDojo upload request fails."""


def upload_defectdojo_report(
    report_path: Path,
    config: DefectDojoConfig,
    *,
    scan_date: Any | None = None,
) -> dict[str, Any]:
    """Upload one Generic Findings Import JSON report to DefectDojo."""
    config.validate()
    normalized_scan_date = normalize_defectdojo_scan_date(scan_date)

    if not report_path.exists() or not report_path.is_file():
        raise FileNotFoundError(f"DefectDojo report file does not exist: {report_path}")

    try:
        with httpx.Client(
            base_url=config.normalized_base_url,
            timeout=config.timeout_seconds,
            verify=config.verify_tls,
            transport=config.transport,
            follow_redirects=True,
            headers=_build_headers(config),
        ) as client:
            warnings_list = _preflight_context(client, config)
            for warning_text in warnings_list:
                warnings.warn(f"DefectDojo preflight warning: {warning_text}", stacklevel=2)

            response = _post_scan_file(
                client,
                endpoint="/api/v2/reimport-scan/",
                file_path=report_path,
                config=config,
                scan_date=normalized_scan_date,
                content_type="application/json",
            )
    except httpx.HTTPError as exc:
        raise DefectDojoUploadError(f"DefectDojo upload request failed: {exc}") from exc

    if not response.is_success:
        raise DefectDojoUploadError(_format_upload_http_error(response, config))

    _LOGGER.info("[+] DefectDojo upload completed")

    try:
        return response.json()
    except ValueError:
        return {
            "status_code": response.status_code,
            "text": response.text,
        }


def upload_defectdojo_raw_artifact(
    artifact_path: Path,
    config: DefectDojoConfig,
    *,
    scan_type: str,
    test_title: str,
    scan_date: Any | None = None,
) -> dict[str, Any]:
    """Upload one scanner-native raw artifact to DefectDojo."""
    normalized_scan_type = _normalize_optional_text(scan_type)
    if not normalized_scan_type:
        raise ValueError("DefectDojo raw upload requires scan_type.")
    normalized_test_title = _normalize_optional_text(test_title)
    if not normalized_test_title:
        raise ValueError("DefectDojo raw upload requires test_title.")

    raw_config = replace(
        config,
        scan_type=normalized_scan_type,
        test_title=normalized_test_title,
        test_id=None,
    )
    raw_config.validate()
    normalized_scan_date = normalize_defectdojo_scan_date(scan_date)

    if not artifact_path.exists() or not artifact_path.is_file():
        raise FileNotFoundError(f"DefectDojo raw artifact file does not exist: {artifact_path}")

    try:
        with httpx.Client(
            base_url=raw_config.normalized_base_url,
            timeout=raw_config.timeout_seconds,
            verify=raw_config.verify_tls,
            transport=raw_config.transport,
            follow_redirects=True,
            headers=_build_headers(raw_config),
        ) as client:
            warnings_list = _preflight_context(client, raw_config)
            for warning_text in warnings_list:
                warnings.warn(f"DefectDojo preflight warning: {warning_text}", stacklevel=2)

            existing_test = find_existing_test_for_raw_upload(client, raw_config)
            scanner_name = _scanner_name_from_raw_title(raw_config.test_title)
            _LOGGER.debug(
                "DefectDojo raw upload decision: scanner=%s scan_type=%s test_title=%s "
                "engagement_id=%s artifact_path=%s existing_test_id=%s",
                scanner_name,
                raw_config.scan_type,
                raw_config.test_title,
                raw_config.engagement_id,
                artifact_path,
                _object_id(existing_test),
            )

            endpoint = "/api/v2/import-scan/"
            upload_config = raw_config
            if existing_test is not None:
                test_id = _object_id(existing_test)
                if test_id is None:
                    raise DefectDojoUploadError(
                        "DefectDojo raw upload failed: matching test response did not include an id."
                    )
                upload_config = replace(raw_config, test_id=test_id)
                endpoint = "/api/v2/reimport-scan/"
                _LOGGER.info(
                    "[*] Existing DefectDojo test found; using reimport: test id %s (%s | %s)",
                    test_id,
                    raw_config.scan_type,
                    raw_config.test_title,
                )
            else:
                _LOGGER.info(
                    "[*] No DefectDojo test found; using first import (%s | %s)",
                    raw_config.scan_type,
                    raw_config.test_title,
                )

            response = _post_scan_file(
                client,
                endpoint=endpoint,
                file_path=artifact_path,
                config=upload_config,
                scan_date=normalized_scan_date,
                content_type="application/octet-stream",
            )
    except httpx.HTTPError as exc:
        raise DefectDojoUploadError(f"DefectDojo raw upload request failed: {exc}") from exc

    if not response.is_success:
        raise DefectDojoUploadError(_format_upload_http_error(response, raw_config))

    _LOGGER.info("[+] DefectDojo raw upload completed")

    try:
        return response.json()
    except ValueError:
        return {
            "status_code": response.status_code,
            "text": response.text,
        }


def find_existing_test_for_raw_upload(
    client: httpx.Client,
    config: DefectDojoConfig,
) -> dict[str, Any] | None:
    """Return the exact DefectDojo Test for one raw scanner upload, if it exists."""
    test_title = _normalize_optional_text(config.test_title)
    scan_type = _normalize_optional_text(config.scan_type)
    if not test_title or not scan_type:
        return None

    engagement_id = _resolve_raw_upload_engagement_id(client, config)
    if engagement_id is None:
        _LOGGER.debug(
            "DefectDojo raw test lookup skipped because engagement is not resolved: "
            "scan_type=%s test_title=%s",
            scan_type,
            test_title,
        )
        return None

    tests = _list_all_objects(
        client,
        _TEST_ENDPOINT,
        params={"limit": 100, "engagement": engagement_id},
    )
    matches: list[dict[str, Any]] = []
    for test in tests:
        candidate = _strict_raw_upload_test_match(
            client,
            test,
            engagement_id=engagement_id,
            test_title=test_title,
            scan_type=scan_type,
        )
        if candidate is not None:
            matches.append(candidate)

    if len(matches) > 1:
        _LOGGER.warning(
            "DefectDojo raw upload found multiple matching tests for engagement_id=%s, "
            "scan_type=%s, test_title=%s; using test id %s",
            engagement_id,
            scan_type,
            test_title,
            _object_id(matches[0]),
        )

    return matches[0] if matches else None


def _build_headers(config: DefectDojoConfig) -> dict[str, str]:
    return {
        "Authorization": f"Token {config.normalized_api_token}",
    }


def _post_scan_file(
    client: httpx.Client,
    *,
    endpoint: str,
    file_path: Path,
    config: DefectDojoConfig,
    scan_date: str | None,
    content_type: str,
) -> httpx.Response:
    url = f"{config.normalized_base_url}{endpoint}"
    with open(file_path, "rb") as handle:
        return client.post(
            url,
            data=_build_form_data(config, scan_date=scan_date),
            files={"file": (file_path.name, handle, content_type)},
        )


def _build_form_data(config: DefectDojoConfig, *, scan_date: str | None) -> dict[str, str]:
    data = {
        "scan_type": config.scan_type or "Generic Findings Import",
        "minimum_severity": _title_case_severity(config.minimum_severity),
        "active": _bool_string(config.active),
        "verified": _bool_string(config.verified),
        "auto_create_context": _bool_string(config.auto_create_context),
    }

    if config.test_id is not None:
        data["test"] = str(config.test_id)
    elif config.engagement_id is not None:
        data["engagement"] = str(config.engagement_id)
    else:
        if config.product_type_id is not None:
            data["product_type"] = str(config.product_type_id)
        elif config.product_type_name:
            data["product_type_name"] = config.product_type_name
        if config.product_id is not None:
            data["product"] = str(config.product_id)
        elif config.product_name:
            data["product_name"] = config.product_name
        if config.engagement_name:
            data["engagement_name"] = config.engagement_name

    if config.test_title:
        data["test_title"] = config.test_title
    if scan_date:
        data["scan_date"] = scan_date
    if config.do_not_reactivate:
        data["do_not_reactivate"] = _bool_string(True)
    if config.close_old_findings:
        data["close_old_findings"] = _bool_string(True)
    if config.environment:
        data["environment"] = config.environment
    if config.background_import:
        data["background_import"] = _bool_string(True)

    return data


def _resolve_raw_upload_engagement_id(client: httpx.Client, config: DefectDojoConfig) -> int | None:
    if config.engagement_id is not None:
        return config.engagement_id

    try:
        return _lookup_raw_upload_engagement_id(client, config)
    except DefectDojoUploadError:
        if config.auto_create_context:
            _LOGGER.debug(
                "DefectDojo raw upload could not resolve engagement id before import; "
                "continuing with auto_create_context=true.",
                exc_info=True,
            )
            return None
        raise


def _lookup_raw_upload_engagement_id(client: httpx.Client, config: DefectDojoConfig) -> int | None:
    if not config.engagement_name:
        return None

    product_id = config.product_id
    if product_id is None:
        product_type_id = config.product_type_id
        if product_type_id is None:
            if not config.product_type_name:
                return None
            product_types = _list_objects(client, _PRODUCT_TYPE_ENDPOINT, params={"limit": 100})
            product_type, resolution_warnings = _resolve_named_object(
                product_types,
                config.product_type_name,
                object_name="product type",
                strict_names=config.strict_names,
                update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE or use --defectdojo-product-type.",
            )
            _log_resolution_debug(resolution_warnings)
            if product_type is None:
                return None

            config.product_type_name = _object_name(product_type) or config.product_type_name
            product_type_id = _object_id(product_type)

        if not config.product_name:
            return None
        products = _list_objects(client, _PRODUCT_ENDPOINT, params={"limit": 100})
        product, resolution_warnings = _resolve_named_object(
            products,
            config.product_name,
            object_name="product",
            parent_id=product_type_id,
            parent_keys=("prod_type", "product_type", "product_type_id"),
            parent_name=config.product_type_name,
            parent_object_name="product type",
            strict_names=config.strict_names,
            update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT or use --defectdojo-product.",
        )
        _log_resolution_debug(resolution_warnings)
        if product is None:
            return None

        config.product_name = _object_name(product) or config.product_name
        product_id = _object_id(product)

    engagements = _list_objects(client, _ENGAGEMENT_ENDPOINT, params={"limit": 100})
    engagement, resolution_warnings = _resolve_named_object(
        engagements,
        config.engagement_name,
        object_name="engagement",
        parent_id=product_id,
        parent_keys=("product", "product_id"),
        parent_name=config.product_name,
        parent_object_name="product",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_ENGAGEMENT or use --defectdojo-engagement-id.",
    )
    _log_resolution_debug(resolution_warnings)
    if engagement is None:
        return None

    config.engagement_name = _object_name(engagement) or config.engagement_name
    engagement_id = _object_id(engagement)
    if engagement_id is not None:
        config.engagement_id = engagement_id
    return engagement_id


def _log_resolution_debug(warnings_list: list[str]) -> None:
    for warning_text in warnings_list:
        _LOGGER.debug("DefectDojo raw context resolution: %s", warning_text)


def _strict_raw_upload_test_match(
    client: httpx.Client,
    test: dict[str, Any],
    *,
    engagement_id: int,
    test_title: str,
    scan_type: str,
) -> dict[str, Any] | None:
    if not _raw_upload_test_can_match_without_detail(test, test_title=test_title):
        return None

    if _raw_upload_test_matches(test, engagement_id=engagement_id, test_title=test_title, scan_type=scan_type):
        return test

    if not _raw_upload_test_needs_detail(test):
        return None

    test_id = _object_id(test)
    if test_id is None:
        return None

    detailed_test = _fetch_detail_or_raise(
        client,
        endpoint=_TEST_ENDPOINT,
        object_name="test",
        object_id=test_id,
        remediation="Check DefectDojo test permissions for raw upload matching.",
    )
    if _raw_upload_test_matches(detailed_test, engagement_id=engagement_id, test_title=test_title, scan_type=scan_type):
        return detailed_test
    return None


def _raw_upload_test_can_match_without_detail(test: dict[str, Any], *, test_title: str) -> bool:
    title = _test_title(test)
    return title is None or title == test_title


def _raw_upload_test_needs_detail(test: dict[str, Any]) -> bool:
    return _test_title(test) is None or _test_scan_type(test) is None or _test_engagement_id(test) is None


def _raw_upload_test_matches(
    test: dict[str, Any],
    *,
    engagement_id: int,
    test_title: str,
    scan_type: str,
) -> bool:
    return (
        _test_engagement_id(test) == engagement_id
        and _test_title(test) == test_title
        and _test_scan_type(test) == scan_type
    )


def _test_title(test: dict[str, Any]) -> str | None:
    return _first_related_text(test, ("title", "name"))


def _test_scan_type(test: dict[str, Any]) -> str | None:
    return _first_related_text(test, ("scan_type", "test_type"))


def _test_engagement_id(test: dict[str, Any]) -> int | None:
    for key in ("engagement", "engagement_id"):
        engagement_id = _coerce_related_id(test.get(key))
        if engagement_id is not None:
            return engagement_id
    return None


def _first_related_text(item: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for key in keys:
        text = _related_text(item.get(key))
        if text:
            return text
    return None


def _related_text(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("name", "title", "display_name", "value"):
            text = _normalize_optional_text(value.get(key))
            if text:
                return text
        return None
    return _normalize_optional_text(value)


def _scanner_name_from_raw_title(test_title: str | None) -> str | None:
    title = _normalize_optional_text(test_title)
    if not title:
        return None
    scanner_name, separator, _target = title.partition("|")
    if not separator:
        return None
    return _normalize_optional_text(scanner_name)


def _preflight_context(client: httpx.Client, config: DefectDojoConfig) -> list[str]:
    warnings_list: list[str] = []

    if config.test_id is not None:
        _fetch_detail_or_raise(
            client,
            endpoint=_TEST_ENDPOINT,
            object_name="test",
            object_id=config.test_id,
            remediation="Check --defectdojo-test-id or VULN_MANAGER_DEFECTDOJO_TEST_ID.",
        )
        _LOGGER.info("[+] DefectDojo auth verified")
        _LOGGER.info("[+] DefectDojo test resolved: %s", config.test_id)
        return warnings_list

    if config.engagement_id is not None:
        _fetch_detail_or_raise(
            client,
            endpoint=_ENGAGEMENT_ENDPOINT,
            object_name="engagement",
            object_id=config.engagement_id,
            remediation="Check --defectdojo-engagement-id or VULN_MANAGER_DEFECTDOJO_ENGAGEMENT_ID.",
        )
        _LOGGER.info("[+] DefectDojo auth verified")
        _LOGGER.info("[+] DefectDojo engagement resolved: %s", config.engagement_id)
        return warnings_list

    if config.product_type_id is not None or config.product_id is not None:
        if config.product_type_id is not None:
            _fetch_detail_or_raise(
                client,
                endpoint=_PRODUCT_TYPE_ENDPOINT,
                object_name="product type",
                object_id=config.product_type_id,
                remediation="Check configured DefectDojo product_type_id.",
            )
        if config.product_id is not None:
            _fetch_detail_or_raise(
                client,
                endpoint=_PRODUCT_ENDPOINT,
                object_name="product",
                object_id=config.product_id,
                remediation="Check configured DefectDojo product_id.",
            )
        _LOGGER.info("[+] DefectDojo auth verified")
        if config.product_type_id is not None:
            _LOGGER.info("[+] DefectDojo product type resolved: %s", config.product_type_id)
        if config.product_id is not None:
            _LOGGER.info("[+] DefectDojo product resolved: %s", config.product_id)
        return warnings_list

    product_types = _list_objects(client, _PRODUCT_TYPE_ENDPOINT, params={"limit": 100})
    _LOGGER.info("[+] DefectDojo auth verified")

    if config.auto_create_context:
        return _preflight_auto_create_context(client, config, product_types, warnings_list)

    return _preflight_existing_context(client, config, product_types, warnings_list)


def _preflight_existing_context(
    client: httpx.Client,
    config: DefectDojoConfig,
    product_types: list[dict[str, Any]],
    warnings_list: list[str],
) -> list[str]:
    product_type_names = _extract_names(product_types)
    product_type, resolution_warnings = _resolve_named_object(
        product_types,
        config.product_type_name,
        object_name="product type",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE or use --defectdojo-product-type.",
    )
    warnings_list.extend(resolution_warnings)
    if product_type is None:
        message = _not_found_message(
            object_name="product type",
            target_name=config.product_type_name or "",
            parent_name=None,
            parent_object_name=None,
            existing_names=product_type_names,
            suggestions=_close_match_suggestions(config.product_type_name or "", product_type_names),
            update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE or use --defectdojo-product-type.",
        )
        return _handle_preflight_miss(message, auto_create_context=False, warnings_list=warnings_list)
    config.product_type_name = _object_name(product_type) or config.product_type_name
    _LOGGER.info("[+] DefectDojo product type resolved: %s", config.product_type_name)

    products = _list_objects(client, _PRODUCT_ENDPOINT, params={"limit": 100})
    products_for_type = _filter_by_parent(
        products,
        _object_id(product_type),
        ("prod_type", "product_type", "product_type_id"),
    )
    product_candidates = products_for_type or products
    product, resolution_warnings = _resolve_named_object(
        products,
        config.product_name,
        object_name="product",
        parent_id=_object_id(product_type),
        parent_keys=("prod_type", "product_type", "product_type_id"),
        parent_name=config.product_type_name,
        parent_object_name="product type",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT or use --defectdojo-product.",
    )
    warnings_list.extend(resolution_warnings)
    if product is None:
        candidate_names = _extract_names(product_candidates)
        message = _not_found_message(
            object_name="product",
            target_name=config.product_name or "",
            parent_name=config.product_type_name,
            parent_object_name="product type",
            existing_names=candidate_names,
            suggestions=_close_match_suggestions(config.product_name or "", candidate_names),
            update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT or use --defectdojo-product.",
        )
        return _handle_preflight_miss(message, auto_create_context=False, warnings_list=warnings_list)
    config.product_name = _object_name(product) or config.product_name
    _LOGGER.info("[+] DefectDojo product resolved: %s", config.product_name)

    engagements = _list_objects(client, _ENGAGEMENT_ENDPOINT, params={"limit": 100})
    engagements_for_product = _filter_by_parent(
        engagements,
        _object_id(product),
        ("product", "product_id"),
    )
    engagement_candidates = engagements_for_product or engagements
    engagement, resolution_warnings = _resolve_named_object(
        engagements,
        config.engagement_name,
        object_name="engagement",
        parent_id=_object_id(product),
        parent_keys=("product", "product_id"),
        parent_name=config.product_name,
        parent_object_name="product",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_ENGAGEMENT or use --defectdojo-engagement-id.",
    )
    warnings_list.extend(resolution_warnings)
    if engagement is None:
        candidate_names = _extract_names(engagement_candidates)
        message = _not_found_message(
            object_name="engagement",
            target_name=config.engagement_name or "",
            parent_name=config.product_name,
            parent_object_name="product",
            existing_names=candidate_names,
            suggestions=_close_match_suggestions(config.engagement_name or "", candidate_names),
            update_hint="Update VULN_MANAGER_DEFECTDOJO_ENGAGEMENT or use --defectdojo-engagement-id.",
        )
        return _handle_preflight_miss(message, auto_create_context=False, warnings_list=warnings_list)
    config.engagement_name = _object_name(engagement) or config.engagement_name
    _LOGGER.info("[+] DefectDojo engagement resolved: %s", config.engagement_name)

    return warnings_list


def _preflight_auto_create_context(
    client: httpx.Client,
    config: DefectDojoConfig,
    product_types: list[dict[str, Any]],
    warnings_list: list[str],
) -> list[str]:
    product_type, resolution_warnings = _resolve_named_object(
        product_types,
        config.product_type_name,
        object_name="product type",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE or use --defectdojo-product-type.",
    )
    warnings_list.extend(resolution_warnings)
    if product_type is None:
        _append_auto_create_context_warning(
            warnings_list,
            object_name="product type",
            target_name=config.product_type_name or "",
            parent_name=None,
            parent_object_name=None,
        )
        _log_auto_create_request("product type", config.product_type_name)
        _log_auto_create_request("product", config.product_name)
        _log_auto_create_request("engagement", config.engagement_name)
        return warnings_list

    config.product_type_name = _object_name(product_type) or config.product_type_name
    _LOGGER.info("[+] DefectDojo product type resolved: %s", config.product_type_name)

    products = _list_objects_best_effort(client, _PRODUCT_ENDPOINT, warnings_list, object_name="products")
    if products is None:
        return warnings_list

    products_for_type = _filter_by_parent(
        products,
        _object_id(product_type),
        ("prod_type", "product_type", "product_type_id"),
    )
    product, resolution_warnings = _resolve_named_object(
        products,
        config.product_name,
        object_name="product",
        parent_id=_object_id(product_type),
        parent_keys=("prod_type", "product_type", "product_type_id"),
        parent_name=config.product_type_name,
        parent_object_name="product type",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_PRODUCT or use --defectdojo-product.",
    )
    warnings_list.extend(resolution_warnings)
    if product is None:
        _append_auto_create_context_warning(
            warnings_list,
            object_name="product",
            target_name=config.product_name or "",
            parent_name=config.product_type_name,
            parent_object_name="product type",
        )
        if not products_for_type:
            _LOGGER.info(
                "[+] DefectDojo product type has no matching products yet: %s",
                config.product_type_name,
            )
        _log_auto_create_request("product", config.product_name)
        _log_auto_create_request("engagement", config.engagement_name)
        return warnings_list

    config.product_name = _object_name(product) or config.product_name
    _LOGGER.info("[+] DefectDojo product resolved: %s", config.product_name)

    engagements = _list_objects_best_effort(
        client,
        _ENGAGEMENT_ENDPOINT,
        warnings_list,
        object_name="engagements",
    )
    if engagements is None:
        return warnings_list

    engagements_for_product = _filter_by_parent(
        engagements,
        _object_id(product),
        ("product", "product_id"),
    )
    engagement, resolution_warnings = _resolve_named_object(
        engagements,
        config.engagement_name,
        object_name="engagement",
        parent_id=_object_id(product),
        parent_keys=("product", "product_id"),
        parent_name=config.product_name,
        parent_object_name="product",
        strict_names=config.strict_names,
        update_hint="Update VULN_MANAGER_DEFECTDOJO_ENGAGEMENT or use --defectdojo-engagement-id.",
    )
    warnings_list.extend(resolution_warnings)
    if engagement is None:
        _append_auto_create_context_warning(
            warnings_list,
            object_name="engagement",
            target_name=config.engagement_name or "",
            parent_name=config.product_name,
            parent_object_name="product",
        )
        if not engagements_for_product:
            _LOGGER.info(
                "[+] DefectDojo product has no matching engagements yet: %s",
                config.product_name,
            )
        _log_auto_create_request("engagement", config.engagement_name)
        return warnings_list

    config.engagement_name = _object_name(engagement) or config.engagement_name
    _LOGGER.info("[+] DefectDojo engagement resolved: %s", config.engagement_name)
    return warnings_list


def _handle_preflight_miss(message: str, auto_create_context: bool, warnings_list: list[str]) -> list[str]:
    if auto_create_context:
        warnings_list.append(f"{message} auto_create_context=true may create new context if your token has permission.")
        return warnings_list
    raise DefectDojoUploadError(message)


def _list_objects_best_effort(
    client: httpx.Client,
    endpoint: str,
    warnings_list: list[str],
    *,
    object_name: str,
) -> list[dict[str, Any]] | None:
    try:
        return _list_objects(client, endpoint, params={"limit": 100})
    except DefectDojoUploadError as exc:
        warnings_list.append(
            f"Could not inspect existing DefectDojo {object_name} after auth verification: {exc}. "
            "Upload will continue because auto_create_context=true."
        )
        return None


def _append_auto_create_context_warning(
    warnings_list: list[str],
    *,
    object_name: str,
    target_name: str,
    parent_name: str | None,
    parent_object_name: str | None,
) -> None:
    if parent_name and parent_object_name:
        message = (
            f"DefectDojo {object_name} '{target_name}' was not found under "
            f"{parent_object_name} '{parent_name}'."
        )
    else:
        message = f"DefectDojo {object_name} '{target_name}' was not found."
    warnings_list.append(
        f"{message} Upload will continue with auto_create_context=true; DefectDojo "
        "will create missing context during reimport if the token has create/import permission."
    )


def _log_auto_create_request(object_name: str, target_name: str | None) -> None:
    if target_name:
        _LOGGER.info("[+] DefectDojo %s will be auto-created during upload: %s", object_name, target_name)


def _fetch_detail_or_raise(
    client: httpx.Client,
    *,
    endpoint: str,
    object_name: str,
    object_id: int,
    remediation: str,
) -> dict[str, Any]:
    response = client.get(f"{endpoint}{object_id}/")
    if response.status_code == 404:
        raise DefectDojoUploadError(
            f"DefectDojo upload failed: {object_name} id {object_id} was not found. {remediation}"
        )
    if not response.is_success:
        raise DefectDojoUploadError(_format_http_error(response, prefix="DefectDojo preflight failed"))

    payload = _parse_json_response(response)
    if not isinstance(payload, dict):
        raise DefectDojoUploadError(
            f"DefectDojo preflight failed: unexpected response while looking up {object_name} id {object_id}."
        )
    return payload


def _list_objects(
    client: httpx.Client,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    response = client.get(endpoint, params=params)
    if not response.is_success:
        raise DefectDojoUploadError(_format_http_error(response, prefix="DefectDojo preflight failed"))

    payload = _parse_json_response(response)
    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _list_all_objects(
    client: httpx.Client,
    endpoint: str,
    *,
    params: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    next_url: str | None = endpoint
    next_params = params
    seen_urls: set[str] = set()

    while next_url:
        response = client.get(next_url, params=next_params)
        if not response.is_success:
            raise DefectDojoUploadError(_format_http_error(response, prefix="DefectDojo preflight failed"))

        payload = _parse_json_response(response)
        if isinstance(payload, dict):
            results = payload.get("results")
            if isinstance(results, list):
                items.extend(item for item in results if isinstance(item, dict))
            else:
                return items

            next_value = _normalize_optional_text(payload.get("next"))
            if next_value is None or next_value in seen_urls:
                break
            seen_urls.add(next_value)
            next_url = next_value
            next_params = None
            continue

        if isinstance(payload, list):
            items.extend(item for item in payload if isinstance(item, dict))
        break

    return items


def _resolve_named_object(
    items: list[dict[str, Any]],
    target_name: str | None,
    *,
    object_name: str,
    parent_id: int | None = None,
    parent_keys: tuple[str, ...] = (),
    parent_name: str | None = None,
    parent_object_name: str | None = None,
    strict_names: bool = False,
    update_hint: str,
) -> tuple[dict[str, Any] | None, list[str]]:
    if not target_name:
        return None, []

    candidates = _candidate_items(items, parent_id=parent_id, parent_keys=parent_keys)
    exact_matches = [
        item
        for item in candidates
        if _object_name(item) == target_name
    ]
    if exact_matches:
        return exact_matches[0], []

    if strict_names:
        return None, []

    target_key = _loose_name(target_name)
    normalized_matches = [
        item
        for item in candidates
        if _loose_name(_object_name(item) or "") == target_key
    ]
    if len(normalized_matches) == 1:
        match = normalized_matches[0]
        canonical_name = _object_name(match)
        warnings_list = []
        if canonical_name and canonical_name != target_name:
            warnings_list.append(
                f"Resolved DefectDojo {object_name} '{target_name}' "
                f"to canonical name '{canonical_name}'."
            )
        return match, warnings_list

    if len(normalized_matches) > 1:
        raise DefectDojoUploadError(
            _ambiguous_name_message(
                object_name=object_name,
                target_name=target_name,
                parent_name=parent_name,
                parent_object_name=parent_object_name,
                candidate_names=_extract_names(normalized_matches),
                update_hint=update_hint,
            )
        )

    return None, []


def _candidate_items(
    items: list[dict[str, Any]],
    *,
    parent_id: int | None = None,
    parent_keys: tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    if parent_id is None or not parent_keys:
        return items

    return [item for item in items if _matches_parent(item, parent_id, parent_keys)]


def _filter_by_parent(
    items: list[dict[str, Any]],
    parent_id: int | None,
    parent_keys: tuple[str, ...],
) -> list[dict[str, Any]]:
    if parent_id is None or not parent_keys:
        return []
    return [item for item in items if _matches_parent(item, parent_id, parent_keys)]


def _matches_parent(item: dict[str, Any], parent_id: int, parent_keys: tuple[str, ...]) -> bool:
    for key in parent_keys:
        related_id = _coerce_related_id(item.get(key))
        if related_id == parent_id:
            return True
    return False


def _coerce_related_id(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    if isinstance(value, dict):
        for key in ("id", "pk", "value"):
            related_id = _coerce_related_id(value.get(key))
            if related_id is not None:
                return related_id
    return None


def _object_id(item: dict[str, Any] | None) -> int | None:
    if not isinstance(item, dict):
        return None
    return _coerce_related_id(item.get("id"))


def _object_name(item: dict[str, Any] | None) -> str | None:
    if not isinstance(item, dict):
        return None
    return _normalize_optional_text(item.get("name"))


def _extract_names(items: list[dict[str, Any]]) -> list[str]:
    names: list[str] = []
    for item in items:
        name = _object_name(item)
        if name:
            names.append(name)
    return names


def _close_match_suggestions(target_name: str, candidates: list[str]) -> list[str]:
    if not target_name:
        return []
    lookup: dict[str, str] = {}
    for candidate in candidates:
        key = _loose_name(candidate)
        if key and key not in lookup:
            lookup[key] = candidate

    target_key = _loose_name(target_name)
    if not target_key:
        return []
    if target_key in lookup:
        return [lookup[target_key]]

    matches = get_close_matches(target_key, list(lookup), n=3, cutoff=0.6)
    return [lookup[match] for match in matches]


def _ambiguous_name_message(
    *,
    object_name: str,
    target_name: str,
    parent_name: str | None,
    parent_object_name: str | None,
    candidate_names: list[str],
    update_hint: str,
) -> str:
    label = _object_label(object_name, len(candidate_names))
    parent_text = ""
    if parent_name and parent_object_name:
        parent_text = f" under {parent_object_name} '{parent_name}'"
    return (
        f"DefectDojo {object_name} '{target_name}' matched multiple existing {label} "
        f"after case/whitespace normalization{parent_text}: {_format_name_list(candidate_names)}. "
        f"{update_hint}"
    )


def _not_found_message(
    *,
    object_name: str,
    target_name: str,
    parent_name: str | None,
    parent_object_name: str | None,
    existing_names: list[str],
    suggestions: list[str],
    update_hint: str,
) -> str:
    if parent_name and parent_object_name:
        message = (
            f"DefectDojo {object_name} '{target_name}' was not found "
            f"under {parent_object_name} '{parent_name}'."
        )
    else:
        message = f"DefectDojo {object_name} '{target_name}' was not found."

    existing_names = _dedupe_names(existing_names)
    if existing_names:
        label = _object_label(object_name, len(existing_names))
        if parent_name and parent_object_name:
            message = (
                f"{message} Existing {label} under {parent_object_name} "
                f"'{parent_name}': {_format_name_list(existing_names)}."
            )
        else:
            message = f"{message} Existing {label} in this environment: {_format_name_list(existing_names)}."

    suggestions = _dedupe_names(suggestions)
    if suggestions:
        label = "Closest match" if len(suggestions) == 1 else "Closest matches"
        message = f"{message} {label}: {_format_name_list(suggestions)}."
    message = f"{message} {update_hint}"
    return message


def _loose_name(value: str) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _dedupe_names(names: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for name in names:
        text = _normalize_optional_text(name)
        if not text:
            continue
        key = _loose_name(text)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _object_label(object_name: str, count: int) -> str:
    if count == 1:
        return object_name
    if object_name == "product type":
        return "product types"
    return f"{object_name}s"


def _format_name_list(names: list[str], *, limit: int = 5) -> str:
    visible = names[:limit]
    text = ", ".join(f"'{name}'" for name in visible)
    remaining = len(names) - len(visible)
    if remaining > 0:
        return f"{text}, and {remaining} more"
    return text


def _normalize_optional_text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_optional_int(value: Any, field_name: str) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError as exc:
        raise ValueError(f"DefectDojo upload requires {field_name} to be an integer.") from exc


def _normalize_api_token(value: Any) -> str | None:
    text = _normalize_optional_text(value)
    if not text:
        return None

    if text[:5].lower() == "token" and (len(text) == 5 or text[5].isspace()):
        text = text[5:].strip()

    return text or None


def _bool_string(value: bool) -> str:
    return "true" if value else "false"


def _title_case_severity(value: str | None) -> str:
    mapping = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }
    normalized = str(value or "").strip().lower()
    return mapping.get(normalized, str(value or "Info"))


def _parse_json_response(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _format_upload_http_error(response: httpx.Response, config: DefectDojoConfig) -> str:
    message = _format_http_error(response, secrets=[config.normalized_api_token])
    if config.auto_create_context:
        message = (
            f"{message} auto_create_context=true was sent; if DefectDojo rejected "
            "context creation, verify the token can create Product Types, Products, "
            "Engagements, Tests, and import scans."
        )
    return message


def _format_http_error(
    response: httpx.Response,
    *,
    prefix: str = "DefectDojo upload failed",
    secrets: list[str] | None = None,
) -> str:
    message = (
        f"{prefix}: HTTP {response.status_code} "
        f"for {response.request.method} {_safe_request_url(response.request)}"
    )

    json_payload = _parse_json_response(response)
    details = _extract_json_error_detail(json_payload)
    if details:
        return f"{message}: {_redact_sensitive_text(details, secrets=secrets)}"

    body = response.text.strip()
    if body:
        return f"{message}: {_truncate_text(_redact_sensitive_text(body, secrets=secrets))}"
    return message


def _extract_json_error_detail(payload: Any) -> str | None:
    if payload is None:
        return None
    flattened = _flatten_json_errors(payload)
    if not flattened:
        return _truncate_text(json.dumps(payload, ensure_ascii=False))
    return _truncate_text("; ".join(flattened))


def _flatten_json_errors(payload: Any, *, prefix: str = "") -> list[str]:
    if isinstance(payload, dict):
        messages: list[str] = []
        for key, value in payload.items():
            label = str(key)
            if label in {"detail", "message", "error"}:
                label = ""
            child_prefix = f"{prefix}.{label}".strip(".") if label else prefix
            messages.extend(_flatten_json_errors(value, prefix=child_prefix))
        return messages

    if isinstance(payload, list):
        messages: list[str] = []
        for value in payload:
            messages.extend(_flatten_json_errors(value, prefix=prefix))
        return messages

    text = _normalize_optional_text(payload)
    if not text:
        return []
    return [f"{prefix}: {text}" if prefix else text]


def _truncate_text(value: str, limit: int = 500) -> str:
    text = value.strip()
    if len(text) <= limit:
        return text
    return f"{text[: limit - 3]}..."


def _safe_request_url(request: httpx.Request) -> str:
    url = request.url
    port = f":{url.port}" if url.port is not None else ""
    return f"{url.scheme}://{url.host}{port}{url.path}"


def _redact_sensitive_text(value: str, *, secrets: list[str] | None = None) -> str:
    redacted = re.sub(
        r"(?i)\b(token|api[_-]?key|secret|password)(\s*[:=]\s*)([^,\s}\]]+)",
        r"\1\2[redacted]",
        value,
    )
    for secret in secrets or []:
        if secret and len(secret) >= 4:
            redacted = redacted.replace(secret, "[redacted]")
    return redacted
