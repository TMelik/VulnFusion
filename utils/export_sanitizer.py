"""
Export sanitization helpers for externally visible pipeline outputs.

These helpers strip internal tracing/runtime-only fields while preserving the
public risk fields and scanner-native finding content that belong in exported
results.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List


_FORBIDDEN_RESULT_KEYS = {
    "asset_criticality",
    "business_context",
    "duplicate_analysis",
    "llm_duplicate_comparisons",
    "previous_findings",
    "scanner_instances",
    "scanner_execution",
    "scoring_context",
    "scan_plan",
    "discovery",
    "target_probe",
    "target_probes",
    "transport_detected",
}

_FORBIDDEN_FINDING_KEYS = {
    "asset_criticality",
    "business_context",
    "change_details",
    "comparison_mode",
    "comparison_match_reasons",
    "comparison_match_score",
    "comparison_uncertainty",
    "confidence_boost",
    "degraded_execution",
    "duplicate_count",
    "environment",
    "evidence_quality",
    "finding_id",
    "fp_general",
    "fp_host_only",
    "fp_strict",
    "impact_for_developers",  # generated prose must not replace scanner-native descriptions
    "importance",
    "internet_exposed",
    "match_level",
    "merge_confidence",
    "normalized_name",
    "previous_match_id",
    "previous_values",
    "requires_auth",
    "sensitive_data",
    "status_info",
}

_FORBIDDEN_META_KEYS = {
    "business_context",
    "confirmation_scanners",
    "cve_intelligence_candidates",
    "cvss_score",
    "cvss_source",
    "cvss_vector",
    "cvss_version",
    "degraded_execution",
    "degraded_scanners",
    "duplicate_resolution_mode",
    "epss_score",
    "epss_percentile",
    "epss_source",
    "evidence_quality",
    "has_multi_scanner_confirmation",
    "kev",
    "kev_due_date",
    "kev_listed",
    "kev_source",
    "merged",
    "original_findings_count",
    "scanner_instance",
    "scanners",
}

_FORBIDDEN_SOURCE_KEYS = {
    "comparison_mode",
    "degraded_execution",
    "finding_id",
    "fp_general",
    "fp_host_only",
    "fp_strict",
}


def _sanitize_meta(meta: Any) -> Dict[str, Any]:
    """Return scanner metadata without derived/enrichment-only fields."""
    if not isinstance(meta, dict):
        return {}

    cleaned = deepcopy(meta)
    for key in _FORBIDDEN_META_KEYS:
        cleaned.pop(key, None)
    return cleaned


def _sanitize_source_record(record: Any) -> Dict[str, Any] | None:
    """Return one preserved source record in export-safe shape."""
    if not isinstance(record, dict):
        return None

    cleaned = deepcopy(record)
    for key in _FORBIDDEN_SOURCE_KEYS:
        cleaned.pop(key, None)

    cleaned["meta"] = _sanitize_meta(cleaned.get("meta"))
    return cleaned


def sanitize_finding_for_export(finding: Any) -> Dict[str, Any] | Any:
    """Strip non-scanner-derived fields from one externally visible finding."""
    if not isinstance(finding, dict):
        return finding

    cleaned = deepcopy(finding)
    for key in _FORBIDDEN_FINDING_KEYS:
        cleaned.pop(key, None)

    cleaned["meta"] = _sanitize_meta(cleaned.get("meta"))

    source_findings = cleaned.get("source_findings")
    if isinstance(source_findings, list):
        cleaned["source_findings"] = [
            source
            for source in (_sanitize_source_record(source) for source in source_findings)
            if source is not None
        ]

    return cleaned


def _sanitize_finding_list(values: Any) -> List[Any]:
    """Sanitize one list of finding-like records."""
    if not isinstance(values, list):
        return []
    return [sanitize_finding_for_export(value) for value in values]


def sanitize_results_for_export(results: Dict[str, Any]) -> Dict[str, Any]:
    """Return an export-safe copy of a pipeline result payload."""
    export = deepcopy(results)

    for key in _FORBIDDEN_RESULT_KEYS:
        export.pop(key, None)

    if "all_findings" in export:
        export["all_findings"] = _sanitize_finding_list(export.get("all_findings"))

    findings_by_scanner = export.get("findings_by_scanner")
    if isinstance(findings_by_scanner, dict):
        export["findings_by_scanner"] = {
            str(scanner): _sanitize_finding_list(findings)
            for scanner, findings in findings_by_scanner.items()
        }

    for key in (
        "fixed_findings",
        "changed_findings",
        "partial_unmatched_current_findings",
        "partial_unmatched_previous_findings",
    ):
        if key in export:
            export[key] = _sanitize_finding_list(export.get(key))

    return export


def iter_forbidden_export_fields(results: Dict[str, Any]) -> Iterable[str]:
    """Yield dotted field paths that violate the external export contract."""
    if not isinstance(results, dict):
        return []

    violations: List[str] = []

    for key in sorted(_FORBIDDEN_RESULT_KEYS):
        if key in results:
            violations.append(key)

    def _visit_finding(prefix: str, finding: Any) -> None:
        if not isinstance(finding, dict):
            return

        for key in sorted(_FORBIDDEN_FINDING_KEYS):
            if key in finding:
                violations.append(f"{prefix}.{key}")

        meta = finding.get("meta")
        if isinstance(meta, dict):
            for key in sorted(_FORBIDDEN_META_KEYS):
                if key in meta:
                    violations.append(f"{prefix}.meta.{key}")

        source_findings = finding.get("source_findings")
        if isinstance(source_findings, list):
            for index, source in enumerate(source_findings):
                if not isinstance(source, dict):
                    continue
                for key in sorted(_FORBIDDEN_SOURCE_KEYS):
                    if key in source:
                        violations.append(f"{prefix}.source_findings[{index}].{key}")
                source_meta = source.get("meta")
                if isinstance(source_meta, dict):
                    for key in sorted(_FORBIDDEN_META_KEYS):
                        if key in source_meta:
                            violations.append(f"{prefix}.source_findings[{index}].meta.{key}")

    for index, finding in enumerate(results.get("all_findings", []) if isinstance(results.get("all_findings"), list) else []):
        _visit_finding(f"all_findings[{index}]", finding)

    findings_by_scanner = results.get("findings_by_scanner")
    if isinstance(findings_by_scanner, dict):
        for scanner, findings in findings_by_scanner.items():
            if not isinstance(findings, list):
                continue
            for index, finding in enumerate(findings):
                _visit_finding(f"findings_by_scanner.{scanner}[{index}]", finding)

    for key in (
        "fixed_findings",
        "changed_findings",
        "partial_unmatched_current_findings",
        "partial_unmatched_previous_findings",
    ):
        values = results.get(key)
        if not isinstance(values, list):
            continue
        for index, finding in enumerate(values):
            _visit_finding(f"{key}[{index}]", finding)

    return violations
