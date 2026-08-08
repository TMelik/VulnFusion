"""
Export sanitization helpers for externally visible pipeline outputs.

These helpers strip internal tracing/runtime-only fields while preserving the
public risk fields and scanner-native finding content that belong in exported
results.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, List

from utils.secret_sanitizer import sanitize_secrets


_AI_ANALYSIS_STATUSES = {"completed", "cached", "unavailable", "skipped_limit"}
_APPLICABILITY_STATUSES = {
    "likely_false_positive",
    "valid_but_not_applicable",
    "likely_valid",
    "needs_review",
}
_AI_SUMMARY_STATUSES = {
    "completed",
    "partial",
    "disabled_not_configured",
    "disabled_by_user",
    "unavailable",
}
_SITE_CONTEXT_CRITICALITIES = {"high", "medium", "low", "unknown"}
_SITE_CONTEXT_ENVIRONMENTS = {
    "production", "staging", "development", "test", "unknown"
}
# Must mirror schema.HUMAN_TRIAGE_STATUSES / HUMAN_TRIAGE_SCOPES. Kept as local
# copies to keep this sanitizer self-contained (same pattern as the sets above).
_HUMAN_TRIAGE_STATUSES = {
    "confirmed", "false_positive", "not_applicable", "needs_review"
}
_HUMAN_TRIAGE_SCOPES = {"finding", "site_vuln"}

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


def _safe_correlation_text(value: Any, *, limit: int = 1000) -> str:
    """Return bounded display text for the public correlation contract."""
    return str(value).strip()[:limit] if isinstance(value, str) else ""


def _safe_ai_text(value: Any, *, limit: int = 1000) -> str:
    """Return bounded text for public advisory AI fields."""
    return str(value).strip()[:limit] if isinstance(value, str) else ""


def _safe_ai_string_list(value: Any, *, limit: int = 5, item_limit: int = 500) -> List[str] | None:
    """Return a bounded non-empty string list or None when malformed."""
    if not isinstance(value, list) or not value or len(value) > limit:
        return None
    cleaned = [_safe_ai_text(item, limit=item_limit) for item in value]
    if any(not item for item in cleaned):
        return None
    return cleaned


def _sanitize_applicability(value: Any) -> Dict[str, Any] | None:
    """Whitelist one structured applicability assessment."""
    if not isinstance(value, dict) or set(value) != {
        "status", "confidence", "reason", "evidence_ids"
    }:
        return None
    status = value.get("status")
    confidence = value.get("confidence")
    reason = _safe_ai_text(value.get("reason"))
    evidence_ids = _safe_ai_string_list(value.get("evidence_ids"), limit=20, item_limit=200)
    if (
        status not in _APPLICABILITY_STATUSES
        or isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0.0 <= float(confidence) <= 1.0
        or not reason
        or evidence_ids is None
    ):
        return None
    return {
        "status": status,
        "confidence": float(confidence),
        "reason": reason,
        "evidence_ids": evidence_ids,
    }


def _sanitize_ai_remediation(value: Any) -> Dict[str, Any] | None:
    """Whitelist advisory remediation and verification lists."""
    if not isinstance(value, dict) or set(value) != {"steps", "verification"}:
        return None
    steps = _safe_ai_string_list(value.get("steps"))
    verification = _safe_ai_string_list(value.get("verification"))
    if steps is None or verification is None:
        return None
    return {"steps": steps, "verification": verification}


def _sanitize_ai_priority(value: Any) -> Dict[str, Any] | None:
    """Whitelist one separate advisory priority recommendation."""
    if not isinstance(value, dict) or set(value) != {
        "recommended_priority", "confidence", "reason", "evidence_ids", "context_revision"
    }:
        return None
    priority = value.get("recommended_priority")
    confidence = value.get("confidence")
    reason = _safe_ai_text(value.get("reason"))
    evidence_ids = _safe_ai_string_list(value.get("evidence_ids"), limit=20, item_limit=200)
    context_revision = _safe_ai_text(value.get("context_revision"), limit=200)
    if (
        priority not in {"P0", "P1", "P2", "P3", "P4"}
        or isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0.0 <= float(confidence) <= 1.0
        or not reason
        or evidence_ids is None
        or not context_revision
    ):
        return None
    return {
        "recommended_priority": priority,
        "confidence": float(confidence),
        "reason": reason,
        "evidence_ids": evidence_ids,
        "context_revision": context_revision,
    }


def _sanitize_ai_summary(value: Any) -> Dict[str, Any] | None:
    """Whitelist the bounded consolidated finding summary."""
    if not isinstance(value, dict) or set(value) != {"description", "business_impact", "evidence_ids"}:
        return None
    description = _safe_ai_text(value.get("description"), limit=1500)
    impact = _safe_ai_text(value.get("business_impact"), limit=1000)
    evidence_ids = _safe_ai_string_list(value.get("evidence_ids"), limit=20, item_limit=200)
    if not description or not impact or evidence_ids is None:
        return None
    return {"description": description, "business_impact": impact, "evidence_ids": evidence_ids}


def _sanitize_finding_ai_analysis(cleaned: Dict[str, Any]) -> None:
    """Keep only a coherent public per-finding AI advisory contract."""
    status = cleaned.get("ai_analysis_status")
    if status not in _AI_ANALYSIS_STATUSES:
        cleaned.pop("ai_analysis_status", None)
        cleaned.pop("applicability", None)
        cleaned.pop("ai_remediation", None)
        cleaned.pop("ai_priority", None)
        cleaned.pop("ai_summary", None)
        return

    if status in {"completed", "cached"}:
        applicability = _sanitize_applicability(cleaned.get("applicability"))
        remediation = _sanitize_ai_remediation(cleaned.get("ai_remediation"))
        priority = _sanitize_ai_priority(cleaned.get("ai_priority"))
        summary = _sanitize_ai_summary(cleaned.get("ai_summary"))
        if applicability is None or remediation is None or priority is None or summary is None:
            cleaned.pop("ai_analysis_status", None)
            cleaned.pop("applicability", None)
            cleaned.pop("ai_remediation", None)
            cleaned.pop("ai_priority", None)
            cleaned.pop("ai_summary", None)
            return
        cleaned["applicability"] = applicability
        cleaned["ai_remediation"] = remediation
        cleaned["ai_priority"] = priority
        cleaned["ai_summary"] = summary
        return

    cleaned.pop("applicability", None)
    cleaned.pop("ai_remediation", None)
    cleaned.pop("ai_priority", None)
    cleaned.pop("ai_summary", None)


def _sanitize_finding_human_triage(cleaned: Dict[str, Any]) -> None:
    """Keep only a coherent, bounded public human-triage contract.

    This is a security boundary, not cosmetic: findings are sanitized by
    *blacklist*, so an un-handled ``human_triage`` (comments are attacker-influenced
    free text) would otherwise pass through unbounded and unescaped. Rebuild a
    valid object from whitelisted keys, or drop it entirely — the output must
    satisfy ``schema._validate_human_triage`` at the final and report stages.
    """
    if "human_triage" not in cleaned:
        return
    value = cleaned.get("human_triage")
    if not isinstance(value, dict):
        cleaned.pop("human_triage", None)
        return

    status = value.get("status")
    scope = value.get("scope")
    key = _safe_ai_text(value.get("key"), limit=512)
    reviewer = _safe_ai_text(value.get("reviewer"), limit=100)
    decided_at = _safe_ai_text(value.get("decided_at"), limit=40)
    if (
        status not in _HUMAN_TRIAGE_STATUSES
        or scope not in _HUMAN_TRIAGE_SCOPES
        or not key
        or not reviewer
        or not decided_at.endswith("Z")
    ):
        cleaned.pop("human_triage", None)
        return

    result: Dict[str, Any] = {
        "status": status,
        "scope": scope,
        "key": key,
        "reviewer": reviewer,
        "decided_at": decided_at,
    }
    comment = _safe_ai_text(value.get("comment"), limit=2000)
    if comment:
        result["comment"] = comment
    updated_at = _safe_ai_text(value.get("updated_at"), limit=40)
    if updated_at.endswith("Z"):
        result["updated_at"] = updated_at
    revision = value.get("revision")
    if isinstance(revision, int) and not isinstance(revision, bool) and revision >= 1:
        result["revision"] = revision
    cleaned["human_triage"] = result


def _sanitize_ai_analysis_summary(value: Any) -> Dict[str, Any] | None:
    """Whitelist non-sensitive aggregate LLM analysis diagnostics."""
    if not isinstance(value, dict) or value.get("status") not in _AI_SUMMARY_STATUSES:
        return None
    cleaned: Dict[str, Any] = {"status": value["status"]}
    model = _safe_ai_text(value.get("model"), limit=200)
    if model:
        cleaned["model"] = model
    prompt_version = _safe_ai_text(value.get("prompt_version"), limit=100)
    if prompt_version:
        cleaned["prompt_version"] = prompt_version
    for key in (
        "limit",
        "selected_count",
        "analyzed_count",
        "cached_count",
        "unavailable_count",
        "skipped_limit_count",
        "needs_review_count",
        "priority_disagreement_count",
        "redaction_count",
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
    ):
        item = value.get(key)
        if isinstance(item, int) and not isinstance(item, bool) and item >= 0:
            cleaned[key] = item
    latency_ms = value.get("latency_ms")
    if (
        isinstance(latency_ms, (int, float))
        and not isinstance(latency_ms, bool)
        and float(latency_ms) >= 0.0
    ):
        cleaned["latency_ms"] = round(float(latency_ms), 3)
    cost = value.get("estimated_cost_usd")
    if cost is None:
        cleaned["estimated_cost_usd"] = None
    elif isinstance(cost, (int, float)) and not isinstance(cost, bool) and float(cost) >= 0.0:
        cleaned["estimated_cost_usd"] = round(float(cost), 8)
    return cleaned


def _sanitize_site_risk_context(value: Any) -> Dict[str, Any] | None:
    """Whitelist the human-confirmed risk proposal stored in a site profile."""
    expected = {
        "asset_criticality", "environment", "sensitive_data", "requires_auth",
        "confidence", "reason", "evidence_ids",
    }
    if not isinstance(value, dict) or set(value) != expected:
        return None
    criticality = value.get("asset_criticality")
    environment = value.get("environment")
    confidence = value.get("confidence")
    if criticality not in _SITE_CONTEXT_CRITICALITIES or environment not in _SITE_CONTEXT_ENVIRONMENTS:
        return None
    if any(value.get(key) is not None and not isinstance(value.get(key), bool) for key in ("sensitive_data", "requires_auth")):
        return None
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0.0 <= float(confidence) <= 1.0:
        return None
    reason = _safe_ai_text(value.get("reason"), limit=500)
    raw_evidence_ids = value.get("evidence_ids")
    evidence_ids = None
    if isinstance(raw_evidence_ids, list) and len(raw_evidence_ids) <= 20:
        candidate_ids = [_safe_ai_text(item, limit=200) for item in raw_evidence_ids]
        if all(candidate_ids):
            evidence_ids = candidate_ids
    if not reason or evidence_ids is None:
        return None
    return {
        "asset_criticality": criticality,
        "environment": environment,
        "sensitive_data": value.get("sensitive_data"),
        "requires_auth": value.get("requires_auth"),
        "confidence": float(confidence),
        "reason": reason,
        "evidence_ids": evidence_ids,
    }


def _sanitize_asset_knowledge(value: Any) -> Dict[str, Any] | None:
    """Keep only bounded display fields from the per-site OKF profile reference."""
    if not isinstance(value, dict):
        return None
    description = _safe_ai_text(value.get("description"), limit=1000)
    reviewer = _safe_ai_text(value.get("reviewer"), limit=100)
    revision = _safe_ai_text(value.get("profile_revision"), limit=128)
    if not description or not reviewer or not revision:
        return None
    cleaned: Dict[str, Any] = {
        "description": description,
        "reviewer": reviewer,
        "profile_revision": revision,
    }
    analysis_source = _safe_ai_text(value.get("analysis_source"), limit=50)
    if analysis_source:
        cleaned["analysis_source"] = analysis_source
    processes = value.get("business_processes")
    if isinstance(processes, list) and processes:
        safe_processes = _safe_ai_string_list(processes, limit=5, item_limit=300)
        if safe_processes is not None:
            cleaned["business_processes"] = safe_processes
    risk_context = _sanitize_site_risk_context(value.get("risk_context"))
    if risk_context is not None:
        cleaned["risk_context"] = risk_context
    return cleaned


def _sanitize_correlation(value: Any) -> Dict[str, Any] | None:
    """Whitelist the structured LLM correlation shape used by the UI."""
    if not isinstance(value, dict):
        return None
    status = value.get("status")
    if status not in {"merged", "needs_review"} or value.get("source") != "llm":
        return None
    confidence = value.get("confidence")
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        return None
    confidence = float(confidence)
    if not 0.0 <= confidence <= 1.0:
        return None

    review_candidates: List[Dict[str, Any]] = []
    candidates = value.get("review_candidates")
    if isinstance(candidates, list):
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            candidate_confidence = candidate.get("confidence")
            if (
                isinstance(candidate_confidence, bool)
                or not isinstance(candidate_confidence, (int, float))
                or not 0.0 <= float(candidate_confidence) <= 1.0
            ):
                continue
            scanners = candidate.get("scanners")
            review_candidates.append(
                {
                    "finding_id": _safe_correlation_text(candidate.get("finding_id"), limit=200),
                    "vulnerability_name": _safe_correlation_text(
                        candidate.get("vulnerability_name"), limit=500
                    ),
                    "scanners": sorted(
                        {
                            _safe_correlation_text(scanner, limit=100)
                            for scanner in scanners
                            if isinstance(scanner, str) and scanner.strip()
                        }
                    )
                    if isinstance(scanners, list)
                    else [],
                    "confidence": float(candidate_confidence),
                    "reason": _safe_correlation_text(candidate.get("reason")),
                    "canonical_title": _safe_correlation_text(
                        candidate.get("canonical_title"), limit=500
                    ),
                }
            )

    review_candidates.sort(
        key=lambda candidate: (
            candidate["finding_id"],
            candidate["confidence"],
            candidate["canonical_title"],
        )
    )
    return {
        "status": status,
        "source": "llm",
        "confidence": confidence,
        "reason": _safe_correlation_text(value.get("reason")),
        "canonical_title": _safe_correlation_text(value.get("canonical_title"), limit=500),
        "needs_review": bool(value.get("needs_review")),
        "review_candidates": review_candidates,
    }


def sanitize_finding_for_export(finding: Any) -> Dict[str, Any] | Any:
    """Strip non-scanner-derived fields from one externally visible finding."""
    if not isinstance(finding, dict):
        return finding

    cleaned = deepcopy(finding)
    for key in _FORBIDDEN_FINDING_KEYS:
        cleaned.pop(key, None)

    cleaned["meta"] = _sanitize_meta(cleaned.get("meta"))
    _sanitize_finding_ai_analysis(cleaned)
    _sanitize_finding_human_triage(cleaned)

    if "correlation" in cleaned:
        correlation = _sanitize_correlation(cleaned.get("correlation"))
        if correlation is None:
            cleaned.pop("correlation", None)
        else:
            cleaned["correlation"] = correlation

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

    if "ai_analysis_summary" in export:
        summary = _sanitize_ai_analysis_summary(export.get("ai_analysis_summary"))
        if summary is None:
            export.pop("ai_analysis_summary", None)
        else:
            export["ai_analysis_summary"] = summary

    if "asset_knowledge" in export:
        asset_knowledge = _sanitize_asset_knowledge(export.get("asset_knowledge"))
        if asset_knowledge is None:
            export.pop("asset_knowledge", None)
        else:
            export["asset_knowledge"] = asset_knowledge

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

    sanitized = sanitize_secrets(export).value
    return sanitized if isinstance(sanitized, dict) else {}


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
