"""
LLM-backed duplicate resolution for cross-scanner findings.

The legacy deterministic deduplicator remains in the codebase, but this module
owns the active cross-scanner duplicate flow:
- suppress non-actionable adapter artifacts
- identify same-target cross-scanner finding pairs
- run one provider health check before live comparison batches
- query an LLM for a strict structured decision
- capture safe provider diagnostics for failed calls
- cache comparison results
- merge only cross-scanner clusters approved by high-confidence decisions
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import re
import time
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import httpx

from utils.deduplicator import (
    is_degraded_finding,
    merge_deterministic_cluster,
    merge_obvious_duplicates,
)
from utils.normalizer import (
    canonical_path,
    canonical_query,
    is_adapter_transport_artifact,
    normalize_vulnerability_name,
    parse_target,
)
from utils.result_summary import refresh_summary_counts
from utils.schema import sort_by_severity
from utils.secret_sanitizer import sanitize_secrets
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase, utcnow_iso


logger = logging.getLogger(__name__)
RETRYABLE_PROVIDER_STATUS_CODES = {429, 500, 502, 503, 504}
PROVIDER_MAX_RETRIES = 2
PROVIDER_RETRY_BACKOFF_BASE_SECONDS = 0.25
PROVIDER_RETRY_BACKOFF_CAP_SECONDS = 2.0
# After two live 5xx/provider-unavailable failures in one run, stop spending
# more duplicate-comparison calls on a provider that appears broadly unhealthy.
PROVIDER_UNAVAILABLE_DISABLE_THRESHOLD = 2
LLM_DUPLICATE_PROMPT_VERSION = 2
LLM_DUPLICATE_CACHE_SEMANTICS_VERSION = 3
LLM_DUPLICATE_MERGE_CONFIDENCE_THRESHOLD = 0.85
CHEAP_SIMILARITY_GENERIC_TITLE_TOKENS = {
    "configuration",
    "content",
    "detected",
    "finding",
    "header",
    "headers",
    "issue",
    "missing",
    "options",
    "policy",
    "protection",
    "security",
    "vulnerability",
}
DETERMINISTIC_HEADER_FAMILIES = {
    "missing clickjacking protection header",
    "missing content security policy header",
    "missing frame ancestors directive",
    "missing x content type options header",
}
DETERMINISTIC_PARAMETERIZED_FAMILY_TOKEN_RULES = {
    "command injection": {"command", "injection"},
    "server side template injection": {"server", "side", "template", "injection"},
    "sql injection": {"sql", "injection"},
    "xml external entity": {"xml", "external", "entity"},
}
LLM_DUPLICATE_COMPARISON_QUESTION = (
    "Do these two scanner findings describe the same underlying vulnerability "
    "on the same target?"
)
LLM_DUPLICATE_DECISION_FIELDS = {
    "same_vulnerability",
    "confidence",
    "reason",
    "canonical_title",
}
PROFILE_STAGE_KEYS = (
    "same_scanner_exact_premerge_seconds",
    "deterministic_cross_scanner_premerge_seconds",
    "candidate_pair_generation_seconds",
    "same_target_filtering_seconds",
    "cheap_similarity_gate_seconds",
    "gray_zone_compare_loop_seconds",
    "final_merge_materialization_seconds",
    "summary_recompute_seconds",
)
@dataclass
class _FindingRuntimeCache:
    """Per-run memoization for derived finding fields used in hot loops."""

    values: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def _finding_key(self, finding: Dict[str, Any]) -> str:
        finding_id = finding.get("finding_id")
        if finding_id is not None:
            return f"finding::{finding_id}"
        return f"object::{id(finding)}"

    def get_or_set(
        self,
        namespace: str,
        finding: Dict[str, Any],
        factory,
    ) -> Any:
        bucket = self.values.setdefault(namespace, {})
        key = self._finding_key(finding)
        if key in bucket:
            return bucket[key]
        value = factory()
        bucket[key] = value
        return value


@dataclass
class _DedupStageProfiler:
    """Accumulate lightweight per-stage timings for one resolver run."""

    stage_seconds: Dict[str, float] = field(
        default_factory=lambda: {key: 0.0 for key in PROFILE_STAGE_KEYS}
    )

    def add(self, stage: str, duration_seconds: float) -> None:
        if stage not in self.stage_seconds:
            self.stage_seconds[stage] = 0.0
        self.stage_seconds[stage] += max(0.0, duration_seconds)

    def snapshot(self, *, total_runtime_seconds: float) -> Dict[str, float]:
        profile = {
            key: round(value, 6)
            for key, value in self.stage_seconds.items()
        }
        profile["total_runtime_seconds"] = round(max(0.0, total_runtime_seconds), 6)
        return profile


def _initial_provider_state() -> Dict[str, Any]:
    """Return clean per-run provider diagnostic state."""
    return {
        "healthcheck_status": "not_run",
        "healthcheck_error": None,
        "healthcheck_payload": None,
        "disabled_reason": None,
        "disabled_error": None,
        "disabled_category": None,
        "disabled_http_status_code": None,
        "live_attempted": 0,
        "live_succeeded": 0,
        "live_failed": 0,
        "skipped_due_to_provider_state": 0,
        "rate_limit_encountered": False,
        "provider_disabled_mid_run": False,
        "failure_categories": {},
    }


@dataclass
class _ResolverRunContext:
    """Mutable state that belongs to exactly one resolver apply() call."""

    runtime_cache: _FindingRuntimeCache = field(default_factory=_FindingRuntimeCache)
    provider_state: Dict[str, Any] = field(default_factory=_initial_provider_state)
    profiler: _DedupStageProfiler = field(default_factory=_DedupStageProfiler)
    runtime_started_at: float = field(default_factory=time.perf_counter)


@dataclass(frozen=True)
class LLMDuplicateDecision:
    """Strict provider decision for one duplicate candidate pair."""

    same_vulnerability: bool
    confidence: float
    reason: str
    canonical_title: str

    def __post_init__(self) -> None:
        if not isinstance(self.same_vulnerability, bool):
            raise TypeError("same_vulnerability must be boolean")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, float):
            raise TypeError("confidence must be a float")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a string")
        if not isinstance(self.canonical_title, str):
            raise TypeError("canonical_title must be a string")

    @property
    def llm_decision(self) -> str:
        """Return the legacy metric label retained for compatibility."""
        return "yes" if self.same_vulnerability else "no"

    @property
    def merge_approved(self) -> bool:
        """Return whether this decision is strong enough to merge."""
        return bool(
            self.same_vulnerability
            and self.confidence >= LLM_DUPLICATE_MERGE_CONFIDENCE_THRESHOLD
        )

    @property
    def needs_review(self) -> bool:
        """Return whether a positive but uncertain decision needs review."""
        return bool(self.same_vulnerability and not self.merge_approved)


def _runtime_cache_get_or_set(
    namespace: str,
    finding: Dict[str, Any],
    factory,
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Any:
    """Return one cached derived finding value when a run-local cache is active."""
    if runtime_cache is None:
        return factory()
    return runtime_cache.get_or_set(namespace, finding, factory)


def _default_port(scheme: str) -> Optional[int]:
    """Return the default port for a known web scheme."""
    scheme = str(scheme or "").lower()
    if scheme == "https":
        return 443
    if scheme == "http":
        return 80
    return None


def _coerce_port(value: Any) -> Optional[int]:
    """Convert a scalar value to an integer port when possible."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _ordered_unique(values: Iterable[Any]) -> List[Any]:
    """Return first-seen unique values."""
    results: List[Any] = []
    seen: set[str] = set()
    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        results.append(value)
    return results


def _meta(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return finding metadata as a dict."""
    meta = finding.get("meta", {})
    return meta if isinstance(meta, dict) else {}


def _scanner_name(finding: Dict[str, Any]) -> str:
    """Return the source scanner name for a finding."""
    return str(_meta(finding).get("scanner") or "unknown").strip().lower()


def _finding_severity_rank(finding: Dict[str, Any]) -> int:
    """Convert severity labels into comparable ranks."""
    ranks = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    return ranks.get(str(finding.get("severity") or "info").lower(), 0)


def _safe_text(value: Any) -> str:
    """Return a display-safe compact string."""
    return str(value or "").strip()


def _looks_like_shell_variable_reference(value: Any) -> bool:
    """Return True when a config value looks like ``$NAME`` or ``${NAME}``."""
    return _safe_text(value).startswith("$")


def _looks_like_api_key(value: Any) -> bool:
    """Return True when a config value resembles a secret token, not a model id."""
    text = _safe_text(value).lower()
    if not text:
        return False
    return text.startswith((
        "gsk_",
        "sk-",
        "sk_",
        "ghp_",
        "github_pat_",
        "hf_",
        "xoxb-",
        "xoxp-",
        "ya29.",
    ))


def mask_secret(value: Optional[str]) -> Optional[str]:
    """Return a masked display-safe form of a secret."""
    text = _safe_text(value)
    if not text:
        return None
    if len(text) <= 4:
        return "***"
    return f"***{text[-4:]}"


def _json_text(value: Any) -> str:
    """Return a stable JSON string for structured provider payloads."""
    try:
        return json.dumps(value, sort_keys=True, ensure_ascii=True, default=str)
    except TypeError:
        return _safe_text(value)


def _truncate_request_preview(value: Any, *, max_text: int = 240) -> Any:
    """Return a bounded preview after secret sanitization."""
    if isinstance(value, dict):
        preview: Dict[str, Any] = {}
        for key, item in value.items():
            if key == "messages" and isinstance(item, list):
                preview[key] = [
                    {
                        "role": _safe_text(message.get("role")) if isinstance(message, dict) else None,
                        "content": (
                            _safe_text(message.get("content"))[:max_text]
                            if isinstance(message, dict)
                            else _safe_text(message)[:max_text]
                        ),
                    }
                    for message in item[:4]
                ]
                continue
            preview[key] = _truncate_request_preview(item, max_text=max_text)
        return preview
    if isinstance(value, list):
        return [_truncate_request_preview(item, max_text=max_text) for item in value[:10]]
    if isinstance(value, str):
        return value[:max_text]
    return value


def _safe_request_preview(value: Any, *, max_text: int = 240) -> Any:
    """Return a secret-free, bounded provider request preview."""
    return _truncate_request_preview(sanitize_secrets(value).value, max_text=max_text)


def _response_json_or_none(response: Any) -> Any:
    """Parse JSON from an HTTP response when possible."""
    try:
        return response.json()
    except (AttributeError, ValueError, TypeError):
        return None


def _extract_provider_message(response_json: Any, response_text: str) -> str:
    """Extract the most useful provider error text available."""
    if isinstance(response_json, dict):
        error = response_json.get("error")
        if isinstance(error, dict):
            for key in ("message", "status", "code"):
                text = _safe_text(error.get(key))
                if text:
                    return text
        if isinstance(error, str) and _safe_text(error):
            return _safe_text(error)
        for key in ("message", "detail", "status"):
            text = _safe_text(response_json.get(key))
            if text:
                return text
    if isinstance(response_json, list):
        text = _safe_text(_json_text(response_json))
        if text:
            return text
    return _safe_text(response_text)


def _classify_provider_failure(
    *,
    http_status_code: Optional[int] = None,
    response_text: str = "",
    response_json: Any = None,
    exception: Optional[BaseException] = None,
) -> str:
    """Conservatively classify provider failures for auditing and skip logic."""
    if isinstance(exception, (TimeoutError, httpx.TimeoutException)):
        return "timeout"
    if isinstance(exception, httpx.RequestError):
        return "provider_unavailable"

    body = f"{_json_text(response_json)} {_safe_text(response_text)}".lower()
    if http_status_code == 429 or "resource_exhausted" in body or "rate limit" in body:
        return "rate_limited"
    if http_status_code in {401, 403} or any(term in body for term in ("permission denied", "forbidden", "not authorized", "unauthorized")):
        return "permission_denied"
    if any(term in body for term in ("deadline exceeded", "timed out", "timeout")):
        return "timeout"
    if http_status_code and http_status_code >= 500:
        return "provider_unavailable"
    if http_status_code == 400:
        if any(
            term in body for term in (
                "billing",
                "billable",
                "free tier",
                "free-tier",
                "payment",
                "quota project",
                "location",
                "region",
                "country",
                "not available",
                "not enabled",
                "precondition",
            )
        ):
            return "billing_or_region_issue"
        return "invalid_request"
    if any(term in body for term in ("unavailable", "overloaded", "temporarily unavailable")):
        return "provider_unavailable"
    return "unknown_provider_error"


@dataclass
class LLMProviderError(Exception):
    """Structured provider failure raised by the OpenAI-compatible client."""

    message: str
    category: str
    retryable: bool = False
    http_status_code: Optional[int] = None
    response_text: Optional[str] = None
    response_json: Any = None
    request_hash: Optional[str] = None
    request_kind: str = "comparison"
    request_url: Optional[str] = None
    request_preview: Any = None
    attempt_count: int = 1
    retry_backoff_seconds: List[float] = field(default_factory=list)

    def __str__(self) -> str:
        return self.message

    def to_trace_payload(self) -> Dict[str, Any]:
        """Return safe structured details for traces and persistence."""
        return {
            "category": self.category,
            "retryable": self.retryable,
            "http_status_code": self.http_status_code,
            "attempt_count": self.attempt_count,
            "retry_backoff_seconds": list(self.retry_backoff_seconds),
            "request_hash": self.request_hash,
            "request_kind": self.request_kind,
            "request_url": self.request_url,
            "request_preview": self.request_preview,
            "response_text": self.response_text,
            "response_json": self.response_json,
        }


def _provider_error_summary(
    *,
    category: str,
    http_status_code: Optional[int],
    response_json: Any,
    response_text: str,
) -> str:
    """Build a concise one-line provider error summary."""
    message = _extract_provider_message(response_json, response_text)
    prefix = f"HTTP {http_status_code} " if http_status_code is not None else ""
    if message:
        return f"{prefix}{category}: {message}"
    return f"{prefix}{category}"


def _coerce_provider_error(
    exc: BaseException,
    *,
    request_kind: str,
    request_hash: Optional[str] = None,
) -> LLMProviderError:
    """Normalize arbitrary request exceptions into structured provider errors."""
    if isinstance(exc, LLMProviderError):
        return exc

    category = _classify_provider_failure(exception=exc)
    if category == "timeout":
        message = "LLM provider request timed out."
    elif category == "provider_unavailable":
        message = f"LLM provider request failed: {exc}"
    else:
        message = f"LLM provider error: {exc}"
    return LLMProviderError(
        message=message,
        category=category,
        retryable=False,
        request_hash=request_hash,
        request_kind=request_kind,
    )


def resolve_llm_duplicate_provider_settings(
    *,
    cli_api_url: Optional[str],
    cli_api_key: Optional[str],
    cli_model_name: Optional[str],
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, Optional[str]]:
    """Resolve provider settings with CLI > VULN_MANAGER_LLM_* precedence."""
    env_map = env or {}

    api_key = (
        _safe_text(cli_api_key)
        or _safe_text(env_map.get("VULN_MANAGER_LLM_API_KEY"))
    ) or None

    api_url = normalize_llm_provider_url(
        _safe_text(cli_api_url)
        or _safe_text(env_map.get("VULN_MANAGER_LLM_API_URL"))
    )

    model_name = (
        _safe_text(cli_model_name)
        or _safe_text(env_map.get("VULN_MANAGER_LLM_MODEL"))
    ) or None

    return {
        "api_url": api_url,
        "api_key": api_key,
        "model_name": model_name,
    }


def normalize_llm_provider_url(api_url: Optional[str]) -> Optional[str]:
    """Normalize a provider base URL into a chat-completions endpoint."""
    normalized = _safe_text(api_url).rstrip("/")
    if not normalized:
        return None
    if normalized.endswith("/chat/completions"):
        return normalized
    return f"{normalized}/chat/completions"


def _sha256_text(text: str) -> str:
    """Hash a string into a hex digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _string_list(value: Any) -> List[str]:
    """Normalize a scalar-or-list input into a compact string list."""
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    return [text for text in (_safe_text(item) for item in items) if text]


def _normalized_title(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> str:
    """Return the normalized vulnerability title used by the cheap filter."""
    return _runtime_cache_get_or_set(
        "normalized_title",
        finding,
        lambda: normalize_vulnerability_name(_safe_text(finding.get("vulnerability_name"))),
        runtime_cache=runtime_cache,
    )


def _token_set(text: str) -> set[str]:
    """Split normalized text into a non-empty token set."""
    return {token for token in str(text or "").split() if token}


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    """Return Jaccard similarity for two token sets."""
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _meaningful_title_tokens(tokens: set[str]) -> set[str]:
    """Drop boilerplate title words that should not justify an LLM comparison."""
    return {
        token
        for token in tokens
        if token
        and token not in CHEAP_SIMILARITY_GENERIC_TITLE_TOKENS
    }


def _uppercase_set(values: Iterable[str]) -> set[str]:
    """Normalize identifier strings into an uppercase set."""
    return {
        _safe_text(value).upper()
        for value in values
        if _safe_text(value)
    }


def _normalized_string_set(values: Iterable[str]) -> set[str]:
    """Normalize descriptive strings into a lowercase family set."""
    normalized: set[str] = set()
    for value in values:
        text = _safe_text(value)
        if not text:
            continue
        normalized_value = normalize_vulnerability_name(text) or text.lower()
        if normalized_value:
            normalized.add(normalized_value)
    return normalized


def _finding_cves(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return all CVE identifiers associated with a finding."""
    return _runtime_cache_get_or_set(
        "finding_cves",
        finding,
        lambda: _uppercase_set(
            [*_string_list(_meta(finding).get("cve_ids")), _meta(finding).get("cve_id")]
        ),
        runtime_cache=runtime_cache,
    )


def _finding_cwes(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return all CWE identifiers associated with a finding."""
    return _runtime_cache_get_or_set(
        "finding_cwes",
        finding,
        lambda: _uppercase_set(
            [*_string_list(_meta(finding).get("cwe_list")), _meta(finding).get("cwe")]
        ),
        runtime_cache=runtime_cache,
    )


def _finding_category_hints(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return normalized category/family hints from scanner metadata."""
    def factory() -> set[str]:
        meta = _meta(finding)
        values: List[str] = []
        values.extend(_string_list(meta.get("category")))
        values.extend(_string_list(meta.get("tags")))
        values.extend(_string_list(meta.get("risk")))
        values.extend(_string_list(meta.get("module")))
        return _normalized_string_set(values)

    return _runtime_cache_get_or_set(
        "finding_category_hints",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def _finding_technology_hints(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return normalized technology/service hints from scanner metadata."""
    def factory() -> set[str]:
        meta = _meta(finding)
        return _normalized_string_set([
            *_string_list(meta.get("technology")),
            *_string_list(meta.get("service")),
            *_string_list(meta.get("service_version")),
        ])

    return _runtime_cache_get_or_set(
        "finding_technology_hints",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def _finding_identity_hints(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return stable scanner/plugin/template identifiers that hint at finding identity."""
    def factory() -> set[str]:
        meta = _meta(finding)
        values = [
            *_string_list(meta.get("plugin_id")),
            *_string_list(meta.get("template_id")),
            *_string_list(meta.get("raw_id")),
            *_string_list(meta.get("raw_ids")),
        ]
        return {
            value.lower()
            for value in values
            if value
            and value.lower() not in {"unknown", "generic", "finding"}
        }

    return _runtime_cache_get_or_set(
        "finding_identity_hints",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def _deterministic_family_candidates(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> set[str]:
    """Return strict scanner-independent families eligible for deterministic merge."""
    def factory() -> set[str]:
        candidates: set[str] = set()
        family_hints = {
            _normalized_title(finding, runtime_cache=runtime_cache),
            *_finding_category_hints(finding, runtime_cache=runtime_cache),
        }
        for family_hint in family_hints:
            if not family_hint or family_hint == "internal server error":
                continue
            if family_hint in DETERMINISTIC_HEADER_FAMILIES:
                candidates.add(family_hint)
                continue
            hint_tokens = _token_set(family_hint)
            for family, required_tokens in DETERMINISTIC_PARAMETERIZED_FAMILY_TOKEN_RULES.items():
                if required_tokens.issubset(hint_tokens):
                    candidates.add(family)
        return candidates

    return _runtime_cache_get_or_set(
        "deterministic_family_candidates",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def _deterministic_effective_target_anchor(ctx: Dict[str, Any]) -> Optional[Tuple[str, str, Optional[int]]]:
    """Return a strict target anchor for deterministic same-target matching."""
    host = _safe_text(ctx.get("host")).lower()
    target_family = _safe_text(ctx.get("target_family")).lower()
    if not host or not target_family:
        return None
    return (host, target_family, ctx.get("port"))


def _deterministic_path_anchor(
    ctx: Dict[str, Any],
) -> Optional[Tuple[str, str, Optional[int], str]]:
    """Return a path-level anchor for deterministic same-endpoint matching."""
    base = _deterministic_effective_target_anchor(ctx)
    if base is None:
        return None
    return base + (_safe_text(ctx.get("path")),)


def _deterministic_parameter_anchor(
    ctx: Dict[str, Any],
) -> Optional[Tuple[str, str, Optional[int], str, str, str]]:
    """Return a strict endpoint anchor for parameter-sensitive issue families."""
    base = _deterministic_path_anchor(ctx)
    if base is None:
        return None
    parameter = _safe_text(ctx.get("parameter")).lower()
    method = _safe_text(ctx.get("method")).upper()
    if not parameter or not method:
        return None
    return base + (parameter, method)


def _deterministic_cross_scanner_match(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Optional[Dict[str, Any]]:
    """Return deterministic cross-scanner merge evidence for only obvious duplicates."""
    if _scanner_name(finding_a) == _scanner_name(finding_b):
        return None
    if is_degraded_finding(finding_a) or is_degraded_finding(finding_b):
        return None

    same_target, _ = findings_share_same_target(
        finding_a,
        finding_b,
        runtime_cache=runtime_cache,
    )
    if not same_target:
        return None

    ctx_a = target_context(finding_a, runtime_cache=runtime_cache)
    ctx_b = target_context(finding_b, runtime_cache=runtime_cache)

    shared_cves = sorted(
        _finding_cves(finding_a, runtime_cache=runtime_cache)
        & _finding_cves(finding_b, runtime_cache=runtime_cache)
    )
    if (
        shared_cves
        and _deterministic_effective_target_anchor(ctx_a)
        and _deterministic_effective_target_anchor(ctx_a) == _deterministic_effective_target_anchor(ctx_b)
    ):
        return {
            "reason": "same_cve_same_effective_target",
            "shared_cves": shared_cves,
        }

    shared_families = sorted(
        _deterministic_family_candidates(finding_a, runtime_cache=runtime_cache)
        & _deterministic_family_candidates(finding_b, runtime_cache=runtime_cache)
    )
    if not shared_families:
        return None

    shared_header_families = [
        family for family in shared_families
        if family in DETERMINISTIC_HEADER_FAMILIES
    ]
    if (
        shared_header_families
        and _deterministic_path_anchor(ctx_a)
        and _deterministic_path_anchor(ctx_a) == _deterministic_path_anchor(ctx_b)
    ):
        return {
            "reason": "same_header_family_same_endpoint",
            "shared_families": shared_header_families,
        }

    shared_parameterized_families = [
        family for family in shared_families
        if family in DETERMINISTIC_PARAMETERIZED_FAMILY_TOKEN_RULES
    ]
    if (
        shared_parameterized_families
        and _deterministic_parameter_anchor(ctx_a)
        and _deterministic_parameter_anchor(ctx_a) == _deterministic_parameter_anchor(ctx_b)
    ):
        return {
            "reason": "same_strong_family_same_endpoint_context",
            "shared_families": shared_parameterized_families,
        }

    return None


def _normalize_endpoint_segment(segment: str) -> str:
    """Collapse unstable path segments so nearby endpoints still share a family."""
    text = _safe_text(segment).lower()
    if not text:
        return ""
    if text.isdigit():
        return "{id}"
    if re.fullmatch(r"[0-9a-f]{8,}", text):
        return "{id}"
    if re.fullmatch(r"[0-9a-f-]{16,}", text):
        return "{id}"
    return text


def _endpoint_family(path: str) -> str:
    """Return a coarse endpoint family for recall-friendly pairing."""
    canonical = canonical_path(_safe_text(path))
    if canonical in {"", "/"}:
        return ""
    parts = [
        _normalize_endpoint_segment(segment)
        for segment in canonical.split("/")
        if _normalize_endpoint_segment(segment)
    ]
    if not parts:
        return ""
    return "/" + "/".join(parts[:2])


def _normalized_service_family(ctx: Dict[str, Any], finding: Dict[str, Any]) -> str:
    """Return a coarse target family that treats web targets consistently."""
    meta = _meta(finding)
    scheme = _safe_text(ctx.get("scheme")).lower()
    protocol = _safe_text(ctx.get("protocol")).lower()
    service = _safe_text(meta.get("service")).lower()

    if (
        scheme in {"http", "https"}
        or protocol in {"http", "https"}
        or "http" in service
        or ctx.get("endpoint_specific")
        or _safe_text(ctx.get("method"))
    ):
        return "web"

    if service and service not in {"tcp", "udp"}:
        return re.sub(r"[^a-z0-9]+", "_", service).strip("_")

    if protocol and protocol not in {"tcp", "udp"}:
        return re.sub(r"[^a-z0-9]+", "_", protocol).strip("_")

    return "generic"


def _cheap_similarity_gate(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Dict[str, Any]:
    """Return whether a same-target pair is similar enough to justify an LLM call."""
    normalized_title_a = _normalized_title(finding_a, runtime_cache=runtime_cache)
    normalized_title_b = _normalized_title(finding_b, runtime_cache=runtime_cache)
    title_tokens_a = _token_set(normalized_title_a)
    title_tokens_b = _token_set(normalized_title_b)
    shared_title_tokens = sorted(title_tokens_a & title_tokens_b)
    title_similarity = _jaccard_similarity(title_tokens_a, title_tokens_b)
    meaningful_title_tokens_a = _meaningful_title_tokens(title_tokens_a)
    meaningful_title_tokens_b = _meaningful_title_tokens(title_tokens_b)
    meaningful_shared_title_tokens = sorted(meaningful_title_tokens_a & meaningful_title_tokens_b)
    meaningful_title_similarity = _jaccard_similarity(
        meaningful_title_tokens_a,
        meaningful_title_tokens_b,
    )

    shared_cves = sorted(
        _finding_cves(finding_a, runtime_cache=runtime_cache)
        & _finding_cves(finding_b, runtime_cache=runtime_cache)
    )
    shared_cwes = sorted(
        _finding_cwes(finding_a, runtime_cache=runtime_cache)
        & _finding_cwes(finding_b, runtime_cache=runtime_cache)
    )
    shared_identity_hints = sorted(
        _finding_identity_hints(finding_a, runtime_cache=runtime_cache)
        & _finding_identity_hints(finding_b, runtime_cache=runtime_cache)
    )
    shared_categories = sorted(
        _finding_category_hints(finding_a, runtime_cache=runtime_cache)
        & _finding_category_hints(finding_b, runtime_cache=runtime_cache)
    )
    shared_technologies = sorted(
        _finding_technology_hints(finding_a, runtime_cache=runtime_cache)
        & _finding_technology_hints(finding_b, runtime_cache=runtime_cache)
    )

    ctx_a = target_context(finding_a, runtime_cache=runtime_cache)
    ctx_b = target_context(finding_b, runtime_cache=runtime_cache)
    method_match = bool(ctx_a["method"] and ctx_a["method"] == ctx_b["method"])
    path_match = bool(ctx_a["path"] and ctx_a["path"] == ctx_b["path"])
    parameter_match = bool(ctx_a["parameter"] and ctx_a["parameter"] == ctx_b["parameter"])
    endpoint_family_a = _safe_text(ctx_a.get("endpoint_family"))
    endpoint_family_b = _safe_text(ctx_b.get("endpoint_family"))
    endpoint_family_match = bool(endpoint_family_a and endpoint_family_a == endpoint_family_b)

    details = {
        "normalized_title_a": normalized_title_a,
        "normalized_title_b": normalized_title_b,
        "title_similarity": round(title_similarity, 3),
        "shared_title_tokens": shared_title_tokens,
        "meaningful_title_similarity": round(meaningful_title_similarity, 3),
        "meaningful_shared_title_tokens": meaningful_shared_title_tokens,
        "shared_cves": shared_cves,
        "shared_cwes": shared_cwes,
        "shared_identity_hints": shared_identity_hints,
        "shared_categories": shared_categories,
        "shared_technologies": shared_technologies,
        "method_match": method_match,
        "path_match": path_match,
        "parameter_match": parameter_match,
        "endpoint_family_a": endpoint_family_a,
        "endpoint_family_b": endpoint_family_b,
        "endpoint_family_match": endpoint_family_match,
    }

    if shared_cves:
        return {
            "allowed": True,
            "decision": "passed_shared_cve",
            "details": details,
        }

    if shared_cwes:
        return {
            "allowed": True,
            "decision": "passed_shared_cwe",
            "details": details,
        }

    if shared_identity_hints:
        return {
            "allowed": True,
            "decision": "passed_shared_scanner_identity",
            "details": details,
        }

    if normalized_title_a and normalized_title_a == normalized_title_b:
        return {
            "allowed": True,
            "decision": "passed_normalized_title_match",
            "details": details,
        }

    if (
        title_similarity >= 0.5
        and len(shared_title_tokens) >= 2
        and len(meaningful_shared_title_tokens) >= 1
    ):
        return {
            "allowed": True,
            "decision": "passed_similar_normalized_title",
            "details": details,
        }

    if (
        endpoint_family_match
        and (
            len(meaningful_shared_title_tokens) >= 1
            or shared_categories
            or shared_technologies
            or parameter_match
        )
    ):
        return {
            "allowed": True,
            "decision": "passed_endpoint_family_overlap",
            "details": details,
        }

    if path_match and (shared_categories or shared_technologies or len(meaningful_shared_title_tokens) >= 1):
        return {
            "allowed": True,
            "decision": "passed_same_path_context",
            "details": details,
        }

    if parameter_match and (shared_categories or len(meaningful_shared_title_tokens) >= 1):
        return {
            "allowed": True,
            "decision": "passed_parameter_context",
            "details": details,
        }

    if len(meaningful_shared_title_tokens) >= 1 and (shared_categories or shared_technologies):
        return {
            "allowed": True,
            "decision": "passed_contextual_overlap",
            "details": details,
        }

    return {
        "allowed": False,
        "decision": "skipped_low_similarity",
        "details": details,
    }


@dataclass(frozen=True)
class LLMDuplicateConfig:
    """Runtime configuration for LLM duplicate resolution."""

    mode: str = "off"
    api_url: Optional[str] = None
    api_key: Optional[str] = None
    model_name: Optional[str] = None
    timeout_seconds: float = 15.0
    debug: bool = False
    cache_enabled: bool = True

    @property
    def enabled(self) -> bool:
        """Return True when the resolver should attempt LLM comparisons."""
        return self.mode == "llm"

    def missing_required_fields(self) -> List[str]:
        """Return missing required config fields when LLM mode is enabled."""
        if not self.enabled:
            return []

        missing: List[str] = []
        if not _safe_text(self.api_url):
            missing.append("llm_api_url")
        if not _safe_text(self.api_key):
            missing.append("llm_api_key")
        if not _safe_text(self.model_name):
            missing.append("llm_model")
        return missing

    def invalid_model_name_error(self) -> Optional[str]:
        """Return a clear error when the configured model looks obviously wrong."""
        if not self.enabled:
            return None

        model_name = _safe_text(self.model_name)
        if not model_name:
            return None

        if _looks_like_shell_variable_reference(model_name):
            return (
                "LLM duplicate mode is enabled but VULN_MANAGER_LLM_MODEL looks like "
                f"an environment-variable reference ({model_name!r}), not a provider model name. "
                "Set --llm-model or VULN_MANAGER_LLM_MODEL to a real model id supported by your provider."
            )

        api_key = _safe_text(self.api_key)
        if model_name == api_key or _looks_like_api_key(model_name):
            return (
                "LLM duplicate mode is enabled but VULN_MANAGER_LLM_MODEL looks like "
                "an API key, not a provider model name. "
                "Set --llm-model or VULN_MANAGER_LLM_MODEL to a real model id supported by your provider."
            )

        return None

    @property
    def ready(self) -> bool:
        """Return True when the configured LLM endpoint can be called."""
        return bool(self.enabled and self.validation_error() is None)

    def validation_error(self) -> Optional[str]:
        """Return a clear configuration error message when required values are missing."""
        missing = self.missing_required_fields()
        if missing:
            missing_text = ", ".join(missing)
            return (
                "LLM duplicate mode is enabled but missing required configuration values: "
                f"{missing_text}. "
                "Set them with --llm-api-url/--llm-api-key/--llm-model, "
                "or VULN_MANAGER_LLM_API_URL/VULN_MANAGER_LLM_API_KEY/"
                "VULN_MANAGER_LLM_MODEL."
            )

        return self.invalid_model_name_error()

    def safe_summary(self) -> Dict[str, Any]:
        """Return a log-safe configuration summary."""
        return {
            "mode": self.mode,
            "api_url": self.api_url,
            "api_key": mask_secret(self.api_key),
            "model_name": self.model_name,
            "timeout_seconds": self.timeout_seconds,
            "debug": self.debug,
            "cache_enabled": self.cache_enabled,
        }

    def __repr__(self) -> str:
        summary = self.safe_summary()
        parts = [
            f"mode={summary['mode']!r}",
            f"api_url={summary['api_url']!r}",
            f"api_key={summary['api_key']!r}",
            f"model_name={summary['model_name']!r}",
            f"timeout_seconds={summary['timeout_seconds']!r}",
            f"debug={summary['debug']!r}",
            f"cache_enabled={summary['cache_enabled']!r}",
        ]
        return f"LLMDuplicateConfig({', '.join(parts)})"

    __str__ = __repr__


def target_context(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Dict[str, Any]:
    """Extract the best available target identity from a normalized finding."""
    def factory() -> Dict[str, Any]:
        meta = _meta(finding)
        asset_id = str(finding.get("asset_id") or "")
        parsed = parse_target(asset_id)

        host = (parsed.get("host") or meta.get("host") or "").strip().lower()
        scheme = (parsed.get("scheme") or meta.get("scheme") or "").strip().lower()
        port = parsed.get("port")
        if port is None:
            port = _coerce_port(meta.get("port"))
        if port is None:
            port = _default_port(scheme)

        path = parsed.get("path") if parsed.get("path") else meta.get("path", "")
        path = canonical_path(str(path or ""))
        if path == "/":
            path = ""

        query_keys_raw = meta.get("query_keys")
        if query_keys_raw is None and parsed.get("query"):
            query_keys_raw = parsed["query"]
        query_keys = canonical_query(query_keys_raw)

        parameter = str(meta.get("parameter") or "").strip().lower()
        method = str(meta.get("method") or "").strip().upper()
        protocol = str(meta.get("protocol") or "").strip().lower()
        endpoint_specific = bool(path or query_keys or parameter)
        context = {
            "host": host,
            "scheme": scheme,
            "port": port,
            "path": path,
            "query_keys": query_keys,
            "parameter": parameter,
            "method": method,
            "protocol": protocol,
            "endpoint_specific": endpoint_specific,
        }
        context["target_family"] = _normalized_service_family(context, finding)
        context["endpoint_family"] = _endpoint_family(path)
        return context

    return _runtime_cache_get_or_set(
        "target_context",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def findings_share_same_target(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Tuple[bool, Dict[str, Any]]:
    """Return whether two findings describe the same concrete target context."""
    ctx_a = target_context(finding_a, runtime_cache=runtime_cache)
    ctx_b = target_context(finding_b, runtime_cache=runtime_cache)

    if not ctx_a["host"] or not ctx_b["host"] or ctx_a["host"] != ctx_b["host"]:
        return False, {"reason": "host_mismatch", "target_a": ctx_a, "target_b": ctx_b}

    family_a = ctx_a["target_family"]
    family_b = ctx_b["target_family"]
    if family_a != family_b and "web" not in {family_a, family_b}:
        return False, {"reason": "target_family_mismatch", "target_a": ctx_a, "target_b": ctx_b}

    if (
        family_a != "web"
        and family_b != "web"
        and ctx_a["protocol"] and ctx_b["protocol"]
        and ctx_a["protocol"] != ctx_b["protocol"]
    ):
        return False, {"reason": "protocol_mismatch", "target_a": ctx_a, "target_b": ctx_b}

    soft_signals: List[str] = []

    if ctx_a["scheme"] and ctx_b["scheme"] and ctx_a["scheme"] != ctx_b["scheme"]:
        soft_signals.append("scheme_mismatch")

    if (
        ctx_a["port"] is not None and ctx_b["port"] is not None
        and ctx_a["port"] != ctx_b["port"]
    ):
        if family_a != "web" and family_b != "web":
            return False, {"reason": "port_mismatch", "target_a": ctx_a, "target_b": ctx_b}
        soft_signals.append("port_mismatch")

    endpoint_specific = ctx_a["endpoint_specific"] or ctx_b["endpoint_specific"]
    if endpoint_specific and ctx_a["path"] != ctx_b["path"]:
        soft_signals.append("path_mismatch")

    if (
        endpoint_specific
        and (ctx_a["query_keys"] or ctx_b["query_keys"])
        and ctx_a["query_keys"] != ctx_b["query_keys"]
    ):
        soft_signals.append("query_mismatch")

    if (
        endpoint_specific
        and (ctx_a["parameter"] or ctx_b["parameter"])
        and ctx_a["parameter"] != ctx_b["parameter"]
    ):
        soft_signals.append("parameter_mismatch")

    if (
        ctx_a["method"] and ctx_b["method"]
        and ctx_a["method"] != ctx_b["method"]
    ):
        soft_signals.append("method_mismatch")

    reason = "same_host_compatible" if soft_signals else "same_target"
    return True, {
        "reason": reason,
        "soft_signals": soft_signals,
        "target_a": ctx_a,
        "target_b": ctx_b,
    }


def _coarse_target_bucket(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Tuple[str, str, str]:
    """Return a coarse grouping key to avoid unnecessary O(n^2) comparisons."""
    ctx = target_context(finding, runtime_cache=runtime_cache)
    if ctx["target_family"] == "web":
        port_bucket = "web-default" if ctx["port"] in {None, 80, 443} else f"web:{ctx['port']}"
        return (ctx["host"], port_bucket, "web")

    port_text = str(ctx["port"]) if ctx["port"] is not None else ""
    return (ctx["host"], port_text, ctx["target_family"])


def assign_finding_ids(
    findings: Iterable[Dict[str, Any]],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> None:
    """Stamp stable finding identifiers in-place when missing."""
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("finding_id"):
            continue
        meta = _meta(finding)
        payload = {
            "scanner": _scanner_name(finding),
            "source_id": meta.get("plugin_id") or meta.get("template_id") or meta.get("raw_id") or meta.get("cve_id"),
            "vulnerability_name": finding.get("vulnerability_name"),
            "asset_id": finding.get("asset_id"),
            "description": finding.get("description"),
            "remediation": finding.get("remediation"),
            "target": target_context(finding, runtime_cache=runtime_cache),
        }
        finding["finding_id"] = f"finding-{_sha256_text(json.dumps(payload, sort_keys=True, ensure_ascii=True))[:16]}"


def _suppress_adapter_artifacts(findings: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """Drop adapter transport artifacts from the active finding set."""
    kept: List[Dict[str, Any]] = []
    suppressed = 0
    for finding in findings:
        if is_adapter_transport_artifact(finding):
            suppressed += 1
        else:
            kept.append(finding)
    return kept, suppressed


def _prompt_payload(
    finding: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Dict[str, Any]:
    """Return the compact structured payload sent to the LLM."""
    def factory() -> Dict[str, Any]:
        meta = _meta(finding)
        ctx = target_context(finding, runtime_cache=runtime_cache)
        return {
            "scanner_name": _scanner_name(finding),
            "title": _safe_text(finding.get("vulnerability_name")),
            "description": _safe_text(finding.get("description"))[:1200],
            "severity": _safe_text(finding.get("severity")).lower(),
            "cves": _ordered_unique([
                *_string_list(_meta(finding).get("cve_ids")),
                _meta(finding).get("cve_id"),
            ]),
            "cwes": _ordered_unique([
                *_string_list(_meta(finding).get("cwe_list")),
                _meta(finding).get("cwe"),
            ]),
            "target": {
                "host": ctx["host"],
                "scheme": ctx["scheme"] or None,
                "port": ctx["port"],
                "path": ctx["path"] or None,
                "query_keys": ctx["query_keys"].split("&") if ctx["query_keys"] else [],
                "parameter": ctx["parameter"] or None,
                "method": ctx["method"] or None,
                "protocol": ctx["protocol"] or None,
            },
            "evidence": _safe_text(
                meta.get("evidence") or meta.get("http_request") or meta.get("curl_command")
            )[:800]
            or None,
            "remediation": _safe_text(finding.get("remediation"))[:800] or None,
        }

    return _runtime_cache_get_or_set(
        "prompt_payload",
        finding,
        factory,
        runtime_cache=runtime_cache,
    )


def _comparison_prompt_payload(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Dict[str, Any]:
    """Return the compact pair payload used to build one LLM comparison request."""
    ordered_a, ordered_b = _normalize_order(finding_a, finding_b)
    return {
        "question": LLM_DUPLICATE_COMPARISON_QUESTION,
        "finding_a": _prompt_payload(ordered_a, runtime_cache=runtime_cache),
        "finding_b": _prompt_payload(ordered_b, runtime_cache=runtime_cache),
    }


def _comparison_request_preview(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
) -> Dict[str, Any]:
    """Return a compact, always-safe summary of one compared pair."""
    ordered_a, ordered_b = _normalize_order(finding_a, finding_b)
    return {
        "finding_a_id": ordered_a.get("finding_id"),
        "finding_b_id": ordered_b.get("finding_id"),
        "finding_a_title": _safe_text(ordered_a.get("vulnerability_name")),
        "finding_b_title": _safe_text(ordered_b.get("vulnerability_name")),
        "finding_a_target": _safe_text(ordered_a.get("asset_id")),
        "finding_b_target": _safe_text(ordered_b.get("asset_id")),
        "scanner_a": _scanner_name(ordered_a),
        "scanner_b": _scanner_name(ordered_b),
    }


def _build_explainability(
    *,
    same_target: bool,
    target_match_details: Optional[Dict[str, Any]],
    cheap_filter_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Return deterministic evidence describing why a pair was or was not compared."""
    cheap_filter = cheap_filter_details if isinstance(cheap_filter_details, dict) else None
    cheap_filter_signal = cheap_filter.get("details") if cheap_filter else None
    signal = cheap_filter_signal if isinstance(cheap_filter_signal, dict) else {}

    return {
        "normalized_title_a": signal.get("normalized_title_a"),
        "normalized_title_b": signal.get("normalized_title_b"),
        "title_similarity": signal.get("title_similarity"),
        "shared_title_tokens": copy.deepcopy(signal.get("shared_title_tokens")),
        "meaningful_title_similarity": signal.get("meaningful_title_similarity"),
        "meaningful_shared_title_tokens": copy.deepcopy(signal.get("meaningful_shared_title_tokens")),
        "shared_cves": copy.deepcopy(signal.get("shared_cves")),
        "shared_cwes": copy.deepcopy(signal.get("shared_cwes")),
        "shared_identity_hints": copy.deepcopy(signal.get("shared_identity_hints")),
        "shared_categories": copy.deepcopy(signal.get("shared_categories")),
        "shared_technologies": copy.deepcopy(signal.get("shared_technologies")),
        "endpoint_family_match": signal.get("endpoint_family_match"),
        "cheap_filter_decision": cheap_filter.get("decision") if cheap_filter else None,
        "cheap_filter_details": copy.deepcopy(cheap_filter),
        "same_target": same_target,
        "same_target_reason": (
            _safe_text(target_match_details.get("reason"))
            if isinstance(target_match_details, dict)
            else None
        ) or None,
    }


def _merge_trace_response_payload(
    payload: Any,
    *,
    target_match_details: Optional[Dict[str, Any]] = None,
    cheap_filter_details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Merge pair-local deterministic trace details into a response payload."""
    merged: Dict[str, Any]
    if isinstance(payload, dict):
        merged = copy.deepcopy(payload)
    else:
        merged = {}
        if payload is not None:
            merged["provider_response"] = copy.deepcopy(payload)

    if target_match_details is not None:
        merged["target_match"] = copy.deepcopy(target_match_details)
    if cheap_filter_details is not None:
        merged["cheap_filter"] = copy.deepcopy(cheap_filter_details)
    return merged


def _trace_provider_payload(payload: Any, *, debug: bool) -> Dict[str, Any]:
    """Return provider trace fields with debug-only raw payload expansion."""
    if not isinstance(payload, dict):
        if debug and payload is not None:
            return {"provider_response": copy.deepcopy(payload)}
        return {}

    if debug:
        return copy.deepcopy(payload)

    safe_payload: Dict[str, Any] = {}
    for key in ("_provider_request", "provider_error", "provider_state", "healthcheck"):
        if key in payload:
            safe_payload[key] = copy.deepcopy(payload[key])
    return safe_payload


def build_llm_request_body(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    model_name: str,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Dict[str, Any]:
    """Build the OpenAI-compatible chat request body for one comparison."""
    payload = _comparison_prompt_payload(
        finding_a,
        finding_b,
        runtime_cache=runtime_cache,
    )
    payload = sanitize_secrets(payload).value
    return {
        "model": model_name,
        "temperature": 0,
        "max_completion_tokens": 220,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You compare two vulnerability scanner findings. "
                    "Return exactly one JSON object with exactly these fields: "
                    "same_vulnerability (boolean), confidence (number from 0.0 to 1.0), "
                    "reason (string), canonical_title (string). "
                    "The object may be wrapped only in a Markdown ```json fence; emit no other text. "
                    "Set same_vulnerability=true only when both findings describe the same underlying "
                    "vulnerability instance on the same target. Base the decision on concrete instance "
                    "anchors such as endpoint/path, parameter, HTTP method, port/service, CVE, or scanner "
                    "identity (plugin/template/raw id). Relevant anchor conflicts require false. "
                    "Confidence is your stated confidence in this decision. canonical_title is only a "
                    "recommended shared title and must not invent unsupported details."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(payload, sort_keys=True, ensure_ascii=True),
            },
        ],
    }


def build_llm_healthcheck_request_body(*, model_name: str) -> Dict[str, Any]:
    """Build a tiny yes/no health-check request for the configured provider."""
    return {
        "model": model_name,
        "temperature": 0,
        "max_completion_tokens": 2,
        "messages": [
            {
                "role": "system",
                "content": (
                    "Answer with exactly one word: yes or no. "
                    "Do not explain."
                ),
            },
            {
                "role": "user",
                "content": "Reply with exactly one word: yes.",
            },
        ],
    }


_YES_NO_TOKEN_PATTERN = re.compile(r"[a-z]+")


def _extract_llm_text(value: Any) -> str:
    """Extract plain text from common chat-completion content shapes."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content"):
            extracted = _extract_llm_text(value.get(key))
            if extracted:
                return extracted
        return ""
    if isinstance(value, list):
        parts = [_extract_llm_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    return _safe_text(value)


def _normalize_yes_no_token(value: Any) -> Optional[str]:
    """Accept one yes/no token with only harmless wrapper punctuation."""
    text = _extract_llm_text(value).strip().lower()
    if text in {"yes", "no"}:
        return text

    tokens = _YES_NO_TOKEN_PATTERN.findall(text)
    if tokens in (["yes"], ["no"]):
        leftover = _YES_NO_TOKEN_PATTERN.sub("", text)
        if not any(char.isalnum() for char in leftover):
            return tokens[0]
    return None


def parse_llm_yes_no_response(response_payload: Dict[str, Any], raw_text: str) -> str:
    """Extract and validate a strict yes/no answer from the LLM response."""
    decision = _normalize_yes_no_token(raw_text)
    if decision:
        return decision

    choices = response_payload.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0]
        if isinstance(choice, dict):
            message = choice.get("message")
            if isinstance(message, dict):
                for key in ("content", "reasoning_content", "reasoning"):
                    decision = _normalize_yes_no_token(message.get(key))
                    if decision:
                        return decision
            decision = _normalize_yes_no_token(choice.get("text"))
            if decision:
                return decision

    decision = _normalize_yes_no_token(response_payload.get("output_text"))
    if decision:
        return decision

    raise ValueError(f"Invalid LLM duplicate response: {raw_text!r}")


_JSON_FENCE_PATTERN = re.compile(
    r"\A\s*```json\s*(\{.*\})\s*```\s*\Z",
    flags=re.DOTALL | re.IGNORECASE,
)


def _duplicate_decision_response_text(
    response_payload: Dict[str, Any],
    raw_text: str,
) -> str:
    """Extract the single assistant response value from common provider envelopes."""
    choices = response_payload.get("choices")
    if isinstance(choices, list) and choices:
        choice = choices[0]
        if isinstance(choice, dict):
            message = choice.get("message")
            if isinstance(message, dict) and "content" in message:
                return _extract_llm_text(message.get("content"))
            if "text" in choice:
                return _extract_llm_text(choice.get("text"))

    if "output_text" in response_payload:
        return _extract_llm_text(response_payload.get("output_text"))
    return _extract_llm_text(raw_text)


def parse_llm_duplicate_decision(
    response_payload: Dict[str, Any],
    raw_text: str,
) -> LLMDuplicateDecision:
    """Parse an exact structured decision, rejecting legacy or embellished output."""
    text = _duplicate_decision_response_text(response_payload, raw_text).strip()
    fence_match = _JSON_FENCE_PATTERN.fullmatch(text)
    json_text = fence_match.group(1) if fence_match else text

    try:
        value = json.loads(json_text)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Invalid structured LLM duplicate response: {text!r}") from exc

    if not isinstance(value, dict) or set(value) != LLM_DUPLICATE_DECISION_FIELDS:
        raise ValueError(
            "Invalid structured LLM duplicate response: expected exactly "
            f"{sorted(LLM_DUPLICATE_DECISION_FIELDS)!r}"
        )

    same_vulnerability = value["same_vulnerability"]
    confidence = value["confidence"]
    reason = value["reason"]
    canonical_title = value["canonical_title"]
    if not isinstance(same_vulnerability, bool):
        raise ValueError("Invalid structured LLM duplicate response: same_vulnerability must be boolean")
    if isinstance(confidence, bool) or not isinstance(confidence, float):
        raise ValueError("Invalid structured LLM duplicate response: confidence must be a float")
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("Invalid structured LLM duplicate response: confidence must be between 0 and 1")
    if not isinstance(reason, str):
        raise ValueError("Invalid structured LLM duplicate response: reason must be a string")
    if not isinstance(canonical_title, str):
        raise ValueError("Invalid structured LLM duplicate response: canonical_title must be a string")

    return LLMDuplicateDecision(
        same_vulnerability=same_vulnerability,
        confidence=confidence,
        reason=reason.strip(),
        canonical_title=canonical_title.strip(),
    )


class OpenAICompatibleLLMClient:
    """Minimal OpenAI-compatible chat-completions client."""

    def __init__(
        self,
        config: LLMDuplicateConfig,
        *,
        transport: Optional[httpx.BaseTransport] = None,
    ):
        self.config = config
        self.transport = transport

    def _request_hash(self, request_body: Dict[str, Any]) -> str:
        """Return a stable request hash for one provider call."""
        return _sha256_text(json.dumps(request_body, sort_keys=True, ensure_ascii=True))

    def _headers(self) -> Dict[str, str]:
        """Build request headers without exposing secrets anywhere else."""
        headers = {"Content-Type": "application/json"}
        if self.config.api_key:
            headers["Authorization"] = f"Bearer {self.config.api_key}"
        return headers

    def _build_retryable_provider_error(
        self,
        *,
        request_kind: str,
        request_hash: str,
        request_body: Dict[str, Any],
        attempt_count: int,
        retry_backoff_seconds: List[float],
        http_status_code: Optional[int] = None,
        response_text: str = "",
        response_json: Any = None,
        exception: Optional[BaseException] = None,
    ) -> LLMProviderError:
        """Create a structured provider error for one failed HTTP attempt."""
        category = _classify_provider_failure(
            http_status_code=http_status_code,
            response_text=response_text,
            response_json=response_json,
            exception=exception,
        )
        retryable = bool(http_status_code in RETRYABLE_PROVIDER_STATUS_CODES)
        if exception is not None and isinstance(exception, (TimeoutError, httpx.TimeoutException, httpx.RequestError)):
            retryable = False
        message = _provider_error_summary(
            category=category,
            http_status_code=http_status_code,
            response_json=response_json,
            response_text=response_text or (str(exception) if exception else ""),
        )
        return LLMProviderError(
            message=message,
            category=category,
            retryable=retryable,
            http_status_code=http_status_code,
            response_text=_safe_text(response_text) or None,
            response_json=response_json,
            request_hash=request_hash,
            request_kind=request_kind,
            request_url=_safe_text(self.config.api_url) or None,
            request_preview=_safe_request_preview(request_body),
            attempt_count=attempt_count,
            retry_backoff_seconds=list(retry_backoff_seconds),
        )

    def _retry_delay_seconds(self, attempt_count: int) -> float:
        """Return exponential backoff delay for a retry attempt."""
        delay = PROVIDER_RETRY_BACKOFF_BASE_SECONDS * (2 ** max(attempt_count - 1, 0))
        return min(delay, PROVIDER_RETRY_BACKOFF_CAP_SECONDS)

    def _post_chat_completion(
        self,
        request_body: Dict[str, Any],
        *,
        request_kind: str,
    ) -> Tuple[Any, str, str, int, List[float]]:
        """Send one OpenAI-compatible chat completion request with bounded retries."""
        safe_request = sanitize_secrets(request_body).value
        if not isinstance(safe_request, dict):
            raise ValueError("LLM request body must be a JSON object.")
        request_hash = self._request_hash(safe_request)
        retry_backoff_seconds: List[float] = []
        max_attempts = 1 + PROVIDER_MAX_RETRIES
        request_url = str(self.config.api_url)

        for attempt_count in range(1, max_attempts + 1):
            try:
                with httpx.Client(
                    timeout=self.config.timeout_seconds,
                    transport=self.transport,
                ) as client:
                    response = client.post(
                        request_url,
                        json=safe_request,
                        headers=self._headers(),
                    )
            except Exception as exc:
                raise _coerce_provider_error(
                    exc,
                    request_kind=request_kind,
                    request_hash=request_hash,
                ) from exc

            parsed_response = _response_json_or_none(response)
            if parsed_response is not None:
                response_json = sanitize_secrets(parsed_response).value
                response_text = _json_text(response_json)
            else:
                response_json = None
                response_text = _safe_text(
                    sanitize_secrets(_safe_text(getattr(response, "text", ""))).value
                )
            status_code = getattr(response, "status_code", None)
            if isinstance(status_code, int) and status_code >= 400:
                provider_error = self._build_retryable_provider_error(
                    request_kind=request_kind,
                    request_hash=request_hash,
                    request_body=safe_request,
                    attempt_count=attempt_count,
                    retry_backoff_seconds=retry_backoff_seconds,
                    http_status_code=status_code,
                    response_text=response_text,
                    response_json=response_json,
                )
                if status_code == 400:
                    logger.warning(
                        "LLM provider rejected %s request %s at %s: %s | request_preview=%s",
                        request_kind,
                        request_hash,
                        request_url,
                        provider_error,
                        _json_text(provider_error.request_preview),
                    )
                if provider_error.retryable and attempt_count < max_attempts:
                    delay = self._retry_delay_seconds(attempt_count)
                    retry_backoff_seconds.append(delay)
                    time.sleep(delay)
                    continue
                raise provider_error

            return response_json if response_json is not None else {}, response_text, request_hash, attempt_count, retry_backoff_seconds

        raise RuntimeError("unreachable")

    def chat_completion(
        self,
        request_body: Dict[str, Any],
        *,
        request_kind: str,
    ) -> Tuple[Any, str, str, int, List[float]]:
        """Send a validated generic chat-completion request.

        Duplicate resolution remains this client's primary consumer, while
        other structured advisory features can reuse the same hardened HTTP,
        secret-redaction, error-classification, and retry boundary.
        """
        validation_error = self.config.validation_error()
        if validation_error:
            raise ValueError(validation_error)
        return self._post_chat_completion(request_body, request_kind=request_kind)

    def healthcheck(self) -> Dict[str, Any]:
        """Validate that the configured provider can answer a tiny yes/no request."""
        validation_error = self.config.validation_error()
        if validation_error:
            raise ValueError(validation_error)

        request_body = build_llm_healthcheck_request_body(model_name=str(self.config.model_name))
        response_payload, raw_text, request_hash, attempt_count, retry_backoff_seconds = self._post_chat_completion(
            request_body,
            request_kind="healthcheck",
        )
        try:
            decision = parse_llm_yes_no_response(
                response_payload if isinstance(response_payload, dict) else {},
                raw_text,
            )
        except ValueError as exc:
            raise LLMProviderError(
                message="unknown_provider_error: invalid healthcheck yes/no response",
                category="unknown_provider_error",
                response_text=raw_text,
                response_json=response_payload,
                request_hash=request_hash,
                request_kind="healthcheck",
                attempt_count=attempt_count,
                retry_backoff_seconds=list(retry_backoff_seconds),
            ) from exc

        return {
            "status": "passed",
            "llm_decision": decision,
            "request_hash": request_hash,
            "attempt_count": attempt_count,
            "retry_backoff_seconds": list(retry_backoff_seconds),
        }

    def compare(
        self,
        finding_a: Dict[str, Any],
        finding_b: Dict[str, Any],
        *,
        runtime_cache: Optional["_FindingRuntimeCache"] = None,
    ) -> Tuple[LLMDuplicateDecision, Dict[str, Any], str, str]:
        """Submit one duplicate-comparison request and return the parsed decision."""
        validation_error = self.config.validation_error()
        if validation_error:
            raise ValueError(validation_error)

        request_body = build_llm_request_body(
            finding_a,
            finding_b,
            model_name=str(self.config.model_name),
            runtime_cache=runtime_cache,
        )
        response_payload, raw_text, request_hash, attempt_count, retry_backoff_seconds = self._post_chat_completion(
            request_body,
            request_kind="comparison",
        )
        parsed_payload = response_payload if isinstance(response_payload, dict) else {}
        try:
            decision = parse_llm_duplicate_decision(parsed_payload, raw_text)
        except ValueError as exc:
            raise LLMProviderError(
                message="unknown_provider_error: invalid structured duplicate response",
                category="unknown_provider_error",
                response_text=raw_text,
                response_json=response_payload,
                request_hash=request_hash,
                request_kind="comparison",
                attempt_count=attempt_count,
                retry_backoff_seconds=list(retry_backoff_seconds),
            ) from exc

        payload_for_trace = (
            dict(parsed_payload)
            if isinstance(response_payload, dict)
            else {"provider_response": response_payload}
        )
        payload_for_trace["_provider_request"] = {
            "request_kind": "comparison",
            "attempt_count": attempt_count,
            "retry_backoff_seconds": list(retry_backoff_seconds),
        }
        return decision, payload_for_trace, raw_text, request_hash


def _normalize_order(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Sort a pair by finding_id so A-B and B-A are equivalent."""
    return (
        (finding_a, finding_b)
        if str(finding_a.get("finding_id")) <= str(finding_b.get("finding_id"))
        else (finding_b, finding_a)
    )


def _pair_key(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
) -> str:
    """Return a stable pair identifier without computing cache semantics."""
    finding_a_id = str(finding_a.get("finding_id"))
    finding_b_id = str(finding_b.get("finding_id"))
    return (
        f"{finding_a_id}::{finding_b_id}"
        if finding_a_id <= finding_b_id
        else f"{finding_b_id}::{finding_a_id}"
    )


def _comparison_cache_key(
    finding_a: Dict[str, Any],
    finding_b: Dict[str, Any],
    *,
    model_name: str,
    runtime_cache: Optional["_FindingRuntimeCache"] = None,
) -> Tuple[str, str]:
    """Return (pair_key, cache_key) for one ordered finding pair."""
    ordered_a, ordered_b = _normalize_order(finding_a, finding_b)
    pair_key = _pair_key(ordered_a, ordered_b)
    comparison_payload = _comparison_prompt_payload(
        ordered_a,
        ordered_b,
        runtime_cache=runtime_cache,
    )
    payload = {
        "pair_key": pair_key,
        "model_name": model_name,
        "finding_a": comparison_payload["finding_a"],
        "finding_b": comparison_payload["finding_b"],
        "normalized_titles": {
            "finding_a": _normalized_title(ordered_a, runtime_cache=runtime_cache),
            "finding_b": _normalized_title(ordered_b, runtime_cache=runtime_cache),
        },
        "prompt_version": LLM_DUPLICATE_PROMPT_VERSION,
        "comparison_semantics_version": LLM_DUPLICATE_CACHE_SEMANTICS_VERSION,
    }
    cache_key = _sha256_text(json.dumps(payload, sort_keys=True, ensure_ascii=True))
    return pair_key, cache_key


def _decision_from_record(record: Mapping[str, Any]) -> Optional[LLMDuplicateDecision]:
    """Rehydrate a structured decision from a trace/cache record when valid."""
    same_vulnerability = record.get("same_vulnerability")
    confidence = record.get("confidence")
    reason = record.get("reason")
    canonical_title = record.get("canonical_title")
    if not isinstance(same_vulnerability, bool):
        return None
    if isinstance(confidence, bool) or not isinstance(confidence, float):
        return None
    if not 0.0 <= confidence <= 1.0:
        return None
    if not isinstance(reason, str) or not isinstance(canonical_title, str):
        return None
    return LLMDuplicateDecision(
        same_vulnerability=same_vulnerability,
        confidence=confidence,
        reason=reason,
        canonical_title=canonical_title,
    )


def _conservative_decision_record(
    records: Iterable[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Return the lowest-confidence valid structured record deterministically."""
    valid = [record for record in records if _decision_from_record(record) is not None]
    if not valid:
        return None
    return min(
        valid,
        key=lambda record: (
            float(record["confidence"]),
            str(record.get("pair_key") or ""),
        ),
    )


def _build_source_record(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Capture a source finding inside a merged LLM-confirmed cluster."""
    record = {
        "finding_id": finding.get("finding_id"),
        "scanner": _scanner_name(finding),
        "vulnerability_name": finding.get("vulnerability_name"),
        "severity": finding.get("severity"),
        "asset_id": finding.get("asset_id"),
        "description": finding.get("description"),
        "remediation": finding.get("remediation"),
        "meta": copy.deepcopy(_meta(finding)),
    }
    if isinstance(finding.get("references"), list):
        record["references"] = copy.deepcopy(finding["references"])
    return record


def _expanded_source_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten nested merged findings into one ordered source-record list."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list) and source_findings:
        return [
            copy.deepcopy(source)
            for source in source_findings
            if isinstance(source, dict)
        ]
    return [_build_source_record(finding)]


def _dedupe_source_records(records: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Return first-seen unique source records keyed by finding_id when possible."""
    deduped: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            continue
        finding_id = record.get("finding_id")
        key = (
            f"finding_id::{finding_id}"
            if finding_id is not None
            else f"record::{repr(record)}"
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def _finding_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return every scanner provenance label represented by one finding."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list):
        scanners = _ordered_unique(
            str(
                source.get("scanner")
                or (
                    source.get("meta", {}).get("scanner")
                    if isinstance(source.get("meta"), dict)
                    else ""
                )
                or ""
            ).strip()
            for source in source_findings
            if isinstance(source, dict)
        )
        scanners = [scanner for scanner in scanners if scanner]
        if scanners:
            return scanners

    found_by = finding.get("found_by")
    if isinstance(found_by, list):
        scanners = _ordered_unique(
            str(scanner).strip()
            for scanner in found_by
            if str(scanner).strip()
        )
        if scanners:
            return scanners

    meta_scanners = _meta(finding).get("scanners")
    if isinstance(meta_scanners, list):
        scanners = _ordered_unique(
            str(scanner).strip()
            for scanner in meta_scanners
            if str(scanner).strip()
        )
        if scanners:
            return scanners

    scanner = str(_scanner_name(finding) or "").strip()
    return [scanner] if scanner else []


def _finding_confirmation_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return scanners that contribute non-degraded confirmation for one finding."""
    confirmation = _meta(finding).get("confirmation_scanners")
    if isinstance(confirmation, list):
        scanners = _ordered_unique(
            str(scanner).strip()
            for scanner in confirmation
            if str(scanner).strip()
        )
        if scanners:
            return scanners

    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list):
        scanners = _ordered_unique(
            str(
                source.get("scanner")
                or (
                    source.get("meta", {}).get("scanner")
                    if isinstance(source.get("meta"), dict)
                    else ""
                )
                or ""
            ).strip()
            for source in source_findings
            if isinstance(source, dict)
            and not (
                source.get("degraded_execution") is True
                or (
                    isinstance(source.get("meta"), dict)
                    and source["meta"].get("degraded_execution") is True
                )
            )
        )
        scanners = [scanner for scanner in scanners if scanner]
        if scanners:
            return scanners

    return [] if is_degraded_finding(finding) else _finding_scanners(finding)


def _collect_string_meta(findings: List[Dict[str, Any]], singular: str, plural: str) -> List[str]:
    """Union singular/plural metadata string fields."""
    values: List[str] = []
    for finding in findings:
        meta = _meta(finding)
        singular_value = meta.get(singular)
        if isinstance(singular_value, str) and singular_value.strip():
            values.append(singular_value.strip())
        plural_value = meta.get(plural)
        if isinstance(plural_value, list):
            for item in plural_value:
                if isinstance(item, str) and item.strip():
                    values.append(item.strip())
    return _ordered_unique(values)


def _collect_int_meta(findings: List[Dict[str, Any]], singular: str, plural: str) -> List[int]:
    """Union singular/plural metadata integer fields."""
    values: List[int] = []
    seen: set[int] = set()
    for finding in findings:
        meta = _meta(finding)
        singular_value = meta.get(singular)
        if isinstance(singular_value, int) and not isinstance(singular_value, bool) and singular_value not in seen:
            values.append(singular_value)
            seen.add(singular_value)
        plural_value = meta.get(plural)
        if isinstance(plural_value, list):
            for item in plural_value:
                if isinstance(item, int) and not isinstance(item, bool) and item not in seen:
                    values.append(item)
                    seen.add(item)
    return values


def _collect_references(findings: List[Dict[str, Any]]) -> List[str]:
    """Return the ordered union of references on a duplicate cluster."""
    values: List[str] = []
    for finding in findings:
        meta = _meta(finding)
        for key in ("reference", "references"):
            value = meta.get(key)
            if isinstance(value, str) and value.strip():
                values.append(value.strip())
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, str) and item.strip():
                        values.append(item.strip())
        top_level = finding.get("references")
        if isinstance(top_level, list):
            for item in top_level:
                if isinstance(item, str) and item.strip():
                    values.append(item.strip())
    return _ordered_unique(values)


def _merge_llm_cluster(
    cluster: List[Dict[str, Any]],
    comparison_records: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Merge a cross-scanner cluster confirmed by the LLM."""
    sorted_cluster = sorted(
        cluster,
        key=lambda finding: (
            0 if is_degraded_finding(finding) else 1,
            _finding_severity_rank(finding),
            str(finding.get("finding_id")),
        ),
        reverse=True,
    )
    base = copy.deepcopy(sorted_cluster[0])
    scanners = _ordered_unique(
        scanner
        for finding in cluster
        for scanner in _finding_scanners(finding)
    )
    confirmation_scanners = _ordered_unique(
        scanner
        for finding in cluster
        for scanner in _finding_confirmation_scanners(finding)
    )
    degraded_scanners = [scanner for scanner in scanners if scanner not in confirmation_scanners]
    raw_ids = _collect_string_meta(cluster, "raw_id", "raw_ids")
    cve_ids = _collect_string_meta(cluster, "cve_id", "cve_ids")
    references = _collect_references(cluster)
    paths = _collect_string_meta(cluster, "path", "paths")
    parameters = _collect_string_meta(cluster, "parameter", "parameters")
    ports = _collect_int_meta(cluster, "port", "ports")
    methods = _collect_string_meta(cluster, "method", "methods")
    evidence_examples = _collect_string_meta(cluster, "evidence", "evidence_examples")
    http_request_examples = _collect_string_meta(cluster, "http_request", "http_request_examples")
    curl_command_examples = _collect_string_meta(cluster, "curl_command", "curl_command_examples")

    source_findings = _dedupe_source_records(
        source
        for finding in cluster
        for source in _expanded_source_records(finding)
    )
    source_count = len(source_findings) or len(sorted_cluster)
    base["description"] = _safe_text(base.get("description"))
    base["remediation"] = _safe_text(base.get("remediation"))
    base["found_by"] = scanners
    base["duplicate_count"] = source_count
    base["source_findings"] = source_findings
    base["finding_id"] = f"cluster-{_sha256_text('::'.join(str(f.get('finding_id')) for f in sorted_cluster))[:16]}"

    meta = _meta(base)
    meta = copy.deepcopy(meta)
    meta.update(
        {
            "merged": True,
            "original_findings_count": source_count,
            "scanners": scanners,
            "has_multi_scanner_confirmation": len(confirmation_scanners) > 1,
            "duplicate_resolution_mode": "llm",
        }
    )
    if confirmation_scanners:
        meta["confirmation_scanners"] = confirmation_scanners
    if degraded_scanners:
        meta["degraded_scanners"] = degraded_scanners
        meta["degraded_execution"] = True
    if raw_ids:
        meta["raw_ids"] = raw_ids
    if cve_ids:
        meta["cve_ids"] = cve_ids
    if references:
        meta["references"] = references
    if paths:
        meta["paths"] = paths
    if parameters:
        meta["parameters"] = parameters
    if ports:
        meta["ports"] = ports
    if methods:
        meta["methods"] = methods
    if evidence_examples:
        meta["evidence_examples"] = evidence_examples
    if http_request_examples:
        meta["http_request_examples"] = http_request_examples
    if curl_command_examples:
        meta["curl_command_examples"] = curl_command_examples
    base["meta"] = meta
    base["duplicate_resolution"] = {
        "mode": "llm",
        "comparison_count": len(comparison_records),
        "comparison_cache_keys": [record.get("cache_key") for record in comparison_records if record.get("cache_key")],
        "llm_decision": "yes",
    }
    conservative_record = _conservative_decision_record(comparison_records)
    if conservative_record is not None:
        base["correlation"] = {
            "status": "merged",
            "source": "llm",
            "confidence": conservative_record["confidence"],
            "reason": conservative_record["reason"],
            "canonical_title": conservative_record["canonical_title"],
            "needs_review": False,
            "review_candidates": [],
        }
    return base


def _finding_original_order(
    finding: Dict[str, Any],
    order_by_finding_id: Dict[str, int],
) -> int:
    """Return the earliest original input order represented by a finding or merged cluster."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list):
        source_orders = [
            order_by_finding_id[str(source.get("finding_id"))]
            for source in source_findings
            if isinstance(source, dict)
            and source.get("finding_id") is not None
            and str(source.get("finding_id")) in order_by_finding_id
        ]
        if source_orders:
            return min(source_orders)

    finding_id = finding.get("finding_id")
    if finding_id is not None and str(finding_id) in order_by_finding_id:
        return order_by_finding_id[str(finding_id)]

    return len(order_by_finding_id)


def _refresh_final_summary(results: Dict[str, Any], *, suppressed_in_resolver: int) -> Dict[str, Any]:
    """Recompute summary counters from the final finding set and current suppression count."""
    if "summary" not in results or not isinstance(results.get("summary"), dict):
        results["summary"] = {}

    prior_suppressed = int(results.get("suppressed_adapter_findings_count") or 0)
    total_suppressed = prior_suppressed + suppressed_in_resolver
    results["suppressed_adapter_findings_count"] = total_suppressed
    results["summary"]["suppressed_adapter_findings_count"] = total_suppressed
    return refresh_summary_counts(results)


def _annotate_final_merge_results(
    comparison_records: List[Dict[str, Any]],
    merged_findings: List[Dict[str, Any]],
) -> None:
    """Stamp each comparison record with its final merge outcome."""
    merged_lookup: Dict[str, str] = {}
    for finding in merged_findings:
        merged_id = str(finding.get("finding_id") or "")
        if not merged_id:
            continue
        source_findings = finding.get("source_findings")
        if isinstance(source_findings, list) and len(source_findings) > 1:
            for source in source_findings:
                if isinstance(source, dict) and source.get("finding_id"):
                    merged_lookup[str(source["finding_id"])] = merged_id
        elif finding.get("finding_id"):
            merged_lookup[str(finding["finding_id"])] = merged_id

    for record in comparison_records:
        left_id = str(record.get("compared_finding_a_id") or "")
        right_id = str(record.get("compared_finding_b_id") or "")
        left_merged_id = merged_lookup.get(left_id)
        right_merged_id = merged_lookup.get(right_id)
        if left_merged_id and left_merged_id == right_merged_id:
            record["final_merge_result"] = "merged"
            record["merged_finding_id"] = left_merged_id
        else:
            record["final_merge_result"] = "not_merged"
            record["merged_finding_id"] = None


def _annotate_structured_correlations(
    materialized_members: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]],
    comparison_records: List[Dict[str, Any]],
) -> None:
    """Attach public review metadata without exposing provider trace internals."""
    finding_by_member_id: Dict[str, Dict[str, Any]] = {}
    for finding, members in materialized_members:
        for member in members:
            member_id = member.get("finding_id")
            if member_id is not None:
                finding_by_member_id[str(member_id)] = finding

    review_records = [
        record
        for record in comparison_records
        if record.get("needs_review") is True
        and record.get("comparison_status") in {"compared_with_llm", "cached"}
        and _decision_from_record(record) is not None
    ]

    for record in sorted(review_records, key=lambda item: str(item.get("pair_key") or "")):
        left = finding_by_member_id.get(str(record.get("compared_finding_a_id") or ""))
        right = finding_by_member_id.get(str(record.get("compared_finding_b_id") or ""))
        if left is None or right is None or left is right:
            continue

        for finding, candidate in ((left, right), (right, left)):
            correlation = finding.get("correlation")
            if not isinstance(correlation, dict) or correlation.get("source") != "llm":
                correlation = {
                    "status": "needs_review",
                    "source": "llm",
                    "confidence": record["confidence"],
                    "reason": record["reason"],
                    "canonical_title": record["canonical_title"],
                    "needs_review": True,
                    "review_candidates": [],
                }
                finding["correlation"] = correlation
            else:
                correlation["needs_review"] = True
                current_confidence = correlation.get("confidence")
                if (
                    correlation.get("status") != "merged"
                    and isinstance(current_confidence, (int, float))
                    and float(record["confidence"]) < float(current_confidence)
                ):
                    correlation["confidence"] = record["confidence"]
                    correlation["reason"] = record["reason"]
                    correlation["canonical_title"] = record["canonical_title"]

            candidates = correlation.setdefault("review_candidates", [])
            candidate_entry = {
                "finding_id": candidate.get("finding_id"),
                "vulnerability_name": _safe_text(candidate.get("vulnerability_name")),
                "scanners": sorted(_finding_scanners(candidate)),
                "confidence": record["confidence"],
                "reason": record["reason"],
                "canonical_title": record["canonical_title"],
            }
            existing_index = next(
                (
                    index
                    for index, existing in enumerate(candidates)
                    if existing.get("finding_id") == candidate_entry["finding_id"]
                ),
                None,
            )
            if existing_index is None:
                candidates.append(candidate_entry)
            elif float(candidate_entry["confidence"]) < float(
                candidates[existing_index].get("confidence") or 0.0
            ):
                candidates[existing_index] = candidate_entry

    for finding, _members in materialized_members:
        correlation = finding.get("correlation")
        if not isinstance(correlation, dict):
            continue
        candidates = correlation.get("review_candidates")
        if isinstance(candidates, list):
            candidates.sort(
                key=lambda candidate: (
                    str(candidate.get("finding_id") or ""),
                    float(candidate.get("confidence") or 0.0),
                    str(candidate.get("canonical_title") or ""),
                )
            )


def _build_duplicate_analysis(
    *,
    mode: str,
    suppressed: int,
    deterministic_same_scanner_merges: int,
    deterministic_fallback_merges: int,
    same_scanner_pairs_skipped: int,
    comparison_records: List[Dict[str, Any]],
    merged_findings: List[Dict[str, Any]],
    provider_state: Dict[str, Any],
) -> Dict[str, Any]:
    """Derive duplicate-analysis counters from final comparison records."""
    statuses = [str(record.get("comparison_status") or "") for record in comparison_records]
    pairs_sent_to_llm = sum(bool(record.get("sent_to_llm")) for record in comparison_records)
    pairs_reused_from_cache = sum(bool(record.get("used_cache")) for record in comparison_records)
    pairs_blocked_by_same_target = sum(status == "skipped_different_target" for status in statuses)
    pairs_blocked_by_similarity_gate = sum(status == "skipped_low_similarity" for status in statuses)
    total_compared_pairs = sum(status in {"compared_with_llm", "cached"} for status in statuses)
    total_skipped_pairs = sum(status.startswith("skipped_") for status in statuses)
    total_cached_pairs = sum(status == "cached" for status in statuses)
    total_failed_pairs = sum(status in {"failed", "pending_configuration"} for status in statuses)
    total_merged_groups = sum(
        1
        for finding in merged_findings
        if isinstance(finding.get("source_findings"), list) and len(finding["source_findings"]) > 1
    )

    return {
        "mode": mode,
        "suppressed_adapter_findings_count": suppressed,
        "deterministic_same_scanner_merges": deterministic_same_scanner_merges,
        "deterministic_fallback_merges": deterministic_fallback_merges,
        "same_scanner_pairs_skipped": same_scanner_pairs_skipped,
        "same_target_pairs_considered": sum(bool(record.get("same_target")) for record in comparison_records),
        "llm_calls": sum(status == "compared_with_llm" for status in statuses),
        "cache_hits": total_cached_pairs,
        "yes_decisions": sum(record.get("llm_decision") == "yes" for record in comparison_records),
        "no_decisions": sum(record.get("llm_decision") == "no" for record in comparison_records),
        "failed_or_pending": total_failed_pairs,
        "different_target_pairs_skipped": sum(status == "skipped_different_target" for status in statuses),
        "low_similarity_pairs_skipped": sum(status == "skipped_low_similarity" for status in statuses),
        "pairs_sent_to_llm": pairs_sent_to_llm,
        "pairs_reused_from_cache": pairs_reused_from_cache,
        "pairs_blocked_by_same_target": pairs_blocked_by_same_target,
        "pairs_blocked_by_similarity_gate": pairs_blocked_by_similarity_gate,
        "total_compared_pairs": total_compared_pairs,
        "total_skipped_pairs": total_skipped_pairs,
        "total_cached_pairs": total_cached_pairs,
        "total_failed_pairs": total_failed_pairs,
        "total_merged_groups": total_merged_groups,
        "final_merged_finding_count": len(merged_findings),
        "merged_clusters": total_merged_groups,
        "provider_healthcheck_status": provider_state.get("healthcheck_status"),
        "provider_healthcheck_error": provider_state.get("healthcheck_error"),
        "live_llm_comparisons_attempted": provider_state.get("live_attempted", 0),
        "live_llm_comparisons_succeeded": provider_state.get("live_succeeded", 0),
        "live_llm_comparisons_failed": provider_state.get("live_failed", 0),
        "comparisons_skipped_due_to_provider_state": provider_state.get("skipped_due_to_provider_state", 0),
        "rate_limit_encountered": bool(provider_state.get("rate_limit_encountered")),
        "provider_disabled_mid_run": bool(provider_state.get("provider_disabled_mid_run")),
        "provider_failure_categories": provider_state.get("failure_categories", {}),
    }


class LLMDuplicateResolver:
    """Apply the active LLM-backed duplicate flow to one scan result set."""

    def __init__(
        self,
        config: LLMDuplicateConfig,
        *,
        database: Optional[UnifiedVulnerabilityDatabase] = None,
        client: Optional[OpenAICompatibleLLMClient] = None,
    ):
        self.config = config
        self.database = database
        self.client = client or OpenAICompatibleLLMClient(config)

    def _new_run_context(self) -> _ResolverRunContext:
        """Return isolated mutable state for one apply() call."""
        return _ResolverRunContext()

    def _increment_failure_category(
        self,
        run_context: _ResolverRunContext,
        category: Optional[str],
    ) -> None:
        """Track provider failure category counts for duplicate-analysis."""
        if not category:
            return
        current = int(run_context.provider_state["failure_categories"].get(category) or 0)
        run_context.provider_state["failure_categories"][category] = current + 1

    def _disable_reason_for_live_error(
        self,
        run_context: _ResolverRunContext,
        error: LLMProviderError,
    ) -> Optional[str]:
        """Return the run-disable reason for a live comparison error, if any.

        Policy:
        - pair-local failures like invalid requests and timeouts should fail only
          the current comparison
        - clearly global provider failures should stop further live comparisons
          for the rest of the run
        """
        if error.category == "rate_limited":
            return "rate_limit_exhausted"
        if error.category in {"billing_or_region_issue", "permission_denied"}:
            return "provider_globally_blocked"
        if error.category == "provider_unavailable":
            failures = int(
                run_context.provider_state["failure_categories"].get("provider_unavailable") or 0
            )
            if failures >= PROVIDER_UNAVAILABLE_DISABLE_THRESHOLD:
                return "provider_unavailable_repeated"
        return None

    def _provider_state_snapshot(self, run_context: _ResolverRunContext) -> Dict[str, Any]:
        """Return a compact snapshot suitable for traces and results."""
        return {
            "healthcheck_status": run_context.provider_state.get("healthcheck_status"),
            "healthcheck_error": run_context.provider_state.get("healthcheck_error"),
            "disabled_reason": run_context.provider_state.get("disabled_reason"),
            "disabled_error": run_context.provider_state.get("disabled_error"),
            "disabled_category": run_context.provider_state.get("disabled_category"),
            "disabled_http_status_code": run_context.provider_state.get("disabled_http_status_code"),
            "rate_limit_encountered": bool(run_context.provider_state.get("rate_limit_encountered")),
            "provider_disabled_mid_run": bool(run_context.provider_state.get("provider_disabled_mid_run")),
        }

    def _disable_provider_for_run(
        self,
        run_context: _ResolverRunContext,
        *,
        reason: str,
        error: LLMProviderError,
        mid_run: bool,
    ) -> None:
        """Disable further live LLM comparisons for the current resolver run."""
        run_context.provider_state["disabled_reason"] = reason
        run_context.provider_state["disabled_error"] = str(error)
        run_context.provider_state["disabled_category"] = error.category
        run_context.provider_state["disabled_http_status_code"] = error.http_status_code
        run_context.provider_state["rate_limit_encountered"] = bool(
            run_context.provider_state.get("rate_limit_encountered") or error.category == "rate_limited"
        )
        run_context.provider_state["provider_disabled_mid_run"] = bool(
            run_context.provider_state.get("provider_disabled_mid_run") or mid_run
        )

    def _provider_skip_status(self, run_context: _ResolverRunContext) -> str:
        """Return the pair status used when provider state blocks live comparisons.

        `skipped_provider_unavailable` is the generic run-disabled status for
        provider-wide blocks other than rate limiting or pre-comparison
        health-check failure.
        """
        if run_context.provider_state.get("disabled_reason") == "healthcheck_failed":
            return "skipped_after_healthcheck_failure"
        if run_context.provider_state.get("disabled_category") == "rate_limited":
            return "skipped_rate_limited"
        return "skipped_provider_unavailable"

    def _provider_skip_error_message(self, run_context: _ResolverRunContext) -> str:
        """Return a concise explanation for provider-state skips."""
        category = _safe_text(run_context.provider_state.get("disabled_category")) or "provider_error"
        reason = _safe_text(run_context.provider_state.get("disabled_reason")) or "provider_unavailable"
        detail = _safe_text(run_context.provider_state.get("disabled_error"))
        prefix = f"Live LLM comparisons disabled for this run ({reason}, {category})."
        if detail:
            return f"{prefix} {detail}"
        return prefix

    def _provider_skip_payload(self, run_context: _ResolverRunContext) -> Dict[str, Any]:
        """Return structured provider-state details for skipped pairs."""
        payload: Dict[str, Any] = {
            "provider_state": self._provider_state_snapshot(run_context),
        }
        if run_context.provider_state.get("healthcheck_payload") is not None:
            payload["healthcheck"] = run_context.provider_state["healthcheck_payload"]
        return payload

    def _provider_skip_record(
        self,
        run_context: _ResolverRunContext,
        record: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Stamp provider-state skip details onto one comparison record."""
        run_context.provider_state["skipped_due_to_provider_state"] += 1
        record.update(
            {
                "comparison_status": self._provider_skip_status(run_context),
                "error_message": self._provider_skip_error_message(run_context),
                "provider_failure_category": run_context.provider_state.get("disabled_category"),
                "http_status_code": run_context.provider_state.get("disabled_http_status_code"),
            }
        )
        response_payload = record.get("response_payload") if isinstance(record.get("response_payload"), dict) else {}
        response_payload.update(self._provider_skip_payload(run_context))
        record["response_payload"] = response_payload
        return record

    def _ensure_provider_healthcheck(self, run_context: _ResolverRunContext) -> bool:
        """Run one health check before the first live comparison of this run."""
        if not self.config.enabled or not self.config.ready:
            return False
        if run_context.provider_state.get("healthcheck_status") == "passed":
            return True
        if run_context.provider_state.get("healthcheck_status") == "failed":
            return False

        healthcheck = getattr(self.client, "healthcheck", None)
        if not callable(healthcheck):
            run_context.provider_state["healthcheck_status"] = "not_supported"
            return True

        try:
            payload = healthcheck()
            run_context.provider_state["healthcheck_status"] = "passed"
            run_context.provider_state["healthcheck_error"] = None
            run_context.provider_state["healthcheck_payload"] = payload
            return True
        except Exception as exc:
            provider_error = _coerce_provider_error(exc, request_kind="healthcheck")
            self._increment_failure_category(run_context, provider_error.category)
            run_context.provider_state["healthcheck_status"] = "failed"
            run_context.provider_state["healthcheck_error"] = str(provider_error)
            run_context.provider_state["healthcheck_payload"] = {
                "status": "failed",
                "provider_error": provider_error.to_trace_payload(),
            }
            self._disable_provider_for_run(
                run_context,
                reason="healthcheck_failed",
                error=provider_error,
                mid_run=False,
            )
            logger.warning("LLM provider health check failed: %s", provider_error)
            return False

    def _comparison_record_base(
        self,
        run_context: _ResolverRunContext,
        finding_a: Dict[str, Any],
        finding_b: Dict[str, Any],
        *,
        same_target: bool,
        pair_key: str,
        cache_key: Optional[str],
        target_match_details: Optional[Dict[str, Any]] = None,
        cheap_filter_details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build the common trace record fields for one finding pair."""
        ordered_a, ordered_b = _normalize_order(finding_a, finding_b)
        return {
            "cache_key": cache_key,
            "pair_key": pair_key,
            "comparison_semantics_version": LLM_DUPLICATE_CACHE_SEMANTICS_VERSION,
            "prompt_version": LLM_DUPLICATE_PROMPT_VERSION,
            "compared_finding_a_id": ordered_a["finding_id"],
            "compared_finding_b_id": ordered_b["finding_id"],
            "scanner_a": _scanner_name(ordered_a),
            "scanner_b": _scanner_name(ordered_b),
            "same_target": same_target,
            "comparison_status": "pending",
            "cheap_filter_decision": (
                cheap_filter_details.get("decision")
                if isinstance(cheap_filter_details, dict)
                else None
            ),
            "llm_decision": None,
            "same_vulnerability": None,
            "merge_approved": False,
            "confidence": None,
            "reason": None,
            "canonical_title": None,
            "needs_review": False,
            "compared_at": None,
            "model_name": self.config.model_name,
            "request_hash": None,
            "raw_response": None,
            "error_message": None,
            "provider_failure_category": None,
            "http_status_code": None,
            "provider_request_kind": None,
            "provider_attempt_count": None,
            "provider_retry_backoff_seconds": [],
            "final_merge_result": None,
            "merged_finding_id": None,
            "sent_to_llm": False,
            "used_cache": False,
            "target_match_details": copy.deepcopy(target_match_details),
            "llm_request_preview": _comparison_request_preview(ordered_a, ordered_b),
            "llm_request_payload": (
                _comparison_prompt_payload(
                    ordered_a,
                    ordered_b,
                    runtime_cache=run_context.runtime_cache,
                )
                if self.config.debug
                else None
            ),
            "llm_request_body": (
                build_llm_request_body(
                    ordered_a,
                    ordered_b,
                    model_name=str(self.config.model_name or ""),
                    runtime_cache=run_context.runtime_cache,
                )
                if self.config.debug
                else None
            ),
            "explainability": _build_explainability(
                same_target=same_target,
                target_match_details=target_match_details,
                cheap_filter_details=cheap_filter_details,
            ),
            "response_payload": None,
            "created_at": None,
            "updated_at": None,
        }

    def _compare_pair(
        self,
        run_context: _ResolverRunContext,
        finding_a: Dict[str, Any],
        finding_b: Dict[str, Any],
        *,
        cheap_filter_details: Dict[str, Any],
        target_match_details: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compare one same-target pair through cache or live LLM call."""
        pair_key = _pair_key(finding_a, finding_b)
        cache_key: Optional[str] = None
        if self.database is not None:
            _, cache_key = _comparison_cache_key(
                finding_a,
                finding_b,
                model_name=str(self.config.model_name or ""),
                runtime_cache=run_context.runtime_cache,
            )
        record = self._comparison_record_base(
            run_context,
            finding_a,
            finding_b,
            same_target=True,
            pair_key=pair_key,
            cache_key=cache_key,
            target_match_details=target_match_details,
            cheap_filter_details=cheap_filter_details,
        )
        record["response_payload"] = _merge_trace_response_payload(
            None,
            target_match_details=target_match_details,
            cheap_filter_details=cheap_filter_details,
        )

        if self.database and self.config.cache_enabled:
            cached = self.database.get_llm_comparison(cache_key)
            cached_decision = _decision_from_record(cached) if cached else None
            cache_versions_match = bool(
                cached
                and cached.get("prompt_version") == LLM_DUPLICATE_PROMPT_VERSION
                and cached.get("comparison_semantics_version")
                == LLM_DUPLICATE_CACHE_SEMANTICS_VERSION
            )
            if cached_decision is not None and cache_versions_match:
                cached_record = dict(record)
                for field in (
                    "llm_decision",
                    "same_vulnerability",
                    "merge_approved",
                    "confidence",
                    "reason",
                    "canonical_title",
                    "needs_review",
                    "compared_at",
                    "request_hash",
                    "error_message",
                    "provider_failure_category",
                    "http_status_code",
                    "provider_request_kind",
                    "provider_attempt_count",
                    "provider_retry_backoff_seconds",
                    "final_merge_result",
                    "merged_finding_id",
                    "created_at",
                    "updated_at",
                ):
                    if field in cached:
                        cached_record[field] = copy.deepcopy(cached[field])
                cached_record.update(
                    {
                        "llm_decision": cached_decision.llm_decision,
                        "same_vulnerability": cached_decision.same_vulnerability,
                        "merge_approved": cached_decision.merge_approved,
                        "confidence": cached_decision.confidence,
                        "reason": cached_decision.reason,
                        "canonical_title": cached_decision.canonical_title,
                        "needs_review": cached_decision.needs_review,
                    }
                )
                cached_record["raw_response"] = (
                    copy.deepcopy(cached.get("raw_response"))
                    if self.config.debug
                    else None
                )
                cached_record["comparison_status"] = "cached"
                cached_record["used_cache"] = True
                cached_record["response_payload"] = _merge_trace_response_payload(
                    _trace_provider_payload(
                        cached.get("response_payload"),
                        debug=self.config.debug,
                    ),
                    target_match_details=target_match_details,
                    cheap_filter_details=cheap_filter_details,
                )
                return cached_record

        if not self.config.enabled:
            record["comparison_status"] = "skipped_duplicate_mode_off"
            return record

        if not self.config.ready:
            validation_error = self.config.validation_error()
            record["comparison_status"] = "pending_configuration"
            record["error_message"] = validation_error or (
                "LLM duplicate mode is enabled but the LLM provider is not fully configured."
            )
            return record

        if run_context.provider_state.get("disabled_reason"):
            return self._provider_skip_record(run_context, record)

        if not self._ensure_provider_healthcheck(run_context):
            return self._provider_skip_record(run_context, record)

        compared_at = utcnow_iso()
        try:
            run_context.provider_state["live_attempted"] += 1
            record["sent_to_llm"] = True
            ordered_a, ordered_b = _normalize_order(finding_a, finding_b)
            decision, response_payload, raw_response, request_hash = self.client.compare(
                ordered_a,
                ordered_b,
                runtime_cache=run_context.runtime_cache,
            )
            if not isinstance(decision, LLMDuplicateDecision):
                raise ValueError("LLM client returned a non-structured duplicate decision")
            run_context.provider_state["live_succeeded"] += 1
            record.update(
                {
                    "comparison_status": "compared_with_llm",
                    "llm_decision": decision.llm_decision,
                    "same_vulnerability": decision.same_vulnerability,
                    "merge_approved": decision.merge_approved,
                    "confidence": decision.confidence,
                    "reason": decision.reason,
                    "canonical_title": decision.canonical_title,
                    "needs_review": decision.needs_review,
                    "compared_at": compared_at,
                    "request_hash": request_hash,
                    "provider_request_kind": "comparison",
                    "provider_attempt_count": (
                        response_payload.get("_provider_request", {}).get("attempt_count")
                        if isinstance(response_payload, dict)
                        else None
                    ),
                    "provider_retry_backoff_seconds": (
                        list(response_payload.get("_provider_request", {}).get("retry_backoff_seconds") or [])
                        if isinstance(response_payload, dict)
                        else []
                    ),
                    "response_payload": _merge_trace_response_payload(
                        _trace_provider_payload(
                            response_payload,
                            debug=self.config.debug,
                        ),
                        target_match_details=target_match_details,
                        cheap_filter_details=cheap_filter_details,
                    ),
                    "raw_response": raw_response if self.config.debug else None,
                }
            )
        except Exception as exc:
            provider_error = _coerce_provider_error(exc, request_kind="comparison")
            run_context.provider_state["live_failed"] += 1
            self._increment_failure_category(run_context, provider_error.category)
            disable_reason = self._disable_reason_for_live_error(run_context, provider_error)
            if disable_reason:
                self._disable_provider_for_run(
                    run_context,
                    reason=disable_reason,
                    error=provider_error,
                    mid_run=True,
                )
            logger.warning(
                "LLM duplicate comparison failed for %s: %s",
                pair_key,
                provider_error,
            )
            record.update(
                {
                    "comparison_status": "failed",
                    "compared_at": compared_at,
                    "request_hash": provider_error.request_hash,
                    "error_message": str(provider_error),
                    "provider_failure_category": provider_error.category,
                    "http_status_code": provider_error.http_status_code,
                    "provider_request_kind": provider_error.request_kind,
                    "provider_attempt_count": provider_error.attempt_count,
                    "provider_retry_backoff_seconds": list(provider_error.retry_backoff_seconds),
                    "response_payload": _merge_trace_response_payload(
                        _trace_provider_payload(
                            {
                                "provider_error": provider_error.to_trace_payload(),
                                "provider_state": self._provider_state_snapshot(run_context),
                            },
                            debug=self.config.debug,
                        ),
                        target_match_details=target_match_details,
                        cheap_filter_details=cheap_filter_details,
                    ),
                    "raw_response": provider_error.response_text if self.config.debug else None,
                }
            )
        return record

    def _premerge_cross_scanner_deterministic_duplicates(
        self,
        run_context: _ResolverRunContext,
        findings: List[Dict[str, Any]],
        *,
        order_by_finding_id: Dict[str, int],
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Merge only high-confidence cross-scanner duplicates before any LLM calls."""
        if len(findings) < 2:
            return list(findings), 0

        deterministic_records: List[Dict[str, Any]] = []
        deterministic_match_lookup: Dict[str, Dict[str, Any]] = {}
        buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
        for finding in findings:
            buckets.setdefault(
                _coarse_target_bucket(
                    finding,
                    runtime_cache=run_context.runtime_cache,
                ),
                [],
            ).append(finding)

        for group in buckets.values():
            for finding_a, finding_b in combinations(group, 2):
                match = _deterministic_cross_scanner_match(
                    finding_a,
                    finding_b,
                    runtime_cache=run_context.runtime_cache,
                )
                if match is None:
                    continue
                pair_key = _pair_key(finding_a, finding_b)
                deterministic_records.append(
                    {
                        "pair_key": pair_key,
                        "llm_decision": "yes",
                        "merge_approved": True,
                        "comparison_status": "deterministic_premerge",
                    }
                )
                deterministic_match_lookup[pair_key] = match

        if not deterministic_records:
            return list(findings), 0

        clusters = self._cluster_findings(findings, deterministic_records)
        merged_findings: List[Dict[str, Any]] = []
        for cluster in clusters:
            cluster = sorted(
                cluster,
                key=lambda finding: _finding_original_order(finding, order_by_finding_id),
            )
            if len(cluster) == 1:
                merged_findings.append(cluster[0])
                continue

            cluster_matches: List[Dict[str, Any]] = []
            for left, right in combinations(cluster, 2):
                pair_key = _pair_key(left, right)
                match = deterministic_match_lookup.get(pair_key)
                if match is not None:
                    cluster_matches.append(match)

            duplicate_resolution_extra: Dict[str, Any] = {
                "stage": "pre_llm",
            }
            reasons = _ordered_unique(
                match.get("reason")
                for match in cluster_matches
                if match.get("reason")
            )
            if reasons:
                duplicate_resolution_extra["rules"] = reasons
            shared_cves = _ordered_unique(
                cve
                for match in cluster_matches
                for cve in match.get("shared_cves", [])
            )
            if shared_cves:
                duplicate_resolution_extra["shared_cves"] = shared_cves
            shared_families = _ordered_unique(
                family
                for match in cluster_matches
                for family in match.get("shared_families", [])
            )
            if shared_families:
                duplicate_resolution_extra["shared_families"] = shared_families

            merged_findings.append(
                merge_deterministic_cluster(
                    cluster,
                    reason="cross_scanner_obvious_duplicate",
                    duplicate_resolution_extra=duplicate_resolution_extra,
                )
            )

        merged_findings = sorted(
            merged_findings,
            key=lambda finding: _finding_original_order(finding, order_by_finding_id),
        )
        return merged_findings, max(0, len(findings) - len(merged_findings))

    def _cluster_findings(
        self,
        findings: List[Dict[str, Any]],
        comparison_records: List[Dict[str, Any]],
    ) -> List[List[Dict[str, Any]]]:
        """Build conservative duplicate clusters from approved decisions only."""
        yes_lookup = {
            record["pair_key"]: record
            for record in comparison_records
            if record.get("merge_approved") is True
            and record.get("comparison_status") in {"cached", "compared_with_llm", "deterministic_premerge"}
        }

        def pair_is_yes(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
            return _pair_key(left, right) in yes_lookup

        ordered = sorted(
            findings,
            key=lambda finding: (_finding_severity_rank(finding), str(finding.get("finding_id"))),
            reverse=True,
        )

        clusters: List[List[Dict[str, Any]]] = []
        for finding in ordered:
            candidates: List[List[Dict[str, Any]]] = []
            finding_scanner = _scanner_name(finding)
            for cluster in clusters:
                comparable_members = [
                    member
                    for member in cluster
                    if _scanner_name(member) != finding_scanner
                ]
                if not comparable_members:
                    continue
                if all(pair_is_yes(finding, member) for member in comparable_members):
                    candidates.append(cluster)

            if not candidates:
                clusters.append([finding])
                continue

            candidates.sort(key=lambda cluster: len(cluster), reverse=True)
            candidates[0].append(finding)

        return clusters

    def apply(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Run the active duplicate-resolution flow on one results payload."""
        all_findings = results.get("all_findings")
        if not isinstance(all_findings, list):
            return results

        run_context = self._new_run_context()

        assign_finding_ids(all_findings, runtime_cache=run_context.runtime_cache)
        order_by_finding_id = {
            str(finding.get("finding_id")): index
            for index, finding in enumerate(all_findings)
            if finding.get("finding_id") is not None
        }
        filtered_findings, suppressed = _suppress_adapter_artifacts(all_findings)
        deterministic_same_scanner_merges = 0
        deterministic_fallback_merges = 0

        if self.config.mode == "llm":
            stage_started_at = time.perf_counter()
            premerged_findings = merge_obvious_duplicates(
                filtered_findings,
                same_scanner_only=True,
            )
            run_context.profiler.add(
                "same_scanner_exact_premerge_seconds",
                time.perf_counter() - stage_started_at,
            )
            deterministic_same_scanner_merges = max(
                0,
                len(filtered_findings) - len(premerged_findings),
            )

            stage_started_at = time.perf_counter()
            filtered_findings, deterministic_fallback_merges = (
                self._premerge_cross_scanner_deterministic_duplicates(
                    run_context,
                    premerged_findings,
                    order_by_finding_id=order_by_finding_id,
                )
            )
            run_context.profiler.add(
                "deterministic_cross_scanner_premerge_seconds",
                time.perf_counter() - stage_started_at,
            )

        comparison_records: List[Dict[str, Any]] = []
        same_scanner_pairs_skipped = 0

        if self.config.mode != "off":
            loop_started_at = time.perf_counter()
            same_target_seconds = 0.0
            cheap_gate_seconds = 0.0
            compare_loop_seconds = 0.0
            buckets: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = {}
            for finding in filtered_findings:
                buckets.setdefault(
                    _coarse_target_bucket(
                        finding,
                        runtime_cache=run_context.runtime_cache,
                    ),
                    [],
                ).append(finding)

            for group in buckets.values():
                for finding_a, finding_b in combinations(group, 2):
                    if _scanner_name(finding_a) == _scanner_name(finding_b):
                        same_scanner_pairs_skipped += 1
                        continue

                    pair_key = _pair_key(finding_a, finding_b)
                    cache_key: Optional[str] = None
                    if self.database is not None:
                        _, cache_key = _comparison_cache_key(
                            finding_a,
                            finding_b,
                            model_name=str(self.config.model_name or ""),
                            runtime_cache=run_context.runtime_cache,
                        )

                    stage_started_at = time.perf_counter()
                    same_target, match_details = findings_share_same_target(
                        finding_a,
                        finding_b,
                        runtime_cache=run_context.runtime_cache,
                    )
                    same_target_seconds += time.perf_counter() - stage_started_at
                    if not same_target:
                        comparison_records.append(
                            {
                                **self._comparison_record_base(
                                    run_context,
                                    finding_a,
                                    finding_b,
                                    same_target=False,
                                    pair_key=pair_key,
                                    cache_key=cache_key,
                                    target_match_details=match_details,
                                ),
                                "comparison_status": "skipped_different_target",
                                "response_payload": _merge_trace_response_payload(
                                    None,
                                    target_match_details=match_details,
                                ),
                            }
                        )
                        continue

                    stage_started_at = time.perf_counter()
                    cheap_filter_details = _cheap_similarity_gate(
                        finding_a,
                        finding_b,
                        runtime_cache=run_context.runtime_cache,
                    )
                    cheap_gate_seconds += time.perf_counter() - stage_started_at
                    if not cheap_filter_details.get("allowed"):
                        comparison_records.append(
                            {
                                **self._comparison_record_base(
                                    run_context,
                                    finding_a,
                                    finding_b,
                                    same_target=True,
                                    pair_key=pair_key,
                                    cache_key=cache_key,
                                    target_match_details=match_details,
                                    cheap_filter_details=cheap_filter_details,
                                ),
                                "comparison_status": "skipped_low_similarity",
                                "response_payload": {
                                    "target_match": match_details,
                                    "cheap_filter": cheap_filter_details,
                                },
                            }
                        )
                        continue

                    stage_started_at = time.perf_counter()
                    record = self._compare_pair(
                        run_context,
                        finding_a,
                        finding_b,
                        cheap_filter_details=cheap_filter_details,
                        target_match_details=match_details,
                    )
                    compare_loop_seconds += time.perf_counter() - stage_started_at
                    comparison_records.append(record)

            total_pair_loop_seconds = time.perf_counter() - loop_started_at
            run_context.profiler.add(
                "same_target_filtering_seconds",
                same_target_seconds,
            )
            run_context.profiler.add(
                "cheap_similarity_gate_seconds",
                cheap_gate_seconds,
            )
            run_context.profiler.add(
                "gray_zone_compare_loop_seconds",
                compare_loop_seconds,
            )
            run_context.profiler.add(
                "candidate_pair_generation_seconds",
                max(
                    0.0,
                    total_pair_loop_seconds
                    - same_target_seconds
                    - cheap_gate_seconds
                    - compare_loop_seconds,
                ),
            )

        stage_started_at = time.perf_counter()
        clusters = (
            self._cluster_findings(filtered_findings, comparison_records)
            if self.config.mode == "llm"
            else [[finding] for finding in filtered_findings]
        )

        comparison_lookup = {
            record["pair_key"]: record
            for record in comparison_records
            if record.get("merge_approved") is True
            and record.get("comparison_status") in {"compared_with_llm", "cached"}
        }

        merged_findings: List[Dict[str, Any]] = []
        materialized_members: List[Tuple[Dict[str, Any], List[Dict[str, Any]]]] = []
        for cluster in clusters:
            cluster = sorted(
                cluster,
                key=lambda finding: _finding_original_order(finding, order_by_finding_id),
            )
            if len(cluster) == 1:
                merged_findings.append(cluster[0])
                materialized_members.append((cluster[0], list(cluster)))
                continue
            cluster_records: List[Dict[str, Any]] = []
            for left, right in combinations(cluster, 2):
                pair_key = _pair_key(left, right)
                record = comparison_lookup.get(pair_key)
                if record is not None:
                    cluster_records.append(record)
            merged_finding = _merge_llm_cluster(cluster, cluster_records)
            merged_findings.append(merged_finding)
            materialized_members.append((merged_finding, list(cluster)))

        if self.config.mode == "llm":
            merged_findings = sorted(
                merged_findings,
                key=lambda finding: _finding_original_order(finding, order_by_finding_id),
            )

        results["all_findings"] = sort_by_severity(merged_findings)
        _annotate_final_merge_results(comparison_records, merged_findings)
        _annotate_structured_correlations(materialized_members, comparison_records)
        run_context.profiler.add(
            "final_merge_materialization_seconds",
            time.perf_counter() - stage_started_at,
        )

        stage_started_at = time.perf_counter()
        _refresh_final_summary(results, suppressed_in_resolver=suppressed)
        if self.database:
            comparison_records = [
                self.database.save_llm_comparison(record)
                for record in comparison_records
            ]
        run_context.profiler.add(
            "summary_recompute_seconds",
            time.perf_counter() - stage_started_at,
        )

        results["llm_duplicate_comparisons"] = comparison_records
        results["duplicate_analysis"] = _build_duplicate_analysis(
            mode=self.config.mode,
            suppressed=suppressed,
            deterministic_same_scanner_merges=deterministic_same_scanner_merges,
            deterministic_fallback_merges=deterministic_fallback_merges,
            same_scanner_pairs_skipped=same_scanner_pairs_skipped,
            comparison_records=comparison_records,
            merged_findings=results["all_findings"],
            provider_state=run_context.provider_state,
        )
        results["duplicate_analysis"]["profiling"] = run_context.profiler.snapshot(
            total_runtime_seconds=time.perf_counter() - run_context.runtime_started_at,
        )
        return results
