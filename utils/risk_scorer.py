"""
Risk Scoring Module

Implements a layered risk model that keeps technical severity separate from
threat, business context, and evidence quality.
"""

from typing import Any, Dict, List, Optional
import re

from utils.deduplicator import is_degraded_finding
from utils.normalizer import create_fingerprints
from utils.result_summary import refresh_summary_counts

PRIORITY_LEVELS = ["P0", "P1", "P2", "P3", "P4"]

PRIORITY_THRESHOLDS = {
    "P0": (85, 100),
    "P1": (65, 84),
    "P2": (45, 64),
    "P3": (25, 44),
    "P4": (0, 24),
}

SEVERITY_FALLBACK_SCORES = {
    "critical": 62,   # raised so critical+dangerous-class+internet reaches P0 without CVSS
    "high": 49,   # raised so high+full-context reaches P1 with new thresholds
    "medium": 30,
    "low": 12,
    "info": 2,
    "unknown": 2,
}

ASSET_CRITICALITY_SCORES = {
    "high": 4,
    "medium": 2,
    "low": 0,
    "unknown": 0,
}

ENVIRONMENT_SCORES = {
    "production": 3,
    "staging": 0,
    "development": -3,
    "test": -2,
    "unknown": 0,
}

CONFIDENCE_ADJUSTMENTS = {
    "high": 0,
    "medium": -1,
    "low": -5,    # reduced penalty so low-confidence critical findings stay actionable
    "unknown": -3,
}

EPSS_SCORE_POINTS = (
    (0.85, 10),
    (0.60, 7),
    (0.30, 4),
    (0.10, 2),
    (0.01, 1),
)

EPSS_PERCENTILE_BONUSES = (
    (0.98, 2),
    (0.90, 1),
)

INTERNET_EXPOSED_SCORE = 6
SENSITIVE_DATA_SCORE = 4
REQUIRES_AUTH_SCORE = -6   # reduced so auth requirement doesn't overpower genuine vuln-class boosts
MAX_BUSINESS_IMPACT_SCORE = 10
MAX_CONTEXTUAL_SCORE = 16
LOW_SIGNAL_CONTEXT_CAP = 12
MAX_EXPLOIT_LIKELIHOOD_SCORE = 12
KNOWN_EXPLOIT_FLOOR = 8
REPEATABILITY_BONUS = 4
LOW_SIGNAL_MAX_SCORE = 35

VULNERABILITY_CLASS_RULES = (
    {
        "id": "remote_code_execution",
        "label": "remote code execution",
        "boost": 18,
        "technical_floor": 78,
        "patterns": (
            r"\bremote code execution\b",
            r"\brce\b",
            r"\bcommand injection\b",
            r"\bos command injection\b",
            r"\bcode injection\b",
            r"\bshell injection\b",
        ),
        "cwes": {77, 78, 88, 94},
    },
    {
        "id": "insecure_deserialization",
        "label": "insecure deserialization",
        "boost": 16,
        "technical_floor": 74,
        "patterns": (
            r"\binsecure deserialization\b",
            r"\bunsafe deserialization\b",
            r"\bdeserialization\b",
        ),
        "cwes": {502},
    },
    {
        "id": "server_side_template_injection",
        "label": "server-side template injection",
        "boost": 16,
        "technical_floor": 72,
        "patterns": (
            r"\bserver[ -]?side template injection\b",
            r"\bssti\b",
        ),
        "cwes": {1336},
    },
    {
        "id": "sql_injection",
        "label": "SQL injection",
        "boost": 14,
        "technical_floor": 60,
        "patterns": (
            r"\bsql injection\b",
            r"\bsqli\b",
        ),
        "cwes": {89, 564},
    },
    {
        "id": "authentication_bypass",
        "label": "authentication or authorization bypass",
        "boost": 14,
        "technical_floor": 60,
        "patterns": (
            r"\bauthentication bypass\b",
            r"\bauthorization bypass\b",
            r"\bauth bypass\b",
            r"\blogin bypass\b",
            r"\baccess control bypass\b",
            r"\bauth[- ]?bypass\b",
        ),
        "cwes": {287, 306, 862, 863},
    },
    {
        "id": "server_side_request_forgery",
        "label": "server-side request forgery",
        "boost": 12,
        "technical_floor": 56,
        "patterns": (
            r"\bserver[ -]?side request forgery\b",
            r"\bssrf\b",
        ),
        "cwes": {918},
    },
    {
        "id": "xml_external_entity",
        "label": "XML external entity",
        "boost": 12,
        "technical_floor": 56,
        "patterns": (
            r"\bxml external entity\b",
            r"\bxxe\b",
        ),
        "cwes": {611},
    },
    {
        "id": "path_traversal",
        "label": "path traversal",
        "boost": 12,
        "technical_floor": 54,
        "patterns": (
            r"\bpath traversal\b",
            r"\bdirectory traversal\b",
            r"\blocal file inclusion\b",
            r"\blfi\b",
            r"\barbitrary file read\b",
            r"\bfile disclosure\b",
        ),
        "cwes": {22, 23, 35, 36, 73},
    },
    {
        "id": "credential_exposure",
        "label": "credential exposure",
        "boost": 12,
        "technical_floor": 54,
        "patterns": (
            r"\bcredential exposure\b",
            r"\bexposed credentials?\b",
            r"\bhardcoded credentials?\b",
            r"\bsecret exposure\b",
            r"\bapi key exposure\b",
            r"\bpassword disclosure\b",
            r"\btoken disclosure\b",
        ),
        "cwes": {259, 312, 522, 798},
    },
)

LOW_SIGNAL_RULES = (
    {
        "id": "missing_hardening_header",
        "label": "missing hardening header",
        "patterns": (
            r"\bmissing security header\b",
            r"\bheader missing\b",
            r"\bmissing (?:the )?(?:strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy)\b",
            r"\b(?:strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy) header missing\b",
        ),
    },
    {
        "id": "header_or_banner_disclosure",
        "label": "header or banner disclosure",
        "patterns": (
            r"\bserver header\b",
            r"\bx-powered-by\b",
            r"\bserver version\b",
            r"\bversion disclosure\b",
            r"\bbanner disclosure\b",
            r"\btechnology stack disclosure\b",
        ),
    },
    {
        "id": "cookie_hardening_flag",
        "label": "cookie hardening flag issue",
        "patterns": (
            r"\bcookie without httponly\b",
            r"\bcookie without secure\b",
            r"\bmissing httponly\b",
            r"\bmissing secure flag\b",
            r"\bsamesite (?:attribute )?(?:is )?missing\b",
        ),
    },
)


def _clamp_int(value: int, minimum: int = 0, maximum: int = 100) -> int:
    """Clamp an integer into the configured score range."""
    return max(minimum, min(maximum, int(value)))


def _coerce_float(value: Any) -> Optional[float]:
    """Convert common score representations to float."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("%"):
            text = text[:-1]
        try:
            return float(text)
        except ValueError:
            return None
    return None


def _normalize_fraction(value: Any) -> Optional[float]:
    """Normalize percentile-like values into the 0.0-1.0 range."""
    coerced = _coerce_float(value)
    if coerced is None:
        return None
    if coerced > 1.0 and coerced <= 100.0:
        coerced /= 100.0
    return max(0.0, min(1.0, coerced))


def _extract_ints(value: Any) -> List[int]:
    """Extract integer identifiers from common CWE-like values."""
    if value is None:
        return []
    if isinstance(value, bool):
        return []
    if isinstance(value, int):
        return [value]
    if isinstance(value, list):
        extracted: List[int] = []
        for item in value:
            extracted.extend(_extract_ints(item))
        return extracted

    text = str(value).strip()
    if not text:
        return []
    return [int(match) for match in re.findall(r"\d+", text)]


def _coerce_bool(value: Any) -> Optional[bool]:
    """Parse common boolean-ish values without guessing too aggressively."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes", "y", "1", "listed"}:
            return True
        if lowered in {"false", "no", "n", "0", "unlisted"}:
            return False
    return None


def _first_value(*values: Any) -> Any:
    """Return the first non-empty value."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, list) and not value:
            continue
        return value
    return None


def _get_finding_value(finding: Dict[str, Any], *keys: str) -> Any:
    """Look up a value from the finding first, then metadata."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    for container in (finding, meta):
        for key in keys:
            if key in container:
                value = container.get(key)
                if value is None:
                    continue
                if isinstance(value, str) and not value.strip():
                    continue
                if isinstance(value, list) and not value:
                    continue
                return value
    return None


def _get_meta_section(finding: Dict[str, Any], section: str) -> Dict[str, Any]:
    """Return a nested metadata section when it is a dict."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        return {}
    value = meta.get(section)
    return value if isinstance(value, dict) else {}


def _get_context_value(context: Dict[str, Any], key: str, asset_id: str) -> Any:
    """Resolve either a global context value or an asset-specific mapping."""
    value = context.get(key)
    if isinstance(value, dict):
        return value.get(asset_id)
    return value


def _normalize_criticality(value: Any) -> str:
    """Normalize asset criticality labels."""
    if value is None:
        return "unknown"
    lowered = str(value).strip().lower()
    aliases = {
        "critical": "high",
        "high": "high",
        "medium": "medium",
        "med": "medium",
        "moderate": "medium",
        "low": "low",
        "unknown": "unknown",
    }
    return aliases.get(lowered, "unknown")


def _normalize_environment(value: Any) -> str:
    """Normalize environment labels to a small stable set."""
    if value is None:
        return "unknown"
    lowered = str(value).strip().lower()
    if lowered in {"production", "prod", "live"}:
        return "production"
    if lowered in {"development", "dev"}:
        return "development"
    if lowered in {"test", "testing", "qa"}:
        return "test"
    if lowered in {"staging", "stage", "preprod", "pre-prod"}:
        return "staging"
    return "unknown"


def _classification_text_blob(finding: Dict[str, Any]) -> str:
    """Build a stable text blob used for vulnerability-class matching."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    parts: List[str] = [
        str(finding.get("vulnerability_name") or ""),
        str(finding.get("description") or ""),
        str(meta.get("raw_id") or ""),
        str(meta.get("cwe") or ""),
    ]
    for key in ("cwe_ids", "references"):
        value = meta.get(key)
        if isinstance(value, list):
            parts.extend(str(item or "") for item in value)
    return " ".join(part for part in parts if part).lower()


def _extract_cwe_numbers(finding: Dict[str, Any]) -> set[int]:
    """Return known CWE identifiers from finding or metadata."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    cwe_values: List[Any] = []
    for container in (finding, meta):
        if not isinstance(container, dict):
            continue
        for key in ("cwe", "cwe_id", "cwe_ids"):
            if key in container:
                cwe_values.append(container.get(key))

    extracted: set[int] = set()
    for value in cwe_values:
        extracted.update(_extract_ints(value))
    return extracted


def _classify_vulnerability(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Classify dangerous vulnerability families that deserve explicit boosts."""
    text = _classification_text_blob(finding)
    cwes = _extract_cwe_numbers(finding)

    for rule in VULNERABILITY_CLASS_RULES:
        matched_on: List[str] = []
        if cwes.intersection(rule["cwes"]):
            matched_on.extend(f"CWE-{cwe}" for cwe in sorted(cwes.intersection(rule["cwes"])))
        for pattern in rule["patterns"]:
            if re.search(pattern, text):
                matched_on.append(pattern)
                break
        if matched_on:
            return {
                "id": rule["id"],
                "label": rule["label"],
                "boost": rule["boost"],
                "technical_floor": rule.get("technical_floor", 0),
                "matched_on": matched_on,
            }

    return {
        "id": "generic_issue",
        "label": "generic issue",
        "boost": 0,
        "technical_floor": 0,
        "matched_on": [],
    }


def _is_internet_exposed(asset_id: str) -> bool:
    """
    Determine if an asset is internet-exposed based on hostname/IP.

    Assumes internet-exposed unless hostname looks internal:
    - *.local, *.internal, *.lan
    - localhost, 127.0.0.1, ::1
    - Private IP ranges (10.x, 172.16-31.x, 192.168.x)
    """
    if not asset_id:
        return False

    asset_lower = asset_id.lower().strip()

    if "://" in asset_lower:
        asset_lower = asset_lower.split("://", 1)[1]

    asset_lower = asset_lower.split("/")[0].split(":")[0]

    internal_patterns = [
        r"localhost",
        r"\.local$",
        r"\.internal$",
        r"\.lan$",
        r"^127\.",
        r"^10\.",
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
        r"^192\.168\.",
        r"^::1$",
        r"^fe80:",
    ]

    for pattern in internal_patterns:
        if re.search(pattern, asset_lower):
            return False

    return True


def _check_auth_required(finding: Dict[str, Any]) -> bool:
    """
    Check if vulnerability requires authentication to exploit.

    Looks for indicators in:
    - finding['meta']['requires_auth']
    - finding['meta']['authenticated']
    - Description contains "authenticated", "after login", etc.
    """
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    explicit = _coerce_bool(_first_value(meta.get("requires_auth"), meta.get("authenticated")))
    if explicit is not None:
        return explicit

    desc = finding.get("description", "").lower()
    no_auth_patterns = (
        r"\bunauthenticated\b",
        r"\bwithout authentication\b",
        r"\bno authentication required\b",
        r"\bauthentication not required\b",
        r"\bpre[- ]auth\b",
        r"\banonymous\b",
    )
    for pattern in no_auth_patterns:
        if re.search(pattern, desc):
            return False

    auth_patterns = (
        r"\bauthenticated\b",
        r"\bafter login\b",
        r"\brequires login\b",
        r"\brequires authentication\b",
        r"\bpost[- ]auth\b",
        r"\bauthenticated user\b",
    )

    for pattern in auth_patterns:
        if re.search(pattern, desc):
            return True

    return False


def _has_known_exploit(finding: Dict[str, Any]) -> bool:
    """
    Check if a public exploit exists for this vulnerability.

    Looks for indicators in:
    - finding['meta']['exploit_available']
    - finding['meta']['exploit_db']
    - References to exploit-db, metasploit, etc. from meta['references']
      (Nuclei — list) or meta['reference'] (ZAP — string).
    """
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    if meta.get("exploit_available") is True:
        return True
    if meta.get("exploit_db"):
        return True

    ref_parts: List[str] = []
    for key in ("reference", "references"):
        val = meta.get(key)
        if isinstance(val, list):
            ref_parts.extend(str(r) for r in val)
        elif isinstance(val, str) and val:
            ref_parts.append(val)

    if ref_parts:
        refs_str = " ".join(ref_parts).lower()
        exploit_reference_patterns = (
            r"exploit-db",
            r"exploitdb",
            r"metasploit",
            r"packetstorm",
            r"\bpublic exploit\b",
            r"\bproof[- ]of[- ]concept exploit\b",
            r"\bpoc exploit\b",
            r"github\.com/\S*(?:exploit|proof[-_]of[-_]concept|poc[-_]exploit)\S*",
        )
        for pattern in exploit_reference_patterns:
            if re.search(pattern, refs_str):
                return True

    return False


def _get_asset_criticality(asset_id: str, finding: Dict[str, Any], context: Dict[str, Any]) -> str:
    """Determine asset criticality from finding metadata or score context."""
    business_context = _get_meta_section(finding, "business_context")
    explicit = _first_value(
        business_context.get("asset_criticality"),
        _get_finding_value(finding, "asset_criticality"),
        _get_context_value(context, "asset_criticality", asset_id),
    )
    return _normalize_criticality(explicit)


_ZAP_NUMERIC_CONFIDENCE: Dict[int, str] = {0: "low", 1: "low", 2: "medium", 3: "high"}


def _get_confidence(finding: Dict[str, Any]) -> str:
    """
    Extract confidence level from finding metadata.

    Handles named strings, ZAP numeric values, and falls back to medium.
    """
    evidence_quality = _get_meta_section(finding, "evidence_quality")
    confidence = _first_value(
        evidence_quality.get("confidence"),
        _get_finding_value(finding, "confidence"),
        "medium",
    )

    if isinstance(confidence, str):
        conf_lower = confidence.lower()
        if conf_lower in ("high", "certain", "confirmed"):
            confidence_label = "high"
        elif conf_lower in ("low", "tentative", "possible"):
            confidence_label = "low"
        elif conf_lower.isdigit():
            confidence_label = _ZAP_NUMERIC_CONFIDENCE.get(int(conf_lower), "medium")
        else:
            confidence_label = "medium"
    elif isinstance(confidence, int) and not isinstance(confidence, bool):
        confidence_label = _ZAP_NUMERIC_CONFIDENCE.get(confidence, "medium")
    else:
        confidence_label = "medium"

    degraded = _degraded_evidence_state(finding)
    if degraded["all"]:
        return "low"
    if degraded["any"] and confidence_label == "high":
        return "medium"
    return confidence_label


def _get_confidence_state(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return normalized confidence plus whether the scanner explicitly supplied it."""
    evidence_quality = _get_meta_section(finding, "evidence_quality")
    explicit_confidence = _first_value(
        evidence_quality.get("confidence"),
        _get_finding_value(finding, "confidence"),
    )
    return {
        "label": _get_confidence(finding),
        "provided": explicit_confidence is not None,
    }


def _source_record_is_degraded(source: Dict[str, Any]) -> bool:
    """Return True when one preserved source record is degraded."""
    if source.get("degraded_execution") is True:
        return True
    meta = source.get("meta", {})
    return isinstance(meta, dict) and meta.get("degraded_execution") is True


def _degraded_evidence_state(finding: Dict[str, Any]) -> Dict[str, bool]:
    """Return whether a finding contains any or only degraded source evidence."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list) and source_findings:
        degraded_states = [
            _source_record_is_degraded(source)
            for source in source_findings
            if isinstance(source, dict)
        ]
        if degraded_states:
            return {
                "any": any(degraded_states),
                "all": all(degraded_states),
            }

    degraded = is_degraded_finding(finding)
    return {
        "any": degraded,
        "all": degraded,
    }


def _is_repeatable(finding: Dict[str, Any], context: Dict[str, Any]) -> bool:
    """
    Check if finding was confirmed across multiple scans.

    Matching strategy:
      1. fp_strict of current vs fp_strict of previous
      2. fp_general fallback when strict fingerprints are missing

    BUG-09 fix: previous findings are NOT mutated in place.  We compute
    fingerprints from a defensive copy so that results['previous_findings']
    (which is persisted as the baseline for the next scan) is not altered.
    """
    # Ensure current finding has fingerprints; updating the current finding
    # is intentional (it is already being modified by the scoring pipeline).
    if not finding.get('fp_strict') and not finding.get('fp_general'):
        finding.update(create_fingerprints(finding))

    curr_strict = finding.get('fp_strict') or ''
    curr_general = finding.get('fp_general') or ''

    if not curr_strict and not curr_general:
        return False

    previous = context.get('previous_findings', [])
    for prev in previous:
        # BUG-09: read fingerprints without writing back to prev.
        prev_fps = create_fingerprints(prev)
        prev_strict = prev.get('fp_strict') or prev_fps.get('fp_strict') or ''
        prev_general = prev.get('fp_general') or prev_fps.get('fp_general') or ''

        if curr_strict and prev_strict:
            if curr_strict == prev_strict:
                return True
            continue

        if curr_general and prev_general and curr_general == prev_general:
            return True

    return False


def _extract_cvss_info(finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return canonical CVSS metadata, preferring v4.0 over v3.1."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    version_hint = _first_value(meta.get("cvss_version"), finding.get("cvss_version"))
    version_hint = str(version_hint).strip() if version_hint is not None else ""

    generic_vector = _first_value(meta.get("cvss_vector"), finding.get("cvss_vector"))
    v4_vector = _first_value(meta.get("cvss_v4_vector"), finding.get("cvss_v4_vector"))
    v3_vector = _first_value(
        meta.get("cvss_v3_1_vector"),
        meta.get("cvss_v31_vector"),
        meta.get("cvss_v3_vector"),
        finding.get("cvss_v3_1_vector"),
        finding.get("cvss_v31_vector"),
        finding.get("cvss_v3_vector"),
    )

    v4_score = _first_value(
        _coerce_float(meta.get("cvss_v4")),
        _coerce_float(meta.get("cvss_v4_score")),
        _coerce_float(finding.get("cvss_v4")),
        _coerce_float(finding.get("cvss_v4_score")),
    )
    if v4_score is None and version_hint in {"4", "4.0"}:
        v4_score = _first_value(
            _coerce_float(meta.get("cvss_score")),
            _coerce_float(meta.get("cvss")),
            _coerce_float(finding.get("cvss_score")),
            _coerce_float(finding.get("cvss")),
        )
    if v4_score is None and isinstance(generic_vector, str) and generic_vector.startswith("CVSS:4.0"):
        v4_score = _first_value(
            _coerce_float(meta.get("cvss_score")),
            _coerce_float(meta.get("cvss")),
            _coerce_float(finding.get("cvss_score")),
            _coerce_float(finding.get("cvss")),
        )
    if v4_score is not None:
        return {
            "score": max(0.0, min(10.0, float(v4_score))),
            "version": "4.0",
            "vector": _first_value(v4_vector, generic_vector),
            "source": "CVSS v4.0",
        }

    v31_score = _first_value(
        _coerce_float(meta.get("cvss_v3_1")),
        _coerce_float(meta.get("cvss_v31")),
        _coerce_float(meta.get("cvss_v3_score")),
        _coerce_float(meta.get("cvss_v3_1_score")),
        _coerce_float(finding.get("cvss_v3_1")),
        _coerce_float(finding.get("cvss_v31")),
        _coerce_float(finding.get("cvss_v3_score")),
        _coerce_float(finding.get("cvss_v3_1_score")),
    )
    if v31_score is None:
        generic_score = _first_value(
            _coerce_float(meta.get("cvss_score")),
            _coerce_float(meta.get("cvss")),
            _coerce_float(finding.get("cvss_score")),
            _coerce_float(finding.get("cvss")),
        )
        if generic_score is not None and version_hint not in {"4", "4.0"}:
            v31_score = generic_score
    if v31_score is not None:
        return {
            "score": max(0.0, min(10.0, float(v31_score))),
            "version": "3.1",
            "vector": _first_value(v3_vector, generic_vector),
            "source": "CVSS v3.1",
        }

    return None


def _extract_epss_info(finding: Dict[str, Any]) -> Dict[str, Optional[float]]:
    """Return normalized EPSS metadata when present."""
    # Prefer raw EPSS inputs over previously-computed canonical fields.
    score = _normalize_fraction(_get_finding_value(finding, "epss", "epss_score"))
    percentile = _normalize_fraction(_get_finding_value(finding, "epss_percentile"))
    return {
        "score": score,
        "percentile": percentile,
    }


def _extract_kev_info(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return KEV metadata in a stable shape."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    kev_block = meta.get("kev")
    listed = _coerce_bool(_get_finding_value(finding, "kev_listed"))
    source = _first_value(_get_finding_value(finding, "kev_source"), meta.get("cisa_kev_source"))
    due_date = _first_value(_get_finding_value(finding, "kev_due_date"), meta.get("cisa_kev_due_date"))

    if isinstance(kev_block, dict):
        listed = _coerce_bool(_first_value(kev_block.get("listed"), kev_block.get("kev_listed"), listed))
        source = _first_value(source, kev_block.get("source"), kev_block.get("catalog"))
        due_date = _first_value(due_date, kev_block.get("due_date"), kev_block.get("date_due"))
    elif listed is None:
        listed = _coerce_bool(kev_block)

    return {
        "listed": bool(listed),
        "source": source,
        "due_date": due_date,
    }


def _score_technical_severity(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Score the technical severity layer, preferring CVSS over scanner severity."""
    severity = str(finding.get("severity", "unknown")).lower()
    cvss = _extract_cvss_info(finding)
    vuln_class = _classify_vulnerability(finding)
    technical_floor = int(vuln_class.get("technical_floor") or 0)

    if cvss:
        base_points = int(round(cvss["score"] * 6.5))  # 6.5x gives CVSS 8.8 → 57 pts; CVSS 10 → 65 pts
        detail = f"{cvss['source']} {cvss['score']:.1f}"
        if cvss.get("vector"):
            detail += f" ({cvss['vector']})"
        raw_points = base_points + vuln_class["boost"]
        return {
            "base_points": base_points,
            "raw_points": raw_points,
            "points": raw_points,
            "source": cvss["source"],
            "detail": detail,
            "vulnerability_class": vuln_class,
            "technical_floor": None,
            "technical_floor_applied": 0,
            "cvss": cvss,
        }

    base_points = SEVERITY_FALLBACK_SCORES.get(severity, SEVERITY_FALLBACK_SCORES["unknown"])
    raw_points = base_points + vuln_class["boost"]
    points = raw_points
    floor_applied = 0
    if technical_floor > points:
        floor_applied = technical_floor - points
        points = technical_floor

    return {
        "base_points": base_points,
        "raw_points": raw_points,
        "points": points,
        "source": "scanner severity fallback",
        "detail": f"normalized severity {severity}",
        "vulnerability_class": vuln_class,
        "technical_floor": technical_floor if floor_applied else None,
        "technical_floor_applied": floor_applied,
        "cvss": None,
    }


def _score_exploit_likelihood(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Score EPSS and public exploit evidence as a bounded threat signal."""
    epss = _extract_epss_info(finding)
    points = 0
    applied: List[str] = []
    known_exploit = _has_known_exploit(finding)

    score = epss["score"]
    percentile = epss["percentile"]
    score_points = 0
    percentile_bonus = 0

    if score is not None:
        for threshold, threshold_points in EPSS_SCORE_POINTS:
            if score >= threshold:
                score_points = threshold_points
                break
    elif percentile is not None and percentile >= 0.75:
        score_points = 1

    if percentile is not None:
        for threshold, bonus in EPSS_PERCENTILE_BONUSES:
            if percentile >= threshold:
                percentile_bonus = bonus
                break

    if score_points:
        label = f"EPSS {score:.3f}" if score is not None else "EPSS percentile-only signal"
        applied.append(f"{label} +{score_points}")
    if percentile_bonus:
        applied.append(f"EPSS percentile {percentile:.0%} +{percentile_bonus}")

    points = min(MAX_EXPLOIT_LIKELIHOOD_SCORE, score_points + percentile_bonus)

    if known_exploit:
        if points < KNOWN_EXPLOIT_FLOOR:
            points = KNOWN_EXPLOIT_FLOOR
            applied.append(f"public exploit evidence -> floor +{KNOWN_EXPLOIT_FLOOR}")

    return {
        "points": points,
        "epss_used": score is not None or percentile is not None,
        "epss_score": score,
        "epss_percentile": percentile,
        "known_exploit": known_exploit,
        "score_points": score_points,
        "percentile_bonus": percentile_bonus,
        "known_exploit_floor_applied": KNOWN_EXPLOIT_FLOOR if known_exploit and points == KNOWN_EXPLOIT_FLOOR else 0,
        "applied": applied,
    }


def _resolve_business_context_inputs(
    finding: Dict[str, Any],
    context: Dict[str, Any],
) -> Dict[str, Any]:
    """Resolve normalized business and reachability inputs once."""
    asset_id = finding.get("asset_id", "")
    business_context = _get_meta_section(finding, "business_context")

    explicit_exposure = _coerce_bool(
        _first_value(
            business_context.get("internet_exposed"),
            _get_finding_value(finding, "internet_exposed"),
            _get_context_value(context, "internet_exposed", asset_id),
        )
    )
    host_hint = asset_id or str(_get_finding_value(finding, "host") or "")
    internet_exposed = explicit_exposure if explicit_exposure is not None else _is_internet_exposed(host_hint)

    asset_criticality = _get_asset_criticality(asset_id, finding, context)
    environment = _normalize_environment(
        _first_value(
            business_context.get("environment"),
            _get_finding_value(finding, "environment"),
            _get_context_value(context, "environment", asset_id),
        )
    )
    sensitive_data = bool(
        _coerce_bool(
            _first_value(
                business_context.get("sensitive_data"),
                _get_finding_value(finding, "sensitive_data"),
                _get_context_value(context, "sensitive_data", asset_id),
            )
        )
    )
    requires_auth = bool(
        _coerce_bool(
            _first_value(
                business_context.get("requires_auth"),
                _get_finding_value(finding, "requires_auth"),
                _get_context_value(context, "requires_auth", asset_id),
            )
        )
    )
    if "requires_auth" not in business_context and _get_finding_value(finding, "requires_auth") is None:
        requires_auth = _check_auth_required(finding)

    return {
        "asset_criticality": asset_criticality,
        "internet_exposed": internet_exposed,
        "environment": environment,
        "sensitive_data": sensitive_data,
        "requires_auth": requires_auth,
    }


def _score_exposure_reachability(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Score exposure and auth reachability separately from business impact."""
    adjustments = {
        "internet_exposed": INTERNET_EXPOSED_SCORE if inputs["internet_exposed"] else 0,
        "requires_auth": REQUIRES_AUTH_SCORE if inputs["requires_auth"] else 0,
    }
    points = max(REQUIRES_AUTH_SCORE, min(INTERNET_EXPOSED_SCORE, sum(adjustments.values())))

    applied: List[str] = []
    if adjustments["internet_exposed"]:
        applied.append(f"internet-exposed +{INTERNET_EXPOSED_SCORE}")
    if adjustments["requires_auth"]:
        applied.append(f"authentication required {REQUIRES_AUTH_SCORE}")

    return {
        "points": points,
        "adjustments": adjustments,
        "applied": applied,
    }


def _score_business_impact(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """Score asset criticality, environment, and data sensitivity."""
    adjustments = {
        "asset_criticality": ASSET_CRITICALITY_SCORES.get(inputs["asset_criticality"], 0),
        "environment": ENVIRONMENT_SCORES.get(inputs["environment"], 0),
        "sensitive_data": SENSITIVE_DATA_SCORE if inputs["sensitive_data"] else 0,
    }
    points = max(-3, min(MAX_BUSINESS_IMPACT_SCORE, sum(adjustments.values())))

    applied: List[str] = []
    if adjustments["asset_criticality"]:
        applied.append(
            f"asset criticality {inputs['asset_criticality']} +{adjustments['asset_criticality']}"
        )
    if adjustments["environment"]:
        sign = "+" if adjustments["environment"] > 0 else ""
        applied.append(f"environment {inputs['environment']} {sign}{adjustments['environment']}")
    if adjustments["sensitive_data"]:
        applied.append(f"sensitive data +{SENSITIVE_DATA_SCORE}")

    return {
        "points": points,
        "adjustments": adjustments,
        "applied": applied,
    }


def _score_business_context(
    finding: Dict[str, Any],
    context: Dict[str, Any],
    technical: Dict[str, Any],
) -> Dict[str, Any]:
    """Score bounded contextual modifiers without overpowering technical severity."""
    inputs = _resolve_business_context_inputs(finding, context)
    exposure = _score_exposure_reachability(inputs)
    impact = _score_business_impact(inputs)
    raw_points = exposure["points"] + impact["points"]
    points = max(REQUIRES_AUTH_SCORE, min(MAX_CONTEXTUAL_SCORE, raw_points))

    applied: List[str] = []
    applied.extend(exposure["applied"])
    applied.extend(impact["applied"])
    context_cap = MAX_CONTEXTUAL_SCORE

    severity = str(finding.get("severity", "unknown")).lower()
    if (
        technical.get("cvss") is None
        and technical.get("vulnerability_class", {}).get("id") == "generic_issue"
        and severity in {"low", "info"}
        and points > LOW_SIGNAL_CONTEXT_CAP
    ):
        points = LOW_SIGNAL_CONTEXT_CAP
        context_cap = LOW_SIGNAL_CONTEXT_CAP
        applied.append(f"low-signal contextual cap +{LOW_SIGNAL_CONTEXT_CAP}")

    if not applied:
        applied.append("neutral context +0")

    adjustments = {
        **exposure["adjustments"],
        **impact["adjustments"],
    }

    return {
        "points": points,
        "raw_points": raw_points,
        "context_cap": context_cap,
        "inputs": inputs,
        "adjustments": adjustments,
        "applied": applied,
        "exposure_reachability": exposure,
        "business_impact": impact,
    }


def _score_evidence_quality(finding: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    """Score bounded evidence-quality modifiers."""
    confidence_state = _get_confidence_state(finding)
    confidence = confidence_state["label"]
    repeatable = _is_repeatable(finding, context)
    degraded = _degraded_evidence_state(finding)

    adjustments = {
        "confidence": (
            CONFIDENCE_ADJUSTMENTS.get(confidence, -3)
            if confidence_state["provided"] or confidence != "medium"
            else 0
        ),
        "repeatability": REPEATABILITY_BONUS if repeatable and not degraded["all"] else 0,
        "degraded_execution": -4 if degraded["all"] else (-2 if degraded["any"] else 0),
    }
    points = max(-10, min(REPEATABILITY_BONUS, sum(adjustments.values())))

    applied: List[str] = []
    if confidence_state["provided"] or adjustments["confidence"] != 0:
        sign = "+" if adjustments["confidence"] > 0 else ""
        applied.append(f"confidence {confidence} {sign}{adjustments['confidence']}")
    if repeatable and not degraded["all"]:
        applied.append(f"repeatable across scans +{REPEATABILITY_BONUS}")
    elif repeatable:
        applied.append("repeatability bonus withheld for degraded-only evidence +0")
    else:
        applied.append("not yet repeated +0")
    if degraded["all"]:
        applied.append("all supporting evidence is degraded -4")
    elif degraded["any"]:
        applied.append("merged evidence includes degraded scanner output -2")

    return {
        "points": points,
        "inputs": {
            "confidence": confidence,
            "confidence_provided": confidence_state["provided"],
            "repeatable": repeatable,
            "degraded_execution": degraded["any"],
            "all_sources_degraded": degraded["all"],
        },
        "adjustments": adjustments,
        "applied": applied,
    }


def _classify_signal_quality(finding: Dict[str, Any], technical: Dict[str, Any]) -> Dict[str, Any]:
    """Identify low-signal generic findings that should not inflate into urgent work."""
    if technical.get("cvss") is not None:
        return {
            "id": "standard_signal",
            "label": "standard signal",
            "low_signal": False,
            "matched_on": [],
            "cap_score": None,
        }

    if technical.get("vulnerability_class", {}).get("id") != "generic_issue":
        return {
            "id": "standard_signal",
            "label": "standard signal",
            "low_signal": False,
            "matched_on": [],
            "cap_score": None,
        }

    text = _classification_text_blob(finding)
    for rule in LOW_SIGNAL_RULES:
        for pattern in rule["patterns"]:
            if re.search(pattern, text):
                return {
                    "id": rule["id"],
                    "label": rule["label"],
                    "low_signal": True,
                    "matched_on": [pattern],
                    "cap_score": LOW_SIGNAL_MAX_SCORE,
                }

    return {
        "id": "standard_signal",
        "label": "standard signal",
        "low_signal": False,
        "matched_on": [],
        "cap_score": None,
    }


def _score_active_exploitation(
    finding: Dict[str, Any],
    base_score: int,
    business_inputs: Dict[str, Any],
) -> Dict[str, Any]:
    """Apply KEV as a strong floor instead of a tiny additive bonus."""
    kev = _extract_kev_info(finding)
    if not kev["listed"]:
        return {
            "points": 0,
            "kev_used": False,
            "floor_score": None,
            "kev": kev,
            "applied": ["KEV not present"],
        }

    internet_exposed = bool(business_inputs.get("internet_exposed"))
    high_criticality_in_prod = (
        business_inputs.get("asset_criticality") == "high"
        and business_inputs.get("environment") == "production"
    )
    sensitive_exposed = bool(business_inputs.get("sensitive_data")) and internet_exposed

    p0_rule = None
    if sensitive_exposed:
        p0_rule = "internet-exposed sensitive-data asset"
    elif high_criticality_in_prod:
        p0_rule = "high-criticality production asset"
    elif internet_exposed:
        p0_rule = "internet-exposed asset"

    floor_score = 85 if p0_rule else 70
    applied = [f"KEV listed -> floor {floor_score}/100"]
    if p0_rule:
        applied.append(f"P0 rule met: {p0_rule}")
    else:
        applied.append("P1 floor only: no P0 context rule met")
    if kev.get("source"):
        applied.append(f"source {kev['source']}")
    if kev.get("due_date"):
        applied.append(f"due {kev['due_date']}")

    return {
        "points": max(0, floor_score - base_score),
        "kev_used": True,
        "floor_score": floor_score,
        "kev": kev,
        "applied": applied,
    }


def _merge_meta_details(
    finding: Dict[str, Any],
    technical: Dict[str, Any],
    exploit: Dict[str, Any],
    active: Dict[str, Any],
    business: Dict[str, Any],
    evidence: Dict[str, Any],
) -> None:
    """Preserve canonical scoring metadata on the finding without broad schema changes."""
    meta = finding.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        finding["meta"] = meta

    cvss = technical.get("cvss")
    if cvss:
        meta["cvss_score"] = cvss["score"]
        meta["cvss_version"] = cvss["version"]
        if cvss.get("vector"):
            meta["cvss_vector"] = cvss["vector"]
        else:
            meta.pop("cvss_vector", None)
    else:
        meta.pop("cvss_score", None)
        meta.pop("cvss_version", None)
        meta.pop("cvss_vector", None)

    if exploit.get("epss_score") is not None:
        meta["epss_score"] = exploit["epss_score"]
    else:
        meta.pop("epss_score", None)
    if exploit.get("epss_percentile") is not None:
        meta["epss_percentile"] = exploit["epss_percentile"]
    else:
        meta.pop("epss_percentile", None)

    kev = active.get("kev", {})
    meta["kev_listed"] = bool(kev.get("listed"))
    if meta["kev_listed"] and kev.get("source"):
        meta["kev_source"] = kev["source"]
    else:
        meta.pop("kev_source", None)
    if meta["kev_listed"] and kev.get("due_date"):
        meta["kev_due_date"] = kev["due_date"]
    else:
        meta.pop("kev_due_date", None)

    existing_business = meta.get("business_context")
    if not isinstance(existing_business, dict):
        existing_business = {}
    existing_business.update(business["inputs"])
    meta["business_context"] = existing_business

    existing_quality = meta.get("evidence_quality")
    if not isinstance(existing_quality, dict):
        existing_quality = {}
    existing_quality.update(evidence["inputs"])
    meta["evidence_quality"] = existing_quality


def _iter_current_finding_groups(results: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
    """Return current-scan finding lists that should share scoring output."""
    groups: List[List[Dict[str, Any]]] = []

    all_findings = results.get("all_findings")
    if isinstance(all_findings, list):
        groups.append(all_findings)

    findings_by_scanner = results.get("findings_by_scanner")
    if isinstance(findings_by_scanner, dict):
        for findings in findings_by_scanner.values():
            if isinstance(findings, list):
                groups.append(findings)

    for key in ("changed_findings", "partial_unmatched_current_findings"):
        findings = results.get(key)
        if isinstance(findings, list):
            groups.append(findings)

    return groups


def _build_technical_rationale(technical: Dict[str, Any]) -> str:
    """Describe the technical severity layer in plain language."""
    detail = str(technical.get("detail") or "technical severity unavailable").strip()
    base_points = int(technical.get("base_points") or 0)
    raw_points = int(technical.get("raw_points") or 0)
    final_points = int(technical.get("points") or 0)
    vuln_class = technical.get("vulnerability_class") or {}
    class_boost = int(vuln_class.get("boost") or 0)
    floor_applied = int(technical.get("technical_floor_applied") or 0)
    technical_floor = technical.get("technical_floor")

    if class_boost > 0 and floor_applied > 0 and technical_floor is not None:
        return (
            f"Technical severity: {detail} ({base_points} points), "
            f"{vuln_class.get('label', 'dangerous vulnerability')} class (+{class_boost}), "
            f"class floor -> {final_points} points"
        )
    if class_boost > 0:
        return (
            f"Technical severity: {detail} ({base_points} points) and "
            f"{vuln_class.get('label', 'dangerous vulnerability')} class (+{class_boost})"
        )
    if raw_points != final_points:
        return f"Technical severity: {detail} ({base_points} points) -> {final_points} points"
    return f"Technical severity: {detail} -> {base_points} points"


def _layer_summary(label: str, applied: List[str], points: int) -> str:
    """Summarize one scored layer when it materially affected the outcome."""
    if not applied:
        return ""
    joined = ", ".join(applied)
    sign = "+" if points >= 0 else ""
    return f"{label}: {joined} -> {sign}{points}"


def calculate_risk_score(finding: Dict[str, Any], context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Calculate a layered 0-100 risk score and assign a priority bucket.

    Layers:
      1. Technical severity (CVSS v4.0 → CVSS v3.1 → scanner severity)
      2. Exploit likelihood (EPSS and public exploit signals)
      3. Active exploitation (KEV floor)
      4. Business context (bounded asset modifiers)
      5. Evidence quality (bounded confidence/repeatability modifiers)
    """
    context = context or {}

    technical = _score_technical_severity(finding)
    exploit = _score_exploit_likelihood(finding)
    business = _score_business_context(finding, context, technical)
    exposure = business["exposure_reachability"]
    impact = business["business_impact"]
    evidence = _score_evidence_quality(finding, context)
    signal_quality = _classify_signal_quality(finding, technical)

    preliminary_score = technical["points"] + exploit["points"] + business["points"] + evidence["points"]
    active = _score_active_exploitation(finding, preliminary_score, business["inputs"])
    score_cap = signal_quality.get("cap_score")
    low_signal_cap_applied = 0
    if (
        score_cap is not None
        and not active["kev_used"]
        and not exploit["known_exploit"]
        and preliminary_score > score_cap
    ):
        low_signal_cap_applied = preliminary_score - score_cap
        preliminary_score = score_cap

    # KEV is handled as a floor so active exploitation meaningfully changes priority.
    final_score = preliminary_score
    if active.get("floor_score") is not None:
        final_score = max(final_score, active["floor_score"])
    final_score = _clamp_int(final_score)
    priority = assign_priority_bucket(final_score)

    _merge_meta_details(finding, technical, exploit, active, business, evidence)

    risk_factors = {
        "base_severity": technical["base_points"],
        "technical_severity": technical["points"],
        "severity_source": technical["source"],
        "cvss_score": technical["cvss"]["score"] if technical.get("cvss") else None,
        "cvss_version": technical["cvss"]["version"] if technical.get("cvss") else None,
        "cvss_vector": technical["cvss"].get("vector") if technical.get("cvss") else None,
        "vulnerability_class": technical["vulnerability_class"],
        "signal_quality": signal_quality,
        "low_signal_cap": score_cap,
        "low_signal_cap_applied": low_signal_cap_applied,
        "technical_floor": technical["technical_floor"],
        "technical_floor_applied": technical["technical_floor_applied"],
        "internet_exposed": exposure["adjustments"]["internet_exposed"],
        "asset_criticality": impact["adjustments"]["asset_criticality"],
        "environment": impact["adjustments"]["environment"],
        "sensitive_data": impact["adjustments"]["sensitive_data"],
        "requires_auth": exposure["adjustments"]["requires_auth"],
        "exploit_likelihood": exploit["points"],
        "known_exploit": exploit["known_exploit_floor_applied"],
        "epss_used": exploit["epss_used"],
        "epss_score": exploit["epss_score"],
        "epss_percentile": exploit["epss_percentile"],
        "exploit_score_points": exploit["score_points"],
        "exploit_percentile_bonus": exploit["percentile_bonus"],
        "active_exploitation": {
            "kev_used": active["kev_used"],
            "floor_score": active["floor_score"],
            "points_added": active["points"],
            "metadata": active["kev"],
        },
        "kev_used": active["kev_used"],
        "business_context": business["points"],
        "business_context_raw": business["raw_points"],
        "business_context_cap": business["context_cap"],
        "exposure_reachability": exposure["points"],
        "exposure_reachability_inputs": {
            "internet_exposed": business["inputs"]["internet_exposed"],
            "requires_auth": business["inputs"]["requires_auth"],
        },
        "exposure_reachability_applied": exposure["applied"],
        "business_impact": impact["points"],
        "business_impact_inputs": {
            "asset_criticality": business["inputs"]["asset_criticality"],
            "environment": business["inputs"]["environment"],
            "sensitive_data": business["inputs"]["sensitive_data"],
        },
        "business_impact_applied": impact["applied"],
        "business_context_inputs": business["inputs"],
        "business_context_applied": business["applied"],
        "evidence_quality": evidence["points"],
        "evidence_quality_inputs": evidence["inputs"],
        "evidence_quality_applied": evidence["applied"],
        "confidence_adjustment": evidence["adjustments"]["confidence"],
        "repeatability": evidence["adjustments"]["repeatability"],
        "degraded_execution_adjustment": evidence["adjustments"]["degraded_execution"],
        "final_score": final_score,
        "final_priority": priority,
    }

    rationale_parts = [_build_technical_rationale(technical)]
    exploit_summary = _layer_summary("Exploit likelihood", exploit["applied"], exploit["points"])
    if exploit_summary:
        rationale_parts.append(exploit_summary)
    exposure_summary = _layer_summary("Exposure and reachability", exposure["applied"], exposure["points"])
    if exposure_summary:
        rationale_parts.append(exposure_summary)
    business_summary = _layer_summary("Business impact", impact["applied"], impact["points"])
    if business_summary:
        rationale_parts.append(business_summary)
    evidence_summary = _layer_summary("Evidence quality", evidence["applied"], evidence["points"])
    if evidence_summary and (
        evidence["points"] != 0
        or evidence["inputs"]["confidence_provided"]
        or evidence["inputs"]["repeatable"]
        or evidence["inputs"]["degraded_execution"]
    ):
        rationale_parts.append(evidence_summary)
    if low_signal_cap_applied:
        rationale_parts.append(
            "Scoring guardrail: "
            f"{signal_quality['label']} without CVSS or exploit evidence was capped at {score_cap}/100"
        )
    if active["kev_used"]:
        rationale_parts.append(f"Active exploitation: {', '.join(active['applied'])}")
    rationale_parts.append(f"Final score: {final_score}/100 -> {priority}")

    return {
        "risk_score": final_score,
        "priority": priority,
        "risk_factors": risk_factors,
        "risk_rationale": " | ".join(rationale_parts),
    }


def assign_priority_bucket(risk_score: int) -> str:
    """Map a numeric score to a priority bucket."""
    for priority, (min_score, max_score) in PRIORITY_THRESHOLDS.items():
        if min_score <= risk_score <= max_score:
            return priority
    return "P4"


def score_vulnerabilities(
    results: Dict[str, Any],
    context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Add risk scoring to all findings in scan results.

    Modifies findings in-place to add:
      - risk_score
      - priority
      - risk_factors
      - risk_rationale
    """
    for findings in _iter_current_finding_groups(results):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            scoring = calculate_risk_score(finding, context)
            finding.update(scoring)

    refresh_summary_counts(results)
    return results
