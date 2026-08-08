"""
Unified Vulnerability Schema

Defines the JSON schema for normalized vulnerability findings and provides
validation utilities to ensure consistency across all scanner outputs.
"""

from typing import Any, Dict, List, Optional

SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info']

PRIORITY_LEVELS = ['P0', 'P1', 'P2', 'P3', 'P4']

# Valid match_level values produced by deduplicator._merge_group()
_MATCH_LEVELS = {'strict', 'general', 'host_only', 'single'}

SCHEMA_VERSION = '2.0'
_CVSS_VERSIONS = {'4.0', '3.1'}
_ENVIRONMENT_LEVELS = {
    'production', 'prod', 'live',
    'staging', 'stage', 'preprod', 'pre-prod',
    'development', 'dev',
    'test', 'testing', 'qa',
    'unknown',
}
_ASSET_CRITICALITY_LEVELS = {
    'critical', 'high',
    'medium', 'med', 'moderate',
    'low',
    'unknown',
}

class VulnerabilitySchema:
    """
    Export-facing vulnerability schema definition.

    Required fields:
        - vulnerability_name: str - Name/title of the vulnerability
        - severity: str - One of: critical, high, medium, low, info
        - asset_id: str - Identifier for the affected asset (IP, URL, hostname)
        - description: str - Scanner-provided description (may be empty when absent)
        - remediation: str - Scanner-provided remediation (may be empty when absent)
        - meta: dict - Scanner metadata (required; may be an empty dict for minimal findings)

    Optional structured meta fields (standardized in v2.0):
        - meta.scanner: str - Source scanner name
        - meta.timestamp: str - ISO8601 UTC timestamp
        - meta.host: str - Hostname or IP (no scheme, no port)
        - meta.scheme: str - URL scheme (http/https/"")
        - meta.port: int|None - Port number
        - meta.path: str - URL path component
        - meta.query_keys: list[str] - Sorted URL query parameter names
        - meta.parameter: str - Active request parameter (web scanners)
        - meta.method: str - HTTP method
        - meta.raw_id: str - Original scanner ID (CVE, template ID, etc.)
        - meta.cve_id: str - Primary CVE ID
        - meta.cve_ids: list[str] - All CVE IDs
        - meta.raw_ids: list[str] - Raw/template/plugin identifiers from merged sources
        - meta.references: list[str] - Union of source reference URLs when merged
        - meta.cwe: str or int - CWE identifier (e.g. "CWE-89" or 89)
        - meta.cvss: number - Scanner-provided CVSS score when present
        - meta.paths: list[str] - Distinct paths preserved from merged findings
        - meta.parameters: list[str] - Distinct parameters preserved from merged findings
        - meta.ports: list[int] - Distinct ports preserved from merged findings
        - meta.methods: list[str] - Distinct methods preserved from merged findings
        - meta.matcher_names: list[str] - Distinct matcher names preserved from merged findings

    Optional deduplication/provenance fields preserved in exported findings:
        - found_by: list[str] - Scanner names that found this
        - source_findings: list[object] - Per-source provenance records for merged findings

    Comparison fields preserved in exported findings when present:
        - status: str - Report-diff state label (NEW/PERSISTENT/CHANGED/FIXED)
        - changed_fields: list[str] - Structured fields that changed across scans

    Public runtime risk fields preserved in exported findings when present:
        - risk_score: int - Deterministic 0-100 runtime risk score
        - priority: str - Priority bucket derived from risk_score
        - risk_factors: dict - Structured scoring inputs/adjustments
        - risk_rationale: str - Concise explanation of the prioritization

    Internal transient fields used for normalization, duplicate resolution,
    comparison matching, or scoring may still be tolerated by validators before
    export, but they are not part of the external output contract.
    """

    REQUIRED_FIELDS = [
        'vulnerability_name',
        'severity',
        'asset_id',
        'description',
        'remediation'
    ]

    @classmethod
    def create(
        cls,
        vulnerability_name: str,
        severity: str,
        asset_id: str,
        description: str,
        remediation: str,
        meta: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Create a new vulnerability finding in unified schema format.

        Args:
            vulnerability_name: Name/title of the vulnerability
            severity: Severity level (critical/high/medium/low/info)
            asset_id: Affected asset identifier
            description: Detailed description
            remediation: Recommended fix
            meta: Optional metadata dict

        Returns:
            Dict in unified schema format
        """
        return {
            'vulnerability_name': vulnerability_name,
            'severity': normalize_severity(severity),
            'asset_id': asset_id,
            'description': description,
            'remediation': remediation,
            'meta': meta or {}
        }

    @classmethod
    def get_schema_definition(cls) -> Dict[str, Any]:
        """Return the JSON Schema definition for validation."""
        source_finding_properties = {
            "scanner": {"type": "string", "description": "Source scanner name"},
            "vulnerability_name": {"type": "string", "description": "Original vulnerability name"},
            "severity": {"type": "string", "enum": SEVERITY_LEVELS, "description": "Original severity"},
            "asset_id": {"type": "string", "description": "Original asset identifier"},
            "description": {"type": "string", "description": "Original description"},
            "remediation": {"type": "string", "description": "Original remediation"},
            "meta": {"type": "object", "description": "Original source metadata"},
            "references": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional source references when preserved"
            },
        }
        return {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "title": "Unified Vulnerability Finding",
            "type": "object",
            # meta is required by validate_finding() — both must agree
            "required": cls.REQUIRED_FIELDS + ["meta"],
            "properties": {
                # ----------------------------------------------------------
                # Required base fields
                # ----------------------------------------------------------
                "vulnerability_name": {
                    "type": "string",
                    "description": "Name or title of the vulnerability"
                },
                "severity": {
                    "type": "string",
                    "enum": SEVERITY_LEVELS,
                    "description": "Severity level of the vulnerability"
                },
                "asset_id": {
                    "type": "string",
                    "description": "Identifier for the affected asset"
                },
                "description": {
                    "type": "string",
                    "description": "Detailed description of the vulnerability"
                },
                "remediation": {
                    "type": "string",
                    "description": "Recommended remediation steps"
                },
                # ----------------------------------------------------------
                # meta — required, all sub-fields optional
                # ----------------------------------------------------------
                "meta": {
                    "type": "object",
                    "description": "Scanner-specific metadata and structured URL components",
                    "properties": {
                        "scanner":    {"type": "string", "description": "Source scanner name"},
                        "timestamp":  {"type": "string", "description": "ISO8601 UTC timestamp"},
                        "host":       {"type": "string", "description": "Hostname or IP (no scheme/port)"},
                        "scheme":     {"type": "string", "description": "URL scheme (http/https)"},
                        "port":       {"type": ["integer", "null"], "description": "Port number or null"},
                        "path":       {"type": "string", "description": "URL path component"},
                        "parameter":  {"type": "string", "description": "Active request parameter"},
                        "method":     {"type": "string", "description": "HTTP method"},
                        "raw_id":     {"type": "string", "description": "Original scanner ID"},
                        "cve_id":     {"type": "string", "description": "Primary CVE identifier"},
                        "cve_ids":    {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "All CVE identifiers"
                        },
                        "raw_ids": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Raw/template/plugin identifiers from merged sources"
                        },
                        "references": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Union of source reference URLs when merged"
                        },
                        "query_keys": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Sorted URL query parameter names"
                        },
                        "cwe": {
                            "type": ["string", "integer"],
                            "description": "CWE identifier (e.g. 'CWE-89' or 89)"
                        },
                        "cvss": {
                            "type": ["number", "null"],
                            "description": "Scanner-provided CVSS score"
                        },
                        "paths": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Distinct paths preserved from merged findings"
                        },
                        "parameters": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Distinct parameters preserved from merged findings"
                        },
                        "ports": {
                            "type": "array",
                            "items": {"type": "integer"},
                            "description": "Distinct ports preserved from merged findings"
                        },
                        "methods": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Distinct methods preserved from merged findings"
                        },
                        "matcher_names": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Distinct matcher names preserved from merged findings"
                        }
                    }
                },
                "found_by": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Scanner names that contributed to this finding"
                },
                "source_findings": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": source_finding_properties
                    },
                    "description": "Per-source provenance records preserved when duplicate findings are merged"
                },
                "status": {
                    "type": "string",
                    "description": "Comparison state label when report-diff metadata is attached"
                },
                "changed_fields": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Structured fields that changed across scans"
                },
                "risk_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100,
                    "description": "Deterministic runtime risk score"
                },
                "priority": {
                    "type": "string",
                    "enum": PRIORITY_LEVELS,
                    "description": "Priority bucket derived from risk_score"
                },
                "risk_factors": {
                    "type": "object",
                    "description": "Structured scoring inputs and adjustments"
                },
                "risk_rationale": {
                    "type": "string",
                    "description": "Concise explanation of why the finding was prioritized"
                },
                "references": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Reference URLs (OWASP, CWE, CVE, etc.)"
                }
            }
        }

def normalize_severity(severity: Optional[str]) -> str:
    """
    Normalize severity string to valid level.

    Args:
        severity: Raw severity string

    Returns:
        Normalized severity (one of: critical, high, medium, low, info)
    """
    if not severity:
        return 'info'

    severity = str(severity).lower().strip()

    if severity in SEVERITY_LEVELS:
        return severity

    aliases = {
        'crit': 'critical',
        'severe': 'critical',
        'hi': 'high',
        'important': 'high',
        'med': 'medium',
        'moderate': 'medium',
        'warning': 'medium',
        'lo': 'low',
        'minor': 'low',
        'informational': 'info',
        'information': 'info',
        'note': 'info',
        'unknown': 'info'
    }

    return aliases.get(severity, 'info')

# ---------------------------------------------------------------------------
# Private validation helpers
# ---------------------------------------------------------------------------

def _check_optional_str(errors: List[str], finding: Dict[str, Any], field: str) -> None:
    """Validate a top-level optional field, when present, is a non-empty string."""
    if field in finding:
        val = finding[field]
        if not isinstance(val, str):
            errors.append(f"'{field}' must be a non-empty string, got {type(val).__name__}")
        elif not val.strip():
            errors.append(f"'{field}' must be a non-empty string")


def _check_meta_str(errors: List[str], meta: Dict[str, Any], field: str) -> None:
    """Validate meta[field], when present, is a string (empty string is allowed)."""
    if field in meta:
        val = meta[field]
        if not isinstance(val, str):
            errors.append(
                f"meta.{field} must be a string, got {type(val).__name__}"
            )


def _check_meta_list_of_str(errors: List[str], meta: Dict[str, Any], field: str) -> None:
    """Validate meta[field], when present, is a list whose every element is a str."""
    if field in meta:
        val = meta[field]
        if not isinstance(val, list):
            errors.append(
                f"meta.{field} must be a list of strings, got {type(val).__name__}"
            )
        elif not all(isinstance(item, str) for item in val):
            errors.append(f"meta.{field} must be a list of strings (found non-string element)")


def _check_meta_list_of_int(errors: List[str], meta: Dict[str, Any], field: str) -> None:
    """Validate meta[field], when present, is a list whose every element is an int."""
    if field in meta:
        val = meta[field]
        if not isinstance(val, list):
            errors.append(
                f"meta.{field} must be a list of integers, got {type(val).__name__}"
            )
        elif not all(isinstance(item, int) and not isinstance(item, bool) for item in val):
            errors.append(f"meta.{field} must be a list of integers (found non-integer element)")


def _check_meta_number(
    errors: List[str],
    meta: Dict[str, Any],
    field: str,
    *,
    minimum: Optional[float] = None,
    maximum: Optional[float] = None,
    allow_none: bool = False,
) -> None:
    """Validate numeric metadata fields when present."""
    if field not in meta:
        return

    val = meta[field]
    if val is None and allow_none:
        return
    if not isinstance(val, (int, float)) or isinstance(val, bool):
        errors.append(f"meta.{field} must be a number, got {type(val).__name__}")
        return
    if minimum is not None and val < minimum:
        errors.append(f"meta.{field} must be >= {minimum}, got {val}")
    if maximum is not None and val > maximum:
        errors.append(f"meta.{field} must be <= {maximum}, got {val}")


def _check_meta_bool(errors: List[str], meta: Dict[str, Any], field: str) -> None:
    """Validate boolean metadata fields when present."""
    if field in meta and not isinstance(meta[field], bool):
        errors.append(f"meta.{field} must be a bool, got {type(meta[field]).__name__}")


def _validate_cve_intelligence_candidates(errors: List[str], meta: Dict[str, Any]) -> None:
    """Validate meta.cve_intelligence_candidates when present."""
    if 'cve_intelligence_candidates' not in meta:
        return

    candidates = meta['cve_intelligence_candidates']
    if not isinstance(candidates, list):
        errors.append(
            "meta.cve_intelligence_candidates must be a list of objects, "
            f"got {type(candidates).__name__}"
        )
        return

    for index, candidate in enumerate(candidates):
        prefix = f"meta.cve_intelligence_candidates[{index}]"
        if not isinstance(candidate, dict):
            errors.append(
                f"{prefix} must be an object, got {type(candidate).__name__}"
            )
            continue

        if 'cve_id' in candidate and not isinstance(candidate['cve_id'], str):
            errors.append(
                f"{prefix}.cve_id must be a string, got {type(candidate['cve_id']).__name__}"
            )

        for field in ('cvss_version', 'cvss_vector', 'cvss_source', 'epss_source', 'kev_source', 'kev_due_date'):
            if field in candidate and candidate[field] is not None and not isinstance(candidate[field], str):
                errors.append(
                    f"{prefix}.{field} must be a string or null, got {type(candidate[field]).__name__}"
                )

        if (
            'cvss_version' in candidate
            and candidate['cvss_version'] is not None
            and candidate['cvss_version'] not in _CVSS_VERSIONS
        ):
            errors.append(
                f"{prefix}.cvss_version must be one of: {', '.join(sorted(_CVSS_VERSIONS))}"
            )

        for field, minimum, maximum in (
            ('cvss_score', 0.0, 10.0),
            ('epss_score', 0.0, 1.0),
            ('epss_percentile', 0.0, 1.0),
        ):
            if field not in candidate or candidate[field] is None:
                continue
            value = candidate[field]
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                errors.append(
                    f"{prefix}.{field} must be a number or null, got {type(value).__name__}"
                )
                continue
            if value < minimum:
                errors.append(f"{prefix}.{field} must be >= {minimum}, got {value}")
            if value > maximum:
                errors.append(f"{prefix}.{field} must be <= {maximum}, got {value}")

        if 'kev_listed' in candidate and not isinstance(candidate['kev_listed'], bool):
            errors.append(
                f"{prefix}.kev_listed must be a bool, got {type(candidate['kev_listed']).__name__}"
            )


def _validate_source_findings(errors: List[str], finding: Dict[str, Any]) -> None:
    """Validate source_findings when present."""
    if 'source_findings' not in finding:
        return

    source_findings = finding['source_findings']
    if not isinstance(source_findings, list):
        errors.append(
            f"'source_findings' must be a list of objects, got {type(source_findings).__name__}"
        )
        return

    for index, source in enumerate(source_findings):
        prefix = f"source_findings[{index}]"
        if not isinstance(source, dict):
            errors.append(f"{prefix} must be an object, got {type(source).__name__}")
            continue

        for field in ('scanner', 'vulnerability_name', 'severity', 'asset_id', 'description', 'remediation', 'fp_strict', 'fp_general', 'fp_host_only'):
            if field in source and not isinstance(source[field], str):
                errors.append(f"{prefix}.{field} must be a string, got {type(source[field]).__name__}")

        if (
            'severity' in source
            and isinstance(source['severity'], str)
            and source['severity'] not in SEVERITY_LEVELS
        ):
            errors.append(
                f"{prefix}.severity must be one of: {', '.join(SEVERITY_LEVELS)}"
            )

        if 'meta' in source and not isinstance(source['meta'], dict):
            errors.append(f"{prefix}.meta must be a dict, got {type(source['meta']).__name__}")

        if 'references' in source:
            refs = source['references']
            if not isinstance(refs, list):
                errors.append(f"{prefix}.references must be a list of strings, got {type(refs).__name__}")
            elif not all(isinstance(item, str) for item in refs):
                errors.append(f"{prefix}.references must be a list of strings (found non-string element)")


# ---------------------------------------------------------------------------
# Public validator
# ---------------------------------------------------------------------------

def validate_finding(finding: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Validate a finding against the unified schema.

    Checks five layers:
      A. Required base fields (vulnerability_name, severity, asset_id,
         description, remediation, meta).
      B. Severity enum against SEVERITY_LEVELS.
      C. Optional fingerprint/normalized top-level fields when present
         (fp_strict, fp_general, fp_host_only).
      D. Optional deduplication + public runtime scoring/prioritization fields when present
         (found_by, duplicate_count, merge_confidence, match_level,
          risk_score, priority, risk_factors, risk_rationale).
      E. Structured meta sub-fields when present:
         string fields, port (int|None), query_keys/cve_ids (list[str]),
         cwe (str|int), plus legacy internal scoring metadata when present.

    Optional internal-only fields are only validated when present, so raw
    pre-normalized findings that lack them still pass.

    Args:
        finding: Dict to validate

    Returns:
        Tuple of (is_valid, list of error messages)
    """
    errors: List[str] = []

    # ------------------------------------------------------------------
    # A. Required base fields
    # ------------------------------------------------------------------
    for field in VulnerabilitySchema.REQUIRED_FIELDS:
        if field not in finding:
            errors.append(f"Missing required field: '{field}'")
        elif not isinstance(finding[field], str):
            errors.append(f"'{field}' must be a string, got {type(finding[field]).__name__}")
        elif field not in {'asset_id', 'description', 'remediation'} and not finding[field].strip():
            # asset_id may legitimately be an empty string for host-level findings.
            # description/remediation may be empty when the scanner did not
            # provide native prose for that field.
            errors.append(f"'{field}' cannot be empty")

    # meta is required but not a string — validate it separately
    if 'meta' not in finding:
        errors.append("Missing required field: 'meta'")
    elif not isinstance(finding['meta'], dict):
        errors.append("'meta' must be a dict")

    # ------------------------------------------------------------------
    # B. Severity enum  (only when the field is present and is a string)
    # ------------------------------------------------------------------
    severity = finding.get('severity')
    if isinstance(severity, str) and severity not in SEVERITY_LEVELS:
        errors.append(
            f"Invalid severity: '{severity}'. "
            f"Must be one of: {', '.join(SEVERITY_LEVELS)}"
        )

    # ------------------------------------------------------------------
    # C. Optional fingerprint / normalized top-level fields
    # ------------------------------------------------------------------
    for fp_field in ('fp_strict', 'fp_general', 'fp_host_only'):
        _check_optional_str(errors, finding, fp_field)
    _validate_source_findings(errors, finding)

    # ------------------------------------------------------------------
    # D. Optional deduplication + scoring / prioritization fields
    # ------------------------------------------------------------------
    if 'risk_score' in finding:
        rs = finding['risk_score']
        if not isinstance(rs, int) or isinstance(rs, bool):
            errors.append(
                f"'risk_score' must be an int, got {type(rs).__name__}"
            )
        elif not (0 <= rs <= 100):
            errors.append(f"'risk_score' must be between 0 and 100, got {rs}")

    if 'priority' in finding:
        p = finding['priority']
        if not isinstance(p, str) or p not in PRIORITY_LEVELS:
            errors.append(
                f"Invalid priority: '{p}'. "
                f"Must be one of: {', '.join(PRIORITY_LEVELS)}"
            )

    if 'risk_factors' in finding and not isinstance(finding['risk_factors'], dict):
        errors.append(
            f"'risk_factors' must be a dict, got {type(finding['risk_factors']).__name__}"
        )

    if 'risk_rationale' in finding:
        rationale = finding['risk_rationale']
        if not isinstance(rationale, str):
            errors.append(
                f"'risk_rationale' must be a string, got {type(rationale).__name__}"
            )
        elif not rationale.strip():
            errors.append("'risk_rationale' cannot be empty")

    if 'impact_for_developers' in finding:
        errors.append("'impact_for_developers' is no longer supported")

    if 'merge_confidence' in finding:
        mc = finding['merge_confidence']
        if not isinstance(mc, (int, float)) or isinstance(mc, bool):
            errors.append(
                f"'merge_confidence' must be a float between 0.0 and 1.0, "
                f"got {type(mc).__name__}"
            )
        elif not (0.0 <= mc <= 1.0):
            errors.append(
                f"'merge_confidence' must be between 0.0 and 1.0, got {mc}"
            )

    if 'match_level' in finding:
        ml = finding['match_level']
        if not isinstance(ml, str) or ml not in _MATCH_LEVELS:
            errors.append(
                f"Invalid match_level: '{ml}'. "
                f"Must be one of: {', '.join(sorted(_MATCH_LEVELS))}"
            )

    if 'found_by' in finding:
        fb = finding['found_by']
        if not isinstance(fb, list):
            errors.append(
                f"'found_by' must be a list of strings, got {type(fb).__name__}"
            )
        elif not all(isinstance(item, str) for item in fb):
            errors.append("'found_by' must be a list of strings (found non-string element)")

    if 'duplicate_count' in finding:
        dc = finding['duplicate_count']
        if not isinstance(dc, int) or isinstance(dc, bool):
            errors.append(
                f"'duplicate_count' must be an int, got {type(dc).__name__}"
            )
        elif dc < 1:
            errors.append(
                f"'duplicate_count' must be an int >= 1, got {dc}"
            )

    # ------------------------------------------------------------------
    # E. Structured meta sub-fields  (only when meta is actually a dict)
    # ------------------------------------------------------------------
    meta = finding.get('meta')
    if isinstance(meta, dict):
        # String-typed meta fields (empty string is acceptable)
        for str_field in (
            'scanner', 'timestamp', 'host', 'scheme', 'path',
            'parameter', 'method', 'raw_id', 'cve_id',
        ):
            _check_meta_str(errors, meta, str_field)

        # meta.port: int or None
        if 'port' in meta:
            port_val = meta['port']
            if port_val is not None and (not isinstance(port_val, int) or isinstance(port_val, bool)):
                errors.append(
                    f"meta.port must be an int or None, got {type(port_val).__name__}"
                )

        # meta.query_keys and meta.cve_ids: list[str]
        _check_meta_list_of_str(errors, meta, 'query_keys')
        _check_meta_list_of_str(errors, meta, 'cve_ids')
        for list_field in ('raw_ids', 'references', 'paths', 'parameters', 'methods', 'matcher_names', 'scanners'):
            _check_meta_list_of_str(errors, meta, list_field)
        _check_meta_list_of_int(errors, meta, 'ports')

        # Canonical scoring metadata when present.
        _check_meta_number(errors, meta, 'cvss', minimum=0.0, maximum=10.0, allow_none=True)
        _check_meta_number(errors, meta, 'cvss_score', minimum=0.0, maximum=10.0, allow_none=True)
        _check_meta_number(errors, meta, 'epss_score', minimum=0.0, maximum=1.0)
        _check_meta_number(errors, meta, 'epss_percentile', minimum=0.0, maximum=1.0)
        for bool_field in ('kev_listed', 'merged', 'has_multi_scanner_confirmation'):
            _check_meta_bool(errors, meta, bool_field)

        if 'original_findings_count' in meta:
            count_val = meta['original_findings_count']
            if not isinstance(count_val, int) or isinstance(count_val, bool):
                errors.append(
                    f"meta.original_findings_count must be an int, got {type(count_val).__name__}"
                )
            elif count_val < 1:
                errors.append(
                    f"meta.original_findings_count must be an int >= 1, got {count_val}"
                )

        # BUG-03/11 fix: cvss_version allows null (no CVSS data available), so it
        # is excluded from the generic string check and validated separately below.
        for str_field in ('cvss_vector', 'cvss_source', 'epss_source', 'kev_source', 'kev_due_date'):
            _check_meta_str(errors, meta, str_field)
        if 'cvss_version' in meta:
            _cv = meta['cvss_version']
            if _cv is not None and not isinstance(_cv, str):
                errors.append(f"meta.cvss_version must be a string or null, got {type(_cv).__name__}")
            elif _cv is not None and _cv not in _CVSS_VERSIONS:
                errors.append(
                    f"meta.cvss_version must be one of: {', '.join(sorted(_CVSS_VERSIONS))} (or null)"
                )
        _validate_cve_intelligence_candidates(errors, meta)

        business_context = meta.get('business_context')
        if business_context is not None:
            if not isinstance(business_context, dict):
                errors.append(
                    f"meta.business_context must be a dict, got {type(business_context).__name__}"
                )
            else:
                for field in ('asset_criticality', 'environment'):
                    if field in business_context and not isinstance(business_context[field], str):
                        errors.append(
                            f"meta.business_context.{field} must be a string, got "
                            f"{type(business_context[field]).__name__}"
                        )
                if (
                    'asset_criticality' in business_context
                    and isinstance(business_context['asset_criticality'], str)
                    and business_context['asset_criticality'].lower() not in _ASSET_CRITICALITY_LEVELS
                ):
                    errors.append(
                        "meta.business_context.asset_criticality must be one of: "
                        + ", ".join(sorted(_ASSET_CRITICALITY_LEVELS))
                    )
                if (
                    'environment' in business_context
                    and isinstance(business_context['environment'], str)
                    and business_context['environment'].lower() not in _ENVIRONMENT_LEVELS
                ):
                    errors.append(
                        "meta.business_context.environment must be one of: "
                        + ", ".join(sorted(_ENVIRONMENT_LEVELS))
                    )
                for field in ('internet_exposed', 'sensitive_data', 'requires_auth'):
                    if field in business_context and not isinstance(business_context[field], bool):
                        errors.append(
                            f"meta.business_context.{field} must be a bool, got "
                            f"{type(business_context[field]).__name__}"
                        )

        evidence_quality = meta.get('evidence_quality')
        if evidence_quality is not None:
            if not isinstance(evidence_quality, dict):
                errors.append(
                    f"meta.evidence_quality must be a dict, got {type(evidence_quality).__name__}"
                )
            else:
                if 'confidence' in evidence_quality and not isinstance(evidence_quality['confidence'], str):
                    errors.append(
                        f"meta.evidence_quality.confidence must be a string, got "
                        f"{type(evidence_quality['confidence']).__name__}"
                    )
                if 'repeatable' in evidence_quality and not isinstance(evidence_quality['repeatable'], bool):
                    errors.append(
                        f"meta.evidence_quality.repeatable must be a bool, got "
                        f"{type(evidence_quality['repeatable']).__name__}"
                    )

        # meta.cwe: str or int
        if 'cwe' in meta:
            cwe_val = meta['cwe']
            if not isinstance(cwe_val, (str, int)) or isinstance(cwe_val, bool):
                errors.append(
                    f"meta.cwe must be a string or int, got {type(cwe_val).__name__}"
                )

    return (len(errors) == 0, errors)


# ---------------------------------------------------------------------------
# Result-level validation (pipeline stage contracts)
# ---------------------------------------------------------------------------

_RESULT_STAGES = frozenset({'post_normalize', 'final', 'report'})
_SCAN_ROUTES = frozenset({'direct', 'proxied', 'skipped'})
_ADAPTER_MODES = frozenset({'direct', 'proxy', 'bridge', 'skipped'})


def assert_valid_results(results: Dict[str, Any], stage: str = 'final') -> None:
    """
    Validate a full results dict against the contract for the given pipeline stage.

    Stages
    ------
    post_normalize
        Used immediately after scanner.normalize(). Does NOT require generated_at
        because the timestamp hasn't been assigned yet.
        Requires: schema_version, target, all_findings (list).

    final
        Used after all post-processing (dedupe/score/compare) and before
        save_results(). Requires generated_at in addition to post_normalize fields.

    report
        Same contract as final. Used inside generate_html_report() to prevent
        rendering from invalid data.

    All stages run every finding in all_findings through validate_finding().
    Legacy internal-only post-processing fields (risk_score, priority, etc.)
    are only validated when present. They are tolerated before export but are
    not part of the external output contract.

    Raises
    ------
    ValueError
        With a clear message listing every error found. Never silently passes
        invalid data.
    """
    if stage not in _RESULT_STAGES:
        raise ValueError(
            f"Unknown validation stage '{stage}'. "
            f"Must be one of: {', '.join(sorted(_RESULT_STAGES))}"
        )

    errors: List[str] = []

    # --- Top-level required fields (all stages) ---
    if not isinstance(results, dict):
        raise ValueError(
            f"assert_valid_results: results must be a dict, got {type(results).__name__}"
        )

    if 'schema_version' not in results:
        errors.append("Missing required field: 'schema_version'")
    elif not isinstance(results['schema_version'], str):
        errors.append(
            f"'schema_version' must be a string, got {type(results['schema_version']).__name__}"
        )

    if 'target' not in results:
        errors.append("Missing required field: 'target'")
    elif not isinstance(results['target'], str):
        errors.append(
            f"'target' must be a string, got {type(results['target']).__name__}"
        )

    if 'all_findings' not in results:
        errors.append("Missing required field: 'all_findings'")
    elif not isinstance(results['all_findings'], list):
        errors.append(
            f"'all_findings' must be a list, got {type(results['all_findings']).__name__}"
        )

    # --- generated_at required for final and report stages ---
    if stage in ('final', 'report'):
        if 'generated_at' not in results:
            errors.append(
                "Missing required field: 'generated_at' "
                f"(required at stage '{stage}')"
            )
        else:
            ga = results['generated_at']
            if not isinstance(ga, str):
                errors.append(
                    f"'generated_at' must be a string, got {type(ga).__name__}"
                )
            elif not ga.endswith('Z'):
                errors.append(
                    f"'generated_at' must be an ISO 8601 UTC string ending in 'Z', got: {ga!r}"
                )

    # Naming note:
    # - top-level results.transport_detected stores the full target probe dict
    # - scanner_execution.<name>.transport_detected stores the summary string
    # This keeps backward compatibility while preserving per-scanner route data.
    transport_detected = results.get('transport_detected')
    if transport_detected is not None and not isinstance(transport_detected, dict):
        errors.append(
            f"'transport_detected' must be a dict when present, got {type(transport_detected).__name__}"
        )
    target_probe = results.get('target_probe')
    if target_probe is not None and not isinstance(target_probe, dict):
        errors.append(
            f"'target_probe' must be a dict when present, got {type(target_probe).__name__}"
        )

    scanner_execution = results.get('scanner_execution')
    if scanner_execution is not None:
        if not isinstance(scanner_execution, dict):
            errors.append(
                f"'scanner_execution' must be a dict when present, got {type(scanner_execution).__name__}"
            )
        else:
            for scanner_name, execution in scanner_execution.items():
                if not isinstance(execution, dict):
                    errors.append(
                        f"scanner_execution.{scanner_name} must be a dict, got {type(execution).__name__}"
                    )
                    continue
                for field in (
                    'scanner_type',
                    'transport_detected',
                    'scanner_transport_notes',
                    'transport_confidence',
                ):
                    if field in execution and not isinstance(execution[field], str):
                        errors.append(
                            f"scanner_execution.{scanner_name}.{field} must be a string, got {type(execution[field]).__name__}"
                        )

                for field in (
                    'adapter_status',
                    'adapter_runtime_state',
                    'adapter_failure_reason',
                    'adapter_diagnostics',
                    'adapter_runtime',
                    'adapter_upstream_url',
                    'adapter_translation_chain',
                    'adapter_shutdown_reason',
                ):
                    if field in execution and execution[field] is not None and not isinstance(execution[field], str):
                        errors.append(
                            f"scanner_execution.{scanner_name}.{field} must be a string or null, got {type(execution[field]).__name__}"
                        )

                if 'probe_method' in execution and execution['probe_method'] is not None and not isinstance(execution['probe_method'], str):
                    errors.append(
                        f"scanner_execution.{scanner_name}.probe_method must be a string or null, got {type(execution['probe_method']).__name__}"
                    )

                if 'scan_route' in execution:
                    route_val = execution['scan_route']
                    if not isinstance(route_val, str) or route_val not in _SCAN_ROUTES:
                        errors.append(
                            f"scanner_execution.{scanner_name}.scan_route must be one of: {', '.join(sorted(_SCAN_ROUTES))}"
                        )
                if 'adapter_mode' in execution:
                    adapter_val = execution['adapter_mode']
                    if not isinstance(adapter_val, str) or adapter_val not in _ADAPTER_MODES:
                        errors.append(
                            f"scanner_execution.{scanner_name}.adapter_mode must be one of: {', '.join(sorted(_ADAPTER_MODES))}"
                        )
                if 'skip_reason' in execution and execution['skip_reason'] is not None and not isinstance(execution['skip_reason'], str):
                    errors.append(
                        f"scanner_execution.{scanner_name}.skip_reason must be a string or null, got {type(execution['skip_reason']).__name__}"
                    )
                for field in ('execution_target', 'effective_target', 'origin_target', 'original_target', 'scanner_error'):
                    if field in execution and execution[field] is not None and not isinstance(execution[field], str):
                        errors.append(
                            f"scanner_execution.{scanner_name}.{field} must be a string or null, got {type(execution[field]).__name__}"
                        )
                for field in ('supports_http2_direct', 'supports_http1_force', 'supports_proxy', 'supports_http2_bridge', 'supports_http2', 'supports_http1_1', 'http2_only'):
                    if field in execution and execution[field] is not None and not isinstance(execution[field], bool):
                        errors.append(
                            f"scanner_execution.{scanner_name}.{field} must be a bool or null, got {type(execution[field]).__name__}"
                        )
                for field in ('partial_results', 'degraded_execution', 'adapter_shutdown_clean'):
                    if field in execution and execution[field] is not None and not isinstance(execution[field], bool):
                        errors.append(
                            f"scanner_execution.{scanner_name}.{field} must be a bool or null, got {type(execution[field]).__name__}"
                        )

    # --- Per-finding validation ---
    findings = results.get('all_findings')
    if isinstance(findings, list):
        for i, finding in enumerate(findings):
            ok, finding_errors = validate_finding(finding)
            if not ok:
                for err in finding_errors:
                    errors.append(f"Finding #{i + 1}: {err}")

    if errors:
        n = len(errors)
        detail = "\n  ".join(errors)
        raise ValueError(
            f"Schema validation failed at stage '{stage}' "
            f"({n} error{'s' if n != 1 else ''}):\n  {detail}"
        )

def severity_rank(severity: str) -> int:
    """
    Get numeric rank for severity (higher = more severe).

    Args:
        severity: Severity level string

    Returns:
        Numeric rank (0-4, with 4 being critical)
    """
    ranks = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }
    return ranks.get(normalize_severity(severity), 0)

def sort_by_severity(findings: List[Dict[str, Any]], descending: bool = True) -> List[Dict[str, Any]]:
    """
    Sort findings by severity.

    Args:
        findings: List of vulnerability findings
        descending: If True, most severe first (default)

    Returns:
        Sorted list of findings
    """
    return sorted(
        findings,
        key=lambda f: severity_rank(f.get('severity', 'info')),
        reverse=descending
    )
