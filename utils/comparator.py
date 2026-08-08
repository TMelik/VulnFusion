"""
Vulnerability Comparison Engine

Compares current scan results against previous scans to track vulnerability status:
- FIXED: Present in old scan, not in new (resolved)
- NEW: Present in new scan, not in old (introduced)
- PERSISTENT: Present in both scans (unresolved)
"""

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from utils.cve_utils import extract_exact_cve_ids
from utils.llm_duplicate_resolver import target_context
from utils.normalizer import normalize_vulnerability_name
from utils.run_folder import get_normalized_json_path, get_scan_results_json_path, list_target_runs

class ComparisonResult:
    """Container for comparison results."""

    def __init__(self):
        self.fixed: List[Dict[str, Any]] = []
        self.new: List[Dict[str, Any]] = []
        self.persistent: List[Dict[str, Any]] = []
        self.changed: List[Dict[str, Any]] = []
        self.partial_unmatched_current: List[Dict[str, Any]] = []
        self.partial_unmatched_previous: List[Dict[str, Any]] = []
        self.old_scan_path: Optional[Path] = None
        self.old_scan_timestamp: Optional[str] = None
        self.new_scan_timestamp: Optional[str] = None
        self.previous_findings: List[Dict[str, Any]] = []
        self.compatible_baseline_used: bool = False
        self.comparison_mode: str = 'skipped'
        self.compatibility_reason: str = 'No previous scan available for comparison.'
        self.current_scanners_run: List[str] = []
        self.previous_scanners_run: List[str] = []
        self.overlapping_scanners: List[str] = []
        self.missing_from_current: List[str] = []
        self.missing_from_previous: List[str] = []
        self.scanner_coverage_delta: Dict[str, List[str]] = {
            'overlapping_scanners': [],
            'missing_from_current': [],
            'missing_from_previous': [],
        }
        self.partial_comparison_limitations: List[str] = []
        self.include_summary: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            'comparison': {
                'old_scan': str(self.old_scan_path) if self.old_scan_path else None,
                'old_scan_timestamp': self.old_scan_timestamp,
                'new_scan_timestamp': self.new_scan_timestamp,
                'compatible_baseline_used': self.compatible_baseline_used,
                'comparison_mode': self.comparison_mode,
                'compatibility_reason': self.compatibility_reason,
                'current_scanners_run': self.current_scanners_run,
                'previous_scanners_run': self.previous_scanners_run,
                'overlapping_scanners': self.overlapping_scanners,
                'missing_from_current': self.missing_from_current,
                'missing_from_previous': self.missing_from_previous,
                'scanner_coverage_delta': self.scanner_coverage_delta,
                'partial_comparison_limitations': self.partial_comparison_limitations,
                'summary': ({
                    'fixed': len(self.fixed),
                    'new': len(self.new),
                    'persistent': len(self.persistent),
                    'changed': len(self.changed),
                    'partial_unmatched_current': len(self.partial_unmatched_current),
                    'partial_unmatched_previous': len(self.partial_unmatched_previous),
                    'total_current': len(self.new) + len(self.persistent) + len(self.changed)
                } if self.include_summary else {})
            },
            'fixed': self.fixed,
            'new': self.new,
            'persistent': self.persistent,
            'changed': self.changed,
            'partial_unmatched_current_findings': self.partial_unmatched_current,
            'partial_unmatched_previous_findings': self.partial_unmatched_previous,
        }

_SEVERITY_RANK = {
    'critical': 5,
    'high': 4,
    'medium': 3,
    'low': 2,
    'info': 1,
}


@dataclass
class ComparisonProfile:
    """Structured logical identity used for cross-run comparison."""

    index: int
    finding: Dict[str, Any]
    finding_id: str
    target_anchors: set[str] = field(default_factory=set)
    hosts: set[str] = field(default_factory=set)
    target_families: set[str] = field(default_factory=set)
    ports: set[int] = field(default_factory=set)
    protocols: set[str] = field(default_factory=set)
    endpoint_families: set[str] = field(default_factory=set)
    paths: set[str] = field(default_factory=set)
    query_keys: set[str] = field(default_factory=set)
    parameters: set[str] = field(default_factory=set)
    methods: set[str] = field(default_factory=set)
    normalized_names: set[str] = field(default_factory=set)
    title_tokens: set[str] = field(default_factory=set)
    cves: set[str] = field(default_factory=set)
    cwes: set[str] = field(default_factory=set)
    stable_ids: set[str] = field(default_factory=set)
    categories: set[str] = field(default_factory=set)
    technologies: set[str] = field(default_factory=set)
    scanners: set[str] = field(default_factory=set)
    severity_values: set[str] = field(default_factory=set)
    confidence_values: set[str] = field(default_factory=set)
    remediation_available: bool = False
    source_count: int = 1

    @property
    def highest_severity(self) -> str:
        if not self.severity_values:
            return 'info'
        return max(
            self.severity_values,
            key=lambda severity: _SEVERITY_RANK.get(severity, 0),
        )

    @property
    def is_web(self) -> bool:
        return 'web' in self.target_families


def _safe_text(value: Any) -> str:
    """Return a compact display-safe string."""
    return str(value or '').strip()


def _meta(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return normalized metadata for one record."""
    meta = record.get('meta')
    return meta if isinstance(meta, dict) else {}


def _string_values(value: Any) -> List[str]:
    """Normalize a scalar-or-list field into non-empty strings."""
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return [text for text in (_safe_text(item) for item in values) if text]


def _normalized_string_values(values: Iterable[Any]) -> set[str]:
    """Normalize descriptive string values into canonical lowercase families."""
    normalized: set[str] = set()
    for value in values:
        text = _safe_text(value)
        if not text:
            continue
        normalized_value = normalize_vulnerability_name(text) or text.lower()
        if normalized_value:
            normalized.add(normalized_value)
    return normalized


def _uppercase_identifier_values(values: Iterable[Any]) -> set[str]:
    """Normalize identifiers like CVE/CWE into uppercase strings."""
    return {
        _safe_text(value).upper()
        for value in values
        if _safe_text(value)
    }


def _record_scanner_names(record: Dict[str, Any]) -> List[str]:
    """Return scanner labels present on one finding or preserved source record."""
    meta = _meta(record)
    scanners: List[str] = []
    scanners.extend(_string_values(record.get('found_by')))
    scanners.extend(_string_values(meta.get('scanners')))
    scanners.extend(_string_values(record.get('scanner')))
    scanners.extend(_string_values(meta.get('scanner')))
    return [scanner.lower() for scanner in scanners if scanner]


def _source_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return preserved source records for one finding, falling back to itself."""
    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        return [source for source in source_findings if isinstance(source, dict)]
    return []


def _all_profile_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the top-level finding plus any preserved source findings."""
    return [finding, *_source_records(finding)]


def _collect_meta_strings(record: Dict[str, Any], singular: str, plural: str) -> List[str]:
    """Collect singular/plural metadata values from one record."""
    meta = _meta(record)
    return [
        *_string_values(meta.get(singular)),
        *_string_values(meta.get(plural)),
    ]


def _collect_meta_ports(record: Dict[str, Any]) -> List[int]:
    """Collect singular/plural port metadata from one record."""
    meta = _meta(record)
    ports: List[int] = []
    for value in [meta.get('port'), *_string_values(meta.get('ports'))]:
        try:
            if value is None or value == '':
                continue
            ports.append(int(value))
        except (TypeError, ValueError):
            continue
    return ports


def _comparison_finding_id(finding: Dict[str, Any], index: int) -> str:
    """Return a stable local identifier for comparison bookkeeping."""
    finding_id = _safe_text(finding.get('finding_id'))
    if finding_id:
        return finding_id
    return f"comparison-finding-{index}"


def _build_comparison_profile(index: int, finding: Dict[str, Any]) -> ComparisonProfile:
    """Build a source-aware logical identity profile for one finding."""
    records = _all_profile_records(finding)
    profile = ComparisonProfile(
        index=index,
        finding=finding,
        finding_id=_comparison_finding_id(finding, index),
        source_count=max(1, len(_source_records(finding)) or 1),
    )

    for record in records:
        if not isinstance(record, dict):
            continue

        ctx = target_context(record)
        host = _safe_text(ctx.get('host')).lower()
        if host:
            profile.hosts.add(host)
            profile.target_anchors.add(host)
        else:
            asset_id = _safe_text(record.get('asset_id')).lower()
            if asset_id:
                profile.target_anchors.add(asset_id)

        family = _safe_text(ctx.get('target_family')).lower()
        if family:
            profile.target_families.add(family)

        protocol = _safe_text(ctx.get('protocol')).lower()
        if protocol:
            profile.protocols.add(protocol)

        port = ctx.get('port')
        if isinstance(port, int):
            profile.ports.add(port)
        profile.ports.update(_collect_meta_ports(record))

        path = _safe_text(ctx.get('path'))
        if path:
            profile.paths.add(path)

        endpoint_family = _safe_text(ctx.get('endpoint_family'))
        if endpoint_family:
            profile.endpoint_families.add(endpoint_family)

        query_keys = _safe_text(ctx.get('query_keys'))
        if query_keys:
            profile.query_keys.update(part for part in query_keys.split('&') if part)

        parameter = _safe_text(ctx.get('parameter')).lower()
        if parameter:
            profile.parameters.add(parameter)

        method = _safe_text(ctx.get('method')).upper()
        if method:
            profile.methods.add(method)

        for path_value in _collect_meta_strings(record, 'path', 'paths'):
            if path_value:
                profile.paths.add(path_value.lower())
        for parameter_value in _collect_meta_strings(record, 'parameter', 'parameters'):
            if parameter_value:
                profile.parameters.add(parameter_value.lower())
        for method_value in _collect_meta_strings(record, 'method', 'methods'):
            if method_value:
                profile.methods.add(method_value.upper())
        for query_key_value in _collect_meta_strings(record, 'query_keys', 'query_keys'):
            if query_key_value:
                profile.query_keys.update(part for part in query_key_value.split('&') if part)

        vuln_name = normalize_vulnerability_name(_safe_text(record.get('vulnerability_name')))
        if vuln_name:
            profile.normalized_names.add(vuln_name)
            profile.title_tokens.update(token for token in vuln_name.split() if token)

        meta = _meta(record)
        profile.cves.update(extract_exact_cve_ids(record))
        profile.cwes.update(
            _uppercase_identifier_values([
                *_string_values(meta.get('cwe')),
                *_string_values(meta.get('cwe_list')),
            ])
        )
        profile.stable_ids.update(
            value.lower()
            for value in [
                *_string_values(meta.get('plugin_id')),
                *_string_values(meta.get('template_id')),
                *_string_values(meta.get('raw_id')),
                *_string_values(meta.get('raw_ids')),
            ]
            if value
        )
        profile.categories.update(
            _normalized_string_values([
                *_string_values(meta.get('category')),
                *_string_values(meta.get('tags')),
                *_string_values(meta.get('risk')),
                *_string_values(meta.get('module')),
            ])
        )
        profile.technologies.update(
            _normalized_string_values([
                *_string_values(meta.get('technology')),
                *_string_values(meta.get('service')),
                *_string_values(meta.get('service_version')),
            ])
        )
        profile.scanners.update(_record_scanner_names(record))

        severity = _safe_text(record.get('severity')).lower()
        if severity in _SEVERITY_RANK:
            profile.severity_values.add(severity)

        confidence = _safe_text(record.get('confidence') or meta.get('confidence')).lower()
        if confidence:
            profile.confidence_values.add(confidence)

        if _safe_text(record.get('remediation')):
            profile.remediation_available = True

    if not profile.severity_values:
        severity = _safe_text(finding.get('severity')).lower()
        profile.severity_values.add(severity if severity in _SEVERITY_RANK else 'info')

    return profile


def _jaccard_similarity(left: set[str], right: set[str]) -> float:
    """Return Jaccard similarity between two token sets."""
    if not left or not right:
        return 0.0
    union = left | right
    if not union:
        return 0.0
    return len(left & right) / len(union)


def _meaningful_port_scope(profile: ComparisonProfile) -> List[int]:
    """Return ports that materially define this finding's location."""
    if not profile.ports:
        return []
    if profile.is_web:
        return sorted(port for port in profile.ports if port not in {80, 443})
    return sorted(profile.ports)


def _endpoint_scope(profile: ComparisonProfile) -> Dict[str, Any]:
    """Return a coarse endpoint scope used for meaningful change detection."""
    return {
        'target_families': sorted(profile.target_families),
        'ports': _meaningful_port_scope(profile),
        'endpoint_families': sorted(profile.endpoint_families),
        'has_path': bool(profile.paths),
        'has_parameter': bool(profile.parameters),
        'methods': sorted(profile.methods),
    }


def _profiles_are_target_compatible(
    current: ComparisonProfile,
    previous: ComparisonProfile,
) -> Tuple[bool, str]:
    """Return whether two logical findings can safely be compared."""
    if current.target_anchors.isdisjoint(previous.target_anchors):
        return False, 'host_mismatch'

    if (
        current.target_families
        and previous.target_families
        and current.target_families.isdisjoint(previous.target_families)
        and 'web' not in current.target_families
        and 'web' not in previous.target_families
    ):
        return False, 'target_family_mismatch'

    if (
        not current.is_web
        and not previous.is_web
        and current.ports
        and previous.ports
        and current.ports.isdisjoint(previous.ports)
    ):
        return False, 'port_mismatch'

    if (
        not current.is_web
        and not previous.is_web
        and current.protocols
        and previous.protocols
        and current.protocols.isdisjoint(previous.protocols)
    ):
        return False, 'protocol_mismatch'

    return True, 'compatible_target'


def _score_profile_match(
    current: ComparisonProfile,
    previous: ComparisonProfile,
) -> Dict[str, Any]:
    """Score one current/previous pair using source-aware logical identity."""
    compatible, reason = _profiles_are_target_compatible(current, previous)
    if not compatible:
        return {
            'accepted': False,
            'score': 0,
            'reason': reason,
        }

    shared_cves = sorted(current.cves & previous.cves)
    shared_cwes = sorted(current.cwes & previous.cwes)
    shared_ids = sorted(current.stable_ids & previous.stable_ids)
    shared_names = sorted(current.normalized_names & previous.normalized_names)
    shared_paths = sorted(current.paths & previous.paths)
    shared_endpoint_families = sorted(current.endpoint_families & previous.endpoint_families)
    shared_parameters = sorted(current.parameters & previous.parameters)
    shared_methods = sorted(current.methods & previous.methods)
    shared_scanners = sorted(current.scanners & previous.scanners)
    shared_categories = sorted(current.categories & previous.categories)
    shared_technologies = sorted(current.technologies & previous.technologies)
    shared_ports = sorted(current.ports & previous.ports)
    shared_target_families = sorted(current.target_families & previous.target_families)
    shared_query_keys = sorted(current.query_keys & previous.query_keys)
    shared_title_tokens = sorted(current.title_tokens & previous.title_tokens)
    title_similarity = _jaccard_similarity(current.title_tokens, previous.title_tokens)

    score = 0
    reasons: List[str] = []

    if current.target_anchors & previous.target_anchors:
        score += 40
        reasons.append('same_host')
    if shared_target_families:
        score += 10
    if shared_ports:
        score += 10
    if shared_cves:
        score += 120
        reasons.append('shared_cve')
    if shared_ids:
        score += 110
        reasons.append('shared_scanner_identity')
    if shared_names:
        score += 55
        reasons.append('shared_vulnerability_family')
    if shared_cwes:
        score += 35
        reasons.append('shared_cwe')
    if title_similarity >= 0.5 and shared_title_tokens:
        score += 25
        reasons.append('similar_title_tokens')
    if shared_paths:
        score += 20
        reasons.append('shared_path')
    if shared_endpoint_families:
        score += 18
        reasons.append('shared_endpoint_family')
    if shared_technologies:
        score += 14
        reasons.append('shared_technology')
    if shared_categories:
        score += 12
        reasons.append('shared_category')
    if shared_parameters:
        score += 8
        reasons.append('shared_parameter')
    if shared_query_keys:
        score += 4
    if shared_methods:
        score += 4
    if shared_scanners:
        score += 4

    strong_identity = bool(shared_cves or shared_ids)
    logical_identity = bool(shared_names or shared_cwes or title_similarity >= 0.5)
    contextual_support = bool(
        shared_target_families
        or shared_ports
        or shared_paths
        or shared_endpoint_families
        or shared_parameters
        or shared_categories
        or shared_technologies
        or shared_scanners
    )

    accepted = False
    acceptance_reason = 'insufficient_logical_overlap'
    if strong_identity and score >= 80:
        accepted = True
        acceptance_reason = 'accepted_strong_identifier_match'
    elif logical_identity and contextual_support and score >= 70:
        accepted = True
        acceptance_reason = 'accepted_logical_identity_match'
    elif (
        title_similarity >= 0.6
        and (shared_paths or shared_endpoint_families)
        and (shared_categories or shared_technologies)
        and score >= 70
    ):
        accepted = True
        acceptance_reason = 'accepted_contextual_title_match'

    return {
        'accepted': accepted,
        'score': score,
        'reason': acceptance_reason,
        'reasons': reasons,
        'title_similarity': round(title_similarity, 3),
        'shared_cves': shared_cves,
        'shared_cwes': shared_cwes,
        'shared_ids': shared_ids,
        'shared_names': shared_names,
        'shared_paths': shared_paths,
        'shared_endpoint_families': shared_endpoint_families,
        'shared_parameters': shared_parameters,
        'shared_methods': shared_methods,
        'shared_scanners': shared_scanners,
        'shared_categories': shared_categories,
        'shared_technologies': shared_technologies,
        'shared_ports': shared_ports,
        'shared_target_families': shared_target_families,
        'shared_query_keys': shared_query_keys,
        'shared_title_tokens': shared_title_tokens,
    }


def _record_comparison_change(
    changed_fields: List[str],
    changes: Dict[str, Dict[str, Any]],
    field: str,
    previous: Any,
    current: Any,
) -> None:
    """Record one structured changed field in a stable shape."""
    changed_fields.append(field)
    changes[field] = {
        'previous': previous,
        'current': current,
    }


def _classify_matched_pair(
    current: ComparisonProfile,
    previous: ComparisonProfile,
    match: Dict[str, Any],
) -> Dict[str, Any]:
    """Return the current finding enriched with comparison status metadata."""
    enriched = current.finding.copy()

    changed_fields: List[str] = []
    changes: Dict[str, Dict[str, Any]] = {}

    current_severities = sorted(current.severity_values)
    previous_severities = sorted(previous.severity_values)
    if current_severities != previous_severities:
        _record_comparison_change(
            changed_fields,
            changes,
            'severity',
            previous_severities,
            current_severities,
        )

    current_confidence = sorted(current.confidence_values)
    previous_confidence = sorted(previous.confidence_values)
    if current_confidence != previous_confidence:
        _record_comparison_change(
            changed_fields,
            changes,
            'confidence',
            previous_confidence,
            current_confidence,
        )

    current_scope = _endpoint_scope(current)
    previous_scope = _endpoint_scope(previous)
    if current_scope != previous_scope:
        _record_comparison_change(
            changed_fields,
            changes,
            'endpoint_scope',
            previous_scope,
            current_scope,
        )

    current_scanners = sorted(current.scanners)
    previous_scanners = sorted(previous.scanners)
    if current_scanners != previous_scanners:
        _record_comparison_change(
            changed_fields,
            changes,
            'source_scanners',
            previous_scanners,
            current_scanners,
        )

    if current.remediation_available != previous.remediation_available:
        _record_comparison_change(
            changed_fields,
            changes,
            'remediation_available',
            previous.remediation_available,
            current.remediation_available,
        )

    current_cves = sorted(current.cves)
    previous_cves = sorted(previous.cves)
    if current_cves != previous_cves:
        _record_comparison_change(
            changed_fields,
            changes,
            'cve_ids',
            previous_cves,
            current_cves,
        )

    current_cwes = sorted(current.cwes)
    previous_cwes = sorted(previous.cwes)
    if current_cwes != previous_cwes:
        _record_comparison_change(
            changed_fields,
            changes,
            'cwe_ids',
            previous_cwes,
            current_cwes,
        )

    if changed_fields:
        enriched['status'] = 'CHANGED'
        enriched['changed_fields'] = changed_fields
        enriched['change_details'] = {
            'changed_fields': changed_fields,
            'changes': changes,
        }
    else:
        enriched['status'] = 'PERSISTENT'

    return enriched


def _result_lookup_key(finding: Dict[str, Any]) -> str:
    """Return a deterministic lookup key for reattaching comparison metadata."""
    finding_id = _safe_text(finding.get('finding_id'))
    if finding_id:
        return f'finding_id::{finding_id}'

    meta = _meta(finding)
    source_findings = finding.get('source_findings')
    source_ids: List[str] = []
    if isinstance(source_findings, list):
        for source in source_findings:
            if not isinstance(source, dict):
                continue
            source_meta = source.get('meta') if isinstance(source.get('meta'), dict) else {}
            source_ids.append(
                '::'.join([
                    _safe_text(source.get('scanner')),
                    _safe_text(source.get('finding_id')),
                    _safe_text(source.get('asset_id')),
                    _safe_text(source.get('vulnerability_name')),
                    _safe_text(source_meta.get('raw_id')),
                ])
            )

    payload = {
        'asset_id': _safe_text(finding.get('asset_id')),
        'vulnerability_name': normalize_vulnerability_name(_safe_text(finding.get('vulnerability_name'))),
        'scanner': _safe_text(meta.get('scanner')).lower(),
        'found_by': sorted(scanner.lower() for scanner in _string_values(finding.get('found_by'))),
        'raw_id': _safe_text(meta.get('raw_id')).lower(),
        'template_id': _safe_text(meta.get('template_id')).lower(),
        'plugin_id': _safe_text(meta.get('plugin_id')).lower(),
        'path': _safe_text(meta.get('path')).lower(),
        'parameter': _safe_text(meta.get('parameter')).lower(),
        'method': _safe_text(meta.get('method')).upper(),
        'source_ids': sorted(source_ids),
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=True)


def _build_partial_unmatched_record(
    finding: Dict[str, Any],
    *,
    direction: str,
) -> Dict[str, Any]:
    """Return a structured unmatched record preserved for partial comparison mode."""
    record = finding.copy()
    record['comparison_mode'] = 'partial'
    return record


def _normalize_scanners_run(value: Any) -> List[str]:
    """Normalize scanner coverage metadata into a stable sorted list."""
    if not isinstance(value, list):
        return []

    seen = set()
    normalized: List[str] = []
    for item in value:
        if not isinstance(item, str):
            continue
        scanner = item.strip().lower()
        if not scanner or scanner in seen:
            continue
        seen.add(scanner)
        normalized.append(scanner)

    normalized.sort()
    return normalized


def _scanner_coverage_delta(
    current_scanners: List[str],
    previous_scanners: List[str],
) -> Dict[str, List[str]]:
    """Return structured scanner-overlap metadata for one baseline candidate."""
    current_set = set(current_scanners)
    previous_set = set(previous_scanners)
    return {
        'overlapping_scanners': sorted(current_set & previous_set),
        'missing_from_current': sorted(previous_set - current_set),
        'missing_from_previous': sorted(current_set - previous_set),
    }


def _evaluate_scanner_compatibility(
    current_results: Dict[str, Any],
    previous_results: Dict[str, Any],
) -> Tuple[bool, str, str, List[str], List[str], Dict[str, List[str]]]:
    """Return whether current and previous scans have full, partial, or no coverage overlap."""
    current_scanners = _normalize_scanners_run(current_results.get('scanners_run'))
    previous_scanners = _normalize_scanners_run(previous_results.get('scanners_run'))
    coverage_delta = _scanner_coverage_delta(current_scanners, previous_scanners)

    if not current_scanners:
        return (
            False,
            'skipped',
            'Comparison skipped because the current scan does not record scanner coverage.',
            current_scanners,
            previous_scanners,
            coverage_delta,
        )
    if not previous_scanners:
        return (
            False,
            'skipped',
            'Comparison skipped because the previous scan does not record scanner coverage.',
            current_scanners,
            previous_scanners,
            coverage_delta,
        )
    if set(current_scanners) == set(previous_scanners):
        return (
            True,
            'full',
            'Compared against the most recent previous scan with matching scanner coverage.',
            current_scanners,
            previous_scanners,
            coverage_delta,
        )

    if coverage_delta['overlapping_scanners']:
        overlap_text = ', '.join(coverage_delta['overlapping_scanners'])
        return (
            True,
            'partial',
            'Compared against the most recent previous scan with partial scanner overlap. '
            f'Overlapping scanners: {overlap_text}.',
            current_scanners,
            previous_scanners,
            coverage_delta,
        )

    return (
        False,
        'skipped',
        'Comparison skipped because scanner coverage had no overlap between scans.',
        current_scanners,
        previous_scanners,
        coverage_delta,
    )


def _iter_previous_scan_candidates(
    reports_dir: Path,
    target: str,
    current_results: Dict[str, Any],
) -> List[Path]:
    """Return candidate baseline result files, newest first, excluding the current run when possible."""
    candidates: List[Path] = []
    seen: set[str] = set()

    current_run_folder_value = current_results.get('run_folder')
    current_run_folder = None
    if isinstance(current_run_folder_value, str) and current_run_folder_value.strip():
        current_run_folder = Path(current_run_folder_value).expanduser().resolve()

    for run_dir in list_target_runs(reports_dir, target):
        resolved_run_dir = run_dir.resolve()
        if current_run_folder and resolved_run_dir == current_run_folder:
            continue

        for candidate_path in (get_normalized_json_path(run_dir), get_scan_results_json_path(run_dir)):
            if not candidate_path.exists():
                continue
            resolved_candidate = str(candidate_path.resolve())
            if resolved_candidate in seen:
                continue
            seen.add(resolved_candidate)
            candidates.append(candidate_path)
            break

    data_dir = reports_dir if reports_dir.name == 'data' else reports_dir / 'data'
    if data_dir.exists():
        from utils.run_folder import create_target_slug
        target_slug = create_target_slug(target)
        legacy_files = sorted(
            data_dir.glob(f"scan_results_{target_slug}_*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for candidate_path in legacy_files:
            resolved_candidate = str(candidate_path.resolve())
            if resolved_candidate in seen:
                continue
            seen.add(resolved_candidate)
            candidates.append(candidate_path)

    return candidates


def _validate_baseline_target(current_target: str, previous_results: Dict[str, Any]) -> str:
    """Ensure the candidate baseline belongs to the same target slug."""
    baseline_target = previous_results.get('target', '').lower().strip()
    current_target_normalized = current_target.lower().strip()

    from utils.run_folder import create_target_slug
    baseline_slug = create_target_slug(baseline_target) if baseline_target else ''
    current_slug = create_target_slug(current_target_normalized) if current_target_normalized else ''

    if baseline_slug and current_slug and baseline_slug != current_slug:
        error_msg = (
            f"\n{'='*70}\n"
            f"COMPARATOR SAFETY CHECK FAILED\n"
            f"{'='*70}\n"
            f"Baseline target does NOT match current target!\n\n"
            f"  Current target: {current_target_normalized}\n"
            f"  Current slug:   {current_slug}\n\n"
            f"  Baseline target: {baseline_target}\n"
            f"  Baseline slug:   {baseline_slug}\n\n"
            f"This indicates a bug in baseline search logic.\n"
            f"Comparison aborted to prevent incorrect baseline matching.\n"
            f"{'='*70}\n"
        )
        raise ValueError(error_msg)

    print(f"[+] Target validation passed: {current_slug}")
    return baseline_slug

def load_scan_results(path: Path) -> Optional[Dict[str, Any]]:
    """
    Load scan results from a JSON file with backward compatibility.

    Automatically upgrades old schema versions (pre-2.0) to current schema.
    """
    try:
        with open(path, 'r') as f:
            data = json.load(f)

        from utils.normalizer import upgrade_schema
        data = upgrade_schema(data)

        return data
    except (json.JSONDecodeError, IOError) as e:
        print(f"[!] Error loading scan results from {path}: {e}")
        return None


def _compare_scan_sets(
    current_findings: List[Dict[str, Any]],
    previous_findings: List[Dict[str, Any]],
    *,
    comparison_mode: str = 'full',
) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two finding sets with mode-aware unmatched-finding semantics."""
    mode = comparison_mode if comparison_mode in {'full', 'partial'} else 'full'

    current_profiles = [
        _build_comparison_profile(index, finding)
        for index, finding in enumerate(current_findings)
        if isinstance(finding, dict)
    ]
    previous_profiles = [
        _build_comparison_profile(index, finding)
        for index, finding in enumerate(previous_findings)
        if isinstance(finding, dict)
    ]

    previous_by_anchor: Dict[str, set[int]] = defaultdict(set)
    for profile in previous_profiles:
        for anchor in profile.target_anchors:
            previous_by_anchor[anchor].add(profile.index)

    candidate_pairs: List[Tuple[int, Tuple[int, int, int, int, int, int], int, int, Dict[str, Any]]] = []
    previous_index_map = {profile.index: profile for profile in previous_profiles}

    for current_profile in current_profiles:
        candidate_indexes: set[int] = set()
        for anchor in current_profile.target_anchors:
            candidate_indexes.update(previous_by_anchor.get(anchor, set()))

        for previous_index in candidate_indexes:
            previous_profile = previous_index_map[previous_index]
            match = _score_profile_match(current_profile, previous_profile)
            if not match.get('accepted'):
                continue

            strength = (
                len(match.get('shared_cves', [])),
                len(match.get('shared_ids', [])),
                len(match.get('shared_names', [])),
                len(match.get('shared_endpoint_families', [])),
                len(match.get('shared_paths', [])),
                len(match.get('shared_scanners', [])),
            )
            candidate_pairs.append(
                (
                    int(match.get('score', 0)),
                    strength,
                    current_profile.index,
                    previous_profile.index,
                    match,
                )
            )

    candidate_pairs.sort(
        key=lambda item: (
            item[0],
            item[1],
            -item[2],
            -item[3],
        ),
        reverse=True,
    )

    matched_current: Dict[int, Tuple[int, Dict[str, Any]]] = {}
    matched_previous: Dict[int, Tuple[int, Dict[str, Any]]] = {}
    for _, _, current_index, previous_index, match in candidate_pairs:
        if current_index in matched_current or previous_index in matched_previous:
            continue
        matched_current[current_index] = (previous_index, match)
        matched_previous[previous_index] = (current_index, match)

    fixed: List[Dict[str, Any]] = []
    new: List[Dict[str, Any]] = []
    persistent: List[Dict[str, Any]] = []
    changed: List[Dict[str, Any]] = []
    partial_unmatched_current: List[Dict[str, Any]] = []
    partial_unmatched_previous: List[Dict[str, Any]] = []

    for current_profile in current_profiles:
        match_entry = matched_current.get(current_profile.index)
        if match_entry is None:
            if mode == 'partial':
                partial_unmatched_current.append(
                    _build_partial_unmatched_record(current_profile.finding, direction='current')
                )
                continue

            finding = current_profile.finding.copy()
            finding['status'] = 'NEW'
            new.append(finding)
            continue

        previous_index, match = match_entry
        previous_profile = previous_index_map[previous_index]
        enriched = _classify_matched_pair(current_profile, previous_profile, match)
        if enriched.get('status') == 'CHANGED':
            changed.append(enriched)
        else:
            persistent.append(enriched)

    for previous_profile in previous_profiles:
        if previous_profile.index in matched_previous:
            continue
        if mode == 'partial':
            partial_unmatched_previous.append(
                _build_partial_unmatched_record(previous_profile.finding, direction='previous')
            )
            continue

        finding = previous_profile.finding.copy()
        finding['status'] = 'FIXED'
        fixed.append(finding)

    return {
        'fixed': fixed,
        'new': new,
        'persistent': persistent,
        'changed': changed,
        'partial_unmatched_current': partial_unmatched_current,
        'partial_unmatched_previous': partial_unmatched_previous,
    }


def compare_scans(
    current_findings: List[Dict[str, Any]],
    previous_findings: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Compare two sets of findings and categorize them.

    Args:
        current_findings: Findings from the new scan
        previous_findings: Findings from the old scan

    Returns:
        Tuple of (fixed, new, persistent, changed) findings
    """
    compared = _compare_scan_sets(
        current_findings,
        previous_findings,
        comparison_mode='full',
    )
    return (
        compared['fixed'],
        compared['new'],
        compared['persistent'],
        compared['changed'],
    )

def compare_with_previous(
    current_results: Dict[str, Any],
    reports_dir: Optional[Path] = None,
    previous_scan_path: Optional[Path] = None
) -> ComparisonResult:
    """
    Compare current scan results with the most recent previous scan.

    Args:
        current_results: Current scan results dict
        reports_dir: Directory to search for previous scans
        previous_scan_path: Explicit path to previous scan (overrides auto-detection)

    Returns:
        ComparisonResult with categorized findings
    """
    result = ComparisonResult()
    result.new_scan_timestamp = current_results.get('timestamp')
    result.current_scanners_run = _normalize_scanners_run(current_results.get('scanners_run'))

    current_findings = current_results.get('all_findings', [])
    target = current_results.get('target', '')

    candidate_paths: List[Path]
    if previous_scan_path is None:
        if reports_dir is None:
            reports_dir = Path('data')
        candidate_paths = _iter_previous_scan_candidates(reports_dir, target, current_results)
    else:
        candidate_paths = [previous_scan_path]

    if not candidate_paths:
        result.include_summary = True
        result.compatibility_reason = 'No previous scan available for comparison.'
        for finding in current_findings:
            f = finding.copy()
            f['status'] = 'NEW'
            result.new.append(f)
        return result

    latest_reason = 'Comparison skipped because no compatible previous scan was found.'
    latest_previous_scanners: List[str] = []
    latest_coverage_delta: Dict[str, List[str]] = {
        'overlapping_scanners': [],
        'missing_from_current': [],
        'missing_from_previous': [],
    }
    partial_candidate: Optional[Tuple[Path, Dict[str, Any], str, List[str], Dict[str, List[str]]]] = None

    def _apply_baseline(
        baseline_path: Path,
        previous_results: Dict[str, Any],
        *,
        selected_mode: str,
        reason: str,
        previous_scanners: List[str],
        coverage_delta: Dict[str, List[str]],
    ) -> ComparisonResult:
        result.compatible_baseline_used = True
        result.comparison_mode = selected_mode
        result.compatibility_reason = reason
        result.include_summary = True
        result.old_scan_path = baseline_path
        result.old_scan_timestamp = previous_results.get('timestamp')
        result.previous_scanners_run = previous_scanners
        result.overlapping_scanners = coverage_delta['overlapping_scanners']
        result.missing_from_current = coverage_delta['missing_from_current']
        result.missing_from_previous = coverage_delta['missing_from_previous']
        result.scanner_coverage_delta = coverage_delta

        previous_findings = previous_results.get('all_findings', [])
        result.previous_findings = previous_findings

        compared = _compare_scan_sets(
            current_findings,
            previous_findings,
            comparison_mode=selected_mode,
        )
        result.fixed = compared['fixed']
        result.new = compared['new']
        result.persistent = compared['persistent']
        result.changed = compared['changed']
        result.partial_unmatched_current = compared['partial_unmatched_current']
        result.partial_unmatched_previous = compared['partial_unmatched_previous']

        if selected_mode == 'partial':
            result.partial_comparison_limitations = [
                'Partial comparison used overlapping scanner coverage only.',
                'Unmatched findings were not classified as fixed/new because scanner coverage differed.',
            ]
            if result.partial_unmatched_current:
                result.partial_comparison_limitations.append(
                    f"{len(result.partial_unmatched_current)} current unmatched finding(s) were left unclassified."
                )
            if result.partial_unmatched_previous:
                result.partial_comparison_limitations.append(
                    f"{len(result.partial_unmatched_previous)} previous unmatched finding(s) were left unclassified."
                )

        return result

    for candidate_path in candidate_paths:
        previous_results = load_scan_results(candidate_path)
        if previous_results is None:
            latest_reason = 'Comparison skipped because no readable previous scan with compatible scanner coverage was found.'
            continue

        _validate_baseline_target(target, previous_results)

        compatible, comparison_mode, reason, current_scanners, previous_scanners, coverage_delta = _evaluate_scanner_compatibility(
            current_results,
            previous_results,
        )
        result.current_scanners_run = current_scanners

        if compatible:
            if comparison_mode == 'full':
                return _apply_baseline(
                    candidate_path,
                    previous_results,
                    selected_mode='full',
                    reason=reason,
                    previous_scanners=previous_scanners,
                    coverage_delta=coverage_delta,
                )
            if comparison_mode == 'partial' and partial_candidate is None:
                partial_candidate = (
                    candidate_path,
                    previous_results,
                    reason,
                    previous_scanners,
                    coverage_delta,
                )
            continue

        latest_reason = reason
        latest_previous_scanners = previous_scanners
        latest_coverage_delta = coverage_delta

    if partial_candidate is not None:
        baseline_path, previous_results, reason, previous_scanners, coverage_delta = partial_candidate
        return _apply_baseline(
            baseline_path,
            previous_results,
            selected_mode='partial',
            reason=reason,
            previous_scanners=previous_scanners,
            coverage_delta=coverage_delta,
        )

    result.compatibility_reason = latest_reason
    result.previous_scanners_run = latest_previous_scanners
    result.overlapping_scanners = latest_coverage_delta['overlapping_scanners']
    result.missing_from_current = latest_coverage_delta['missing_from_current']
    result.missing_from_previous = latest_coverage_delta['missing_from_previous']
    result.scanner_coverage_delta = latest_coverage_delta

    return result

def add_comparison_to_results(
    results: Dict[str, Any],
    reports_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """
    Convenience wrapper to add comparison data to scan results.

    Args:
        results: Current scan results
        reports_dir: Directory with previous scans

    Returns:
        Results with comparison data added

    Raises:
        ValueError: If baseline target doesn't match current target
    """
    comparison = compare_with_previous(results, reports_dir)

    results['comparison'] = comparison.to_dict()['comparison']

    # BUG-10 fix: the previous implementation indexed compared findings by a
    # non-unique string key (vulnerability_name + asset_id + scanner …) so two
    # findings sharing the same name and asset could get the wrong status stamped.
    #
    # New strategy: build an ordered pool of compared-finding objects and match
    # each raw finding to the first unclaimed pool entry whose identity overlaps.
    # We try fp_strict first (highest certainty), then _result_lookup_key as a
    # fallback.  Each pool slot is consumed at most once (claimed flag) to prevent
    # one raw finding from consuming two compared findings.
    compared_pool: List[Dict[str, Any]] = list(comparison.new + comparison.persistent + comparison.changed)
    compared_keys: List[str] = [_result_lookup_key(f) for f in compared_pool]
    compared_fp: List[str] = [f.get('fp_strict') or '' for f in compared_pool]
    claimed: List[bool] = [False] * len(compared_pool)

    def _find_match(raw_finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        raw_fp = raw_finding.get('fp_strict') or ''
        raw_key = _result_lookup_key(raw_finding)
        # Pass 1: fp_strict exact match (available after normalization).
        if raw_fp:
            for i, fp in enumerate(compared_fp):
                if not claimed[i] and fp and fp == raw_fp:
                    claimed[i] = True
                    return compared_pool[i]
        # Pass 2: _result_lookup_key match.
        for i, key in enumerate(compared_keys):
            if not claimed[i] and key == raw_key:
                claimed[i] = True
                return compared_pool[i]
        return None

    enriched_findings: List[Dict[str, Any]] = []
    for finding in results.get('all_findings', []):
        matched = _find_match(finding)
        enriched_findings.append(matched if matched is not None else finding)

    results['all_findings'] = enriched_findings
    results['fixed_findings'] = comparison.fixed
    results['changed_findings'] = comparison.changed
    results['partial_unmatched_current_findings'] = comparison.partial_unmatched_current
    results['partial_unmatched_previous_findings'] = comparison.partial_unmatched_previous

    return results

def print_comparison_summary(comparison: Dict[str, Any]) -> None:
    """Print a formatted comparison summary to console."""
    comparison_meta = comparison.get('comparison', {})
    summary = comparison_meta.get('summary', {})
    compatible_baseline_used = comparison_meta.get('compatible_baseline_used', False)
    comparison_mode = comparison_meta.get('comparison_mode', 'skipped')
    compatibility_reason = comparison_meta.get('compatibility_reason', '')
    current_scanners = comparison_meta.get('current_scanners_run', [])
    previous_scanners = comparison_meta.get('previous_scanners_run', [])
    overlapping_scanners = comparison_meta.get('overlapping_scanners', [])
    missing_from_current = comparison_meta.get('missing_from_current', [])
    missing_from_previous = comparison_meta.get('missing_from_previous', [])
    limitations = comparison_meta.get('partial_comparison_limitations', [])

    print("\n" + "=" * 60)
    print("SCAN COMPARISON")
    print("=" * 60)

    if compatible_baseline_used and comparison_meta.get('old_scan'):
        print(f"Previous scan: {comparison_meta['old_scan']}")
        print(f"Previous timestamp: {comparison_meta['old_scan_timestamp']}")
        if comparison_mode == 'partial' and compatibility_reason:
            print(compatibility_reason)
    else:
        print(compatibility_reason or "No previous scan available for comparison")

    if current_scanners:
        print(f"Current scanners: {', '.join(current_scanners)}")
    if previous_scanners:
        print(f"Previous scanners: {', '.join(previous_scanners)}")
    if overlapping_scanners:
        print(f"Overlapping scanners: {', '.join(overlapping_scanners)}")
    if missing_from_current:
        print(f"Missing from current: {', '.join(missing_from_current)}")
    if missing_from_previous:
        print(f"Missing from previous: {', '.join(missing_from_previous)}")
    for limitation in limitations:
        print(f"Note: {limitation}")

    if summary:
        print()
        print(f"  🟢 FIXED:      {summary.get('fixed', 0)} vulnerabilities resolved")
        print(f"  🔴 NEW:        {summary.get('new', 0)} vulnerabilities introduced")
        print(f"  🟠 CHANGED:    {summary.get('changed', 0)} vulnerabilities modified")
        print(f"  🟡 PERSISTENT: {summary.get('persistent', 0)} vulnerabilities remain")
        if comparison_mode == 'partial':
            print(f"  ⚪ CURRENT UNCERTAIN:  {summary.get('partial_unmatched_current', 0)} unmatched current findings")
            print(f"  ⚪ PREVIOUS UNCERTAIN: {summary.get('partial_unmatched_previous', 0)} unmatched previous findings")
        print()
        print(f"  Total current: {summary.get('total_current', 0)}")
    print("=" * 60)
