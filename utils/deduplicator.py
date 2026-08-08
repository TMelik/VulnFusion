"""
Vulnerability Deduplicator Module

Provides functions to merge duplicate findings across multiple scanners
using layered fingerprinting (strict → general → host-only).
"""

from copy import deepcopy
import hashlib
from typing import Any, Dict, Iterable, List
from utils.normalizer import (
    canonical_path,
    create_fingerprints,
    is_adapter_transport_artifact,
    normalize_vulnerability_name,
    parse_target,
)
from utils.result_summary import refresh_summary_counts

# Rank of each match level: higher rank = weaker/lower confidence.
# 'single' is a sentinel for a group that has not yet been merged with anything.
_LEVEL_RANK: Dict[str, int] = {
    'single':    -1,  # sentinel – no real merge yet
    'strict':     0,
    'general':    1,
    'host_only':  2,
}
def _update_match_level(levels: Dict[str, str], key: str, join_level: str) -> None:
    """
    Update a group's match_level using weakest-wins semantics.

    The recorded level for a group is always the weakest (lowest-confidence)
    level that was used to bring any finding into that group.
    """
    current = levels.get(key, 'single')
    if _LEVEL_RANK.get(join_level, 0) > _LEVEL_RANK.get(current, -1):
        levels[key] = join_level

def _severity_rank(severity: str) -> int:
    """Convert severity string to numeric rank."""
    ranks = {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1, 'unknown': 0}
    return ranks.get(str(severity).lower(), 0)

def _get_scanner_name(finding: Dict[str, Any]) -> str:
    """Extract scanner name from finding."""
    return finding.get('meta', {}).get('scanner', 'unknown')


def is_degraded_finding(finding: Dict[str, Any]) -> bool:
    """Return True when a finding carries degraded scanner evidence."""
    meta = finding.get('meta', {})
    if isinstance(meta, dict) and meta.get('degraded_execution') is True:
        return True

    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        for source in source_findings:
            if not isinstance(source, dict):
                continue
            if source.get('degraded_execution') is True:
                return True
            source_meta = source.get('meta', {})
            if isinstance(source_meta, dict) and source_meta.get('degraded_execution') is True:
                return True

    return False


def _finding_identity_for_deterministic_merge(finding: Dict[str, Any]) -> str:
    """Return the narrowest stable vuln identity available for exact same-scanner merges."""
    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    for key in ('plugin_id', 'template_id', 'raw_id', 'cve_id'):
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()

    return normalize_vulnerability_name(str(finding.get('vulnerability_name') or ''))


def _same_scanner_exact_duplicate_key(finding: Dict[str, Any]) -> tuple[Any, ...] | None:
    """Return a strict, same-scanner-only merge key for exact duplicate findings."""
    scanner = _get_scanner_name(finding).strip().lower()
    identity = _finding_identity_for_deterministic_merge(finding)
    strict_fingerprint = create_fingerprints(finding).get('fp_strict', '')
    if not scanner or not identity or not strict_fingerprint:
        return None
    return (scanner, identity, strict_fingerprint)


def _dedupe_preserve_order(values: Iterable[Any]) -> List[Any]:
    """Return unique values in first-seen order."""
    deduped: List[Any] = []
    seen = set()
    for value in values:
        key = value if isinstance(value, (str, int, float, bool, type(None))) else repr(value)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(value)
    return deduped


def _collect_meta_string_union(
    findings: List[Dict[str, Any]],
    singular_key: str,
    plural_key: str,
) -> List[str]:
    """Collect string values from singular and plural metadata fields."""
    values: List[str] = []
    for finding in findings:
        meta = finding.get('meta', {})
        if not isinstance(meta, dict):
            continue
        singular = meta.get(singular_key)
        if isinstance(singular, str) and singular.strip():
            values.append(singular)
        plural = meta.get(plural_key)
        if isinstance(plural, list):
            for item in plural:
                if isinstance(item, str) and item.strip():
                    values.append(item)
    return _dedupe_preserve_order(values)


def _collect_meta_int_union(
    findings: List[Dict[str, Any]],
    singular_key: str,
    plural_key: str,
) -> List[int]:
    """Collect integer values from singular and plural metadata fields."""
    values: List[int] = []
    for finding in findings:
        meta = finding.get('meta', {})
        if not isinstance(meta, dict):
            continue
        singular = meta.get(singular_key)
        if isinstance(singular, int) and not isinstance(singular, bool):
            values.append(singular)
        plural = meta.get(plural_key)
        if isinstance(plural, list):
            for item in plural:
                if isinstance(item, int) and not isinstance(item, bool):
                    values.append(item)
    return _dedupe_preserve_order(values)


def _collect_cve_ids(findings: List[Dict[str, Any]]) -> List[str]:
    """Collect canonical CVE IDs from cve_id/cve_ids metadata."""
    cve_ids: List[str] = []
    for finding in findings:
        meta = finding.get('meta', {})
        if not isinstance(meta, dict):
            continue
        cve_id = meta.get('cve_id')
        if isinstance(cve_id, str) and cve_id.strip():
            cve_ids.append(cve_id)
        meta_cve_ids = meta.get('cve_ids')
        if isinstance(meta_cve_ids, list):
            for value in meta_cve_ids:
                if isinstance(value, str) and value.strip():
                    cve_ids.append(value)
    return _dedupe_preserve_order(cve_ids)


def _collect_reference_urls(findings: List[Dict[str, Any]]) -> List[str]:
    """Collect references from meta.reference/meta.references and optional top-level references."""
    references: List[str] = []
    for finding in findings:
        meta = finding.get('meta', {})
        if isinstance(meta, dict):
            for key in ('reference', 'references'):
                value = meta.get(key)
                if isinstance(value, str) and value.strip():
                    references.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item.strip():
                            references.append(item)

        top_level_references = finding.get('references')
        if isinstance(top_level_references, list):
            for item in top_level_references:
                if isinstance(item, str) and item.strip():
                    references.append(item)

    return _dedupe_preserve_order(references)


def _collect_scanners_by_quality(findings: List[Dict[str, Any]]) -> tuple[List[str], List[str]]:
    """Return ordered (all_scanners, confirmation_scanners) lists."""
    all_scanners: List[str] = []
    confirmation_scanners: List[str] = []

    for finding in findings:
        for scanner in _finding_all_scanners(finding):
            if scanner and scanner not in all_scanners:
                all_scanners.append(scanner)
        for scanner in _finding_confirmation_scanners(finding):
            if scanner and scanner not in confirmation_scanners:
                confirmation_scanners.append(scanner)

    return all_scanners, confirmation_scanners


def _obvious_internal_server_error_key(
    finding: Dict[str, Any],
    *,
    same_scanner_only: bool = False,
) -> tuple[Any, ...] | None:
    """Return a deterministic merge key for repeated same-endpoint HTTP 500 findings."""
    normalized_name = normalize_vulnerability_name(str(finding.get('vulnerability_name') or ''))
    if normalized_name != 'internal server error':
        return None

    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}
    parsed = parse_target(str(finding.get('asset_id') or ''))

    host = str(parsed.get('host') or meta.get('host') or '').strip().lower()
    if not host:
        return None

    scheme = str(parsed.get('scheme') or meta.get('scheme') or '').strip().lower()
    port = parsed.get('port')
    if port is None:
        raw_port = meta.get('port')
        if isinstance(raw_port, int) and not isinstance(raw_port, bool):
            port = raw_port
        elif isinstance(raw_port, str) and raw_port.isdigit():
            port = int(raw_port)

    path = canonical_path(str(parsed.get('path') or meta.get('path') or ''))
    method = str(meta.get('method') or '').strip().upper()
    scanner = _get_scanner_name(finding)

    key: tuple[Any, ...] = (
        normalized_name,
        host,
        scheme,
        port,
        path,
        method,
    )
    if same_scanner_only:
        key = key + (scanner,)
    return key


def _build_source_record(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Capture a source finding for auditability inside a merged record."""
    fps = create_fingerprints(finding)
    source = {
        'finding_id': finding.get('finding_id'),
        'scanner': _get_scanner_name(finding),
        'vulnerability_name': finding.get('vulnerability_name'),
        'severity': finding.get('severity', 'info'),
        'asset_id': finding.get('asset_id'),
        'description': finding.get('description', ''),
        'remediation': finding.get('remediation', ''),
        'meta': deepcopy(finding.get('meta', {})) if isinstance(finding.get('meta', {}), dict) else {},
        'fp_strict': fps.get('fp_strict', ''),
        'fp_general': fps.get('fp_general', ''),
        'fp_host_only': fps.get('fp_host_only', ''),
    }

    if isinstance(finding.get('references'), list):
        source['references'] = deepcopy(finding.get('references', []))

    return source


def _finding_all_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return every scanner provenance label represented by one finding."""
    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        scanners = _dedupe_preserve_order(
            [
                str(
                    source.get('scanner')
                    or (
                        source.get('meta', {}).get('scanner')
                        if isinstance(source.get('meta'), dict)
                        else ''
                    )
                    or ''
                ).strip()
                for source in source_findings
                if isinstance(source, dict)
            ]
        )
        scanners = [scanner for scanner in scanners if scanner]
        if scanners:
            return scanners

    for value in (finding.get('found_by'), meta.get('scanners')):
        if isinstance(value, list):
            scanners = _dedupe_preserve_order(
                str(scanner).strip()
                for scanner in value
                if str(scanner).strip()
            )
            if scanners:
                return scanners

    scanner = str(_get_scanner_name(finding) or '').strip()
    return [scanner] if scanner else []


def _finding_confirmation_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return scanners that contribute non-degraded confirmation for one finding."""
    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    confirmation = meta.get('confirmation_scanners')
    if isinstance(confirmation, list):
        scanners = _dedupe_preserve_order(
            str(scanner).strip()
            for scanner in confirmation
            if str(scanner).strip()
        )
        if scanners:
            return scanners

    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        scanners = _dedupe_preserve_order(
            [
                str(
                    source.get('scanner')
                    or (
                        source.get('meta', {}).get('scanner')
                        if isinstance(source.get('meta'), dict)
                        else ''
                    )
                    or ''
                ).strip()
                for source in source_findings
                if isinstance(source, dict)
                and not (
                    source.get('degraded_execution') is True
                    or (
                        isinstance(source.get('meta'), dict)
                        and source['meta'].get('degraded_execution') is True
                    )
                )
            ]
        )
        scanners = [scanner for scanner in scanners if scanner]
        if scanners:
            return scanners

    return [] if is_degraded_finding(finding) else _finding_all_scanners(finding)


def _expanded_source_records(finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Flatten nested merged findings into one ordered source-record list."""
    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list) and source_findings:
        return [
            deepcopy(source)
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
        finding_id = record.get('finding_id')
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


def _collect_lineage_ids(findings: List[Dict[str, Any]]) -> List[str]:
    """Return ordered merged-lineage ids represented by one merged group."""
    lineage_ids: List[str] = []
    for finding in findings:
        finding_id = finding.get('finding_id')
        if finding_id is not None:
            text = str(finding_id).strip()
            if text:
                lineage_ids.append(text)
        meta = finding.get('meta', {})
        if not isinstance(meta, dict):
            continue
        merged_lineage_ids = meta.get('merged_lineage_ids')
        if isinstance(merged_lineage_ids, list):
            for item in merged_lineage_ids:
                text = str(item).strip()
                if text:
                    lineage_ids.append(text)
    return _dedupe_preserve_order(lineage_ids)


def _find_matching_group(
    groups: Dict[str, List[int]],
    fingerprints: List[Dict[str, str]],
    fps: Dict[str, str],
    fp_field: str,
) -> str | None:
    """
    Return the key for the first group containing a matching fingerprint.

    A group can contain findings brought together through weaker tiers, so the
    newest finding must be compared with every group member, not just the first
    member that happened to create the group.
    """
    candidate = fps.get(fp_field, '')
    if not candidate:
        return None

    for existing_key, group in groups.items():
        if any(candidate == fingerprints[index].get(fp_field, '') for index in group):
            return existing_key

    return None


def _internal_server_error_group_conflicts(
    candidate_finding: Dict[str, Any],
    group_findings: List[Dict[str, Any]],
) -> bool:
    """Return True when a candidate 500 finding should stay separate from an existing group."""
    candidate_key = _obvious_internal_server_error_key(candidate_finding)
    if candidate_key is None:
        return False

    for existing_finding in group_findings:
        existing_key = _obvious_internal_server_error_key(existing_finding)
        if existing_key is not None and existing_key != candidate_key:
            return True

    return False


def _suppress_adapter_transport_artifacts(findings: List[Dict[str, Any]]) -> tuple[List[Dict[str, Any]], int]:
    """Drop local adapter artifacts from final-report candidate findings."""
    kept: List[Dict[str, Any]] = []
    suppressed = 0
    for finding in findings:
        if is_adapter_transport_artifact(finding):
            suppressed += 1
        else:
            kept.append(finding)
    return kept, suppressed


def merge_deterministic_cluster(
    findings: List[Dict[str, Any]],
    *,
    reason: str,
    duplicate_resolution_extra: Dict[str, Any] | None = None,
    match_level: str = 'general',
) -> Dict[str, Any]:
    """Merge one deterministic duplicate cluster while preserving provenance."""
    merged_group = _merge_group(findings, match_level)
    source_ids = [
        str(source.get('finding_id'))
        for source in merged_group.get('source_findings', [])
        if isinstance(source, dict) and source.get('finding_id')
    ]
    if source_ids:
        cluster_key = '::'.join(sorted(source_ids))
        merged_group['finding_id'] = f"cluster-{hashlib.sha256(cluster_key.encode('utf-8')).hexdigest()[:16]}"

    meta = merged_group.get('meta', {})
    if isinstance(meta, dict):
        meta['duplicate_resolution_mode'] = 'deterministic'

    duplicate_resolution = {
        'mode': 'deterministic',
        'reason': reason,
    }
    if isinstance(duplicate_resolution_extra, dict):
        duplicate_resolution.update(deepcopy(duplicate_resolution_extra))
    merged_group['duplicate_resolution'] = duplicate_resolution
    return merged_group


def merge_obvious_duplicates(
    findings: List[Dict[str, Any]],
    *,
    same_scanner_only: bool = False,
) -> List[Dict[str, Any]]:
    """Merge deterministic obvious duplicates before or after the LLM flow."""
    if not findings:
        return []

    if not same_scanner_only:
        return list(findings)

    return _merge_deterministic_groups(
        findings,
        key_builder=_same_scanner_exact_duplicate_key,
        reason='same_scanner_exact_duplicate',
    )


def _merge_deterministic_groups(
    findings: List[Dict[str, Any]],
    *,
    key_builder,
    reason: str,
) -> List[Dict[str, Any]]:
    """Apply one deterministic merge rule while preserving first-seen order."""
    grouped: Dict[tuple[Any, ...], List[Dict[str, Any]]] = {}
    ordered_items: List[tuple[str, Any]] = []
    seen_group_keys: set[tuple[Any, ...]] = set()

    for finding in findings:
        key = key_builder(finding)
        if key is None:
            ordered_items.append(('passthrough', finding))
            continue
        grouped.setdefault(key, []).append(finding)
        if key not in seen_group_keys:
            ordered_items.append(('group', key))
            seen_group_keys.add(key)

    merged: List[Dict[str, Any]] = []
    for item_type, value in ordered_items:
        if item_type == 'passthrough':
            merged.append(value)
            continue

        group_findings = grouped[value]
        if len(group_findings) <= 1:
            merged.extend(group_findings)
            continue

        merged_group = merge_deterministic_cluster(group_findings, reason=reason)
        merged.append(merged_group)

    return merged

def merge_vulnerabilities(data_list: List[Dict[str, Any]], use_host_only: bool = False) -> List[Dict[str, Any]]:
    """
    Merge duplicate vulnerabilities using layered fingerprinting.

    Matching strategy:
    1. Try fp_strict (exact context match)
    2. Fall back to fp_general (same host + path)
    3. Fall back to fp_host_only (same host) - OPTIONAL, may merge unrelated vulns

    Args:
        data_list: List of vulnerability findings
        use_host_only: Enable host-only matching (default: False, safer)

    Returns:
        List of merged findings with confidence scores
    """
    if not data_list:
        return []

    data_list = merge_obvious_duplicates(data_list, same_scanner_only=False)

    fingerprints = []
    for finding in data_list:
        fps = create_fingerprints(finding)
        fingerprints.append(fps)

    groups = {}
    match_levels: Dict[str, str] = {}

    for i, finding in enumerate(data_list):
        fps = fingerprints[i]
        matched = False

        # --- Tier 1: strict match ---
        existing_key = _find_matching_group(groups, fingerprints, fps, 'fp_strict')
        if existing_key is not None:
            group_findings = [data_list[index] for index in groups[existing_key]]
            if _internal_server_error_group_conflicts(finding, group_findings):
                existing_key = None
        if existing_key is not None:
            groups[existing_key].append(i)
            # strict join never weakens the group level
            _update_match_level(match_levels, existing_key, 'strict')
            matched = True

        if matched:
            continue

        # --- Tier 2: general match ---
        existing_key = _find_matching_group(groups, fingerprints, fps, 'fp_general')
        if existing_key is not None:
            group_findings = [data_list[index] for index in groups[existing_key]]
            if _internal_server_error_group_conflicts(finding, group_findings):
                existing_key = None
        if existing_key is not None:
            groups[existing_key].append(i)
            # general join weakens any group that was previously strict
            _update_match_level(match_levels, existing_key, 'general')
            matched = True

        if matched:
            continue

        # --- Tier 3: host-only match (opt-in) ---
        if use_host_only:
            existing_key = _find_matching_group(groups, fingerprints, fps, 'fp_host_only')
            if existing_key is not None:
                group_findings = [data_list[index] for index in groups[existing_key]]
                if _internal_server_error_group_conflicts(finding, group_findings):
                    existing_key = None
            if existing_key is not None:
                groups[existing_key].append(i)
                # host_only is the weakest level — always wins
                _update_match_level(match_levels, existing_key, 'host_only')
                matched = True

        # --- No match: new singleton group ---
        if not matched:
            key = fps['fp_strict'] or fps['fp_general'] or fps['fp_host_only'] or f'unique_{i}'
            groups[key] = [i]
            # 'single' sentinel: no real merge yet; resolved in _merge_group
            match_levels[key] = 'single'

    merged_results = []
    for key, indices in groups.items():
        member_findings = [data_list[i] for i in indices]
        level = match_levels.get(key, 'single')
        if len(indices) > 1 and level == 'single':
            level = 'strict'
        merged = _merge_group(member_findings, level)
        merged_results.append(merged)

    merged_results.sort(key=lambda x: _severity_rank(x.get('severity', 'info')), reverse=True)

    return merged_results

def _merge_group(findings: List[Dict[str, Any]], match_level: str) -> Dict[str, Any]:
    """
    Merge a group of findings into a single result.

    Args:
        findings: List of findings to merge
        match_level: 'strict', 'general', or 'host_only'

    Returns:
        Merged finding dict
    """
    if len(findings) == 1:
        result = deepcopy(findings[0])
        if not isinstance(result.get('found_by'), list) or not result.get('found_by'):
            result['found_by'] = [_get_scanner_name(findings[0])]
        if 'merge_confidence' not in result:
            result['merge_confidence'] = 1.0
        if 'match_level' not in result:
            result['match_level'] = 'single'
        return result

    findings_sorted = sorted(
        findings,
        key=lambda x: (
            0 if is_degraded_finding(x) else 1,
            _severity_rank(x.get('severity', 'info')),
        ),
        reverse=True,
    )
    base = findings_sorted[0].copy()

    scanner_names, confirmation_scanners = _collect_scanners_by_quality(findings)
    degraded_scanners = [
        scanner for scanner in scanner_names
        if scanner not in confirmation_scanners
    ]

    confidence_map = {
        'strict': 1.0,
        'general': 0.85,
        'host_only': 0.60
    }
    confidence = confidence_map.get(match_level, 0.5)

    vuln_name = base.get('vulnerability_name', '')
    normalized_name = normalize_vulnerability_name(vuln_name)
    meta = deepcopy(base.get('meta', {})) if isinstance(base.get('meta', {}), dict) else {}
    merged_source_findings = _dedupe_source_records(
        source
        for finding in findings
        for source in _expanded_source_records(finding)
    )
    source_count = len(merged_source_findings) or len(findings)
    lineage_ids = _collect_lineage_ids(findings)

    raw_ids = _collect_meta_string_union(findings, 'raw_id', 'raw_ids')
    cve_ids = _collect_cve_ids(findings)
    references = _collect_reference_urls(findings)
    paths = _collect_meta_string_union(findings, 'path', 'paths')
    parameters = _collect_meta_string_union(findings, 'parameter', 'parameters')
    ports = _collect_meta_int_union(findings, 'port', 'ports')
    methods = _collect_meta_string_union(findings, 'method', 'methods')
    matcher_names = _collect_meta_string_union(findings, 'matcher_name', 'matcher_names')
    evidence_examples = _collect_meta_string_union(findings, 'evidence', 'evidence_examples')
    http_request_examples = _collect_meta_string_union(findings, 'http_request', 'http_request_examples')
    curl_command_examples = _collect_meta_string_union(findings, 'curl_command', 'curl_command_examples')

    merged = {
        'vulnerability_name': base.get('vulnerability_name'),
        'normalized_name': normalized_name,
        'severity': base.get('severity', 'info'),
        'asset_id': base.get('asset_id', 'unknown'),
        'description': str(base.get('description') or ''),
        'remediation': str(base.get('remediation') or ''),
        'found_by': scanner_names,
        'duplicate_count': source_count,
        'merge_confidence': confidence,
        'match_level': match_level,
        'meta': meta,
        'source_findings': merged_source_findings,
    }

    merged['meta'].update({
        'merged': True,
        'original_findings_count': source_count,
        'scanners': scanner_names,
        'has_multi_scanner_confirmation': len(confirmation_scanners) > 1,
        'match_level': match_level
    })
    if confirmation_scanners:
        merged['meta']['confirmation_scanners'] = confirmation_scanners
    if degraded_scanners:
        merged['meta']['degraded_scanners'] = degraded_scanners
        merged['meta']['degraded_execution'] = True

    if raw_ids:
        merged['meta']['raw_ids'] = raw_ids
    if cve_ids:
        merged['meta']['cve_ids'] = cve_ids
    if references:
        merged['meta']['references'] = references
    if paths:
        merged['meta']['paths'] = paths
    if parameters:
        merged['meta']['parameters'] = parameters
    if ports:
        merged['meta']['ports'] = ports
    if methods:
        merged['meta']['methods'] = methods
    if matcher_names:
        merged['meta']['matcher_names'] = matcher_names
    if evidence_examples:
        merged['meta']['evidence_examples'] = evidence_examples
    if http_request_examples:
        merged['meta']['http_request_examples'] = http_request_examples
    if curl_command_examples:
        merged['meta']['curl_command_examples'] = curl_command_examples
    if lineage_ids:
        merged['meta']['merged_lineage_ids'] = lineage_ids

    return merged

def deduplicate_scan_results(results: Dict[str, Any], use_host_only: bool = False) -> Dict[str, Any]:
    """
    Deduplicate scan results using layered fingerprinting.

    Args:
        results: Scan results dict with all_findings
        use_host_only: Enable host-only matching (default: False, safer)

    Returns:
        Results with deduplicated findings
    """
    if 'all_findings' not in results:
        return results

    results['all_findings'], suppressed_adapter_count = _suppress_adapter_transport_artifacts(results['all_findings'])
    orig_count = len(results['all_findings'])
    results['all_findings'] = merge_vulnerabilities(results['all_findings'], use_host_only=use_host_only)
    dedup_count = len(results['all_findings'])

    if 'summary' not in results:
        results['summary'] = {}

    results['summary'].update({
        'original_findings_count': orig_count,
        'deduplicated_findings_count': dedup_count,
        'duplicates_merged': orig_count - dedup_count
    })
    if suppressed_adapter_count:
        results['summary']['suppressed_adapter_findings_count'] = (
            int(results['summary'].get('suppressed_adapter_findings_count') or 0)
            + suppressed_adapter_count
        )
    refresh_summary_counts(results)

    return results
