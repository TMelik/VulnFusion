"""
HTML Report Generator

Generates modern, interactive HTML reports with light/dark mode, advanced filtering, and animations.
"""

from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.cve_utils import extract_exact_cve_ids
from utils.export_sanitizer import sanitize_results_for_export
from utils.schema import PRIORITY_LEVELS, SEVERITY_LEVELS

_SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_LEVELS)}
_PRIORITY_RANK = {priority: index for index, priority in enumerate(PRIORITY_LEVELS)}
_CORRELATION_GRAPH_LIMIT = 10

def _get_severity_color(severity: str, theme: str = 'dark') -> str:
    """Get CSS color for severity badge."""
    colors = {
        'critical': '#dc2626',
        'high': '#ea580c',
        'medium': '#ca8a04',
        'low': '#2563eb',
        'info': '#6b7280',
    }
    return colors.get(severity, '#6b7280')


def _unique_nonempty_strings(values: List[Any]) -> List[str]:
    """Return unique non-empty strings while preserving first-seen order."""
    deduped: List[str] = []
    for value in values:
        if not isinstance(value, str):
            continue
        stripped = value.strip()
        if stripped and stripped not in deduped:
            deduped.append(stripped)
    return deduped


def _collect_finding_scanners(finding: Dict[str, Any]) -> List[str]:
    """Collect scanner provenance for a finding using report-friendly fallbacks."""
    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    found_by = finding.get('found_by')
    if isinstance(found_by, list):
        scanners = _unique_nonempty_strings(found_by)
        if scanners:
            return scanners

    meta_scanners = meta.get('scanners')
    if isinstance(meta_scanners, list):
        scanners = _unique_nonempty_strings(meta_scanners)
        if scanners:
            return scanners

    scanners = _unique_nonempty_strings([meta.get('scanner')])
    if scanners:
        return scanners

    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        scanners = _unique_nonempty_strings(
            [source.get('scanner') for source in source_findings if isinstance(source, dict)]
        )
        if scanners:
            return scanners

    return []


def _normalize_report_severity(value: Any) -> str:
    """Normalize a report severity to a known value with a safe fallback."""
    severity = str(value or 'info').strip().lower()
    return severity if severity in _SEVERITY_RANK else 'info'


def _extract_cve_ids(finding: Dict[str, Any]) -> List[str]:
    """Extract CVE identifiers from the report finding using strict exact matches."""
    return extract_exact_cve_ids(finding)


def _group_findings_by_cve(
    findings: List[Dict[str, Any]]
) -> tuple[Dict[str, List[Dict[str, Any]]], List[Dict[str, Any]]]:
    """Bucket findings by CVE while keeping findings with no CVE in a separate list."""
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    without_cve: List[Dict[str, Any]] = []

    for finding in findings:
        cve_ids = _extract_cve_ids(finding)
        if not cve_ids:
            without_cve.append(finding)
            continue
        for cve_id in cve_ids:
            grouped.setdefault(cve_id, []).append(finding)

    return grouped, without_cve


def _finding_sort_key(finding: Dict[str, Any]) -> tuple[int, str]:
    """Sort findings by priority/risk first, then severity and name."""
    priority = str(finding.get('priority') or '').strip().upper()
    priority_rank = _PRIORITY_RANK.get(priority, len(PRIORITY_LEVELS))
    risk_score = finding.get('risk_score')
    risk_score_sort = -(risk_score if isinstance(risk_score, int) and not isinstance(risk_score, bool) else -1)
    severity = _normalize_report_severity(finding.get('severity'))
    vuln_name = str(finding.get('vulnerability_name') or 'Unknown').strip().lower()
    return (
        priority_rank,
        risk_score_sort,
        _SEVERITY_RANK.get(severity, len(SEVERITY_LEVELS)),
        vuln_name,
    )


def _finding_asset_label(finding: Dict[str, Any]) -> str:
    """Return a stable asset label for report rendering."""
    return str(finding.get('asset_id') or 'Unknown asset').strip() or 'Unknown asset'


def _finding_description_snippet(value: Any, max_length: int = 160) -> str:
    """Return a compact single-line description snippet for grouped views."""
    text = ' '.join(str(value or '').split())
    if not text:
        return 'No description provided.'
    if len(text) <= max_length:
        return text
    return text[: max_length - 3].rstrip() + '...'


def _finding_primary_report_description(finding: Dict[str, Any]) -> str:
    """Return the scanner-native description text preferred for report snippets."""
    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        for source in source_findings:
            if not isinstance(source, dict):
                continue
            description = str(source.get('description') or '').strip()
            if description:
                return description
    return str(finding.get('description') or '')


def _highest_group_severity(findings: List[Dict[str, Any]]) -> str:
    """Return the most severe severity present in a finding group."""
    if not findings:
        return 'info'
    return min(
        (_normalize_report_severity(finding.get('severity')) for finding in findings),
        key=lambda severity: _SEVERITY_RANK.get(severity, len(SEVERITY_LEVELS)),
    )


def _render_chip_list(values: List[str]) -> str:
    """Render simple metadata chips with HTML escaping."""
    return ''.join(f'<span class="meta-chip">{escape(value)}</span>' for value in values)


def _priority_badge_color(priority: str) -> str:
    """Return a stable color for priority badges/cards."""
    colors = {
        'P0': '#b91c1c',
        'P1': '#dc2626',
        'P2': '#ea580c',
        'P3': '#2563eb',
        'P4': '#6b7280',
    }
    return colors.get(priority, '#6b7280')


def _priority_business_label(priority: str) -> str:
    """Return concise copy for priority distribution cards."""
    labels = {
        'P0': 'Immediate business priority',
        'P1': 'Critical business priority',
        'P2': 'High business priority',
        'P3': 'Standard business priority',
        'P4': 'Low business priority',
    }
    return labels.get(priority, 'Business priority')


def _pluralize_findings(count: int) -> str:
    """Return a compact finding count label."""
    return 'finding' if count == 1 else 'findings'


def _change_field_label(field: str) -> str:
    """Return a report-friendly label for one structured changed field."""
    labels = {
        'cve_ids': 'CVE IDs',
        'cwe_ids': 'CWE IDs',
        'endpoint_scope': 'Endpoint Scope',
        'source_scanners': 'Source Scanners',
        'remediation_available': 'Remediation Available',
    }
    return labels.get(field, field.replace('_', ' ').title())


def _render_cve_finding_items(findings: List[Dict[str, Any]]) -> str:
    """Render compact finding rows for the CVE-grouped section."""
    items = ""
    for finding in findings:
        severity = _normalize_report_severity(finding.get('severity'))
        severity_color = _get_severity_color(severity)
        vuln_name = escape(str(finding.get('vulnerability_name') or 'Unknown vulnerability'))
        asset_id = escape(_finding_asset_label(finding))
        description = str(_finding_primary_report_description(finding) or '').strip()
        snippet = escape(description if description else 'No description provided.')
        items += f"""
        <div class="cve-finding-item">
            <div class="cve-finding-item-header">
                <div class="cve-finding-title">{vuln_name}</div>
                <span class="badge severity-badge" style="background: {severity_color};">{escape(severity.upper())}</span>
            </div>
            <div class="cve-finding-asset"><code>{asset_id}</code></div>
            <div class="cve-finding-snippet">{snippet}</div>
        </div>
        """
    return items


def _collect_source_context(source: Dict[str, Any]) -> List[tuple[str, str]]:
    """Build compact context rows for a preserved source finding."""
    meta = source.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    context: List[tuple[str, str]] = []
    for label, key in (
        ('Path', 'path'),
        ('Parameter', 'parameter'),
        ('Method', 'method'),
        ('Port', 'port'),
        ('Raw ID', 'raw_id'),
        ('Matcher', 'matcher_name'),
    ):
        value = meta.get(key)
        if value is not None and str(value).strip():
            context.append((label, str(value)))

    extracted_results = meta.get('extracted_results')
    if isinstance(extracted_results, list):
        extracted_preview = _unique_nonempty_strings([str(item) for item in extracted_results])
        if extracted_preview:
            preview = ', '.join(extracted_preview[:3])
            if len(extracted_preview) > 3:
                preview += f" (+{len(extracted_preview) - 3} more)"
            context.append(('Extracted', preview))

    cve_ids = _unique_nonempty_strings(
        [meta.get('cve_id')] + (meta.get('cve_ids', []) if isinstance(meta.get('cve_ids'), list) else [])
    )
    if cve_ids:
        context.append(('CVEs', ', '.join(cve_ids)))

    references = _unique_nonempty_strings(
        (source.get('references', []) if isinstance(source.get('references'), list) else [])
        + ([meta.get('reference')] if isinstance(meta.get('reference'), str) else [])
        + (meta.get('references', []) if isinstance(meta.get('references'), list) else [])
    )
    if references:
        ref_text = ', '.join(references[:2])
        if len(references) > 2:
            ref_text += f" (+{len(references) - 2} more)"
        context.append(('References', ref_text))

    return context


def _render_source_artifacts(source_meta: Dict[str, Any]) -> str:
    """Render preserved evidence/request artifacts for one source finding."""
    evidence = str(source_meta.get('evidence', '') or '').strip()
    http_request = str(source_meta.get('http_request', '') or '').strip()
    curl_command = str(source_meta.get('curl_command', '') or '').strip()

    parts = ""
    if evidence:
        parts += (
            f'<p class="source-snippet"><strong>Evidence:</strong> '
            f'{escape(evidence)}</p>'
        )
    if http_request:
        parts += (
            '<details class="source-artifact">'
            '<summary>Request Example</summary>'
            f'<pre>{escape(http_request)}</pre>'
            '</details>'
        )
    if curl_command:
        parts += (
            '<details class="source-artifact">'
            '<summary>Curl Replay</summary>'
            f'<pre>{escape(curl_command)}</pre>'
            '</details>'
        )
    return parts


def _render_source_evidence(finding: Dict[str, Any]) -> tuple[str, str]:
    """Render compact merged-evidence summary and inline source details."""
    source_findings = finding.get('source_findings')
    if not isinstance(source_findings, list) or not source_findings:
        return "", ""

    meta = finding.get('meta', {})
    if not isinstance(meta, dict):
        meta = {}

    scanners = _collect_finding_scanners(finding)
    source_count = len(source_findings)

    if len(scanners) > 1:
        summary_html = (
            f'<div class="merge-summary"><strong>Confirmed by:</strong> '
            f'{escape(", ".join(scanners))}'
            f'<span class="merge-summary-meta">{source_count} source records preserved</span></div>'
        )
    else:
        scanner_label = scanners[0] if scanners else 'scanner evidence'
        summary_html = (
            f'<div class="merge-summary"><strong>Merged evidence:</strong> '
            f'{escape(scanner_label)}'
            f'<span class="merge-summary-meta">{source_count} source records preserved</span></div>'
        )

    source_cards = ""
    for source in source_findings:
        if not isinstance(source, dict):
            continue

        source_meta = source.get('meta', {})
        if not isinstance(source_meta, dict):
            source_meta = {}

        source_scanner = escape(str(source.get('scanner') or source_meta.get('scanner') or 'unknown'))
        source_title = escape(str(source.get('vulnerability_name') or finding.get('vulnerability_name', 'Unknown')))
        source_severity = str(source.get('severity', 'info')).lower()
        source_asset = escape(str(source.get('asset_id') or finding.get('asset_id', 'Unknown')))
        severity_color = _get_severity_color(source_severity)
        degraded_source = bool(source.get('degraded_execution')) or bool(source_meta.get('degraded_execution'))

        context_items = _collect_source_context(source)
        context_html = ""
        if context_items:
            context_html = '<ul class="source-context">' + ''.join(
                f'<li><strong>{escape(label)}:</strong> {escape(value)}</li>'
                for label, value in context_items
            ) + '</ul>'

        description = str(source.get('description', '') or '').strip()
        remediation = str(source.get('remediation') or source.get('recommendation') or '').strip()
        impact = str(source.get('impact', '') or '').strip()
        artifact_html = _render_source_artifacts(source_meta)

        source_cards += f"""
        <div class="source-card">
            <div class="source-card-header">
                <div>
                    <div class="source-scanner">{source_scanner}</div>
                    <div class="source-title">{source_title}</div>
                </div>
                <div>
                    <span class="badge severity-badge" style="background: {severity_color};">{escape(source_severity.upper())}</span>
                    {f'<span class="badge transport-badge">DEGRADED</span>' if degraded_source else ''}
                </div>
            </div>
            <div class="source-asset"><code>{source_asset}</code></div>
            {f'<p class="source-snippet"><strong>Execution:</strong> This source came from a degraded scanner run and is treated as lower-confidence evidence.</p>' if degraded_source else ''}
            {context_html}
            {f'<p class="source-snippet"><strong>Description:</strong> {escape(description)}</p>' if description else ''}
            {f'<p class="source-snippet"><strong>Impact:</strong> {escape(impact)}</p>' if impact else ''}
            {f'<p class="source-snippet"><strong>Remediation:</strong> {escape(remediation)}</p>' if remediation else ''}
            {artifact_html}
        </div>
        """

    if not source_cards:
        return summary_html, ""

    details_html = f"""
    <div class="detail-section source-evidence">
        <div class="section-summary">Source Evidence</div>
        <div class="detail-content">
            <div class="source-grid">
                {source_cards}
            </div>
        </div>
    </div>
    """

    return summary_html, details_html


def _correlation_confidence_percent(value: Any) -> Optional[int]:
    """Return a 0-100 integer percent for a model-reported confidence, or None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not 0.0 <= float(value) <= 1.0:
        return None
    return round(float(value) * 100)


def _render_correlation(finding: Dict[str, Any]) -> str:
    """Render the public LLM correlation advisory for one finding.

    Consumes only the whitelisted `correlation` contract (see
    utils/export_sanitizer._sanitize_correlation). All model/scanner text is
    treated as untrusted and HTML-escaped; nothing is rendered raw. Returns an
    empty string when the finding carries no valid correlation object.
    """
    correlation = finding.get('correlation')
    if not isinstance(correlation, dict):
        return ""
    status = correlation.get('status')
    if status not in ('merged', 'needs_review'):
        return ""
    if correlation.get('source') != 'llm':
        return ""

    needs_review = bool(correlation.get('needs_review'))
    review_candidates = correlation.get('review_candidates')
    if not isinstance(review_candidates, list):
        review_candidates = []

    # State badge: merged vs needs-review. The canonical_title is only ever an
    # AI suggestion and never replaces the scanner-native vulnerability_name.
    if status == 'merged':
        state_badge = (
            '<span class="badge correlation-badge correlation-merged">'
            'Merged by AI correlation</span>'
        )
    else:
        state_badge = (
            '<span class="badge correlation-badge correlation-review">'
            'Needs review</span>'
        )

    percent = _correlation_confidence_percent(correlation.get('confidence'))
    confidence_badge = (
        f'<span class="badge correlation-confidence">Confidence {percent}%</span>'
        if percent is not None else ''
    )

    # Drive the review warning off needs_review/candidates, not status alone:
    # a merged cluster can still carry an uncertain external candidate.
    review_warning = ""
    if needs_review or review_candidates:
        review_warning = (
            '<div class="correlation-review-warning">'
            'Potential duplicate flagged for human review — the original '
            'finding is retained.</div>'
        )

    reason = escape(str(correlation.get('reason') or '').strip())
    canonical_title = escape(str(correlation.get('canonical_title') or '').strip())

    reason_html = (
        f'<div class="correlation-reason"><strong>Reason:</strong> {reason}</div>'
        if reason else ''
    )
    canonical_html = (
        '<div class="correlation-canonical">'
        '<strong>Suggested canonical title:</strong> '
        f'<span class="correlation-canonical-value">{canonical_title}</span> '
        '<span class="correlation-hint">(AI suggestion — not applied)</span>'
        '</div>'
        if canonical_title else ''
    )

    # Review candidates: render in the order received; never re-sort here.
    candidates_html = ""
    candidate_items = ""
    for candidate in review_candidates:
        if not isinstance(candidate, dict):
            continue
        cand_name = escape(str(candidate.get('vulnerability_name') or '').strip()) or 'Unknown'
        cand_reason = escape(str(candidate.get('reason') or '').strip())
        cand_canonical = escape(str(candidate.get('canonical_title') or '').strip())
        scanners = candidate.get('scanners')
        if isinstance(scanners, list):
            cand_scanners = escape(
                ', '.join(str(s) for s in scanners if isinstance(s, str) and s.strip())
            )
        else:
            cand_scanners = ''
        cand_percent = _correlation_confidence_percent(candidate.get('confidence'))
        cand_conf = (
            f'<span class="badge correlation-confidence">{cand_percent}%</span>'
            if cand_percent is not None else ''
        )
        provenance = (
            f'<div class="correlation-candidate-scanners">Found by: {cand_scanners}</div>'
            if cand_scanners else ''
        )
        reason_line = (
            f'<div class="correlation-candidate-reason">{cand_reason}</div>'
            if cand_reason else ''
        )
        canonical_line = (
            '<div class="correlation-candidate-canonical">'
            f'Suggested canonical title: {cand_canonical}</div>'
            if cand_canonical else ''
        )
        candidate_items += (
            '<li class="correlation-candidate">'
            '<div class="correlation-candidate-head">'
            f'{cand_conf}<span class="correlation-candidate-name">{cand_name}</span>'
            '</div>'
            f'{provenance}{reason_line}{canonical_line}'
            '</li>'
        )
    if candidate_items:
        candidates_html = (
            '<div class="correlation-candidates-label">Review candidates</div>'
            f'<ul class="correlation-candidates">{candidate_items}</ul>'
        )

    disclaimer = (
        '<div class="correlation-disclaimer">Confidence is model-reported, not a '
        'proven probability. AI correlation is advisory only.</div>'
    )
    details_body = f'{reason_html}{canonical_html}{candidates_html}{disclaimer}'

    return (
        '<div class="finding-correlation">'
        f'<div class="correlation-badges">{state_badge}{confidence_badge}</div>'
        f'{review_warning}'
        '<details class="correlation-details">'
        '<summary>AI correlation details</summary>'
        f'<div class="correlation-details-body">{details_body}</div>'
        '</details>'
        '</div>'
    )


def _correlation_graph_node_key(title: Any, scanners: Any) -> str:
    """Return a stable label used to suppress reciprocal review pairs."""
    normalized_title = ' '.join(str(title or 'Unknown').lower().split())
    scanner_values = scanners if isinstance(scanners, list) else []
    normalized_scanners = sorted(
        {
            str(scanner).strip().lower()
            for scanner in scanner_values
            if isinstance(scanner, str) and scanner.strip()
        }
    )
    return f"{normalized_title}|{','.join(normalized_scanners)}"


def _correlation_graph_sources(finding: Dict[str, Any]) -> List[Dict[str, str]]:
    """Return compact scanner-native source nodes for one graph row."""
    nodes: List[Dict[str, str]] = []
    source_findings = finding.get('source_findings')
    if isinstance(source_findings, list):
        for source in source_findings:
            if not isinstance(source, dict):
                continue
            source_meta = source.get('meta')
            if not isinstance(source_meta, dict):
                source_meta = {}
            scanner = str(source.get('scanner') or source_meta.get('scanner') or 'unknown').strip()
            title = str(
                source.get('vulnerability_name')
                or finding.get('vulnerability_name')
                or 'Unknown vulnerability'
            ).strip()
            asset = str(source.get('asset_id') or finding.get('asset_id') or '').strip()
            node = {'scanner': scanner or 'unknown', 'title': title, 'asset': asset}
            if node not in nodes:
                nodes.append(node)

    if nodes:
        return nodes[:5]

    title = str(finding.get('vulnerability_name') or 'Unknown vulnerability').strip()
    asset = _finding_asset_label(finding)
    scanners = _collect_finding_scanners(finding) or ['unknown']
    return [
        {'scanner': scanner, 'title': title, 'asset': asset}
        for scanner in scanners[:5]
    ]


def _render_correlation_graph_source_node(node: Dict[str, str], *, review: bool = False) -> str:
    """Render one escaped source/candidate node."""
    scanner = escape(str(node.get('scanner') or 'unknown'))
    title = escape(str(node.get('title') or 'Unknown vulnerability'))
    asset = escape(str(node.get('asset') or ''))
    review_class = ' graph-node-review' if review else ''
    asset_html = f'<code class="graph-node-asset">{asset}</code>' if asset else ''
    return (
        f'<div class="correlation-graph-node graph-source-node{review_class}">'
        f'<span class="graph-node-scanner">{scanner}</span>'
        f'<strong class="graph-node-title">{title}</strong>'
        f'{asset_html}'
        '</div>'
    )


def _render_correlation_graph(findings: List[Dict[str, Any]], *, limit: int = _CORRELATION_GRAPH_LIMIT) -> str:
    """Render a bounded source-findings → LLM-decision graph.

    The graph consumes only the export-safe structured correlation contract.
    Reciprocal low-confidence pairs are collapsed using scanner/title labels so
    the same review relationship is not presented twice.
    """
    entries: List[Dict[str, Any]] = []
    seen_review_pairs: set[tuple[str, ...]] = set()

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        correlation = finding.get('correlation')
        if not isinstance(correlation, dict) or correlation.get('source') != 'llm':
            continue
        status = correlation.get('status')
        if status not in {'merged', 'needs_review'}:
            continue

        candidates = correlation.get('review_candidates')
        if not isinstance(candidates, list):
            candidates = []

        if status == 'needs_review':
            current_key = _correlation_graph_node_key(
                finding.get('vulnerability_name'),
                _collect_finding_scanners(finding),
            )
            candidate_keys = [
                _correlation_graph_node_key(candidate.get('vulnerability_name'), candidate.get('scanners'))
                for candidate in candidates
                if isinstance(candidate, dict)
            ]
            pair_signature = tuple(sorted({current_key, *candidate_keys}))
            if pair_signature in seen_review_pairs:
                continue
            seen_review_pairs.add(pair_signature)

        entries.append(
            {
                'finding': finding,
                'correlation': correlation,
                'status': status,
                'candidates': candidates,
            }
        )

    if not entries:
        return ''

    entries.sort(
        key=lambda entry: (
            0 if entry['status'] == 'merged' else 1,
            str(entry['finding'].get('vulnerability_name') or '').lower(),
            _finding_asset_label(entry['finding']).lower(),
            ','.join(_collect_finding_scanners(entry['finding'])),
        )
    )
    total_entries = len(entries)
    visible_entries = entries[:max(1, limit)]
    graph_rows = ''

    for entry in visible_entries:
        finding = entry['finding']
        correlation = entry['correlation']
        status = entry['status']
        candidates = entry['candidates']
        source_nodes = _correlation_graph_sources(finding)
        source_html = ''.join(
            _render_correlation_graph_source_node(node)
            for node in source_nodes
        )

        if status == 'needs_review':
            for candidate in candidates[:4]:
                if not isinstance(candidate, dict):
                    continue
                scanners = candidate.get('scanners')
                scanner_label = ', '.join(
                    str(scanner).strip()
                    for scanner in scanners
                    if isinstance(scanner, str) and scanner.strip()
                ) if isinstance(scanners, list) else 'unknown'
                source_html += _render_correlation_graph_source_node(
                    {
                        'scanner': scanner_label or 'unknown',
                        'title': str(candidate.get('vulnerability_name') or 'Unknown vulnerability'),
                        'asset': '',
                    },
                    review=True,
                )

        confidence = _correlation_confidence_percent(correlation.get('confidence'))
        confidence_html = (
            f'<span class="graph-result-confidence">{confidence}% model confidence</span>'
            if confidence is not None else ''
        )
        reason = escape(str(correlation.get('reason') or '').strip())
        result_title = escape(str(finding.get('vulnerability_name') or 'Unknown vulnerability'))
        if status == 'merged':
            connector_label = 'LLM merge'
            result_badge = 'Merged'
            result_subtitle = result_title
            row_class = 'graph-row-merged'
        else:
            connector_label = 'review'
            result_badge = 'Needs review'
            result_subtitle = 'Findings retained separately'
            row_class = 'graph-row-review'

        review_note = ''
        if status == 'merged' and (correlation.get('needs_review') or candidates):
            review_note = '<span class="graph-external-review">External candidate still needs review</span>'
        reason_html = f'<span class="graph-result-reason">{reason}</span>' if reason else ''

        graph_rows += (
            f'<article class="correlation-graph-row {row_class}">'
            f'<div class="correlation-graph-sources">{source_html}</div>'
            '<div class="correlation-graph-connector" aria-hidden="true">'
            f'<span>{escape(connector_label)}</span><div class="graph-connector-line"></div><b>→</b>'
            '</div>'
            '<div class="correlation-graph-node graph-result-node">'
            f'<span class="graph-result-badge">{result_badge}</span>'
            f'<strong class="graph-node-title">{result_subtitle}</strong>'
            f'{confidence_html}{review_note}'
            f'{reason_html}'
            '</div>'
            '</article>'
        )

    limit_note = ''
    if total_entries > len(visible_entries):
        limit_note = (
            '<p class="section-description correlation-graph-limit">'
            f'Showing {len(visible_entries)} of {total_entries} correlation cases. '
            'All details remain available in the finding cards.</p>'
        )

    return (
        '<section class="section correlation-graph-section">'
        '<div class="section-header">'
        '<h2 class="section-title">AI Correlation Graph</h2>'
        f'<span class="section-count">{total_entries}</span>'
        '</div>'
        '<p class="section-description">Scanner findings on the left remain traceable to '
        'the merged result or human-review decision on the right.</p>'
        f'<div class="correlation-graph">{graph_rows}</div>'
        f'{limit_note}'
        '</section>'
    )


def _collect_degraded_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return scanner names whose preserved evidence was degraded."""
    degraded: List[str] = []
    source_findings = finding.get('source_findings')
    if not isinstance(source_findings, list):
        return degraded

    for source in source_findings:
        if not isinstance(source, dict):
            continue
        source_meta = source.get('meta', {})
        if not isinstance(source_meta, dict):
            source_meta = {}
        if source.get('degraded_execution') is not True and source_meta.get('degraded_execution') is not True:
            continue
        scanner = str(source.get('scanner') or source_meta.get('scanner') or '').strip()
        if scanner and scanner not in degraded:
            degraded.append(scanner)

    return degraded


def _transport_status_label(execution: Dict[str, Any]) -> str:
    """Return the compact user-facing transport execution status label."""
    if str(execution.get('adapter_status') or '').strip().lower() == 'startup_failed':
        return 'Startup Failed'
    if execution.get('skip_reason'):
        return 'Skipped'
    if bool(execution.get('degraded_execution')):
        return 'Degraded'
    if execution.get('scanner_error'):
        return 'Failed'
    return 'Completed'


def _compact_transport_diagnostics(value: Any, max_lines: int = 6, max_chars: int = 700) -> str:
    """Trim transport diagnostics to one compact report-friendly block."""
    text = str(value or '').strip()
    if not text:
        return ''
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ['...']
    compact = '\n'.join(lines)
    if len(compact) > max_chars:
        compact = compact[: max_chars - 3].rstrip() + '...'
    return compact


def _render_transport_detail_grid(execution: Dict[str, Any]) -> str:
    """Render structured transport metadata without overwhelming the report."""
    items: List[tuple[str, str]] = []
    adapter_runtime = str(execution.get('adapter_runtime') or '').strip()
    if adapter_runtime:
        items.append(('Runtime', adapter_runtime))
    adapter_upstream_url = str(execution.get('adapter_upstream_url') or '').strip()
    if adapter_upstream_url:
        items.append(('Reverse Upstream', adapter_upstream_url))
    adapter_translation_chain = str(execution.get('adapter_translation_chain') or '').strip()
    if adapter_translation_chain:
        items.append(('Path', adapter_translation_chain))
    adapter_status = str(execution.get('adapter_status') or '').strip()
    if adapter_status:
        items.append(('Adapter Status', adapter_status))
    adapter_runtime_state = str(execution.get('adapter_runtime_state') or '').strip()
    if adapter_runtime_state:
        items.append(('Runtime State', adapter_runtime_state))
    transport_confidence = str(execution.get('transport_confidence') or '').strip()
    if transport_confidence:
        items.append(('Confidence', transport_confidence))

    if not items:
        return ''

    body = ''.join(
        '<div class="transport-detail-item">'
        f'<span class="transport-detail-label">{escape(label)}</span>'
        f'<span class="transport-detail-value">{escape(value)}</span>'
        '</div>'
        for label, value in items
    )
    return f'<div class="transport-detail-grid">{body}</div>'

def generate_modern_html_report(results: Dict[str, Any]) -> str:
    """Generate modern interactive HTML report with light/dark mode, filters, and animations."""
    results = sanitize_results_for_export(results)
    target = escape(str(results.get('target', 'Unknown')))
    timestamp = results.get('timestamp', datetime.now().isoformat())
    raw_findings = results.get('all_findings', [])
    findings = raw_findings if isinstance(raw_findings, list) else []
    summary = results.get('summary', {})
    correlation_graph_section = _render_correlation_graph(findings)
    asset_knowledge = results.get('asset_knowledge', {})
    site_context_section = ""
    if isinstance(asset_knowledge, dict) and str(asset_knowledge.get('description') or '').strip():
        context_description = escape(str(asset_knowledge['description']).strip())
        context_reviewer = escape(str(asset_knowledge.get('reviewer') or 'human-reviewed'))
        context_revision = escape(str(asset_knowledge.get('profile_revision') or '')[:12])
        site_context_section = f"""
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Confirmed Site Context</h2>
            </div>
            <p class="section-description">{context_description}</p>
            <div class="risk-metrics">
                <div><strong>Source:</strong> Per-site Google OKF profile</div>
                <div><strong>Reviewed by:</strong> {context_reviewer}</div>
                {f'<div><strong>Revision:</strong> {context_revision}</div>' if context_revision else ''}
            </div>
        </section>
        """

    comparison = results.get('comparison', {})
    comparison_summary = comparison.get('summary', {})
    changed_findings = results.get('changed_findings', [])
    has_comparison = bool(comparison_summary) and comparison.get('compatible_baseline_used', True) is not False
    comparison_detail = ""
    comparison_mode = str(comparison.get('comparison_mode') or 'skipped').lower()
    if comparison and comparison.get('compatibility_reason') and (comparison_mode == 'partial' or not has_comparison):
        current_scanners = comparison.get('current_scanners_run', [])
        previous_scanners = comparison.get('previous_scanners_run', [])
        overlapping_scanners = comparison.get('overlapping_scanners', [])
        missing_from_current = comparison.get('missing_from_current', [])
        missing_from_previous = comparison.get('missing_from_previous', [])
        limitations = comparison.get('partial_comparison_limitations', [])
        partial_unmatched_current = comparison_summary.get('partial_unmatched_current', 0)
        partial_unmatched_previous = comparison_summary.get('partial_unmatched_previous', 0)
        detail_title = 'Partial comparison details' if comparison_mode == 'partial' else 'Comparison unavailable'
        limitations_html = ''.join(
            f'<li>{escape(str(item))}</li>'
            for item in limitations
            if str(item).strip()
        )
        compatibility_reason = str(comparison.get('compatibility_reason', 'Comparison was skipped.'))
        no_previous_report = (
            not comparison.get('old_scan')
            and not previous_scanners
            and 'no previous' in compatibility_reason.lower()
        )
        comparison_message = (
            'No previous report was provided for comparison.'
            if no_previous_report
            else escape(compatibility_reason)
        )
        comparison_detail = f"""
        <div class="comparison-detail">
            <div class="comparison-detail-title">{detail_title}</div>
            <p class="section-description">{comparison_message}</p>
            {f'<ul class="comparison-limitations">{limitations_html}</ul>' if limitations_html else ''}
            <div class="risk-metrics">
                {f'<div><strong>Current scanners:</strong> {escape(", ".join(current_scanners))}</div>' if current_scanners else ''}
                {f'<div><strong>Previous scanners:</strong> {escape(", ".join(previous_scanners))}</div>' if previous_scanners else ''}
                {f'<div><strong>Overlap:</strong> {escape(", ".join(overlapping_scanners))}</div>' if overlapping_scanners else ''}
                {f'<div><strong>Missing from current:</strong> {escape(", ".join(missing_from_current))}</div>' if missing_from_current else ''}
                {f'<div><strong>Missing from previous:</strong> {escape(", ".join(missing_from_previous))}</div>' if missing_from_previous else ''}
                {f'<div><strong>Unclassified current findings:</strong> {partial_unmatched_current}</div>' if comparison_mode == 'partial' else ''}
                {f'<div><strong>Unclassified previous findings:</strong> {partial_unmatched_previous}</div>' if comparison_mode == 'partial' else ''}
            </div>
        </div>
        """

    by_priority = summary.get('by_priority', {})
    scanner_execution = results.get('scanner_execution', {})

    severity_counts = {severity: 0 for severity in SEVERITY_LEVELS}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity_counts[_normalize_report_severity(finding.get('severity'))] += 1

    summary_cards = f"""
        <div class="summary-metric fade-in" style="--accent-color: #3b82f6;">
            <div class="summary-metric-label">Total findings</div>
            <div class="summary-metric-value">{len(findings)}</div>
        </div>
    """
    for severity in SEVERITY_LEVELS:
        color = _get_severity_color(severity)
        summary_cards += f"""
        <div class="summary-metric fade-in" style="--accent-color: {color};">
            <div class="summary-metric-label">{escape(severity.title())}</div>
            <div class="summary-metric-value">{severity_counts.get(severity, 0)}</div>
        </div>
        """

    priority_cards = ""
    finding_has_priority = any(
        isinstance(finding, dict)
        and str(finding.get('priority') or '').strip().upper() in _PRIORITY_RANK
        for finding in findings
    )
    show_priority_section = isinstance(by_priority, dict) and (
        any(priority in by_priority for priority in PRIORITY_LEVELS)
        or finding_has_priority
    )
    for priority in PRIORITY_LEVELS:
        raw_count = by_priority.get(priority, 0) if isinstance(by_priority, dict) else 0
        count = raw_count if isinstance(raw_count, int) and not isinstance(raw_count, bool) else 0
        color = _priority_badge_color(priority)
        priority_cards += f"""
        <div class="priority-card fade-in" style="--accent-color: {color};">
            <span class="priority-token">{escape(priority)}</span>
            <div class="priority-count">{count} {_pluralize_findings(count)}</div>
            <div class="priority-description">{escape(_priority_business_label(priority))}</div>
        </div>
        """

    comparison_cards = ""
    if has_comparison:
        comparison_stats = [
            ('fixed', 'Fixed', '#22c55e'),
            ('new', 'New', '#ef4444'),
            ('changed', 'Changed', '#f97316'),
            ('persistent', 'Persistent', '#eab308'),
        ]
        for key, label, color in comparison_stats:
            count = comparison_summary.get(key, 0)
            comparison_cards += f"""
            <div class="comparison-card fade-in" style="--accent-color: {color};">
                <div class="comparison-value">{count}</div>
                <div class="comparison-label">{label}</div>
            </div>
            """

    transport_section = ""
    if scanner_execution:
        transport_rows = ""
        for scanner_name, execution in scanner_execution.items():
            if not isinstance(execution, dict):
                continue
            route = execution.get('scan_route', 'direct')
            adapter_mode = execution.get('adapter_mode', route)
            route_label = route.replace('_', ' ').title()
            adapter_label = adapter_mode.replace('_', ' ').title()
            transport = execution.get('transport_detected', 'unknown').replace('_', ' ').upper()
            notes = escape(execution.get('scanner_transport_notes', '') or '')
            skip_reason = execution.get('skip_reason')
            scanner_error = execution.get('scanner_error')
            adapter_failure_reason = execution.get('adapter_failure_reason')
            degraded_execution = bool(execution.get('degraded_execution'))
            partial_results = bool(execution.get('partial_results'))
            status_label = _transport_status_label(execution)
            skip_html = f'<div class="transport-skip">{escape(skip_reason)}</div>' if skip_reason else ''
            error_html = f'<div class="transport-skip">{escape(scanner_error)}</div>' if scanner_error and not skip_reason else ''
            failure_html = ''
            if adapter_failure_reason and adapter_failure_reason not in {skip_reason, scanner_error}:
                failure_html = (
                    '<div class="transport-skip transport-failure">'
                    f'<strong>Transport issue:</strong> {escape(str(adapter_failure_reason))}'
                    '</div>'
                )
            partial_html = (
                '<div class="transport-notes">Partial results were preserved from a degraded execution.</div>'
                if partial_results else ''
            )
            detail_grid_html = _render_transport_detail_grid(execution)
            diagnostics = _compact_transport_diagnostics(execution.get('adapter_diagnostics'))
            diagnostics_html = (
                '<details class="transport-diagnostics">'
                '<summary>Diagnostics</summary>'
                f'<pre class="transport-diagnostics-body">{escape(diagnostics)}</pre>'
                '</details>'
            ) if diagnostics else ''

            transport_rows += f"""
            <div class="transport-card fade-in">
                <div class="transport-card-header">
                    <div>
                        <div class="transport-scanner">{escape(scanner_name)}</div>
                        <div class="transport-meta">{escape(execution.get('scanner_type', 'generic')).title()} scanner</div>
                    </div>
                    <div class="transport-badges">
                        <span class="badge transport-badge">{status_label}</span>
                        <span class="badge transport-badge">{route_label}</span>
                        <span class="badge transport-badge">{adapter_label}</span>
                        <span class="badge transport-state">{transport}</span>
                    </div>
                </div>
                {f'<p class="transport-notes">{notes}</p>' if notes else ''}
                {detail_grid_html}
                {skip_html}
                {error_html}
                {failure_html}
                {partial_html}
                {diagnostics_html}
            </div>
            """

        if transport_rows:
            transport_section = f"""
            <section class="section">
                <div class="section-header">
                    <h2 class="section-title">Scanner Transport</h2>
                    <span class="section-count">{len(scanner_execution)}</span>
                </div>
                <p class="section-description">
                    Shows whether each scanner ran directly, through a compatibility adapter, or in a degraded/skipped state.
                </p>
                <div class="transport-grid">
                    {transport_rows}
                </div>
            </section>
            """

    sorted_findings = sorted(findings, key=_finding_sort_key)

    finding_cards = ""
    for idx, finding in enumerate(sorted_findings):
        vuln_name = escape(finding.get('vulnerability_name', 'Unknown'))
        severity = finding.get('severity', 'info')
        asset = escape(finding.get('asset_id', 'Unknown'))
        description = escape(str(finding.get('description') or ''))
        impact = escape(str(finding.get('impact') or ''))
        remediation = escape(str(finding.get('remediation') or finding.get('recommendation') or ''))
        priority = str(finding.get('priority') or '').strip().upper()
        risk_score = finding.get('risk_score')
        risk_rationale = escape(str(finding.get('risk_rationale') or '').strip())
        status = finding.get('status', '')
        changed_fields = finding.get('changed_fields', [])
        meta = finding.get('meta', {})
        if not isinstance(meta, dict):
            meta = {}
        scanner_name = meta.get('scanner_instance') or meta.get('scanner', '')
        execution = scanner_execution.get(scanner_name, {})
        if not execution and meta.get('scanner'):
            execution = scanner_execution.get(meta.get('scanner', ''), {})
        degraded_scanners = _collect_degraded_scanners(finding)
        degraded_note = ""
        if degraded_scanners:
            degraded_note = (
                "<div class=\"finding-transport\">Evidence quality: "
                f"<strong>degraded scanner evidence included</strong> ({escape(', '.join(str(s) for s in degraded_scanners))}). "
                "Treat cross-scanner confirmation conservatively.</div>"
            )
        elif meta.get('degraded_execution') is True or execution.get('degraded_execution'):
            degraded_note = (
                "<div class=\"finding-transport\">Evidence quality: "
                "<strong>degraded scanner execution</strong>. Treat this finding as lower-confidence evidence.</div>"
            )

        severity_color = _get_severity_color(severity)

        merge_summary_html, source_evidence_html = _render_source_evidence(finding)
        render_scanner_native_top_level = not bool(source_evidence_html)
        correlation_html = _render_correlation(finding)
        finding_scanners = _collect_finding_scanners(finding)
        scanner_provenance = ", ".join(finding_scanners) if finding_scanners else "unknown"

        status_colors = {
            'NEW': '#ef4444',
            'CHANGED': '#f97316',
            'PERSISTENT': '#eab308',
            'FIXED': '#22c55e'
        }
        status_color = status_colors.get(status, '#6b7280')
        status_badge = (
            f'<span class="badge status-badge" style="background: {status_color};">{status}</span>'
            if status else ''
        )
        priority_badge = (
            f'<span class="badge priority-badge" style="background: {_priority_badge_color(priority)};">{escape(priority)}</span>'
            if priority in _PRIORITY_RANK else ''
        )
        risk_score_badge = (
            f'<span class="badge risk-score-badge">Risk {risk_score}/100</span>'
            if isinstance(risk_score, int) and not isinstance(risk_score, bool) else ''
        )
        priority_summary = ""
        if priority_badge or risk_score_badge:
            priority_summary = (
                '<div class="finding-risk-summary">'
                f'{priority_badge}{risk_score_badge}'
                '</div>'
            )
        rationale_html = (
            '<div class="finding-rationale"><strong>Why this is prioritized:</strong>'
            f'<p>{risk_rationale}</p></div>'
            if risk_rationale else ''
        )
        changed_fields_html = ""
        if isinstance(changed_fields, list) and changed_fields:
            changes_html = ""
            for field in changed_fields:
                changes_html += f"""
                <div class="change-item">
                    <div class="change-label">{_change_field_label(str(field))}</div>
                    <div class="change-comparison">
                        <span class="change-after">Changed in scanner output</span>
                    </div>
                </div>
                """
            changed_fields_html = f"""
            <div class="changes-section">
                <div class="changes-header">Changes Detected</div>
                {changes_html}
            </div>
            """
        finding_cards += f"""
        <div class="finding-card fade-in"
             data-severity="{severity}"
             data-priority="{escape(priority.lower()) if priority else ''}"
             data-status="{status}"
             style="--delay: {idx * 0.05}s; animation-delay: {idx * 0.05}s;">
            <div class="finding-header">
                <div class="finding-title-wrapper">
                    <div class="severity-indicator" style="background: {severity_color};"></div>
                    <h3 class="finding-title">{vuln_name}</h3>
                </div>
                <div class="finding-badges">
                    {status_badge}
                    {priority_badge}
                    {risk_score_badge}
                    <span class="badge severity-badge" style="background: {severity_color};">{severity.upper()}</span>
                </div>
            </div>
            <div class="finding-body">
                <div class="finding-asset">
                    <svg class="icon" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                    </svg>
                    <code>{asset}</code>
                </div>
                <div class="finding-provenance">Found by: {escape(scanner_provenance)}</div>
                {f'<div class="finding-transport">Route: <strong>{escape(execution.get("scan_route", "direct")).title()}</strong> | Adapter: <strong>{escape(execution.get("adapter_mode", execution.get("scan_route", "direct"))).title()}</strong> | Transport: <strong>{escape(execution.get("transport_detected", "unknown")).replace("_", " ").upper()}</strong></div>' if execution else ''}
                {degraded_note}
                {priority_summary}
                {rationale_html}
                {changed_fields_html}
                {f'<div class="finding-description"><strong>Description:</strong><p>{description}</p></div>' if render_scanner_native_top_level and description else ''}
                {f'<div class="finding-impact"><strong>Impact:</strong><p>{impact}</p></div>' if render_scanner_native_top_level and impact else ''}
                {f'<div class="finding-remediation"><strong>Remediation:</strong><p>{remediation}</p></div>' if render_scanner_native_top_level and remediation else ''}
                {correlation_html}
                {merge_summary_html}
                {source_evidence_html}
            </div>
        </div>
        """

    changed_section = ""
    if changed_findings:
        changed_cards = ""
        for idx, finding in enumerate(changed_findings):
            vuln_name = escape(finding.get('vulnerability_name', 'Unknown'))
            severity = finding.get('severity', 'info')
            asset = escape(finding.get('asset_id', 'Unknown'))
            changed_fields = finding.get('changed_fields', [])
            finding_scanners = _collect_finding_scanners(finding)
            scanner_provenance = ", ".join(finding_scanners) if finding_scanners else "unknown"
            correlation_html = _render_correlation(finding)

            severity_color = _get_severity_color(severity)
            changed_color = "#f97316"

            changes_html = ""
            for field in changed_fields:
                changes_html += f"""
                <div class="change-item">
                    <div class="change-label">{_change_field_label(field)}</div>
                    <div class="change-comparison">
                        <span class="change-after">Changed in scanner output</span>
                    </div>
                </div>
                """

            changed_cards += f"""
            <div class="finding-card changed-card fade-in" style="--delay: {idx * 0.05}s; animation-delay: {idx * 0.05}s;">
                <div class="finding-header">
                    <div class="finding-title-wrapper">
                        <div class="severity-indicator" style="background: {changed_color};"></div>
                        <h3 class="finding-title">{vuln_name}</h3>
                    </div>
                    <div class="finding-badges">
                        <span class="badge status-badge" style="background: {changed_color};">CHANGED</span>
                        <span class="badge severity-badge" style="background: {severity_color};">{severity.upper()}</span>
                    </div>
                </div>
                <div class="finding-body">
                    <div class="finding-asset">
                        <svg class="icon" viewBox="0 0 20 20" fill="currentColor">
                            <path fill-rule="evenodd" d="M5 9V7a5 5 0 0110 0v2a2 2 0 012 2v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5a2 2 0 012-2zm8-2v2H7V7a3 3 0 016 0z" clip-rule="evenodd" />
                        </svg>
                        <code>{asset}</code>
                    </div>
                    <div class="finding-provenance">Found by: {escape(scanner_provenance)}</div>
                    {correlation_html}
                    <div class="changes-section">
                        <div class="changes-header">⚠️ Changes Detected</div>
                        {changes_html}
                    </div>
                </div>
            </div>
            """

        changed_section = f"""
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">⚠️ Changed Vulnerabilities</h2>
                <span class="section-count">{len(changed_findings)}</span>
            </div>
            <p class="section-description">
                These vulnerabilities exist in both scans but have been modified
            </p>
            <div class="findings-grid">
                {changed_cards}
            </div>
        </section>
        """

    findings_by_cve, no_cve_findings = _group_findings_by_cve(findings)
    sorted_cve_groups = sorted(
        findings_by_cve.items(),
        key=lambda item: (
            _SEVERITY_RANK.get(_highest_group_severity(item[1]), len(SEVERITY_LEVELS)),
            item[0],
        ),
    )

    cve_group_cards = ""
    for cve_id, group_findings in sorted_cve_groups:
        sorted_group_findings = sorted(group_findings, key=_finding_sort_key)
        highest_severity = _highest_group_severity(sorted_group_findings)
        highest_severity_color = _get_severity_color(highest_severity)
        affected_assets = _unique_nonempty_strings(
            [_finding_asset_label(finding) for finding in sorted_group_findings]
        ) or ['Unknown asset']
        scanners = _unique_nonempty_strings(
            [
                scanner
                for finding in sorted_group_findings
                for scanner in (_collect_finding_scanners(finding) or ['unknown'])
            ]
        ) or ['unknown']

        cve_group_cards += f"""
        <div class="cve-group-card">
            <div class="cve-group-header">
                <div>
                    <div class="cve-group-title">{escape(cve_id)}</div>
                    <div class="cve-group-subtitle">{len(sorted_group_findings)} linked findings</div>
                </div>
                <div class="finding-badges">
                    <span class="badge severity-badge" style="background: {highest_severity_color};">{escape(highest_severity.upper())}</span>
                </div>
            </div>
            <div class="cve-group-meta">
                <div class="cve-meta-row">
                    <strong>Affected Assets</strong>
                    <div class="chip-list">{_render_chip_list(affected_assets)}</div>
                </div>
                <div class="cve-meta-row">
                    <strong>Scanners</strong>
                    <div class="chip-list">{_render_chip_list(scanners)}</div>
                </div>
            </div>
            <div class="cve-finding-list">
                {_render_cve_finding_items(sorted_group_findings)}
            </div>
        </div>
        """

    sorted_no_cve_findings = sorted(no_cve_findings, key=_finding_sort_key)
    no_cve_meta = ""
    no_cve_body = ""
    if sorted_no_cve_findings:
        no_cve_assets = _unique_nonempty_strings(
            [_finding_asset_label(finding) for finding in sorted_no_cve_findings]
        ) or ['Unknown asset']
        no_cve_scanners = _unique_nonempty_strings(
            [
                scanner
                for finding in sorted_no_cve_findings
                for scanner in (_collect_finding_scanners(finding) or ['unknown'])
            ]
        ) or ['unknown']
        no_cve_meta = f"""
        <div class="cve-group-meta">
            <div class="cve-meta-row">
                <strong>Affected Assets</strong>
                <div class="chip-list">{_render_chip_list(no_cve_assets)}</div>
            </div>
            <div class="cve-meta-row">
                <strong>Scanners</strong>
                <div class="chip-list">{_render_chip_list(no_cve_scanners)}</div>
            </div>
        </div>
        """
        no_cve_body = f'<div class="cve-finding-list">{_render_cve_finding_items(sorted_no_cve_findings)}</div>'

    no_cve_block = f"""
    <div class="cve-group-card">
        {no_cve_meta}
        {no_cve_body}
    </div>
    """

    cve_section = ""
    if sorted_cve_groups:
        cve_section = f"""
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Findings by CVE</h2>
                <span class="section-count">{len(sorted_cve_groups)}</span>
            </div>
            <p class="section-description">
                Groups findings by exact CVE identifier.
            </p>
            <div class="cve-groups-grid">
                {cve_group_cards}
            </div>
        </section>
        """

    no_cve_section = ""
    if sorted_no_cve_findings:
        no_cve_section = f"""
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Findings without CVE</h2>
                <span class="section-count">{len(sorted_no_cve_findings)}</span>
            </div>
            <p class="section-description">
                Findings that do not include an exact CVE identifier.
            </p>
            <div class="cve-groups-grid">
                {no_cve_block}
            </div>
        </section>
        """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {target}</title>
    <style>
        :root[data-theme="dark"] {{
            --bg-primary: #0a0e1a;
            --bg-secondary: #111827;
            --bg-tertiary: #1f2937;
            --bg-hover: #374151;
            --text-primary: #f9fafb;
            --text-secondary: #d1d5db;
            --text-muted: #9ca3af;
            --border: #374151;
            --accent: #3b82f6;
            --card-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3), 0 2px 4px -1px rgba(0, 0, 0, 0.2);
        }}

        :root[data-theme="light"] {{
            --bg-primary: #ffffff;
            --bg-secondary: #f9fafb;
            --bg-tertiary: #f3f4f6;
            --bg-hover: #e5e7eb;
            --text-primary: #111827;
            --text-secondary: #374151;
            --text-muted: #6b7280;
            --border: #e5e7eb;
            --accent: #3b82f6;
            --card-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            transition: background-color 0.3s ease, color 0.3s ease;
        }}

        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}

        /* Header */
        header {{
            margin-bottom: 2.5rem;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 1rem;
        }}

        .header-content {{
            flex: 1;
            min-width: 300px;
        }}

        h1 {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .subtitle {{
            color: var(--text-muted);
            font-size: 0.95rem;
            font-weight: 400;
        }}

        /* Theme Toggle */
        .theme-toggle {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 2rem;
            padding: 0.5rem;
            cursor: pointer;
            display: flex;
            gap: 0.25rem;
            transition: all 0.3s ease;
        }}

        .theme-toggle:hover {{
            background: var(--bg-hover);
        }}

        .theme-option {{
            padding: 0.5rem 1rem;
            border-radius: 1.5rem;
            font-size: 0.875rem;
            font-weight: 500;
            transition: all 0.3s ease;
            cursor: pointer;
            border: none;
            background: transparent;
            color: var(--text-secondary);
        }}

        .theme-option.active {{
            background: var(--accent);
            color: white;
            box-shadow: 0 2px 8px rgba(59, 130, 246, 0.3);
        }}

        /* Controls */
        .controls {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
            box-shadow: var(--card-shadow);
        }}

        .search-filter-container {{
            display: grid;
            gap: 1rem;
            grid-template-columns: 1fr;
        }}

        @media (min-width: 768px) {{
            .search-filter-container {{
                grid-template-columns: 1fr auto;
            }}
        }}

        .search-box {{
            position: relative;
        }}

        .search-box input {{
            width: 100%;
            padding: 0.75rem 1rem 0.75rem 2.75rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            color: var(--text-primary);
            font-size: 0.95rem;
            font-family: inherit;
            transition: all 0.2s ease;
        }}

        .search-box input:focus {{
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }}

        .search-icon {{
            position: absolute;
            left: 0.875rem;
            top: 50%;
            transform: translateY(-50%);
            width: 1.25rem;
            height: 1.25rem;
            color: var(--text-muted);
            pointer-events: none;
        }}

        .filters {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            align-items: center;
        }}

        .filter-set {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .filter-label {{
            color: var(--text-muted);
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }}

        .filter-group {{
            display: flex;
            gap: 0.25rem;
            background: var(--bg-primary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 0.25rem;
        }}

        .filter-btn {{
            padding: 0.5rem 0.875rem;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-size: 0.813rem;
            font-weight: 500;
            border-radius: 0.375rem;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: inherit;
        }}

        .filter-btn:hover {{
            background: var(--bg-hover);
        }}

        .filter-btn.active {{
            background: var(--accent);
            color: white;
        }}

        .clear-filters {{
            padding: 0.5rem 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            color: var(--text-secondary);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: inherit;
        }}

        .clear-filters:hover {{
            background: var(--bg-hover);
        }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-grid,
        .priority-grid,
        .comparison-grid {{
            display: grid;
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-grid {{
            grid-template-columns: repeat(auto-fit, minmax(145px, 1fr));
        }}

        .priority-grid {{
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        }}

        .comparison-grid {{
            grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
        }}

        .summary-metric,
        .priority-card,
        .comparison-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent-color);
            border-radius: 0.75rem;
            padding: 1.125rem;
            box-shadow: var(--card-shadow);
            opacity: 0;
            transform: translateY(20px);
            min-width: 0;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .summary-metric-label,
        .priority-description,
        .comparison-label {{
            color: var(--text-muted);
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }}

        .summary-metric-value,
        .comparison-value {{
            color: var(--text-primary);
            font-size: 1.85rem;
            font-weight: 750;
            line-height: 1.1;
            margin-top: 0.35rem;
        }}

        .priority-card {{
            display: grid;
            gap: 0.55rem;
        }}

        .priority-token {{
            display: inline-flex;
            width: fit-content;
            padding: 0.25rem 0.625rem;
            border-radius: 9999px;
            background: var(--accent-color);
            color: white;
            font-size: 0.8rem;
            font-weight: 800;
            letter-spacing: 0.03em;
        }}

        .priority-count {{
            color: var(--text-primary);
            font-size: 1.35rem;
            font-weight: 750;
            line-height: 1.2;
        }}

        .comparison-detail {{
            margin-top: 1rem;
            padding: 1rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent);
            border-radius: 0.75rem;
        }}

        .comparison-detail-title {{
            color: var(--text-primary);
            font-weight: 700;
            margin-bottom: 0.4rem;
        }}

        .stat-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-left: 3px solid var(--accent-color);
            border-radius: 0.75rem;
            padding: 1.25rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            cursor: pointer;
            box-shadow: var(--card-shadow);
            opacity: 0;
            transform: translateY(20px);
        }}

        .stat-card:hover {{
            transform: translateY(-4px);
            box-shadow: 0 12px 24px -4px rgba(0, 0, 0, 0.2);
            border-left-width: 4px;
        }}

        .stat-icon {{
            font-size: 1.75rem;
        }}

        .stat-content {{
            flex: 1;
        }}

        .stat-value {{
            font-size: 1.75rem;
            font-weight: 700;
            line-height: 1;
            margin-bottom: 0.25rem;
        }}

        .stat-label {{
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-muted);
            font-weight: 600;
        }}

        /* Sections */
        .section {{
            margin-bottom: 2.5rem;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}

        .section-title {{
            font-size: 1.5rem;
            font-weight: 600;
        }}

        .section-count {{
            background: var(--accent);
            color: white;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .section-description {{
            color: var(--text-muted);
            margin-bottom: 1.5rem;
            font-size: 0.95rem;
        }}

        /* Findings Grid */
        .findings-grid {{
            display: grid;
            gap: 1rem;
        }}

        .transport-grid {{
            display: grid;
            gap: 1rem;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
        }}

        .cve-groups-grid {{
            display: grid;
            gap: 1rem;
        }}

        .finding-card,
        .cve-group-card,
        .cve-finding-item,
        .source-card,
        .transport-card,
        .detail-content {{
            min-width: 0;
            height: auto;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .cve-group-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            box-shadow: var(--card-shadow);
        }}

        .cve-group-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}

        .cve-group-header > div:first-child {{
            flex: 1 1 18rem;
            min-width: 0;
        }}

        .cve-group-title {{
            color: var(--text-primary);
            font-size: 1.05rem;
            font-weight: 700;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .cve-group-subtitle {{
            margin-top: 0.25rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        .cve-group-meta {{
            display: grid;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }}

        .cve-meta-row strong {{
            display: block;
            margin-bottom: 0.375rem;
            color: var(--text-primary);
            font-size: 0.85rem;
        }}

        .chip-list {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            min-width: 0;
        }}

        .meta-chip {{
            display: inline-flex;
            align-items: center;
            max-width: 100%;
            padding: 0.25rem 0.625rem;
            border-radius: 9999px;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.75rem;
            font-weight: 600;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .cve-finding-list {{
            display: grid;
            gap: 0.75rem;
        }}

        .cve-finding-item {{
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 0.875rem;
        }}

        .cve-finding-item-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 0.75rem;
            margin-bottom: 0.5rem;
            flex-wrap: wrap;
        }}

        .cve-finding-title {{
            color: var(--text-primary);
            font-weight: 600;
            min-width: 0;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .cve-finding-asset {{
            margin-bottom: 0.5rem;
        }}

        .cve-finding-asset code {{
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            color: var(--text-primary);
            font-size: 0.85rem;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .cve-finding-snippet {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            line-height: 1.5;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .transport-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.25rem;
            box-shadow: var(--card-shadow);
        }}

        .transport-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}

        .transport-card-header > div:first-child {{
            flex: 1 1 14rem;
            min-width: 0;
        }}

        .transport-scanner {{
            font-size: 1rem;
            font-weight: 700;
            color: var(--text-primary);
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}

        .transport-meta {{
            color: var(--text-muted);
            font-size: 0.85rem;
        }}

        .transport-badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            justify-content: flex-end;
        }}

        .transport-badge {{
            background: #2563eb;
        }}

        .transport-state {{
            background: #475569;
        }}

        .transport-notes {{
            color: var(--text-secondary);
            font-size: 0.92rem;
        }}

        .transport-detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 0.75rem;
            margin-top: 0.85rem;
        }}

        .transport-detail-item {{
            background: rgba(37, 99, 235, 0.08);
            border: 1px solid rgba(37, 99, 235, 0.16);
            border-radius: 0.5rem;
            padding: 0.7rem 0.8rem;
        }}

        .transport-detail-label {{
            display: block;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            color: var(--text-muted);
            margin-bottom: 0.25rem;
        }}

        .transport-detail-value {{
            display: block;
            color: var(--text-primary);
            font-size: 0.9rem;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .transport-skip {{
            margin-top: 0.75rem;
            padding: 0.75rem;
            border-radius: 0.5rem;
            background: rgba(239, 68, 68, 0.1);
            color: var(--text-primary);
            border: 1px solid rgba(239, 68, 68, 0.25);
            font-size: 0.9rem;
        }}

        .transport-failure {{
            background: rgba(245, 158, 11, 0.12);
            border-color: rgba(245, 158, 11, 0.28);
        }}

        .transport-diagnostics {{
            margin-top: 0.85rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            background: rgba(15, 23, 42, 0.04);
        }}

        .transport-diagnostics summary {{
            cursor: pointer;
            padding: 0.7rem 0.85rem;
            font-size: 0.88rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .transport-diagnostics-body {{
            margin: 0;
            padding: 0 0.85rem 0.85rem;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.55;
        }}

        .finding-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
            padding: 1.5rem;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: var(--card-shadow);
            opacity: 0;
            transform: translateY(20px);
        }}

        .finding-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 12px 24px -4px rgba(0, 0, 0, 0.15);
            border-color: var(--accent);
        }}

        .changed-card {{
            background: linear-gradient(135deg, var(--bg-secondary) 0%, rgba(249, 115, 22, 0.05) 100%);
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 1rem;
            margin-bottom: 1.25rem;
            flex-wrap: wrap;
            min-width: 0;
        }}

        .finding-title-wrapper {{
            display: flex;
            align-items: flex-start;
            gap: 0.75rem;
            flex: 1 1 18rem;
            min-width: 0;
        }}

        .severity-indicator {{
            width: 4px;
            height: 2rem;
            border-radius: 2px;
            flex-shrink: 0;
        }}

        .finding-title {{
            font-size: 1.125rem;
            font-weight: 600;
            line-height: 1.4;
            min-width: 0;
            max-width: 100%;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-badges {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            justify-content: flex-end;
            align-items: flex-start;
            flex: 0 1 auto;
            max-width: 100%;
        }}

        .badge {{
            display: inline-block;
            padding: 0.375rem 0.875rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.025em;
            color: white;
            transition: all 0.2s ease;
            text-align: center;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-body {{
            color: var(--text-secondary);
            font-size: 0.938rem;
            min-width: 0;
        }}

        .finding-asset {{
            display: flex;
            align-items: flex-start;
            gap: 0.5rem;
            padding: 0.75rem;
            background: var(--bg-tertiary);
            border-radius: 0.5rem;
            margin-bottom: 1rem;
            min-width: 0;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-asset code {{
            display: block;
            min-width: 0;
            max-width: 100%;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.875rem;
            color: var(--text-primary);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .icon {{
            width: 1.125rem;
            height: 1.125rem;
            color: var(--text-muted);
            flex-shrink: 0;
        }}

        .finding-description,
        .finding-remediation,
        .finding-rationale,
        .finding-impact {{
            margin-bottom: 1rem;
        }}

        .finding-risk-summary {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }}

        .risk-score-badge {{
            background: var(--bg-tertiary);
            color: var(--text-primary);
            border: 1px solid var(--border);
        }}

        .finding-provenance {{
            margin-bottom: 1rem;
            padding: 0.75rem 0.875rem;
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent);
            border-radius: 0.5rem;
            color: var(--text-primary);
            font-size: 0.875rem;
            font-weight: 600;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-transport {{
            margin-bottom: 1rem;
            color: var(--text-muted);
            font-size: 0.85rem;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-description strong,
        .finding-remediation strong,
        .finding-rationale strong,
        .finding-impact strong {{
            color: var(--text-primary);
            display: block;
            margin-bottom: 0.375rem;
            font-weight: 600;
        }}

        .merge-summary {{
            margin-bottom: 1rem;
            padding: 0.875rem 1rem;
            background: rgba(34, 197, 94, 0.08);
            border-left: 3px solid #22c55e;
            border-radius: 0.5rem;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .merge-summary strong {{
            color: var(--text-primary);
        }}

        .merge-summary-meta {{
            display: block;
            margin-top: 0.375rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .finding-correlation {{
            margin-bottom: 1rem;
            padding: 0.875rem 1rem;
            background: var(--bg-tertiary);
            border-left: 3px solid var(--accent);
            border-radius: 0.5rem;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .correlation-badges {{
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            align-items: center;
        }}

        .correlation-badge {{
            color: #fff;
        }}

        .correlation-merged {{
            background: var(--accent);
        }}

        .correlation-review {{
            background: #f59e0b;
            color: #1f2937;
        }}

        .correlation-confidence {{
            background: var(--bg-secondary);
            color: var(--text-secondary);
            border: 1px solid var(--border);
        }}

        .correlation-review-warning {{
            margin-top: 0.625rem;
            padding: 0.625rem 0.75rem;
            background: rgba(245, 158, 11, 0.12);
            border-left: 3px solid #f59e0b;
            border-radius: 0.375rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
        }}

        .correlation-details {{
            margin-top: 0.625rem;
        }}

        .correlation-details > summary {{
            cursor: pointer;
            font-size: 0.9rem;
            color: var(--text-secondary);
            user-select: none;
        }}

        .correlation-details > summary:hover {{
            color: var(--text-primary);
        }}

        .correlation-details-body {{
            margin-top: 0.625rem;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .correlation-reason strong,
        .correlation-canonical strong {{
            color: var(--text-primary);
        }}

        .correlation-canonical-value {{
            font-style: italic;
        }}

        .correlation-hint {{
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        .correlation-candidates-label {{
            margin-top: 0.25rem;
            font-weight: 600;
            color: var(--text-primary);
        }}

        .correlation-candidates {{
            list-style: none;
            margin: 0.25rem 0 0 0;
            padding: 0;
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .correlation-candidate {{
            padding: 0.625rem 0.75rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.375rem;
        }}

        .correlation-candidate-head {{
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            gap: 0.5rem;
        }}

        .correlation-candidate-name {{
            font-weight: 600;
            color: var(--text-primary);
        }}

        .correlation-candidate-scanners,
        .correlation-candidate-reason,
        .correlation-candidate-canonical {{
            margin-top: 0.375rem;
            font-size: 0.85rem;
            color: var(--text-muted);
        }}

        .correlation-disclaimer {{
            margin-top: 0.25rem;
            font-size: 0.8rem;
            color: var(--text-muted);
        }}

        .correlation-graph {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .correlation-graph-row {{
            display: grid;
            grid-template-columns: minmax(0, 1fr) 7rem minmax(0, 1fr);
            gap: 0.75rem;
            align-items: center;
            padding: 1rem;
            background: var(--bg-tertiary);
            border: 1px solid var(--border);
            border-radius: 0.75rem;
        }}

        .correlation-graph-sources {{
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }}

        .correlation-graph-node {{
            display: flex;
            flex-direction: column;
            gap: 0.3rem;
            min-width: 0;
            padding: 0.75rem;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.6rem;
            overflow-wrap: anywhere;
        }}

        .graph-row-merged .graph-result-node {{
            border: 2px solid #22c55e;
            box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.1);
        }}

        .graph-row-review .graph-result-node,
        .graph-node-review {{
            border: 2px dashed #f59e0b;
        }}

        .graph-node-scanner,
        .graph-result-badge {{
            align-self: flex-start;
            padding: 0.18rem 0.45rem;
            border-radius: 999px;
            background: var(--bg-tertiary);
            color: var(--text-secondary);
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }}

        .graph-row-merged .graph-result-badge {{
            background: rgba(34, 197, 94, 0.16);
            color: #22c55e;
        }}

        .graph-row-review .graph-result-badge {{
            background: rgba(245, 158, 11, 0.16);
            color: #f59e0b;
        }}

        .graph-node-title {{
            color: var(--text-primary);
            font-size: 0.9rem;
        }}

        .graph-node-asset,
        .graph-result-confidence,
        .graph-result-reason,
        .graph-external-review {{
            color: var(--text-muted);
            font-size: 0.78rem;
            overflow-wrap: anywhere;
        }}

        .graph-external-review {{
            color: #f59e0b;
            font-weight: 600;
        }}

        .correlation-graph-connector {{
            display: grid;
            grid-template-columns: 1fr auto;
            grid-template-rows: auto auto;
            align-items: center;
            column-gap: 0.35rem;
            color: var(--text-muted);
            text-align: center;
        }}

        .correlation-graph-connector span {{
            grid-column: 1 / -1;
            margin-bottom: 0.25rem;
            font-size: 0.7rem;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .graph-connector-line {{
            width: 100%;
            border-top: 2px solid #22c55e;
        }}

        .graph-row-review .graph-connector-line {{
            border-top: 2px dashed #f59e0b;
        }}

        .correlation-graph-connector b {{
            color: #22c55e;
            font-size: 1.25rem;
        }}

        .graph-row-review .correlation-graph-connector b {{
            color: #f59e0b;
        }}

        .correlation-graph-limit {{
            margin-top: 1rem;
        }}

        .finding-description p,
        .finding-remediation p,
        .finding-rationale p,
        .finding-impact p {{
            line-height: 1.6;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .finding-rationale,
        .finding-impact {{
            padding: 0.875rem 1rem;
            background: var(--bg-tertiary);
            border-radius: 0.5rem;
        }}

        .finding-impact {{
            border-left: 3px solid var(--accent);
        }}

        /* Changes Section */
        .changes-section {{
            margin-top: 1rem;
        }}

        .changes-header {{
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--text-primary);
        }}

        .change-item {{
            margin-bottom: 0.75rem;
            padding: 0.875rem;
            background: rgba(249, 115, 22, 0.1);
            border-radius: 0.5rem;
            border-left: 3px solid #f97316;
        }}

        .change-label {{
            font-weight: 600;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
            color: var(--text-primary);
        }}

        .change-comparison {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.875rem;
        }}

        .change-before {{
            color: #f87171;
            text-decoration: line-through;
            opacity: 0.8;
        }}

        .change-arrow {{
            width: 1.25rem;
            height: 1.25rem;
            color: var(--text-muted);
            flex-shrink: 0;
        }}

        .change-after {{
            color: #4ade80;
            font-weight: 600;
        }}

        /* Detail Sections */
        .detail-section {{
            margin-top: 1.25rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
        }}

        .detail-section details {{
            background: var(--bg-tertiary);
        }}

        .detail-section details[open] {{
            background: var(--bg-primary);
        }}

        .section-summary {{
            padding: 0.875rem 1rem;
            cursor: pointer;
            font-weight: 600;
            font-size: 0.938rem;
            background: var(--bg-tertiary);
            border-bottom: 1px solid var(--border);
            transition: all 0.2s ease;
            list-style: none;
            user-select: none;
        }}

        .section-summary:hover {{
            background: var(--bg-hover);
        }}

        .section-summary::-webkit-details-marker {{
            display: none;
        }}

        .section-summary::before {{
            content: '▶';
            display: inline-block;
            margin-right: 0.5rem;
            transition: transform 0.2s ease;
            font-size: 0.75rem;
        }}

        details[open] .section-summary::before {{
            transform: rotate(90deg);
        }}

        .detail-content {{
            padding: 1rem;
        }}

        .source-grid {{
            display: grid;
            gap: 0.875rem;
        }}

        .source-card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            padding: 1rem;
        }}

        .source-card-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
            flex-wrap: wrap;
        }}

        .source-card-header > div:first-child {{
            flex: 1 1 16rem;
            min-width: 0;
        }}

        .source-card-header > div:last-child {{
            display: flex;
            justify-content: flex-end;
            align-items: flex-start;
            gap: 0.5rem;
            flex-wrap: wrap;
        }}

        .source-scanner {{
            font-size: 0.78rem;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
            color: var(--accent);
        }}

        .source-title {{
            margin-top: 0.25rem;
            color: var(--text-primary);
            font-weight: 600;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .source-asset {{
            margin-bottom: 0.75rem;
        }}

        .source-asset code {{
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 0.85rem;
            color: var(--text-primary);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .source-context {{
            list-style: none;
            padding: 0;
            margin: 0 0 0.75rem 0;
            display: grid;
            gap: 0.5rem;
        }}

        .source-context li {{
            padding: 0.625rem 0.75rem;
            background: var(--bg-primary);
            border-radius: 0.375rem;
            font-size: 0.875rem;
            color: var(--text-secondary);
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .source-context strong,
        .source-snippet strong {{
            color: var(--text-primary);
        }}

        .source-snippet {{
            margin-top: 0.625rem;
            font-size: 0.9rem;
            color: var(--text-secondary);
            line-height: 1.6;
            overflow-wrap: anywhere;
            word-break: break-word;
        }}

        .source-artifact {{
            margin-top: 0.75rem;
            border: 1px solid var(--border);
            border-radius: 0.375rem;
            background: var(--bg-primary);
        }}

        .source-artifact summary {{
            cursor: pointer;
            padding: 0.625rem 0.75rem;
            font-size: 0.875rem;
            font-weight: 600;
            color: var(--text-primary);
            background: var(--bg-tertiary);
        }}

        .source-artifact pre {{
            margin: 0;
            padding: 0.75rem;
            white-space: pre-wrap;
            overflow-wrap: anywhere;
            word-break: break-word;
            font-size: 0.82rem;
            line-height: 1.5;
            color: var(--text-secondary);
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
        }}

        .risk-metrics {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 0.75rem;
            margin: 0.875rem 0;
        }}

        .metric {{
            padding: 0.625rem;
            background: var(--bg-secondary);
            border-radius: 0.375rem;
            border-left: 3px solid var(--accent);
        }}

        .metric-label {{
            font-size: 0.75rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            font-weight: 600;
            display: block;
            margin-bottom: 0.25rem;
        }}

        .metric-value {{
            font-size: 0.938rem;
            color: var(--text-primary);
            font-weight: 600;
        }}

        /* Empty State */
        .empty-state {{
            text-align: center;
            padding: 4rem 2rem;
            color: var(--text-muted);
        }}

        .empty-state-icon {{
            font-size: 4rem;
            margin-bottom: 1rem;
        }}

        .empty-state-text {{
            font-size: 1.125rem;
        }}

        .empty-state-action {{
            margin-top: 1rem;
            padding: 0.625rem 1rem;
            background: var(--accent);
            border: none;
            border-radius: 0.5rem;
            color: white;
            font-size: 0.875rem;
            font-weight: 700;
            cursor: pointer;
            font-family: inherit;
        }}

        .empty-state-action:hover {{
            filter: brightness(1.08);
        }}

        /* Animations */
        @keyframes fadeInUp {{
            from {{
                opacity: 0;
                transform: translateY(20px);
            }}
            to {{
                opacity: 1;
                transform: translateY(0);
            }}
        }}

        .fade-in {{
            animation: fadeInUp 0.5s cubic-bezier(0.4, 0, 0.2, 1) forwards;
        }}

        /* Hidden class for filtering */
        .hidden {{
            display: none !important;
        }}

        /* Responsive */
        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}

            h1 {{
                font-size: 1.5rem;
            }}

            .finding-header {{
                flex-direction: column;
                align-items: flex-start;
            }}

            .stats-grid {{
                grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            }}

            .correlation-graph-row {{
                grid-template-columns: 1fr;
            }}

            .correlation-graph-connector {{
                width: min(8rem, 60%);
                margin: 0 auto;
                transform: rotate(90deg);
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="header-content">
                <h1>
                    <svg class="icon" style="width: 2rem; height: 2rem;" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M2.166 4.999A11.954 11.954 0 0010 1.944 11.954 11.954 0 0017.834 5c.11.65.166 1.32.166 2.001 0 5.225-3.34 9.67-8 11.317C5.34 16.67 2 12.225 2 7c0-.682.057-1.35.166-2.001zm11.541 3.708a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                    </svg>
                    Security Vulnerability Report
                </h1>
                <div class="subtitle">
                    Target: <strong>{target}</strong> • Scan Date: {timestamp[:19].replace('T', ' ')}
                </div>
            </div>
            <div class="theme-toggle">
                <button class="theme-option active" data-theme="dark">🌙 Dark</button>
                <button class="theme-option" data-theme="light">☀️ Light</button>
            </div>
        </header>

        <div class="controls">
            <div class="search-filter-container">
                <div class="search-box">
                    <svg class="search-icon" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M8 4a4 4 0 100 8 4 4 0 000-8zM2 8a6 6 0 1110.89 3.476l4.817 4.817a1 1 0 01-1.414 1.414l-4.816-4.816A6 6 0 012 8z" clip-rule="evenodd" />
                    </svg>
                    <input type="text" id="searchInput" placeholder="Search vulnerabilities..." />
                </div>
                <div class="filters">
                    <div class="filter-set">
                        <span class="filter-label">Severity</span>
                        <div class="filter-group" id="severityFilters" aria-label="Severity filters">
                            <button class="filter-btn active" data-filter="severity" data-value="all">All</button>
                            <button class="filter-btn" data-filter="severity" data-value="critical">Critical</button>
                            <button class="filter-btn" data-filter="severity" data-value="high">High</button>
                            <button class="filter-btn" data-filter="severity" data-value="medium">Medium</button>
                            <button class="filter-btn" data-filter="severity" data-value="low">Low</button>
                            <button class="filter-btn" data-filter="severity" data-value="info">Info</button>
                        </div>
                    </div>
                    <div class="filter-set">
                        <span class="filter-label">Status</span>
                        <div class="filter-group" id="statusFilters" aria-label="Status filters">
                            <button class="filter-btn active" data-filter="status" data-value="all">All</button>
                            <button class="filter-btn" data-filter="status" data-value="new">New</button>
                            <button class="filter-btn" data-filter="status" data-value="changed">Changed</button>
                            <button class="filter-btn" data-filter="status" data-value="persistent">Persistent</button>
                            <button class="filter-btn" data-filter="status" data-value="fixed">Fixed</button>
                        </div>
                    </div>
                    <button class="clear-filters" id="clearFilters">Clear filters</button>
                </div>
            </div>
        </div>

        <section class="section summary-section">
            <div class="summary-grid">
                {summary_cards}
            </div>
        </section>

        {site_context_section}

        {f'''
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Priority Distribution</h2>
            </div>
            <div class="priority-grid">
                {priority_cards}
            </div>
        </section>
        ''' if show_priority_section else ''}

        {f'''
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Historical Comparison</h2>
            </div>
            <p class="section-description">Shows how findings changed compared with the previous report.</p>
            <div class="comparison-grid">
                {comparison_cards}
            </div>
            {comparison_detail}
        </section>
        ''' if has_comparison else ''}

        {f'''
        <section class="section">
            <div class="section-header">
                <h2 class="section-title">Historical Comparison</h2>
            </div>
            {comparison_detail}
        </section>
        ''' if comparison_detail and not has_comparison else ''}

        <section class="section">
            <div class="section-header">
                <h2 class="section-title">All Findings</h2>
                <span class="section-count" id="findingsCount">{len(findings)}</span>
            </div>
            <div class="findings-grid" id="findingsGrid">
                {finding_cards if findings else '<div class="empty-state"><div class="empty-state-icon">✅</div><div class="empty-state-text">No vulnerabilities found!</div></div>'}
                <div class="empty-state hidden" id="filteredEmptyState">
                    <div class="empty-state-text">No findings match the selected filters.</div>
                    <button class="empty-state-action" id="emptyClearFilters">Clear filters</button>
                </div>
            </div>
        </section>

        {cve_section}
        {no_cve_section}
        {correlation_graph_section}
    </div>

<script>
// Theme Management
const root = document.documentElement;
const themeButtons = document.querySelectorAll('.theme-option');
const savedTheme = localStorage.getItem('theme') || 'dark';

function setTheme(theme) {{
    root.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
    themeButtons.forEach(btn => {{
        btn.classList.toggle('active', btn.dataset.theme === theme);
    }});
}}

setTheme(savedTheme);

themeButtons.forEach(btn => {{
    btn.addEventListener('click', () => setTheme(btn.dataset.theme));
}});

// Filter & Search Management
const searchInput = document.getElementById('searchInput');
const findingsGrid = document.getElementById('findingsGrid');
const findingCards = Array.from(findingsGrid.querySelectorAll('.finding-card'));
const findingsCount = document.getElementById('findingsCount');
const filterBtns = document.querySelectorAll('.filter-btn');
const clearFiltersBtn = document.getElementById('clearFilters');
const filteredEmptyState = document.getElementById('filteredEmptyState');
const emptyClearFiltersBtn = document.getElementById('emptyClearFilters');

let activeFilters = {{
    severity: 'all',
    status: 'all',
    search: ''
}};

function hasActiveFilters() {{
    return activeFilters.severity !== 'all'
        || activeFilters.status !== 'all'
        || activeFilters.search.trim() !== '';
}}

function syncFilterButtons() {{
    filterBtns.forEach(btn => {{
        const filterType = btn.dataset.filter;
        btn.classList.toggle('active', activeFilters[filterType] === btn.dataset.value);
    }});
}}

function applyFilters() {{
    let visibleCount = 0;

    findingCards.forEach(card => {{
        const severity = card.dataset.severity?.toLowerCase() || '';
        const status = card.dataset.status?.toLowerCase() || '';
        const text = card.textContent.toLowerCase();

        const severityMatch = activeFilters.severity === 'all' || severity === activeFilters.severity;
        const statusMatch = activeFilters.status === 'all' || status === activeFilters.status;
        const searchMatch = !activeFilters.search || text.includes(activeFilters.search.toLowerCase());

        const shouldShow = severityMatch && statusMatch && searchMatch;
        card.classList.toggle('hidden', !shouldShow);

        if (shouldShow) visibleCount++;
    }});

    findingsCount.textContent = visibleCount;
    if (filteredEmptyState) {{
        filteredEmptyState.classList.toggle(
            'hidden',
            !(findingCards.length > 0 && visibleCount === 0 && hasActiveFilters())
        );
    }}
}}

// Search
searchInput.addEventListener('input', (e) => {{
    activeFilters.search = e.target.value.trim().toLowerCase();
    applyFilters();
}});

// Filters
filterBtns.forEach(btn => {{
    btn.addEventListener('click', () => {{
        const filterType = btn.dataset.filter;
        const filterValue = btn.dataset.value;

        activeFilters[filterType] = filterValue;
        syncFilterButtons();
        applyFilters();
    }});
}});

function clearFilters() {{
    activeFilters = {{ severity: 'all', status: 'all', search: '' }};
    searchInput.value = '';
    syncFilterButtons();
    applyFilters();
}}

// Clear filters
clearFiltersBtn.addEventListener('click', clearFilters);
if (emptyClearFiltersBtn) {{
    emptyClearFiltersBtn.addEventListener('click', clearFilters);
}}

syncFilterButtons();
applyFilters();
</script>
</body>
</html>
"""

    return html

def generate_html_report(results: Dict[str, Any], output_path: Optional[Path] = None) -> str:
    """Generate HTML report (wrapper for backward compatibility).

    Raises:
        ValueError: If results fail report-stage schema validation.
                    report.html is never written from invalid data.
    """
    from utils.schema import assert_valid_results
    export_results = sanitize_results_for_export(results)
    assert_valid_results(export_results, stage='report')

    html = generate_modern_html_report(export_results)

    if output_path:
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    return html

def save_html_report(results: Dict[str, Any], reports_dir: Optional[Path] = None) -> Path:
    """
    Save HTML report to reports directory.

    Args:
        results: Scan results
        reports_dir: Reports directory (default: ./reports)

    Returns:
        Path to generated report
    """
    reports_dir = reports_dir or Path('reports')
    reports_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    target = str(results.get('target', 'unknown')).replace("://", "_").replace("/", "_").replace(":", "_")
    output_path = reports_dir / f"report_{target}_{timestamp}.html"

    generate_html_report(results, output_path)
    return output_path
