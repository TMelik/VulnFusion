"""
Canonical scan-result summary helpers.

Summary counters must describe the final finding set that will be reported,
not an earlier raw or pre-deduplicated set.
"""

from typing import Any, Dict, Iterable, List


SEVERITY_LEVELS = ("critical", "high", "medium", "low", "info")
PRIORITY_LEVELS = ("P0", "P1", "P2", "P3", "P4")


def _finding_scanners(finding: Dict[str, Any]) -> List[str]:
    """Return scanner names represented by a final finding."""
    scanners = finding.get("found_by")
    if isinstance(scanners, list):
        return [str(scanner) for scanner in scanners if scanner]

    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    meta_scanners = meta.get("scanners")
    if isinstance(meta_scanners, list):
        return [str(scanner) for scanner in meta_scanners if scanner]

    scanner = meta.get("scanner")
    return [str(scanner)] if scanner else []


def count_by_severity(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Count final findings by normalized severity."""
    counts = {severity: 0 for severity in SEVERITY_LEVELS}
    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()
        if severity in counts:
            counts[severity] += 1
    return counts


def count_by_scanner(
    findings: Iterable[Dict[str, Any]],
    existing_counts: Dict[str, Any] | None = None,
) -> Dict[str, int]:
    """
    Count final findings by scanner while preserving zero-count scanner keys.

    Merged findings are counted once for each scanner that contributed evidence,
    so this distribution is not expected to sum to total_findings.
    """
    counts = {
        str(scanner): 0
        for scanner in (existing_counts or {})
    }
    for finding in findings:
        scanners = _finding_scanners(finding)
        if not scanners:
            scanners = ["unknown"]
        for scanner in scanners:
            counts[scanner] = counts.get(scanner, 0) + 1
    return counts


def count_by_priority(findings: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    """Count final findings by risk priority bucket."""
    counts = {priority: 0 for priority in PRIORITY_LEVELS}
    for finding in findings:
        priority = finding.get("priority", "P4")
        if priority in counts:
            counts[priority] += 1
    return counts


def refresh_summary_counts(results: Dict[str, Any]) -> Dict[str, Any]:
    """Refresh summary totals from results['all_findings'] in-place."""
    findings = results.get("all_findings", [])
    if not isinstance(findings, list):
        findings = []

    summary = results.get("summary")
    if not isinstance(summary, dict):
        summary = {}

    summary["total_findings"] = len(findings)
    summary["by_severity"] = count_by_severity(findings)

    existing_by_scanner = summary.get("by_scanner")
    if isinstance(existing_by_scanner, dict) or findings:
        summary["by_scanner"] = count_by_scanner(
            findings,
            existing_by_scanner if isinstance(existing_by_scanner, dict) else None,
        )

    if "by_priority" in summary or any(isinstance(f, dict) and f.get("priority") for f in findings):
        summary["by_priority"] = count_by_priority(findings)

    results["summary"] = summary
    return results
