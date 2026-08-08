"""Strict exact-CVE helpers shared by comparison and report rendering."""

from __future__ import annotations

import re
from typing import Any, Dict, List


_CVE_EXACT_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def collect_exact_cve_values(value: Any) -> List[str]:
    """Return exact CVE identifiers from a scalar-or-list value."""
    if value is None:
        return []

    values = value if isinstance(value, (list, tuple, set)) else [value]
    normalized: List[str] = []
    for item in values:
        candidate = str(item or "").strip().upper()
        if _CVE_EXACT_RE.fullmatch(candidate):
            normalized.append(candidate)
    return normalized


def extract_exact_cve_ids(finding: Dict[str, Any]) -> List[str]:
    """Extract exact CVE identifiers from supported finding fields."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        meta = {}

    deduped: List[str] = []
    for value in (
        meta.get("cve_ids"),
        meta.get("cve_id"),
        meta.get("cve"),
        meta.get("raw_id"),
        finding.get("vulnerability_name"),
    ):
        for cve_id in collect_exact_cve_values(value):
            if cve_id not in deduped:
                deduped.append(cve_id)
    return deduped
