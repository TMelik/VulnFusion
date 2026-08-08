"""
Offline CVE intelligence enrichment helpers.

This stage normalizes CVE identifiers and enriches findings with locally
provided CVSS, EPSS, and KEV intelligence before risk scoring runs.
"""

from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


@dataclass(frozen=True)
class VulnerabilityIntelligence:
    """Resolved offline vulnerability intelligence datasets."""

    cvss: Dict[str, Dict[str, Any]]
    epss: Dict[str, Dict[str, Any]]
    kev: Dict[str, Dict[str, Any]]


def normalize_cve_id(value: Any) -> Optional[str]:
    """Normalize a single CVE identifier to canonical uppercase form."""
    if value is None:
        return None
    match = _CVE_RE.search(str(value).strip())
    if not match:
        return None
    return match.group(0).upper()


def _extract_cves_from_value(value: Any) -> List[str]:
    """Extract all valid CVEs from a scalar or list-like value."""
    if value is None:
        return []
    if isinstance(value, list):
        found: List[str] = []
        for item in value:
            found.extend(_extract_cves_from_value(item))
        return found
    return [match.group(0).upper() for match in _CVE_RE.finditer(str(value))]


def _dedupe_preserve_order(values: Iterable[str]) -> List[str]:
    """Deduplicate a sequence while preserving its original order."""
    seen = set()
    deduped: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def extract_cve_ids(finding: Dict[str, Any]) -> List[str]:
    """Extract normalized CVE IDs from finding metadata."""
    meta = finding.get("meta", {})
    if not isinstance(meta, dict):
        return []

    collected: List[str] = []
    for key in ("cve_id", "cve_ids", "cve"):
        if key in meta:
            collected.extend(_extract_cves_from_value(meta.get(key)))
    return _dedupe_preserve_order(collected)


def clear_vuln_intel_caches() -> None:
    """Clear cached offline intelligence file reads."""
    _load_json_file.cache_clear()
    _load_csv_rows.cache_clear()


def _coerce_float(value: Any) -> Optional[float]:
    """Convert common numeric representations to float."""
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
    """Normalize score/percentile values into the 0.0-1.0 range."""
    numeric = _coerce_float(value)
    if numeric is None:
        return None
    if numeric > 1.0 and numeric <= 100.0:
        numeric /= 100.0
    return max(0.0, min(1.0, numeric))


def _first_value(*values: Any) -> Any:
    """Return the first non-empty value."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        return value
    return None


def _path_str(path: Optional[str]) -> Optional[str]:
    """Normalize an optional path to a stable absolute string."""
    if not path:
        return None
    return str(Path(path).expanduser().resolve())


@lru_cache(maxsize=16)
def _load_json_file(path_str: str) -> Any:
    """Load a JSON file once per path."""
    with open(path_str, "r", encoding="utf-8") as fh:
        return json.load(fh)


@lru_cache(maxsize=16)
def _load_csv_rows(path_str: str) -> List[Dict[str, Any]]:
    """Load a CSV file once per path."""
    with open(path_str, "r", encoding="utf-8", newline="") as fh:
        return list(csv.DictReader(fh))


def _iter_records(data: Any) -> List[Dict[str, Any]]:
    """Flatten common JSON structures into a list of records."""
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for list_key in ("vulnerabilities", "items", "records"):
            values = data.get(list_key)
            if isinstance(values, list):
                return [item for item in values if isinstance(item, dict)]

        keyed_records: List[Dict[str, Any]] = []
        for key, value in data.items():
            normalized = normalize_cve_id(key)
            if not normalized:
                continue
            if isinstance(value, dict):
                record = dict(value)
            else:
                record = {"value": value}
            record.setdefault("cve", normalized)
            keyed_records.append(record)
        if keyed_records:
            return keyed_records

        return [data]

    return []


def _record_cve(record: Dict[str, Any]) -> Optional[str]:
    """Extract the primary CVE from a data record."""
    for key in ("cve", "cve_id", "cveID", "id"):
        normalized = normalize_cve_id(record.get(key))
        if normalized:
            return normalized

    nested = record.get("cve")
    if isinstance(nested, dict):
        for key in ("id", "cve_id", "cveID"):
            normalized = normalize_cve_id(nested.get(key))
            if normalized:
                return normalized

    found = _extract_cves_from_value(record)
    return found[0] if found else None


def _extract_nested_cvss(value: Any, version: str) -> Optional[Dict[str, Any]]:
    """Extract a nested CVSS block into canonical fields."""
    if isinstance(value, dict):
        score = _coerce_float(_first_value(value.get("score"), value.get("baseScore"), value.get("cvss_score")))
        vector = _first_value(value.get("vector"), value.get("vectorString"), value.get("cvss_vector"))
    else:
        score = _coerce_float(value)
        vector = None

    if score is None:
        return None

    return {
        "cvss_score": max(0.0, min(10.0, score)),
        "cvss_version": version,
        "cvss_vector": vector,
    }


def _extract_cvss_entry(record: Dict[str, Any], default_source: str) -> Optional[tuple[str, Dict[str, Any]]]:
    """Extract a canonical CVSS entry from a file record."""
    cve_id = _record_cve(record)
    if not cve_id:
        return None

    source = _first_value(record.get("cvss_source"), record.get("source"), default_source)
    entry = (
        _extract_nested_cvss(record.get("cvss_v4"), "4.0")
        or _extract_nested_cvss(
            _first_value(record.get("cvss_v4_score"), record.get("cvss_v4_base_score"), record.get("cvss_v4Score")),
            "4.0",
        )
    )
    if entry:
        entry["cvss_vector"] = _first_value(entry.get("cvss_vector"), record.get("cvss_v4_vector"), record.get("cvss_v4Vector"))
    if not entry:
        entry = (
            _extract_nested_cvss(record.get("cvss_v3_1"), "3.1")
            or _extract_nested_cvss(record.get("cvss_v31"), "3.1")
            or _extract_nested_cvss(record.get("cvss_v3"), "3.1")
            or _extract_nested_cvss(
                _first_value(record.get("cvss_v3_1_score"), record.get("cvss_v31_score"), record.get("cvss_v3_score")),
                "3.1",
            )
        )
        if entry:
            entry["cvss_vector"] = _first_value(
                entry.get("cvss_vector"),
                record.get("cvss_v3_1_vector"),
                record.get("cvss_v31_vector"),
                record.get("cvss_v3_vector"),
            )
    if not entry:
        version_hint = str(_first_value(record.get("cvss_version"), "3.1")).strip()
        generic_score = _coerce_float(_first_value(record.get("cvss_score"), record.get("cvss"), record.get("value")))
        if generic_score is not None:
            entry = {
                "cvss_score": max(0.0, min(10.0, generic_score)),
                "cvss_version": "4.0" if version_hint == "4.0" else "3.1",
                "cvss_vector": record.get("cvss_vector"),
            }

    if not entry:
        return None

    entry["cvss_source"] = source
    return cve_id, entry


def _extract_epss_entry(record: Dict[str, Any], default_source: str) -> Optional[tuple[str, Dict[str, Any]]]:
    """Extract a canonical EPSS entry from a file record."""
    cve_id = _record_cve(record)
    if not cve_id:
        return None

    score = _normalize_fraction(_first_value(record.get("epss"), record.get("epss_score"), record.get("score"), record.get("value")))
    percentile = _normalize_fraction(_first_value(record.get("epss_percentile"), record.get("percentile")))
    if score is None and percentile is None:
        return None

    return cve_id, {
        "epss_score": score,
        "epss_percentile": percentile,
        "epss_source": _first_value(record.get("epss_source"), record.get("source"), default_source),
    }


def _extract_kev_entry(record: Dict[str, Any], default_source: str) -> Optional[tuple[str, Dict[str, Any]]]:
    """Extract a canonical KEV entry from a file record."""
    cve_id = _record_cve(record)
    if not cve_id:
        return None

    listed_value = _first_value(record.get("listed"), record.get("value"))
    if listed_value is False:
        return None

    due_date = _first_value(record.get("dueDate"), record.get("due_date"), record.get("date_due"))
    source = _first_value(record.get("kev_source"), record.get("source"), record.get("catalog"), default_source)
    return cve_id, {
        "kev_listed": True,
        "kev_source": source,
        "kev_due_date": due_date,
    }


def _load_cvss_intelligence(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Load offline CVSS intelligence from JSON or CSV."""
    path_str = _path_str(path)
    if path_str is None:
        return {}

    source_name = Path(path_str).name
    data = _load_json_file(path_str) if path_str.lower().endswith(".json") else _load_csv_rows(path_str)
    entries: Dict[str, Dict[str, Any]] = {}
    for record in _iter_records(data) if path_str.lower().endswith(".json") else data:
        entry = _extract_cvss_entry(record, source_name)
        if entry is None:
            continue
        cve_id, values = entry
        entries[cve_id] = values
    return entries


def _load_epss_intelligence(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Load offline EPSS intelligence from JSON or CSV."""
    path_str = _path_str(path)
    if path_str is None:
        return {}

    source_name = Path(path_str).name
    data = _load_json_file(path_str) if path_str.lower().endswith(".json") else _load_csv_rows(path_str)
    entries: Dict[str, Dict[str, Any]] = {}
    for record in _iter_records(data) if path_str.lower().endswith(".json") else data:
        entry = _extract_epss_entry(record, source_name)
        if entry is None:
            continue
        cve_id, values = entry
        entries[cve_id] = values
    return entries


def _load_kev_intelligence(path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    """Load offline KEV intelligence from JSON or CSV."""
    path_str = _path_str(path)
    if path_str is None:
        return {}

    source_name = Path(path_str).name
    data = _load_json_file(path_str) if path_str.lower().endswith(".json") else _load_csv_rows(path_str)
    entries: Dict[str, Dict[str, Any]] = {}
    for record in _iter_records(data) if path_str.lower().endswith(".json") else data:
        entry = _extract_kev_entry(record, source_name)
        if entry is None:
            continue
        cve_id, values = entry
        entries[cve_id] = values
    return entries


def load_vulnerability_intelligence(
    *,
    cvss_file: Optional[str] = None,
    epss_file: Optional[str] = None,
    kev_file: Optional[str] = None,
) -> VulnerabilityIntelligence:
    """Load offline CVSS, EPSS, and KEV datasets from local files."""
    return VulnerabilityIntelligence(
        cvss=_load_cvss_intelligence(cvss_file),
        epss=_load_epss_intelligence(epss_file),
        kev=_load_kev_intelligence(kev_file),
    )


def _existing_cvss_info(meta: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Return the existing canonical/scanner CVSS fields when present."""
    score = _coerce_float(_first_value(meta.get("cvss_score"), meta.get("cvss")))
    if score is None:
        return None
    version = str(_first_value(meta.get("cvss_version"), "3.1")).strip()
    if version not in {"4.0", "3.1"}:
        version = "3.1"
    return {
        "cvss_score": max(0.0, min(10.0, score)),
        "cvss_version": version,
        "cvss_vector": meta.get("cvss_vector"),
        "cvss_source": _first_value(meta.get("cvss_source"), "scanner"),
    }


def _build_candidates(
    cve_ids: List[str],
    meta: Dict[str, Any],
    intelligence: VulnerabilityIntelligence,
) -> List[Dict[str, Any]]:
    """Build candidate intelligence records for each CVE."""
    candidates: List[Dict[str, Any]] = []
    existing_cvss = _existing_cvss_info(meta)
    fallback_cve = normalize_cve_id(meta.get("cve_id")) or cve_ids[0]

    for cve_id in cve_ids:
        candidate: Dict[str, Any] = {
            "cve_id": cve_id,
            "cvss_score": None,
            "cvss_version": None,
            "cvss_vector": None,
            "cvss_source": None,
            "epss_score": None,
            "epss_percentile": None,
            "epss_source": None,
            "kev_listed": False,
            "kev_source": None,
            "kev_due_date": None,
            "has_external_cvss": False,
        }

        cvss_values = intelligence.cvss.get(cve_id)
        if cvss_values:
            candidate.update(cvss_values)
            candidate["has_external_cvss"] = True
        elif existing_cvss and cve_id == fallback_cve:
            candidate.update(existing_cvss)

        epss_values = intelligence.epss.get(cve_id)
        if epss_values:
            candidate.update(epss_values)

        kev_values = intelligence.kev.get(cve_id)
        if kev_values:
            candidate.update(kev_values)

        candidates.append(candidate)

    return candidates


def _candidate_sort_value(candidate: Dict[str, Any]) -> tuple:
    """Return a stable sort tuple for fallback tie-breaking."""
    cvss_score = candidate.get("cvss_score")
    return (
        1 if candidate.get("kev_listed") else 0,
        cvss_score if cvss_score is not None else -1.0,
        candidate.get("epss_score") if candidate.get("epss_score") is not None else -1.0,
        candidate.get("epss_percentile") if candidate.get("epss_percentile") is not None else -1.0,
        1 if candidate.get("has_external_cvss") else 0,
        candidate.get("cve_id", ""),
    )


def _choose_primary_candidate(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Choose the canonical CVE for scoring fields."""
    primary = candidates[0]
    for candidate in candidates[1:]:
        primary_cvss = primary.get("cvss_score")
        candidate_cvss = candidate.get("cvss_score")

        comparable_severity = (
            primary_cvss is not None
            and candidate_cvss is not None
            and abs(primary_cvss - candidate_cvss) <= 1.0
        )
        if comparable_severity and candidate.get("kev_listed") != primary.get("kev_listed"):
            if candidate.get("kev_listed"):
                primary = candidate
            continue

        if _candidate_sort_value(candidate) > _candidate_sort_value(primary):
            primary = candidate

    return primary


def _set_or_clear(meta: Dict[str, Any], key: str, value: Any) -> None:
    """Write a metadata key when a value exists, else remove it."""
    if value is None:
        meta.pop(key, None)
    else:
        meta[key] = value


def _apply_canonical_cvss(meta: Dict[str, Any], primary: Dict[str, Any]) -> None:
    """Write canonical CVSS fields for the selected CVE."""
    if primary.get("cvss_score") is None:
        return
    meta["cvss"] = primary["cvss_score"]
    meta["cvss_score"] = primary["cvss_score"]
    meta["cvss_version"] = primary["cvss_version"]
    _set_or_clear(meta, "cvss_vector", primary.get("cvss_vector"))
    _set_or_clear(meta, "cvss_source", primary.get("cvss_source"))


def _apply_canonical_epss(meta: Dict[str, Any], primary: Dict[str, Any], *, external_requested: bool) -> None:
    """Write canonical EPSS fields for the selected CVE."""
    if primary.get("epss_score") is not None or primary.get("epss_percentile") is not None:
        _set_or_clear(meta, "epss_score", primary.get("epss_score"))
        _set_or_clear(meta, "epss_percentile", primary.get("epss_percentile"))
        _set_or_clear(meta, "epss_source", primary.get("epss_source"))
        return

    if external_requested:
        meta.pop("epss_score", None)
        meta.pop("epss_percentile", None)
        meta.pop("epss_source", None)


def _apply_canonical_kev(meta: Dict[str, Any], primary: Dict[str, Any], *, external_requested: bool) -> None:
    """Write canonical KEV fields for the selected CVE."""
    if primary.get("kev_listed"):
        meta["kev_listed"] = True
        _set_or_clear(meta, "kev_source", primary.get("kev_source"))
        _set_or_clear(meta, "kev_due_date", primary.get("kev_due_date"))
        return

    if external_requested:
        meta["kev_listed"] = False
        meta.pop("kev_source", None)
        meta.pop("kev_due_date", None)


def _clear_stale_cve_intelligence(meta: Dict[str, Any]) -> None:
    """Remove canonical CVE intelligence fields when no valid CVE remains."""
    meta.pop("cve_id", None)
    meta["cve_ids"] = []
    meta.pop("cve_intelligence_candidates", None)

    meta.pop("cvss", None)
    meta.pop("cvss_score", None)
    meta.pop("cvss_version", None)
    meta.pop("cvss_vector", None)
    meta.pop("cvss_source", None)

    meta.pop("epss_score", None)
    meta.pop("epss_percentile", None)
    meta.pop("epss_source", None)

    meta.pop("kev_listed", None)
    meta.pop("kev_source", None)
    meta.pop("kev_due_date", None)


def enrich_finding_with_vuln_intel(
    finding: Dict[str, Any],
    intelligence: VulnerabilityIntelligence,
    *,
    cvss_file: Optional[str] = None,
    epss_file: Optional[str] = None,
    kev_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Enrich a single finding with offline CVE intelligence."""
    meta = finding.get("meta")
    if not isinstance(meta, dict):
        meta = {}
        finding["meta"] = meta

    cve_ids = extract_cve_ids(finding)
    had_cve_fields = any(key in meta for key in ("cve_id", "cve_ids", "cve", "cve_intelligence_candidates"))
    if not cve_ids:
        if had_cve_fields:
            _clear_stale_cve_intelligence(meta)
        return finding

    meta["cve_ids"] = cve_ids

    candidates = _build_candidates(cve_ids, meta, intelligence)
    primary = _choose_primary_candidate(candidates)
    meta["cve_id"] = primary["cve_id"]
    meta["cve_intelligence_candidates"] = [
        {
            "cve_id": candidate["cve_id"],
            "cvss_score": candidate.get("cvss_score"),
            "cvss_version": candidate.get("cvss_version"),
            "cvss_vector": candidate.get("cvss_vector"),
            "cvss_source": candidate.get("cvss_source"),
            "epss_score": candidate.get("epss_score"),
            "epss_percentile": candidate.get("epss_percentile"),
            "epss_source": candidate.get("epss_source"),
            "kev_listed": bool(candidate.get("kev_listed")),
            "kev_source": candidate.get("kev_source"),
            "kev_due_date": candidate.get("kev_due_date"),
        }
        for candidate in candidates
    ]

    _apply_canonical_cvss(meta, primary)
    _apply_canonical_epss(meta, primary, external_requested=bool(epss_file))
    _apply_canonical_kev(meta, primary, external_requested=bool(kev_file))

    return finding


def enrich_findings_with_vuln_intel(
    findings: List[Dict[str, Any]],
    *,
    cvss_file: Optional[str] = None,
    epss_file: Optional[str] = None,
    kev_file: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Enrich all findings with offline CVE intelligence."""
    intelligence = load_vulnerability_intelligence(
        cvss_file=cvss_file,
        epss_file=epss_file,
        kev_file=kev_file,
    )

    for finding in findings:
        if isinstance(finding, dict):
            enrich_finding_with_vuln_intel(
                finding,
                intelligence,
                cvss_file=cvss_file,
                epss_file=epss_file,
                kev_file=kev_file,
            )
    return findings
