"""
Scanner vulnerability metadata synchronization.

The project normalizes scanner findings into one shared schema. This module
maps those findings into a YAML-backed common knowledge store while
preserving source identity per scanner record.
"""

from __future__ import annotations

import csv
import hashlib
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from utils.unified_vuln_db import (
    UnifiedVulnerabilityDatabase,
    UnifiedVulnerabilityRecord,
    utcnow_iso,
)


def _meta(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return finding metadata as a dict."""
    meta = finding.get("meta", {})
    return meta if isinstance(meta, dict) else {}


def _first_string(*values: Any) -> str:
    """Return the first non-empty string from the candidates."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return ""


def _string_list(value: Any) -> List[str]:
    """Normalize one-or-many string values into a list."""
    if value is None:
        return []
    if isinstance(value, list):
        items = value
    else:
        items = [value]
    normalized: List[str] = []
    seen: set[str] = set()
    for item in items:
        text = str(item).strip() if item is not None else ""
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def _stable_hash(parts: Iterable[Any]) -> str:
    """Return a short stable hash from arbitrary scalar parts."""
    text = "::".join(str(part).strip() for part in parts if part is not None)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def load_json_records(path: str | Path) -> List[Dict[str, Any]]:
    """Load a JSON array or object-wrapped records list."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        records = data.get("records")
        if isinstance(records, list):
            return [item for item in records if isinstance(item, dict)]
        return [data]
    return []


def load_jsonl_records(path: str | Path) -> List[Dict[str, Any]]:
    """Load newline-delimited JSON objects."""
    records: List[Dict[str, Any]] = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text:
            continue
        payload = json.loads(text)
        if isinstance(payload, dict):
            records.append(payload)
    return records


def load_csv_records(path: str | Path) -> List[Dict[str, Any]]:
    """Load a CSV file into a list of record dicts."""
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return [dict(row) for row in csv.DictReader(handle)]


def load_xml_records(path: str | Path, record_tag: str = "record") -> List[Dict[str, Any]]:
    """Load XML entries into a simple dict-per-record form."""
    root = ET.fromstring(Path(path).read_text(encoding="utf-8"))
    records: List[Dict[str, Any]] = []
    for node in root.findall(f".//{record_tag}"):
        record: Dict[str, Any] = {}
        for child in list(node):
            if child.text and child.text.strip():
                record[child.tag] = child.text.strip()
        if record:
            records.append(record)
    return records


class FindingKnowledgeAdapter:
    """Base adapter for mapping normalized findings into knowledge records."""

    scanner_name = "generic"

    def build_record(self, finding: Dict[str, Any], *, sync_timestamp: str) -> UnifiedVulnerabilityRecord:
        """Convert one normalized finding into the unified knowledge schema."""
        meta = _meta(finding)
        return UnifiedVulnerabilityRecord(
            scanner_name=self.scanner_name,
            source_vulnerability_id=self.source_vulnerability_id(finding),
            title=str(finding.get("vulnerability_name") or "").strip(),
            description=str(finding.get("description") or "").strip(),
            severity=str(finding.get("severity") or "info").strip().lower() or "info",
            cvss=self.cvss(finding),
            cve_list=self.cves(finding),
            cwe_list=self.cwes(finding),
            category=self.category(finding),
            remediation=str(finding.get("remediation") or "").strip(),
            references=self.references(finding),
            technology=self.technology(finding),
            affected_target_type=self.affected_target_type(finding),
            raw_source_payload=finding,
            source_update_timestamp=_first_string(meta.get("timestamp"), sync_timestamp) or sync_timestamp,
            last_synced_timestamp=sync_timestamp,
        )

    def source_vulnerability_id(self, finding: Dict[str, Any]) -> str:
        """Return the scanner's own record identifier, or a stable derived key."""
        meta = _meta(finding)
        raw_id = _first_string(
            meta.get("plugin_id"),
            meta.get("template_id"),
            meta.get("check_id"),
            meta.get("raw_id"),
            meta.get("osvdb_id"),
            meta.get("cve_id"),
        )
        if raw_id:
            return raw_id
        return f"derived-{_stable_hash(self.identity_parts(finding))}"

    def identity_parts(self, finding: Dict[str, Any]) -> List[Any]:
        """Return fallback identity parts for records without a native source id."""
        meta = _meta(finding)
        return [
            self.scanner_name,
            finding.get("vulnerability_name"),
            meta.get("category"),
            meta.get("module"),
            meta.get("service"),
            meta.get("path"),
        ]

    def cvss(self, finding: Dict[str, Any]) -> Optional[float]:
        """Return the canonical CVSS score if present."""
        meta = _meta(finding)
        value = meta.get("cvss_score", meta.get("cvss"))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        return None

    def cves(self, finding: Dict[str, Any]) -> List[str]:
        """Return all known CVE identifiers."""
        meta = _meta(finding)
        values = _string_list(meta.get("cve_ids"))
        primary = _first_string(meta.get("cve_id"))
        if primary and primary not in values:
            values.insert(0, primary)
        return values

    def cwes(self, finding: Dict[str, Any]) -> List[str]:
        """Return all known CWE identifiers."""
        meta = _meta(finding)
        values = _string_list(meta.get("cwe_list"))
        primary = _first_string(meta.get("cwe"))
        if primary and primary not in values:
            values.insert(0, primary)
        return values

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        """Return a coarse vulnerability category if the scanner provides one."""
        meta = _meta(finding)
        return _first_string(meta.get("category")) or None

    def references(self, finding: Dict[str, Any]) -> List[str]:
        """Return reference URLs/identifiers attached to the source finding."""
        meta = _meta(finding)
        references = _string_list(meta.get("references"))
        reference = _first_string(meta.get("reference"))
        if reference and reference not in references:
            references.insert(0, reference)
        top_level_references = _string_list(finding.get("references"))
        for item in top_level_references:
            if item not in references:
                references.append(item)
        return references

    def technology(self, finding: Dict[str, Any]) -> Optional[str]:
        """Return the affected technology/service when available."""
        meta = _meta(finding)
        return _first_string(meta.get("service"), meta.get("technology")) or None

    def affected_target_type(self, finding: Dict[str, Any]) -> Optional[str]:
        """Return a normalized target type label."""
        meta = _meta(finding)
        if meta.get("path") or meta.get("parameter") or meta.get("scheme"):
            return "web_endpoint"
        if meta.get("service") or meta.get("port") or meta.get("protocol"):
            return "network_service"
        return "host"

    def records_from_findings(
        self,
        findings: Iterable[Dict[str, Any]],
        *,
        sync_timestamp: str,
) -> Iterator[UnifiedVulnerabilityRecord]:
        """Yield unified store records for a sequence of normalized findings."""
        for finding in findings:
            if isinstance(finding, dict):
                yield self.build_record(finding, sync_timestamp=sync_timestamp)


class NucleiKnowledgeAdapter(FindingKnowledgeAdapter):
    scanner_name = "nuclei"

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        tags = meta.get("tags")
        if isinstance(tags, list) and tags:
            return _first_string(tags[0]) or None
        return super().category(finding)


class ZapKnowledgeAdapter(FindingKnowledgeAdapter):
    scanner_name = "zap"

    def source_vulnerability_id(self, finding: Dict[str, Any]) -> str:
        meta = _meta(finding)
        plugin_id = _first_string(meta.get("plugin_id"), meta.get("raw_id"))
        if plugin_id:
            return plugin_id
        return f"derived-{_stable_hash(self.identity_parts(finding))}"

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        return _first_string(meta.get("cwe"), meta.get("risk")) or None


class WapitiKnowledgeAdapter(FindingKnowledgeAdapter):
    scanner_name = "wapiti"

    def source_vulnerability_id(self, finding: Dict[str, Any]) -> str:
        meta = _meta(finding)
        raw_id = _first_string(meta.get("check_id"), meta.get("raw_id"))
        if raw_id:
            return raw_id
        category = _first_string(meta.get("category"))
        module = _first_string(meta.get("module"))
        if category or module:
            return "::".join(part for part in (category, module) if part)
        return f"derived-{_stable_hash(self.identity_parts(finding))}"

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        return _first_string(meta.get("category"), meta.get("module")) or None


class NiktoKnowledgeAdapter(FindingKnowledgeAdapter):
    scanner_name = "nikto"

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        return _first_string(meta.get("osvdb_id")) or None


class NmapKnowledgeAdapter(FindingKnowledgeAdapter):
    scanner_name = "nmap"

    def source_vulnerability_id(self, finding: Dict[str, Any]) -> str:
        meta = _meta(finding)
        raw_id = _first_string(meta.get("cve_id"), meta.get("raw_id"))
        if raw_id:
            return raw_id
        return f"derived-{_stable_hash(self.identity_parts(finding))}"

    def category(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        return _first_string(meta.get("service"), meta.get("protocol")) or None

    def technology(self, finding: Dict[str, Any]) -> Optional[str]:
        meta = _meta(finding)
        return _first_string(meta.get("service"), meta.get("service_version")) or None


_ADAPTERS = {
    "nuclei": NucleiKnowledgeAdapter(),
    "zap": ZapKnowledgeAdapter(),
    "wapiti": WapitiKnowledgeAdapter(),
    "nikto": NiktoKnowledgeAdapter(),
    "nmap": NmapKnowledgeAdapter(),
}


def get_knowledge_adapter(scanner_name: str) -> FindingKnowledgeAdapter:
    """Return the registered knowledge adapter for a scanner."""
    scanner = str(scanner_name or "").strip().lower()
    adapter = _ADAPTERS.get(scanner)
    if adapter is not None:
        return adapter
    fallback = FindingKnowledgeAdapter()
    fallback.scanner_name = scanner or "generic"
    return fallback


def iter_original_findings(findings: Iterable[Dict[str, Any]]) -> Iterator[Dict[str, Any]]:
    """Yield original source findings, unwrapping merged findings when present."""
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        source_findings = finding.get("source_findings")
        if isinstance(source_findings, list) and source_findings:
            for source in source_findings:
                if isinstance(source, dict):
                    yield source
            continue
        yield finding


def sync_findings_to_knowledge_db(
    findings: Iterable[Dict[str, Any]],
    database: UnifiedVulnerabilityDatabase,
    *,
    sync_timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """Upsert normalized findings into the unified vulnerability knowledge store."""
    sync_time = sync_timestamp or utcnow_iso()
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for finding in iter_original_findings(findings):
        meta = _meta(finding)
        scanner = _first_string(meta.get("scanner")).lower()
        if scanner:
            grouped[scanner].append(finding)

    by_scanner: Dict[str, Dict[str, Any]] = {}
    totals = {
        "total_imported": 0,
        "total_updated": 0,
        "total_skipped": 0,
    }

    for scanner_name, scanner_findings in sorted(grouped.items()):
        adapter = get_knowledge_adapter(scanner_name)
        records = list(adapter.records_from_findings(scanner_findings, sync_timestamp=sync_time))
        stats = database.upsert_knowledge_records(
            records,
            scanner_source_name=scanner_name,
            sync_timestamp=sync_time,
        )
        by_scanner[scanner_name] = stats
        for key in totals:
            totals[key] += int(stats.get(key, 0))

    return {
        "sync_timestamp": sync_time,
        "by_scanner": by_scanner,
        **totals,
    }
