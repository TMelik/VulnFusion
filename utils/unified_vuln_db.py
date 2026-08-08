"""
Unified vulnerability knowledge and comparison storage.

This module provides a lightweight YAML-backed store for JSON-compatible records:
- scanner vulnerability metadata synced into one common schema
- LLM duplicate-comparison cache and trace records
"""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import yaml


STORE_VERSION = 1


def utcnow_iso() -> str:
    """Return the current UTC timestamp in stable ISO 8601 form."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_dumps(value: Any) -> str:
    """Serialize structured values to stable JSON text for hashing."""
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def _normalize_strings(values: Iterable[Any]) -> List[str]:
    """Return first-seen non-empty string values."""
    normalized: List[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip() if value is not None else ""
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def _sha256_json(payload: Dict[str, Any]) -> str:
    """Hash a dict through canonical JSON serialization."""
    return hashlib.sha256(_json_dumps(payload).encode("utf-8")).hexdigest()


def _sorted_copy(records: List[Dict[str, Any]], *, keys: List[str]) -> List[Dict[str, Any]]:
    """Return a stable sorted deep copy of a list of dict records."""
    return sorted(
        (copy.deepcopy(record) for record in records if isinstance(record, dict)),
        key=lambda record: tuple(str(record.get(key) or "") for key in keys),
    )


@dataclass(frozen=True)
class UnifiedVulnerabilityRecord:
    """One scanner metadata record in the unified vulnerability database."""

    scanner_name: str
    source_vulnerability_id: str
    title: str
    description: str = ""
    severity: str = "info"
    cvss: Optional[float] = None
    cve_list: List[str] = field(default_factory=list)
    cwe_list: List[str] = field(default_factory=list)
    category: Optional[str] = None
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    technology: Optional[str] = None
    affected_target_type: Optional[str] = None
    raw_source_payload: Any = None
    source_update_timestamp: Optional[str] = None
    last_synced_timestamp: Optional[str] = None

    def normalized(self, *, sync_timestamp: Optional[str] = None) -> "UnifiedVulnerabilityRecord":
        """Return a copy with normalized lists and sync timestamp filled."""
        return UnifiedVulnerabilityRecord(
            scanner_name=str(self.scanner_name).strip().lower(),
            source_vulnerability_id=str(self.source_vulnerability_id).strip(),
            title=str(self.title or "").strip(),
            description=str(self.description or "").strip(),
            severity=str(self.severity or "info").strip().lower() or "info",
            cvss=float(self.cvss) if isinstance(self.cvss, (int, float)) else None,
            cve_list=_normalize_strings(self.cve_list),
            cwe_list=_normalize_strings(self.cwe_list),
            category=(str(self.category).strip() if self.category else None) or None,
            remediation=str(self.remediation or "").strip(),
            references=_normalize_strings(self.references),
            technology=(str(self.technology).strip() if self.technology else None) or None,
            affected_target_type=(
                str(self.affected_target_type).strip()
                if self.affected_target_type else None
            ) or None,
            raw_source_payload=self.raw_source_payload,
            source_update_timestamp=self.source_update_timestamp or sync_timestamp,
            last_synced_timestamp=self.last_synced_timestamp or sync_timestamp,
        )

    def content_hash(self) -> str:
        """Return a stable hash of the vulnerability metadata content."""
        payload = asdict(self.normalized())
        payload.pop("last_synced_timestamp", None)
        return _sha256_json(payload)


class UnifiedVulnerabilityDatabase:
    """YAML file store for unified vulnerability knowledge and LLM comparison cache."""

    def __init__(self, path: str | Path):
        self.path = str(path)
        self._in_memory = self.path == ":memory:"
        self._memory_store = self._empty_store()
        if not self._in_memory:
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    @staticmethod
    def _empty_store() -> Dict[str, Any]:
        """Return the normalized empty YAML document."""
        return {
            "version": STORE_VERSION,
            "vulnerability_knowledge": [],
            "knowledge_sync_runs": [],
            "llm_duplicate_comparisons": [],
        }

    def _normalize_store(self, payload: Any) -> Dict[str, Any]:
        """Normalize a loaded YAML payload into the expected document shape."""
        normalized = self._empty_store()
        if isinstance(payload, dict):
            version = payload.get("version")
            if isinstance(version, int) and version > 0:
                normalized["version"] = version
            for key in ("vulnerability_knowledge", "knowledge_sync_runs", "llm_duplicate_comparisons"):
                value = payload.get(key)
                if isinstance(value, list):
                    normalized[key] = [copy.deepcopy(item) for item in value if isinstance(item, dict)]

        normalized["vulnerability_knowledge"] = _sorted_copy(
            normalized["vulnerability_knowledge"],
            keys=["scanner_name", "source_vulnerability_id"],
        )
        normalized["llm_duplicate_comparisons"] = _sorted_copy(
            normalized["llm_duplicate_comparisons"],
            keys=["cache_key"],
        )
        return normalized

    def _read_store(self) -> Dict[str, Any]:
        """Load and normalize the YAML store from disk or memory."""
        if self._in_memory:
            return copy.deepcopy(self._memory_store)

        path = Path(self.path).expanduser()
        if not path.exists():
            return self._empty_store()

        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Knowledge DB is not valid UTF-8 YAML: {self.path}") from exc

        if not text.strip():
            return self._empty_store()

        try:
            payload = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ValueError(f"Knowledge DB is not valid YAML: {self.path}") from exc
        return self._normalize_store(payload)

    def _write_store(self, store: Dict[str, Any]) -> None:
        """Write the normalized YAML document atomically."""
        normalized = self._normalize_store(store)
        if self._in_memory:
            self._memory_store = normalized
            return

        path = Path(self.path).expanduser()
        temp_path = path.with_name(f"{path.name}.tmp")
        text = yaml.safe_dump(
            normalized,
            sort_keys=False,
            allow_unicode=False,
            default_flow_style=False,
        )
        temp_path.write_text(text, encoding="utf-8")
        temp_path.replace(path)

    def _initialize(self) -> None:
        """Ensure the YAML document exists with the expected top-level sections."""
        self._write_store(self._read_store())

    def upsert_knowledge_records(
        self,
        records: Iterable[UnifiedVulnerabilityRecord],
        *,
        scanner_source_name: str,
        sync_timestamp: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Insert or update scanner metadata records and return sync statistics."""
        sync_time = sync_timestamp or utcnow_iso()
        imported = 0
        updated = 0
        skipped = 0

        store = self._read_store()
        knowledge_records = store["vulnerability_knowledge"]
        index = {
            (str(record.get("scanner_name") or ""), str(record.get("source_vulnerability_id") or "")): idx
            for idx, record in enumerate(knowledge_records)
            if isinstance(record, dict)
        }

        for raw_record in records:
            record = raw_record.normalized(sync_timestamp=sync_time)
            content_hash = record.content_hash()
            record_payload = asdict(record)
            record_key = (record.scanner_name, record.source_vulnerability_id)
            existing_index = index.get(record_key)

            if existing_index is None:
                knowledge_records.append(
                    {
                        **record_payload,
                        "content_hash": content_hash,
                        "created_at": sync_time,
                        "updated_at": sync_time,
                    }
                )
                index[record_key] = len(knowledge_records) - 1
                imported += 1
                continue

            existing = knowledge_records[existing_index]
            if str(existing.get("content_hash") or "") == content_hash:
                existing["last_synced_timestamp"] = record.last_synced_timestamp or sync_time
                existing["updated_at"] = sync_time
                skipped += 1
                continue

            knowledge_records[existing_index] = {
                **record_payload,
                "content_hash": content_hash,
                "created_at": existing.get("created_at") or sync_time,
                "updated_at": sync_time,
            }
            updated += 1

        store["knowledge_sync_runs"].append(
            {
                "scanner_source_name": str(scanner_source_name).strip().lower(),
                "sync_timestamp": sync_time,
                "total_imported": imported,
                "total_updated": updated,
                "total_skipped": skipped,
            }
        )
        self._write_store(store)

        return {
            "scanner_source_name": str(scanner_source_name).strip().lower(),
            "sync_timestamp": sync_time,
            "total_imported": imported,
            "total_updated": updated,
            "total_skipped": skipped,
        }

    def list_knowledge_records(self, *, scanner_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return stored vulnerability knowledge records for inspection/tests."""
        records = self._read_store()["vulnerability_knowledge"]
        if scanner_name:
            wanted = str(scanner_name).strip().lower()
            records = [record for record in records if str(record.get("scanner_name") or "") == wanted]
        return _sorted_copy(records, keys=["scanner_name", "source_vulnerability_id"])

    def list_sync_runs(self) -> List[Dict[str, Any]]:
        """Return recorded knowledge sync runs."""
        return [copy.deepcopy(run) for run in self._read_store()["knowledge_sync_runs"]]

    def get_llm_comparison(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Return one cached LLM comparison record when present."""
        wanted = str(cache_key)
        for record in self._read_store()["llm_duplicate_comparisons"]:
            if str(record.get("cache_key") or "") != wanted:
                continue
            payload = copy.deepcopy(record)
            payload["same_target"] = bool(payload.get("same_target"))
            return payload
        return None

    def save_llm_comparison(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Insert or update an LLM comparison trace/cache record."""
        now = utcnow_iso()
        store = self._read_store()
        comparisons = store["llm_duplicate_comparisons"]
        payload = copy.deepcopy(record)
        payload["same_target"] = bool(payload.get("same_target"))
        payload["created_at"] = payload.get("created_at") or now
        payload["updated_at"] = now

        cache_key = str(payload.get("cache_key") or "")
        for idx, existing in enumerate(comparisons):
            if str(existing.get("cache_key") or "") != cache_key:
                continue
            payload["created_at"] = existing.get("created_at") or payload["created_at"]
            comparisons[idx] = payload
            self._write_store(store)
            return copy.deepcopy(payload)

        comparisons.append(payload)
        self._write_store(store)
        return copy.deepcopy(payload)

    def list_llm_comparisons(self) -> List[Dict[str, Any]]:
        """Return all stored LLM comparison rows for tests/debugging."""
        rows = self._read_store()["llm_duplicate_comparisons"]
        results = _sorted_copy(rows, keys=["cache_key"])
        for row in results:
            row["same_target"] = bool(row.get("same_target"))
        return results
