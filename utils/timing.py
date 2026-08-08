"""
Workflow timing helpers for scan runs.

Timing data is stored as a sidecar artifact so exported scanner results can
keep their existing public schema.
"""

from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, TextIO


def utc_now_z() -> str:
    """Return the current UTC time as an ISO-8601 string ending in Z."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass
class TimingHandle:
    """In-progress timing state for one stage."""

    stage: str
    start_time: str
    start_perf: float
    note: str = ""


class WorkflowTimer:
    """Collect ordered timing records for one workflow."""

    def __init__(self) -> None:
        self.records: list[Dict[str, Any]] = []

    def start(self, stage: str, note: str = "") -> TimingHandle:
        return TimingHandle(
            stage=stage,
            start_time=utc_now_z(),
            start_perf=time.perf_counter(),
            note=note,
        )

    def finish(
        self,
        handle: TimingHandle,
        *,
        status: str = "success",
        note: Optional[str] = None,
    ) -> Dict[str, Any]:
        end_perf = time.perf_counter()
        record = {
            "stage": handle.stage,
            "start_time": handle.start_time,
            "end_time": utc_now_z(),
            "duration_seconds": round(max(0.0, end_perf - handle.start_perf), 6),
            "status": status,
            "note": handle.note if note is None else note,
        }
        self.records.append(record)
        return record

    def record_skipped(self, stage: str, note: str = "") -> Dict[str, Any]:
        handle = self.start(stage, note)
        return self.finish(handle, status="skipped", note=note)

    def has_stage(self, stage: str) -> bool:
        return any(record.get("stage") == stage for record in self.records)

    def to_payload(
        self,
        *,
        target: str,
        run_folder: Optional[Path] = None,
    ) -> Dict[str, Any]:
        statuses: Dict[str, int] = {}
        for record in self.records:
            status = str(record.get("status") or "unknown")
            statuses[status] = statuses.get(status, 0) + 1

        total_record = next(
            (record for record in reversed(self.records) if record.get("stage") == "total_workflow"),
            None,
        )
        return {
            "target": target,
            "run_id": run_folder.name if run_folder is not None else None,
            "run_folder": str(run_folder) if run_folder is not None else None,
            "generated_at": utc_now_z(),
            "summary": {
                "stage_count": len(self.records),
                "statuses": statuses,
                "total_duration_seconds": (
                    total_record.get("duration_seconds") if total_record else None
                ),
            },
            "stages": list(self.records),
        }


def _write_json(path: Path, payload: Dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def save_timing_payload(
    payload: Dict[str, Any],
    *,
    run_folder: Path,
    target_slug: str,
    reports_dir: Path = Path("reports"),
) -> list[Path]:
    """
    Save timing.json in the active run folder and in reports/<target>/<run_id>/.

    The active run folder preserves the existing project layout. The reports
    copy satisfies the diploma/reporting artifact path without moving any other
    scan outputs.
    """
    paths = [_write_json(run_folder / "timing.json", payload)]

    reports_path = reports_dir / target_slug / run_folder.name / "timing.json"
    try:
        same_path = reports_path.resolve() == paths[0].resolve()
    except OSError:
        same_path = False
    if not same_path:
        paths.append(_write_json(reports_path, payload))

    return paths


def print_timing_summary(payload: Dict[str, Any], *, file: Optional[TextIO] = None) -> None:
    """Print a compact timing table for terminal users."""
    stream = file or sys.stdout
    records = payload.get("stages") if isinstance(payload, dict) else []
    if not isinstance(records, list) or not records:
        return

    print("\nTIMING SUMMARY", file=stream)
    print("=" * 72, file=stream)
    print(f"{'Stage':<20} {'Status':<10} {'Seconds':>10}  Note", file=stream)
    print("-" * 72, file=stream)
    for record in records:
        if not isinstance(record, dict):
            continue
        stage = str(record.get("stage") or "")
        status = str(record.get("status") or "")
        seconds = record.get("duration_seconds")
        note = str(record.get("note") or "")
        print(f"{stage:<20} {status:<10} {seconds!s:>10}  {note}", file=stream)
    print("=" * 72, file=stream)


def missing_scanner_stages(
    active_scanners: Iterable[str],
    records: Iterable[Dict[str, Any]],
) -> list[str]:
    """Return active scanner names that did not produce timing records."""
    present = {
        str(record.get("stage"))
        for record in records
        if isinstance(record, dict)
    }
    return [
        scanner
        for scanner in active_scanners
        if scanner in {"nmap", "nikto", "nuclei", "wapiti", "zap"} and scanner not in present
    ]
