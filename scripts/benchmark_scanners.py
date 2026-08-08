#!/usr/bin/env python3
"""
Benchmark vuln-manager scanner runtime across targets/pages.

Examples:
  python3 scripts/benchmark_scanners.py --target https://example.com
  python3 scripts/benchmark_scanners.py --targets-file targets.txt --include-all
  python3 scripts/benchmark_scanners.py --targets-file targets.txt --scanners nuclei wapiti -- --no-dedupe
"""

from __future__ import annotations

import argparse
import csv
import json
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_SCANNERS = ("nmap", "nuclei", "wapiti", "nikto", "zap")
CSV_COLUMNS = (
    "target",
    "scanner",
    "started_at",
    "finished_at",
    "duration_seconds",
    "exit_code",
    "command",
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_z(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def read_targets(values: Iterable[str], targets_file: str | None) -> list[str]:
    targets: list[str] = []
    targets.extend(target.strip() for target in values if target.strip())

    if targets_file:
        path = Path(targets_file).expanduser()
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                target = line.strip()
                if not target or target.startswith("#"):
                    continue
                targets.append(target)

    deduped: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if target in seen:
            continue
        seen.add(target)
        deduped.append(target)
    return deduped


def normalize_extra_args(extra_args: list[str]) -> list[str]:
    if extra_args and extra_args[0] == "--":
        return extra_args[1:]
    return extra_args


def has_report_flag(args: list[str]) -> bool:
    return any(arg == "--report" or arg == "--no-report" for arg in args)


def build_command(
    *,
    python_executable: str,
    main_path: Path,
    target: str,
    scanner: str,
    extra_args: list[str],
    add_no_report: bool,
) -> list[str]:
    command = [
        python_executable,
        str(main_path),
        "--target",
        target,
        "--scanner",
        scanner,
    ]
    if add_no_report and not has_report_flag(extra_args):
        command.append("--no-report")
    command.extend(extra_args)
    return command


def run_one(command: list[str], *, target: str, scanner: str) -> dict[str, object]:
    started_at = utc_now()
    start = time.perf_counter()
    completed = subprocess.run(command, check=False)
    duration = time.perf_counter() - start
    finished_at = utc_now()

    return {
        "target": target,
        "scanner": scanner,
        "started_at": iso_z(started_at),
        "finished_at": iso_z(finished_at),
        "duration_seconds": f"{duration:.3f}",
        "exit_code": completed.returncode,
        "command": shlex.join(command),
    }


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        json.dump(rows, fh, indent=2)


def print_summary(rows: list[dict[str, object]]) -> None:
    print("\nTiming summary")
    print("-" * 72)
    print(f"{'scanner':<12} {'seconds':>10}  {'exit':>4}  target")
    for row in rows:
        print(
            f"{str(row['scanner']):<12} "
            f"{str(row['duration_seconds']):>10}  "
            f"{str(row['exit_code']):>4}  "
            f"{row['target']}"
        )


def parse_args() -> argparse.Namespace:
    project_root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(
        description="Run vuln-manager scanners against targets/pages and record elapsed time.",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="Target/page to benchmark. Can be provided multiple times.",
    )
    parser.add_argument(
        "--targets-file",
        help="Text file with one target/page per line. Empty lines and # comments are ignored.",
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        default=list(DEFAULT_SCANNERS),
        help="Scanner names to run individually. Default: nmap nuclei wapiti nikto zap.",
    )
    parser.add_argument(
        "--include-all",
        action="store_true",
        help="Also run one --scanner all project orchestration per target.",
    )
    parser.add_argument(
        "--only-all",
        action="store_true",
        help="Only run --scanner all project orchestration per target.",
    )
    parser.add_argument(
        "--output",
        default="data/scanner_timings.csv",
        help="CSV output path. Default: data/scanner_timings.csv.",
    )
    parser.add_argument(
        "--json-output",
        help="Optional JSON output path for the same timing rows.",
    )
    parser.add_argument(
        "--project-root",
        default=str(project_root),
        help="Project root containing main.py. Defaults to this script's parent repo.",
    )
    parser.add_argument(
        "--python",
        default=sys.executable,
        help="Python executable used to run main.py.",
    )
    parser.add_argument(
        "--include-report",
        dest="add_no_report",
        action="store_false",
        default=True,
        help="Do not automatically add --no-report to scanner runs.",
    )
    parser.add_argument(
        "--stop-on-failure",
        action="store_true",
        help="Stop benchmarking after the first non-zero scanner exit code.",
    )
    parser.add_argument(
        "main_args",
        nargs=argparse.REMAINDER,
        help="Extra arguments passed to main.py after --, for example: -- --scan-mode manual --ports 80,443",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    targets = read_targets(args.target, args.targets_file)
    if not targets:
        print("Provide at least one --target or --targets-file.", file=sys.stderr)
        return 2

    project_root = Path(args.project_root).expanduser().resolve()
    main_path = project_root / "main.py"
    if not main_path.exists():
        print(f"main.py was not found at: {main_path}", file=sys.stderr)
        return 2

    extra_args = normalize_extra_args(args.main_args)
    scanners = ["all"] if args.only_all else list(args.scanners)
    if args.include_all and "all" not in scanners:
        scanners.append("all")

    rows: list[dict[str, object]] = []
    for target in targets:
        for scanner in scanners:
            command = build_command(
                python_executable=args.python,
                main_path=main_path,
                target=target,
                scanner=scanner,
                extra_args=extra_args,
                add_no_report=args.add_no_report,
            )
            print(f"\n[*] Benchmarking {scanner} on {target}")
            row = run_one(command, target=target, scanner=scanner)
            rows.append(row)
            print(
                f"[+] {scanner} on {target}: "
                f"{row['duration_seconds']}s (exit {row['exit_code']})"
            )
            if args.stop_on_failure and row["exit_code"] != 0:
                write_csv(Path(args.output), rows)
                if args.json_output:
                    write_json(Path(args.json_output), rows)
                print_summary(rows)
                return int(row["exit_code"])

    output_path = Path(args.output)
    write_csv(output_path, rows)
    if args.json_output:
        write_json(Path(args.json_output), rows)

    print_summary(rows)
    print(f"\n[+] Timing CSV saved to: {output_path}")
    if args.json_output:
        print(f"[+] Timing JSON saved to: {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
