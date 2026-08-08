#!/usr/bin/env python3
"""
Integration Demo - Vulnerability Scanner Pipeline

Demonstrates the complete thesis-ready pipeline:
1. Runs baseline scan
2. Runs second scan with comparison
3. Applies LLM duplicate resolution and comparison in the same order as the main CLI
4. Shows NEW, PERSISTENT, CHANGED, FIXED findings
5. Generates complete run folder with both JSON files

Usage:
    python demo_integration.py --target example.com

Requirements:
    - At least one scanner installed (nuclei recommended)
    - Target should be accessible
"""

import sys
import argparse
import os
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from utils.env_loader import load_project_dotenv

load_project_dotenv()

from orchestrator import create_default_orchestrator
from utils.export_sanitizer import sanitize_results_for_export
from utils.schema import SCHEMA_VERSION, assert_valid_results
from utils.comparator import add_comparison_to_results
from utils.llm_duplicate_resolver import (
    LLMDuplicateConfig,
    LLMDuplicateResolver,
    resolve_llm_duplicate_provider_settings,
)
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase


def _wrap_single_scanner_results(orchestrator, scanner_name: str, target: str, scan_results: dict) -> dict:
    """Wrap run_scanner() output into the results envelope used by the pipeline."""
    scanner_obj = orchestrator.scanners.get(scanner_name)
    try:
        scanner_version = scanner_obj.get_version() if scanner_obj else None
    except Exception:
        scanner_version = None

    findings = scan_results.get('findings', [])
    return {
        'schema_version': SCHEMA_VERSION,
        'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        'target': target,
        'timestamp': scan_results.get('timestamp'),
        'scanners_run': [scanner_name],
        'errors': ([{
            'scanner': scanner_name,
            'error': scan_results['error']
        }] if scan_results.get('error') else []),
        'tool_versions': {scanner_name: scanner_version},
        'all_findings': findings,
        'findings_by_scanner': {scanner_name: findings},
        'summary': {
            'total_findings': len(findings),
            'by_severity': orchestrator._count_by_severity(findings)
        }
    }

def print_banner(text):
    """Print formatted banner."""
    print(f"\n{'='*70}")
    print(f"{text:^70}")
    print(f"{'='*70}\n")

def print_findings_summary(results):
    """Print summary of findings."""
    all_findings = results.get('all_findings', [])

    status_counts = {'NEW': 0, 'PERSISTENT': 0, 'CHANGED': 0, 'FIXED': 0}
    for finding in all_findings:
        status = finding.get('status', 'NEW')
        status_counts[status] = status_counts.get(status, 0) + 1

    sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for finding in all_findings:
        sev = finding.get('severity', 'info')
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    print(f"Total Findings: {len(all_findings)}")
    print(f"\nBy Status:")
    for status, count in status_counts.items():
        if count > 0:
            print(f"  {status:12s}: {count}")

    print(f"\nBy Severity:")
    for sev, count in sev_counts.items():
        if count > 0:
            print(f"  {sev.capitalize():12s}: {count}")

def show_changed_findings(results):
    """Show details of changed findings."""
    changed = results.get('changed_findings', [])

    if not changed:
        print("\nNo changed findings")
        return

    print(f"\nChanged Findings ({len(changed)}):")
    print("-" * 70)

    for i, finding in enumerate(changed, 1):
        print(f"\n{i}. {finding.get('vulnerability_name')}")
        print(f"   Asset: {finding.get('asset_id')}")

        changed_fields = finding.get('changed_fields', [])
        if changed_fields:
            print(f"   Changed fields: {', '.join(str(field) for field in changed_fields)}")


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable with a safe default."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _default_duplicate_mode() -> str:
    """Choose the duplicate mode from environment-aware defaults."""
    env_mode = str(os.getenv('VULN_MANAGER_DUPLICATE_MODE') or '').strip().lower()
    if env_mode in {'llm', 'off'}:
        return env_mode
    if (
        os.getenv('VULN_MANAGER_LLM_API_URL')
        and os.getenv('VULN_MANAGER_LLM_API_KEY')
        and os.getenv('VULN_MANAGER_LLM_MODEL')
    ):
        return 'llm'
    return 'off'


def _build_duplicate_config(args: argparse.Namespace) -> LLMDuplicateConfig:
    """Build duplicate-resolution config for the integration demo."""
    timeout_seconds = (
        args.llm_timeout
        if args.llm_timeout is not None
        else float(os.getenv('VULN_MANAGER_LLM_TIMEOUT', '15'))
    )
    provider_settings = resolve_llm_duplicate_provider_settings(
        cli_api_url=args.llm_api_url,
        cli_api_key=args.llm_api_key,
        cli_model_name=args.llm_model,
        env=os.environ,
    )
    return LLMDuplicateConfig(
        mode=args.duplicate_mode or _default_duplicate_mode(),
        api_url=provider_settings["api_url"],
        api_key=provider_settings["api_key"],
        model_name=provider_settings["model_name"],
        timeout_seconds=float(timeout_seconds),
        debug=args.llm_debug or _env_bool('VULN_MANAGER_LLM_DEBUG', False),
        cache_enabled=(False if args.no_llm_cache else _env_bool('VULN_MANAGER_LLM_CACHE_ENABLED', True)),
    )

def main():
    parser = argparse.ArgumentParser(description="Integration Demo - Vulnerability Scanner")
    parser.add_argument('--target', required=True, help='Target to scan (e.g., example.com)')
    parser.add_argument('--scanner', choices=['nmap', 'nuclei', 'wapiti', 'nikto', 'zap', 'all'], default='all', help='Scanner to use (default: all)')
    parser.add_argument('--data-dir', default='demo_data', help='Data directory (default: demo_data)')
    parser.add_argument('--duplicate-mode', choices=['llm', 'off'], default=None, help='Active duplicate-handling mode for the demo (default: auto from environment)')
    parser.add_argument('--llm-api-url', help='OpenAI-compatible chat completions endpoint used for duplicate decisions')
    parser.add_argument('--llm-api-key', help='API key for the configured LLM duplicate endpoint')
    parser.add_argument('--llm-model', help='Model name sent to the configured LLM duplicate endpoint')
    parser.add_argument('--llm-timeout', type=float, help='Timeout in seconds for one LLM duplicate request')
    parser.add_argument('--llm-debug', action='store_true', help='Store raw LLM duplicate responses in trace records')
    parser.add_argument('--no-llm-cache', action='store_true', help='Disable reuse of cached LLM duplicate decisions')
    parser.add_argument('--knowledge-db', help='Path to the YAML store used for LLM duplicate-resolution cache data')

    args = parser.parse_args()

    print_banner("INTEGRATION DEMO - VULNERABILITY SCANNER PIPELINE")

    data_dir = Path(args.data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)

    orchestrator = create_default_orchestrator(reports_dir=data_dir)
    duplicate_config = _build_duplicate_config(args)
    validation_error = duplicate_config.validation_error()
    if validation_error:
        parser.error(validation_error)
    knowledge_db_path = (
        Path(args.knowledge_db).expanduser()
        if args.knowledge_db else Path(
            os.getenv('VULN_MANAGER_KNOWLEDGE_DB')
            or (data_dir / 'unified_vulnerabilities.yaml')
        )
    )
    knowledge_db = UnifiedVulnerabilityDatabase(knowledge_db_path)

    print_banner("RUN 1: BASELINE SCAN")

    print(f"[*] Scanning {args.target} (baseline)...")

    if args.scanner == 'all':
        results1 = orchestrator.run_all(args.target)
    else:
        results1 = orchestrator.run_scanner(args.scanner, args.target)
        if 'findings' in results1:
            results1 = _wrap_single_scanner_results(orchestrator, args.scanner, args.target, results1)

    print("[*] Processing findings (LLM duplicate resolution)...")
    results1 = LLMDuplicateResolver(duplicate_config, database=knowledge_db).apply(results1)
    results1 = sanitize_results_for_export(results1)

    # Stamp final metadata, validate, then persist (save_results does not auto-fill).
    results1['schema_version'] = SCHEMA_VERSION
    results1['generated_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    assert_valid_results(results1, stage='final')
    normalized_path1 = orchestrator.save_results(results1)

    print(f"[+] Baseline scan complete")
    print(f"[+] Results saved to: {orchestrator.current_run_folder}")
    print_findings_summary(results1)

    print_banner("RUN 2: COMPARISON SCAN")

    orchestrator.current_run_folder = None

    print(f"[*] Scanning {args.target} (comparison)...")

    if args.scanner == 'all':
        results2 = orchestrator.run_all(args.target)
    else:
        results2 = orchestrator.run_scanner(args.scanner, args.target)
        if 'findings' in results2:
            results2 = _wrap_single_scanner_results(orchestrator, args.scanner, args.target, results2)

    results2 = LLMDuplicateResolver(duplicate_config, database=knowledge_db).apply(results2)
    print("[*] Comparing with baseline...")
    results2 = add_comparison_to_results(results2, data_dir)
    print("[*] Processing findings (LLM duplicate resolution, compare)...")
    results2 = sanitize_results_for_export(results2)

    # Stamp final metadata, validate, then persist (save_results does not auto-fill).
    results2['schema_version'] = SCHEMA_VERSION
    results2['generated_at'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
    assert_valid_results(results2, stage='final')
    normalized_path2 = orchestrator.save_results(results2)

    print(f"[+] Comparison scan complete")
    print(f"[+] Results saved to: {orchestrator.current_run_folder}")
    print_findings_summary(results2)

    show_changed_findings(results2)

    print_banner("INTEGRATION DEMO COMPLETE")

    print("Run Folders Created:")
    print(f"  Baseline:   {normalized_path1.parent}")
    print(f"  Comparison: {normalized_path2.parent}")

    print(f"\nFiles Generated (per run):")
    print(f"  - scan_results.json  (raw aggregation)")
    print(f"  - normalized.json    (processed with llm-duplicate-resolution/compare)")
    print(f"  - raw/               (individual scanner outputs)")

    comparison = results2.get('comparison', {})
    if comparison:
        print(f"\nComparison Summary:")
        summary = comparison.get('summary', {})
        print(f"  NEW:        {summary.get('new', 0)}")
        print(f"  PERSISTENT: {summary.get('persistent', 0)}")
        print(f"  CHANGED:    {summary.get('changed', 0)}")
        print(f"  FIXED:      {summary.get('fixed', 0)}")

    print(f"\n{'='*70}")
    print("✓ Pipeline demonstrates:")
    print("  - Run folder structure (data/<target_slug>/<timestamp>/)")
    print("  - Schema versioning (schema_version + generated_at)")
    print("  - Comparison logic (NEW/PERSISTENT/CHANGED/FIXED)")
    print("  - Change tracking (field-level diffs in change_details)")
    print("  - Thesis-ready reliability (target validation, no data loss)")
    print(f"{'='*70}\n")

    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
