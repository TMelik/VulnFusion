#!/usr/bin/env python3
"""
Vulnerability Management Tool - Main Entry Point
"""

import argparse
import json
import logging
import os
import sys
from dataclasses import replace
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from utils.env_loader import load_project_dotenv

load_project_dotenv()

from orchestrator import (
    SCAN_MODE_AUTOMATIC,
    SCAN_MODE_MANUAL,
    create_default_orchestrator,
)
from utils.defectdojo_client import DefectDojoConfig, upload_defectdojo_raw_artifact, upload_defectdojo_report
from utils.defectdojo_dates import normalize_defectdojo_scan_date
from utils.defectdojo_export import write_defectdojo_generic_report
from utils.defectdojo_raw import (
    DEFAULT_DEFECTDOJO_UPLOAD_MODE,
    DEFECTDOJO_UPLOAD_MODE_MERGED,
    DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN,
    SUPPORTED_DEFECTDOJO_UPLOAD_MODES,
    build_raw_upload_manifest_entry,
    build_raw_test_title,
    normalize_defectdojo_upload_mode,
    resolve_raw_scan_type,
)
from utils.export_sanitizer import sanitize_results_for_export
from utils.finding_annotations import apply_annotations
from utils.schema import SEVERITY_LEVELS, SCHEMA_VERSION, assert_valid_results
from utils.comparator import add_comparison_to_results, print_comparison_summary
from utils.report_generator import generate_html_report
from utils.target_probe import HTTP_MODE_AUTO, HTTP_MODE_HTTP1, HTTP_MODE_HTTP2
from utils.llm_duplicate_resolver import (
    LLMDuplicateConfig,
    LLMDuplicateResolver,
    resolve_llm_duplicate_provider_settings,
)
from utils.llm_finding_analyzer import (
    LLM_FINDING_ANALYSIS_PROMPT_VERSION,
    LLMFindingAnalysisConfig,
    LLMFindingAnalyzer,
)
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase
from utils.http_transport_adapters import (
    HTTP2_ADAPTER_MODE_AUTO,
    HTTP2_ADAPTER_MODE_BRIDGE,
)
from utils.asset_context import apply_asset_context, load_asset_context_file
from utils.site_context import (
    discover_site_context,
    load_site_okf_bundle,
    write_site_okf_bundle,
)
from utils.config_loader import DefectDojoFileConfig, load_defectdojo_config
from utils.risk_scorer import score_vulnerabilities
from utils.run_folder import create_target_slug, get_scan_results_json_path, update_latest_pointer
from utils.scan_config import resolve_scan_config, save_effective_scan_config
from utils.timing import missing_scanner_stages, print_timing_summary, save_timing_payload

WEB_SCANNERS = {'nuclei', 'wapiti', 'nikto', 'zap'}
RUNTIME_RISK_FIELDS = {'risk_score', 'priority', 'risk_factors', 'risk_rationale'}
_SITE_CONTEXT_CRITICALITIES = {'high', 'medium', 'low'}
_SITE_CONTEXT_ENVIRONMENTS = {'production', 'staging', 'development', 'test'}

def print_banner():
    """Print application banner."""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║           VULNERABILITY MANAGEMENT TOOL                   ║
║                    v1.0.0                                 ║
╚═══════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_summary(results: dict):
    """Print a summary of scan results."""
    summary = results.get('summary', {})

    print("\n" + "=" * 60)
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Target: {results.get('target')}")
    print(f"Timestamp: {results.get('timestamp')}")
    print(f"Scanners Run: {', '.join(results.get('scanners_run', []))}")
    print()

    print("Findings by Severity:")
    by_severity = summary.get('by_severity', {})
    for sev in SEVERITY_LEVELS:
        count = by_severity.get(sev, 0)
        if count > 0:
            indicator = "🔴" if sev == 'critical' else \
                       "🟠" if sev == 'high' else \
                       "🟡" if sev == 'medium' else \
                       "🔵" if sev == 'low' else "⚪"
            print(f"  {indicator} {sev.upper()}: {count}")

    print(f"\nTotal Findings: {summary.get('total_findings', 0)}")

    ai_summary = results.get('ai_analysis_summary')
    if isinstance(ai_summary, dict):
        print("\nAdvisory AI Analysis:")
        print(f"  Status: {ai_summary.get('status', 'unknown')}")
        print(
            "  Findings: "
            f"analyzed={ai_summary.get('analyzed_count', 0)}, "
            f"cached={ai_summary.get('cached_count', 0)}, "
            f"needs_review={ai_summary.get('needs_review_count', 0)}, "
            f"unavailable={ai_summary.get('unavailable_count', 0)}, "
            f"skipped_limit={ai_summary.get('skipped_limit_count', 0)}"
        )

    errors = results.get('errors', [])
    if errors:
        print("\nErrors:")
        for err in errors:
            print(f"    {err['scanner']}: {err['error']}")
        if len(results.get('scanners_run', [])) == 1:
            print("\nCheck the saved raw scanner output for full stdout/stderr details.")

    warnings = results.get('warnings', [])
    if warnings:
        print("\nWarnings:")
        for warn in warnings:
            print(f"    {warn['scanner']}: {warn['warning']}")

    print("=" * 60)

def print_target_probe_summary(probe: dict, http_mode: str):
    """Print the short pre-scan protocol summary required for web targets."""
    print("[*] Target probe:")
    print(f"    input: {probe.get('input_target', '')}")
    print(f"    normalized target: {probe.get('normalized_target', '')}")
    print(f"    selected scheme: {probe.get('selected_scheme', 'unknown') or 'unknown'}")
    print(f"    detected HTTP version: {probe.get('detected_http_version', 'unknown')}")
    print(f"    http mode used: {http_mode}")

def print_probe_only_summary(probe: dict):
    """Print probe-only output in a compact human-readable form."""
    print(f"normalized_target: {probe.get('normalized_target', '')}")
    print(f"selected_scheme: {probe.get('selected_scheme', 'unknown') or 'unknown'}")
    print(f"detected_http_version: {probe.get('detected_http_version', 'unknown')}")
    print(f"supports_http2: {probe.get('supports_http2')}")
    print(f"supports_http1_1: {probe.get('supports_http1_1')}")
    print(f"reason: {probe.get('reason', '')}")

def print_findings(results: dict, verbose: bool = False):
    """Print detailed findings."""
    findings = results.get('all_findings', [])
    errors = results.get('errors', [])

    if not findings:
        warnings = results.get('warnings', [])
        if errors or warnings:
            print("\n No findings were produced because the scan failed, timed out, or was degraded.")
        else:
            print("\n No vulnerabilities found!")
        return

    print(f"\n DETAILED FINDINGS ({len(findings)} total)")
    print("-" * 60)

    for i, finding in enumerate(findings, 1):
        sev = finding.get('severity', 'info')
        sev_color = {
            'critical': '\033[91m',
            'high': '\033[93m',
            'medium': '\033[33m',
            'low': '\033[94m',
            'info': '\033[90m'
        }.get(sev, '')
        reset = '\033[0m'

        status = finding.get('status', '')
        status_str = f" [{status}]" if status else ""

        print(f"\n[{i}]{status_str} {sev_color}{finding.get('vulnerability_name')}{reset}")
        print(f"    Severity: {sev.upper()}")
        print(f"    Asset: {finding.get('asset_id')}")

        if verbose:
            print(f"    Description: {finding.get('description', 'N/A')[:200]}...")
            print(f"    Remediation: {finding.get('remediation', 'N/A')[:200]}...")
            meta = finding.get('meta', {})
            if meta.get('scanner'):
                print(f"    Scanner: {meta['scanner']}")


def _finish_timing_stage(timer, handle, *, status: str, note: str) -> None:
    """Finish a timing stage when the active orchestrator exposes a timer."""
    if timer is not None and handle is not None:
        timer.finish(handle, status=status, note=note)


def _ensure_skipped_timing_stage(timer, stage: str, note: str) -> None:
    """Record a skipped stage only when no timing record exists for it yet."""
    if timer is None or timer.has_stage(stage):
        return
    timer.record_skipped(stage, note=note)


def _record_missing_scanner_timing(timer, active_scanners: list[str]) -> None:
    """Surface scanners that were enabled but not scheduled by discovery mode."""
    if timer is None:
        return
    for scanner_name in missing_scanner_stages(active_scanners, timer.records):
        timer.record_skipped(
            scanner_name,
            note="scanner enabled but not scheduled for this target/run mode",
        )


def _save_and_print_timing(
    *,
    timer,
    target: str,
    run_folder: Path | None,
    json_mode: bool,
) -> dict | None:
    """Persist timing sidecar output and print a terminal summary."""
    if timer is None or run_folder is None:
        return None
    payload = timer.to_payload(target=target, run_folder=run_folder)
    paths = save_timing_payload(
        payload,
        run_folder=run_folder,
        target_slug=create_target_slug(target),
    )
    summary_stream = sys.stderr if json_mode else sys.stdout
    print_timing_summary(payload, file=summary_stream)
    for path in paths:
        print(f"[+] Timing results saved to: {path}", file=summary_stream)
    return payload


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse a boolean environment variable with a safe default."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _env_bool_optional(name: str) -> bool | None:
    """Parse a boolean environment variable, returning None when unset."""
    value = os.getenv(name)
    if value is None:
        return None
    return value.strip().lower() in {'1', 'true', 'yes', 'on'}


def _env_text(name: str) -> str | None:
    """Return one stripped environment variable, or None when empty."""
    value = os.getenv(name)
    if value is None:
        return None
    text = value.strip()
    return text or None


def _env_int(name: str) -> int | None:
    """Return one integer environment variable, or None when empty."""
    value = _env_text(name)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer.") from exc


def _env_float(name: str) -> float | None:
    """Return one numeric environment variable, or None when empty."""
    value = _env_text(name)
    if value is None:
        return None
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number.") from exc


def _first_configured(*values):
    """Return the first value that is not None."""
    for value in values:
        if value is not None:
            return value
    return None


def _default_duplicate_mode() -> str:
    """Choose the active duplicate mode from environment-aware defaults."""
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


def _expand_existing_path_argument(flag: str, path_value: str | None, parser: argparse.ArgumentParser) -> str | None:
    """Expand ``~`` and validate file-based CLI arguments consistently."""
    if not path_value:
        return None
    expanded_path = Path(path_value).expanduser()
    expanded = str(expanded_path)
    if not expanded_path.exists():
        parser.error(f"{flag} does not exist: {expanded}")
    if not expanded_path.is_file():
        parser.error(f"{flag} must point to a regular file: {expanded}")
    return expanded


def _build_duplicate_config(args: argparse.Namespace) -> LLMDuplicateConfig:
    """Build the LLM duplicate resolver config from CLI and environment."""
    mode = 'off' if args.no_dedupe else (args.duplicate_mode or _default_duplicate_mode())
    timeout_seconds = (
        args.llm_timeout
        if args.llm_timeout is not None
        else float(os.getenv('VULN_MANAGER_LLM_TIMEOUT', '15'))
    )
    cache_enabled = False if args.no_llm_cache else _env_bool('VULN_MANAGER_LLM_CACHE_ENABLED', True)
    provider_settings = resolve_llm_duplicate_provider_settings(
        cli_api_url=args.llm_api_url,
        cli_api_key=args.llm_api_key,
        cli_model_name=args.llm_model,
        env=os.environ,
    )
    return LLMDuplicateConfig(
        mode=mode,
        api_url=provider_settings["api_url"],
        api_key=provider_settings["api_key"],
        model_name=provider_settings["model_name"],
        timeout_seconds=float(timeout_seconds),
        debug=args.llm_debug or _env_bool('VULN_MANAGER_LLM_DEBUG', False),
        cache_enabled=cache_enabled,
    )


def _build_finding_analysis_config(
    args: argparse.Namespace,
    duplicate_config: LLMDuplicateConfig,
) -> LLMFindingAnalysisConfig:
    """Build the bounded advisory-analysis config from shared provider settings."""
    return LLMFindingAnalysisConfig.from_duplicate_config(
        duplicate_config,
        enabled=not bool(args.no_ai_analysis),
        limit=int(args.ai_analysis_limit),
        input_cost_per_million=_env_float('VULN_MANAGER_LLM_INPUT_COST_PER_1M'),
        output_cost_per_million=_env_float('VULN_MANAGER_LLM_OUTPUT_COST_PER_1M'),
    )


def _clear_partial_ai_analysis(results: dict) -> None:
    """Remove partial advisory fields after an unexpected analyzer-level failure."""
    findings = results.get('all_findings') if isinstance(results, dict) else None
    if not isinstance(findings, list):
        return
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        finding.pop('ai_analysis_status', None)
        finding.pop('applicability', None)
        finding.pop('ai_remediation', None)


def _unexpected_ai_analysis_summary(config: LLMFindingAnalysisConfig) -> dict:
    """Return a safe aggregate diagnostic for an unexpected analyzer failure."""
    return {
        'status': 'unavailable',
        'model': str(config.model_name or ''),
        'prompt_version': LLM_FINDING_ANALYSIS_PROMPT_VERSION,
        'limit': config.limit,
        'selected_count': 0,
        'analyzed_count': 0,
        'cached_count': 0,
        'unavailable_count': 0,
        'skipped_limit_count': 0,
        'needs_review_count': 0,
        'redaction_count': 0,
        'prompt_tokens': 0,
        'completion_tokens': 0,
        'total_tokens': 0,
        'latency_ms': 0.0,
        'estimated_cost_usd': None,
    }


def _finding_collections_for_enrichment(results: dict) -> list[list[dict]]:
    """Return current-scan finding collections that should share enrichment updates."""
    collections: list[list[dict]] = []

    all_findings = results.get("all_findings")
    if isinstance(all_findings, list):
        collections.append(all_findings)

    findings_by_scanner = results.get("findings_by_scanner")
    if isinstance(findings_by_scanner, dict):
        for findings in findings_by_scanner.values():
            if isinstance(findings, list):
                collections.append(findings)

    for key in ("changed_findings", "partial_unmatched_current_findings"):
        findings = results.get(key)
        if isinstance(findings, list):
            collections.append(findings)

    return collections


def _apply_asset_context_to_results(results: dict, rules: list[dict]) -> dict:
    """Apply asset-context rules to all current-scan finding views in-place."""
    for findings in _finding_collections_for_enrichment(results):
        apply_asset_context(findings, rules)
    return results


def _scanner_uses_offline_input(scanner: object, options: dict | None = None) -> bool:
    """Call the optional offline-input capability without breaking lightweight test doubles."""
    hook = getattr(scanner, "uses_offline_input", None)
    return bool(hook(options or {})) if callable(hook) else False


def _print_site_context_preview(draft: dict, *, stream=None) -> None:
    """Show only the compact review fields, never raw crawled page text."""
    stream = stream or sys.stdout
    analysis = draft.get("analysis") if isinstance(draft, dict) else {}
    if not isinstance(analysis, dict):
        analysis = {}
    print("\n[*] Suggested site context:", file=stream)
    print(f"    Description: {analysis.get('site_description') or 'Unknown'}", file=stream)
    analysis_source = str(analysis.get('analysis_source') or 'unknown').replace('_', ' ')
    model_name = str(analysis.get('analysis_model') or analysis.get('model') or '').strip()
    source_detail = f" ({model_name})" if model_name else ""
    print(f"    Analysis source: {analysis_source}{source_detail}", file=stream)
    processes = analysis.get("business_processes")
    if isinstance(processes, list) and processes:
        print("    Business processes:", file=stream)
        for process in processes:
            print(f"      - {process}", file=stream)
    risk_context = analysis.get("risk_context")
    if isinstance(risk_context, dict):
        print("    Proposed risk context (applied only after confirmation):", file=stream)
        for key in ("asset_criticality", "environment", "sensitive_data", "requires_auth"):
            value = risk_context.get(key)
            print(f"      - {key.replace('_', ' ')}: {value if value is not None else 'unknown'}", file=stream)
        confidence = risk_context.get('confidence')
        if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
            print(f"      - model-stated confidence: {float(confidence):.2f}", file=stream)
        evidence_ids = risk_context.get('evidence_ids')
        if isinstance(evidence_ids, list) and evidence_ids:
            print(
                "      - cited evidence: "
                + ", ".join(str(item) for item in evidence_ids if str(item).strip()),
                file=stream,
            )
        reason = str(risk_context.get('reason') or '').strip()
        if reason:
            print(f"      - reason: {reason}", file=stream)
    uncertainties = analysis.get('uncertainties')
    if isinstance(uncertainties, list) and uncertainties:
        print("    Uncertainties:", file=stream)
        for uncertainty in uncertainties[:5]:
            if isinstance(uncertainty, str) and uncertainty.strip():
                print(f"      - {uncertainty.strip()}", file=stream)
    pages = draft.get("pages") if isinstance(draft, dict) else []
    if isinstance(pages, list) and pages:
        print("    Sources:", file=stream)
        for page in pages:
            if isinstance(page, dict):
                print(f"      - {page.get('url')}", file=stream)
    osint_sources = draft.get('osint') if isinstance(draft, dict) else []
    if isinstance(osint_sources, list) and osint_sources:
        print("    Local metadata:", file=stream)
        for source in osint_sources:
            if not isinstance(source, dict):
                continue
            kind = str(source.get('kind') or 'metadata').upper()
            resource = str(source.get('resource') or '').strip()
            print(f"      - {kind}: {resource}", file=stream)


def _review_site_context_description(args: argparse.Namespace, draft: dict) -> str | None:
    """Confirm the displayed profile and return its final description, or skip it."""
    analysis = draft.get("analysis") if isinstance(draft, dict) else {}
    if not isinstance(analysis, dict):
        analysis = {}
    suggestion = str(analysis.get("site_description") or "").strip()

    if args.context_description:
        return str(args.context_description).strip()
    if args.context_accept:
        return suggestion or None
    if args.json or not sys.stdin.isatty():
        print(
            "[!] Site context was not confirmed. Use --context-accept or "
            "--context-description to create the per-site OKF bundle.",
            file=sys.stderr,
        )
        return None

    answer = input(
        "Accept the description and proposed risk context [Enter], "
        "type a replacement description, or type 'skip': "
    ).strip()
    if answer.lower() in {"skip", "s"}:
        return None
    return answer or suggestion or None


def _site_context_scoring_context(results: dict, asset_knowledge: dict | None) -> dict:
    """Return risk-scoring inputs augmented only by human-confirmed site context."""
    scoring_context = dict(results)
    if not isinstance(asset_knowledge, dict):
        return scoring_context
    risk_context = asset_knowledge.get('risk_context')
    if not isinstance(risk_context, dict):
        return scoring_context

    criticality = risk_context.get('asset_criticality')
    if criticality in _SITE_CONTEXT_CRITICALITIES:
        scoring_context['asset_criticality'] = criticality
    environment = risk_context.get('environment')
    if environment in _SITE_CONTEXT_ENVIRONMENTS:
        scoring_context['environment'] = environment
    for key in ('sensitive_data', 'requires_auth'):
        value = risk_context.get(key)
        if isinstance(value, bool):
            scoring_context[key] = value
    return scoring_context


def _public_asset_knowledge_reference(asset_knowledge: dict) -> dict:
    """Drop local OKF filesystem paths before a profile reference enters results."""
    public = {
        key: asset_knowledge[key]
        for key in (
            'description', 'reviewer', 'profile_revision', 'analysis_source',
            'business_processes', 'risk_context',
        )
        if key in asset_knowledge
    }
    return public


def _strip_runtime_risk_fields(results: dict) -> dict:
    """Remove runtime risk-scoring fields when scoring is disabled."""
    for findings in _finding_collections_for_enrichment(results):
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            for field in RUNTIME_RISK_FIELDS:
                finding.pop(field, None)

    summary = results.get("summary")
    if isinstance(summary, dict):
        summary.pop("by_priority", None)
    return results


def _save_raw_only_results(orchestrator, results: dict, output: str | None, data_dir: Path) -> Path:
    """Persist raw-only CLI output without normalized-schema validation."""
    if getattr(orchestrator, "current_run_folder", None):
        output_path = get_scan_results_json_path(orchestrator.current_run_folder)
    elif output:
        output_path = Path(output).expanduser()
    else:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')
        target = str(results.get('target') or 'unknown')
        safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
        output_path = data_dir / f"scan_results_{safe_target}_{timestamp}.json"

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)

    if getattr(orchestrator, "current_run_folder", None):
        update_latest_pointer(orchestrator.current_run_folder)

    print(f"[+] Raw results saved to: {output_path}")
    return output_path


def _save_ai_analysis_metrics(run_folder: Path | None, summary: dict | None) -> Path | None:
    """Persist the sanitized advisory-AI run diagnostics beside scan artifacts."""
    if run_folder is None or not isinstance(summary, dict):
        return None
    output_path = Path(run_folder) / 'ai_analysis_metrics.json'
    with output_path.open('w', encoding='utf-8') as fh:
        json.dump(summary, fh, indent=2, default=str)
    return output_path


def _resolve_defectdojo_api_token(file_config: DefectDojoFileConfig | None) -> str | None:
    config_token_from_env = None
    if file_config and file_config.api_token_env:
        config_token_from_env = _env_text(file_config.api_token_env)
    return _first_configured(
        _env_text('VULN_MANAGER_DEFECTDOJO_API_TOKEN'),
        config_token_from_env,
        file_config.api_token if file_config else None,
    )


def _normalize_defectdojo_upload_mode_alias(value: str | None) -> str | None:
    mode = str(value or "").strip()
    if mode.lower() == "generic":
        return DEFECTDOJO_UPLOAD_MODE_MERGED
    return mode or None


def _resolve_defectdojo_name_and_id(
    *,
    cli_name: str | None,
    cli_id: int | None,
    env_name: str | None,
    env_id: int | None,
    config_name: str | None,
    config_id: int | None,
) -> tuple[str | None, int | None]:
    if cli_id is not None:
        return cli_name, cli_id
    if cli_name is not None:
        return cli_name, None
    if env_id is not None:
        return env_name, env_id
    if env_name is not None:
        return env_name, None
    return config_name, config_id


def _resolve_defectdojo_engagement_target(
    args: argparse.Namespace,
    file_config: DefectDojoFileConfig,
) -> tuple[str | None, int | None, int | None]:
    cli_name = getattr(args, 'defectdojo_engagement', None)
    cli_engagement_id = getattr(args, 'defectdojo_engagement_id', None)
    cli_test_id = getattr(args, 'defectdojo_test_id', None)
    env_name = _env_text('VULN_MANAGER_DEFECTDOJO_ENGAGEMENT')
    env_engagement_id = _env_int('VULN_MANAGER_DEFECTDOJO_ENGAGEMENT_ID')
    env_test_id = _env_int('VULN_MANAGER_DEFECTDOJO_TEST_ID')

    if cli_test_id is not None:
        return cli_name, cli_engagement_id, cli_test_id
    if cli_engagement_id is not None:
        return cli_name, cli_engagement_id, None
    if cli_name is not None:
        return cli_name, None, None
    if env_test_id is not None:
        return env_name, env_engagement_id, env_test_id
    if env_engagement_id is not None:
        return env_name, env_engagement_id, None
    if env_name is not None:
        return env_name, None, None
    return file_config.engagement_name, file_config.engagement_id, file_config.test_id


def _resolve_defectdojo_config(
    args: argparse.Namespace,
    file_config: DefectDojoFileConfig | None = None,
) -> DefectDojoConfig:
    """Build the DefectDojo upload config from CLI, environment, and optional INI config."""
    file_config = file_config or DefectDojoFileConfig(path=Path("defectdojo.config"))
    product_type_name, product_type_id = _resolve_defectdojo_name_and_id(
        cli_name=getattr(args, 'defectdojo_product_type', None),
        cli_id=getattr(args, 'defectdojo_product_type_id', None),
        env_name=_env_text('VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE'),
        env_id=_env_int('VULN_MANAGER_DEFECTDOJO_PRODUCT_TYPE_ID'),
        config_name=file_config.product_type_name,
        config_id=file_config.product_type_id,
    )
    product_name, product_id = _resolve_defectdojo_name_and_id(
        cli_name=getattr(args, 'defectdojo_product', None),
        cli_id=getattr(args, 'defectdojo_product_id', None),
        env_name=_env_text('VULN_MANAGER_DEFECTDOJO_PRODUCT'),
        env_id=_env_int('VULN_MANAGER_DEFECTDOJO_PRODUCT_ID'),
        config_name=file_config.product_name,
        config_id=file_config.product_id,
    )
    engagement_name, engagement_id, test_id = _resolve_defectdojo_engagement_target(args, file_config)
    return DefectDojoConfig(
        base_url=_first_configured(
            getattr(args, 'defectdojo_url', None),
            _env_text('VULN_MANAGER_DEFECTDOJO_URL'),
            file_config.base_url,
        ),
        api_token=_first_configured(
            getattr(args, 'defectdojo_api_token', None),
            _resolve_defectdojo_api_token(file_config),
        ),
        product_type_name=product_type_name,
        product_type_id=product_type_id,
        product_name=product_name,
        product_id=product_id,
        engagement_name=engagement_name,
        test_id=test_id,
        engagement_id=engagement_id,
        scan_type=_first_configured(
            _env_text('VULN_MANAGER_DEFECTDOJO_SCAN_TYPE'),
            'Generic Findings Import',
        ),
        test_title=_first_configured(
            getattr(args, 'defectdojo_test_title', None),
            _env_text('VULN_MANAGER_DEFECTDOJO_TEST_TITLE'),
        ),
        minimum_severity=_first_configured(
            getattr(args, 'defectdojo_minimum_severity', None),
            _env_text('VULN_MANAGER_DEFECTDOJO_MINIMUM_SEVERITY'),
            file_config.minimum_severity,
            'Info',
        ),
        active=_first_configured(
            getattr(args, 'defectdojo_active', None),
            _env_bool_optional('VULN_MANAGER_DEFECTDOJO_ACTIVE'),
            file_config.active,
            True,
        ),
        verified=_first_configured(
            getattr(args, 'defectdojo_verified', None),
            _env_bool_optional('VULN_MANAGER_DEFECTDOJO_VERIFIED'),
            file_config.verified,
            True,
        ),
        auto_create_context=_first_configured(
            True if getattr(args, 'defectdojo_auto_create_context', False) else None,
            False if getattr(args, 'defectdojo_no_auto_create_context', False) else None,
            _env_bool_optional('VULN_MANAGER_DEFECTDOJO_AUTO_CREATE_CONTEXT'),
            file_config.auto_create_context,
            True,
        ),
        do_not_reactivate=(
            getattr(args, 'defectdojo_do_not_reactivate', False)
            or _env_bool(
                'VULN_MANAGER_DEFECTDOJO_DO_NOT_REACTIVATE',
                False if file_config.do_not_reactivate is None else file_config.do_not_reactivate,
            )
        ),
        close_old_findings=(
            getattr(args, 'defectdojo_close_old_findings', False)
            or _env_bool(
                'VULN_MANAGER_DEFECTDOJO_CLOSE_OLD_FINDINGS',
                False if file_config.close_old_findings is None else file_config.close_old_findings,
            )
        ),
        environment=_first_configured(
            getattr(args, 'defectdojo_environment', None),
            _env_text('VULN_MANAGER_DEFECTDOJO_ENVIRONMENT'),
            file_config.environment,
        ),
        background_import=(
            getattr(args, 'defectdojo_background_import', False)
            or _env_bool(
                'VULN_MANAGER_DEFECTDOJO_BACKGROUND_IMPORT',
                False if file_config.background_import is None else file_config.background_import,
            )
        ),
        strict_names=(
            getattr(args, 'defectdojo_strict_names', False)
            or _env_bool(
                'VULN_MANAGER_DEFECTDOJO_STRICT_NAMES',
                False if file_config.strict_names is None else file_config.strict_names,
            )
        ),
        verify_tls=(
            _first_configured(
                True if getattr(args, 'defectdojo_verify_ssl', False) else None,
                False if getattr(args, 'defectdojo_insecure', False) else None,
                _env_bool_optional('VULN_MANAGER_DEFECTDOJO_VERIFY_TLS'),
                file_config.verify_tls,
                True,
            )
        ),
        timeout_seconds=_first_configured(
            getattr(args, 'defectdojo_timeout_seconds', None),
            _env_float('VULN_MANAGER_DEFECTDOJO_TIMEOUT_SECONDS'),
            file_config.timeout_seconds,
            30.0,
        ),
    )


def _resolve_defectdojo_upload_mode(
    args: argparse.Namespace,
    file_config: DefectDojoFileConfig | None = None,
) -> str:
    """Return the configured DefectDojo upload mode."""
    return normalize_defectdojo_upload_mode(
        _normalize_defectdojo_upload_mode_alias(
            _first_configured(
                getattr(args, 'defectdojo_upload_mode', None),
                _env_text('VULN_MANAGER_DEFECTDOJO_UPLOAD_MODE'),
                file_config.upload_mode if file_config else None,
            )
        )
    )


def _resolve_defectdojo_raw_scan_type_overrides(
    args: argparse.Namespace,
    file_config: DefectDojoFileConfig | None = None,
) -> dict[str, str | None]:
    """Build scanner-specific DefectDojo parser overrides from CLI and environment."""
    scanner_names = ('nmap', 'nuclei', 'wapiti', 'nikto', 'zap')
    overrides: dict[str, str | None] = {}
    for scanner_name in scanner_names:
        cli_value = getattr(args, f'defectdojo_scan_type_{scanner_name}', None)
        env_name = f"VULN_MANAGER_DEFECTDOJO_SCAN_TYPE_{scanner_name.upper()}"
        config_value = file_config.scan_types.get(scanner_name) if file_config else None
        value = _first_configured(cli_value, _env_text(env_name), config_value)
        if value:
            overrides[scanner_name] = value
    if file_config:
        for scanner_name, scan_type in file_config.scan_types.items():
            overrides.setdefault(scanner_name, scan_type)
    return overrides


def _load_defectdojo_file_config(args: argparse.Namespace, parser: argparse.ArgumentParser) -> DefectDojoFileConfig:
    """Load the optional DefectDojo INI config file."""
    explicit_config = getattr(args, 'config', None)
    try:
        file_config = load_defectdojo_config(explicit_config, require=bool(explicit_config))
    except (FileNotFoundError, ValueError) as exc:
        parser.error(str(exc))

    if file_config.loaded:
        print(f"[*] Loaded config: {file_config.path}")
        if file_config.has_inline_api_token:
            print(
                "[!] DefectDojo config contains api_token directly; storing tokens in config files is not recommended.",
                file=sys.stderr,
            )
        if file_config.enabled is True:
            print("[*] DefectDojo enabled from config")
    return file_config


def _resolve_defectdojo_upload_requested(
    args: argparse.Namespace,
    file_config: DefectDojoFileConfig,
) -> bool:
    """Return whether DefectDojo upload should run."""
    if getattr(args, 'no_defectdojo_upload', False):
        return False
    if getattr(args, 'defectdojo_upload', False):
        return True

    env_enabled = _env_text('VULN_MANAGER_DEFECTDOJO_ENABLED')
    if env_enabled is not None:
        return env_enabled.strip().lower() in {'1', 'true', 'yes', 'on'}

    return file_config.enabled is True


def _validate_defectdojo_upload_settings(
    config: DefectDojoConfig,
    *,
    upload_mode: str,
) -> None:
    """Fail before scanning if upload is requested but required settings are missing."""
    config.validate()
    if not upload_mode:
        raise ValueError("DefectDojo upload requires upload_mode.")


def _config_test_title_for_raw_upload(
    entry: dict,
    file_config: DefectDojoFileConfig | None,
    *,
    original_target: str | None = None,
) -> str:
    scanner_name = str(entry.get('scanner') or '').strip().lower()
    execution_target = _raw_upload_target(entry)
    stable_target = str(original_target or '').strip() or execution_target

    env_template = _env_text(f"VULN_MANAGER_DEFECTDOJO_TEST_TITLE_{scanner_name.upper()}") if scanner_name else None
    config_template = file_config.test_titles.get(scanner_name) if file_config else None
    template = _first_configured(env_template, config_template)
    if template:
        return (
            str(template)
            .replace('{target}', stable_target)
            .replace('{execution_target}', execution_target)
        )

    return build_raw_test_title(scanner_name, stable_target)


def _resolve_raw_upload_scan_type(
    scanner_name: str,
    scan_type_overrides: dict[str, str | None],
    file_config: DefectDojoFileConfig | None,
) -> str | None:
    scanner_key = str(scanner_name or '').strip().lower()
    if (
        file_config
        and file_config.has_scan_types_section
        and scanner_key
        and scanner_key not in scan_type_overrides
        and scanner_key not in file_config.scan_types
    ):
        raise ValueError(f"Missing DefectDojo scan type mapping for scanner: {scanner_key}")
    return resolve_raw_scan_type(scanner_key, scan_type_overrides)


def _defectdojo_output_path(orchestrator, json_path: Path) -> Path:
    """Choose a stable output path for one DefectDojo export artifact."""
    if orchestrator is not None and getattr(orchestrator, 'current_run_folder', None):
        return orchestrator.current_run_folder / 'defectdojo_generic.json'
    return json_path.parent / 'defectdojo_generic.json'


def _defectdojo_success_message(response: object) -> str:
    """Return a compact human-readable summary for a successful upload."""
    if isinstance(response, dict):
        for key in ('message', 'detail'):
            value = response.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        identifiers = []
        for key in ('test', 'test_id', 'id', 'engagement', 'engagement_id'):
            value = response.get(key)
            if isinstance(value, (int, str)) and str(value).strip():
                identifiers.append(f"{key}={value}")
        if identifiers:
            return f"created/updated test successfully ({', '.join(identifiers)})"

    return "created/updated test successfully."


def _raw_upload_target(entry: dict) -> str:
    return str(entry.get('target') or '').strip() or 'unknown target'


def _raw_upload_test_title(entry: dict) -> str:
    return build_raw_test_title(str(entry.get('scanner') or ''), _raw_upload_target(entry))


def _raw_artifact_path(artifact: dict) -> str | None:
    path = artifact.get('path') or artifact.get('raw_artifact_path')
    text = str(path or '').strip()
    return text or None


def _raw_artifact_format(artifact: dict) -> str:
    artifact_format = str(artifact.get('artifact_format') or '').strip().lower()
    if artifact_format:
        return artifact_format

    path = _raw_artifact_path(artifact)
    if not path:
        return ''
    return Path(path).suffix.lower().lstrip('.')


def _append_raw_artifact_candidate(candidates: list[dict], artifact: dict) -> None:
    path = _raw_artifact_path(artifact)
    candidate = dict(artifact)
    if path:
        candidate['path'] = path
        candidate['raw_artifact_path'] = path
    candidate['artifact_format'] = _raw_artifact_format(candidate) or None

    for existing in candidates:
        if _raw_artifact_path(existing) == path and path:
            existing.update(candidate)
            return
    candidates.append(candidate)


def _raw_upload_artifact_candidates(entry: dict) -> list[dict]:
    candidates: list[dict] = []
    primary_path = entry.get('raw_artifact_path')
    if primary_path or any(
        entry.get(key) is not None
        for key in ('artifact_format', 'native', 'artifact_role', 'artifact_source')
    ):
        _append_raw_artifact_candidate(
            candidates,
            {
                'path': primary_path,
                'raw_artifact_path': primary_path,
                'artifact_format': entry.get('artifact_format'),
                'native': entry.get('native'),
                'role': entry.get('role') or entry.get('artifact_role'),
                'source': entry.get('source') or entry.get('artifact_source'),
            },
        )

    raw_artifacts = entry.get('raw_artifacts')
    if isinstance(raw_artifacts, list):
        for artifact in raw_artifacts:
            if isinstance(artifact, dict):
                _append_raw_artifact_candidate(candidates, artifact)

    return candidates


def _raw_artifact_matches_preference(artifact: dict, preferred_format: str) -> bool:
    artifact_format = _raw_artifact_format(artifact)
    preference = str(preferred_format or '').strip().lower()
    if preference == 'native_jsonl':
        return bool(artifact.get('native')) and artifact_format in {'jsonl', 'native_jsonl'}
    return artifact_format == preference


def _native_artifact_format_summary(candidates: list[dict]) -> str:
    formats = []
    for artifact in candidates:
        if not artifact.get('native'):
            continue
        artifact_format = _raw_artifact_format(artifact) or 'unknown'
        if artifact_format not in formats:
            formats.append(artifact_format)
    return ', '.join(formats) if formats else 'none'


def _select_raw_upload_artifact(
    entry: dict,
    *,
    scanner_name: str,
    preferred_formats: tuple[str, ...],
) -> tuple[dict | None, str | None]:
    scanner_key = str(scanner_name or '').strip().lower()
    wapiti_xml_required = (
        scanner_key == 'wapiti'
        and (
            not preferred_formats
            or ('xml' in preferred_formats and 'json' not in preferred_formats)
        )
    )
    candidates = _raw_upload_artifact_candidates(entry)
    if not candidates:
        if wapiti_xml_required:
            return None, "Wapiti XML artifact missing; cannot upload to DefectDojo Wapiti Scan."
        return None, str(entry.get('skip_reason') or 'no scanner-native raw artifact was produced')

    native_candidates = [artifact for artifact in candidates if artifact.get('native')]
    if not native_candidates:
        if wapiti_xml_required:
            return None, "Wapiti XML artifact missing; cannot upload to DefectDojo Wapiti Scan."
        return None, str(entry.get('skip_reason') or 'raw artifact is not scanner-native parser input')

    if wapiti_xml_required:
        for artifact in native_candidates:
            if _raw_artifact_format(artifact) == 'xml':
                return artifact, None
        return None, "Wapiti XML artifact missing; cannot upload to DefectDojo Wapiti Scan."

    if preferred_formats:
        for preferred_format in preferred_formats:
            for artifact in native_candidates:
                if _raw_artifact_matches_preference(artifact, preferred_format):
                    return artifact, None

        return None, (
            f"no scanner-native raw artifact matches configured formats for scanner {scanner_name}; "
            f"configured formats: {', '.join(preferred_formats)}; "
            f"available native formats: {_native_artifact_format_summary(candidates)}"
        )

    primary_path = str(entry.get('raw_artifact_path') or '').strip()
    if primary_path:
        for artifact in native_candidates:
            if _raw_artifact_path(artifact) == primary_path:
                return artifact, None

    return native_candidates[0], None


def _raw_upload_context_config(config: DefectDojoConfig) -> DefectDojoConfig:
    """Return DefectDojo context settings safe for raw per-scanner uploads."""
    return replace(
        config,
        scan_type='Generic Findings Import',
        test_title=None,
        test_id=None,
    )


def _upload_defectdojo_raw_manifest(
    results: dict,
    config: DefectDojoConfig,
    *,
    scan_date: str | None,
    scan_type_overrides: dict[str, str | None],
    file_config: DefectDojoFileConfig | None = None,
) -> dict[str, int]:
    """Upload scanner-native raw artifacts from the aggregate manifest."""
    manifest = results.get('defectdojo_raw_uploads')
    if not isinstance(manifest, list) or not manifest:
        print("[!] DefectDojo raw upload skipped: no scanner-native raw upload manifest was produced.", file=sys.stderr)
        return {'uploaded': 0, 'skipped': 1, 'failed': 0}

    original_target = str(results.get('target') or '').strip()
    summary = {'uploaded': 0, 'skipped': 0, 'failed': 0}
    for raw_entry in manifest:
        if not isinstance(raw_entry, dict):
            summary['skipped'] += 1
            print("[!] DefectDojo raw upload skipped: malformed manifest entry.", file=sys.stderr)
            continue

        execution_key = str(raw_entry.get('execution_key') or raw_entry.get('scanner') or 'unknown')
        scanner_name = str(raw_entry.get('scanner') or '').strip()
        scanner_key = scanner_name.lower()
        scan_type = _resolve_raw_upload_scan_type(scanner_name, scan_type_overrides, file_config)
        test_title = _config_test_title_for_raw_upload(
            raw_entry,
            file_config,
            original_target=original_target,
        )
        preferred_formats = file_config.artifact_formats.get(scanner_key, ()) if file_config else ()
        selected_artifact, selection_error = _select_raw_upload_artifact(
            raw_entry,
            scanner_name=scanner_name,
            preferred_formats=preferred_formats,
        )
        artifact_path = _raw_artifact_path(selected_artifact) if selected_artifact else None
        skip_reason = None
        if not scan_type:
            skip_reason = "no configured native parser mapping"
        elif selection_error:
            skip_reason = selection_error
        elif not artifact_path:
            skip_reason = "scanner-native raw artifact path is missing"
        elif not Path(str(artifact_path)).exists():
            skip_reason = f"scanner-native raw artifact does not exist: {artifact_path}"

        if skip_reason:
            summary['skipped'] += 1
            print(
                f"[!] DefectDojo raw upload skipped: {execution_key} -> {skip_reason}",
                file=sys.stderr,
            )
            continue

        print(f"[*] Scanner {scanner_name} uses scan type: {scan_type}")
        print(f"[*] Generated test title: {test_title}")
        logging.debug(
            "DefectDojo raw upload selected artifact: scanner=%s scan_type=%s "
            "test_title=%s engagement_id=%s artifact_path=%s preferred_formats=%s",
            scanner_name,
            scan_type,
            test_title,
            config.engagement_id,
            artifact_path,
            ','.join(preferred_formats) if preferred_formats else '',
        )
        try:
            upload_defectdojo_raw_artifact(
                Path(str(artifact_path)),
                _raw_upload_context_config(config),
                scan_type=scan_type,
                test_title=test_title,
                scan_date=scan_date,
            )
        except Exception as exc:
            summary['failed'] += 1
            print(
                f"[!] DefectDojo raw upload failed: {execution_key} -> {scan_type} | {artifact_path}: {exc}",
                file=sys.stderr,
            )
            continue

        summary['uploaded'] += 1
        print(f"[+] DefectDojo raw upload completed: {execution_key} -> {scan_type} | {artifact_path}")

    print(
        "[*] DefectDojo raw upload summary: "
        f"uploaded={summary['uploaded']}, skipped={summary['skipped']}, failed={summary['failed']}"
    )
    return summary


def main():
    """Main entry point."""
    orchestrator = None
    workflow_timer = None
    total_workflow_timing = None
    try:
        parser = argparse.ArgumentParser(
            description='Vulnerability Management Tool - Scan targets for security vulnerabilities',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "Simple usage:\n"
                "  python3 main.py --target example.com\n"
                "  python3 main.py --target https://example.com --scanner zap\n"
                "  python3 main.py --target example.com --probe-only\n"
                "  python3 main.py --target https://example.com --http-mode http1\n"
                "  python3 main.py --target https://example.com --http-mode http2\n"
                "\n"
                "HTTP version probing and bridge routing are automatic by default for web scans.\n"
            ),
        )

        parser.add_argument(
            '--target', '-t',
            help='Target to scan (IP, hostname, URL, or CIDR range)'
        )

        parser.add_argument(
            '--scanner', '-s',
            choices=['nmap', 'nuclei', 'wapiti', 'nikto', 'zap', 'all'],
            default='all',
            help='Scanner to use (default: all)'
        )

        parser.add_argument(
            '--scan-config',
            type=str,
            metavar='PATH',
            help='Optional YAML/JSON scan config file with global settings and per-scanner options'
        )

        parser.add_argument(
            '--scan-mode',
            choices=[SCAN_MODE_AUTOMATIC, SCAN_MODE_MANUAL],
            default=SCAN_MODE_AUTOMATIC,
            help='Multi-scanner orchestration mode for --scanner all: discovery-driven automatic follow-up selection or manual port selection'
        )

        parser.add_argument(
            '--ports', '-p',
            help='Ports to scan/select (used for nmap discovery and required for manual mode, e.g., "22,80,443" or "1-1000")'
        )

        parser.add_argument(
            '--nmap-timeout',
            type=int,
            metavar='SECONDS',
            help='Nmap scan timeout in seconds'
        )

        parser.add_argument(
            '--nmap-scripts',
            nargs='*',
            metavar='SCRIPT',
            help='Nmap NSE scripts to run; pass the flag with no values to disable NSE scripts for fast smoke tests'
        )

        parser.add_argument(
            '--nmap-args',
            type=str,
            default='',
            metavar='ARGS',
            help='Extra arguments forwarded to nmap'
        )

        parser.add_argument(
            '--severity',
            nargs='+',
            choices=SEVERITY_LEVELS,
            help='Filter nuclei/wapiti by severity levels'
        )

        parser.add_argument(
            '--output', '-o',
            help='Custom output filename for results'
        )

        parser.add_argument(
            '--data-dir',
            default='data',
            help='Directory for saving raw output (default: ./data)'
        )

        parser.add_argument(
            '--config',
            type=str,
            default=None,
            help='Optional project config file (default: ./defectdojo.config when present)'
        )

        parser.add_argument(
            '--verbose', '-v',
            action='store_true',
            help='Show detailed output including descriptions'
        )

        parser.add_argument(
            '--json',
            action='store_true',
            help='Output results as JSON only'
        )

        parser.add_argument(
            '--defectdojo-export',
            action='store_true',
            help='Write the final merged findings as DefectDojo Generic Findings Import JSON'
        )

        parser.add_argument(
            '--defectdojo-upload',
            action='store_true',
            help=(
                'Upload scanner-native raw results to DefectDojo via /api/v2/reimport-scan/ '
                '(default: raw-per-scan; use --defectdojo-upload-mode merged for merged findings upload)'
            )
        )

        parser.add_argument(
            '--no-defectdojo-upload',
            action='store_true',
            help='Disable DefectDojo upload even when enabled in config'
        )

        parser.add_argument(
            '--defectdojo-upload-mode',
            choices=sorted(SUPPORTED_DEFECTDOJO_UPLOAD_MODES | {'generic'}),
            default=None,
            help='DefectDojo upload mode: raw per-scanner artifacts (default) or merged Generic Findings JSON'
        )

        parser.add_argument(
            '--defectdojo-url',
            type=str,
            help='Base URL for the DefectDojo instance'
        )

        parser.add_argument(
            '--defectdojo-api-token',
            type=str,
            help='API token for the DefectDojo instance'
        )

        parser.add_argument(
            '--defectdojo-product-type',
            type=str,
            help='DefectDojo Product Type name for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-product-type-id',
            type=int,
            help='DefectDojo Product Type ID for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-product',
            type=str,
            help='DefectDojo Product name for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-product-id',
            type=int,
            help='DefectDojo Product ID for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-engagement',
            type=str,
            help='DefectDojo Engagement name for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-test-id',
            type=int,
            help='Optional DefectDojo Test ID to target directly on reimport'
        )

        parser.add_argument(
            '--defectdojo-engagement-id',
            type=int,
            help='Optional DefectDojo Engagement ID for import/reimport context'
        )

        parser.add_argument(
            '--defectdojo-test-title',
            type=str,
            help='Optional DefectDojo test title to target on reimport'
        )

        parser.add_argument(
            '--defectdojo-minimum-severity',
            type=str,
            help='Minimum severity sent to DefectDojo (default: Info)'
        )

        parser.add_argument(
            '--defectdojo-active',
            action=argparse.BooleanOptionalAction,
            default=None,
            help='Set DefectDojo active flag for imported findings'
        )

        parser.add_argument(
            '--defectdojo-verified',
            action=argparse.BooleanOptionalAction,
            default=None,
            help='Set DefectDojo verified flag for imported findings'
        )

        parser.add_argument(
            '--defectdojo-scan-type-nmap',
            type=str,
            help='DefectDojo scan type override for raw nmap artifacts'
        )

        parser.add_argument(
            '--defectdojo-scan-type-nuclei',
            type=str,
            help='DefectDojo scan type override for raw nuclei artifacts'
        )

        parser.add_argument(
            '--defectdojo-scan-type-wapiti',
            type=str,
            help='DefectDojo scan type override for raw wapiti artifacts'
        )

        parser.add_argument(
            '--defectdojo-scan-type-nikto',
            type=str,
            help='DefectDojo scan type override for raw nikto artifacts'
        )

        parser.add_argument(
            '--defectdojo-scan-type-zap',
            type=str,
            help='DefectDojo scan type override for raw zap artifacts'
        )

        parser.add_argument(
            '--defectdojo-environment',
            type=str,
            help='Optional DefectDojo environment name'
        )

        parser.add_argument(
            '--defectdojo-no-auto-create-context',
            action='store_true',
            help='Disable DefectDojo auto_create_context for import/reimport'
        )

        parser.add_argument(
            '--defectdojo-auto-create-context',
            action='store_true',
            help='Enable DefectDojo auto_create_context for import/reimport'
        )

        parser.add_argument(
            '--defectdojo-do-not-reactivate',
            action='store_true',
            help='Set DefectDojo do_not_reactivate=true on reimport'
        )

        parser.add_argument(
            '--defectdojo-close-old-findings',
            action='store_true',
            help='Set DefectDojo close_old_findings=true on reimport'
        )

        parser.add_argument(
            '--defectdojo-background-import',
            action='store_true',
            help='Set DefectDojo background_import=true for large uploads'
        )

        parser.add_argument(
            '--defectdojo-strict-names',
            action='store_true',
            help='Require exact DefectDojo Product Type, Product, and Engagement names'
        )

        parser.add_argument(
            '--defectdojo-scan-date',
            type=str,
            help='Optional scan_date sent to DefectDojo reimport'
        )

        parser.add_argument(
            '--defectdojo-timeout-seconds',
            type=float,
            help='Timeout in seconds for DefectDojo requests'
        )

        parser.add_argument(
            '--defectdojo-verify-ssl',
            action='store_true',
            help='Enable TLS certificate verification for DefectDojo uploads'
        )

        parser.add_argument(
            '--defectdojo-insecure',
            action='store_true',
            help='Disable TLS certificate verification for DefectDojo uploads'
        )

        parser.add_argument(
            '--probe-only',
            action='store_true',
            help='Probe scheme and HTTP version behavior, print the result, and exit'
        )

        parser.add_argument(
            '--list-scanners',
            action='store_true',
            help='List available scanners and exit'
        )

        parser.add_argument(
            '--no-save',
            action='store_true',
            help='Do not save raw scanner output'
        )

        normalize_group = parser.add_mutually_exclusive_group()
        normalize_group.add_argument(
            '--normalize',
            dest='normalize',
            action='store_true',
            default=None,
            help='Enable normalized findings and the normalized pipeline stages (default)'
        )
        normalize_group.add_argument(
            '--no-normalize',
            dest='normalize',
            action='store_false',
            help='Produce raw scanner results only and disable normalized pipeline stages'
        )

        parser.add_argument(
            '--no-dedupe',
            action='store_true',
            help='Skip active duplicate resolution; the legacy dedupe code remains disabled in the normal pipeline'
        )

        risk_scoring_group = parser.add_mutually_exclusive_group()
        risk_scoring_group.add_argument(
            '--risk-scoring',
            dest='risk_scoring',
            action='store_true',
            default=None,
            help='Enable runtime risk scoring and priority fields (default)'
        )
        risk_scoring_group.add_argument(
            '--no-risk-scoring',
            '--no-score',
            dest='risk_scoring',
            action='store_false',
            help='Disable runtime risk scoring; --no-score is a backwards-compatible alias'
        )

        parser.add_argument(
            '--compare',
            action='store_true',
            help='Compare with most recent previous scan'
        )

        report_group = parser.add_mutually_exclusive_group()
        report_group.add_argument(
            '--report',
            dest='report',
            action='store_true',
            help='Generate HTML report (enabled by default for normal scan runs)'
        )
        report_group.add_argument(
            '--no-report',
            dest='report',
            action='store_false',
            help='Disable HTML report generation for this run'
        )
        parser.set_defaults(report=None)

        annotation_group = parser.add_mutually_exclusive_group()
        annotation_group.add_argument(
            '--apply-annotations',
            dest='apply_annotations',
            action='store_true',
            help='Re-attach saved human triage decisions (false positive / not applicable / '
                 'comments) from the per-site OKF bundle to matching findings (default: enabled)'
        )
        annotation_group.add_argument(
            '--no-apply-annotations',
            dest='apply_annotations',
            action='store_false',
            help='Do not re-attach saved human triage decisions for this run'
        )
        parser.set_defaults(apply_annotations=True)

        ui_group = parser.add_argument_group('web UI (human triage)')
        ui_group.add_argument(
            '--ui',
            action='store_true',
            help='Launch the local human-triage web UI (a wrapper over this CLI) instead of scanning'
        )
        ui_group.add_argument(
            '--ui-host',
            default='127.0.0.1',
            help='Host/interface for --ui (default: 127.0.0.1, loopback only)'
        )
        ui_group.add_argument(
            '--ui-port',
            type=int,
            default=8765,
            help='Port for --ui (default: 8765; use 0 to pick a free port)'
        )
        ui_group.add_argument(
            '--ui-reviewer',
            default=None,
            help='Reviewer id recorded on triage decisions made via --ui (default: local-user)'
        )
        ui_group.add_argument(
            '--allow-remote',
            action='store_true',
            help='Permit --ui to bind a non-loopback host (exposes scan control to the network)'
        )

        parser.add_argument(
            '--merge-by-host',
            action='store_true',
            help='Legacy compatibility flag retained for the old dedupe path; ignored by the active LLM duplicate flow'
        )

        parser.add_argument(
            '--duplicate-mode',
            choices=['llm', 'off'],
            default=None,
            help='Active duplicate-handling mode: LLM-backed cross-scanner duplicate resolution or off (default: auto from environment)'
        )

        parser.add_argument(
            '--llm-api-url',
            type=str,
            help='OpenAI-compatible chat completions endpoint used for duplicate decisions and advisory finding analysis'
        )

        parser.add_argument(
            '--llm-api-key',
            type=str,
            help='API key for the configured LLM endpoint'
        )

        parser.add_argument(
            '--llm-model',
            type=str,
            help='Model name used for structured duplicate and advisory finding decisions'
        )

        parser.add_argument(
            '--llm-timeout',
            type=float,
            metavar='SECONDS',
            help='Timeout in seconds for one LLM provider request (default: 15 or VULN_MANAGER_LLM_TIMEOUT)'
        )

        parser.add_argument(
            '--llm-debug',
            action='store_true',
            help='Store raw LLM duplicate responses in trace records for debugging'
        )

        parser.add_argument(
            '--no-llm-cache',
            action='store_true',
            help='Disable reuse of cached LLM duplicate and advisory finding decisions'
        )

        parser.add_argument(
            '--knowledge-db',
            type=str,
            help='Path to the YAML store used for LLM decision caches (default: <data-dir>/unified_vulnerabilities.yaml or VULN_MANAGER_KNOWLEDGE_DB)'
        )

        parser.add_argument(
            '--asset-context-file',
            type=str,
            metavar='PATH',
            help='Optional JSON/YAML asset-context rules file applied before runtime risk scoring'
        )

        parser.add_argument(
            '--discover-context',
            action='store_true',
            help='Before scanning, crawl up to three same-site pages and propose a short site context'
        )

        parser.add_argument(
            '--context-accept',
            action='store_true',
            help='Accept the proposed site description without an interactive prompt (requires --discover-context)'
        )

        parser.add_argument(
            '--context-description',
            type=str,
            metavar='TEXT',
            help='Use this human-reviewed description instead of prompting (requires --discover-context)'
        )

        parser.add_argument(
            '--context-reviewer',
            type=str,
            default=os.getenv('VULN_MANAGER_CONTEXT_REVIEWER', 'local-user'),
            metavar='ID',
            help='Reviewer ID recorded in the generated per-site OKF bundle (default: local-user)'
        )

        parser.add_argument(
            '--no-context-reuse',
            action='store_true',
            help='Do not automatically reuse a non-stale human-confirmed site context profile'
        )

        parser.add_argument(
            '--no-ai-analysis',
            action='store_true',
            help='Disable automatic advisory LLM applicability and remediation analysis'
        )

        parser.add_argument(
            '--ai-analysis-limit',
            type=int,
            default=10,
            metavar='COUNT',
            help='Maximum highest-priority findings analyzed by the advisory LLM stage (default: 10)'
        )

        parser.add_argument(
            '--zap-timeout',
            type=int,
            default=1200,
            metavar='SECONDS',
            help='ZAP scan timeout in seconds (default: 1200)'
        )

        parser.add_argument(
            '--zap-active-scan',
            action='store_true',
            help='Add a ZAP Automation Framework activeScan job before reporting when the resolved template does not already include one'
        )

        parser.add_argument(
            '--with-zap',
            action='store_true',
            help='With --scanner all, enable the conservative built-in passive ZAP plan; add --zap-active-scan only when an active scan is authorized'
        )

        parser.add_argument(
            '--zap-report',
            type=str,
            metavar='PATH',
            help='Import an existing OWASP ZAP traditional JSON report instead of starting ZAP; also enables ZAP when disabled by scan config'
        )

        parser.add_argument(
            '--zap-args',
            type=str,
            default='',
            metavar='ARGS',
            help='Extra arguments forwarded to the ZAP runtime before `-cmd -autorun` (e.g. \'--zap-args "-config api.disablekey=true"\')',
        )

        parser.add_argument(
            '--zap-af-plan',
            type=str,
            metavar='PATH',
            help='Optional custom ZAP Automation Framework YAML plan template (defaults to configs/zap_test_template.yaml when omitted)'
        )

        parser.add_argument(
            '--zap-use-proxy',
            action='store_true',
            help='Enable proxy-assisted ZAP mode'
        )

        parser.add_argument(
            '--zap-proxy-url',
            type=str,
            metavar='URL',
            help='Proxy URL that ZAP will actually scan'
        )

        parser.add_argument(
            '--zap-proxy-original-target',
            type=str,
            metavar='URL',
            help='Real target URL to preserve in normalized ZAP findings'
        )

        parser.add_argument(
            '--wapiti-level',
            type=int,
            metavar='LEVEL',
            help='Wapiti scan level (1-3)'
        )

        parser.add_argument(
            '--wapiti-modules',
            nargs='+',
            metavar='MODULE',
            help='Wapiti modules to run (space-separated)'
        )

        parser.add_argument(
            '--wapiti-timeout',
            type=int,
            metavar='SECONDS',
            help='Wapiti scan timeout in seconds'
        )

        parser.add_argument(
            '--wapiti-args',
            type=str,
            default='',
            metavar='ARGS',
            help='Extra arguments forwarded to wapiti'
        )

        parser.add_argument(
            '--nikto-timeout',
            type=int,
            metavar='SECONDS',
            help='Nikto scan timeout in seconds'
        )

        parser.add_argument(
            '--nikto-tuning',
            type=str,
            metavar='TUNING',
            help='Nikto tuning string (e.g. 123b)'
        )

        parser.add_argument(
            '--nikto-args',
            type=str,
            default='',
            metavar='ARGS',
            help='Extra arguments forwarded to nikto'
        )

        parser.add_argument(
            '--strict-scanners',
            action='store_true',
            help='Exit with code 1 if any selected scanner is not available'
        )

        parser.add_argument(
            '--http2-proxy-url',
            type=str,
            help='Optional proxy override for HTTP/2-only routing when a scanner uses proxy mode'
        )

        parser.add_argument(
            '--http2-bridge-url',
            type=str,
            help='Optional local bridge override for HTTP/2-only routing; if omitted, a local bridge is started automatically when needed'
        )

        parser.add_argument(
            '--http2-adapter-mode',
            choices=[
                HTTP2_ADAPTER_MODE_AUTO,
                HTTP2_ADAPTER_MODE_BRIDGE,
            ],
            default=HTTP2_ADAPTER_MODE_AUTO,
            help='Compatibility adapter policy for adapter-dependent HTTP/2-only web scans: preserve automatic routing or force the built-in bridge'
        )

        parser.add_argument(
            '--http-mode',
            choices=[HTTP_MODE_AUTO, HTTP_MODE_HTTP1, HTTP_MODE_HTTP2],
            default=HTTP_MODE_AUTO,
            help='HTTP protocol mode for web scans: auto-detect and route by default, or require http1/http2 explicitly'
        )

        parser.add_argument(
            '--http-probe-timeout',
            type=int,
            default=8,
            metavar='SECONDS',
            help='HTTP transport probe timeout in seconds (default: 8)'
        )

        # When called with no arguments (e.g. `docker run vuln-manager`)
        # default to --list-scanners so the container exits cleanly with useful output.
        if len(sys.argv) == 1:
            sys.argv.append("--list-scanners")

        args = parser.parse_args()
        if (args.context_accept or args.context_description) and not args.discover_context:
            parser.error("--context-accept/--context-description require --discover-context")
        if args.ai_analysis_limit < 1:
            parser.error("--ai-analysis-limit must be at least 1")
        if args.defectdojo_upload and args.no_defectdojo_upload:
            parser.error("--defectdojo-upload and --no-defectdojo-upload cannot be used together")
        if args.defectdojo_auto_create_context and args.defectdojo_no_auto_create_context:
            parser.error("--defectdojo-auto-create-context and --defectdojo-no-auto-create-context cannot be used together")
        if args.defectdojo_verify_ssl and args.defectdojo_insecure:
            parser.error("--defectdojo-verify-ssl and --defectdojo-insecure cannot be used together")
        logging.basicConfig(
            level=logging.DEBUG if args.llm_debug else logging.INFO,
            format='%(message)s',
        )
        defectdojo_file_config = _load_defectdojo_file_config(args, parser)
        defectdojo_upload_requested = _resolve_defectdojo_upload_requested(args, defectdojo_file_config)
        defectdojo_upload_mode = DEFAULT_DEFECTDOJO_UPLOAD_MODE
        if (
            defectdojo_upload_requested
            or args.defectdojo_export
            or args.defectdojo_upload_mode
            or defectdojo_file_config.upload_mode
        ):
            try:
                defectdojo_upload_mode = _resolve_defectdojo_upload_mode(args, defectdojo_file_config)
            except ValueError as exc:
                parser.error(str(exc))
        if args.zap_use_proxy and not args.zap_proxy_url:
            parser.error("--zap-use-proxy requires --zap-proxy-url")
        if args.with_zap and args.scanner != 'all':
            parser.error("--with-zap requires --scanner all")
        if args.with_zap and args.zap_report:
            parser.error("--with-zap cannot be combined with --zap-report")
        if args.with_zap and args.zap_af_plan:
            parser.error(
                "--with-zap uses the conservative built-in ZAP plan and cannot be combined with --zap-af-plan"
            )
        if args.zap_report and args.scanner not in {'all', 'zap'}:
            parser.error("--zap-report requires --scanner all or --scanner zap")
        if args.zap_report and (
            args.zap_active_scan
            or args.zap_af_plan
            or args.zap_args
            or args.zap_use_proxy
            or args.zap_proxy_url
            or args.zap_proxy_original_target
        ):
            parser.error(
                "--zap-report imports an existing report and cannot be combined with ZAP execution options"
            )
        args.zap_af_plan = _expand_existing_path_argument("--zap-af-plan", args.zap_af_plan, parser)
        args.zap_report = _expand_existing_path_argument("--zap-report", args.zap_report, parser)
        args.scan_config = _expand_existing_path_argument("--scan-config", args.scan_config, parser)

        data_dir = Path(args.data_dir)
        orchestrator = create_default_orchestrator(
            reports_dir=data_dir,
            http2_proxy_url=args.http2_proxy_url,
            http2_bridge_url=args.http2_bridge_url,
            http_probe_timeout=args.http_probe_timeout,
        )
        workflow_timer = getattr(orchestrator, 'timing', None)
        if workflow_timer is not None:
            total_workflow_timing = workflow_timer.start(
                'total_workflow',
                note=f"target={args.target or ''}; scanner={args.scanner}",
            )
        if hasattr(orchestrator, 'set_http2_adapter_mode'):
            orchestrator.set_http2_adapter_mode(args.http2_adapter_mode)
        else:
            setattr(orchestrator, 'http2_adapter_mode', args.http2_adapter_mode)

        if args.list_scanners:
            print("\nAvailable Scanners:")
            print("-" * 40)
            for scanner in orchestrator.list_scanners():
                status = "Available" if scanner['available'] else "Not installed"
                version = scanner['version'] or 'Unknown'
                capabilities = scanner.get('capabilities', {})
                print(f"  {scanner['name']}: {status}")
                if scanner['available']:
                    print(f"    Version: {version}")
                print(
                    "    Type: {stype} | HTTP/2 direct: {h2} | Proxy: {proxy}".format(
                        stype=capabilities.get('scanner_type', 'generic'),
                        h2='yes' if capabilities.get('supports_http2_direct') else 'no',
                        proxy='yes' if capabilities.get('supports_proxy') else 'no',
                    )
                )
                if capabilities.get('supports_http2_bridge'):
                    print("    Bridge: yes")
            print("\nHTTP/2 Compatibility Adapters:")
            print("-" * 40)
            print("  bridge: Available")
            return 0

        if getattr(args, 'ui', False):
            from utils.triage_ui import serve
            serve(
                data_dir=data_dir,
                main_py=Path(__file__).resolve(),
                host=args.ui_host,
                port=args.ui_port,
                reviewer=args.ui_reviewer,
                allow_remote=args.allow_remote,
            )
            return 0

        if not args.target:
            parser.error("--target is required for scanning")

        try:
            resolved_scan_config = resolve_scan_config(
                args=args,
                parser=parser,
                scanners=orchestrator.scanners,
                argv=sys.argv[1:],
            )
        except ValueError as exc:
            parser.error(str(exc))

        effective_http_mode = resolved_scan_config.global_settings['http_mode']
        effective_scan_mode = resolved_scan_config.global_settings['scan_mode']
        save_raw = resolved_scan_config.global_settings['save_raw']
        normalize_output = resolved_scan_config.global_settings['normalize']
        risk_scoring_enabled = resolved_scan_config.global_settings['risk_scoring']
        should_report = resolved_scan_config.global_settings['report']

        if not normalize_output:
            if args.report is True:
                parser.error("HTML report requires normalized findings. Remove --no-normalize or add --no-report.")
            if args.compare:
                parser.error("Comparison requires normalized findings. Remove --no-normalize or remove --compare.")

            explicit_merged_upload_mode = (
                args.defectdojo_upload_mode
                and _normalize_defectdojo_upload_mode_alias(args.defectdojo_upload_mode) in {
                    DEFECTDOJO_UPLOAD_MODE_MERGED,
                    "generic",
                }
            )
            if (
                args.defectdojo_export
                or explicit_merged_upload_mode
                or (defectdojo_upload_requested and defectdojo_upload_mode == DEFECTDOJO_UPLOAD_MODE_MERGED)
            ):
                parser.error(
                    "Merged DefectDojo export requires normalized findings. Use raw-per-scan upload or enable normalization."
                )
            if args.duplicate_mode == 'llm':
                parser.error(
                    "LLM duplicate resolution requires normalized findings. Remove --no-normalize or use --duplicate-mode off."
                )
            if not args.no_dedupe and args.duplicate_mode is None and _default_duplicate_mode() == 'llm':
                print(
                    "[!] LLM duplicate resolution disabled because normalization is disabled.",
                    file=sys.stderr,
                )
            if args.asset_context_file:
                print(
                    "[!] Asset context ignored because normalization is disabled.",
                    file=sys.stderr,
                )
            if should_report:
                print(
                    "[!] HTML report disabled because normalization is disabled.",
                    file=sys.stderr,
                )
            if risk_scoring_enabled:
                print(
                    "[!] Risk scoring disabled because normalization is disabled.",
                    file=sys.stderr,
                )
            should_report = False
            risk_scoring_enabled = False
            resolved_scan_config.global_settings['report'] = False
            resolved_scan_config.global_settings['risk_scoring'] = False
            resolved_scan_config.effective_config['global'] = dict(resolved_scan_config.global_settings)
        else:
            args.asset_context_file = _expand_existing_path_argument(
                "--asset-context-file",
                args.asset_context_file,
                parser,
            )

        if defectdojo_upload_requested:
            try:
                _validate_defectdojo_upload_settings(
                    _resolve_defectdojo_config(args, defectdojo_file_config),
                    upload_mode=defectdojo_upload_mode,
                )
            except (ValueError, RuntimeError) as exc:
                parser.error(str(exc))
            print(f"[*] DefectDojo upload mode: {defectdojo_upload_mode}")

        if hasattr(orchestrator, 'set_http_mode'):
            orchestrator.set_http_mode(effective_http_mode)
        else:
            setattr(orchestrator, 'http_mode', effective_http_mode)
        if hasattr(orchestrator, 'set_scan_mode'):
            orchestrator.set_scan_mode(effective_scan_mode)
        else:
            setattr(orchestrator, 'scan_mode', effective_scan_mode)
        try:
            if hasattr(orchestrator, 'set_selected_ports'):
                orchestrator.set_selected_ports(resolved_scan_config.selected_ports_spec)
            else:
                setattr(orchestrator, 'selected_ports_spec', resolved_scan_config.selected_ports_spec)
        except ValueError as exc:
            parser.error(str(exc))

        selected_scanner_options = resolved_scan_config.scanner_options.get(args.scanner, {})
        selected_scanner = orchestrator.scanners.get(args.scanner)
        selected_offline_input = bool(
            selected_scanner
            and _scanner_uses_offline_input(selected_scanner, selected_scanner_options)
        )
        should_probe_target = args.probe_only or (
            args.scanner in WEB_SCANNERS and not selected_offline_input
        )
        target_probe = None
        if should_probe_target and hasattr(orchestrator, 'probe_target'):
            target_probe = orchestrator.probe_target(args.target)

        if not args.json and not args.probe_only:
            print_banner()
        if target_probe and not args.json and not args.probe_only:
            print_target_probe_summary(target_probe, effective_http_mode)
            print()

        if args.probe_only:
            if target_probe is None:
                parser.error("--probe-only requires an orchestrator with target probing support")
            if args.json:
                print(json.dumps(target_probe, indent=2, default=str))
            else:
                print_probe_only_summary(target_probe)
            return 0

        confirmed_asset_knowledge = None
        context_target = (
            target_probe.get("normalized_target")
            if isinstance(target_probe, dict) and target_probe.get("normalized_target")
            else args.target
        )
        context_stream = sys.stderr if args.json else sys.stdout
        if args.discover_context:
            provider_settings = resolve_llm_duplicate_provider_settings(
                cli_api_url=args.llm_api_url,
                cli_api_key=args.llm_api_key,
                cli_model_name=args.llm_model,
                env=os.environ,
            )
            context_timeout = float(args.llm_timeout if args.llm_timeout is not None else 8.0)
            try:
                context_draft = discover_site_context(
                    str(context_target),
                    api_url=provider_settings["api_url"],
                    api_key=provider_settings["api_key"],
                    model_name=provider_settings["model_name"],
                    timeout_seconds=context_timeout,
                )
                _print_site_context_preview(context_draft, stream=context_stream)
                confirmed_description = _review_site_context_description(args, context_draft)
                if confirmed_description:
                    confirmed_asset_knowledge = write_site_okf_bundle(
                        data_dir,
                        context_draft,
                        confirmed_description=confirmed_description,
                        reviewer=args.context_reviewer,
                    )
                    print(
                        f"[+] Confirmed site OKF: {confirmed_asset_knowledge['profile_path']}",
                        file=context_stream,
                    )
                else:
                    print("[*] Continuing without confirmed site context.", file=context_stream)
            except Exception as exc:
                print(
                    f"[!] Site context discovery failed; continuing without it: {exc}",
                    file=sys.stderr,
                )
        elif not args.no_context_reuse:
            try:
                existing_context = load_site_okf_bundle(data_dir, str(context_target))
            except Exception as exc:
                logging.debug("Site context reuse skipped: %s", exc)
                existing_context = None
            if existing_context is not None and existing_context.get('stale'):
                print(
                    "[!] Confirmed site context is stale and will not affect this run. "
                    "Use --discover-context to refresh it.",
                    file=sys.stderr,
                )
            elif existing_context is not None:
                confirmed_asset_knowledge = existing_context
                print(
                    "[*] Reusing confirmed site context: "
                    f"{existing_context.get('profile_path')} "
                    f"(revision {str(existing_context.get('profile_revision') or '')[:12]})",
                    file=context_stream,
                )

        options = resolved_scan_config.scanner_options

        if args.strict_scanners:
            selected = resolved_scan_config.active_scanners
            unavailable = [
                name for name in selected
                if (
                    name in orchestrator.scanners
                    and not _scanner_uses_offline_input(
                        orchestrator.scanners[name], options.get(name, {})
                    )
                    and not orchestrator.scanners[name].is_available()
                )
            ]
            if unavailable:
                print(f"[!] --strict-scanners: unavailable scanner(s): {', '.join(unavailable)}", file=sys.stderr)
                return 1

        if hasattr(orchestrator, 'ensure_run_folder'):
            orchestrator.ensure_run_folder(args.target)
        if orchestrator.current_run_folder:
            save_effective_scan_config(orchestrator.current_run_folder, resolved_scan_config)

        if args.scanner == 'all':
            results = orchestrator.run_all(
                args.target,
                options=options,
                normalize=normalize_output,
                save_raw=save_raw,
            )
        else:
            scanner_result = orchestrator.run_scanner(
                args.scanner,
                args.target,
                options=options.get(args.scanner, {}),
                normalize=normalize_output,
                save_raw=save_raw,
            )
            results = scanner_result
            if 'findings' in results and 'all_findings' not in results:
                _scanner_obj = orchestrator.scanners.get(args.scanner)
                try:
                    _ver = _scanner_obj.get_version() if _scanner_obj else None
                except Exception:
                    _ver = None
                _execution = results.get('scanner_execution', {})
                _transport = results.get('target_probe') or target_probe
                _raw_upload_target = (
                    _execution.get('original_target')
                    if isinstance(_execution, dict) else None
                ) or results.get('origin_target') or results.get('target') or args.target
                results = {
                    'schema_version': SCHEMA_VERSION,
                    'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
                    'target': args.target,
                    'timestamp': results.get('timestamp'),
                    'scanners_run': [args.scanner],
                    'errors': ([{
                        'scanner': args.scanner,
                        'error': results['error']
                    }] if results.get('error') else []),
                    'warnings': ([{
                        'scanner': args.scanner,
                        'warning': results['warning']
                    }] if results.get('warning') else []),
                    'tool_versions': {args.scanner: _ver},
                    'all_findings': results.get('findings', []),
                    'scanner_execution': {args.scanner: _execution},
                    'target_probe': _transport,
                    'transport_detected': _transport,
                    'defectdojo_raw_uploads': [
                        build_raw_upload_manifest_entry(
                            scanner_name=args.scanner,
                            execution_key=args.scanner,
                            target=str(_raw_upload_target or args.target),
                            artifact=scanner_result.get('defectdojo_raw_artifact'),
                            scan_type=resolve_raw_scan_type(args.scanner),
                            raw_artifacts=scanner_result.get('raw_artifacts'),
                        )
                    ],
                    'imported_reports': ([{
                        'scanner': args.scanner,
                        'execution_key': args.scanner,
                        'path': scanner_result.get('imported_report_path'),
                        'format': scanner_result.get('report_format'),
                    }] if scanner_result.get('imported_report') else []),
                    'summary': {
                        'total_findings': len(results.get('findings', [])),
                        'by_severity': orchestrator._count_by_severity(results.get('findings', []))
                    }
                }

        if target_probe and 'target_probe' not in results:
            results['target_probe'] = target_probe
        if target_probe and 'transport_detected' not in results:
            results['transport_detected'] = target_probe
        if confirmed_asset_knowledge:
            results['asset_knowledge'] = _public_asset_knowledge_reference(
                confirmed_asset_knowledge
            )

        _record_missing_scanner_timing(workflow_timer, resolved_scan_config.active_scanners)
        if normalize_output:
            _ensure_skipped_timing_stage(
                workflow_timer,
                'normalization',
                'normalization did not run because no scanner result reached the normalization step',
            )
        else:
            _ensure_skipped_timing_stage(
                workflow_timer,
                'normalization',
                'normalization disabled for this run',
            )

        # (BUG-02 fix: second save_effective_scan_config call removed — already
        # written above before the scan started.  Writing it again here would race
        # with the first write and produce identical output with a newer mtime.)

        if normalize_output:
            duplicate_config = _build_duplicate_config(args)
            validation_error = duplicate_config.validation_error()
            if validation_error:
                parser.error(validation_error)
            try:
                finding_analysis_config = _build_finding_analysis_config(args, duplicate_config)
            except ValueError as exc:
                parser.error(str(exc))
            if args.merge_by_host and not args.json:
                print("[*] --merge-by-host is ignored because the active pipeline no longer uses the legacy host-only dedupe path.")

            asset_context_rules = None
            if args.asset_context_file:
                try:
                    asset_context_rules = load_asset_context_file(args.asset_context_file)
                except (FileNotFoundError, ValueError) as exc:
                    parser.error(str(exc))

            knowledge_db_path = (
                Path(args.knowledge_db).expanduser()
                if args.knowledge_db else Path(
                    os.getenv('VULN_MANAGER_KNOWLEDGE_DB')
                    or (data_dir / 'unified_vulnerabilities.yaml')
                )
            )
            knowledge_db = UnifiedVulnerabilityDatabase(knowledge_db_path)

            resolver = LLMDuplicateResolver(
                duplicate_config,
                database=knowledge_db,
            )
            dedupe_timing = workflow_timer.start(
                'deduplication',
                note=f"duplicate_mode={duplicate_config.mode}",
            ) if workflow_timer is not None else None
            llm_timing = None
            if duplicate_config.mode == 'llm' and workflow_timer is not None:
                llm_timing = workflow_timer.start(
                    'llm_processing',
                    note=f"model={duplicate_config.model_name}; cache_enabled={duplicate_config.cache_enabled}",
                )
            try:
                results = resolver.apply(results)
            except Exception as exc:
                _finish_timing_stage(
                    workflow_timer,
                    llm_timing,
                    status='failed',
                    note=f"llm duplicate processing failed: {exc}",
                )
                _finish_timing_stage(
                    workflow_timer,
                    dedupe_timing,
                    status='failed',
                    note=f"duplicate_mode={duplicate_config.mode}; error={exc}",
                )
                raise
            if llm_timing is not None:
                analysis = results.get('duplicate_analysis') if isinstance(results, dict) else {}
                if not isinstance(analysis, dict):
                    analysis = {}
                llm_note = (
                    f"mode=llm; llm_calls={analysis.get('llm_calls', 0)}; "
                    f"attempted={analysis.get('live_llm_comparisons_attempted', 0)}; "
                    f"succeeded={analysis.get('live_llm_comparisons_succeeded', 0)}"
                )
                _finish_timing_stage(
                    workflow_timer,
                    llm_timing,
                    status='success',
                    note=llm_note,
                )
            analysis = results.get('duplicate_analysis') if isinstance(results, dict) else {}
            if not isinstance(analysis, dict):
                analysis = {}
            _finish_timing_stage(
                workflow_timer,
                dedupe_timing,
                status='success',
                note=(
                    f"duplicate_mode={duplicate_config.mode}; "
                    f"final_findings={len(results.get('all_findings', []))}; "
                    f"merged_groups={analysis.get('total_merged_groups', 0)}"
                ),
            )

            if args.compare:
                comparison_timing = workflow_timer.start(
                    'comparison',
                    note='comparison requested',
                ) if workflow_timer is not None else None
                try:
                    results = add_comparison_to_results(results, data_dir)
                except Exception as exc:
                    _finish_timing_stage(
                        workflow_timer,
                        comparison_timing,
                        status='failed',
                        note=f"comparison failed: {exc}",
                    )
                    raise
                comparison_meta = results.get('comparison') if isinstance(results, dict) else {}
                if not isinstance(comparison_meta, dict):
                    comparison_meta = {}
                _finish_timing_stage(
                    workflow_timer,
                    comparison_timing,
                    status='success',
                    note=str(comparison_meta.get('status') or comparison_meta.get('mode') or 'comparison completed'),
                )
            else:
                _ensure_skipped_timing_stage(
                    workflow_timer,
                    'comparison',
                    'comparison not requested',
                )

            if asset_context_rules:
                results = _apply_asset_context_to_results(results, asset_context_rules)

            if risk_scoring_enabled:
                results = score_vulnerabilities(
                    results,
                    context=_site_context_scoring_context(results, confirmed_asset_knowledge),
                )
            else:
                results = _strip_runtime_risk_fields(results)

            finding_analysis_timing = workflow_timer.start(
                'finding_analysis',
                note=(
                    f"model={finding_analysis_config.model_name or 'not-configured'}; "
                    f"limit={finding_analysis_config.limit}"
                ),
            ) if workflow_timer is not None else None
            try:
                results = LLMFindingAnalyzer(
                    finding_analysis_config,
                    database=knowledge_db,
                ).apply(
                    results,
                    asset_knowledge=confirmed_asset_knowledge,
                )
            except Exception as exc:
                _clear_partial_ai_analysis(results)
                results['ai_analysis_summary'] = _unexpected_ai_analysis_summary(
                    finding_analysis_config
                )
                logging.exception("Unexpected advisory AI analysis failure")
                _finish_timing_stage(
                    workflow_timer,
                    finding_analysis_timing,
                    status='failed',
                    note=f"advisory analyzer failed open: {type(exc).__name__}",
                )
            else:
                ai_summary = results.get('ai_analysis_summary')
                if not isinstance(ai_summary, dict):
                    ai_summary = {}
                _finish_timing_stage(
                    workflow_timer,
                    finding_analysis_timing,
                    status='success',
                    note=(
                        f"status={ai_summary.get('status', 'unknown')}; "
                        f"analyzed={ai_summary.get('analyzed_count', 0)}; "
                        f"cached={ai_summary.get('cached_count', 0)}; "
                        f"unavailable={ai_summary.get('unavailable_count', 0)}"
                    ),
                )

            ai_summary = results.get('ai_analysis_summary')
            if isinstance(ai_summary, dict):
                ai_log_stream = sys.stderr if args.json else sys.stdout
                ai_status = ai_summary.get('status')
                if ai_status == 'disabled_not_configured':
                    print(
                        "[*] AI finding analysis disabled: LLM provider is not configured.",
                        file=ai_log_stream,
                    )
                elif ai_status == 'disabled_by_user':
                    print("[*] AI finding analysis disabled by --no-ai-analysis.", file=ai_log_stream)
                else:
                    print(
                        "[*] AI finding analysis: "
                        f"status={ai_status}, analyzed={ai_summary.get('analyzed_count', 0)}, "
                        f"cached={ai_summary.get('cached_count', 0)}, "
                        f"unavailable={ai_summary.get('unavailable_count', 0)}.",
                        file=ai_log_stream,
                    )
            # Re-attach saved human triage decisions before sanitize so future
            # scans reflect prior analyst judgements. Read-only on the store and
            # a no-op when the per-site bundle has no annotations.
            if getattr(args, 'apply_annotations', True):
                results = apply_annotations(results, data_dir=data_dir)
            results = sanitize_results_for_export(results)
            ai_metrics_path = _save_ai_analysis_metrics(
                getattr(orchestrator, 'current_run_folder', None),
                results.get('ai_analysis_summary'),
            )
            if ai_metrics_path is not None and not args.json:
                print(f"[+] AI analysis metrics saved to: {ai_metrics_path}")

            # Stamp final metadata, validate, then persist.
            # main.py owns this responsibility; save_results() does not auto-fill.
            # BUG-06 fix: preserve the generated_at timestamp that _finalize_aggregate_results
            # already stamped on run_all() results.  For single-scanner paths the key is
            # absent, so setdefault() still produces the required field.
            results['schema_version'] = SCHEMA_VERSION
            results.setdefault(
                'generated_at',
                datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            )
            assert_valid_results(results, stage='final')
            json_path = orchestrator.save_results(results, args.output)
        else:
            _ensure_skipped_timing_stage(
                workflow_timer,
                'deduplication',
                'deduplication skipped because normalization is disabled',
            )
            _ensure_skipped_timing_stage(
                workflow_timer,
                'finding_analysis',
                'advisory AI analysis skipped because normalization is disabled',
            )
            _ensure_skipped_timing_stage(
                workflow_timer,
                'comparison',
                'comparison skipped because normalization is disabled',
            )
            results['schema_version'] = results.get('schema_version') or SCHEMA_VERSION
            results.setdefault(
                'generated_at',
                datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            )
            json_path = _save_raw_only_results(orchestrator, results, args.output, data_dir)

        if should_report and orchestrator.current_run_folder:
            html_path = orchestrator.current_run_folder / 'report.html'
            report_timing = workflow_timer.start(
                'report_generation',
                note=f"output={html_path}",
            ) if workflow_timer is not None else None
            try:
                generate_html_report(results, html_path)
            except Exception as exc:
                _finish_timing_stage(
                    workflow_timer,
                    report_timing,
                    status='failed',
                    note=f"report generation failed: {exc}",
                )
                raise
            _finish_timing_stage(
                workflow_timer,
                report_timing,
                status='success',
                note=f"output={html_path}",
            )
            if not args.json:
                print(f"[+] HTML report generated: {html_path}")
        else:
            _ensure_skipped_timing_stage(
                workflow_timer,
                'report_generation',
                'HTML report generation disabled or no run folder was created',
            )

        defectdojo_export_requested = (
            args.defectdojo_export
            or (defectdojo_upload_requested and defectdojo_upload_mode == DEFECTDOJO_UPLOAD_MODE_MERGED)
        )
        defectdojo_error = None
        if defectdojo_export_requested:
            try:
                defectdojo_path = _defectdojo_output_path(orchestrator, json_path)
                write_defectdojo_generic_report(results, defectdojo_path)
                print(f"[+] DefectDojo export written: {defectdojo_path}")

                if defectdojo_upload_requested:
                    defectdojo_config = _resolve_defectdojo_config(args, defectdojo_file_config)
                    defectdojo_scan_date = normalize_defectdojo_scan_date(
                        args.defectdojo_scan_date or results.get('generated_at')
                    )
                    defectdojo_response = upload_defectdojo_report(
                        defectdojo_path,
                        defectdojo_config,
                        scan_date=defectdojo_scan_date,
                    )
                    print(f"[+] DefectDojo import/reimport succeeded: {_defectdojo_success_message(defectdojo_response)}")
            except Exception as exc:
                defectdojo_error = exc
                action = "upload" if defectdojo_upload_requested else "export"
                print(f"[!] DefectDojo {action} failed: {exc}", file=sys.stderr)
                if defectdojo_upload_requested:
                    print(
                        "[!] DefectDojo did not import the scan. Final scan results and "
                        "defectdojo_generic.json were kept for retry.",
                        file=sys.stderr,
                    )

        if defectdojo_upload_requested and defectdojo_upload_mode == DEFECTDOJO_UPLOAD_MODE_RAW_PER_SCAN:
            try:
                defectdojo_config = _resolve_defectdojo_config(args, defectdojo_file_config)
                defectdojo_scan_date = normalize_defectdojo_scan_date(
                    args.defectdojo_scan_date or results.get('generated_at')
                )
                raw_upload_summary = _upload_defectdojo_raw_manifest(
                    results,
                    defectdojo_config,
                    scan_date=defectdojo_scan_date,
                    scan_type_overrides=_resolve_defectdojo_raw_scan_type_overrides(args, defectdojo_file_config),
                    file_config=defectdojo_file_config,
                )
                if raw_upload_summary.get('failed'):
                    defectdojo_error = RuntimeError(
                        f"{raw_upload_summary['failed']} DefectDojo raw upload(s) failed"
                    )
            except Exception as exc:
                defectdojo_error = exc
                print(f"[!] DefectDojo raw upload failed: {exc}", file=sys.stderr)
                print(
                    "[!] DefectDojo did not import every raw scanner artifact. Final scan results were kept for retry.",
                    file=sys.stderr,
                )

        if total_workflow_timing is not None:
            _finish_timing_stage(
                workflow_timer,
                total_workflow_timing,
                status='failed' if defectdojo_error is not None else 'success',
                note=(
                    f"target={args.target}; scanner={args.scanner}; "
                    f"findings={len(results.get('all_findings', []))}; "
                    f"defectdojo_error={defectdojo_error}"
                    if defectdojo_error is not None
                    else f"target={args.target}; scanner={args.scanner}; findings={len(results.get('all_findings', []))}"
                ),
            )
            total_workflow_timing = None
        _save_and_print_timing(
            timer=workflow_timer,
            target=args.target,
            run_folder=getattr(orchestrator, 'current_run_folder', None),
            json_mode=args.json,
        )

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            print_summary(results)
            if args.compare and results.get('comparison'):
                 print_comparison_summary(results)
            print_findings(results, args.verbose)
            print(f"\n[✓] Results saved to: {json_path}")

        if defectdojo_error is not None:
            return 1
        return 0
    except KeyboardInterrupt:
        print("Scan cancelled by user.", file=sys.stderr)
        return 130
    finally:
        if orchestrator is not None and hasattr(orchestrator, 'shutdown_background_services'):
            try:
                orchestrator.shutdown_background_services()
            except Exception as exc:
                print(f"[!] Failed to stop background helper services: {exc}", file=sys.stderr)

if __name__ == '__main__':
    sys.exit(main())
