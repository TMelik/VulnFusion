#!/usr/bin/env python3
"""
Smoke-test the OpenAI-compatible LLM credentials used by vuln-manager.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from utils.env_loader import load_project_dotenv
from utils.llm_duplicate_resolver import (
    LLMDuplicateConfig,
    LLMDuplicateResolver,
    OpenAICompatibleLLMClient,
    _coerce_provider_error,
    resolve_llm_duplicate_provider_settings,
)

load_project_dotenv(ROOT)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the built-in OpenAI-compatible provider health check used "
            "by the LLM duplicate resolver."
        )
    )
    parser.add_argument(
        "--api-url",
        help=(
            "Override the chat completions endpoint. Defaults to "
            "VULN_MANAGER_LLM_API_URL."
        ),
    )
    parser.add_argument(
        "--api-key",
        help=(
            "Override the API key. Defaults to VULN_MANAGER_LLM_API_KEY."
        ),
    )
    parser.add_argument(
        "--model",
        help=(
            "Override the model name. Defaults to VULN_MANAGER_LLM_MODEL."
        ),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.getenv("VULN_MANAGER_LLM_TIMEOUT", "15")),
        help="Timeout in seconds for the health check request (default: 15)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the result as JSON instead of human-readable text.",
    )
    parser.add_argument(
        "--duplicate-smoke",
        action="store_true",
        help=(
            "Run the live duplicate-resolution smoke path used by the resolver. "
            "This performs the provider health check and at least one real comparison."
        ),
    )
    return parser


def build_config(args: argparse.Namespace) -> LLMDuplicateConfig:
    provider_settings = resolve_llm_duplicate_provider_settings(
        cli_api_url=args.api_url,
        cli_api_key=args.api_key,
        cli_model_name=args.model,
        env=os.environ,
    )
    return LLMDuplicateConfig(
        mode="llm",
        api_url=provider_settings["api_url"],
        api_key=provider_settings["api_key"],
        model_name=provider_settings["model_name"],
        timeout_seconds=float(args.timeout),
        cache_enabled=False,
    )


def _print_human_success(config: LLMDuplicateConfig, result: Dict[str, Any]) -> None:
    summary = config.safe_summary()
    print("[+] OpenAI-compatible provider health check passed.")
    print(f"    api_url: {summary['api_url']}")
    print(f"    model: {summary['model_name']}")
    print(f"    api_key: {summary['api_key']}")
    print(f"    llm_decision: {result.get('llm_decision')}")
    print(f"    request_hash: {result.get('request_hash')}")
    print(f"    attempt_count: {result.get('attempt_count')}")


def _print_human_failure(config: LLMDuplicateConfig, error_payload: Dict[str, Any]) -> None:
    summary = config.safe_summary()
    print("[-] OpenAI-compatible provider health check failed.", file=sys.stderr)
    print(f"    api_url: {summary['api_url']}", file=sys.stderr)
    print(f"    model: {summary['model_name']}", file=sys.stderr)
    print(f"    api_key: {summary['api_key']}", file=sys.stderr)
    print(f"    category: {error_payload.get('category')}", file=sys.stderr)
    print(f"    message: {error_payload.get('error')}", file=sys.stderr)
    if error_payload.get("http_status_code") is not None:
        print(f"    http_status_code: {error_payload['http_status_code']}", file=sys.stderr)
    print(f"    attempt_count: {error_payload.get('attempt_count')}", file=sys.stderr)


def _smoke_finding(
    scanner: str,
    *,
    title: str,
    asset_id: str,
    description: str,
    path: str,
    parameter: str,
    raw_id: str,
) -> Dict[str, Any]:
    return {
        "vulnerability_name": title,
        "severity": "medium",
        "asset_id": asset_id,
        "description": description,
        "remediation": "Review and fix the affected input handling.",
        "meta": {
            "scanner": scanner,
            "timestamp": "2026-04-20T00:00:00Z",
            "host": "example.com",
            "scheme": "https",
            "port": 443,
            "path": path,
            "parameter": parameter,
            "method": "GET",
            "query_keys": [parameter] if parameter else [],
            "raw_id": raw_id,
            "category": "SQL Injection",
        },
    }


def build_duplicate_smoke_findings() -> list[Dict[str, Any]]:
    """Return a gray-zone pair that must cross the live provider boundary."""
    return [
        _smoke_finding(
            "zap",
            title="SQL Injection in search parameter",
            asset_id="https://example.com/login?q=1",
            description="search field may be injectable",
            path="/login",
            parameter="q",
            raw_id="zap-live-smoke-1",
        ),
        _smoke_finding(
            "nuclei",
            title="SQL Injection",
            asset_id="https://example.com/login?account=2",
            description="generic SQL injection finding on a nearby login input",
            path="/login",
            parameter="account",
            raw_id="nuclei-live-smoke-1",
        ),
    ]


def _safe_comparison_record(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "comparison_status": record.get("comparison_status"),
        "llm_decision": record.get("llm_decision"),
        "sent_to_llm": bool(record.get("sent_to_llm")),
        "used_cache": bool(record.get("used_cache")),
        "provider_request_kind": record.get("provider_request_kind"),
        "provider_attempt_count": record.get("provider_attempt_count"),
        "provider_failure_category": record.get("provider_failure_category"),
        "http_status_code": record.get("http_status_code"),
        "request_hash": record.get("request_hash"),
        "error_message": record.get("error_message"),
    }


def run_duplicate_smoke(config: LLMDuplicateConfig) -> Dict[str, Any]:
    """Execute the real duplicate-resolution path and return a safe summary payload."""
    resolver = LLMDuplicateResolver(config)
    results = resolver.apply(
        {
            "all_findings": build_duplicate_smoke_findings(),
            "summary": {},
        }
    )
    duplicate_analysis = dict(results.get("duplicate_analysis") or {})
    comparison_records = [
        _safe_comparison_record(record)
        for record in (results.get("llm_duplicate_comparisons") or [])
        if isinstance(record, dict)
    ]

    checks = {
        "provider_healthcheck_passed": duplicate_analysis.get("provider_healthcheck_status") == "passed",
        "live_comparison_attempted": int(duplicate_analysis.get("live_llm_comparisons_attempted") or 0) >= 1,
        "live_comparison_succeeded": int(duplicate_analysis.get("live_llm_comparisons_succeeded") or 0) >= 1,
        "provider_boundary_reached": any(record.get("comparison_status") == "compared_with_llm" for record in comparison_records),
        "comparison_sent_to_llm": any(record.get("sent_to_llm") for record in comparison_records),
    }
    failures = [name for name, passed in checks.items() if not passed]

    return {
        "status": "passed" if not failures else "failed",
        "mode": "duplicate_smoke",
        "config": config.safe_summary(),
        "checks": checks,
        "failed_checks": failures,
        "duplicate_analysis": duplicate_analysis,
        "comparison_records": comparison_records,
    }


def _print_duplicate_smoke_success(config: LLMDuplicateConfig, payload: Dict[str, Any]) -> None:
    summary = config.safe_summary()
    analysis = payload.get("duplicate_analysis") or {}
    comparison_records = payload.get("comparison_records") or []
    print("[+] Live LLM duplicate smoke test passed.")
    print(f"    api_url: {summary['api_url']}")
    print(f"    model: {summary['model_name']}")
    print(f"    api_key: {summary['api_key']}")
    print(f"    provider_healthcheck_status: {analysis.get('provider_healthcheck_status')}")
    print(f"    live_llm_comparisons_attempted: {analysis.get('live_llm_comparisons_attempted')}")
    print(f"    live_llm_comparisons_succeeded: {analysis.get('live_llm_comparisons_succeeded')}")
    if comparison_records:
        first_record = comparison_records[0]
        print(f"    comparison_status: {first_record.get('comparison_status')}")
        print(f"    request_hash: {first_record.get('request_hash')}")
        print(f"    provider_attempt_count: {first_record.get('provider_attempt_count')}")


def _print_duplicate_smoke_failure(config: LLMDuplicateConfig, payload: Dict[str, Any]) -> None:
    summary = config.safe_summary()
    analysis = payload.get("duplicate_analysis") or {}
    comparison_records = payload.get("comparison_records") or []
    print("[-] Live LLM duplicate smoke test failed.", file=sys.stderr)
    print(f"    api_url: {summary['api_url']}", file=sys.stderr)
    print(f"    model: {summary['model_name']}", file=sys.stderr)
    print(f"    api_key: {summary['api_key']}", file=sys.stderr)
    print(f"    failed_checks: {', '.join(payload.get('failed_checks') or [])}", file=sys.stderr)
    print(f"    provider_healthcheck_status: {analysis.get('provider_healthcheck_status')}", file=sys.stderr)
    print(f"    provider_healthcheck_error: {analysis.get('provider_healthcheck_error')}", file=sys.stderr)
    print(f"    live_llm_comparisons_attempted: {analysis.get('live_llm_comparisons_attempted')}", file=sys.stderr)
    print(f"    live_llm_comparisons_succeeded: {analysis.get('live_llm_comparisons_succeeded')}", file=sys.stderr)
    print(f"    live_llm_comparisons_failed: {analysis.get('live_llm_comparisons_failed')}", file=sys.stderr)
    if analysis.get("provider_failure_categories"):
        print(f"    provider_failure_categories: {analysis.get('provider_failure_categories')}", file=sys.stderr)
    if comparison_records:
        first_record = comparison_records[0]
        print(f"    comparison_status: {first_record.get('comparison_status')}", file=sys.stderr)
        print(f"    provider_failure_category: {first_record.get('provider_failure_category')}", file=sys.stderr)
        print(f"    http_status_code: {first_record.get('http_status_code')}", file=sys.stderr)
        print(f"    error_message: {first_record.get('error_message')}", file=sys.stderr)


def main() -> int:
    args = _parser().parse_args()
    config = build_config(args)
    validation_error = config.validation_error()
    if validation_error:
        if args.json:
            print(json.dumps({
                "status": "invalid_configuration",
                "config": config.safe_summary(),
                "error": validation_error,
            }, indent=2))
        else:
            print("[-] OpenAI-compatible provider health check cannot run.", file=sys.stderr)
            print(f"    {validation_error}", file=sys.stderr)
            print(
                "    Tip: put VULN_MANAGER_LLM_API_URL/VULN_MANAGER_LLM_API_KEY/"
                "VULN_MANAGER_LLM_MODEL in a local .env or export them in your shell.",
                file=sys.stderr,
            )
        return 2

    if args.duplicate_smoke:
        smoke_payload = run_duplicate_smoke(config)
        if args.json:
            print(json.dumps(smoke_payload, indent=2))
        elif smoke_payload["status"] == "passed":
            _print_duplicate_smoke_success(config, smoke_payload)
        else:
            _print_duplicate_smoke_failure(config, smoke_payload)
        return 0 if smoke_payload["status"] == "passed" else 1

    client = OpenAICompatibleLLMClient(config)
    try:
        result = client.healthcheck()
    except Exception as exc:
        provider_error = _coerce_provider_error(exc, request_kind="healthcheck")
        error_payload = {
            "status": "failed",
            "config": config.safe_summary(),
            "error": str(provider_error),
            "category": provider_error.category,
            "http_status_code": provider_error.http_status_code,
            "attempt_count": provider_error.attempt_count,
            "retry_backoff_seconds": list(provider_error.retry_backoff_seconds),
        }
        if args.json:
            print(json.dumps(error_payload, indent=2))
        else:
            _print_human_failure(config, error_payload)
        return 1

    success_payload = {
        "status": "passed",
        "config": config.safe_summary(),
        "result": result,
    }
    if args.json:
        print(json.dumps(success_payload, indent=2))
    else:
        _print_human_success(config, result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
