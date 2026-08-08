import copy
import json
import os

import pytest

import main
import utils.llm_duplicate_resolver as llm_duplicate_resolver
from utils.llm_duplicate_resolver import (
    LLMProviderError,
    LLMDuplicateConfig,
    LLMDuplicateResolver,
    OpenAICompatibleLLMClient,
    build_llm_request_body,
    findings_share_same_target,
    parse_llm_yes_no_response,
)
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase


def _finding(
    scanner: str,
    *,
    title: str,
    asset_id: str,
    description: str,
    severity: str = "medium",
    path: str = "/login",
    parameter: str = "",
    method: str = "GET",
    cve_ids: list[str] | None = None,
    cwe_list: list[str] | None = None,
    category: str | None = None,
    technology: str | None = None,
    raw_id: str | None = None,
    meta_extra: dict | None = None,
) -> dict:
    meta = {
        "scanner": scanner,
        "timestamp": "2026-04-09T12:00:00Z",
        "host": "example.com",
        "scheme": "https",
        "port": 443,
        "path": path,
        "parameter": parameter,
        "method": method,
        "query_keys": ["q"] if "?" in asset_id else [],
    }
    if cve_ids:
        meta["cve_ids"] = cve_ids
        meta["cve_id"] = cve_ids[0]
    if cwe_list:
        meta["cwe_list"] = cwe_list
        meta["cwe"] = cwe_list[0]
    if category:
        meta["category"] = category
    if technology:
        meta["technology"] = technology
    if raw_id:
        meta["raw_id"] = raw_id
    if scanner == "zap":
        meta["plugin_id"] = raw_id or "zap-plugin"
        meta["evidence"] = "evidence"
    if scanner == "nuclei":
        meta["template_id"] = raw_id or "nuclei-template"
    if meta_extra:
        meta.update(meta_extra)
    return {
        "vulnerability_name": title,
        "severity": severity,
        "asset_id": asset_id,
        "description": description,
        "remediation": "Fix it.",
        "meta": meta,
    }


class FakeLLMClient:
    def __init__(self, decision_by_pair=None, error=None):
        self.calls = []
        self.decision_by_pair = decision_by_pair or {}
        self.error = error

    def compare(self, finding_a, finding_b, *, runtime_cache=None):
        self.calls.append((finding_a["vulnerability_name"], finding_b["vulnerability_name"]))
        if self.error is not None:
            raise self.error
        key = tuple(sorted((finding_a["vulnerability_name"], finding_b["vulnerability_name"])))
        decision = self.decision_by_pair.get(key, "yes")
        response_payload = {"choices": [{"message": {"content": decision}}]}
        return decision, response_payload, json.dumps(response_payload), f"hash-{len(self.calls)}"


class HealthcheckedFakeLLMClient(FakeLLMClient):
    def __init__(self, decision_by_pair=None, error=None, *, healthcheck_payload=None):
        super().__init__(decision_by_pair=decision_by_pair, error=error)
        self.healthcheck_calls = 0
        self.compare_calls = 0
        self.healthcheck_payload = healthcheck_payload or {
            "status": "passed",
            "llm_decision": "yes",
            "request_hash": "healthcheck-hash",
            "attempt_count": 1,
            "retry_backoff_seconds": [],
        }

    def healthcheck(self):
        self.healthcheck_calls += 1
        return copy.deepcopy(self.healthcheck_payload)

    def compare(self, finding_a, finding_b, *, runtime_cache=None):
        self.compare_calls += 1
        return super().compare(finding_a, finding_b, runtime_cache=runtime_cache)


class HealthcheckFailingClient:
    def __init__(self, error):
        self.error = error
        self.healthcheck_calls = 0
        self.compare_calls = 0

    def healthcheck(self):
        self.healthcheck_calls += 1
        raise self.error

    def compare(self, finding_a, finding_b, *, runtime_cache=None):
        self.compare_calls += 1
        raise AssertionError("compare should not be called after a failed health check")


class ScriptedHTTPResponse:
    def __init__(self, status_code, *, json_data=None, text=None, json_error=None):
        self.status_code = status_code
        self._json_data = json_data
        self._json_error = json_error
        self.text = text if text is not None else (json.dumps(json_data) if json_data is not None else "")

    def json(self):
        if self._json_error is not None:
            raise self._json_error
        if self._json_data is None:
            raise ValueError("response body is not JSON")
        return self._json_data


def _llm_config(*, api_key="super-secret-key-1234", debug=False) -> LLMDuplicateConfig:
    return LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key=api_key,
        model_name="test-model",
        debug=debug,
    )


def _install_scripted_http(monkeypatch, responses, calls):
    class _FakeHTTPClient:
        def __init__(self, *args, **kwargs):
            self.timeout = kwargs.get("timeout")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def post(self, url, json=None, headers=None):
            calls.append(
                {
                    "url": url,
                    "json": copy.deepcopy(json),
                    "headers": dict(headers or {}),
                }
            )
            if not responses:
                raise AssertionError("unexpected extra HTTP request")
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

    monkeypatch.setattr(llm_duplicate_resolver.httpx, "Client", _FakeHTTPClient)


def _same_target_triplet() -> list[dict]:
    return [
        _finding("zap", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="zap-1"),
        _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="nuclei-1"),
        _finding("wapiti", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="wapiti-1"),
    ]


def _weak_endpoint_sqli(
    scanner: str,
    *,
    parameter: str,
    path: str = "/db/get",
    asset_id: str | None = None,
    raw_id: str | None = None,
    severity: str = "info",
    confidence: str = "medium",
    description: str | None = None,
    method: str = "GET",
) -> dict:
    asset = asset_id or f"https://example.com{path}"
    request_target = path
    if (
        parameter
        and "header" not in parameter.lower()
        and "cookie" not in parameter.lower()
        and "?" not in asset
    ):
        request_target = f"{path}?{parameter.lower().replace(' ', '-') }=1"

    return _finding(
        scanner,
        title="SQL Injection",
        asset_id=asset,
        description=description or f"Weak SQL injection signal via parameter {parameter}",
        severity=severity,
        path=path,
        parameter=parameter,
        method=method,
        category="SQL Injection",
        raw_id=raw_id,
        meta_extra={
            "module": "sql",
            "http_request": f"{method} {request_target} HTTP/1.1",
            "curl_command": f"curl 'https://example.com{request_target}'",
            "evidence_quality": {
                "confidence": confidence,
                "repeatable": False,
                "degraded_execution": False,
                "all_sources_degraded": False,
            },
        },
    )


# Gray-zone fixtures must avoid deterministic anchors on purpose.
# If deterministic rules expand and one of these pairs becomes obvious, refresh
# the fixture rather than weakening production logic to force an LLM call.
def _gray_zone_sqli_pair() -> list[dict]:
    return [
        _finding(
            "zap",
            title="SQL Injection in search parameter",
            asset_id="https://example.com/login?q=1",
            description="search field may be injectable",
            parameter="q",
            raw_id="zap-3",
            category="SQL Injection",
        ),
        _finding(
            "nuclei",
            title="SQL Injection",
            asset_id="https://example.com/login?account=2",
            description="generic SQL injection finding on a nearby login input",
            parameter="account",
            raw_id="nuclei-3",
            category="SQL Injection",
            meta_extra={"query_keys": ["account"]},
        ),
    ]


def _gray_zone_header_pair() -> list[dict]:
    return [
        _finding(
            "zap",
            title="Clickjacking policy check",
            asset_id="https://example.com/login",
            description="Login page may not enforce anti-framing controls.",
            raw_id="zap-clickjacking-review",
            category="Browser Security",
        ),
        _finding(
            "nuclei",
            title="Framing protections review",
            asset_id="https://example.com/login",
            description="Template flagged potentially missing anti-framing controls.",
            raw_id="nuclei-framing-review",
            category="Browser Security",
        ),
    ]


def _gray_zone_service_vs_url_pair() -> list[dict]:
    return [
        _finding(
            "nmap",
            title="Potential CMS Exposure",
            asset_id="example.com:443",
            description="HTTPS service exposes a CMS login surface.",
            raw_id="nmap-web-fingerprint",
            meta_extra={
                "scheme": "",
                "protocol": "tcp",
                "service": "https",
                "path": "",
                "query_keys": [],
                "technology": "AcmeCMS",
                "method": "",
            },
        ),
        _finding(
            "nuclei",
            title="Generic CMS SQLi",
            asset_id="https://example.com/login",
            description="Generic SQL injection match on the AcmeCMS login endpoint.",
            raw_id="nuclei-cms-sqli",
            category="SQL Injection",
            technology="AcmeCMS",
        ),
    ]


@pytest.fixture
def duplicate_test_pairs():
    return {
        "same_vuln": _gray_zone_header_pair(),
        "clearly_not_same_vuln": [
            _finding("zap", title="Missing Content-Security-Policy Header", asset_id="https://example.com/login", description="missing CSP header", raw_id="zap-2"),
            _finding("nuclei", title="X-Content-Type-Options Header Missing", asset_id="https://example.com/login", description="missing X-Content-Type-Options header", raw_id="nuclei-2"),
        ],
        "ambiguous_reaches_llm": _gray_zone_sqli_pair(),
        "low_similarity_skip": [
            _finding("zap", title="Missing X-Frame-Options Header", asset_id="https://example.com/login", description="header issue", raw_id="zap-4"),
            _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="sqli issue", raw_id="nuclei-4"),
        ],
    }


def _duplicate_debug_snapshot(results: dict) -> str:
    return json.dumps(
        {
            "duplicate_analysis": results.get("duplicate_analysis"),
            "llm_duplicate_comparisons": results.get("llm_duplicate_comparisons"),
            "all_findings_count": len(results.get("all_findings", [])),
        },
        sort_keys=True,
        indent=2,
        default=str,
    )


def _live_llm_smoke_enabled(pytestconfig) -> bool:
    return bool(
        pytestconfig.getoption("--run-live-llm")
        or os.getenv("RUN_LIVE_LLM_TESTS") == "1"
    )


def _legacy_cache_key(finding_a: dict, finding_b: dict, *, model_name: str) -> tuple[str, str]:
    ordered_a, ordered_b = llm_duplicate_resolver._normalize_order(finding_a, finding_b)
    pair_key = f"{ordered_a['finding_id']}::{ordered_b['finding_id']}"
    comparison_payload = llm_duplicate_resolver._comparison_prompt_payload(ordered_a, ordered_b)
    payload = {
        "pair_key": pair_key,
        "model_name": model_name,
        "finding_a": comparison_payload["finding_a"],
        "finding_b": comparison_payload["finding_b"],
        "prompt_version": 1,
    }
    return pair_key, llm_duplicate_resolver._sha256_text(json.dumps(payload, sort_keys=True, ensure_ascii=True))


def _install_recording_boundary_client(monkeypatch, *, decision: str = "yes"):
    calls = {"healthcheck": 0, "compare": []}

    class _RecordingBoundaryClient:
        def __init__(self, config):
            self.config = config

        def healthcheck(self):
            calls["healthcheck"] += 1
            return {
                "status": "passed",
                "llm_decision": "yes",
                "request_hash": "healthcheck-hash",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            }

        def compare(self, finding_a, finding_b, *, runtime_cache=None):
            calls["compare"].append((finding_a["vulnerability_name"], finding_b["vulnerability_name"]))
            payload = {
                "choices": [{"message": {"content": decision}}],
                "_provider_request": {
                    "request_kind": "comparison",
                    "attempt_count": 1,
                    "retry_backoff_seconds": [],
                },
            }
            raw_response = json.dumps({"choices": [{"message": {"content": decision}}]})
            return decision, payload, raw_response, f"request-{len(calls['compare'])}"

    monkeypatch.setattr(llm_duplicate_resolver, "OpenAICompatibleLLMClient", _RecordingBoundaryClient)
    return calls


def _build_main_flow_orchestrator(tmp_path, findings: list[dict]):
    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": "2.0",
                "target": target,
                "timestamp": "2026-04-09T12:00:00Z",
                "scanners_run": [finding["meta"]["scanner"] for finding in findings],
                "all_findings": copy.deepcopy(findings),
                "errors": [],
                "summary": {
                    "total_findings": len(findings),
                    "by_severity": {"critical": 0, "high": 0, "medium": len(findings), "low": 0, "info": 0},
                },
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results), encoding="utf-8")
            return path

    return FakeOrchestrator()


def test_same_target_detection_uses_existing_target_fields():
    zap = _finding(
        "zap",
        title="Missing X-Frame-Options Header",
        asset_id="https://example.com/login?q=1",
        description="header missing",
        parameter="q",
        raw_id="zap-1",
    )
    nuclei = _finding(
        "nuclei",
        title="Clickjacking protection header missing",
        asset_id="https://example.com/login?q=2",
        description="header missing too",
        parameter="q",
        raw_id="nuclei-1",
    )
    other_path = _finding(
        "nuclei",
        title="Clickjacking protection header missing",
        asset_id="https://example.com/admin?q=2",
        description="different endpoint",
        path="/admin",
        parameter="q",
        raw_id="nuclei-2",
    )

    same_target, same_reason = findings_share_same_target(zap, nuclei)
    compatible_target, reason = findings_share_same_target(zap, other_path)

    assert same_target is True
    assert same_reason["reason"] == "same_target"
    assert compatible_target is True
    assert reason["reason"] == "same_host_compatible"
    assert "path_mismatch" in reason["soft_signals"]


def test_runtime_cache_resets_between_apply_calls_with_reused_finding_ids():
    resolver = LLMDuplicateResolver(
        _llm_config(),
        client=HealthcheckedFakeLLMClient(),
    )
    first_run_findings = [
        _weak_endpoint_sqli("zap", parameter="user", raw_id="zap-run-1"),
        _weak_endpoint_sqli("nuclei", parameter="search", raw_id="nuclei-run-1"),
    ]
    for finding_id, finding in zip(("stable-a", "stable-b"), first_run_findings):
        finding["finding_id"] = finding_id

    second_run_findings = [
        _weak_endpoint_sqli("zap", parameter="user", raw_id="zap-run-2"),
        _weak_endpoint_sqli(
            "nuclei",
            parameter="search",
            asset_id="https://other.example/db/get?search=1",
            raw_id="nuclei-run-2",
        ),
    ]
    for finding_id, finding in zip(("stable-a", "stable-b"), second_run_findings):
        finding["finding_id"] = finding_id

    first_results = resolver.apply({"all_findings": first_run_findings, "summary": {}})
    second_results = resolver.apply({"all_findings": second_run_findings, "summary": {}})

    assert len(first_results["all_findings"]) == 1
    assert first_results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm"
    assert len(second_results["all_findings"]) == 2
    assert second_results["llm_duplicate_comparisons"] == []
    assert second_results["duplicate_analysis"]["pairs_sent_to_llm"] == 0
    assert resolver.client.compare_calls == 1
    assert "_runtime_cache" not in vars(resolver)
    assert "_provider_state" not in vars(resolver)


def test_resolver_instances_use_distinct_runtime_cache_objects(monkeypatch):
    observed_cache_ids: list[int] = []
    original_get_or_set = llm_duplicate_resolver._runtime_cache_get_or_set

    def _tracking_get_or_set(namespace, finding, factory, *, runtime_cache=None):
        if runtime_cache is not None:
            observed_cache_ids.append(id(runtime_cache))
        return original_get_or_set(
            namespace,
            finding,
            factory,
            runtime_cache=runtime_cache,
        )

    monkeypatch.setattr(
        llm_duplicate_resolver,
        "_runtime_cache_get_or_set",
        _tracking_get_or_set,
    )

    resolver_a = LLMDuplicateResolver(_llm_config(), client=HealthcheckedFakeLLMClient())
    resolver_b = LLMDuplicateResolver(_llm_config(), client=HealthcheckedFakeLLMClient())

    resolver_a.apply({"all_findings": _gray_zone_sqli_pair(), "summary": {}})
    first_run_cache_ids = set(observed_cache_ids)
    observed_cache_ids.clear()

    resolver_b.apply({"all_findings": _gray_zone_sqli_pair(), "summary": {}})
    second_run_cache_ids = set(observed_cache_ids)

    assert len(first_run_cache_ids) == 1
    assert len(second_run_cache_ids) == 1
    assert first_run_cache_ids != second_run_cache_ids
    assert "_runtime_cache" not in vars(resolver_a)
    assert "_runtime_cache" not in vars(resolver_b)
    assert "_provider_state" not in vars(resolver_a)
    assert "_provider_state" not in vars(resolver_b)


def test_provider_disabled_state_does_not_leak_across_runs_on_one_resolver():
    class FailOnceThenRecoverClient:
        def __init__(self):
            self.healthcheck_calls = 0
            self.compare_calls = 0
            self._failed_once = False

        def healthcheck(self):
            self.healthcheck_calls += 1
            return {
                "status": "passed",
                "llm_decision": "yes",
                "request_hash": f"healthcheck-{self.healthcheck_calls}",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            }

        def compare(self, finding_a, finding_b, *, runtime_cache=None):
            self.compare_calls += 1
            if not self._failed_once:
                self._failed_once = True
                raise LLMProviderError(
                    message="HTTP 403 permission_denied: billing disabled",
                    category="permission_denied",
                    http_status_code=403,
                    request_kind="comparison",
                )
            decision = "yes"
            response_payload = {
                "choices": [{"message": {"content": decision}}],
                "_provider_request": {
                    "request_kind": "comparison",
                    "attempt_count": 1,
                    "retry_backoff_seconds": [],
                },
            }
            return decision, response_payload, json.dumps(response_payload), "recovered-hash"

    client = FailOnceThenRecoverClient()
    resolver = LLMDuplicateResolver(_llm_config(), client=client)

    first_results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})
    second_results = resolver.apply({"all_findings": _gray_zone_sqli_pair(), "summary": {}})

    assert [record["comparison_status"] for record in first_results["llm_duplicate_comparisons"]] == [
        "failed",
        "skipped_provider_unavailable",
        "skipped_provider_unavailable",
    ]
    assert first_results["duplicate_analysis"]["provider_disabled_mid_run"] is True
    assert second_results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm"
    assert second_results["duplicate_analysis"]["provider_disabled_mid_run"] is False
    assert second_results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 0
    assert client.healthcheck_calls == 2
    assert client.compare_calls == 2
    assert "_runtime_cache" not in vars(resolver)
    assert "_provider_state" not in vars(resolver)


def test_cross_scanner_filtering_skips_llm_for_different_hosts(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding("zap", title="SQL Injection", asset_id="https://example.com/login?q=1", description="same title", path="/login", parameter="q", raw_id="zap-1"),
        _finding(
            "nuclei",
            title="SQL Injection",
            asset_id="https://api.example.com/admin?q=1",
            description="same title",
            path="/admin",
            parameter="q",
            raw_id="nuclei-1",
            meta_extra={"host": "api.example.com"},
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert client.calls == []
    assert len(results["all_findings"]) == 2
    assert results["llm_duplicate_comparisons"] == []
    assert results["duplicate_analysis"]["pairs_blocked_by_same_target"] == 0


def test_llm_request_format_is_compact_and_structured():
    request = build_llm_request_body(
        _finding("zap", title="Missing X-Frame-Options Header", asset_id="https://example.com/login?q=1", description="desc", path="/login", parameter="q", raw_id="zap-1"),
        _finding("nuclei", title="Clickjacking protection header missing", asset_id="https://example.com/login?q=2", description="desc2", path="/login", parameter="q", raw_id="nuclei-1"),
        model_name="test-model",
    )

    assert request["model"] == "test-model"
    assert request["max_completion_tokens"] == 3
    assert "max_tokens" not in request
    assert "exactly one word: yes or no" in request["messages"][0]["content"].lower()

    payload = json.loads(request["messages"][1]["content"])
    assert payload["finding_a"]["scanner_name"] == "zap"
    assert payload["finding_b"]["target"]["path"] == "/login"
    assert payload["finding_b"]["target"]["parameter"] == "q"
    assert "raw_source_payload" not in request["messages"][1]["content"]


def test_parse_llm_yes_no_response_accepts_single_yes_no_token_only():
    assert parse_llm_yes_no_response({}, "yes") == "yes"
    assert parse_llm_yes_no_response({"choices": [{"message": {"content": "no"}}]}, '{"choices":[{"message":{"content":"no"}}]}') == "no"
    assert parse_llm_yes_no_response({"choices": [{"message": {"content": "Yes."}}]}, '{"choices":[{"message":{"content":"Yes."}}]}') == "yes"
    assert parse_llm_yes_no_response({"choices": [{"message": {"content": [{"type": "text", "text": "`no`"}]}}]}, '{"choices":[{"message":{"content":[{"type":"text","text":"`no`"}]}}]}') == "no"

    with pytest.raises(ValueError):
        parse_llm_yes_no_response({"choices": [{"message": {"content": "yes because"}}]}, '{"choices":[{"message":{"content":"yes because"}}]}')

    with pytest.raises(ValueError):
        parse_llm_yes_no_response({"choices": [{"message": {"content": "answer: yes"}}]}, '{"choices":[{"message":{"content":"answer: yes"}}]}')


def test_cache_reuses_saved_decision_with_reversed_pair_order(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient(decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"})
    config = LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model")

    findings = _gray_zone_sqli_pair()
    first = LLMDuplicateResolver(config, database=database, client=client).apply({"all_findings": copy.deepcopy(findings), "summary": {}})
    second = LLMDuplicateResolver(config, database=database, client=client).apply({"all_findings": list(reversed(copy.deepcopy(findings))), "summary": {}})

    assert len(client.calls) == 1
    assert len(first["all_findings"]) == 1
    assert len(second["all_findings"]) == 1
    comparison = second["llm_duplicate_comparisons"][0]
    assert comparison["comparison_status"] == "cached"
    assert comparison["sent_to_llm"] is False
    assert comparison["used_cache"] is True
    assert {
        comparison["llm_request_preview"]["finding_a_title"],
        comparison["llm_request_preview"]["finding_b_title"],
    } == {"SQL Injection", "SQL Injection in search parameter"}
    assert comparison["target_match_details"]["reason"] == "same_host_compatible"
    assert comparison["explainability"]["same_target"] is True
    assert second["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    assert second["duplicate_analysis"]["total_cached_pairs"] == 1
    assert second["duplicate_analysis"]["pairs_reused_from_cache"] == 1


def test_cached_raw_response_respects_current_debug_mode(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"}
    )

    first = LLMDuplicateResolver(
        _llm_config(debug=True),
        database=database,
        client=client,
    ).apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    second = LLMDuplicateResolver(
        _llm_config(debug=False),
        database=database,
        client=client,
    ).apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    first_comparison = first["llm_duplicate_comparisons"][0]
    second_comparison = second["llm_duplicate_comparisons"][0]

    assert first_comparison["comparison_status"] == "compared_with_llm"
    assert first_comparison["raw_response"]
    assert second_comparison["comparison_status"] == "cached"
    assert second_comparison["used_cache"] is True
    assert second_comparison["sent_to_llm"] is False
    assert second_comparison["llm_request_payload"] is None
    assert second_comparison["llm_request_body"] is None
    assert second_comparison["raw_response"] is None
    assert second_comparison["llm_request_preview"]
    assert second_comparison["provider_request_kind"] == "comparison"
    assert "choices" not in second_comparison["response_payload"]


def test_llm_failure_does_not_crash_pipeline_and_marks_failed(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=FakeLLMClient(error=TimeoutError("request timed out")),
    )
    findings = _gray_zone_header_pair()

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 2
    assert results["duplicate_analysis"]["failed_or_pending"] == 1
    assert results["duplicate_analysis"]["total_failed_pairs"] == 1
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    comparison = results["llm_duplicate_comparisons"][0]
    assert comparison["comparison_status"] == "failed"
    assert comparison["provider_failure_category"] == "timeout"
    assert comparison["sent_to_llm"] is True
    assert comparison["used_cache"] is False
    assert comparison["target_match_details"]["reason"] == "same_target"
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 1
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"timeout": 1}


def test_gray_zone_pair_can_merge_via_llm_and_preserve_provenance(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=FakeLLMClient(decision_by_pair={("Clickjacking policy check", "Framing protections review"): "yes"}),
    )
    findings = _gray_zone_header_pair()

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 1
    merged = results["all_findings"][0]
    assert merged["duplicate_count"] == 2
    assert set(merged["found_by"]) == {"zap", "nuclei"}
    assert len(merged["source_findings"]) == 2
    assert merged["meta"]["merged"] is True
    assert merged["meta"]["scanners"] == ["zap", "nuclei"]
    comparison = results["llm_duplicate_comparisons"][0]
    assert comparison["comparison_status"] == "compared_with_llm"
    assert comparison["cheap_filter_decision"] == "passed_endpoint_family_overlap"
    assert comparison["final_merge_result"] == "merged"
    assert comparison["merged_finding_id"] == merged["finding_id"]
    stored = database.list_llm_comparisons()[0]
    assert stored["same_target"] is True
    assert stored["cheap_filter_decision"] == "passed_endpoint_family_overlap"
    assert stored["llm_decision"] == "yes"
    assert stored["final_merge_result"] == "merged"
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    assert results["duplicate_analysis"]["total_compared_pairs"] == 1
    assert results["duplicate_analysis"]["total_merged_groups"] == 1
    assert results["duplicate_analysis"]["final_merged_finding_count"] == 1


def test_llm_merged_cluster_keeps_base_scanner_text_without_joining_source_prose(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(
        _llm_config(),
        database=database,
        client=FakeLLMClient(decision_by_pair={("Clickjacking policy check", "Framing protections review"): "yes"}),
    )
    findings = [
        _finding(
            "zap",
            title="Clickjacking policy check",
            asset_id="https://example.com/login",
            description="ZAP reported a possible anti-framing weakness on the login page.",
            severity="medium",
            raw_id="zap-1",
            category="Browser Security",
        ),
        _finding(
            "nuclei",
            title="Framing protections review",
            asset_id="https://example.com/login",
            description="Nuclei matched the same anti-framing weakness.",
            severity="high",
            raw_id="nuclei-1",
            category="Browser Security",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    merged = results["all_findings"][0]
    assert merged["description"] == "Nuclei matched the same anti-framing weakness."
    assert merged["remediation"] == "Fix it."
    assert "---" not in merged["description"]
    assert "ZAP reported a possible anti-framing weakness" not in merged["description"]
    assert [source["description"] for source in merged["source_findings"]] == [
        "ZAP reported a possible anti-framing weakness on the login page.",
        "Nuclei matched the same anti-framing weakness.",
    ]


def test_same_target_obviously_unrelated_pair_is_skipped_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding("zap", title="Missing X-Frame-Options Header", asset_id="https://example.com/login", description="header issue", raw_id="zap-1"),
        _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="sqli issue", raw_id="nuclei-1"),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert client.calls == []
    assert len(results["all_findings"]) == 2
    comparison = results["llm_duplicate_comparisons"][0]
    assert comparison["same_target"] is True
    assert comparison["comparison_status"] == "skipped_low_similarity"
    assert comparison["cheap_filter_decision"] == "skipped_low_similarity"
    assert comparison["llm_decision"] is None
    assert comparison["sent_to_llm"] is False
    assert comparison["used_cache"] is False
    assert comparison["target_match_details"]["reason"] == "same_target"
    assert comparison["explainability"]["cheap_filter_decision"] == "skipped_low_similarity"
    assert comparison["explainability"]["cheap_filter_details"]["details"]["shared_title_tokens"] == []
    assert comparison["final_merge_result"] == "not_merged"
    assert results["duplicate_analysis"]["total_skipped_pairs"] == 1
    assert results["duplicate_analysis"]["low_similarity_pairs_skipped"] == 1
    assert results["duplicate_analysis"]["pairs_blocked_by_similarity_gate"] == 1


def test_same_host_minor_path_query_and_parameter_differences_still_reach_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in account parameter"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _finding(
            "zap",
            title="SQL Injection in search parameter",
            asset_id="https://example.com/login?q=1",
            description="Input handling on /login looked injectable.",
            path="/login",
            parameter="q",
            raw_id="zap-1",
            category="SQL Injection",
        ),
        _finding(
            "nuclei",
            title="SQL Injection in account parameter",
            asset_id="https://example.com/auth/login?account=1",
            description="Generic SQL injection match on a nearby login endpoint.",
            path="/auth/login",
            parameter="account",
            raw_id="nuclei-1",
            category="SQL Injection",
            meta_extra={"query_keys": ["account"]},
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 1
    assert client.healthcheck_calls == 1
    assert client.compare_calls == 1
    comparison = results["llm_duplicate_comparisons"][0]
    assert comparison["same_target"] is True
    assert comparison["comparison_status"] == "compared_with_llm"
    assert comparison["target_match_details"]["reason"] == "same_host_compatible"
    assert sorted(comparison["target_match_details"]["soft_signals"]) == [
        "parameter_mismatch",
        "path_mismatch",
        "query_mismatch",
    ]
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    assert results["duplicate_analysis"]["pairs_sent_to_llm"] == 1
    assert results["duplicate_analysis"]["final_merged_finding_count"] == 1


def test_web_target_represented_as_service_and_url_without_shared_cve_still_reaches_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("Generic CMS SQLi", "Potential CMS Exposure"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = _gray_zone_service_vs_url_pair()

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 1
    assert client.healthcheck_calls == 1
    assert client.compare_calls == 1
    comparison = results["llm_duplicate_comparisons"][0]
    assert comparison["same_target"] is True
    assert comparison["comparison_status"] == "compared_with_llm"
    assert comparison["cheap_filter_decision"] == "passed_contextual_overlap"
    assert comparison["target_match_details"]["reason"] == "same_host_compatible"
    assert "path_mismatch" in comparison["target_match_details"]["soft_signals"]
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0


def test_same_scanner_similar_findings_stay_separate_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _weak_endpoint_sqli(
            "wapiti",
            parameter="id",
            raw_id="wapiti-sqli-id",
            description="SQL Injection via injection in the parameter id",
        ),
        _weak_endpoint_sqli(
            "wapiti",
            parameter="fn",
            raw_id="wapiti-sqli-fn",
            description="SQL Injection via injection in the parameter fn",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert client.healthcheck_calls == 0
    assert client.compare_calls == 0
    assert len(results["llm_duplicate_comparisons"]) == 0
    assert len(results["all_findings"]) == 2
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0


def test_same_scanner_exact_duplicates_still_merge_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _finding(
            "zap",
            title="SQL Injection",
            asset_id="https://example.com/login?q=1",
            description="Repeated scanner record.",
            parameter="q",
            raw_id="zap-1",
        ),
        _finding(
            "zap",
            title="SQL Injection",
            asset_id="https://example.com/login?q=1",
            description="Repeated scanner record.",
            parameter="q",
            raw_id="zap-1",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert client.healthcheck_calls == 0
    assert client.compare_calls == 0
    assert len(results["all_findings"]) == 1
    assert results["llm_duplicate_comparisons"] == []
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 1
    merged = results["all_findings"][0]
    assert merged["duplicate_resolution"]["reason"] == "same_scanner_exact_duplicate"
    assert merged["source_findings"][0]["scanner"] == "zap"
    assert results["summary"]["total_findings"] == len(results["all_findings"])


def test_same_scanner_findings_can_join_llm_cluster_via_cross_scanner_matches(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(decision_by_pair={("SQL Injection", "SQL Injection"): "yes"})
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _weak_endpoint_sqli(
            "wapiti",
            parameter="id",
            raw_id="wapiti-sqli-id",
            description="SQL Injection via injection in the parameter id",
        ),
        _weak_endpoint_sqli(
            "wapiti",
            parameter="fn",
            raw_id="wapiti-sqli-fn",
            description="SQL Injection via injection in the parameter fn",
        ),
        _weak_endpoint_sqli(
            "nuclei",
            parameter="account",
            asset_id="https://example.com/db/get?account=1",
            raw_id="nuclei-sqli-account",
            description="Generic SQL injection match on the same endpoint",
        ),
    ]
    findings[2]["meta"]["query_keys"] = ["account"]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    merged = results["all_findings"][0]
    assert client.healthcheck_calls == 1
    assert client.compare_calls == 2
    assert len(results["all_findings"]) == 1
    assert merged["duplicate_count"] == 3
    assert set(merged["found_by"]) == {"wapiti", "nuclei"}
    assert len(merged["source_findings"]) == 3
    assert {
        source["meta"]["raw_id"]
        for source in merged["source_findings"]
    } == {"wapiti-sqli-id", "wapiti-sqli-fn", "nuclei-sqli-account"}
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    assert merged["meta"]["original_findings_count"] == 3
    assert all(
        comparison["comparison_status"] == "compared_with_llm"
        for comparison in results["llm_duplicate_comparisons"]
    )
    assert all(
        comparison["final_merge_result"] == "merged"
        for comparison in results["llm_duplicate_comparisons"]
    )
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0
    assert results["duplicate_analysis"]["pairs_sent_to_llm"] == 2


def test_same_scanner_weak_same_family_different_endpoints_do_not_merge(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=HealthcheckedFakeLLMClient())
    findings = [
        _weak_endpoint_sqli("wapiti", parameter="id", path="/db/get", raw_id="wapiti-sqli-id"),
        _weak_endpoint_sqli("wapiti", parameter="id", path="/db/list", asset_id="https://example.com/db/list", raw_id="wapiti-sqli-list"),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 2
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0


def test_same_scanner_weak_same_endpoint_different_parameter_channels_do_not_merge(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=HealthcheckedFakeLLMClient())
    findings = [
        _weak_endpoint_sqli("wapiti", parameter="id", raw_id="wapiti-sqli-id"),
        _weak_endpoint_sqli("wapiti", parameter="Header User-Agent", raw_id="wapiti-sqli-header"),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 2
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0


def test_same_scanner_strong_findings_are_not_collapsed_by_weak_endpoint_rule(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=HealthcheckedFakeLLMClient())
    findings = [
        _weak_endpoint_sqli(
            "wapiti",
            parameter="id",
            severity="high",
            confidence="high",
            raw_id="wapiti-confirmed-id",
            description="Confirmed SQL injection in id",
        ),
        _weak_endpoint_sqli(
            "wapiti",
            parameter="fn",
            severity="high",
            confidence="high",
            raw_id="wapiti-confirmed-fn",
            description="Confirmed SQL injection in fn",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(results["all_findings"]) == 2
    assert results["duplicate_analysis"]["deterministic_same_scanner_merges"] == 0


def test_llm_mode_selected_can_finish_without_any_live_provider_calls(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["low_similarity_skip"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert results["duplicate_analysis"]["mode"] == "llm", debug_snapshot
    assert results["duplicate_analysis"]["llm_calls"] == 0, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 0, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 0, debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "not_run", debug_snapshot
    assert comparison["comparison_status"] == "skipped_low_similarity", debug_snapshot
    assert comparison["cheap_filter_decision"] == "skipped_low_similarity", debug_snapshot
    assert comparison["llm_decision"] is None, debug_snapshot
    assert client.healthcheck_calls == 0, debug_snapshot
    assert client.compare_calls == 0, debug_snapshot


def test_pair_that_passes_prefilters_runs_healthcheck_and_live_llm_compare(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert client.healthcheck_calls == 1, debug_snapshot
    assert client.compare_calls == 1, debug_snapshot
    assert results["duplicate_analysis"]["mode"] == "llm", debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["llm_calls"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 1, debug_snapshot
    assert comparison["comparison_status"] == "compared_with_llm", debug_snapshot
    assert comparison["cheap_filter_decision"] == "passed_similar_normalized_title", debug_snapshot
    assert comparison["llm_decision"] == "yes", debug_snapshot
    assert comparison["sent_to_llm"] is True, debug_snapshot
    assert comparison["used_cache"] is False, debug_snapshot
    assert comparison["target_match_details"]["reason"] == "same_host_compatible", debug_snapshot
    assert {
        comparison["llm_request_preview"]["finding_a_title"],
        comparison["llm_request_preview"]["finding_b_title"],
    } == {"SQL Injection", "SQL Injection in search parameter"}, debug_snapshot
    assert comparison["llm_request_payload"] is None, debug_snapshot
    assert comparison["explainability"]["cheap_filter_decision"] == "passed_similar_normalized_title", debug_snapshot
    assert comparison["provider_request_kind"] == "comparison", debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert results["duplicate_analysis"]["pairs_sent_to_llm"] == 1, debug_snapshot


def test_live_llm_trace_payload_is_only_persisted_when_debug_is_enabled(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(debug=True), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    comparison = results["llm_duplicate_comparisons"][0]

    assert comparison["comparison_status"] == "compared_with_llm"
    assert comparison["sent_to_llm"] is True
    assert comparison["used_cache"] is False
    assert {
        comparison["llm_request_preview"]["finding_a_title"],
        comparison["llm_request_preview"]["finding_b_title"],
    } == {"SQL Injection", "SQL Injection in search parameter"}
    assert comparison["llm_request_payload"]["question"].startswith("Do these two scanner findings")
    assert {
        comparison["llm_request_payload"]["finding_a"]["title"],
        comparison["llm_request_payload"]["finding_b"]["title"],
    } == {"SQL Injection", "SQL Injection in search parameter"}
    assert comparison["llm_request_body"]["model"] == "test-model"
    assert comparison["llm_request_body"]["messages"][0]["role"] == "system"
    assert {
        comparison["llm_request_payload"]["finding_a"]["target"]["parameter"],
        comparison["llm_request_payload"]["finding_b"]["target"]["parameter"],
    } == {"q", "account"}
    assert comparison["raw_response"]
    assert comparison["response_payload"]["choices"][0]["message"]["content"] == "yes"


def test_live_llm_success_is_sanitized_when_debug_is_disabled(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(debug=False), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    comparison = results["llm_duplicate_comparisons"][0]

    assert comparison["comparison_status"] == "compared_with_llm"
    assert comparison["raw_response"] is None
    assert comparison["llm_request_payload"] is None
    assert comparison["llm_request_body"] is None
    assert comparison["provider_request_kind"] == "comparison"
    assert "choices" not in comparison["response_payload"]
    assert "provider_response" not in comparison["response_payload"]


def test_successful_live_yes_decision_merges_findings_and_records_provider_success(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("Clickjacking policy check", "Framing protections review"): "yes"}
    )
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["same_vuln"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    merged = results["all_findings"][0]
    comparison = results["llm_duplicate_comparisons"][0]

    assert len(results["all_findings"]) == 1, debug_snapshot
    assert merged["duplicate_count"] == 2, debug_snapshot
    assert set(merged["found_by"]) == {"zap", "nuclei"}, debug_snapshot
    assert len(merged["source_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["final_merged_finding_count"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["total_merged_groups"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert comparison["comparison_status"] == "compared_with_llm", debug_snapshot
    assert comparison["llm_decision"] == "yes", debug_snapshot
    assert comparison["final_merge_result"] == "merged", debug_snapshot
    assert comparison["merged_finding_id"] == merged["finding_id"], debug_snapshot


def test_successful_live_no_decision_keeps_findings_separate(tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(
        decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "no"}
    )
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)

    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["llm_calls"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["no_decisions"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["final_merged_finding_count"] == 2, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert comparison["comparison_status"] == "compared_with_llm", debug_snapshot
    assert comparison["llm_decision"] == "no", debug_snapshot
    assert comparison["final_merge_result"] == "not_merged", debug_snapshot


def test_same_target_same_cve_different_wording_merges_deterministically_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding(
            "nmap",
            title="CVE-2024-1111",
            asset_id="example.com:443",
            description="Service-level CVE match.",
            raw_id="nmap-cve-1",
            cve_ids=["CVE-2024-1111"],
            meta_extra={"scheme": "", "protocol": "tcp", "service": "https", "path": "", "query_keys": []},
        ),
        _finding(
            "nuclei",
            title="Generic CMS SQLi",
            asset_id="https://example.com/login",
            description="Web endpoint wording for the same CVE.",
            cve_ids=["CVE-2024-1111"],
            raw_id="nuclei-cve-1",
            category="SQL Injection",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert client.healthcheck_calls == 0, debug_snapshot
    assert client.compare_calls == 0, debug_snapshot
    assert len(results["all_findings"]) == 1
    assert results["llm_duplicate_comparisons"] == []
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 1
    assert results["summary"]["total_findings"] == 1
    merged = results["all_findings"][0]
    assert merged["duplicate_count"] == 2
    assert set(merged["found_by"]) == {"nmap", "nuclei"}
    assert merged["meta"]["scanners"] == ["nmap", "nuclei"]
    assert merged["duplicate_resolution"]["reason"] == "cross_scanner_obvious_duplicate"
    assert "same_cve_same_effective_target" in merged["duplicate_resolution"]["rules"]
    assert merged["duplicate_resolution"]["shared_cves"] == ["CVE-2024-1111"]
    assert len(merged["source_findings"]) == 2


def test_same_header_family_same_endpoint_merges_deterministically_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _finding(
            "zap",
            title="CSP Header Missing",
            asset_id="https://example.com/login",
            description="ZAP reported a missing CSP header.",
            raw_id="zap-csp-1",
        ),
        _finding(
            "nuclei",
            title="Content Security Policy Configuration",
            asset_id="https://example.com/login",
            description="Nuclei reported the same missing header family.",
            raw_id="nuclei-csp-1",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert client.healthcheck_calls == 0, debug_snapshot
    assert client.compare_calls == 0, debug_snapshot
    assert len(results["all_findings"]) == 1, debug_snapshot
    assert results["llm_duplicate_comparisons"] == [], debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 1, debug_snapshot
    assert results["summary"]["total_findings"] == 1, debug_snapshot
    merged = results["all_findings"][0]
    assert merged["duplicate_count"] == 2, debug_snapshot
    assert set(merged["found_by"]) == {"zap", "nuclei"}, debug_snapshot
    assert merged["meta"]["scanners"] == ["zap", "nuclei"], debug_snapshot
    assert len(merged["source_findings"]) == 2, debug_snapshot
    assert "same_header_family_same_endpoint" in merged["duplicate_resolution"]["rules"], debug_snapshot


def test_same_strong_injection_family_same_path_parameter_and_method_merges_deterministically_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _weak_endpoint_sqli(
            "zap",
            parameter="id",
            path="/db/get",
            asset_id="https://example.com/db/get?id=1",
            method="POST",
            raw_id="zap-sqli-id",
            description="ZAP found injectable id input.",
        ),
        _weak_endpoint_sqli(
            "wapiti",
            parameter="id",
            path="/db/get",
            asset_id="https://example.com/db/get?id=2",
            method="POST",
            raw_id="wapiti-sqli-id",
            description="Wapiti found the same parameter-level SQL injection.",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert client.healthcheck_calls == 0, debug_snapshot
    assert client.compare_calls == 0, debug_snapshot
    assert len(results["all_findings"]) == 1, debug_snapshot
    assert results["llm_duplicate_comparisons"] == [], debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 1, debug_snapshot
    assert results["summary"]["total_findings"] == len(results["all_findings"]), debug_snapshot
    merged = results["all_findings"][0]
    assert merged["duplicate_count"] == 2, debug_snapshot
    assert set(merged["found_by"]) == {"zap", "wapiti"}, debug_snapshot
    assert len(merged["source_findings"]) == 2, debug_snapshot
    assert merged["meta"]["scanners"] == ["zap", "wapiti"], debug_snapshot
    assert "same_strong_family_same_endpoint_context" in merged["duplicate_resolution"]["rules"], debug_snapshot


def test_same_target_similar_normalized_titles_reach_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient(decision_by_pair={("SQL Injection", "SQL Injection in search parameter"): "yes"})
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding("zap", title="SQL Injection in search parameter", asset_id="https://example.com/login", description="search field injection", parameter="q", raw_id="zap-1"),
        _finding(
            "nuclei",
            title="SQL Injection",
            asset_id="https://example.com/login?account=1",
            description="generic SQL injection",
            parameter="account",
            raw_id="nuclei-1",
            meta_extra={"query_keys": ["account"]},
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(client.calls) == 1
    assert set(client.calls[0]) == {"SQL Injection", "SQL Injection in search parameter"}
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm"
    assert results["llm_duplicate_comparisons"][0]["cheap_filter_decision"] == "passed_similar_normalized_title"
    assert results["llm_duplicate_comparisons"][0]["llm_decision"] == "yes"
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0


def test_similar_header_wording_but_different_issue_type_is_skipped_before_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding("zap", title="Content-Type Header Missing", asset_id="https://example.com/login", description="missing content-type header", raw_id="zap-1"),
        _finding("nuclei", title="Content Security Policy Configuration", asset_id="https://example.com/login", description="missing CSP header", raw_id="nuclei-1"),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    comparison = results["llm_duplicate_comparisons"][0]
    assert client.calls == []
    assert len(results["all_findings"]) == 2
    assert comparison["comparison_status"] == "skipped_low_similarity"
    assert comparison["cheap_filter_decision"] == "skipped_low_similarity"
    assert comparison["llm_decision"] is None
    assert comparison["final_merge_result"] == "not_merged"
    assert comparison["explainability"]["normalized_title_a"] == "content type header missing"
    assert comparison["explainability"]["normalized_title_b"] == "missing content security policy header"


def test_csp_related_x_frame_guidance_is_not_treated_as_duplicate_candidate(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding(
            "nikto",
            title="X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive.",
            asset_id="https://example.com/",
            description="legacy X-Frame-Options guidance",
            raw_id="nikto-1",
        ),
        _finding(
            "wapiti",
            title="Content Security Policy Configuration",
            asset_id="https://example.com/",
            description="missing CSP header",
            raw_id="wapiti-1",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    comparison = results["llm_duplicate_comparisons"][0]
    assert client.calls == []
    assert len(results["all_findings"]) == 2
    assert comparison["comparison_status"] == "skipped_low_similarity"
    assert comparison["cheap_filter_decision"] == "skipped_low_similarity"
    assert comparison["llm_decision"] is None
    assert comparison["used_cache"] is False
    assert comparison["explainability"]["normalized_title_a"] != comparison["explainability"]["normalized_title_b"]
    assert "deprecated" in comparison["explainability"]["normalized_title_a"]
    assert comparison["explainability"]["normalized_title_b"] == "missing content security policy header"
    assert comparison["final_merge_result"] == "not_merged"


def test_frame_ancestors_missing_stays_distinct_from_missing_csp_header(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=client,
    )
    findings = [
        _finding(
            "nikto",
            title="Content-Security-Policy frame-ancestors directive missing",
            asset_id="https://example.com/",
            description="frame-ancestors directive missing",
            raw_id="nikto-1",
        ),
        _finding(
            "wapiti",
            title="Content Security Policy Configuration",
            asset_id="https://example.com/",
            description="missing CSP header",
            raw_id="wapiti-1",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    comparison = results["llm_duplicate_comparisons"][0]
    assert client.calls == []
    assert len(results["all_findings"]) == 2
    assert comparison["comparison_status"] == "skipped_low_similarity"
    assert comparison["cheap_filter_decision"] == "skipped_low_similarity"
    assert comparison["explainability"]["normalized_title_a"] == "missing frame ancestors directive"
    assert comparison["explainability"]["normalized_title_b"] == "missing content security policy header"
    assert comparison["explainability"]["meaningful_shared_title_tokens"] == []
    assert comparison["final_merge_result"] == "not_merged"


def test_different_header_families_do_not_deterministically_merge_on_same_endpoint(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient()
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _finding(
            "zap",
            title="CSP Header Missing",
            asset_id="https://example.com/login",
            description="Missing CSP header.",
            raw_id="zap-csp-guardrail",
        ),
        _finding(
            "nuclei",
            title="Content-Type Header Missing",
            asset_id="https://example.com/login",
            description="Missing Content-Type header.",
            raw_id="nuclei-content-type-guardrail",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert client.compare_calls == 0, debug_snapshot
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "skipped_low_similarity", debug_snapshot


def test_same_strong_family_same_path_but_different_parameters_stays_for_llm(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(decision_by_pair={("SQL Injection", "SQL Injection"): "no"})
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _weak_endpoint_sqli(
            "zap",
            parameter="id",
            path="/db/get",
            asset_id="https://example.com/db/get?id=1",
            raw_id="zap-param-id",
        ),
        _weak_endpoint_sqli(
            "nuclei",
            parameter="account",
            path="/db/get",
            asset_id="https://example.com/db/get?account=1",
            raw_id="nuclei-param-account",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert client.healthcheck_calls == 1, debug_snapshot
    assert client.compare_calls == 1, debug_snapshot
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm", debug_snapshot


def test_same_strong_family_different_paths_stays_for_llm_without_exact_cve(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(decision_by_pair={("SQL Injection", "SQL Injection"): "no"})
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _weak_endpoint_sqli(
            "zap",
            parameter="id",
            path="/db/get",
            asset_id="https://example.com/db/get?id=1",
            raw_id="zap-path-db-get",
        ),
        _weak_endpoint_sqli(
            "nuclei",
            parameter="id",
            path="/db/list",
            asset_id="https://example.com/db/list?id=1",
            raw_id="nuclei-path-db-list",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert client.healthcheck_calls == 1, debug_snapshot
    assert client.compare_calls == 1, debug_snapshot
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm", debug_snapshot


def test_internal_server_error_on_same_host_but_different_endpoint_context_does_not_deterministically_merge(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = HealthcheckedFakeLLMClient(decision_by_pair={("Internal Server Error", "Internal Server Error"): "no"})
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)
    findings = [
        _finding(
            "zap",
            title="Internal Server Error",
            asset_id="https://example.com/db/get?id=1",
            description="500 error on /db/get.",
            path="/db/get",
            parameter="id",
            raw_id="zap-ise-get",
        ),
        _finding(
            "nuclei",
            title="Internal Server Error",
            asset_id="https://example.com/db/list?id=1",
            description="500 error on /db/list.",
            path="/db/list",
            parameter="id",
            raw_id="nuclei-ise-list",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)

    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert client.healthcheck_calls == 1, debug_snapshot
    assert client.compare_calls == 1, debug_snapshot
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "compared_with_llm", debug_snapshot


def test_legacy_cached_decision_does_not_hide_changed_header_comparison_semantics(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    client = FakeLLMClient()
    config = LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key="test-key",
        model_name="test-model",
    )
    findings = [
        _finding(
            "nikto",
            title="X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive.",
            asset_id="https://example.com/",
            description="legacy X-Frame-Options guidance",
            raw_id="nikto-1",
        ),
        _finding(
            "wapiti",
            title="Content Security Policy Configuration",
            asset_id="https://example.com/",
            description="missing CSP header",
            raw_id="wapiti-1",
        ),
    ]
    llm_duplicate_resolver.assign_finding_ids(findings)
    legacy_pair_key, legacy_cache_key = _legacy_cache_key(findings[0], findings[1], model_name="test-model")
    database.save_llm_comparison(
        {
            "cache_key": legacy_cache_key,
            "pair_key": legacy_pair_key,
            "same_target": True,
            "llm_decision": "yes",
            "comparison_status": "cached",
            "cheap_filter_decision": "passed_normalized_title_match",
            "model_name": "test-model",
            "request_hash": "legacy-request-hash",
            "provider_request_kind": "comparison",
            "provider_attempt_count": 1,
            "provider_retry_backoff_seconds": [],
            "response_payload": {
                "_provider_request": {
                    "request_kind": "comparison",
                    "attempt_count": 1,
                    "retry_backoff_seconds": [],
                }
            },
        }
    )

    results = LLMDuplicateResolver(config, database=database, client=client).apply(
        {"all_findings": copy.deepcopy(findings), "summary": {}}
    )

    comparison = results["llm_duplicate_comparisons"][0]
    rows = database.list_llm_comparisons()

    assert client.calls == []
    assert comparison["comparison_status"] == "skipped_low_similarity"
    assert comparison["used_cache"] is False
    assert comparison["cache_key"] != legacy_cache_key
    assert any(row["cache_key"] == legacy_cache_key and row["llm_decision"] == "yes" for row in rows)
    assert any(
        row["cache_key"] == comparison["cache_key"]
        and row["comparison_status"] == "skipped_low_similarity"
        for row in rows
    )


def test_non_2xx_provider_response_is_captured_safely_in_yaml_trace(monkeypatch, tmp_path, caplog):
    database_path = tmp_path / "knowledge.yaml"
    database = UnifiedVulnerabilityDatabase(database_path)
    error_body = {
        "error": {
            "message": "INVALID_ARGUMENT: request body is malformed",
            "status": "INVALID_ARGUMENT",
        }
    }
    responses = [
        ScriptedHTTPResponse(
            200,
            json_data={"choices": [{"message": {"content": "yes"}}]},
        ),
        ScriptedHTTPResponse(
            400,
            json_data=error_body,
            text=json.dumps(error_body, sort_keys=True),
        ),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    findings = [
        _finding("zap", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="zap-1"),
        _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="nuclei-1"),
    ]

    with caplog.at_level("WARNING"):
        results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(http_calls) == 2
    assert len(results["all_findings"]) == 2
    comparison = results["llm_duplicate_comparisons"][0]
    provider_error = comparison["response_payload"]["provider_error"]

    assert comparison["comparison_status"] == "failed"
    assert comparison["provider_failure_category"] == "invalid_request"
    assert comparison["http_status_code"] == 400
    assert comparison["provider_request_kind"] == "comparison"
    assert comparison["provider_attempt_count"] == 1
    assert comparison["provider_retry_backoff_seconds"] == []
    assert comparison["request_hash"]
    assert comparison["raw_response"] is None
    assert comparison["error_message"] == "HTTP 400 invalid_request: INVALID_ARGUMENT: request body is malformed"
    assert provider_error["http_status_code"] == 400
    assert provider_error["response_json"] == error_body
    assert provider_error["response_text"] == json.dumps(error_body, sort_keys=True)
    assert provider_error["request_hash"] == comparison["request_hash"]
    assert provider_error["request_url"] == "https://llm.example/v1/chat/completions"
    assert provider_error["request_preview"]["model"] == "test-model"
    assert provider_error["request_preview"]["max_completion_tokens"] == 3
    assert "Authorization" not in provider_error
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"invalid_request": 1}
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is False
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 0

    stored = database.list_llm_comparisons()[0]
    yaml_text = database_path.read_text(encoding="utf-8")
    assert stored["provider_failure_category"] == "invalid_request"
    assert stored["response_payload"]["provider_error"]["response_json"] == error_body
    assert "super-secret-key-1234" not in yaml_text
    assert "Authorization" not in yaml_text
    assert "super-secret-key-1234" not in caplog.text
    assert "Authorization" not in caplog.text


def test_permission_denied_provider_failure_is_visible_and_does_not_false_merge(monkeypatch, tmp_path, duplicate_test_pairs):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    error_body = {
        "error": {
            "message": "Unauthorized",
            "status": "UNAUTHENTICATED",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(401, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert len(http_calls) == 2, debug_snapshot
    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"permission_denied": 1}, debug_snapshot
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is True, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert comparison["comparison_status"] == "failed", debug_snapshot
    assert comparison["provider_failure_category"] == "permission_denied", debug_snapshot
    assert comparison["http_status_code"] == 401, debug_snapshot
    assert comparison["final_merge_result"] == "not_merged", debug_snapshot


@pytest.mark.parametrize(
    ("comparison_response", "expected_error_snippet"),
    [
        (
            ScriptedHTTPResponse(200, text="not-json-response", json_error=ValueError("response body is not JSON")),
            "invalid duplicate yes/no response",
        ),
        (
            ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "maybe"}}]}),
            "invalid duplicate yes/no response",
        ),
    ],
    ids=["invalid_json", "malformed_yes_no"],
)
def test_unparseable_provider_success_responses_fail_safely_without_false_merge(
    monkeypatch,
    tmp_path,
    duplicate_test_pairs,
    comparison_response,
    expected_error_snippet,
):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        comparison_response,
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(debug=True), database=database)
    results = resolver.apply({"all_findings": copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"]), "summary": {}})

    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert len(http_calls) == 2, debug_snapshot
    assert len(results["all_findings"]) == 2, debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["llm_calls"] == 0, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 1, debug_snapshot
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"unknown_provider_error": 1}, debug_snapshot
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0, debug_snapshot
    assert comparison["comparison_status"] == "failed", debug_snapshot
    assert comparison["provider_failure_category"] == "unknown_provider_error", debug_snapshot
    assert expected_error_snippet in str(comparison["error_message"]), debug_snapshot
    assert comparison["final_merge_result"] == "not_merged", debug_snapshot
    assert comparison["raw_response"], debug_snapshot


def test_healthcheck_accepts_single_yes_no_token_with_punctuation(monkeypatch):
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "Yes."}}]}),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    result = OpenAICompatibleLLMClient(_llm_config()).healthcheck()

    assert len(http_calls) == 1
    assert result["status"] == "passed"
    assert result["llm_decision"] == "yes"
    assert result["attempt_count"] == 1


def test_invalid_request_failure_does_not_fallback_merge_cross_scanner_findings(monkeypatch, tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    error_body = {
        "error": {
            "message": "INVALID_ARGUMENT: pair payload rejected",
            "status": "INVALID_ARGUMENT",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(400, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    findings = [
        _finding(
            "zap",
            title="Internal Server Error",
            asset_id="https://example.com/db/get?id=1",
            description="500 while injecting payload into id parameter",
            parameter="id",
            raw_id="zap-1",
        ),
        _finding(
            "nuclei",
            title="Internal Server Error",
            asset_id="https://example.com/db/get?id=2",
            description="500 while injecting payload into id parameter",
            parameter="id",
            raw_id="nuclei-1",
        ),
    ]

    results = resolver.apply({"all_findings": findings, "summary": {}})

    assert len(http_calls) == 2
    assert len(results["all_findings"]) == 2
    assert results["llm_duplicate_comparisons"][0]["comparison_status"] == "failed"
    assert results["llm_duplicate_comparisons"][0]["provider_failure_category"] == "invalid_request"
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0


def test_malformed_400_is_classified_and_not_retried(monkeypatch):
    error_body = {
        "error": {
            "message": "INVALID_ARGUMENT: request body is malformed",
            "status": "INVALID_ARGUMENT",
        }
    }
    responses = [
        ScriptedHTTPResponse(
            400,
            json_data=error_body,
            text=json.dumps(error_body, sort_keys=True),
        ),
    ]
    http_calls = []
    sleep_delays = []
    _install_scripted_http(monkeypatch, responses, http_calls)
    monkeypatch.setattr(llm_duplicate_resolver.time, "sleep", lambda delay: sleep_delays.append(delay))

    client = OpenAICompatibleLLMClient(_llm_config())

    with pytest.raises(LLMProviderError) as exc_info:
        client.compare(
            _finding("zap", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="zap-1"),
            _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="same issue", raw_id="nuclei-1"),
        )

    error = exc_info.value
    assert error.category == "invalid_request"
    assert error.http_status_code == 400
    assert error.retryable is False
    assert error.attempt_count == 1
    assert error.retry_backoff_seconds == []
    assert len(http_calls) == 1
    assert sleep_delays == []


def test_invalid_request_failure_does_not_disable_later_pairs(monkeypatch, tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    error_body = {
        "error": {
            "message": "INVALID_ARGUMENT: pair payload rejected",
            "status": "INVALID_ARGUMENT",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(400, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "no"}}]}),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})

    assert len(http_calls) == 4
    statuses = [record["comparison_status"] for record in results["llm_duplicate_comparisons"]]
    assert statuses == ["failed", "compared_with_llm", "compared_with_llm"]
    assert results["llm_duplicate_comparisons"][0]["provider_failure_category"] == "invalid_request"
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 3
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 2
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 1
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 0
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is False
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"invalid_request": 1}


def test_429_is_retried_with_bounded_backoff_and_later_pairs_are_skipped(monkeypatch, tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    rate_limit_body = {
        "error": {
            "message": "RESOURCE_EXHAUSTED: Too many requests.",
            "status": "RESOURCE_EXHAUSTED",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(429, json_data=rate_limit_body, text=json.dumps(rate_limit_body, sort_keys=True)),
        ScriptedHTTPResponse(429, json_data=rate_limit_body, text=json.dumps(rate_limit_body, sort_keys=True)),
        ScriptedHTTPResponse(429, json_data=rate_limit_body, text=json.dumps(rate_limit_body, sort_keys=True)),
    ]
    http_calls = []
    sleep_delays = []
    _install_scripted_http(monkeypatch, responses, http_calls)
    monkeypatch.setattr(llm_duplicate_resolver.time, "sleep", lambda delay: sleep_delays.append(delay))

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})

    assert len(http_calls) == 4
    assert sleep_delays == [0.25, 0.5]
    assert len(results["all_findings"]) == 3

    first, second, third = results["llm_duplicate_comparisons"]
    assert first["comparison_status"] == "failed"
    assert first["provider_failure_category"] == "rate_limited"
    assert first["http_status_code"] == 429
    assert first["provider_attempt_count"] == 3
    assert first["provider_retry_backoff_seconds"] == [0.25, 0.5]
    assert first["response_payload"]["provider_error"]["attempt_count"] == 3
    assert second["comparison_status"] == "skipped_rate_limited"
    assert second["provider_failure_category"] == "rate_limited"
    assert third["comparison_status"] == "skipped_rate_limited"
    assert third["provider_failure_category"] == "rate_limited"

    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 1
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] == 0
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 1
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 2
    assert results["duplicate_analysis"]["rate_limit_encountered"] is True
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is True
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"rate_limited": 1}


def test_billing_or_region_issue_disables_later_pairs(monkeypatch, tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    error_body = {
        "error": {
            "message": "The model is not available in your region until billing is enabled.",
            "status": "FAILED_PRECONDITION",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(400, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
    ]
    http_calls = []
    _install_scripted_http(monkeypatch, responses, http_calls)

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})

    assert len(http_calls) == 2
    first, second, third = results["llm_duplicate_comparisons"]
    assert first["comparison_status"] == "failed"
    assert first["provider_failure_category"] == "billing_or_region_issue"
    assert second["comparison_status"] == "skipped_provider_unavailable"
    assert second["provider_failure_category"] == "billing_or_region_issue"
    assert third["comparison_status"] == "skipped_provider_unavailable"
    assert third["provider_failure_category"] == "billing_or_region_issue"
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 2
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is True
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"billing_or_region_issue": 1}


def test_repeated_provider_unavailable_failures_disable_later_pairs(monkeypatch, tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    error_body = {
        "error": {
            "message": "upstream service unavailable",
            "status": "UNAVAILABLE",
        }
    }
    responses = [
        ScriptedHTTPResponse(200, json_data={"choices": [{"message": {"content": "yes"}}]}),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
        ScriptedHTTPResponse(503, json_data=error_body, text=json.dumps(error_body, sort_keys=True)),
    ]
    http_calls = []
    sleep_delays = []
    _install_scripted_http(monkeypatch, responses, http_calls)
    monkeypatch.setattr(llm_duplicate_resolver.time, "sleep", lambda delay: sleep_delays.append(delay))

    resolver = LLMDuplicateResolver(_llm_config(), database=database)
    results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})

    assert len(http_calls) == 7
    assert sleep_delays == [0.25, 0.5, 0.25, 0.5]
    first, second, third = results["llm_duplicate_comparisons"]
    assert first["comparison_status"] == "failed"
    assert first["provider_failure_category"] == "provider_unavailable"
    assert first["provider_attempt_count"] == 3
    assert second["comparison_status"] == "failed"
    assert second["provider_failure_category"] == "provider_unavailable"
    assert second["provider_attempt_count"] == 3
    assert third["comparison_status"] == "skipped_provider_unavailable"
    assert third["provider_failure_category"] == "provider_unavailable"
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 2
    assert results["duplicate_analysis"]["live_llm_comparisons_failed"] == 2
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 1
    assert results["duplicate_analysis"]["provider_disabled_mid_run"] is True
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"provider_unavailable": 2}


def test_healthcheck_failure_prevents_wave_of_live_comparisons(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    provider_error = LLMProviderError(
        message="HTTP 503 provider_unavailable: upstream unavailable",
        category="provider_unavailable",
        http_status_code=503,
        response_text="upstream unavailable",
        response_json={"error": {"message": "upstream unavailable"}},
        request_kind="healthcheck",
    )
    client = HealthcheckFailingClient(provider_error)
    resolver = LLMDuplicateResolver(_llm_config(), database=database, client=client)

    results = resolver.apply({"all_findings": _same_target_triplet(), "summary": {}})

    assert len(results["all_findings"]) == 3
    assert client.healthcheck_calls == 1
    assert client.compare_calls == 0
    assert [record["comparison_status"] for record in results["llm_duplicate_comparisons"]] == [
        "skipped_after_healthcheck_failure",
        "skipped_after_healthcheck_failure",
        "skipped_after_healthcheck_failure",
    ]
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "failed"
    assert results["duplicate_analysis"]["provider_healthcheck_error"] == "HTTP 503 provider_unavailable: upstream unavailable"
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] == 0
    assert results["duplicate_analysis"]["comparisons_skipped_due_to_provider_state"] == 3
    assert results["duplicate_analysis"]["provider_failure_categories"] == {"provider_unavailable": 1}
    assert results["llm_duplicate_comparisons"][0]["response_payload"]["healthcheck"]["provider_error"]["http_status_code"] == 503
    assert results["llm_duplicate_comparisons"][0]["provider_failure_category"] == "provider_unavailable"


def test_summary_is_recomputed_from_final_merged_findings(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=FakeLLMClient(decision_by_pair={("Clickjacking policy check", "Framing protections review"): "yes"}),
    )
    findings = [
        _finding(
            "zap",
            title="Clickjacking policy check",
            asset_id="https://example.com/login",
            description="header issue",
            severity="high",
            raw_id="zap-1",
            category="Browser Security",
        ),
        _finding(
            "nuclei",
            title="Framing protections review",
            asset_id="https://example.com/login",
            description="same issue",
            severity="low",
            raw_id="nuclei-1",
            category="Browser Security",
        ),
    ]

    results = resolver.apply(
        {
            "all_findings": findings,
            "summary": {
                "total_findings": 99,
                "by_severity": {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 0},
                "by_scanner": {"zap": 1, "nuclei": 1},
            },
        }
    )

    assert len(results["all_findings"]) == 1
    assert results["duplicate_analysis"]["deterministic_fallback_merges"] == 0
    assert results["summary"]["total_findings"] == 1
    assert results["summary"]["by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 0,
        "info": 0,
    }
    assert results["summary"]["by_scanner"] == {"zap": 1, "nuclei": 1}


def test_summary_stays_correct_when_findings_do_not_merge(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(mode="llm", api_url="https://llm.example/v1/chat/completions", api_key="test-key", model_name="test-model"),
        database=database,
        client=FakeLLMClient(),
    )
    findings = [
        _finding("zap", title="Missing X-Frame-Options Header", asset_id="https://example.com/login", description="header issue", severity="low", raw_id="zap-1"),
        _finding("nuclei", title="SQL Injection", asset_id="https://example.com/login", description="sqli issue", severity="high", raw_id="nuclei-1"),
    ]

    results = resolver.apply(
        {
            "all_findings": findings,
            "summary": {
                "total_findings": 1,
                "by_severity": {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 0},
            },
        }
    )

    assert len(results["all_findings"]) == 2
    assert results["summary"]["total_findings"] == 2
    assert results["summary"]["by_severity"] == {
        "critical": 0,
        "high": 1,
        "medium": 0,
        "low": 1,
        "info": 0,
    }


@pytest.mark.live_llm
def test_live_provider_smoke_duplicate_comparison(tmp_path, duplicate_test_pairs, pytestconfig):
    if not _live_llm_smoke_enabled(pytestconfig):
        pytest.skip(
            "Set RUN_LIVE_LLM_TESTS=1 or pass --run-live-llm to enable live provider smoke tests."
        )

    provider_settings = llm_duplicate_resolver.resolve_llm_duplicate_provider_settings(
        cli_api_url=None,
        cli_api_key=None,
        cli_model_name=None,
        env=os.environ,
    )
    config = LLMDuplicateConfig(
        mode="llm",
        api_url=provider_settings["api_url"],
        api_key=provider_settings["api_key"],
        model_name=provider_settings["model_name"],
        timeout_seconds=float(os.getenv("VULN_MANAGER_LLM_TIMEOUT", "15")),
    )
    if not config.ready:
        pytest.skip(
            "Live LLM smoke test requires "
            "VULN_MANAGER_LLM_API_URL/VULN_MANAGER_LLM_API_KEY/VULN_MANAGER_LLM_MODEL."
        )

    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    resolver = LLMDuplicateResolver(config, database=database)
    findings = copy.deepcopy(duplicate_test_pairs["ambiguous_reaches_llm"])

    results = resolver.apply({"all_findings": findings, "summary": {}})
    debug_snapshot = _duplicate_debug_snapshot(results)
    comparison = results["llm_duplicate_comparisons"][0]

    assert results["duplicate_analysis"]["mode"] == "llm", debug_snapshot
    assert results["duplicate_analysis"]["provider_healthcheck_status"] == "passed", debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_attempted"] >= 1, debug_snapshot
    assert results["duplicate_analysis"]["live_llm_comparisons_succeeded"] >= 1, debug_snapshot
    assert results["duplicate_analysis"]["llm_calls"] >= 1, debug_snapshot
    assert results["duplicate_analysis"]["pairs_sent_to_llm"] >= 1, debug_snapshot
    assert comparison["comparison_status"] == "compared_with_llm", debug_snapshot
    assert comparison["sent_to_llm"] is True, debug_snapshot
    assert comparison["used_cache"] is False, debug_snapshot
    assert comparison["provider_request_kind"] == "comparison", debug_snapshot
    assert comparison["provider_attempt_count"] is not None, debug_snapshot
    assert comparison["request_hash"], debug_snapshot
    assert comparison["llm_decision"] in {"yes", "no"}, debug_snapshot


def test_main_active_flow_reaches_provider_boundary_and_records_live_llm_usage(
    monkeypatch,
    tmp_path,
    capsys,
    duplicate_test_pairs,
):
    calls = _install_recording_boundary_client(monkeypatch, decision="yes")
    findings = duplicate_test_pairs["ambiguous_reaches_llm"]
    orchestrator = _build_main_flow_orchestrator(tmp_path, findings)

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: orchestrator,
    )
    monkeypatch.setattr(
        main.sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--json",
            "--no-score",
            "--duplicate-mode", "llm",
            "--llm-api-url", "https://llm.example/v1/chat/completions",
            "--llm-api-key", "test-key",
            "--llm-model", "test-model",
            "--data-dir", str(tmp_path),
            "--knowledge-db", str(tmp_path / "knowledge.yaml"),
        ],
    )

    rc = main.main()
    capsys.readouterr()

    normalized = json.loads((tmp_path / "normalized.json").read_text(encoding="utf-8"))
    debug_snapshot = _duplicate_debug_snapshot(normalized)
    merged = normalized["all_findings"][0]

    assert rc == 0, debug_snapshot
    assert calls["healthcheck"] >= 1, debug_snapshot
    assert len(calls["compare"]) >= 1, debug_snapshot
    assert "duplicate_analysis" not in normalized, debug_snapshot
    assert "llm_duplicate_comparisons" not in normalized, debug_snapshot
    assert not (tmp_path / "llm_duplicate_trace.json").exists(), debug_snapshot
    assert len(normalized["all_findings"]) == 1, debug_snapshot
    assert "duplicate_count" not in merged, debug_snapshot
    assert set(merged["found_by"]) == {"zap", "nuclei"}, debug_snapshot
    assert len(merged["source_findings"]) == 2, debug_snapshot


def test_main_active_flow_can_select_llm_mode_without_reaching_provider_boundary(
    monkeypatch,
    tmp_path,
    capsys,
    duplicate_test_pairs,
):
    calls = _install_recording_boundary_client(monkeypatch, decision="yes")
    findings = duplicate_test_pairs["low_similarity_skip"]
    orchestrator = _build_main_flow_orchestrator(tmp_path, findings)

    monkeypatch.setattr(
        main,
        "create_default_orchestrator",
        lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: orchestrator,
    )
    monkeypatch.setattr(
        main.sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--json",
            "--no-score",
            "--duplicate-mode", "llm",
            "--llm-api-url", "https://llm.example/v1/chat/completions",
            "--llm-api-key", "test-key",
            "--llm-model", "test-model",
            "--data-dir", str(tmp_path),
            "--knowledge-db", str(tmp_path / "knowledge.yaml"),
        ],
    )

    rc = main.main()
    capsys.readouterr()

    normalized = json.loads((tmp_path / "normalized.json").read_text(encoding="utf-8"))
    debug_snapshot = _duplicate_debug_snapshot(normalized)

    assert rc == 0, debug_snapshot
    assert calls["healthcheck"] == 0, debug_snapshot
    assert calls["compare"] == [], debug_snapshot
    assert "duplicate_analysis" not in normalized, debug_snapshot
    assert "llm_duplicate_comparisons" not in normalized, debug_snapshot
    assert not (tmp_path / "llm_duplicate_trace.json").exists(), debug_snapshot


def test_legacy_deduplicator_is_preserved_but_not_used_in_main_active_flow(monkeypatch, tmp_path, capsys):
    class FakeOrchestrator:
        current_run_folder = None
        scanners = {}

        def run_all(self, target, options=None, normalize=True, save_raw=True):
            return {
                "schema_version": "2.0",
                "target": target,
                "timestamp": "2026-04-09T12:00:00Z",
                "scanners_run": ["zap", "nuclei"],
                "all_findings": [
                    _finding("zap", title="Missing X-Frame-Options Header", asset_id="https://example.com/login", description="header issue", raw_id="zap-1"),
                    _finding("nuclei", title="Clickjacking protection header missing", asset_id="https://example.com/login", description="same issue", raw_id="nuclei-1"),
                ],
                "errors": [],
                "summary": {"total_findings": 2, "by_severity": {"high": 0, "medium": 2}},
            }

        def save_results(self, results, output=None):
            path = tmp_path / "normalized.json"
            path.write_text(json.dumps(results), encoding="utf-8")
            return path

    class FakeResolver:
        called = False

        def __init__(self, config, database=None):
            self.config = config
            self.database = database

        def apply(self, results):
            FakeResolver.called = True
            return results

    class FakeDB:
        def __init__(self, path):
            self.path = str(path)

    import utils.deduplicator as legacy_deduplicator

    monkeypatch.setattr(main, "create_default_orchestrator", lambda reports_dir=None, http2_proxy_url=None, http2_bridge_url=None, http_probe_timeout=8: FakeOrchestrator())
    monkeypatch.setattr(main, "LLMDuplicateResolver", FakeResolver)
    monkeypatch.setattr(main, "UnifiedVulnerabilityDatabase", FakeDB)
    monkeypatch.setattr(main, "add_comparison_to_results", lambda results, data_dir: results)
    monkeypatch.setattr(legacy_deduplicator, "deduplicate_scan_results", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("legacy dedupe should not run")))
    monkeypatch.setattr(
        main.sys,
        "argv",
        [
            "main.py",
            "--target", "example.com",
            "--scanner", "all",
            "--json",
            "--duplicate-mode", "llm",
            "--llm-api-url", "https://llm.example/v1/chat/completions",
            "--llm-api-key", "test-key",
            "--llm-model", "test-model",
            "--data-dir", str(tmp_path),
        ],
    )

    rc = main.main()
    capsys.readouterr()

    assert rc == 0
    assert FakeResolver.called is True
