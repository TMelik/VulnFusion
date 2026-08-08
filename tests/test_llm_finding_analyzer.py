import copy
import json

import pytest

from utils.llm_finding_analyzer import (
    LLM_FINDING_ANALYSIS_CACHE_SEMANTICS_VERSION,
    LLMFindingAnalysisConfig,
    LLMFindingAnalyzer,
    build_llm_finding_analysis_request_body,
    parse_llm_finding_analysis_response,
)
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase


def _finding(
    title="SQL Injection",
    *,
    priority="P1",
    risk_score=80,
    asset="https://example.com/search?q=test",
    description="The q parameter changed the database response.",
):
    return {
        "vulnerability_name": title,
        "severity": "high",
        "asset_id": asset,
        "description": description,
        "remediation": "Use parameterized queries.",
        "priority": priority,
        "risk_score": risk_score,
        "meta": {
            "scanner": "zap",
            "method": "GET",
            "path": "/search",
            "parameter": "q",
            "evidence": "Database error marker was returned.",
        },
    }


def _decision(*, status="likely_valid", evidence_ids=None, confidence=0.9):
    return {
        "applicability": {
            "status": status,
            "confidence": confidence,
            "reason": "The endpoint, parameter, and scanner match evidence support the finding.",
            "evidence_ids": evidence_ids or ["finding-description", "finding-evidence"],
        },
        "ai_remediation": {
            "steps": ["Replace string-built queries with parameterized queries."],
            "verification": ["Repeat the scanner request and verify the error marker is absent."],
        },
    }


class QueueClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def complete(self, request_body):
        self.calls.append(copy.deepcopy(request_body))
        if not self.responses:
            raise AssertionError("unexpected provider call")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        payload = {
            "choices": [{"message": {"content": response}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }
        return {
            "response_payload": payload,
            "raw_text": json.dumps(payload),
            "request_hash": f"request-{len(self.calls)}",
        }


def _config(**overrides):
    values = {
        "api_url": "https://llm.example/v1/chat/completions",
        "api_key": "test-key",
        "model_name": "test-model",
    }
    values.update(overrides)
    return LLMFindingAnalysisConfig(**values)


def _response_text(**overrides):
    payload = _decision(**overrides)
    return json.dumps(payload, sort_keys=True)


def _request_titles(client):
    titles = []
    for request in client.calls:
        user = json.loads(request["messages"][1]["content"])
        title = next(item for item in user["evidence"] if item["id"] == "finding-title")
        titles.append(title["content"])
    return titles


def test_strict_parser_accepts_one_json_object_or_json_fence():
    content = _response_text(evidence_ids=["finding-description"])
    decision = parse_llm_finding_analysis_response(
        {}, content, evidence_ids=["finding-description"]
    )
    fenced = parse_llm_finding_analysis_response(
        {}, f"```json\n{content}\n```", evidence_ids=["finding-description"]
    )

    assert decision == fenced
    assert decision.applicability_status == "likely_valid"
    assert decision.confidence == 0.9


@pytest.mark.parametrize(
    "content",
    [
        "yes",
        "Here is the result: " + _response_text(evidence_ids=["finding-description"]),
        json.dumps({**_decision(evidence_ids=["finding-description"]), "extra": True}),
        json.dumps(_decision(evidence_ids=["finding-description"], confidence=1)),
        json.dumps(_decision(evidence_ids=["unknown-evidence"])),
    ],
)
def test_strict_parser_rejects_legacy_text_extra_fields_wrong_types_and_unknown_evidence(content):
    with pytest.raises(ValueError):
        parse_llm_finding_analysis_response(
            {}, content, evidence_ids=["finding-description", "finding-evidence"]
        )


def test_request_is_bounded_redacted_and_marks_evidence_as_untrusted():
    finding = _finding(
        description="Authorization: Bearer abcdefghijklmnopqrstuvwxyz",
    )
    request = build_llm_finding_analysis_request_body(
        finding,
        model_name="test-model",
        asset_knowledge={
            "description": "Public appointment service",
            "risk_context": {"environment": "production"},
        },
    )

    assert "abcdefghijklmnopqrstuvwxyz" not in json.dumps(request)
    assert "[REDACTED:AUTHORIZATION]" in json.dumps(request)
    assert "untrusted data" in request["messages"][0]["content"]
    assert request["max_completion_tokens"] == 600
    assert "max_tokens" not in request
    user = json.loads(request["messages"][1]["content"])
    assert {item["id"] for item in user["evidence"]} >= {
        "finding-title",
        "finding-anchors",
        "site-description",
        "site-risk-context",
    }


def test_stable_top_n_uses_priority_then_risk_and_marks_the_rest():
    findings = [
        _finding("P2 high score", priority="P2", risk_score=99),
        _finding("P0 lower score", priority="P0", risk_score=50),
        _finding("P0 higher score", priority="P0", risk_score=90),
    ]
    client = QueueClient([_response_text(), _response_text()])
    results = LLMFindingAnalyzer(_config(limit=2), client=client).apply(
        {"all_findings": list(reversed(copy.deepcopy(findings)))}
    )

    assert _request_titles(client) == ["P0 higher score", "P0 lower score"]
    by_title = {item["vulnerability_name"]: item for item in results["all_findings"]}
    assert by_title["P2 high score"]["ai_analysis_status"] == "skipped_limit"
    assert by_title["P0 lower score"]["ai_analysis_status"] == "completed"
    assert results["ai_analysis_summary"]["selected_count"] == 2
    assert results["ai_analysis_summary"]["skipped_limit_count"] == 1


def test_top_n_tie_break_is_stable_for_different_parameters_when_input_reverses():
    first = _finding(description="Generic database response change.")
    second = _finding(description="Generic database response change.")
    first["meta"]["parameter"] = "q"
    second["meta"]["parameter"] = "category"

    def selected_parameter(findings):
        results = LLMFindingAnalyzer(
            _config(limit=1), client=QueueClient([_response_text()])
        ).apply({"all_findings": copy.deepcopy(findings)})
        selected = [
            finding["meta"]["parameter"]
            for finding in results["all_findings"]
            if finding.get("ai_analysis_status") == "completed"
        ]
        assert len(selected) == 1
        return selected[0]

    assert selected_parameter([first, second]) == selected_parameter([second, first])


def test_provider_failure_and_malformed_response_are_fail_open():
    findings = [_finding("Failure"), _finding("Malformed")]
    client = QueueClient([TimeoutError("provider timeout"), "not json"])

    results = LLMFindingAnalyzer(_config(), client=client).apply({"all_findings": findings})

    assert [finding["ai_analysis_status"] for finding in results["all_findings"]] == [
        "unavailable",
        "unavailable",
    ]
    assert all("applicability" not in finding for finding in results["all_findings"])
    assert results["ai_analysis_summary"]["status"] == "unavailable"
    assert results["ai_analysis_summary"]["unavailable_count"] == 2
    # The malformed completion still consumed provider tokens and cost.
    assert results["ai_analysis_summary"]["total_tokens"] == 150


def test_cache_hit_context_revision_miss_and_old_semantics_are_handled(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    context_v1 = {"profile_revision": "revision-1", "description": "Booking service"}
    first_client = QueueClient([_response_text(status="needs_review")])
    first = LLMFindingAnalyzer(_config(), database=database, client=first_client).apply(
        {"all_findings": [_finding()]}, asset_knowledge=context_v1
    )
    assert first["all_findings"][0]["ai_analysis_status"] == "completed"

    cached_client = QueueClient([])
    cached = LLMFindingAnalyzer(_config(), database=database, client=cached_client).apply(
        {"all_findings": [_finding()]}, asset_knowledge=context_v1
    )
    assert cached["all_findings"][0]["ai_analysis_status"] == "cached"
    assert cached["ai_analysis_summary"]["cached_count"] == 1
    assert cached["ai_analysis_summary"]["needs_review_count"] == 1
    assert cached_client.calls == []

    changed_client = QueueClient([_response_text()])
    LLMFindingAnalyzer(_config(), database=database, client=changed_client).apply(
        {"all_findings": [_finding()]},
        asset_knowledge={**context_v1, "profile_revision": "revision-2"},
    )
    assert len(changed_client.calls) == 1

    row = next(
        item
        for item in database.list_llm_finding_analyses()
        if item["context_revision"] == "revision-1"
    )
    row["cache_semantics_version"] = LLM_FINDING_ANALYSIS_CACHE_SEMANTICS_VERSION - 1
    database.save_llm_finding_analysis(row)
    old_version_client = QueueClient([_response_text()])
    refreshed = LLMFindingAnalyzer(_config(), database=database, client=old_version_client).apply(
        {"all_findings": [_finding()]}, asset_knowledge=context_v1
    )
    assert refreshed["all_findings"][0]["ai_analysis_status"] == "completed"
    assert len(old_version_client.calls) == 1


def test_summary_tracks_tokens_cost_redactions_and_partial_status():
    client = QueueClient(
        [
            _response_text(),
            RuntimeError("down"),
        ]
    )
    results = LLMFindingAnalyzer(
        _config(input_cost_per_million=2.0, output_cost_per_million=4.0),
        client=client,
    ).apply(
        {
            "all_findings": [
                _finding(description="Authorization: Bearer abcdefghijklmnopqrstuvwxyz"),
                _finding("Second finding", asset="https://example.com/other"),
            ]
        }
    )

    summary = results["ai_analysis_summary"]
    assert summary["status"] == "partial"
    assert summary["analyzed_count"] == 1
    assert summary["unavailable_count"] == 1
    assert summary["redaction_count"] == 1
    assert summary["prompt_tokens"] == 100
    assert summary["completion_tokens"] == 50
    assert summary["total_tokens"] == 150
    assert summary["estimated_cost_usd"] == 0.0004


def test_cache_read_and_write_errors_do_not_block_completed_advice():
    class BrokenCache:
        def get_llm_finding_analysis(self, cache_key):
            raise ValueError("corrupt YAML")

        def save_llm_finding_analysis(self, record):
            raise OSError("read-only cache")

    client = QueueClient([_response_text()])
    results = LLMFindingAnalyzer(
        _config(),
        database=BrokenCache(),
        client=client,
    ).apply({"all_findings": [_finding()]})

    assert len(client.calls) == 1
    assert results["all_findings"][0]["ai_analysis_status"] == "completed"
    assert results["ai_analysis_summary"]["status"] == "completed"


def test_source_evidence_and_cache_payload_are_stable_when_sources_are_reversed():
    source_a = {
        "scanner": "zap",
        "vulnerability_name": "SQL Injection",
        "asset_id": "https://example.com/search",
        "description": "ZAP proof",
        "remediation": "Parameterized query",
        "meta": {"scanner": "zap", "plugin_id": "40018", "evidence": "SQL error"},
    }
    source_b = {
        "scanner": "zap",
        "vulnerability_name": "SQL Injection",
        "asset_id": "https://example.com/search",
        "description": "Second proof",
        "remediation": "Query builder",
        "meta": {"scanner": "zap", "plugin_id": "40019", "http_request": "GET /search?q=x"},
    }
    left = _finding()
    right = _finding()
    left["source_findings"] = [source_a, source_b]
    right["source_findings"] = [source_b, source_a]

    left_request = build_llm_finding_analysis_request_body(left, model_name="test-model")
    right_request = build_llm_finding_analysis_request_body(right, model_name="test-model")

    assert left_request == right_request
    evidence = json.loads(left_request["messages"][1]["content"])["evidence"]
    evidence_ids = {item["id"] for item in evidence}
    assert "source-1-anchors" in evidence_ids
    assert {"source-1-evidence", "source-1-request"} & evidence_ids


@pytest.mark.parametrize(
    ("config", "expected"),
    [
        (LLMFindingAnalysisConfig(enabled=False), "disabled_by_user"),
        (LLMFindingAnalysisConfig(), "disabled_not_configured"),
    ],
)
def test_disabled_and_unconfigured_provider_are_explicit(config, expected):
    finding = _finding()
    results = LLMFindingAnalyzer(config, client=QueueClient([])).apply(
        {"all_findings": [finding]}
    )

    assert results["ai_analysis_summary"]["status"] == expected
    assert "ai_analysis_status" not in finding
