import json

import httpx
import pytest

from utils.llm_duplicate_resolver import (
    LLMDuplicateConfig,
    OpenAICompatibleLLMClient,
    normalize_llm_provider_url,
    resolve_llm_duplicate_provider_settings,
)
from utils.llm_finding_analyzer import (
    LLMFindingAnalysisConfig,
    OpenAICompatibleFindingAnalysisClient,
)
from utils.site_context import analyze_site_context


BASE_URL = "https://openrouter.ai/api/v1"
CHAT_COMPLETIONS_URL = f"{BASE_URL}/chat/completions"
MODEL = "deepseek/deepseek-v4-pro"


@pytest.mark.parametrize(
    ("configured_url", "expected"),
    [
        (BASE_URL, CHAT_COMPLETIONS_URL),
        (f"{BASE_URL}/", CHAT_COMPLETIONS_URL),
        (CHAT_COMPLETIONS_URL, CHAT_COMPLETIONS_URL),
        (f"{CHAT_COMPLETIONS_URL}/", CHAT_COMPLETIONS_URL),
        ("  https://provider.example/v1  ", "https://provider.example/v1/chat/completions"),
        (None, None),
        ("  ", None),
    ],
)
def test_normalize_llm_provider_url(configured_url, expected):
    assert normalize_llm_provider_url(configured_url) == expected


def test_provider_settings_preserve_cli_precedence_before_normalization():
    settings = resolve_llm_duplicate_provider_settings(
        cli_api_url="https://cli.example/v1/",
        cli_api_key="cli-key",
        cli_model_name="cli-model",
        env={
            "VULN_MANAGER_LLM_API_URL": "https://env.example/v1",
            "VULN_MANAGER_LLM_API_KEY": "env-key",
            "VULN_MANAGER_LLM_MODEL": "env-model",
        },
    )

    assert settings == {
        "api_url": "https://cli.example/v1/chat/completions",
        "api_key": "cli-key",
        "model_name": "cli-model",
    }


def _settings():
    return resolve_llm_duplicate_provider_settings(
        cli_api_url=None,
        cli_api_key=None,
        cli_model_name=None,
        env={
            "VULN_MANAGER_LLM_API_URL": BASE_URL,
            "VULN_MANAGER_LLM_API_KEY": "test-key",
            "VULN_MANAGER_LLM_MODEL": MODEL,
        },
    )


def _duplicate_config():
    settings = _settings()
    return LLMDuplicateConfig(
        mode="llm",
        api_url=settings["api_url"],
        api_key=settings["api_key"],
        model_name=settings["model_name"],
    )


def test_healthcheck_uses_normalized_endpoint_and_selected_model():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "yes"}}]})

    result = OpenAICompatibleLLMClient(
        _duplicate_config(), transport=httpx.MockTransport(handler)
    ).healthcheck()

    assert result["status"] == "passed"
    assert str(requests[0].url) == CHAT_COMPLETIONS_URL
    assert json.loads(requests[0].content)["model"] == MODEL
    assert requests[0].headers["authorization"] == "Bearer test-key"
    assert "http-referer" not in requests[0].headers
    assert "x-title" not in requests[0].headers


def test_structured_dedup_uses_normalized_endpoint_and_selected_model():
    requests = []
    response = {
        "same_vulnerability": False,
        "confidence": 0.97,
        "reason": "The concrete targets differ.",
        "canonical_title": "SQL Injection",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(response)}}]},
        )

    client = OpenAICompatibleLLMClient(
        _duplicate_config(), transport=httpx.MockTransport(handler)
    )
    decision, _, _, _ = client.compare(
        {"vulnerability_name": "SQL Injection", "asset_id": "https://example.com/a"},
        {"vulnerability_name": "SQL Injection", "asset_id": "https://example.com/b"},
    )

    assert decision.same_vulnerability is False
    assert str(requests[0].url) == CHAT_COMPLETIONS_URL
    assert json.loads(requests[0].content)["model"] == MODEL


def test_finding_analysis_uses_normalized_endpoint_and_selected_model():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    settings = _settings()
    config = LLMFindingAnalysisConfig(
        api_url=settings["api_url"],
        api_key=settings["api_key"],
        model_name=settings["model_name"],
    )
    client = OpenAICompatibleFindingAnalysisClient(
        config, transport=httpx.MockTransport(handler)
    )
    client.complete({"model": config.model_name, "messages": []})

    assert str(requests[0].url) == CHAT_COMPLETIONS_URL
    assert json.loads(requests[0].content)["model"] == MODEL


def test_site_context_uses_normalized_endpoint_and_selected_model():
    requests = []
    page = {
        "id": "page-1",
        "url": "https://example.com/",
        "title": "Example",
        "meta_description": "Customer portal",
        "text": "Customer portal home page.",
    }
    analysis_body = {
        "organization_name": "Example",
        "site_description": "A customer portal.",
        "business_processes": ["Customer service"],
        "evidence_ids": ["page-1"],
        "uncertainties": [],
        "risk_context": {
            "asset_criticality": "medium",
            "environment": "production",
            "sensitive_data": None,
            "requires_auth": True,
            "confidence": 0.8,
            "reason": "The public customer portal appears to be a production service.",
            "evidence_ids": ["page-1"],
        },
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(analysis_body)}}]},
        )

    settings = _settings()
    result = analyze_site_context(
        "https://example.com",
        [page],
        api_url=settings["api_url"],
        api_key=settings["api_key"],
        model_name=settings["model_name"],
        transport=httpx.MockTransport(handler),
    )

    assert result["analysis_source"] == "llm"
    assert str(requests[0].url) == CHAT_COMPLETIONS_URL
    assert json.loads(requests[0].content)["model"] == MODEL
