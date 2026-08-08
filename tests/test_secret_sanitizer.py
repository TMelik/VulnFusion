import json

import pytest

from utils.export_sanitizer import sanitize_results_for_export
from utils.llm_duplicate_resolver import (
    LLMDuplicateConfig,
    LLMProviderError,
    OpenAICompatibleLLMClient,
    build_llm_request_body,
)
from utils.secret_sanitizer import sanitize_secrets


def _finding(scanner: str, description: str, evidence: str) -> dict:
    return {
        "vulnerability_name": "Sensitive request evidence",
        "severity": "medium",
        "asset_id": "https://example.com/login",
        "description": description,
        "remediation": "Rotate exposed credentials.",
        "meta": {
            "scanner": scanner,
            "path": "/login",
            "method": "POST",
            "evidence": evidence,
        },
    }


def test_recursive_sanitizer_redacts_structured_secret_fields_without_mutation():
    payload = {
        "headers": {
            "Authorization": "Bearer top-secret-token",
            "Cookie": "sessionid=cookie-secret",
            "X-API-Key": "api-key-secret",
        },
        "body": {
            "password": "hunter2",
            "access_token": "access-token-secret",
            "profile": {"display_name": "Session Token Research"},
        },
    }

    result = sanitize_secrets(payload)

    assert payload["headers"]["Authorization"] == "Bearer top-secret-token"
    assert result.value["headers"] == {
        "Authorization": "[REDACTED:AUTHORIZATION]",
        "Cookie": "[REDACTED:COOKIE]",
        "X-API-Key": "[REDACTED:API_KEY]",
    }
    assert result.value["body"]["password"] == "[REDACTED:PASSWORD]"
    assert result.value["body"]["access_token"] == "[REDACTED:TOKEN]"
    assert result.value["body"]["profile"]["display_name"] == "Session Token Research"
    assert result.total_redactions == 5


def test_text_sanitizer_redacts_http_curl_url_jwt_and_known_api_key_signatures():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop"
    api_key = "sk-abcdefghijklmnopqrstuvwxyz"
    text = (
        "POST /login HTTP/1.1\n"
        "Authorization: Bearer bearer-secret-value\n"
        "Cookie: sessionid=cookie-secret\n"
        f"X-Debug: {jwt}\n"
        f"password=hunter2&api_key={api_key}\n"
        "curl https://demo-user:demo-password@example.com/private"
    )

    result = sanitize_secrets(text)
    cleaned = result.value

    for secret in ("bearer-secret-value", "cookie-secret", jwt, api_key, "hunter2", "demo-password"):
        assert secret not in cleaned
    assert "Authorization: [REDACTED:AUTHORIZATION]" in cleaned
    assert "Cookie: [REDACTED:COOKIE]" in cleaned
    assert "[REDACTED:JWT]" in cleaned
    assert "password=[REDACTED:PASSWORD]" in cleaned
    assert "api_key=[REDACTED:API_KEY]" in cleaned
    assert "demo-user:[REDACTED:PASSWORD]@example.com" in cleaned


def test_sanitizer_is_idempotent_and_preserves_benign_security_text():
    benign = (
        "CVE-2024-12345 uses token validation. Session handling and password "
        "policy were reviewed. Request id 550e8400-e29b-41d4-a716-446655440000."
    )
    first = sanitize_secrets({"description": benign, "password": "secret"})
    second = sanitize_secrets(first.value)

    assert first.value["description"] == benign
    assert second.value == first.value
    assert second.total_redactions == 0


def test_text_sanitizer_redacts_quoted_values_containing_spaces():
    raw_json = '{"password": "two word password", "session_id": "session with spaces"}'
    shell_text = "client_secret='quoted secret value'"

    cleaned_json = sanitize_secrets(raw_json).value
    cleaned_shell = sanitize_secrets(shell_text).value

    assert "two word password" not in cleaned_json
    assert "session with spaces" not in cleaned_json
    assert '"password": "[REDACTED:PASSWORD]"' in cleaned_json
    assert '"session_id": "[REDACTED:SESSION]"' in cleaned_json
    assert "quoted secret value" not in cleaned_shell
    assert "client_secret='[REDACTED:API_KEY]'" in cleaned_shell


def test_llm_request_builder_removes_secrets_from_prompt_payload():
    secret = "sk-abcdefghijklmnopqrstuvwxyz"
    request = build_llm_request_body(
        _finding("zap", f"Observed api_key={secret}", "Authorization: Bearer request-secret-value"),
        _finding("nuclei", "Same endpoint", "Cookie: sessionid=session-secret-value"),
        model_name="test-model",
    )
    serialized = json.dumps(request)

    assert secret not in serialized
    assert "request-secret-value" not in serialized
    assert "session-secret-value" not in serialized
    assert "[REDACTED:" in serialized


def test_llm_transport_sanitizes_arbitrary_future_request_builders(monkeypatch):
    captured = {}

    class Response:
        status_code = 200
        text = '{"choices":[{"message":{"content":"yes"}}]}'

        def json(self):
            return {"choices": [{"message": {"content": "yes"}}]}

    class Client:
        def __init__(self, **kwargs):
            captured["client_kwargs"] = kwargs

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def post(self, url, *, json, headers):
            captured.update(url=url, body=json, headers=headers)
            return Response()

    monkeypatch.setattr("utils.llm_duplicate_resolver.httpx.Client", Client)
    config = LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key="provider-secret-key",
        model_name="test-model",
    )
    client = OpenAICompatibleLLMClient(config)

    client._post_chat_completion(
        {
            "model": "test-model",
            "messages": [{"role": "user", "content": "password=hunter2"}],
        },
        request_kind="test",
    )

    assert "hunter2" not in json.dumps(captured["body"])
    assert "[REDACTED:PASSWORD]" in json.dumps(captured["body"])
    assert captured["headers"]["Authorization"] == "Bearer provider-secret-key"
    assert "provider-secret-key" not in json.dumps(captured["body"])


def test_llm_provider_error_trace_and_logs_do_not_persist_secrets(monkeypatch, caplog):
    leaked_secret = "two word password"

    class Response:
        status_code = 400
        text = f'{{"error":{{"message":"password: \\\"{leaked_secret}\\\""}}}}'

        def json(self):
            return {"error": {"message": f'password: "{leaked_secret}"'}}

    class Client:
        def __init__(self, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def post(self, url, *, json, headers):
            return Response()

    monkeypatch.setattr("utils.llm_duplicate_resolver.httpx.Client", Client)
    client = OpenAICompatibleLLMClient(
        LLMDuplicateConfig(
            mode="llm",
            api_url="https://llm.example/v1/chat/completions",
            api_key="provider-secret-key",
            model_name="test-model",
        )
    )

    with caplog.at_level("WARNING"), pytest.raises(LLMProviderError) as exc_info:
        client._post_chat_completion(
            {
                "model": "test-model",
                "messages": [{"role": "user", "content": f'password="{leaked_secret}"'}],
            },
            request_kind="test",
        )

    error = exc_info.value
    serialized_error = json.dumps(error.to_trace_payload())
    assert leaked_secret not in serialized_error
    assert leaked_secret not in caplog.text
    assert "provider-secret-key" not in serialized_error
    assert "[REDACTED:PASSWORD]" in serialized_error


def test_export_sanitizer_redacts_secrets_but_keeps_finding_content():
    results = {
        "schema_version": "2.0",
        "all_findings": [
            _finding(
                "zap",
                "Login request returned medium severity.",
                "Authorization: Bearer exported-secret-value",
            )
        ],
        "summary": {"total_findings": 1},
    }

    exported = sanitize_results_for_export(results)
    serialized = json.dumps(exported)

    assert "exported-secret-value" not in serialized
    assert "[REDACTED:AUTHORIZATION]" in serialized
    assert exported["all_findings"][0]["description"] == "Login request returned medium severity."
