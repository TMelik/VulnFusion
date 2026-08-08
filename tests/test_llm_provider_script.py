import argparse
import importlib.util
from pathlib import Path
import sys


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "test_llm_provider.py"
SPEC = importlib.util.spec_from_file_location("llm_provider_script", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
llm_provider_script = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(llm_provider_script)


LLM_ENV_VARS = (
    "VULN_MANAGER_LLM_API_URL",
    "VULN_MANAGER_LLM_API_KEY",
    "VULN_MANAGER_LLM_MODEL",
    "VULN_MANAGER_LLM_TIMEOUT",
)


def _clear_llm_env(monkeypatch):
    for name in LLM_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def test_build_config_uses_generic_env_settings(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")

    config = llm_provider_script.build_config(
        argparse.Namespace(api_url=None, api_key=None, model=None, timeout=9.5, json=False)
    )

    assert config.api_url == "https://llm.example/v1/chat/completions"
    assert config.api_key == "generic-secret-5678"
    assert config.model_name == "generic-model"
    assert config.timeout_seconds == 9.5


def test_parser_accepts_api_key_flag():
    args = llm_provider_script._parser().parse_args(
        [
            "--api-url", "https://cli.example/v1/chat/completions",
            "--api-key", "cli-secret-9999",
            "--model", "cli-model",
        ]
    )

    assert args.api_url == "https://cli.example/v1/chat/completions"
    assert args.api_key == "cli-secret-9999"
    assert args.model == "cli-model"
    assert args.duplicate_smoke is False


def test_parser_accepts_duplicate_smoke_flag():
    args = llm_provider_script._parser().parse_args(["--duplicate-smoke"])

    assert args.duplicate_smoke is True


def test_build_config_prefers_cli_over_env(monkeypatch):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")

    config = llm_provider_script.build_config(
        argparse.Namespace(
            api_url="https://cli.example/v1/chat/completions",
            api_key="cli-secret-9999",
            model="cli-model",
            timeout=9.5,
            json=False,
        )
    )

    assert config.api_url == "https://cli.example/v1/chat/completions"
    assert config.api_key == "cli-secret-9999"
    assert config.model_name == "cli-model"


def test_main_returns_validation_error_without_complete_generic_config(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "VULN_MANAGER_LLM_API_KEY" in captured.err
    assert "VULN_MANAGER_LLM_API_URL" in captured.err
    assert "VULN_MANAGER_LLM_MODEL" in captured.err
    assert "cannot run" in captured.err


def test_main_returns_validation_error_for_model_env_reference(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "$GROQ_API_KEY")
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "environment-variable reference" in captured.err
    assert "VULN_MANAGER_LLM_MODEL" in captured.err
    assert "cannot run" in captured.err


def test_main_reports_passed_healthcheck(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")

    class FakeClient:
        def __init__(self, config):
            self.config = config

        def healthcheck(self):
            return {
                "status": "passed",
                "llm_decision": "yes",
                "request_hash": "req-123",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            }

    monkeypatch.setattr(llm_provider_script, "OpenAICompatibleLLMClient", FakeClient)
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "health check passed" in captured.out.lower()
    assert "***5678" in captured.out
    assert "generic-secret-5678" not in captured.out
    assert "req-123" in captured.out


def test_main_reports_passed_healthcheck_with_cli_only_config(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)

    class FakeClient:
        def __init__(self, config):
            self.config = config

        def healthcheck(self):
            return {
                "status": "passed",
                "llm_decision": "yes",
                "request_hash": "req-cli-123",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            }

    monkeypatch.setattr(llm_provider_script, "OpenAICompatibleLLMClient", FakeClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_llm_provider.py",
            "--api-url", "https://cli.example/v1/chat/completions",
            "--api-key", "cli-secret-9999",
            "--model", "cli-model",
        ],
    )

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "***9999" in captured.out
    assert "cli-secret-9999" not in captured.out
    assert "req-cli-123" in captured.out


def test_main_json_output_masks_cli_api_key(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)

    class FakeClient:
        def __init__(self, config):
            self.config = config

        def healthcheck(self):
            return {
                "status": "passed",
                "llm_decision": "yes",
                "request_hash": "req-json-123",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            }

    monkeypatch.setattr(llm_provider_script, "OpenAICompatibleLLMClient", FakeClient)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "test_llm_provider.py",
            "--api-url", "https://cli.example/v1/chat/completions",
            "--api-key", "cli-secret-9999",
            "--model", "cli-model",
            "--json",
        ],
    )

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"api_key": "***9999"' in captured.out
    assert "cli-secret-9999" not in captured.out
    assert "cli-secret-9999" not in captured.err


def test_main_reports_passed_duplicate_smoke(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")
    monkeypatch.setattr(
        llm_provider_script,
        "run_duplicate_smoke",
        lambda config: {
            "status": "passed",
            "mode": "duplicate_smoke",
            "config": config.safe_summary(),
            "checks": {
                "provider_healthcheck_passed": True,
                "live_comparison_attempted": True,
                "live_comparison_succeeded": True,
                "provider_boundary_reached": True,
                "comparison_sent_to_llm": True,
            },
            "failed_checks": [],
            "duplicate_analysis": {
                "provider_healthcheck_status": "passed",
                "live_llm_comparisons_attempted": 1,
                "live_llm_comparisons_succeeded": 1,
            },
            "comparison_records": [
                {
                    "comparison_status": "compared_with_llm",
                    "request_hash": "req-dup-123",
                    "provider_attempt_count": 1,
                }
            ],
        },
    )
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py", "--duplicate-smoke"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "duplicate smoke test passed" in captured.out.lower()
    assert "***5678" in captured.out
    assert "generic-secret-5678" not in captured.out
    assert "req-dup-123" in captured.out


def test_main_reports_failed_duplicate_smoke(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")
    monkeypatch.setattr(
        llm_provider_script,
        "run_duplicate_smoke",
        lambda config: {
            "status": "failed",
            "mode": "duplicate_smoke",
            "config": config.safe_summary(),
            "checks": {
                "provider_healthcheck_passed": False,
                "live_comparison_attempted": True,
                "live_comparison_succeeded": False,
                "provider_boundary_reached": False,
                "comparison_sent_to_llm": False,
            },
            "failed_checks": [
                "provider_healthcheck_passed",
                "live_comparison_succeeded",
                "provider_boundary_reached",
            ],
            "duplicate_analysis": {
                "provider_healthcheck_status": "failed",
                "provider_healthcheck_error": "HTTP 401 authentication_error: invalid key",
                "live_llm_comparisons_attempted": 0,
                "live_llm_comparisons_succeeded": 0,
                "live_llm_comparisons_failed": 0,
                "provider_failure_categories": {"authentication_error": 1},
            },
            "comparison_records": [],
        },
    )
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py", "--duplicate-smoke"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "duplicate smoke test failed" in captured.err.lower()
    assert "***5678" in captured.err
    assert "generic-secret-5678" not in captured.err
    assert "authentication_error" in captured.err


def test_main_duplicate_smoke_json_masks_api_key(monkeypatch, capsys):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "generic-secret-5678")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "generic-model")
    monkeypatch.setattr(
        llm_provider_script,
        "run_duplicate_smoke",
        lambda config: {
            "status": "passed",
            "mode": "duplicate_smoke",
            "config": config.safe_summary(),
            "checks": {
                "provider_healthcheck_passed": True,
                "live_comparison_attempted": True,
                "live_comparison_succeeded": True,
                "provider_boundary_reached": True,
                "comparison_sent_to_llm": True,
            },
            "failed_checks": [],
            "duplicate_analysis": {
                "provider_healthcheck_status": "passed",
                "live_llm_comparisons_attempted": 1,
                "live_llm_comparisons_succeeded": 1,
            },
            "comparison_records": [],
        },
    )
    monkeypatch.setattr(sys, "argv", ["test_llm_provider.py", "--duplicate-smoke", "--json"])

    exit_code = llm_provider_script.main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"api_key": "***5678"' in captured.out
    assert "generic-secret-5678" not in captured.out
