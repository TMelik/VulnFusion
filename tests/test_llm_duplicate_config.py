import argparse
import os

import pytest

import demo_integration
import main
from utils.env_loader import load_project_dotenv
from utils.llm_duplicate_resolver import LLMDuplicateConfig


LLM_ENV_VARS = (
    "VULN_MANAGER_DUPLICATE_MODE",
    "VULN_MANAGER_LLM_API_URL",
    "VULN_MANAGER_LLM_API_KEY",
    "VULN_MANAGER_LLM_MODEL",
    "VULN_MANAGER_LLM_TIMEOUT",
    "VULN_MANAGER_LLM_DEBUG",
    "VULN_MANAGER_LLM_CACHE_ENABLED",
)


def _args(**overrides) -> argparse.Namespace:
    values = {
        "no_dedupe": False,
        "duplicate_mode": "llm",
        "llm_timeout": None,
        "no_llm_cache": False,
        "llm_api_url": None,
        "llm_api_key": None,
        "llm_model": None,
        "llm_debug": False,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


@pytest.fixture(params=[main._build_duplicate_config, demo_integration._build_duplicate_config], ids=["main", "demo"])
def config_builder(request):
    return request.param


@pytest.fixture(params=[main._default_duplicate_mode, demo_integration._default_duplicate_mode], ids=["main", "demo"])
def default_duplicate_mode(request):
    return request.param


def _clear_llm_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in LLM_ENV_VARS:
        monkeypatch.delenv(name, raising=False)


def _write_dotenv(tmp_path, lines) -> None:
    (tmp_path / ".env").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_config_builder_prefers_cli_args_first(monkeypatch, config_builder):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://env.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "env-model")

    config = config_builder(
        _args(
            llm_api_url="https://cli.example/v1/chat/completions",
            llm_api_key="cli-secret-9999",
            llm_model="cli-model",
        )
    )

    assert config.api_url == "https://cli.example/v1/chat/completions"
    assert config.api_key == "cli-secret-9999"
    assert config.model_name == "cli-model"


def test_config_builder_reads_generic_env_settings(monkeypatch, config_builder):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://env.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "env-model")

    config = config_builder(_args())

    assert config.api_url == "https://env.example/v1/chat/completions"
    assert config.api_key == "env-secret-1234"
    assert config.model_name == "env-model"


def test_config_builder_reads_values_from_dotenv_and_masks_secret(monkeypatch, tmp_path, config_builder):
    _clear_llm_env(monkeypatch)
    _write_dotenv(
        tmp_path,
        [
            "VULN_MANAGER_LLM_API_URL=https://dotenv.example/v1/chat/completions",
            "VULN_MANAGER_LLM_API_KEY=dotenv-secret-5678",
            "VULN_MANAGER_LLM_MODEL=dotenv-model",
            "VULN_MANAGER_LLM_TIMEOUT=21",
            "VULN_MANAGER_LLM_DEBUG=true",
            "VULN_MANAGER_LLM_CACHE_ENABLED=false",
        ],
    )

    loaded_path = load_project_dotenv(tmp_path, force=True)
    config = config_builder(_args())

    assert loaded_path == tmp_path / ".env"
    assert config.api_url == "https://dotenv.example/v1/chat/completions"
    assert config.api_key == "dotenv-secret-5678"
    assert config.model_name == "dotenv-model"
    assert config.timeout_seconds == 21.0
    assert config.debug is True
    assert config.cache_enabled is False
    assert config.safe_summary()["api_key"] == "***5678"
    assert "dotenv-secret-5678" not in repr(config)


def test_load_project_dotenv_preserves_existing_environment_values(monkeypatch, tmp_path):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "shell-model")
    _write_dotenv(
        tmp_path,
        [
            "VULN_MANAGER_LLM_API_URL=https://dotenv.example/v1/chat/completions",
            "VULN_MANAGER_LLM_API_KEY=dotenv-secret-5678",
            "VULN_MANAGER_LLM_MODEL=dotenv-model",
        ],
    )

    load_project_dotenv(tmp_path, force=True)

    assert os.getenv("VULN_MANAGER_LLM_API_URL") == "https://dotenv.example/v1/chat/completions"
    assert os.getenv("VULN_MANAGER_LLM_API_KEY") == "dotenv-secret-5678"
    assert os.getenv("VULN_MANAGER_LLM_MODEL") == "shell-model"


def test_config_builder_still_works_when_dotenv_is_absent(monkeypatch, tmp_path, config_builder):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://env.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "env-model")

    assert load_project_dotenv(tmp_path, force=True) is None

    config = config_builder(_args())

    assert config.api_url == "https://env.example/v1/chat/completions"
    assert config.api_key == "env-secret-1234"
    assert config.model_name == "env-model"


def test_config_builder_leaves_partial_env_for_validation_error(monkeypatch, config_builder):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")

    config = config_builder(_args())
    error = config.validation_error()

    assert error is not None
    assert "llm_api_url" in error
    assert "llm_model" in error
    assert "VULN_MANAGER_LLM_API_URL" in error
    assert "VULN_MANAGER_LLM_API_KEY" in error
    assert "VULN_MANAGER_LLM_MODEL" in error
    assert "env-secret-1234" not in error


def test_llm_duplicate_config_masks_secret_in_repr_and_summary():
    config = LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key="super-secret-key-1234",
        model_name="test-model",
        debug=True,
    )

    summary_text = str(config.safe_summary())

    assert "super-secret-key-1234" not in repr(config)
    assert "super-secret-key-1234" not in summary_text
    assert "***1234" in repr(config)
    assert config.safe_summary()["api_key"] == "***1234"


def test_llm_duplicate_config_reports_generic_missing_values_without_provider_fallbacks():
    config = LLMDuplicateConfig(mode="llm")
    error = config.validation_error()

    assert error is not None
    assert "llm_api_url" in error
    assert "llm_api_key" in error
    assert "llm_model" in error
    assert "VULN_MANAGER_LLM_API_URL" in error
    assert "VULN_MANAGER_LLM_API_KEY" in error
    assert "VULN_MANAGER_LLM_MODEL" in error
    assert "GROQ_" not in error
    assert "GEMINI_" not in error


def test_llm_duplicate_config_rejects_env_var_reference_as_model_name():
    config = LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key="test-key-1234",
        model_name="$GROQ_API_KEY",
    )

    error = config.validation_error()

    assert error is not None
    assert "environment-variable reference" in error
    assert "VULN_MANAGER_LLM_MODEL" in error
    assert config.ready is False


def test_llm_duplicate_config_rejects_api_key_like_model_name_without_leaking_secret():
    config = LLMDuplicateConfig(
        mode="llm",
        api_url="https://llm.example/v1/chat/completions",
        api_key="gsk_real-secret-1234",
        model_name="gsk_real-secret-1234",
    )

    error = config.validation_error()

    assert error is not None
    assert "looks like an API key" in error
    assert "real-secret-1234" not in error
    assert config.ready is False


def test_existing_generic_openai_compatible_behavior_still_works(monkeypatch, config_builder):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://azure-openai.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "azure-secret-4321")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "gpt-4.1-mini")

    config = config_builder(_args())

    assert config.api_url == "https://azure-openai.example/v1/chat/completions"
    assert config.api_key == "azure-secret-4321"
    assert config.model_name == "gpt-4.1-mini"


def test_default_duplicate_mode_auto_enables_llm_for_complete_generic_env(monkeypatch, default_duplicate_mode):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://llm.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "provider-model")

    assert default_duplicate_mode() == "llm"


def test_default_duplicate_mode_returns_off_for_partial_generic_env(monkeypatch, default_duplicate_mode):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")

    assert default_duplicate_mode() == "off"


def test_default_duplicate_mode_explicit_off_still_wins(monkeypatch, default_duplicate_mode):
    _clear_llm_env(monkeypatch)
    monkeypatch.setenv("VULN_MANAGER_DUPLICATE_MODE", "off")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_URL", "https://env.example/v1/chat/completions")
    monkeypatch.setenv("VULN_MANAGER_LLM_API_KEY", "env-secret-1234")
    monkeypatch.setenv("VULN_MANAGER_LLM_MODEL", "env-model")

    assert default_duplicate_mode() == "off"


def test_default_duplicate_mode_returns_off_without_llm_env(monkeypatch, default_duplicate_mode):
    _clear_llm_env(monkeypatch)

    assert default_duplicate_mode() == "off"
