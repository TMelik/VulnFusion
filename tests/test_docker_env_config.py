from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parent.parent


def test_docker_compose_forwards_supported_llm_env_vars():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    service = compose["services"]["vuln-manager"]
    environment = service["environment"]

    assert environment["VULN_MANAGER_LLM_API_KEY"] == "${VULN_MANAGER_LLM_API_KEY:-}"
    assert environment["VULN_MANAGER_LLM_API_URL"] == "${VULN_MANAGER_LLM_API_URL:-}"
    assert environment["VULN_MANAGER_LLM_MODEL"] == "${VULN_MANAGER_LLM_MODEL:-}"
    assert "GROQ_API_KEY" not in environment
    assert "GEMINI_API_KEY" not in environment


def test_dockerignore_excludes_local_env_files_from_build_context():
    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")

    assert ".env" in dockerignore
    assert ".env.*" in dockerignore
    assert "!.env.example" in dockerignore
