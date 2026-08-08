from pathlib import Path
import subprocess
import sys

import pytest


ROOT = Path(__file__).resolve().parent.parent


def test_main_and_demo_default_to_yaml_knowledge_store_paths():
    for script_path in (ROOT / "main.py", ROOT / "demo_integration.py"):
        source = script_path.read_text(encoding="utf-8")

        assert "unified_vulnerabilities.yaml" in source
        assert "VULN_MANAGER_KNOWLEDGE_DB" in source
        assert "unified_vulnerabilities.sqlite" not in source


@pytest.mark.parametrize("script_name", ["main.py", "demo_integration.py"])
def test_help_text_describes_yaml_knowledge_store_without_sqlite(script_name):
    result = subprocess.run(
        [sys.executable, script_name, "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    help_text = " ".join(result.stdout.split())
    normalized_help = help_text.lower().replace("- ", "-")

    assert result.returncode == 0, result.stderr
    assert "--knowledge-db" in help_text
    assert "yaml store used for llm" in normalized_help
    assert "cache" in normalized_help
    assert "sqlite" not in help_text.lower()
