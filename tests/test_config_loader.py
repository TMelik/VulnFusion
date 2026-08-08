from pathlib import Path

import pytest

from utils.config_loader import load_defectdojo_config


def test_defectdojo_config_file_loads_correctly(tmp_path):
    config_path = tmp_path / "defectdojo.config"
    config_path.write_text(
        """
[defectdojo]
enabled = true
base_url = http://localhost:8080
api_token_env = DD_TOKEN
product_type = Research and Development
product = My App
engagement = Nightly Scans
upload_mode = raw-per-scan
minimum_severity = Info
active = true
verified = false
auto_create_context = true
verify_ssl = false
timeout_seconds = 60

[defectdojo.scan_types]
nmap = Nmap Scan
zap = ZAP Scan

[defectdojo.test_titles]
nmap = nmap | {target}
zap = zap | {target}

[defectdojo.artifacts]
nmap = xml
zap = xml,json
""".strip()
        + "\n",
        encoding="utf-8",
    )

    config = load_defectdojo_config(config_path)

    assert config.loaded is True
    assert config.enabled is True
    assert config.base_url == "http://localhost:8080"
    assert config.api_token_env == "DD_TOKEN"
    assert config.product_type_name == "Research and Development"
    assert config.product_name == "My App"
    assert config.engagement_name == "Nightly Scans"
    assert config.upload_mode == "raw-per-scan"
    assert config.verified is False
    assert config.verify_tls is False
    assert config.timeout_seconds == 60
    assert config.scan_types == {"nmap": "Nmap Scan", "zap": "ZAP Scan"}
    assert config.test_titles["nmap"] == "nmap | {target}"
    assert config.artifact_formats["zap"] == ("xml", "json")


def test_missing_default_defectdojo_config_does_not_fail(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    config = load_defectdojo_config()

    assert config.loaded is False
    assert config.path == Path("defectdojo.config")


def test_missing_explicit_defectdojo_config_fails(tmp_path):
    with pytest.raises(FileNotFoundError, match="Config file does not exist"):
        load_defectdojo_config(tmp_path / "missing.config", require=True)
