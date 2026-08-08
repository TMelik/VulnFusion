from pathlib import Path
import subprocess
import sys

import demo_integration


ROOT = Path(__file__).resolve().parent.parent


def test_demo_integration_help_runs():
    result = subprocess.run(
        [sys.executable, "demo_integration.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    assert "Integration Demo" in result.stdout
    for flag in ("--cvss-file", "--epss-file", "--kev-file", "--asset-context-file"):
        assert flag not in result.stdout


def test_single_scanner_wrapper_preserves_failure_metadata():
    class FakeScanner:
        def get_version(self):
            return "v-test"

    class FakeOrchestrator:
        scanners = {"zap": FakeScanner()}

        @staticmethod
        def _count_by_severity(findings):
            counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            for finding in findings:
                severity = finding.get('severity', 'info')
                if severity in counts:
                    counts[severity] += 1
            return counts

    wrapped = demo_integration._wrap_single_scanner_results(
        FakeOrchestrator(),
        "zap",
        "https://example.com",
        {
            "timestamp": "2026-03-31T12:00:00Z",
            "error": "scanner failed",
            "findings": [],
        },
    )

    assert wrapped["timestamp"] == "2026-03-31T12:00:00Z"
    assert wrapped["scanners_run"] == ["zap"]
    assert wrapped["tool_versions"] == {"zap": "v-test"}
    assert wrapped["errors"] == [{"scanner": "zap", "error": "scanner failed"}]
    assert wrapped["all_findings"] == []
    assert wrapped["summary"]["total_findings"] == 0
