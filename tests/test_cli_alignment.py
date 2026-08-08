from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent.parent


def _assert_in_order(text: str, fragments: list[str]) -> None:
    lowered = text.lower()
    positions = []
    for fragment in fragments:
        position = lowered.find(fragment.lower())
        assert position != -1, f"Missing fragment: {fragment}"
        positions.append(position)
    assert positions == sorted(positions), f"Fragments out of order: {fragments}"


def test_main_help_omits_removed_legacy_enrichment_flags():
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert result.returncode == 0, result.stderr
    for flag in ("--cvss-file", "--epss-file", "--kev-file"):
        assert flag not in result.stdout
    assert "--asset-context-file" in result.stdout


def test_main_help_lists_zap_af_plan_flag():
    result = subprocess.run(
        [sys.executable, "main.py", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    help_text = " ".join(result.stdout.split())

    assert result.returncode == 0, result.stderr
    assert "--zap-af-plan" in help_text
    assert "custom ZAP Automation Framework YAML plan template" in help_text


def test_documented_pipeline_order_matches_main():
    main_source = (ROOT / "main.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    walkthrough = (ROOT / "docs" / "walkthrough.md").read_text(encoding="utf-8")

    _assert_in_order(
        main_source,
        [
            "results = resolver.apply(results)",
            "results = add_comparison_to_results(results, data_dir)",
            "results = _apply_asset_context_to_results(results, asset_context_rules)",
            "results = score_vulnerabilities(",
            "results = LLMFindingAnalyzer(",
            "results = sanitize_results_for_export(results)",
            "json_path = orchestrator.save_results(results, args.output)",
        ],
    )
    _assert_in_order(
        readme,
        [
            "scan and normalize",
            "conservative cross-scanner deduplication",
            "optional comparison with the previous scan",
            "asset context and deterministic risk scoring",
            "bounded advisory finding analysis",
            "sanitized JSON and self-contained HTML report",
        ],
    )
    _assert_in_order(
        walkthrough,
        [
            "scan or offline ZAP import",
            "normalize",
            "structured LLM duplicate resolution",
            "optional history comparison",
            "deterministic risk scoring",
            "structured advisory LLM analysis",
            "sanitize / validate / save / HTML report",
        ],
    )


def test_docs_describe_current_and_removed_enrichment_flags_correctly():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    walkthrough = (ROOT / "docs" / "walkthrough.md").read_text(encoding="utf-8")

    for flag in ("--cvss-file", "--epss-file", "--kev-file"):
        assert flag not in readme
        assert flag not in walkthrough
    assert "--asset-context-file" in readme
    assert "--asset-context-file" in walkthrough

    for removed_flag in ("--no-enrich", "--debug-enrich", "--knowledge-base"):
        assert removed_flag not in readme
        assert removed_flag not in walkthrough


def test_docs_describe_knowledge_db_as_versioned_llm_caches():
    readme = " ".join((ROOT / "README.md").read_text(encoding="utf-8").lower().split())
    walkthrough = (ROOT / "docs" / "walkthrough.md").read_text(encoding="utf-8").lower()

    assert "duplicate-resolution cache" in readme
    assert "advisory finding-analysis cache" in readme

    assert "decisions are cached by finding evidence" in walkthrough
    assert "scanner evidence as the source of truth" in walkthrough


def test_docs_describe_reports_as_default_for_normal_scans():
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    walkthrough = " ".join(
        (ROOT / "docs" / "walkthrough.md").read_text(encoding="utf-8").lower().split()
    )

    assert "normal scan runs write `report.html` automatically" in readme
    assert "--no-report" in readme
    assert "global.report: false" in readme
    assert "exit before the save/report stage" in walkthrough


def test_docs_do_not_describe_removed_steps_or_incomplete_report():
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    walkthrough = (ROOT / "docs" / "walkthrough.md").read_text(encoding="utf-8").lower()

    for stale_phrase in (
        "→ analyze →",
        "after risk scoring, before analysis/reporting",
        "status:** partially implemented",
        "full html report implementation can be completed in follow-up work",
        "current report shows enriched data in json export",
    ):
        assert stale_phrase not in walkthrough

    for stale_phrase in (
        "knowledge sync",
        "offline cve intelligence",
        "risk score / priority output is unchanged when scoring is enabled",
    ):
        assert stale_phrase not in walkthrough

    assert "partially implemented" not in readme
    assert "impact knowledge layer" not in readme
    assert "impact knowledge layer" not in walkthrough
    assert "knowledge/vuln_knowledge.yaml" not in readme
    assert "knowledge/vuln_knowledge.yaml" not in walkthrough
    assert "scanner evidence" in readme
    assert "scanner-native vulnerability name" in readme


def test_demo_wrapper_text_matches_current_pipeline_description():
    demo = (ROOT / "demo_integration.py").read_text(encoding="utf-8").lower()

    assert "llm duplicate resolution)" in demo
    assert "llm duplicate resolution, compare)" in demo
    assert "processed with llm-duplicate-resolution/compare" in demo
    assert "knowledge sync" not in demo
    assert "cve intel" not in demo
    assert "asset context" not in demo
    assert "impact enrich" not in demo
