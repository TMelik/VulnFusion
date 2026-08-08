import json
from pathlib import Path

import utils.dedup_benchmark as dedup_benchmark


DATASET_PATH = Path(__file__).resolve().parent / "fixtures" / "dedup_benchmark_cases.json"


def _single_dataset_fixture_path(tmp_path: Path) -> Path:
    specs = dedup_benchmark.load_benchmark_specs(DATASET_PATH)
    path = tmp_path / "single_benchmark_dataset.json"
    path.write_text(
        json.dumps({"datasets": [specs[0]]}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return path


def test_benchmark_specs_load_and_generate_expected_dataset_sizes():
    specs = dedup_benchmark.load_benchmark_specs(DATASET_PATH)

    assert [spec["dataset_id"] for spec in specs] == [
        "synthetic_100_balanced",
        "synthetic_500_balanced",
        "synthetic_1000_balanced",
    ]
    assert [spec["size"] for spec in specs] == [100, 500, 1000]
    assert all(spec["mix"] == "balanced" for spec in specs)
    assert all(spec["planned_findings"] == spec["size"] for spec in specs)

    generated = [dedup_benchmark.generate_benchmark_dataset(spec) for spec in specs]

    assert [len(dataset["findings"]) for dataset in generated] == [100, 500, 1000]
    assert all(dataset["expected_groups"] for dataset in generated)
    assert all(dataset["host_pool"] > 0 for dataset in generated)


def test_benchmark_metrics_are_computed_consistently_on_real_synthetic_dataset():
    spec = dedup_benchmark.load_benchmark_specs(DATASET_PATH)[0]
    result = dedup_benchmark.benchmark_from_spec(spec)

    assert result["dataset_id"] == "synthetic_100_balanced"
    assert result["client_kind"] == "oracle"
    assert result["live_provider_used"] is False
    assert result["total_findings"] == 100
    assert result["total_final_findings"] <= result["total_findings"]
    assert result["naive_pair_count"] == 4950
    assert result["candidate_pairs_before_blocking"] == result["naive_pair_count"]
    assert 0 <= result["candidate_pairs_after_same_target_blocking"] <= result["naive_pair_count"]
    assert 0 <= result["pairs_skipped_by_similarity_gate"] <= result["candidate_pairs_after_same_target_blocking"]
    assert result["deterministic_merges"] >= 0
    assert result["pairs_sent_to_llm_path"] >= 0
    assert result["llm_or_cached_comparisons"] >= 0
    assert result["cache_hits"] >= 0
    assert result["runtime_seconds"] >= 0.0
    assert result["profiling"]["total_runtime_seconds"] >= 0.0
    assert result["profiling"]["same_scanner_exact_premerge_seconds"] >= 0.0
    assert result["profiling"]["deterministic_cross_scanner_premerge_seconds"] >= 0.0
    assert result["profiling"]["candidate_pair_generation_seconds"] >= 0.0
    assert result["profiling"]["same_target_filtering_seconds"] >= 0.0
    assert result["profiling"]["cheap_similarity_gate_seconds"] >= 0.0
    assert result["profiling"]["gray_zone_compare_loop_seconds"] >= 0.0
    assert result["profiling"]["final_merge_materialization_seconds"] >= 0.0
    assert result["profiling"]["summary_recompute_seconds"] >= 0.0
    assert 0.0 <= result["blocking_reduction_ratio"] <= 1.0
    assert 0.0 <= result["comparison_reduction_ratio"] <= 1.0
    assert result["candidate_pairs_after_same_target_blocking"] >= result["llm_or_cached_comparisons"]
    assert result["pairs_sent_to_llm_path"] >= result["llm_or_cached_comparisons"]
    assert set(result["mode_counts"]) == {"deterministic", "hybrid", "llm", "no_merge"}
    assert sum(result["mode_counts"].values()) == result["total_final_findings"]
    assert 0.0 <= result["deterministic_resolution_share"] <= 1.0
    assert 0.0 <= result["gray_zone_share"] <= 1.0


def test_benchmark_summary_is_readable_and_reports_runtime_and_ratios(capsys, tmp_path):
    dataset_path = _single_dataset_fixture_path(tmp_path)

    rc = dedup_benchmark.main([str(dataset_path)])
    captured = capsys.readouterr().out

    assert rc == 0
    assert "Dedup Benchmark Summary" in captured
    assert "Dataset synthetic_100_balanced" in captured
    assert "- llm client: oracle" in captured
    assert "- findings: 100" in captured
    assert "- final findings:" in captured
    assert "- naive pair count: 4950" in captured
    assert "- candidate pairs after blocking:" in captured
    assert "- runtime:" in captured
    assert "- comparison reduction ratio:" in captured
    assert "- deterministic resolution share:" in captured
    assert "- gray-zone share:" in captured
    assert "- mode distribution:" in captured


def test_benchmark_profile_summary_is_readable_without_live_provider_calls(capsys, tmp_path):
    dataset_path = _single_dataset_fixture_path(tmp_path)

    rc = dedup_benchmark.main([str(dataset_path), "--profile"])
    captured = capsys.readouterr().out

    assert rc == 0
    assert "Dedup Profiling Summary" in captured
    assert "- dataset: synthetic_100_balanced" in captured
    assert "- total runtime:" in captured
    assert "- same-scanner premerge:" in captured
    assert "- deterministic cross-scanner premerge:" in captured
    assert "- candidate pair generation:" in captured
    assert "- same-target filtering:" in captured
    assert "- cheap similarity gate:" in captured
    assert "- gray-zone compare loop:" in captured
    assert "- final merge/materialization:" in captured
    assert "- summary recompute:" in captured
    assert "- top hot spots:" in captured


def test_repeated_benchmark_runs_remain_stable_without_shared_runtime_state():
    spec = dedup_benchmark.load_benchmark_specs(DATASET_PATH)[1]

    first = dedup_benchmark.benchmark_from_spec(spec)
    second = dedup_benchmark.benchmark_from_spec(spec)

    stable_keys = [
        "dataset_id",
        "client_kind",
        "live_provider_used",
        "total_findings",
        "total_final_findings",
        "naive_pair_count",
        "candidate_pairs_before_blocking",
        "candidate_pairs_after_same_target_blocking",
        "pairs_skipped_by_similarity_gate",
        "deterministic_merges",
        "pairs_sent_to_llm_path",
        "llm_or_cached_comparisons",
        "cache_hits",
        "blocking_reduction_ratio",
        "comparison_reduction_ratio",
        "deterministic_resolution_share",
        "gray_zone_share",
        "mode_counts",
    ]

    for key in stable_keys:
        assert second[key] == first[key]

    assert set(second["profiling"]) >= {
        "same_scanner_exact_premerge_seconds",
        "deterministic_cross_scanner_premerge_seconds",
        "candidate_pair_generation_seconds",
        "same_target_filtering_seconds",
        "cheap_similarity_gate_seconds",
        "gray_zone_compare_loop_seconds",
        "final_merge_materialization_seconds",
        "summary_recompute_seconds",
        "total_runtime_seconds",
    }
