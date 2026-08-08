from pathlib import Path

import utils.dedup_evaluation as dedup_evaluation


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BASE_DATASET_PATH = FIXTURES_DIR / "dedup_eval_cases.json"
CLUSTER_DATASET_PATH = FIXTURES_DIR / "dedup_eval_clusters.json"
HISTORY_DATASET_PATH = FIXTURES_DIR / "dedup_history_eval_cases.json"


def test_dedup_eval_datasets_load_with_expected_structure():
    base_cases = dedup_evaluation.load_dedup_eval_cases(BASE_DATASET_PATH)
    cluster_cases = dedup_evaluation.load_dedup_eval_cases(CLUSTER_DATASET_PATH)
    history_cases = dedup_evaluation.load_dedup_history_eval_cases(HISTORY_DATASET_PATH)

    assert len(base_cases) == 13
    assert len(cluster_cases) == 6
    assert len(history_cases) == 6

    assert {case["bucket"] for case in base_cases} == {
        "deterministic",
        "gray_zone",
        "guardrail",
    }
    assert {case["expected_mode"] for case in cluster_cases} == {
        "deterministic",
        "hybrid",
        "llm",
    }
    assert {tag for case in cluster_cases for tag in case["case_tags"]} == {
        "cluster",
        "provenance",
    }

    assert all(case["expected_groups"] for case in base_cases + cluster_cases)
    assert all(len(case["finding_ids"]) >= 2 for case in base_cases + cluster_cases)
    assert all("expected_diff" in case for case in history_cases)


def test_pairwise_and_cluster_metrics_are_computed_correctly_on_known_mini_datasets():
    pairwise = dedup_evaluation.compute_pairwise_metrics(
        expected_groups=[["a", "b"], ["c"]],
        actual_groups=[["a", "c"], ["b"]],
    )
    cluster = dedup_evaluation.compute_cluster_metrics(
        expected_groups=[["a", "b", "c"], ["d"]],
        actual_groups=[["a", "b", "d"], ["c"]],
    )

    assert pairwise == {
        "true_positives": 0,
        "false_positives": 1,
        "false_negatives": 1,
        "predicted_pairs": 1,
        "expected_duplicate_pairs": 1,
        "precision": 0.0,
        "recall": 0.0,
        "false_merge_rate": 1.0,
        "false_split_rate": 1.0,
    }
    assert cluster == {
        "exact_partition_match": False,
        "merge_count_match": True,
        "expected_merge_count": 1,
        "actual_merge_count": 1,
        "cluster_overmerge_count": 1,
        "cluster_undersplit_count": 1,
    }


def test_combined_dedup_evaluation_scores_cleanly_on_base_cluster_and_provenance_cases():
    report = dedup_evaluation.evaluate_dedup_dataset(
        [BASE_DATASET_PATH, CLUSTER_DATASET_PATH]
    )

    assert report["summary"]["total_cases"] == 19
    assert report["summary"]["passed_cases"] == 19
    assert report["summary"]["failed_cases"] == 0
    assert report["summary"]["precision"] == 1.0
    assert report["summary"]["recall"] == 1.0
    assert report["summary"]["false_merge_rate"] == 0.0
    assert report["summary"]["false_split_rate"] == 0.0
    assert report["summary"]["exact_cluster_partition_match_rate"] == 1.0
    assert report["summary"]["merge_count_accuracy"] == 1.0
    assert report["summary"]["cluster_overmerge_count"] == 0
    assert report["summary"]["cluster_undersplit_count"] == 0
    assert report["summary"]["provenance_cases"] == 2
    assert report["summary"]["provenance_passed_cases"] == 2
    assert report["summary"]["confirmation_quality_passed_cases"] == 2
    assert report["summary"]["degraded_merge_handling_passed_cases"] == 2

    assert report["buckets"]["deterministic"]["total_cases"] == 5
    assert report["buckets"]["gray_zone"]["total_cases"] == 9
    assert report["buckets"]["guardrail"]["total_cases"] == 5
    assert report["tags"]["cluster"]["total_cases"] == 4
    assert report["tags"]["cluster"]["passed_cases"] == 4
    assert report["tags"]["provenance"]["total_cases"] == 2
    assert report["tags"]["provenance"]["passed_cases"] == 2

    assert report["mode_counts"] == {
        "deterministic": 5,
        "hybrid": 1,
        "llm": 11,
        "no_merge": 2,
    }

    cases = {case["case_id"]: case for case in report["cases"]}

    assert cases["cluster_three_scanners_same_issue"]["actual_mode"] == "deterministic"
    assert cases["cluster_three_scanners_same_issue"]["comparison_statuses"] == []
    assert (
        cases["cluster_same_scanner_premerge_then_gray_zone_join"]["actual_mode"]
        == "hybrid"
    )
    assert cases["cluster_same_scanner_premerge_then_gray_zone_join"][
        "comparison_statuses"
    ] == ["compared_with_llm"]
    assert (
        cases["guardrail_unrelated_same_target_header_vs_sqli"]["actual_mode"]
        == "no_merge"
    )
    assert cases["guardrail_unrelated_same_target_header_vs_sqli"][
        "comparison_statuses"
    ] == ["skipped_low_similarity"]

    clean_plus_degraded = cases[
        "provenance_clean_plus_degraded_merges_with_clean_confirmation"
    ]["provenance"]
    degraded_only = cases[
        "provenance_degraded_only_corroboration_not_strong_confirmation"
    ]["provenance"]

    assert clean_plus_degraded["required"] is True
    assert clean_plus_degraded["provenance_preserved"] is True
    assert clean_plus_degraded["confirmation_quality_correct"] is True
    assert clean_plus_degraded["degraded_merge_handling_correct"] is True
    assert degraded_only["required"] is True
    assert degraded_only["provenance_preserved"] is True
    assert degraded_only["confirmation_quality_correct"] is True
    assert degraded_only["degraded_merge_handling_correct"] is True


def test_history_evaluation_scores_cleanly_on_labeled_fixture_set():
    report = dedup_evaluation.evaluate_history_dataset(HISTORY_DATASET_PATH)

    assert report["summary"]["total_cases"] == 6
    assert report["summary"]["passed_cases"] == 6
    assert report["summary"]["failed_cases"] == 0
    assert report["summary"]["fixed_accuracy"] == 1.0
    assert report["summary"]["added_accuracy"] == 1.0
    assert report["summary"]["removed_accuracy"] == 1.0
    assert report["summary"]["changed_accuracy"] == 1.0
    assert report["summary"]["unchanged_accuracy"] == 1.0
    assert report["summary"]["stable_identity_match_accuracy"] == 1.0
    assert report["summary"]["stable_identity_matches_total"] == 4
    assert report["summary"]["stable_identity_matches_correct"] == 4

    cases = {case["case_id"]: case for case in report["cases"]}

    assert cases["fixed_finding"]["actual_diff"] == {
        "fixed": ["prev-fixed"],
        "added": [],
        "removed": ["prev-fixed"],
        "changed": [],
        "unchanged": [],
    }
    assert cases["changed_finding_stable_identity"]["actual_diff"] == {
        "fixed": [],
        "added": [],
        "removed": [],
        "changed": ["curr-changed"],
        "unchanged": [],
    }
    assert cases["wording_change_same_finding"]["actual_diff"] == {
        "fixed": [],
        "added": [],
        "removed": [],
        "changed": [],
        "unchanged": ["curr-wording"],
    }
    assert cases["unstable_identity_not_fixed_plus_added"]["stable_matches"] == [
        {
            "previous": "prev-identity",
            "current": "curr-identity",
            "expected_classification": "unchanged",
            "actual_classification": "unchanged",
            "matched": True,
        }
    ]


def test_dedup_evaluation_cli_prints_readable_combined_summary(capsys):
    rc = dedup_evaluation.main(["--history-dataset", str(HISTORY_DATASET_PATH)])
    captured = capsys.readouterr().out

    assert rc == 0
    assert "Dedup Evaluation Summary" in captured
    assert "Pairwise Metrics" in captured
    assert "Cluster Metrics" in captured
    assert "Provenance Checks" in captured
    assert "Tagged Metrics" in captured
    assert "Actual Path Coverage" in captured
    assert "- hybrid: 1" in captured
    assert "History Evaluation Summary" in captured
    assert "- total cases: 19" in captured
    assert "- total cases: 6" in captured
    assert (
        "cluster_same_scanner_premerge_then_gray_zone_join: bucket=gray_zone "
        "tags=cluster expected_mode=hybrid actual_mode=hybrid"
    ) in captured
    assert (
        "guardrail_unrelated_same_target_header_vs_sqli: bucket=guardrail "
        "tags=none expected_mode=no_merge actual_mode=no_merge"
    ) in captured
    assert (
        "wording_change_same_finding: passed=yes fixed=[] added=[] removed=[] "
        "changed=[] unchanged=['curr-wording']"
    ) in captured
