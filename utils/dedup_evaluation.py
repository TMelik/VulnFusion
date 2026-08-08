"""Practical evaluation helpers for dedup quality and history stability."""

from __future__ import annotations

import argparse
import copy
import json
from itertools import combinations
from pathlib import Path
from typing import Any, Dict, Iterable, List, Sequence, Tuple

from utils.comparator import compare_scans
from utils.llm_duplicate_resolver import LLMDuplicateConfig, LLMDuplicateResolver


DEFAULT_DEDUP_DATASET_PATH = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "dedup_eval_cases.json"
)
DEFAULT_DEDUP_CLUSTER_DATASET_PATH = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "dedup_eval_clusters.json"
)
DEFAULT_HISTORY_DATASET_PATH = (
    Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "dedup_history_eval_cases.json"
)
DEFAULT_DEDUP_DATASET_PATHS = [
    DEFAULT_DEDUP_DATASET_PATH,
    DEFAULT_DEDUP_CLUSTER_DATASET_PATH,
]


def _ordered_unique(values: Iterable[str]) -> List[str]:
    """Return first-seen unique strings."""
    seen: set[str] = set()
    ordered: List[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        ordered.append(text)
    return ordered


def _path_list(paths: str | Path | Sequence[str | Path]) -> List[Path]:
    """Normalize one path or many paths into Path objects."""
    if isinstance(paths, (str, Path)):
        return [Path(paths)]
    return [Path(path) for path in paths]


def _sorted_groups(groups: Sequence[Sequence[str]]) -> List[List[str]]:
    """Return groups sorted deterministically for comparisons and reports."""
    normalized = [sorted(_ordered_unique(group)) for group in groups if group]
    return sorted(normalized, key=lambda group: (len(group), group))


def _pairwise_pairs(groups: Sequence[Sequence[str]]) -> set[Tuple[str, str]]:
    """Expand groups into sorted pairwise duplicate relations."""
    pairs: set[Tuple[str, str]] = set()
    for group in groups:
        ordered = sorted(_ordered_unique(group))
        for left, right in combinations(ordered, 2):
            pairs.add((left, right))
    return pairs


def _rate_or_default(numerator: int, denominator: int, *, default: float) -> float:
    """Return a stable metric rate with explicit empty-denominator behavior."""
    if denominator <= 0:
        return default
    return numerator / denominator


def _finding_lineage_ids(finding: Dict[str, Any]) -> List[str]:
    """Return original finding ids represented by one current finding."""
    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list) and source_findings:
        finding_ids = [
            str(source.get("finding_id") or "").strip()
            for source in source_findings
            if isinstance(source, dict)
        ]
        finding_ids = [finding_id for finding_id in finding_ids if finding_id]
        if finding_ids:
            return _ordered_unique(finding_ids)

    finding_id = str(finding.get("finding_id") or "").strip()
    return [finding_id] if finding_id else []


def _comparison_ids(records: Sequence[Dict[str, Any]]) -> List[str]:
    """Return stable finding ids from one comparison category list."""
    return _ordered_unique(
        str(record.get("finding_id") or "").strip()
        for record in records
        if isinstance(record, dict)
    )


class OracleLLMClient:
    """A deterministic yes/no client that reuses case labels instead of live LLMs."""

    def __init__(self, *, expected_groups: Sequence[Sequence[str]]) -> None:
        self.duplicate_groups = [
            set(group)
            for group in _sorted_groups(expected_groups)
            if len(group) > 1
        ]
        self.healthcheck_calls = 0
        self.compare_calls: List[Tuple[str, ...]] = []

    def healthcheck(self) -> Dict[str, Any]:
        self.healthcheck_calls += 1
        return {
            "status": "passed",
            "llm_decision": "yes",
            "request_hash": "oracle-healthcheck",
            "attempt_count": 1,
            "retry_backoff_seconds": [],
        }

    def compare(
        self,
        finding_a: Dict[str, Any],
        finding_b: Dict[str, Any],
        *,
        runtime_cache: Any = None,
    ) -> Tuple[str, Dict[str, Any], str, str]:
        compared_ids = tuple(
            sorted(
                _ordered_unique([
                    *_finding_lineage_ids(finding_a),
                    *_finding_lineage_ids(finding_b),
                ])
            )
        )
        self.compare_calls.append(compared_ids)
        compared_set = set(compared_ids)
        decision = (
            "yes"
            if any(compared_set.issubset(group) for group in self.duplicate_groups)
            else "no"
        )
        response_payload = {
            "choices": [{"message": {"content": decision}}],
            "_provider_request": {
                "request_kind": "comparison",
                "attempt_count": 1,
                "retry_backoff_seconds": [],
            },
        }
        raw_response = json.dumps(
            {"choices": [{"message": {"content": decision}}]},
            sort_keys=True,
            ensure_ascii=True,
        )
        request_hash = f"oracle-{len(self.compare_calls)}"
        return decision, response_payload, raw_response, request_hash


def _normalize_expected_groups(
    *,
    finding_ids: Sequence[str],
    expected_groups: Sequence[Sequence[str]],
) -> List[List[str]]:
    """Return a complete expected partition, filling in omitted singletons."""
    known_ids = {str(finding_id) for finding_id in finding_ids}
    covered: set[str] = set()
    groups: List[List[str]] = []

    for raw_group in expected_groups:
        group = sorted(_ordered_unique(raw_group))
        if not group:
            continue
        unknown = [finding_id for finding_id in group if finding_id not in known_ids]
        if unknown:
            raise ValueError(f"expected_groups references unknown finding ids: {unknown}")
        duplicates = sorted(set(group) & covered)
        if duplicates:
            raise ValueError(f"expected_groups repeats finding ids: {duplicates}")
        covered.update(group)
        groups.append(group)

    for finding_id in finding_ids:
        if finding_id not in covered:
            groups.append([finding_id])

    return _sorted_groups(groups)


def _load_case_objects(paths: str | Path | Sequence[str | Path], *, label: str) -> List[Dict[str, Any]]:
    """Load one or more JSON case files and return a combined case list."""
    loaded: List[Dict[str, Any]] = []
    seen_case_ids: set[str] = set()

    for path in _path_list(paths):
        payload = json.loads(path.read_text(encoding="utf-8"))
        cases = payload.get("cases", payload) if isinstance(payload, dict) else payload
        if not isinstance(cases, list):
            raise ValueError(f"{label} dataset must contain a list of cases: {path}")

        for raw_case in cases:
            if not isinstance(raw_case, dict):
                raise ValueError(f"{label} case entries must be objects: {path}")
            case = copy.deepcopy(raw_case)
            case_id = str(case.get("case_id") or "").strip()
            if not case_id:
                raise ValueError(f"{label} dataset cases must include case_id: {path}")
            if case_id in seen_case_ids:
                raise ValueError(f"duplicate {label} case_id: {case_id}")
            seen_case_ids.add(case_id)
            case["_source_file"] = str(path)
            loaded.append(case)

    return loaded


def load_dedup_eval_cases(
    paths: str | Path | Sequence[str | Path] = DEFAULT_DEDUP_DATASET_PATH,
) -> List[Dict[str, Any]]:
    """Load and validate one or more labeled dedup evaluation datasets."""
    cases = _load_case_objects(paths, label="dedup evaluation")
    loaded: List[Dict[str, Any]] = []

    for case in cases:
        case_id = str(case.get("case_id") or "").strip()
        findings = case.get("findings")
        if not isinstance(findings, list) or len(findings) < 2:
            raise ValueError(f"{case_id}: findings must contain at least two items")

        finding_ids: List[str] = []
        for finding in findings:
            if not isinstance(finding, dict):
                raise ValueError(f"{case_id}: findings must be objects")
            finding_id = str(finding.get("finding_id") or "").strip()
            if not finding_id:
                raise ValueError(f"{case_id}: every finding must include finding_id")
            finding_ids.append(finding_id)

        if len(set(finding_ids)) != len(finding_ids):
            raise ValueError(f"{case_id}: finding_id values must be unique within a case")

        case["bucket"] = str(case.get("bucket") or "").strip() or "gray_zone"
        case["expected_mode"] = str(case.get("expected_mode") or "").strip() or "no_merge"
        if case["expected_mode"] not in {"deterministic", "llm", "no_merge", "hybrid"}:
            raise ValueError(f"{case_id}: unsupported expected_mode {case['expected_mode']!r}")

        raw_case_tags = case.get("case_tags") or []
        if isinstance(raw_case_tags, str):
            raw_case_tags = [raw_case_tags]
        case["case_tags"] = _ordered_unique(raw_case_tags)
        case["finding_ids"] = finding_ids
        case["expected_groups"] = _normalize_expected_groups(
            finding_ids=finding_ids,
            expected_groups=case.get("expected_groups") or [],
        )
        case["expected_merge_count"] = int(
            case.get(
                "expected_merge_count",
                sum(1 for group in case["expected_groups"] if len(group) > 1),
            )
        )

        expected_provenance = case.get("expected_provenance")
        if expected_provenance is None:
            case["expected_provenance"] = []
        elif isinstance(expected_provenance, dict):
            case["expected_provenance"] = [copy.deepcopy(expected_provenance)]
        elif isinstance(expected_provenance, list):
            case["expected_provenance"] = copy.deepcopy(expected_provenance)
        else:
            raise ValueError(f"{case_id}: expected_provenance must be an object or list")

        for expected in case["expected_provenance"]:
            if not isinstance(expected, dict):
                raise ValueError(f"{case_id}: expected_provenance entries must be objects")
            group = sorted(_ordered_unique(expected.get("group") or []))
            if not group:
                raise ValueError(f"{case_id}: expected_provenance group must not be empty")
            unknown = [finding_id for finding_id in group if finding_id not in finding_ids]
            if unknown:
                raise ValueError(
                    f"{case_id}: expected_provenance references unknown finding ids: {unknown}"
                )
            expected["group"] = group

        loaded.append(case)

    return loaded


def load_dedup_history_eval_cases(
    path: str | Path = DEFAULT_HISTORY_DATASET_PATH,
) -> List[Dict[str, Any]]:
    """Load and validate the labeled history-comparison evaluation dataset."""
    cases = _load_case_objects(path, label="history evaluation")
    loaded: List[Dict[str, Any]] = []

    for case in cases:
        case_id = str(case.get("case_id") or "").strip()
        previous_findings = case.get("previous_findings")
        current_findings = case.get("current_findings")
        if not isinstance(previous_findings, list) or not isinstance(current_findings, list):
            raise ValueError(f"{case_id}: previous_findings/current_findings must be lists")

        previous_ids: List[str] = []
        current_ids: List[str] = []
        for label, findings in (("previous", previous_findings), ("current", current_findings)):
            finding_ids: List[str] = []
            for finding in findings:
                if not isinstance(finding, dict):
                    raise ValueError(f"{case_id}: {label} findings must be objects")
                finding_id = str(finding.get("finding_id") or "").strip()
                if not finding_id:
                    raise ValueError(f"{case_id}: {label} findings must include finding_id")
                finding_ids.append(finding_id)
            if len(set(finding_ids)) != len(finding_ids):
                raise ValueError(f"{case_id}: {label} finding_id values must be unique")
            if label == "previous":
                previous_ids = finding_ids
            else:
                current_ids = finding_ids

        expected_diff = copy.deepcopy(case.get("expected_diff") or {})
        normalized_expected_diff = {
            "fixed": _ordered_unique(expected_diff.get("fixed") or []),
            "added": _ordered_unique(expected_diff.get("added") or []),
            "removed": _ordered_unique(
                expected_diff.get("removed")
                if "removed" in expected_diff
                else expected_diff.get("fixed") or []
            ),
            "changed": _ordered_unique(expected_diff.get("changed") or []),
            "unchanged": _ordered_unique(expected_diff.get("unchanged") or []),
        }
        invalid_previous = sorted(
            finding_id
            for finding_id in (
                *normalized_expected_diff["fixed"],
                *normalized_expected_diff["removed"],
            )
            if finding_id not in previous_ids
        )
        if invalid_previous:
            raise ValueError(
                f"{case_id}: expected fixed/removed ids must exist in previous_findings: "
                f"{invalid_previous}"
            )

        invalid_current = sorted(
            finding_id
            for finding_id in (
                *normalized_expected_diff["added"],
                *normalized_expected_diff["changed"],
                *normalized_expected_diff["unchanged"],
            )
            if finding_id not in current_ids
        )
        if invalid_current:
            raise ValueError(
                f"{case_id}: expected added/changed/unchanged ids must exist in current_findings: "
                f"{invalid_current}"
            )
        case["expected_diff"] = normalized_expected_diff

        stable_matches = copy.deepcopy(case.get("expected_stable_matches") or [])
        for match in stable_matches:
            if not isinstance(match, dict):
                raise ValueError(f"{case_id}: expected_stable_matches entries must be objects")
            match["previous"] = str(match.get("previous") or "").strip()
            match["current"] = str(match.get("current") or "").strip()
            match["classification"] = str(match.get("classification") or "").strip() or "unchanged"
            if not match["previous"] or not match["current"]:
                raise ValueError(
                    f"{case_id}: expected_stable_matches entries require previous/current ids"
                )
            if match["classification"] not in {"changed", "unchanged"}:
                raise ValueError(
                    f"{case_id}: expected_stable_matches classification must be changed/unchanged"
                )
            if match["previous"] not in previous_ids:
                raise ValueError(
                    f"{case_id}: expected_stable_matches previous id is unknown: "
                    f"{match['previous']}"
                )
            if match["current"] not in current_ids:
                raise ValueError(
                    f"{case_id}: expected_stable_matches current id is unknown: "
                    f"{match['current']}"
                )
        case["expected_stable_matches"] = stable_matches
        loaded.append(case)

    return loaded


def compute_pairwise_metrics(
    *,
    expected_groups: Sequence[Sequence[str]],
    actual_groups: Sequence[Sequence[str]],
) -> Dict[str, Any]:
    """Compute pairwise duplicate metrics for one expected/actual partition."""
    expected_pairs = _pairwise_pairs(expected_groups)
    actual_pairs = _pairwise_pairs(actual_groups)
    true_positives = len(expected_pairs & actual_pairs)
    false_positives = len(actual_pairs - expected_pairs)
    false_negatives = len(expected_pairs - actual_pairs)
    predicted_pairs = len(actual_pairs)
    expected_duplicate_pairs = len(expected_pairs)

    precision = _rate_or_default(true_positives, predicted_pairs, default=1.0)
    recall = _rate_or_default(true_positives, expected_duplicate_pairs, default=1.0)
    false_merge_rate = _rate_or_default(false_positives, predicted_pairs, default=0.0)
    false_split_rate = _rate_or_default(false_negatives, expected_duplicate_pairs, default=0.0)

    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "predicted_pairs": predicted_pairs,
        "expected_duplicate_pairs": expected_duplicate_pairs,
        "precision": precision,
        "recall": recall,
        "false_merge_rate": false_merge_rate,
        "false_split_rate": false_split_rate,
    }


def compute_cluster_metrics(
    *,
    expected_groups: Sequence[Sequence[str]],
    actual_groups: Sequence[Sequence[str]],
) -> Dict[str, Any]:
    """Compute cluster-oriented partition metrics for one case."""
    expected = _sorted_groups(expected_groups)
    actual = _sorted_groups(actual_groups)
    expected_index = {
        finding_id: index
        for index, group in enumerate(expected)
        for finding_id in group
    }
    actual_index = {
        finding_id: index
        for index, group in enumerate(actual)
        for finding_id in group
    }

    cluster_overmerge_count = 0
    for group in actual:
        touched_expected_groups = {
            expected_index[finding_id]
            for finding_id in group
            if finding_id in expected_index
        }
        if len(touched_expected_groups) > 1:
            cluster_overmerge_count += 1

    cluster_undersplit_count = 0
    for group in expected:
        if len(group) <= 1:
            continue
        touched_actual_groups = {
            actual_index[finding_id]
            for finding_id in group
            if finding_id in actual_index
        }
        if len(touched_actual_groups) > 1:
            cluster_undersplit_count += 1

    expected_merge_count = sum(1 for group in expected if len(group) > 1)
    actual_merge_count = sum(1 for group in actual if len(group) > 1)

    return {
        "exact_partition_match": expected == actual,
        "merge_count_match": expected_merge_count == actual_merge_count,
        "expected_merge_count": expected_merge_count,
        "actual_merge_count": actual_merge_count,
        "cluster_overmerge_count": cluster_overmerge_count,
        "cluster_undersplit_count": cluster_undersplit_count,
    }


def _extract_actual_groups(results: Dict[str, Any]) -> List[List[str]]:
    """Return actual finding clusters as groups of original finding ids."""
    groups: List[List[str]] = []
    for finding in results.get("all_findings", []):
        group = _finding_lineage_ids(finding)
        groups.append(group)
    return _sorted_groups(groups)


def _normalize_text_list(value: Any) -> List[str]:
    """Normalize a scalar-or-list field into a compact string list."""
    if value is None:
        return []
    if isinstance(value, list):
        return _ordered_unique(str(item or "").strip() for item in value)
    text = str(value or "").strip()
    return [text] if text else []


def _find_actual_group_finding(
    results: Dict[str, Any],
    *,
    group: Sequence[str],
) -> Dict[str, Any] | None:
    """Return the merged finding whose lineage matches one expected group."""
    target = sorted(_ordered_unique(group))
    for finding in results.get("all_findings", []):
        if _finding_lineage_ids(finding) == target:
            return finding
    return None


def _evaluate_provenance_expectations(
    case: Dict[str, Any],
    results: Dict[str, Any],
) -> Dict[str, Any]:
    """Check provenance and degraded-handling expectations for one case."""
    if not case.get("expected_provenance"):
        return {
            "required": False,
            "all_passed": True,
            "provenance_preserved": True,
            "confirmation_quality_correct": True,
            "degraded_merge_handling_correct": True,
            "errors": [],
        }

    provenance_errors: List[str] = []
    confirmation_errors: List[str] = []
    degraded_errors: List[str] = []

    for expected in case["expected_provenance"]:
        actual_finding = _find_actual_group_finding(results, group=expected["group"])
        if actual_finding is None:
            provenance_errors.append(
                f"group {expected['group']} was not present in the final merged findings"
            )
            continue

        meta = actual_finding.get("meta", {}) if isinstance(actual_finding.get("meta"), dict) else {}
        actual_source_ids = _ordered_unique(
            str(source.get("finding_id") or "").strip()
            for source in actual_finding.get("source_findings", [])
            if isinstance(source, dict)
        )

        expected_found_by = expected.get("found_by")
        if expected_found_by is not None and _normalize_text_list(actual_finding.get("found_by")) != _normalize_text_list(expected_found_by):
            provenance_errors.append(
                f"group {expected['group']} found_by mismatch: "
                f"expected {expected_found_by}, got {actual_finding.get('found_by')}"
            )

        expected_meta_scanners = expected.get("meta_scanners")
        if expected_meta_scanners is not None and _normalize_text_list(meta.get("scanners")) != _normalize_text_list(expected_meta_scanners):
            provenance_errors.append(
                f"group {expected['group']} meta.scanners mismatch: "
                f"expected {expected_meta_scanners}, got {meta.get('scanners')}"
            )

        expected_source_ids = expected.get("source_findings")
        if expected_source_ids is not None and actual_source_ids != _normalize_text_list(expected_source_ids):
            provenance_errors.append(
                f"group {expected['group']} source_findings mismatch: "
                f"expected {expected_source_ids}, got {actual_source_ids}"
            )

        expected_confirmation = expected.get("confirmation_scanners")
        if expected_confirmation is not None and _normalize_text_list(meta.get("confirmation_scanners")) != _normalize_text_list(expected_confirmation):
            confirmation_errors.append(
                f"group {expected['group']} confirmation_scanners mismatch: "
                f"expected {expected_confirmation}, got {meta.get('confirmation_scanners')}"
            )

        expected_multi = expected.get("has_multi_scanner_confirmation")
        if expected_multi is not None and bool(meta.get("has_multi_scanner_confirmation")) is not bool(expected_multi):
            confirmation_errors.append(
                f"group {expected['group']} has_multi_scanner_confirmation mismatch: "
                f"expected {expected_multi}, got {meta.get('has_multi_scanner_confirmation')}"
            )

        expected_degraded_scanners = expected.get("degraded_scanners")
        if expected_degraded_scanners is not None and _normalize_text_list(meta.get("degraded_scanners")) != _normalize_text_list(expected_degraded_scanners):
            degraded_errors.append(
                f"group {expected['group']} degraded_scanners mismatch: "
                f"expected {expected_degraded_scanners}, got {meta.get('degraded_scanners')}"
            )

        expected_degraded_execution = expected.get("degraded_execution")
        if expected_degraded_execution is not None and bool(meta.get("degraded_execution")) is not bool(expected_degraded_execution):
            degraded_errors.append(
                f"group {expected['group']} degraded_execution mismatch: "
                f"expected {expected_degraded_execution}, got {meta.get('degraded_execution')}"
            )

    errors = [*provenance_errors, *confirmation_errors, *degraded_errors]
    return {
        "required": True,
        "all_passed": not errors,
        "provenance_preserved": not provenance_errors,
        "confirmation_quality_correct": not confirmation_errors,
        "degraded_merge_handling_correct": not degraded_errors,
        "errors": errors,
    }


def _infer_actual_mode(results: Dict[str, Any]) -> str:
    """Return the dominant execution path for one evaluated case."""
    analysis = results.get("duplicate_analysis", {})
    had_deterministic = bool(
        analysis.get("deterministic_same_scanner_merges", 0) > 0
        or analysis.get("deterministic_fallback_merges", 0) > 0
    )

    comparison_records = results.get("llm_duplicate_comparisons", [])
    statuses = {
        str(record.get("comparison_status") or "")
        for record in comparison_records
        if isinstance(record, dict)
    }
    had_llm_path = bool(statuses & {"compared_with_llm", "cached"})

    if had_deterministic and had_llm_path:
        return "hybrid"
    if had_deterministic:
        return "deterministic"
    if had_llm_path:
        return "llm"
    return "no_merge"


def evaluate_dedup_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Run the real dedup flow for one labeled evaluation case."""
    client = OracleLLMClient(expected_groups=case["expected_groups"])
    resolver = LLMDuplicateResolver(
        LLMDuplicateConfig(
            mode="llm",
            api_url="https://llm.example/v1/chat/completions",
            api_key="dedup-eval-key",
            model_name="dedup-eval-oracle",
        ),
        client=client,
    )
    results = resolver.apply(
        {
            "all_findings": copy.deepcopy(case["findings"]),
            "summary": {},
        }
    )

    actual_groups = _extract_actual_groups(results)
    pairwise = compute_pairwise_metrics(
        expected_groups=case["expected_groups"],
        actual_groups=actual_groups,
    )
    cluster = compute_cluster_metrics(
        expected_groups=case["expected_groups"],
        actual_groups=actual_groups,
    )
    actual_mode = _infer_actual_mode(results)
    comparison_statuses = _ordered_unique(
        str(record.get("comparison_status") or "")
        for record in results.get("llm_duplicate_comparisons", [])
        if isinstance(record, dict)
    )
    provenance = _evaluate_provenance_expectations(case, results)

    failure_reasons: List[str] = []
    if actual_groups != case["expected_groups"]:
        failure_reasons.append(
            f"expected_groups={case['expected_groups']} actual_groups={actual_groups}"
        )
    if actual_mode != case["expected_mode"]:
        failure_reasons.append(
            f"expected_mode={case['expected_mode']} actual_mode={actual_mode}"
        )
    if not provenance["all_passed"]:
        failure_reasons.extend(provenance["errors"])

    actual_merge_count = sum(1 for group in actual_groups if len(group) > 1)
    return {
        "case_id": case["case_id"],
        "bucket": case["bucket"],
        "case_tags": list(case["case_tags"]),
        "description": case.get("description"),
        "expected_mode": case["expected_mode"],
        "actual_mode": actual_mode,
        "expected_groups": case["expected_groups"],
        "actual_groups": actual_groups,
        "expected_merge_count": case["expected_merge_count"],
        "actual_merge_count": actual_merge_count,
        "comparison_statuses": comparison_statuses,
        "pairwise": pairwise,
        "cluster": cluster,
        "provenance": provenance,
        "passed": not failure_reasons,
        "failure_reasons": failure_reasons,
        "duplicate_analysis": {
            "deterministic_same_scanner_merges": results.get("duplicate_analysis", {}).get(
                "deterministic_same_scanner_merges",
                0,
            ),
            "deterministic_fallback_merges": results.get("duplicate_analysis", {}).get(
                "deterministic_fallback_merges",
                0,
            ),
            "pairs_sent_to_llm": results.get("duplicate_analysis", {}).get(
                "pairs_sent_to_llm",
                0,
            ),
            "low_similarity_pairs_skipped": results.get("duplicate_analysis", {}).get(
                "low_similarity_pairs_skipped",
                0,
            ),
            "total_compared_pairs": results.get("duplicate_analysis", {}).get(
                "total_compared_pairs",
                0,
            ),
        },
    }


def _aggregate_dedup_case_results(case_results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate pairwise, cluster, and provenance metrics for dedup case slices."""
    total_cases = len(case_results)
    passed_cases = sum(1 for result in case_results if result["passed"])
    failed_cases = total_cases - passed_cases
    true_positives = sum(result["pairwise"]["true_positives"] for result in case_results)
    false_positives = sum(result["pairwise"]["false_positives"] for result in case_results)
    false_negatives = sum(result["pairwise"]["false_negatives"] for result in case_results)
    predicted_pairs = sum(result["pairwise"]["predicted_pairs"] for result in case_results)
    expected_duplicate_pairs = sum(
        result["pairwise"]["expected_duplicate_pairs"]
        for result in case_results
    )

    cluster_exact_matches = sum(
        1 for result in case_results if result["cluster"]["exact_partition_match"]
    )
    merge_count_matches = sum(
        1 for result in case_results if result["cluster"]["merge_count_match"]
    )
    cluster_overmerge_count = sum(
        result["cluster"]["cluster_overmerge_count"]
        for result in case_results
    )
    cluster_undersplit_count = sum(
        result["cluster"]["cluster_undersplit_count"]
        for result in case_results
    )

    provenance_cases = sum(1 for result in case_results if result["provenance"]["required"])
    provenance_passed_cases = sum(
        1 for result in case_results if result["provenance"]["required"] and result["provenance"]["all_passed"]
    )
    confirmation_quality_passed_cases = sum(
        1
        for result in case_results
        if result["provenance"]["required"] and result["provenance"]["confirmation_quality_correct"]
    )
    degraded_merge_handling_passed_cases = sum(
        1
        for result in case_results
        if result["provenance"]["required"] and result["provenance"]["degraded_merge_handling_correct"]
    )

    return {
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "predicted_pairs": predicted_pairs,
        "expected_duplicate_pairs": expected_duplicate_pairs,
        "precision": _rate_or_default(true_positives, predicted_pairs, default=1.0),
        "recall": _rate_or_default(true_positives, expected_duplicate_pairs, default=1.0),
        "false_merge_rate": _rate_or_default(false_positives, predicted_pairs, default=0.0),
        "false_split_rate": _rate_or_default(false_negatives, expected_duplicate_pairs, default=0.0),
        "exact_cluster_partition_match_rate": _rate_or_default(
            cluster_exact_matches,
            total_cases,
            default=1.0,
        ),
        "merge_count_accuracy": _rate_or_default(merge_count_matches, total_cases, default=1.0),
        "cluster_overmerge_count": cluster_overmerge_count,
        "cluster_undersplit_count": cluster_undersplit_count,
        "provenance_cases": provenance_cases,
        "provenance_passed_cases": provenance_passed_cases,
        "confirmation_quality_passed_cases": confirmation_quality_passed_cases,
        "degraded_merge_handling_passed_cases": degraded_merge_handling_passed_cases,
    }


def evaluate_dedup_cases(cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate a sequence of labeled dedup cases and return aggregate metrics."""
    case_results = [evaluate_dedup_case(case) for case in cases]
    bucket_results: Dict[str, Dict[str, Any]] = {}
    for bucket in _ordered_unique(result["bucket"] for result in case_results):
        bucket_cases = [result for result in case_results if result["bucket"] == bucket]
        bucket_results[bucket] = _aggregate_dedup_case_results(bucket_cases)

    tag_results: Dict[str, Dict[str, Any]] = {}
    tags = _ordered_unique(
        tag
        for result in case_results
        for tag in result.get("case_tags", [])
    )
    for tag in tags:
        tagged_cases = [result for result in case_results if tag in result.get("case_tags", [])]
        tag_results[tag] = _aggregate_dedup_case_results(tagged_cases)

    return {
        "summary": _aggregate_dedup_case_results(case_results),
        "buckets": bucket_results,
        "tags": tag_results,
        "mode_counts": {
            mode: sum(1 for result in case_results if result["actual_mode"] == mode)
            for mode in ("deterministic", "hybrid", "llm", "no_merge")
        },
        "cases": case_results,
    }


def evaluate_dedup_dataset(
    paths: str | Path | Sequence[str | Path] = DEFAULT_DEDUP_DATASET_PATH,
) -> Dict[str, Any]:
    """Load one or more dedup datasets and evaluate every included case."""
    return evaluate_dedup_cases(load_dedup_eval_cases(paths))


def _compare_id_sets(expected: Sequence[str], actual: Sequence[str]) -> Dict[str, Any]:
    """Return TP/FP/FN metrics for one expected/actual id set."""
    expected_set = set(_ordered_unique(expected))
    actual_set = set(_ordered_unique(actual))
    true_positives = len(expected_set & actual_set)
    false_positives = len(actual_set - expected_set)
    false_negatives = len(expected_set - actual_set)
    return {
        "true_positives": true_positives,
        "false_positives": false_positives,
        "false_negatives": false_negatives,
        "accuracy": _rate_or_default(
            true_positives,
            true_positives + false_positives + false_negatives,
            default=1.0,
        ),
    }


def evaluate_history_case(case: Dict[str, Any]) -> Dict[str, Any]:
    """Run the real history-comparison flow for one labeled case."""
    fixed, added, unchanged, changed = compare_scans(
        copy.deepcopy(case["current_findings"]),
        copy.deepcopy(case["previous_findings"]),
    )
    actual_diff = {
        "fixed": _comparison_ids(fixed),
        "added": _comparison_ids(added),
        "removed": _comparison_ids(fixed),
        "changed": _comparison_ids(changed),
        "unchanged": _comparison_ids(unchanged),
    }

    stable_match_results: List[Dict[str, Any]] = []
    for expected_match in case["expected_stable_matches"]:
        actual_classification = None
        if expected_match["current"] in actual_diff["changed"]:
            actual_classification = "changed"
        elif expected_match["current"] in actual_diff["unchanged"]:
            actual_classification = "unchanged"
        elif expected_match["current"] in actual_diff["added"]:
            actual_classification = "added"

        matched = (
            actual_classification == expected_match["classification"]
            and expected_match["previous"] not in actual_diff["fixed"]
        )
        stable_match_results.append(
            {
                "previous": expected_match["previous"],
                "current": expected_match["current"],
                "expected_classification": expected_match["classification"],
                "actual_classification": actual_classification,
                "matched": matched,
            }
        )

    failure_reasons: List[str] = []
    for category in ("fixed", "added", "removed", "changed", "unchanged"):
        expected_ids = case["expected_diff"][category]
        actual_ids = actual_diff[category]
        if _ordered_unique(expected_ids) != _ordered_unique(actual_ids):
            failure_reasons.append(
                f"{category} mismatch: expected {expected_ids}, got {actual_ids}"
            )

    for match in stable_match_results:
        if not match["matched"]:
            failure_reasons.append(
                "stable identity mismatch: "
                f"expected previous={match['previous']} current={match['current']} "
                f"as {match['expected_classification']}, got {match['actual_classification']}"
            )

    return {
        "case_id": case["case_id"],
        "description": case.get("description"),
        "expected_diff": case["expected_diff"],
        "actual_diff": actual_diff,
        "stable_matches": stable_match_results,
        "passed": not failure_reasons,
        "failure_reasons": failure_reasons,
    }


def _aggregate_history_results(case_results: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate classification accuracy metrics across history-eval cases."""
    total_cases = len(case_results)
    passed_cases = sum(1 for result in case_results if result["passed"])
    failed_cases = total_cases - passed_cases

    summary: Dict[str, Any] = {
        "total_cases": total_cases,
        "passed_cases": passed_cases,
        "failed_cases": failed_cases,
    }

    for category in ("fixed", "added", "removed", "changed", "unchanged"):
        true_positives = 0
        false_positives = 0
        false_negatives = 0
        for result in case_results:
            metrics = _compare_id_sets(
                result["expected_diff"][category],
                result["actual_diff"][category],
            )
            true_positives += metrics["true_positives"]
            false_positives += metrics["false_positives"]
            false_negatives += metrics["false_negatives"]
        summary[f"{category}_accuracy"] = _rate_or_default(
            true_positives,
            true_positives + false_positives + false_negatives,
            default=1.0,
        )

    stable_total = sum(len(result["stable_matches"]) for result in case_results)
    stable_correct = sum(
        1
        for result in case_results
        for match in result["stable_matches"]
        if match["matched"]
    )
    summary["stable_identity_matches_total"] = stable_total
    summary["stable_identity_matches_correct"] = stable_correct
    summary["stable_identity_match_accuracy"] = _rate_or_default(
        stable_correct,
        stable_total,
        default=1.0,
    )
    return summary


def evaluate_history_cases(cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate a sequence of history-comparison cases."""
    case_results = [evaluate_history_case(case) for case in cases]
    return {
        "summary": _aggregate_history_results(case_results),
        "cases": case_results,
    }


def evaluate_history_dataset(
    path: str | Path = DEFAULT_HISTORY_DATASET_PATH,
) -> Dict[str, Any]:
    """Load and evaluate the labeled history-comparison dataset."""
    return evaluate_history_cases(load_dedup_history_eval_cases(path))


def evaluate_full_evaluation(
    *,
    dedup_paths: Sequence[str | Path] = DEFAULT_DEDUP_DATASET_PATHS,
    history_path: str | Path = DEFAULT_HISTORY_DATASET_PATH,
) -> Dict[str, Any]:
    """Evaluate both dedup and history datasets in one combined report."""
    return {
        "dedup": evaluate_dedup_dataset(dedup_paths),
        "history": evaluate_history_dataset(history_path),
    }


def format_dedup_evaluation_summary(report: Dict[str, Any]) -> str:
    """Render a contributor-friendly dedup evaluation summary."""
    summary = report["summary"]
    lines = [
        "Dedup Evaluation Summary",
        "Pairwise Metrics",
        f"- total cases: {summary['total_cases']}",
        f"- passed cases: {summary['passed_cases']}",
        f"- failed cases: {summary['failed_cases']}",
        f"- precision: {summary['precision']:.2f}",
        f"- recall: {summary['recall']:.2f}",
        f"- false merge rate: {summary['false_merge_rate']:.2f}",
        f"- false split rate: {summary['false_split_rate']:.2f}",
        "",
        "Cluster Metrics",
        f"- exact cluster partition match rate: {summary['exact_cluster_partition_match_rate']:.2f}",
        f"- merge count accuracy: {summary['merge_count_accuracy']:.2f}",
        f"- cluster overmerge count: {summary['cluster_overmerge_count']}",
        f"- cluster undersplit count: {summary['cluster_undersplit_count']}",
        "",
        "Provenance Checks",
        f"- provenance cases: {summary['provenance_cases']}",
        f"- provenance preservation pass rate: "
        f"{_rate_or_default(summary['provenance_passed_cases'], summary['provenance_cases'], default=1.0):.2f}",
        f"- confirmation quality pass rate: "
        f"{_rate_or_default(summary['confirmation_quality_passed_cases'], summary['provenance_cases'], default=1.0):.2f}",
        f"- degraded merge handling pass rate: "
        f"{_rate_or_default(summary['degraded_merge_handling_passed_cases'], summary['provenance_cases'], default=1.0):.2f}",
        "",
        "Bucket Metrics",
    ]

    for bucket in ("deterministic", "gray_zone", "guardrail"):
        bucket_summary = report["buckets"].get(bucket)
        if not bucket_summary:
            continue
        lines.append(
            f"- {bucket}: cases={bucket_summary['total_cases']} "
            f"passed={bucket_summary['passed_cases']} "
            f"precision={bucket_summary['precision']:.2f} "
            f"recall={bucket_summary['recall']:.2f} "
            f"cluster_match_rate={bucket_summary['exact_cluster_partition_match_rate']:.2f}"
        )

    if report["tags"]:
        lines.extend(["", "Tagged Metrics"])
        for tag in ("cluster", "provenance"):
            tag_summary = report["tags"].get(tag)
            if not tag_summary:
                continue
            lines.append(
                f"- {tag}: cases={tag_summary['total_cases']} "
                f"passed={tag_summary['passed_cases']} "
                f"precision={tag_summary['precision']:.2f} "
                f"recall={tag_summary['recall']:.2f}"
            )

    lines.extend(
        [
            "",
            "Actual Path Coverage",
            f"- deterministic: {report['mode_counts']['deterministic']}",
            f"- hybrid: {report['mode_counts']['hybrid']}",
            f"- llm: {report['mode_counts']['llm']}",
            f"- no_merge: {report['mode_counts']['no_merge']}",
            "",
            "Case Paths",
        ]
    )

    for case in report["cases"]:
        statuses = ",".join(case["comparison_statuses"]) or "none"
        tags = ",".join(case["case_tags"]) or "none"
        lines.append(
            f"- {case['case_id']}: bucket={case['bucket']} tags={tags} "
            f"expected_mode={case['expected_mode']} actual_mode={case['actual_mode']} "
            f"passed={'yes' if case['passed'] else 'no'} statuses={statuses}"
        )

    failures = [case for case in report["cases"] if not case["passed"]]
    if failures:
        lines.extend(["", "Dedup Failures"])
        for case in failures:
            lines.append(f"- {case['case_id']}: {'; '.join(case['failure_reasons'])}")

    return "\n".join(lines)


def format_history_evaluation_summary(report: Dict[str, Any]) -> str:
    """Render a contributor-friendly history evaluation summary."""
    summary = report["summary"]
    lines = [
        "History Evaluation Summary",
        f"- total cases: {summary['total_cases']}",
        f"- passed cases: {summary['passed_cases']}",
        f"- failed cases: {summary['failed_cases']}",
        f"- fixed classification accuracy: {summary['fixed_accuracy']:.2f}",
        f"- added classification accuracy: {summary['added_accuracy']:.2f}",
        f"- removed classification accuracy: {summary['removed_accuracy']:.2f}",
        f"- changed classification accuracy: {summary['changed_accuracy']:.2f}",
        f"- unchanged classification accuracy: {summary['unchanged_accuracy']:.2f}",
        f"- stable identity match accuracy: {summary['stable_identity_match_accuracy']:.2f}",
        "",
        "History Cases",
    ]

    for case in report["cases"]:
        lines.append(
            f"- {case['case_id']}: passed={'yes' if case['passed'] else 'no'} "
            f"fixed={case['actual_diff']['fixed']} "
            f"added={case['actual_diff']['added']} "
            f"removed={case['actual_diff']['removed']} "
            f"changed={case['actual_diff']['changed']} "
            f"unchanged={case['actual_diff']['unchanged']}"
        )

    failures = [case for case in report["cases"] if not case["passed"]]
    if failures:
        lines.extend(["", "History Failures"])
        for case in failures:
            lines.append(f"- {case['case_id']}: {'; '.join(case['failure_reasons'])}")

    return "\n".join(lines)


def format_full_evaluation_summary(report: Dict[str, Any]) -> str:
    """Render the combined dedup + history evaluation summary."""
    return "\n\n".join(
        [
            format_dedup_evaluation_summary(report["dedup"]),
            format_history_evaluation_summary(report["history"]),
        ]
    )


def main(argv: Sequence[str] | None = None) -> int:
    """Run the dedup and history evaluation datasets and print readable summaries."""
    parser = argparse.ArgumentParser(
        description="Evaluate dedup quality and history stability on the labeled fixture sets."
    )
    parser.add_argument(
        "dedup_dataset",
        nargs="?",
        default=None,
        help="Optional primary dedup dataset path. If omitted, the built-in dedup datasets are used.",
    )
    parser.add_argument(
        "--extra-dedup-dataset",
        action="append",
        default=[],
        help="Additional dedup dataset path(s) to include.",
    )
    parser.add_argument(
        "--history-dataset",
        default=str(DEFAULT_HISTORY_DATASET_PATH),
        help="Path to the history evaluation dataset JSON file.",
    )
    args = parser.parse_args(argv)

    if args.dedup_dataset:
        dedup_paths = [args.dedup_dataset, *args.extra_dedup_dataset]
    else:
        dedup_paths = [*DEFAULT_DEDUP_DATASET_PATHS, *args.extra_dedup_dataset]

    report = evaluate_full_evaluation(
        dedup_paths=dedup_paths,
        history_path=args.history_dataset,
    )
    print(format_full_evaluation_summary(report))
    return 0 if (
        report["dedup"]["summary"]["failed_cases"] == 0
        and report["history"]["summary"]["failed_cases"] == 0
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
