"""Evaluate advisory finding analysis against explicit human labels.

The evaluator never calls an LLM.  It consumes an exported VulnFusion result
and a small human-reviewed label file, then writes reproducible aggregate
metrics suitable for the hackathon evidence artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping


EVALUATION_SCHEMA_VERSION = 1
VALID_APPLICABILITY_STATUSES = {
    "likely_false_positive",
    "valid_but_not_applicable",
    "likely_valid",
    "needs_review",
}
REMEDIATION_RUBRIC_FIELDS = ("supported", "actionable", "verifiable")


def _text(value: Any) -> str:
    return " ".join(str(value or "").split()).strip()


def _finding_scanners(finding: Mapping[str, Any]) -> list[str]:
    values: list[str] = []
    found_by = finding.get("found_by")
    if isinstance(found_by, list):
        values.extend(str(item).strip().lower() for item in found_by if str(item).strip())
    meta = finding.get("meta")
    if isinstance(meta, Mapping) and str(meta.get("scanner") or "").strip():
        values.append(str(meta["scanner"]).strip().lower())
    return sorted(set(values))


def _finding_instance_anchors(finding: Mapping[str, Any]) -> Dict[str, Any]:
    """Return public technical anchors that distinguish retained instances."""
    meta = finding.get("meta")
    if not isinstance(meta, Mapping):
        meta = {}
    anchors: Dict[str, Any] = {}
    for key in ("method", "path", "parameter", "port", "service"):
        value = meta.get(key)
        if value not in (None, ""):
            anchors[key] = value
    for key in ("raw_id", "raw_ids", "template_id", "plugin_id", "cve_id", "cve_ids"):
        value = meta.get(key)
        if value in (None, "", []):
            continue
        if isinstance(value, list):
            anchors[key] = sorted({_text(item) for item in value if _text(item)})
        else:
            anchors[key] = _text(value)
    return anchors


def finding_evaluation_key(finding: Mapping[str, Any]) -> str:
    """Return a stable public-output key for matching one labeled finding."""
    payload = {
        "vulnerability_name": _text(finding.get("vulnerability_name")).lower(),
        "asset_id": _text(finding.get("asset_id")).lower(),
        "scanners": _finding_scanners(finding),
        "instance_anchors": _finding_instance_anchors(finding),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:20]


def build_label_template(results: Mapping[str, Any]) -> Dict[str, Any]:
    """Create a human-fillable label template from exported scan results."""
    findings = results.get("all_findings")
    if not isinstance(findings, list):
        findings = []
    cases = []
    seen_keys: set[str] = set()
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        finding_key = finding_evaluation_key(finding)
        if finding_key in seen_keys:
            raise ValueError(
                "Evaluation results contain findings that are indistinguishable by public instance anchors"
            )
        seen_keys.add(finding_key)
        cases.append(
            {
                "finding_key": finding_key,
                "vulnerability_name": _text(finding.get("vulnerability_name")),
                "asset_id": _text(finding.get("asset_id")),
                "instance_anchors": _finding_instance_anchors(finding),
                "expected_applicability_status": None,
                "remediation_review": {
                    "supported": None,
                    "actionable": None,
                    "verifiable": None,
                },
                "notes": "",
            }
        )
    cases.sort(key=lambda item: (item["vulnerability_name"].lower(), item["asset_id"], item["finding_key"]))
    return {"version": EVALUATION_SCHEMA_VERSION, "cases": cases}


def _validate_labels(labels: Mapping[str, Any]) -> list[Dict[str, Any]]:
    if labels.get("version") != EVALUATION_SCHEMA_VERSION:
        raise ValueError(f"AI evaluation labels require version {EVALUATION_SCHEMA_VERSION}")
    cases = labels.get("cases")
    if not isinstance(cases, list):
        raise ValueError("AI evaluation labels field 'cases' must be an array")
    validated: list[Dict[str, Any]] = []
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if not isinstance(case, dict):
            raise ValueError(f"AI evaluation labels case {index} must be an object")
        key = _text(case.get("finding_key"))
        expected = case.get("expected_applicability_status")
        if not key or key in seen:
            raise ValueError(f"AI evaluation labels case {index} has a missing or duplicate finding_key")
        if expected not in VALID_APPLICABILITY_STATUSES:
            raise ValueError(
                f"AI evaluation labels case {index} has invalid expected_applicability_status"
            )
        review = case.get("remediation_review")
        if not isinstance(review, dict):
            raise ValueError(f"AI evaluation labels case {index} requires remediation_review")
        for field in REMEDIATION_RUBRIC_FIELDS:
            value = review.get(field)
            if value is not None and type(value) is not bool:
                raise ValueError(
                    f"AI evaluation labels case {index} remediation_review.{field} must be bool or null"
                )
        seen.add(key)
        validated.append(case)
    return validated


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _analysis_run_provenance(results: Mapping[str, Any]) -> Dict[str, Any]:
    """Copy only reproducibility-safe run fields from the exported summary."""
    summary = results.get("ai_analysis_summary")
    if not isinstance(summary, Mapping):
        summary = {}
    provenance: Dict[str, Any] = {}
    for key in ("status", "model", "prompt_version"):
        value = _text(summary.get(key))
        if value:
            provenance[key] = value
    for key in (
        "limit", "selected_count", "analyzed_count", "cached_count",
        "unavailable_count", "skipped_limit_count", "prompt_tokens",
        "completion_tokens", "total_tokens", "redaction_count",
    ):
        value = summary.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            provenance[key] = value
    for key in ("latency_ms", "estimated_cost_usd"):
        value = summary.get(key)
        if value is None or (isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0):
            provenance[key] = value
    asset_knowledge = results.get("asset_knowledge")
    if isinstance(asset_knowledge, Mapping):
        revision = _text(asset_knowledge.get("profile_revision"))
        if revision:
            provenance["context_revision"] = revision
    return provenance


def evaluate_ai_analysis(
    results: Mapping[str, Any],
    labels: Mapping[str, Any],
    *,
    generated_at: str | None = None,
) -> Dict[str, Any]:
    """Return measured applicability and remediation-review metrics."""
    cases = _validate_labels(labels)
    findings = results.get("all_findings")
    if not isinstance(findings, list):
        findings = []
    finding_index: Dict[str, Mapping[str, Any]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        key = finding_evaluation_key(finding)
        if key in finding_index:
            raise ValueError(
                "Evaluation results contain findings that are indistinguishable by public instance anchors"
            )
        finding_index[key] = finding

    matched = 0
    analyzed = 0
    correct = 0
    needs_review = 0
    unavailable = 0
    skipped_limit = 0
    predicted_false_positive_wrong = 0
    confusion: Counter[str] = Counter()
    rubric_totals = {field: 0 for field in REMEDIATION_RUBRIC_FIELDS}
    rubric_passes = {field: 0 for field in REMEDIATION_RUBRIC_FIELDS}
    case_results = []

    for label in cases:
        key = str(label["finding_key"])
        finding = finding_index.get(key)
        if finding is None:
            case_results.append({"finding_key": key, "matched": False})
            continue
        matched += 1
        analysis_status = str(finding.get("ai_analysis_status") or "missing")
        if analysis_status == "unavailable":
            unavailable += 1
        if analysis_status == "skipped_limit":
            skipped_limit += 1
        applicability = finding.get("applicability")
        predicted = applicability.get("status") if isinstance(applicability, Mapping) else None
        expected = label["expected_applicability_status"]
        agreement = False
        if analysis_status in {"completed", "cached"} and predicted in VALID_APPLICABILITY_STATUSES:
            analyzed += 1
            agreement = predicted == expected
            correct += int(agreement)
            needs_review += int(predicted == "needs_review")
            confusion[f"{expected}->{predicted}"] += 1
            if predicted == "likely_false_positive" and expected != "likely_false_positive":
                predicted_false_positive_wrong += 1

        remediation = finding.get("ai_remediation")
        if analysis_status in {"completed", "cached"} and isinstance(remediation, Mapping):
            review = label.get("remediation_review") or {}
            for field in REMEDIATION_RUBRIC_FIELDS:
                value = review.get(field)
                if isinstance(value, bool):
                    rubric_totals[field] += 1
                    rubric_passes[field] += int(value)

        case_results.append(
            {
                "finding_key": key,
                "matched": True,
                "ai_analysis_status": analysis_status,
                "expected_applicability_status": expected,
                "predicted_applicability_status": predicted,
                "agreement": agreement if predicted is not None else None,
            }
        )

    timestamp = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return {
        "schema_version": EVALUATION_SCHEMA_VERSION,
        "generated_at": timestamp,
        "source_target": _text(results.get("target")),
        "source_generated_at": _text(results.get("generated_at") or results.get("timestamp")),
        "analysis_run": _analysis_run_provenance(results),
        "metrics": {
            "labeled_cases": len(cases),
            "matched_cases": matched,
            "analyzed_cases": analyzed,
            "match_rate": _ratio(matched, len(cases)),
            "analysis_coverage": _ratio(analyzed, matched),
            "applicability_agreement": _ratio(correct, analyzed),
            "needs_review_rate": _ratio(needs_review, analyzed),
            "unavailable_count": unavailable,
            "skipped_limit_count": skipped_limit,
            "wrong_false_positive_decisions": predicted_false_positive_wrong,
            "remediation_supported_rate": _ratio(rubric_passes["supported"], rubric_totals["supported"]),
            "remediation_actionable_rate": _ratio(rubric_passes["actionable"], rubric_totals["actionable"]),
            "remediation_verifiable_rate": _ratio(rubric_passes["verifiable"], rubric_totals["verifiable"]),
        },
        "confusion": dict(sorted(confusion.items())),
        "cases": case_results,
    }


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate VulnFusion AI advice against human labels")
    parser.add_argument("--results", required=True, type=Path, help="Exported normalized.json")
    parser.add_argument("--labels", type=Path, help="Human-reviewed label JSON")
    parser.add_argument("--output", type=Path, help="Where to write measured evaluation JSON")
    parser.add_argument(
        "--write-label-template",
        type=Path,
        help="Write a label template for --results and exit without evaluation",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    results = _read_json(args.results)
    if args.write_label_template:
        _write_json(args.write_label_template, build_label_template(results))
        print(f"AI label template written: {args.write_label_template}")
        return 0
    if args.labels is None:
        parser.error("--labels is required unless --write-label-template is used")
    labels = _read_json(args.labels)
    evaluation = evaluate_ai_analysis(results, labels)
    output = args.output or args.results.with_name("ai_evaluation.json")
    _write_json(output, evaluation)
    print(f"AI evaluation written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
