"""
Helpers for exporting finalized vuln-manager results to DefectDojo's
Generic Findings Import JSON format.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from utils.normalizer import normalize_vulnerability_name, parse_target


_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
}


def build_defectdojo_generic_report(results: dict) -> dict:
    """Return a DefectDojo Generic Findings Import payload."""
    findings = results.get("all_findings")
    if not isinstance(findings, list):
        findings = []

    target = str(results.get("target") or "unknown target").strip() or "unknown target"
    generated_at = str(results.get("generated_at") or results.get("timestamp") or "unknown time").strip() or "unknown time"
    report_date = _normalize_finding_date(generated_at) or ""

    return {
        "name": f"Vuln Manager findings for {target} at {generated_at}",
        "findings": [
            _build_defectdojo_finding(finding, report_date=report_date)
            for finding in findings
            if isinstance(finding, dict)
        ],
    }


def write_defectdojo_generic_report(results: dict, output_path: Path) -> Path:
    """Write one DefectDojo Generic Findings Import JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    report = build_defectdojo_generic_report(results)
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
    return output_path


def _build_defectdojo_finding(finding: dict[str, Any], *, report_date: str) -> dict[str, Any]:
    meta = finding.get("meta") if isinstance(finding.get("meta"), dict) else {}

    description = _scanner_description(finding)
    mitigation = _scanner_mitigation(finding)
    tags = _build_tags(finding, meta)
    references = _collect_references(finding, meta)
    endpoints = _build_endpoints(finding, meta)
    impact = _build_impact(finding)
    severity_justification = _clean_text(finding.get("risk_rationale"))
    cwe = _parse_cwe(meta.get("cwe"))
    cve = _extract_cve(meta)
    finding_date = _normalize_finding_date(meta.get("timestamp"))

    if not finding_date:
        finding_date = report_date

    payload: dict[str, Any] = {
        "title": _clean_text(finding.get("vulnerability_name")) or "Unnamed vulnerability",
        "severity": _map_severity(finding.get("severity")),
        "description": description,
        "mitigation": mitigation,
        "date": finding_date or "",
    }

    if cwe is not None:
        payload["cwe"] = cwe
    if cve:
        payload["cve"] = cve
    if severity_justification:
        payload["severity_justification"] = severity_justification
    if impact:
        payload["impact"] = impact
    if tags:
        payload["tags"] = tags
    payload["unique_id_from_tool"] = _build_unique_id_from_tool(finding, meta, cve=cve, cwe=cwe)
    if references:
        payload["references"] = references
    if endpoints:
        payload["endpoints"] = endpoints
        payload["static_finding"] = False
        payload["dynamic_finding"] = True

    return payload


def _scanner_description(finding: dict[str, Any]) -> str:
    description = _clean_text(finding.get("description"))
    if description:
        return description

    asset_id = _clean_text(finding.get("asset_id")) or "unknown asset"
    return f"No scanner description was provided. Affected asset: {asset_id}."


def _scanner_mitigation(finding: dict[str, Any]) -> str:
    mitigation = _clean_text(finding.get("remediation"))
    if mitigation:
        return mitigation
    return "No scanner remediation was provided."


def _map_severity(value: Any) -> str:
    key = str(value or "").strip().lower()
    return _SEVERITY_MAP.get(key, "Info")


def _normalize_finding_date(value: Any) -> str | None:
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not text:
        return None

    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        return text

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        match = re.match(r"(\d{4}-\d{2}-\d{2})", text)
        return match.group(1) if match else None
    return parsed.date().isoformat()


def _parse_cwe(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str):
        match = re.search(r"(\d+)", value)
        if match:
            return int(match.group(1))
    return None


def _extract_cve(meta: dict[str, Any]) -> str | None:
    primary = _clean_text(meta.get("cve_id"))
    if primary:
        return primary

    cve_ids = meta.get("cve_ids")
    if isinstance(cve_ids, list):
        for item in cve_ids:
            candidate = _clean_text(item)
            if candidate:
                return candidate
    return None


def _build_impact(finding: dict[str, Any]) -> str | None:
    risk_score = finding.get("risk_score")
    risk_factors = finding.get("risk_factors") if isinstance(finding.get("risk_factors"), dict) else {}
    priority = _clean_text(finding.get("priority")) or _clean_text(risk_factors.get("final_priority"))
    rationale = _clean_text(finding.get("risk_rationale"))

    score_value = risk_score
    if score_value is None:
        score_value = risk_factors.get("final_score")

    lines: list[str] = []
    if isinstance(score_value, (int, float)) and not isinstance(score_value, bool):
        score_text = int(score_value) if float(score_value).is_integer() else score_value
        lines.append(f"Risk score: {score_text}")
    if priority:
        lines.append(f"Priority: {priority}")
    if rationale:
        lines.append(f"Rationale: {rationale}")
    if not lines:
        return None
    return "\n".join(lines)


def _build_tags(finding: dict[str, Any], meta: dict[str, Any]) -> list[str]:
    tags: set[str] = {"source:vuln-manager"}

    found_by = finding.get("found_by")
    if isinstance(found_by, list):
        for scanner in found_by:
            name = _clean_text(scanner)
            if name:
                tags.add(f"scanner:{name.lower()}")
    else:
        scanner = _clean_text(meta.get("scanner"))
        if scanner:
            tags.add(f"scanner:{scanner.lower()}")

    priority = _clean_text(finding.get("priority"))
    if priority:
        tags.add(f"priority:{priority}")

    status = _clean_text(finding.get("status"))
    if status:
        tags.add(f"status:{status}")

    return sorted(tags)


def _collect_references(finding: dict[str, Any], meta: dict[str, Any]) -> str | None:
    merged: list[str] = []
    seen: set[str] = set()

    for value in _iter_reference_values(meta.get("references")):
        if value not in seen:
            seen.add(value)
            merged.append(value)

    for value in _iter_reference_values(finding.get("references")):
        if value not in seen:
            seen.add(value)
            merged.append(value)

    source_findings = finding.get("source_findings")
    if isinstance(source_findings, list):
        for source in source_findings:
            if not isinstance(source, dict):
                continue
            for value in _iter_reference_values(source.get("references")):
                if value not in seen:
                    seen.add(value)
                    merged.append(value)

    if not merged:
        return None
    return "\n".join(merged)


def _iter_reference_values(value: Any) -> list[str]:
    if isinstance(value, list):
        return [text for item in value if (text := _clean_text(item))]
    if isinstance(value, str):
        cleaned = _clean_text(value)
        return [cleaned] if cleaned else []
    return []


def _build_endpoints(finding: dict[str, Any], meta: dict[str, Any]) -> list[Any]:
    asset_id = _clean_text(finding.get("asset_id"))
    if asset_id and "://" in asset_id:
        return [asset_id]

    host = _clean_text(meta.get("host"))
    if not host and asset_id and "://" not in asset_id:
        parsed_asset = parse_target(asset_id)
        host = _clean_text(parsed_asset.get("host"))
        if host == asset_id:
            host = ""
    if not host:
        return []

    endpoint: dict[str, Any] = {"host": host}

    port = meta.get("port")
    if isinstance(port, int) and not isinstance(port, bool):
        endpoint["port"] = port

    path = _clean_text(meta.get("path"))
    if path:
        endpoint["path"] = path

    protocol = _clean_text(meta.get("protocol")) or _clean_text(meta.get("scheme"))
    if protocol:
        endpoint["protocol"] = protocol

    return [endpoint]


def _build_unique_id_from_tool(
    finding: dict[str, Any],
    meta: dict[str, Any],
    *,
    cve: str | None,
    cwe: int | None,
) -> str:
    parsed_asset = parse_target(_clean_text(finding.get("asset_id")) or "")

    identity = {
        "asset_id": _clean_text(finding.get("asset_id")) or "",
        "cve": cve or "",
        "cwe": str(cwe or ""),
        "host": _clean_text(meta.get("host")) or _clean_text(parsed_asset.get("host")) or "",
        "method": (_clean_text(meta.get("method")) or "").upper(),
        "name": normalize_vulnerability_name(_clean_text(finding.get("vulnerability_name")) or ""),
        "parameter": _clean_text(meta.get("parameter")) or _clean_text(parsed_asset.get("parameter")) or "",
        "path": _clean_text(meta.get("path")) or _clean_text(parsed_asset.get("path")) or "",
        "port": str(meta.get("port") if isinstance(meta.get("port"), int) else parsed_asset.get("port") or ""),
        "query_keys": ",".join(_sorted_query_keys(meta, parsed_asset)),
    }
    encoded = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    return f"vm-{digest}"


def _sorted_query_keys(meta: dict[str, Any], parsed_asset: dict[str, Any]) -> list[str]:
    query_keys = meta.get("query_keys")
    if isinstance(query_keys, list):
        return sorted(str(item) for item in query_keys if str(item).strip())
    query = parsed_asset.get("query")
    if isinstance(query, dict):
        return sorted(str(key) for key in query if str(key).strip())
    return []


def _clean_text(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text or None
