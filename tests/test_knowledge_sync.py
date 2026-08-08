import json

import yaml

from utils.knowledge_sync import (
    load_csv_records,
    load_json_records,
    load_jsonl_records,
    load_xml_records,
    sync_findings_to_knowledge_db,
)
from utils.unified_vuln_db import UnifiedVulnerabilityDatabase


def _finding(scanner: str, *, title: str = "SQL Injection", description: str = "desc", raw_id: str = "template-1") -> dict:
    meta = {
        "scanner": scanner,
        "timestamp": "2026-04-09T12:00:00Z",
        "host": "example.com",
        "scheme": "https",
        "path": "/login",
        "port": 443,
        "query_keys": ["q"],
        "parameter": "q",
        "references": ["https://example.com/reference"],
        "cve_ids": ["CVE-2024-1111"],
    }
    if scanner == "nuclei":
        meta["template_id"] = raw_id
        meta["raw_id"] = raw_id
        meta["tags"] = ["injection"]
    elif scanner == "zap":
        meta["plugin_id"] = raw_id
        meta["cwe"] = "CWE-89"
    elif scanner == "wapiti":
        meta["category"] = "SQL Injection"
        meta["module"] = "sql"
    elif scanner == "nikto":
        meta["osvdb_id"] = raw_id
    elif scanner == "nmap":
        meta["raw_id"] = raw_id
        meta["cve_id"] = "CVE-2024-1111"
        meta["service"] = "http"

    return {
        "vulnerability_name": title,
        "severity": "high",
        "asset_id": "https://example.com/login?q=test",
        "description": description,
        "remediation": "Fix it.",
        "meta": meta,
    }


def test_unified_vulnerability_db_sync_is_idempotent_and_updates_changed_records(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    finding = _finding("nuclei", description="Initial description", raw_id="nuclei-sqli")

    first = sync_findings_to_knowledge_db([finding], database, sync_timestamp="2026-04-09T12:00:00Z")
    second = sync_findings_to_knowledge_db([finding], database, sync_timestamp="2026-04-09T12:05:00Z")

    updated_finding = _finding("nuclei", description="Updated description", raw_id="nuclei-sqli")
    third = sync_findings_to_knowledge_db([updated_finding], database, sync_timestamp="2026-04-09T12:10:00Z")

    assert first["total_imported"] == 1
    assert first["total_updated"] == 0
    assert first["total_skipped"] == 0

    assert second["total_imported"] == 0
    assert second["total_updated"] == 0
    assert second["total_skipped"] == 1

    assert third["total_imported"] == 0
    assert third["total_updated"] == 1
    assert third["total_skipped"] == 0

    records = database.list_knowledge_records(scanner_name="nuclei")
    assert len(records) == 1
    assert records[0]["source_vulnerability_id"] == "nuclei-sqli"
    assert records[0]["description"] == "Updated description"
    assert records[0]["last_synced_timestamp"] == "2026-04-09T12:10:00Z"

    sync_runs = database.list_sync_runs()
    assert [run["total_imported"] for run in sync_runs] == [1, 0, 0]
    assert [run["total_skipped"] for run in sync_runs] == [0, 1, 0]
    assert [run["total_updated"] for run in sync_runs] == [0, 0, 1]


def test_sync_uses_source_findings_from_merged_records(tmp_path):
    database = UnifiedVulnerabilityDatabase(tmp_path / "knowledge.yaml")
    merged = {
        "vulnerability_name": "SQL Injection",
        "severity": "high",
        "asset_id": "https://example.com/login?q=test",
        "description": "merged",
        "remediation": "fix",
        "meta": {"scanner": "zap"},
        "source_findings": [
            _finding("zap", raw_id="40018"),
            _finding("nuclei", raw_id="nuclei-sqli"),
        ],
    }

    stats = sync_findings_to_knowledge_db([merged], database, sync_timestamp="2026-04-09T12:00:00Z")

    assert stats["by_scanner"]["zap"]["total_imported"] == 1
    assert stats["by_scanner"]["nuclei"]["total_imported"] == 1
    assert len(database.list_knowledge_records()) == 2


def test_yaml_store_persists_human_readable_sections(tmp_path):
    db_path = tmp_path / "knowledge.yaml"
    database = UnifiedVulnerabilityDatabase(db_path)

    sync_findings_to_knowledge_db(
        [_finding("nuclei", raw_id="nuclei-sqli")],
        database,
        sync_timestamp="2026-04-09T12:00:00Z",
    )
    database.save_llm_comparison(
        {
            "cache_key": "cache-1",
            "pair_key": "finding-a::finding-b",
            "compared_finding_a_id": "finding-a",
            "compared_finding_b_id": "finding-b",
            "same_target": True,
            "comparison_status": "cached",
            "cheap_filter_decision": "passed_shared_cve",
            "llm_decision": "yes",
            "compared_at": "2026-04-09T12:00:00Z",
            "model_name": "llama-3.3-70b-versatile",
            "request_hash": "hash-1",
            "raw_response": None,
            "error_message": None,
            "provider_failure_category": None,
            "http_status_code": None,
            "final_merge_result": "merged",
            "merged_finding_id": "cluster-1",
            "response_payload": {
                "choices": [
                    {"message": {"content": "yes"}}
                ]
            },
        }
    )

    payload = yaml.safe_load(db_path.read_text(encoding="utf-8"))

    assert payload["version"] == 1
    assert isinstance(payload["vulnerability_knowledge"], list)
    assert isinstance(payload["knowledge_sync_runs"], list)
    assert isinstance(payload["llm_duplicate_comparisons"], list)
    assert payload["vulnerability_knowledge"][0]["scanner_name"] == "nuclei"
    assert payload["llm_duplicate_comparisons"][0]["response_payload"]["choices"][0]["message"]["content"] == "yes"


def test_generic_source_loaders_support_json_jsonl_csv_and_xml(tmp_path):
    json_path = tmp_path / "records.json"
    json_path.write_text(json.dumps([{"id": "json-1", "title": "one"}]), encoding="utf-8")

    jsonl_path = tmp_path / "records.jsonl"
    jsonl_path.write_text('{"id":"jsonl-1","title":"two"}\n', encoding="utf-8")

    csv_path = tmp_path / "records.csv"
    csv_path.write_text("id,title\ncsv-1,three\n", encoding="utf-8")

    xml_path = tmp_path / "records.xml"
    xml_path.write_text("<root><record><id>xml-1</id><title>four</title></record></root>", encoding="utf-8")

    assert load_json_records(json_path) == [{"id": "json-1", "title": "one"}]
    assert load_jsonl_records(jsonl_path) == [{"id": "jsonl-1", "title": "two"}]
    assert load_csv_records(csv_path) == [{"id": "csv-1", "title": "three"}]
    assert load_xml_records(xml_path) == [{"id": "xml-1", "title": "four"}]
