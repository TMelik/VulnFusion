"""Tests for the human-triage annotation core (utils/finding_annotations.py)."""

import pytest

from utils.finding_annotations import (
    HUMAN_TRIAGE_SCOPES,
    HUMAN_TRIAGE_STATUSES,
    annotation_key,
    apply_annotations,
    load_annotations,
    record_annotation,
)
from utils.site_context import site_bundle_key

TARGET = "https://example.com"


def _finding(name="SQL Injection", path="/login", **meta_over):
    meta = {"host": "example.com", "scheme": "https", "port": 443, "path": path,
            "parameter": "user", "method": "POST"}
    meta.update(meta_over)
    return {
        "vulnerability_name": name, "severity": "high",
        "asset_id": f"https://example.com{path}", "description": "d", "remediation": "r",
        "meta": meta,
    }


def _hostless():
    return {"vulnerability_name": "Weak Cipher", "severity": "low", "asset_id": "",
            "description": "", "remediation": "", "meta": {}}


# --- key derivation -------------------------------------------------------

def test_key_derivation_by_scope():
    f = _finding()
    assert annotation_key(f, "finding") == "sql injection::example.com::/login"
    assert annotation_key(f, "site_vuln") == "sql injection::example.com"


def test_key_derivation_is_export_field_only_stable():
    # Different description/remediation must NOT change the key (unlike finding_id).
    a = _finding()
    b = _finding()
    b["description"] = "totally different wording"
    b["remediation"] = "different too"
    assert annotation_key(a, "finding") == annotation_key(b, "finding")


def test_hostless_finding_has_no_site_key_but_has_finding_key():
    f = _hostless()
    assert annotation_key(f, "site_vuln") == ""
    assert annotation_key(f, "finding")  # fp_strict fallback, non-empty


def test_annotation_key_rejects_unknown_scope():
    with pytest.raises(ValueError):
        annotation_key(_finding(), "nonsense")


# --- record / load --------------------------------------------------------

def test_record_and_load_roundtrip(tmp_path):
    entry = record_annotation(tmp_path, TARGET, _finding(), status="false_positive",
                              comment="server-validated", reviewer="alice", scope="finding")
    assert entry["status"] == "false_positive" and entry["revision"] == 1
    loaded = load_annotations(tmp_path, TARGET)
    key = "finding::sql injection::example.com::/login"
    assert list(loaded) == [key]
    assert loaded[key]["comment"] == "server-validated"


def test_annotations_file_is_okf_and_leaves_discovery_untouched(tmp_path):
    record_annotation(tmp_path, TARGET, _finding(), status="confirmed", reviewer="bob")
    bundle = tmp_path / "asset_knowledge" / site_bundle_key(TARGET)
    text = (bundle / "annotations.md").read_text(encoding="utf-8")
    assert text.startswith("---")
    assert "type: Finding Triage" in text
    assert "human:bob" in text
    assert "# Finding Triage Log" in text
    for name in ("index.md", "profile.md", "log.md"):
        assert not (bundle / name).exists()


def test_comment_secret_is_scrubbed_on_write(tmp_path):
    entry = record_annotation(tmp_path, TARGET, _finding(), status="false_positive",
                              comment="ignore token ghp_ABCDEFGHIJKLMNOPQRST here")
    assert "ghp_" not in entry["comment"]
    assert "REDACTED" in entry["comment"]


def test_upsert_bumps_revision_and_preserves_decided_at(tmp_path):
    e1 = record_annotation(tmp_path, TARGET, _finding(), status="needs_review", reviewer="a")
    e2 = record_annotation(tmp_path, TARGET, _finding(), status="false_positive", reviewer="b")
    assert e2["revision"] == 2
    assert e2["decided_at"] == e1["decided_at"]
    assert len(load_annotations(tmp_path, TARGET)) == 1


def test_record_rejects_bad_status_and_scope(tmp_path):
    with pytest.raises(ValueError):
        record_annotation(tmp_path, TARGET, _finding(), status="bogus")
    with pytest.raises(ValueError):
        record_annotation(tmp_path, TARGET, _finding(), status="confirmed", scope="bogus")


def test_site_scope_refused_for_hostless_finding(tmp_path):
    with pytest.raises(ValueError):
        record_annotation(tmp_path, TARGET, _hostless(), status="false_positive", scope="site_vuln")


def test_record_accepts_precomputed_key_for_cli_path(tmp_path):
    entry = record_annotation(tmp_path, TARGET, "sql injection::example.com::/login",
                              status="confirmed", scope="finding")
    assert entry["key"] == "sql injection::example.com::/login"
    with pytest.raises(ValueError):
        record_annotation(tmp_path, TARGET, "loneword", status="confirmed", scope="site_vuln")


def test_load_returns_empty_for_missing_or_malformed(tmp_path):
    assert load_annotations(tmp_path, TARGET) == {}
    bundle = tmp_path / "asset_knowledge" / site_bundle_key(TARGET)
    bundle.mkdir(parents=True)
    (bundle / "annotations.md").write_text("not valid frontmatter", encoding="utf-8")
    assert load_annotations(tmp_path, TARGET) == {}


# --- apply ----------------------------------------------------------------

def test_apply_stamps_matching_finding(tmp_path):
    record_annotation(tmp_path, TARGET, _finding(), status="false_positive", comment="c")
    results = {"target": TARGET, "all_findings": [_finding()]}
    apply_annotations(results, data_dir=tmp_path)
    triage = results["all_findings"][0]["human_triage"]
    assert triage["status"] == "false_positive" and triage["scope"] == "finding"
    assert triage["key"] == "sql injection::example.com::/login"
    assert triage["decided_at"].endswith("Z")


def test_apply_is_noop_without_bundle(tmp_path):
    results = {"target": TARGET, "all_findings": [_finding()]}
    out = apply_annotations(results, data_dir=tmp_path)
    assert "human_triage" not in out["all_findings"][0]


def test_apply_site_scope_matches_across_paths(tmp_path):
    record_annotation(tmp_path, TARGET, _finding(path="/login"), status="not_applicable", scope="site_vuln")
    results = {"target": TARGET, "all_findings": [_finding(path="/search", parameter="q")]}
    apply_annotations(results, data_dir=tmp_path)
    triage = results["all_findings"][0]["human_triage"]
    assert triage["scope"] == "site_vuln" and triage["status"] == "not_applicable"


def test_apply_finding_scope_takes_precedence_over_site(tmp_path):
    record_annotation(tmp_path, TARGET, _finding(path="/login"), status="confirmed", scope="site_vuln")
    record_annotation(tmp_path, TARGET, _finding(path="/login"), status="false_positive", scope="finding")
    results = {"target": TARGET, "all_findings": [_finding(path="/login")]}
    apply_annotations(results, data_dir=tmp_path)
    assert results["all_findings"][0]["human_triage"]["status"] == "false_positive"


def test_apply_covers_changed_and_fixed_lists(tmp_path):
    record_annotation(tmp_path, TARGET, _finding(), status="false_positive")
    results = {"target": TARGET, "all_findings": [],
               "changed_findings": [_finding()], "fixed_findings": [_finding()]}
    apply_annotations(results, data_dir=tmp_path)
    assert results["changed_findings"][0]["human_triage"]["status"] == "false_positive"
    assert results["fixed_findings"][0]["human_triage"]["status"] == "false_positive"


def test_constants_are_shared_and_stable():
    assert HUMAN_TRIAGE_STATUSES == ["confirmed", "false_positive", "not_applicable", "needs_review"]
    assert HUMAN_TRIAGE_SCOPES == ["finding", "site_vuln"]
