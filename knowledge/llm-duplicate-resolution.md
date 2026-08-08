---
type: Pipeline Stage
title: LLM Duplicate Resolution
description: Cross-scanner duplicate finding resolution using a cheap pre-filter plus a strict structured LLM decision.
resource: utils/llm_duplicate_resolver.py
tags: [vulnfusion, llm, dedupe]
status: stable
generated:
  by: claude/sonnet-5
  at: 2026-08-08
---

# LLM Duplicate Resolution

This is the active duplicate-handling path in the pipeline (see
[/pipeline.md](/pipeline.md)); the older fingerprint-based
`utils/deduplicator.py` still exists but is not called from the normal CLI
flow (`--duplicate-mode off` disables this stage entirely).

## Flow

1. Same-target candidates are found using normalized finding fields already
   present in the schema: `host`, `scheme`, `port`, `path`, `query_keys`,
   `parameter` (see [/schema.md](/schema.md)).
2. A cheap pre-LLM filter checks overlap (shared CVE/CWE identifiers,
   normalized title similarity) before spending an API call.
3. Only pairs that pass the filter are sent to the configured LLM endpoint.
   The provider must return one strict JSON object with
   `same_vulnerability`, `confidence`, `reason`, and `canonical_title`.
   A Markdown `json` fence is the only permitted wrapper.
4. Decisions are cached in
   [/unified-vulnerability-db.md](/unified-vulnerability-db.md) (disable
   with `--no-llm-cache`).
5. A pair merges only when `same_vulnerability=true` and confidence is at
   least `0.85`. Lower-confidence positive decisions remain separate and are
   exposed as review candidates.
6. Merged findings preserve `source_findings` provenance. Internal comparison
   traces are not exported; the safe structured result is exported as
   `correlation`. `canonical_title` is an AI recommendation and never replaces
   the scanner-derived `vulnerability_name`.

The benchmark and product-evidence plan for this stage is documented in
[/llm-effectiveness-evidence.md](/llm-effectiveness-evidence.md).

## Configuration

Generic OpenAI-compatible chat-completions contract:
`VULN_MANAGER_LLM_API_URL`, `VULN_MANAGER_LLM_API_KEY`,
`VULN_MANAGER_LLM_MODEL` (env or `--llm-api-url` / `--llm-api-key` /
`--llm-model`). `--llm-timeout` (default 15s). Healthcheck script:
`scripts/test_llm_provider.py`.
