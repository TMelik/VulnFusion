# VulnFusion Pipeline Walkthrough

## What the normal run does

VulnFusion keeps scanner evidence as the source of truth, then adds two clearly
separated layers:

- deterministic correlation and risk prioritization;
- advisory LLM applicability, summary, priority, and remediation guidance.

The LLM cannot delete a finding, replace scanner evidence, or change
`risk_score`/`priority`.

```text
optional bounded context discovery/reuse
  -> scan or offline ZAP import
  -> normalize
  -> structured LLM duplicate resolution
  -> optional history comparison
  -> manual + confirmed site context
  -> deterministic risk scoring
  -> structured advisory LLM analysis
  -> sanitize / validate / save / HTML report
```

## 1. Optional pre-scan site context

`--discover-context` performs a small, fail-open discovery before scanners run:

- at most three same-site HTML pages;
- allowlisted HTTP metadata from those responses;
- DNS A/AAAA addresses without reverse lookups;
- allowlisted TLS certificate and connection metadata for HTTPS.

There is no search API, ASN lookup, or deep crawl. The configured LLM receives
bounded, secret-sanitized evidence and returns a strict description, business
processes, citations, uncertainties, and a proposed `risk_context`. If the LLM
is unavailable, page metadata supplies a visible fallback instead of stopping
the scan.

The CLI displays both the description and the risk proposal. Only after the
user confirms them does VulnFusion write a site-specific OKF bundle under
`data/asset_knowledge/<site-key>/`. Each bundle has a current `profile.md`, an
append-only log, and immutable `revisions/<sha256>.md` snapshots. A non-stale,
human-confirmed profile is reused automatically on later scans; use
`--no-context-reuse` to disable reuse or `--discover-context` to refresh it.

Confirmed context may affect deterministic business-risk inputs. Unknown or
unconfirmed proposals do not. Site context never changes duplicate identity:
correlation still depends on technical instance anchors such as path,
parameter, method, port/service, CVE, and scanner identity.

The local web workflow (`python main.py --ui`) persists project settings in the
same per-site bundle. New or stale projects pause at the context review before
launching the selected scanner checkboxes; Safe and Full presets are available.

## 2. Scanning and normalization

The selected scanners produce native output, and their normalizers convert it
to the shared finding schema. For a conservative demo:

```bash
uv run python main.py --target https://example.com --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml
```

The polite profile runs bounded Nmap/Nuclei checks. ZAP stays off unless the
operator chooses one explicit route:

- `--with-zap` enables the conservative passive ZAP template; adding
  `--zap-active-scan` is an explicit active-scan decision;
- `--zap-report report.json` imports an existing ZAP Traditional JSON report
  without starting another ZAP run.

`--with-zap` and `--zap-report` are mutually exclusive.

## 3. Correlation, comparison, and risk

Structured duplicate resolution merges only a positive decision with
confidence at least `0.85`. Low-confidence positive pairs remain separate and
become review candidates. Invalid output, timeout, or provider failure means no
merge. The exported `correlation` object exposes safe structured decisions;
the scanner-native `vulnerability_name` remains unchanged.

When `--compare` is enabled, history labels findings as new, persistent,
changed, or fixed. Optional `--asset-context-file` rules and human-confirmed
site context are then applied before the deterministic risk scorer creates:

- `risk_score` (`0`-`100`);
- `priority` (`P0`-`P4`);
- `risk_factors`;
- `risk_rationale`.

## 4. Advisory finding analysis

When the same LLM provider is configured, VulnFusion automatically analyzes
the highest-priority final findings, up to 25 by default. Override the cap with
`--ai-analysis-limit`; disable this layer with `--no-ai-analysis`.

The strict response adds:

- `applicability.status`, `confidence`, `reason`, and cited `evidence_ids`;
- `ai_priority.recommended_priority`, confidence, rationale, cited evidence,
  and the confirmed context revision;
- `ai_summary.description`, business impact, and cited evidence;
- `ai_remediation.steps` and `verification`.

Decisions are cached by finding evidence, model, prompt/schema semantics, and
confirmed context revision. Findings beyond the cap are marked
`skipped_limit`; malformed responses and provider failures are marked
`unavailable`. In every case, the original finding and deterministic risk
remain visible.

The run writes sanitized AI totals to `ai_analysis_metrics.json`: analyzed,
cached, review, unavailable and skipped counts, redactions, latency, tokens,
and estimated cost when pricing variables are configured.

## 5. Export and report

Before saving, `utils/export_sanitizer.py` removes internal/debug fields and
strictly allowlists public site-context, correlation, and AI-advice objects.
`utils/schema.py` validates the result, which is written to `normalized.json`
and rendered as `report.html`.

Utility flows such as `--probe-only` and `--list-scanners` exit before the
save/report stage.

The report deliberately separates:

- scanner-derived description, evidence, and remediation;
- deterministic correlation and risk;
- advisory applicability, remediation, verification, limitations, and run
  diagnostics.

This makes failure visible instead of silently hiding a result.

## Evaluation

Create human labels and evaluate without making another LLM call:

```bash
uv run python -m utils.ai_evaluation \
  --results data/example/latest/normalized.json \
  --write-label-template evaluation/labels.json

uv run python -m utils.ai_evaluation \
  --results data/example/latest/normalized.json \
  --labels evaluation/labels.json \
  --output evaluation/ai_evaluation.json
```

The artifact reports applicability agreement/coverage, review and failure
counts, wrong false-positive decisions, and human ratings for whether suggested
remediation is supported, actionable, and verifiable.

## Authoritative implementation files

- `main.py`
- `utils/site_context.py`
- `utils/llm_duplicate_resolver.py`
- `utils/risk_scorer.py`
- `utils/llm_finding_analyzer.py`
- `utils/export_sanitizer.py`
- `utils/schema.py`
- `utils/report_generator.py`
- `utils/ai_evaluation.py`
