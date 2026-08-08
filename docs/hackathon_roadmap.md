# Hackathon Roadmap — Safe AI Triage for Armenian Public-Interest Systems

## The claim

Armenia is expanding digital services while cybersecurity expertise is scarce.
Public-interest organizations still need specialist judgment, but specialists
should not spend most of their time manually reconciling overlapping scanner
output.

Public evidence for the local need:

- the [USAID Armenia Digital Ecosystem Country Assessment](https://web.archive.org/web/20241228070807if_/https://www.usaid.gov/sites/default/files/2024-07/USAID_DECA_Armenia.pdf)
  describes a mismatch between cybersecurity needs and available expertise;
- Armenia's official [Law on Cybersecurity](https://hightech.gov.am/articles/laws/%D5%AF%D5%AB%D5%A2%D5%A5%D5%BC%D5%A1%D5%B6%D5%BE%D5%BF%D5%A1%D5%B6%D5%A3%D5%B8%D6%82%D5%A9%D5%B5%D5%A1%D5%B6-%D5%B4%D5%A1%D5%BD%D5%AB%D5%B6-%D6%85%D6%80%D5%A5%D5%B6%D6%84)
  establishes the importance of vital sectors and critical information
  infrastructure;
- the official [Cybersecurity Hackathon announcement](https://old.hightech.gov.am/en/tegekatvakan-kentron/ayl/norutyunner/cybersecurity-hackathon)
  calls for stronger specialist capacity and cooperation;
- CyberHUB-AM's public [2024](https://mdi.am/en/archives/2183) and
  [2025](https://mdi.am/en/archives/42043) reports show the changing local
  threat environment.

These sources prove public need, not product effectiveness. VulnFusion's
narrower claim must be measured:

> VulnFusion helps a human turn overlapping scanner evidence into a safe,
> reviewable report faster, while preserving known vulnerabilities and making
> uncertainty visible.

VulnFusion assists security engineers. It does not replace them, prove
exploitability, protect all critical infrastructure, or solve most business
risk by itself.

## Why this is more than one prompt

A prompt such as “deduplicate and prioritize these findings” has no reliable
input contract, stable identity rules, conservative merge threshold, cache,
schema validation, failure handling, or reproducible evaluation. VulnFusion
wraps the LLM in a working system:

1. multiple scanners collect and normalize evidence;
2. deterministic gates select plausible duplicate pairs;
3. a strict LLM decision merges only at confidence `>= 0.85` and escalates
   ambiguity;
4. deterministic scoring remains authoritative;
5. separate structured AI advice is bounded, cited, cached, sanitized, and
   fail-open;
6. JSON/HTML outputs preserve sources and expose limitations and metrics.

## Implemented demo path

### Safe pre-scan context

`--discover-context` now collects a bounded public profile before scanning:

- no more than three same-site HTML pages;
- allowlisted HTTP response metadata;
- DNS A/AAAA results without reverse lookup;
- allowlisted TLS certificate/connection metadata;
- one strict LLM summary with source IDs, business processes, uncertainties,
  and a proposed risk context.

Discovery is fail-open. Without a configured/available LLM, page metadata is
shown as a fallback. DNS or TLS failure becomes an uncertainty, not a scan
failure. There is no broad search API, ASN enrichment, or deep crawler.

The user confirms the description and risk proposal together. Confirmation
creates an independent OKF v0.2 bundle under
`data/asset_knowledge/<site-key>/` with:

- current `profile.md`;
- immutable `revisions/<revision>.md` files;
- append-only verification/update log;
- human reviewer, sources, freshness date, and profile revision.

Fresh confirmed profiles are reused automatically. `--no-context-reuse`
disables reuse; `--discover-context` refreshes it. Different hosts and
non-default services remain isolated. Confirmed context can affect the
deterministic business-risk inputs, but never duplicate identity.

### Conservative correlation

The provider must return one strict structured decision with
`same_vulnerability`, `confidence`, `reason`, and `canonical_title`.

- positive + confidence `>= 0.85`: merge;
- positive + lower confidence: keep separate and mark for review;
- negative, malformed, timeout, or provider failure: do not merge.

Technical instance anchors remain mandatory: endpoint/path, parameter, method,
port/service, CVE, or scanner identity. `canonical_title` is advisory and does
not overwrite `vulnerability_name`.

### Advisory applicability and remediation

When the provider is configured, final findings are automatically analyzed in
deterministic priority order. The default live-call cap is the top 10 findings;
use `--ai-analysis-limit` to change it or `--no-ai-analysis` to disable the
stage.

The strict public fields are:

```json
{
  "ai_analysis_status": "completed",
  "applicability": {
    "status": "likely_valid",
    "confidence": 0.88,
    "reason": "Scanner evidence identifies the affected parameter.",
    "evidence_ids": ["finding-anchors", "finding-evidence"]
  },
  "ai_remediation": {
    "steps": ["Use parameterized database queries."],
    "verification": ["Repeat the request with the controlled test corpus."]
  }
}
```

The analyzer receives only bounded, secret-sanitized evidence. Its cache key
includes evidence, model, prompt/schema semantics, and confirmed context
revision. Provider or parser failure sets `unavailable`; findings beyond the
cap get `skipped_limit`. Neither state removes a finding or changes its score.

### Rate-conscious scanning and ZAP choices

`configs/examples/polite_demo_config.yaml` keeps the default public demo to
bounded Nmap plus Nuclei at 5 requests/second with low concurrency and no
retry. ZAP is disabled until explicitly requested:

- `--with-zap` enables a 120-second passive-only template with one low-thread
  traditional spider and no form processing;
- `--zap-active-scan` is a separate explicit active-scan decision;
- `--zap-report existing.json` imports a ZAP Traditional JSON report without
  starting another scan.

`--with-zap` and `--zap-report` cannot be combined. The profile lowers load but
cannot guarantee that an unknown target-side rate limit will not be reached.

### Report and diagnostics

The HTML report separates scanner evidence, deterministic risk, correlation,
and advisory AI output. It includes applicability, suggested remediation,
verification, `needs_review`, limitations, and a run summary.

Each run stores sanitized `ai_analysis_metrics.json` with counts, redactions,
latency, tokens, and estimated cost when model pricing variables are supplied.
The export sanitizer strictly allowlists the public `correlation`,
`asset_knowledge`, `applicability`, `ai_remediation`, and summary objects.

## Small, credible evaluation

Do not invent results. Use one controlled vulnerable application or frozen
fixtures and save the exact dataset, labels, command, model, prompt/schema
version, and output artifact.

### Main comparison: raw evidence vs VulnFusion

Use two matched datasets with seeded known vulnerabilities:

1. **Human-only:** give the analyst raw scanner evidence and ask for unique
   vulnerabilities, priorities, preserved sources, and a final report.
2. **VulnFusion-assisted:** give the analyst the VulnFusion report and ask them
   to review merges, `needs_review` items, AI applicability, and remediation.
3. Measure time, known vulnerabilities retained, missed vulnerabilities, false
   merges/splits, manual corrections, and preserved source links.

With one participant, use different matched datasets and reverse order where
possible. Do not show the same dataset twice, because memory would bias the
second result.

The best concise claim has the form:

> Review time changed from X to Y; N/N seeded vulnerabilities stayed visible;
> there were A false merges, B review escalations, and C manual corrections.

Report the real numbers even if improvement is smaller than expected.

### Isolate the LLM's role

Use 5–10 ambiguous candidate pairs and compare:

- deterministic-only decision;
- structured LLM decision;
- human label from the same evidence.

Show one useful semantic merge, one prevented unsafe merge, and one honest
review escalation. Report agreement, review rate, and incorrect automatic
merge count. This directly demonstrates where the LLM adds value without
claiming it is always correct.

### Evaluate finding advice without another model call

Create and fill a label template:

```bash
uv run python -m utils.ai_evaluation \
  --results path/to/normalized.json \
  --write-label-template evaluation/labels.json

uv run python -m utils.ai_evaluation \
  --results path/to/normalized.json \
  --labels evaluation/labels.json \
  --output evaluation/ai_evaluation.json
```

This records:

- applicability coverage and human-label agreement;
- `needs_review`, unavailable, skipped, and wrong false-positive counts;
- human ratings that remediation is supported, actionable, and verifiable;
- run provenance, token/latency/redaction metrics, and context revision.

## Judging-criterion evidence

| Criterion | What to demonstrate |
|---|---|
| Idea quality and public fit | Armenia-specific public sources plus one realistic local/public-interest workflow |
| Working prototype and LLM fit | End-to-end run and the small deterministic-vs-LLM-vs-human panel |
| Evaluation | Frozen inputs, human labels, baseline comparison, saved metrics, and visible errors |
| Limitations and safety | No-delete/no-score guardrails, strict schemas, sanitization, thresholds, review escalation, fail-open behavior |
| Feasibility and reproducibility | One documented command, polite/offline scan route, bounded calls, cache, costs, and isolated site knowledge |

## Known limits to state explicitly

- Scanner evidence can be incomplete or wrong; the LLM cannot prove
  exploitability.
- Model confidence is self-reported, not a calibrated probability.
- Similar titles may represent different technical instances.
- Pattern-based sanitization cannot guarantee detection of every secret.
- Suggested remediation may not fit an unknown implementation.
- Public context cannot reliably prove business criticality; human confirmation
  is required before it affects scoring.
- Provider availability, latency, context limits, and price constrain scale.
- The polite profile does not discover or bypass an unknown adaptive rate
  limit.

## Definition of done for the defense

1. Run the documented demo from frozen fixtures and, optionally, an authorized
   target.
2. Show that provider failure leaves findings and deterministic scores intact.
3. Show a confirmed site profile revision and its sources.
4. Save real comparison and AI evaluation artifacts.
5. Present both successful cases and failures/review escalations.
6. Clearly separate pre-existing scanner infrastructure from the new context,
   structured AI, safety, metrics, and evaluation layers.
