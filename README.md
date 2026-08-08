# VulnFusion

VulnFusion turns results from several security scanners into one prioritized,
explainable vulnerability report. It normalizes scanner output, identifies
cross-scanner duplicates, preserves the original evidence, tracks changes
between scans, and produces JSON plus a self-contained HTML report.

> Scan only systems you own or are explicitly authorized to test.

## Why VulnFusion

Security scanners often describe the same issue differently. A raw combined
report can contain repeated findings, inconsistent severity labels, and little
business context. VulnFusion keeps deterministic rules for obvious matches and
uses a structured LLM decision only for ambiguous cross-scanner pairs. Low
confidence decisions are not merged and can be marked for review.

The result is easier to review without hiding scanner evidence:

- findings from Nmap, Nuclei, Wapiti, Nikto, and OWASP ZAP;
- strict normalized schema and scanner provenance;
- conservative LLM-assisted duplicate resolution;
- bounded advisory applicability and remediation guidance;
- deterministic risk score, priority, and rationale;
- NEW, PERSISTENT, CHANGED, and FIXED tracking;
- per-site context and knowledge bundles;
- HTML report with an AI correlation graph;
- optional DefectDojo export and upload.

## Quick start

Requirements: Python 3.10+, [`uv`](https://docs.astral.sh/uv/), and at least one
supported scanner installed locally. Docker can provide the complete scanner
environment.

```bash
git clone https://github.com/TMelik/VulnFusion.git
cd VulnFusion
uv sync

# Show available scanners
uv run python main.py --list-scanners

# Run a scan and generate report.html
uv run python main.py --target example.com --scanner all
```

Results are written under `data/<target>/<timestamp>/` by default.

## Recommended demo

The included demo profile uses Nmap discovery and rate-limited Nuclei checks.
Wapiti, Nikto, and active ZAP execution are disabled to reduce traffic and make
the demo more repeatable.

```bash
uv run python main.py \
  --target example.com \
  --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml
```

If a traditional JSON report already exists from a manual ZAP scan, import it
without running ZAP again:

```bash
uv run python main.py \
  --target example.com \
  --scanner all \
  --scan-config configs/examples/polite_demo_config.yaml \
  --zap-report reports/manual-zap-report.json
```

The imported findings pass through the same normalization, deduplication,
scoring, and reporting pipeline as live scanner output.

To run a small passive ZAP pass instead, explicitly add `--with-zap`. With the
demo profile it uses the bounded one-thread spider template; without a profile
the flag selects the same conservative template automatically. Add
`--zap-active-scan` only for a separately authorized active test.

## Optional site context

VulnFusion can crawl up to three same-site pages and collect allowlisted HTTP,
DNS, and TLS metadata. It proposes a short description and risk context, then
asks the user to confirm them before scanning. Confirmed knowledge is stored in
an isolated, versioned OKF bundle for each site/domain.

```bash
# Interactive review
uv run python main.py --target example.com --discover-context

# Non-interactive demo with an explicit reviewed description
uv run python main.py \
  --target example.com \
  --discover-context \
  --context-description "Public customer portal for account services"
```

Fresh confirmed profiles are reused automatically; use `--discover-context` to
refresh one or `--no-context-reuse` to ignore it. Only confirmed values may
affect deterministic scoring. Site context never changes deduplication identity
and no external search API or broad reconnaissance is used.

Owner-supplied deterministic rules remain available through
`--asset-context-file`.

## Structured LLM assistance

Configure an OpenAI-compatible chat-completions endpoint through environment
variables or equivalent CLI flags:

```bash
export VULN_MANAGER_LLM_API_URL="https://provider.example/v1/chat/completions"
export VULN_MANAGER_LLM_API_KEY="..."
export VULN_MANAGER_LLM_MODEL="model-name"
```

The same provider supports two bounded stages. Duplicate resolution merges only
when `same_vulnerability=true` and confidence is at least `0.85`. Invalid,
timed-out, failed, or low-confidence decisions never trigger a merge. The
canonical title remains a separate recommendation and does not overwrite the
scanner-native vulnerability name.

After deterministic scoring, VulnFusion automatically analyzes at most the ten
highest-priority findings for applicability and advisory remediation. Strict
JSON, evidence IDs, secret redaction, versioned caching, and fail-open handling
are enforced. Advice never suppresses a finding or changes scanner remediation
or risk. Use `--ai-analysis-limit N` or `--no-ai-analysis` to control this stage.
The YAML knowledge store is a versioned duplicate-resolution cache and advisory
finding-analysis cache; it never replaces scanner evidence.

Disable only duplicate resolution with `--duplicate-mode off` or `--no-dedupe`.

## Pipeline

```text
scan and normalize
        ↓
conservative cross-scanner deduplication
        ↓
optional comparison with the previous scan
        ↓
asset context and deterministic risk scoring
        ↓
bounded advisory finding analysis
        ↓
sanitized JSON and self-contained HTML report
```

Normal scan runs write `report.html` automatically. Use `--no-report` (or
`global.report: false` in scan config) to skip it, or `--compare` to include
change tracking against the latest previous run.

Typical run output:

```text
data/<target>/<timestamp>/
├── raw/                       # original scanner artifacts
├── effective_scan_config.json
├── scan_results.json          # aggregated scanner results
├── normalized.json            # processed findings
├── ai_analysis_metrics.json   # bounded AI diagnostics, when normalized
└── report.html                # shareable report
```

## Docker

Build the complete scanner image:

```bash
docker build -t vulnfusion:latest .
docker run --rm vulnfusion:latest
```

Run a scan and keep the output on the host:

```bash
docker run --rm \
  --env-file .env \
  -v "$(pwd)/data:/app/data" \
  vulnfusion:latest \
  python3 main.py --target example.com --scanner all
```

For localhost or LAN targets on Linux, use the provided host-network Compose
override. Do not use host networking unless the target and authorization scope
are clear.

## Useful commands

```bash
# Inspect transport without scanning
uv run python main.py --target example.com --probe-only

# Run one scanner
uv run python main.py --target https://example.com --scanner zap

# Compare with the previous run
uv run python main.py --target example.com --scanner all --compare

# Full CLI reference
uv run python main.py --help

# Test suite and dedup evaluation
uv run pytest
uv run python -m utils.dedup_evaluation

# Create human labels, then evaluate advisory AI output
uv run python -m utils.ai_evaluation --results data/.../normalized.json \
  --write-label-template data/.../ai_labels.json
```

## Documentation

| Document | Purpose |
|---|---|
| [Pipeline walkthrough](docs/walkthrough.md) | Processing order, output contract, and implementation map |
| [Dedup evaluation](docs/dedup_evaluation.md) | Reproducible duplicate-resolution evaluation |
| [LLM effectiveness evidence](docs/llm_effectiveness_evidence.md) | Baselines and evidence for the LLM's role |
| [Risk model](docs/risk_model.md) | Risk-scoring design and limitations |
| [Hackathon roadmap](docs/hackathon_roadmap.md) | Demo scope, evaluation plan, and remaining work |
| [Knowledge index](knowledge/index.md) | OKF-oriented project knowledge for people and agents |
| [ZAP guide](knowledge/scanners/zap.md) | ZAP execution and existing-report import |
| [Polite scanning](knowledge/polite-scanning.md) | Conservative demo profile and rate-limit guidance |

DefectDojo integration details live in
[knowledge/defectdojo-integration.md](knowledge/defectdojo-integration.md).

## Current boundaries

- Confidence is the model's stated confidence, not a proven probability.
- LLM failure degrades to separate findings, never an automatic merge.
- Site context is human-confirmed and isolated per site/domain.
- AI applicability and remediation are advisory; scanner evidence stays authoritative.
- Scanner availability and scan depth depend on the local or container setup.
- ZAP active scans can be slow and intrusive; use them only when explicitly
  authorized.

The core pipeline is covered by the repository test suite. Experimental or
environment-dependent scanner paths are documented separately rather than
presented as universal guarantees.
