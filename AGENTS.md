# Repository guidance

## Project

VulnFusion is a Python 3.10+ vulnerability-scanning pipeline. It normalizes
scanner-native findings, conservatively deduplicates them, calculates risk,
tracks changes, and generates JSON/HTML reports. The CLI entry point is
`main.py`; scanner integrations live in `scanners/`, shared pipeline logic in
`utils/`, and tests in `tests/`.

## Development workflow

- Use `uv` for the environment and commands.
- Run focused tests while developing: `uv run pytest tests/<test_file>.py -q`.
- Before handing off, run `uv run pytest -m "not live_llm and not zap_docker" -q`.
- Never run live provider calls, Docker scanner smoke tests, or scans against
  external targets unless the user explicitly asks and confirms authorization.
- Keep changes focused and preserve unrelated work in a dirty worktree.

## Implementation principles

- Preserve scanner evidence, provenance, and deterministic behavior.
- Deduplication must be conservative: failures, malformed LLM output, and low
  confidence must not merge findings.
- Advisory AI analysis must fail open and must not suppress findings or replace
  scanner remediation.
- Keep provider integrations generic and OpenAI-compatible unless a task
  explicitly requires provider-specific behavior.
- Add or update tests for behavior changes. Prefer deterministic mocks over
  network access.

## Security and secrets

- Never commit, log, snapshot, or place API keys and tokens in fixtures.
- Keep real credentials only in the ignored `.env`; document placeholders in
  `.env.example`.
- Sanitize provider payloads and diagnostics before persistence or logging.
- Do not weaken target validation, request bounds, or authorization warnings.
