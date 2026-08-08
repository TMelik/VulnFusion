# Dedup Benchmark

This repository includes a lightweight synthetic benchmark for dedup runtime and
pair-count reduction.

Fixture:

- `tests/fixtures/dedup_benchmark_cases.json`

Run it locally with:

```bash
python -m utils.dedup_benchmark
```

Add `--profile` to print per-stage timings from the real resolver flow:

```bash
python -m utils.dedup_benchmark --profile
```

What it measures per dataset:

- input findings and final findings
- naive `O(n^2)` pair count
- same-target candidate pairs after blocking
- low-similarity skips
- deterministic merge reductions
- pairs that reached the gray-zone LLM path
- total LLM or cached comparisons
- runtime
- comparison reduction ratio
- deterministic vs gray-zone resolution share
- final mode distribution across `deterministic`, `hybrid`, `llm`, and `no_merge`

The benchmark uses:

- fixed-seed synthetic dataset generation
- the real `LLMDuplicateResolver`
- an oracle client instead of live provider calls

Interpret the results as an engineering guardrail, not a research benchmark. A
healthy run should keep comparison counts far below the naive pair count while
still leaving some gray-zone work for the LLM path. If deterministic rules
expand later, update the synthetic mix or expectations instead of weakening the
resolver. Profiling numbers help explain *where* time is going; benchmark
numbers show *how much* total work remains after blocking, deterministic merges,
and gray-zone routing.
