---
title: Criterion bench trust - rebuild codegen drift, baseline CLI exclusivity, allocator parity
date: 2026-06-10
category: docs/solutions/best-practices
module: criterion benchmarking across the retained workspace benches
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - "Interpreting a criterion p<0.05 regression or improvement that spans a rebuild"
  - "Chaining criterion runs with --baseline / --save-baseline flags"
  - "Reading criterion numbers for code whose production binary ships mimalloc"
related_components:
  - testing_framework
tags:
  - criterion
  - benchmark
  - codegen-drift
  - baseline
  - mimalloc
  - measured-regression
---

# Criterion bench trust: three failure modes that fabricate or hide deltas

## Context

During the round-2 hot-path campaign (2026-06-10), three independent Criterion
pitfalls nearly corrupted commit decisions: a phantom regression almost vetoed a
verified optimization, a CLI flag conflict silently killed half an A/B chain,
and allocator mismatch skewed allocation-heavy benches relative to the shipped
binary. The campaign harnesses are historical; the rules below still apply to
the retained production-path benches.

## Guidance

1. **A p=0.00 delta across a fat-LTO rebuild can be codegen drift, not your change.**
   Re-run the suspect bench against the same saved baseline with no intervening
   rebuild. Only a delta that reproduces on the same binary is binary-level; only
   one that survives a rebuild pair is attributable to the source change.
2. **`--baseline` and `--save-baseline` are mutually exclusive Criterion CLI args.**
   Save first and compare in a separate run; otherwise the invocation fails and
   a piped campaign can misreport the empty phase as a measurement result.
3. **Allocator parity gates bench trust.** `bin/bitcoin-rs` ships mimalloc, and
   the retained `utxo_commit` bench registers the same allocator directly. The
   older `bench-mimalloc` A/B campaign showed that system-allocator numbers can
   diverge materially from production-shaped results; that feature and comparison
   harness are retired. Reopen an A/B only as a newly scoped, explicitly
   controlled investigation.

## Why This Matters

Bench-driven decisions inherit every bias of the bench run. The retained
benchmarks therefore measure shipped paths and workloads; historical A/B and
synthetic attribution results remain evidence in the benchmark pages and git
history, not executable regression contracts.

## When to Apply

- Before accepting or vetoing a Criterion delta that spans a rebuild.
- When scripting multi-phase Criterion chains with saved baselines.
- When a retained bench allocates heavily and the binary ships a custom allocator.

## Examples

- Same-binary re-probe:
  `cargo bench -p bitcoin-rs-node --bench sync_pipeline -- --baseline fixed partial_apply_tick`
  (no rebuild in between).
- The current UTXO commit bench uses the production allocator in every run.

## Related

- [small-window-benchmarks-do-not-predict-at-scale-throughput](small-window-benchmarks-do-not-predict-at-scale-throughput.md)
  - cross-node measurement methodology for single-machine benchmark hygiene.
- [utxo-commit-borrowed-removal-win-is-off-the-coalescing-event-path](../architecture-patterns/utxo-commit-borrowed-removal-win-is-off-the-coalescing-event-path.md)
  - why a synthetic listener-only win is not production evidence.
