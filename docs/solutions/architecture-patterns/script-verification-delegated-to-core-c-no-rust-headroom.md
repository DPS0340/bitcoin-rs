---
title: "Production script verification runs through bitcoinkernel: optimize measured Rust-side preparation and non-script stages"
date: 2026-06-09
category: docs/solutions/architecture-patterns
module: crates/consensus
problem_type: architecture_pattern
component: tooling
severity: medium
applies_when:
  - "Proposing work to make bitcoin-rs faster than Bitcoin Core at block validation"
  - "Micro-optimizing a data structure inside or adjacent to a bitcoinkernel consensus call"
  - "Choosing a container for a very-small-N collection on a hot path"
  - "Editing a dependency or swapping a container without a baseline benchmark"
related_components:
  - consensus
  - script-verification
  - utxo
tags:
  - bitcoinkernel
  - script-verification
  - consensus
  - performance
  - benchmark
  - bottleneck
  - profile-before-optimize
  - measured-regression
---

# Production script verification runs through bitcoinkernel: optimize measured Rust-side preparation and non-script stages

> **Current Architecture Status (Tasks 16–18):**
> In Tasks 16–18, `bitcoinkernel` (`libbitcoinkernel`) became the default production input-script verification engine across all script classes (legacy, segwit, and Taproot script-path and key-path spends). Historical `bitcoinconsensus` has been removed.
>
> **Architecture Decision and Tradeoff:**
> Adopting `bitcoinkernel` as the single native input-script verification engine addresses the unsupported Taproot script-path capability exposed during the block-938344 IBD stall under the portable path; successful live progression through block 938344 and full-tip completion remain pending a fresh rerun. The tradeoff is a hard build requirement on C++ build tools (`cmake` and `libboost-dev`) for default builds. The pure-Rust interpreter remains an explicit `--no-default-features` portable posture for differential testing, but cannot validate Taproot script-path transactions on mainnet.
>
> **Performance Evidence Note:**
> The `BTreeSet` vs `HashSet` benchmark delta below was measured under the historical `bitcoinconsensus` backend. Production script verification now runs entirely through `bitcoinkernel`. The cutover is a correctness and architecture requirement, not a speed optimization; final end-to-end performance must be remeasured under the kernel default.

## Context

The block-validation performance effort set a goal of matching or exceeding Bitcoin Core validation speed while maintaining a compact footprint. An early optimization attempt targeted the duplicate-input detection set during transaction verification in `crates/consensus/src/verify_tx.rs`, which enforces the consensus rule that a transaction must not spend the same outpoint twice:

```rust
let mut seen = BTreeSet::new();
for (input_index, input) in tx.input.iter().enumerate() {
    if input.previous_output.is_null() {
        return Err(ConsensusError::NullPrevout { input_index });
    }
    if !seen.insert(input.previous_output) {
        return Err(ConsensusError::DuplicateInput { input_index });
    }
}
```

The hypothesis was that replacing `std::collections::BTreeSet` with `hashbrown::HashSet` would reduce per-transaction verification overhead by substituting O(1) hashing for tree operations. Instead, the change caused a statistically significant performance regression of +2.7% on the `verify_tx/multi_input_true_scripts` benchmark (p<0.05), leading to an immediate revert.

Because the `seen` set holds only a few outpoints per transaction, swapping containers at tiny N adds allocation and hashing overhead without reducing execution time. The +2.7% number was measured in the `bitcoinconsensus` era; the container conclusion holds regardless, but a direct performance comparison against the current `bitcoinkernel` default needs fresh measurement.

## Guidance

**Optimize measured Rust-side preparation and non-script stages.** Because core script evaluation runs inside `bitcoinkernel`, Rust-side micro-optimizations inside verifier loops provide limited leverage. Optimization efforts must focus on measured Rust-side bottlenecks (such as UTXO caching, input preparation, storage commits, and block download scheduling).

Concretely:

- **Do not micro-optimize small-N Rust data structures adjacent to consensus calls without profiling.** Small-N collections like the duplicate-input `seen` set carry constant-factor allocation and hashing overhead that often exceeds ordered tree lookups.
- **Profile non-script and wrapper paths alongside script execution:** UTXO cache lookup efficiency, transaction iteration, parallelism, storage backend commits, and block download scheduling. Measure actual overhead before attempting Rust-side modifications.
- **Maintain measurement discipline:** (a) define the baseline harness before optimizing; (b) profile to isolate the rate-limiting stage; (c) benchmark candidates against the `bitcoinkernel` baseline; (d) revert measured regressions immediately.

## Why This Matters

**Delegating production script evaluation to `bitcoinkernel` bounds Rust-side headroom on the script path.** Surrounding Rust logic — UTXO retrieval, transaction iteration, container allocation, storage commits — decides the remaining Rust-side performance.

This aligns with a core system design principle: **optimize the actual bottleneck, not the convenient one.** Real-world IBD wall-clock time is frequently download-bandwidth or storage-bound rather than CPU-script bound. Profiling isolates the true constraint before code changes begin.

## When to Apply

- Before micro-optimizing any data structure inside `crates/consensus/src/verify_tx.rs` or adjacent to a `bitcoinkernel` call: verify whether script execution or C++ kernel overhead dominates execution time.
- When evaluating small-N collections (handful of elements): test whether hash-based containers outperform ordered or array-backed alternatives at tiny scale.
- When proposing block-validation performance work: benchmark full block input-script verification under the default `bitcoinkernel` feature rather than isolated non-production interpreter paths.
- Whenever editing containers or dependencies on hot validation paths: establish a baseline benchmark before modifying code.
- When a candidate change produces a statistically significant regression: revert immediately instead of tuning an ineffective path.

## Examples

**Baseline (reverted code):** `crates/consensus/src/verify_tx.rs`

```rust
use std::collections::BTreeSet;

let mut seen = BTreeSet::new();
if !seen.insert(input.previous_output) {
    return Err(ConsensusError::DuplicateInput { input_index });
}
```

**Experiment (rejected code):**

```rust
use hashbrown::HashSet;

let mut seen = HashSet::new();
if !seen.insert(input.previous_output) {
    return Err(ConsensusError::DuplicateInput { input_index });
}
```

**Historical measured result** — `verify_tx/multi_input_true_scripts`, `crates/consensus/benches/verify_tx.rs` (measured under historical `bitcoinconsensus` engine):

| Variant          | Container             | Time      | Delta vs baseline      | Significance       |
| ---------------- | --------------------- | --------- | ---------------------- | ------------------ |
| Baseline         | `BTreeSet`            | 3.6312 ms | —                      | —                  |
| Experiment       | `hashbrown::HashSet`  | 3.7297 ms | **+2.7% (regression)** | p<0.05 significant |

Outcome: reverted.

## Related

- `multi-peer-block-download-requires-core-stalling-disconnect.md`: Sibling instance of optimizing the actual bottleneck. That doc covers download scheduling; this doc covers production script verification (delegated to `bitcoinkernel`, requiring focus on measured non-script Rust stages).
