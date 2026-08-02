---
title: Non-taproot script verification runs Core's own C engine — optimize non-script paths
date: 2026-06-09
category: docs/solutions/architecture-patterns
module: crates/consensus
problem_type: architecture_pattern
component: tooling
severity: medium
applies_when:
  - "Proposing work to make bitcoin-rs faster than Bitcoin Core at block validation"
  - "Micro-optimizing a data structure inside or adjacent to a bitcoinconsensus call"
  - "Choosing a container for a very-small-N collection on a hot path"
  - "Editing a dependency or swapping a container without a baseline benchmark"
related_components:
  - consensus
  - script-verification
  - utxo
tags:
  - bitcoinconsensus
  - script-verification
  - consensus
  - performance
  - benchmark
  - bottleneck
  - profile-before-optimize
  - measured-regression
---

# Non-taproot script verification runs Core's own C engine — optimize non-script paths

## Context

The IBD / block-validation effort set a goal of beating Bitcoin Core (C++) and gocoin (Go) on
validation speed while staying compact. A natural first instinct was to micro-optimize the consensus
hot path. The candidate: the duplicate-input detection set in transaction verification, which enforces
the consensus rule that a transaction may not spend the same outpoint twice.

That set lives at `crates/consensus/src/verify_tx.rs:179`:

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

The hypothesis was that swapping the ordered `std::collections::BTreeSet` for `hashbrown::HashSet`
(O(log n) tree ops -> amortized O(1) hashing) would shave time off per-transaction verification. It did
the opposite.

**What didn't work:** swapping `BTreeSet` -> `hashbrown::HashSet` for the `seen` outpoint set produced
a *statistically significant regression* of **+2.7%** on the `verify_tx/multi_input_true_scripts`
criterion benchmark (p<0.05). The change was reverted; HEAD still uses `BTreeSet`. Codex metacognition
independently flagged the micro-opt as "premature and not goal-aligned" before the bench came back — the
regression confirmed the flag empirically.

The root cause is structural, not tuning-fixable. Under the default `bitcoinconsensus` feature, the
verification loop immediately after the dup-input check routes each **non-taproot** input into
`bitcoinconsensus` (libbitcoinconsensus — Bitcoin Core's *own* extracted script-verification engine).
The feature is on by default (`crates/consensus/Cargo.toml:15`, `default = ["bitcoinconsensus"]`) and the
call site is gated by `#[cfg(feature = "bitcoinconsensus")]` (`verify_tx.rs:202`). The `seen` set holds
only a handful of outpoints per transaction, so swapping its container for a small N set without profiling
adds overhead rather than leverage. Worse, at tiny N (a few elements), `HashSet`'s allocation plus
hashing constant-factor costs *more* than `BTreeSet`'s. Pure downside.

## Guidance

**Non-taproot script evaluation delegates to `bitcoinconsensus`; this narrows likely Rust-side leverage but does not rule out a measured cache hit or wrapper/data-preparation win.** With the shipping default (`bitcoinconsensus`), **non-taproot** per-input script verification is delegated to Core's own extracted C engine (taproot inputs run bitcoin-rs's Rust `Interpreter` instead — see Scope below). Delegating script evaluation to `bitcoinconsensus` means execution runs C code, but Rust wrapper overhead, data-preparation structures, or caching can still impact total execution time. Any proposed optimization on this path must measure actual hit rates, caching potential, or wrapper costs rather than assuming zero headroom or guaranteed speedup.

> Scope — non-taproot only: on the default build the per-input routing is **split**. Non-taproot inputs
> go to the `bitcoinconsensus` C engine (`verify_tx.rs:203`, then `continue`); taproot (P2TR) inputs fall
> through to bitcoin-rs's own Rust `Interpreter` (`verify_tx.rs:215`) *even on the default build*. Delegating
> non-taproot script evaluation to `bitcoinconsensus` narrows likely Rust-side leverage on that path — which is
> what the regression evidence exercises (the bench script is OP_1, non-taproot). The taproot path is Rust and
> carries its own optimization story; see the parallel Rust validation path.

Concretely:

- **Do not micro-optimize small-N Rust data structures adjacent to `bitcoinconsensus` without profiling.**
  The `seen` duplicate-input set and similar small-N collections in `verify_tx` are small enough that unprofiled
  container swaps often add hashing or allocation overhead without delivering measurable wins.
- **Profile non-script and wrapper paths alongside script execution:** the UTXO cache (hit rate,
  eviction, layout), parallelism and commit batching, block download (multi-peer, bandwidth-bound),
  storage backends, and wrapper/data-preparation overhead. Measure actual hit rates or wrapper costs before
  accepting or rejecting Rust-side changes.
- **Process discipline that would have caught this before the edit:** (a) define the success metric and
  comparison harness *before* micro-optimizing; (b) profile to learn where time actually goes before
  picking what to change; (c) benchmark a candidate *before* editing dependencies or containers; (d)
  treat a measured regression as an immediate **reject** — revert, do not tune.

## Why This Matters

This is the load-bearing strategic corollary, and it generalizes beyond one benchmark:

**Delegating non-taproot script evaluation to `bitcoinconsensus` narrows likely Rust-side leverage, but does not rule out a measured cache hit or wrapper/data-preparation win.** While core script execution runs in C, surrounding Rust wrappers, container choices, and caching layers can still affect overall performance. Unprofiled micro-optimizations risk adding wrapper overhead or allocation costs (as shown by the `BTreeSet`-to-`HashSet` regression), whereas measured caching or data-preparation wins remain possible. Work on this path requires empirical profiling and benchmarking of actual hit rates and wrapper overhead before drawing conclusions.

It also reinforces a pattern that already shows up in this codebase: **optimize the actual bottleneck,
not the convenient one.** The sibling doc
`multi-peer-block-download-requires-core-stalling-disconnect.md` makes the same shape of argument for the
download/apply path: real-world IBD is download-bandwidth-bound, not CPU-bound — block *apply* runs at
~1228 blk/s while single-peer *download* runs at ~5-25 blk/s, so shaving CPU off a path that already
runs 50-250x faster than the upstream bottleneck buys nothing. Two subsystems, one principle: profile
first, find the rate-limiting stage, and spend there.

## When to Apply

- Before micro-optimizing any data structure inside `crates/consensus/src/verify_tx.rs` or adjacent to a
  `bitcoinconsensus` call — stop and confirm the path is not dominated by the external C verifier.
- When the optimization target is small-N (a handful of elements): question whether a hash-based
  container beats an ordered or array one at all; constant factors and allocation often lose at tiny N.
- When proposing "faster than Core" work on non-taproot script paths: profile and benchmark actual hit rates,
  caching potential, or wrapper costs rather than assuming automatic speedup or absolute limits.
- Whenever you are tempted to edit a dependency or swap a container without a baseline benchmark and a
  profile — the prerequisite is the measurement, not the edit.
- When a candidate change shows a statistically significant regression: revert immediately; do not enter
  a tuning loop on a path that was the wrong target to begin with.

## Examples

**Before (HEAD — reverted to this):** `crates/consensus/src/verify_tx.rs:179`

```rust
use std::collections::BTreeSet;

let mut seen = BTreeSet::new();
// reject a tx spending the same outpoint twice (consensus rule)
if !seen.insert(input.previous_output) {
    return Err(ConsensusError::DuplicateInput { input_index });
}
```

**After (the experiment — rejected):**

```rust
use hashbrown::HashSet;

let mut seen = HashSet::new();
if !seen.insert(input.previous_output) {
    return Err(ConsensusError::DuplicateInput { input_index });
}
```

**Measured result** — `verify_tx/multi_input_true_scripts`, `crates/consensus/benches/verify_tx.rs`:

| Variant          | Container             | Time      | Delta vs baseline      | Significance       |
| ---------------- | --------------------- | --------- | ---------------------- | ------------------ |
| Baseline (HEAD)  | `BTreeSet`            | 3.6312 ms | —                      | —                  |
| Experiment       | `hashbrown::HashSet`  | 3.7297 ms | **+2.7% (regression)** | p<0.05 significant |

The `seen` set holds only a handful of outpoints per tx; the container swap added `HashSet` allocation
plus hashing constant-factor at tiny N without delivering a measured cache or data-preparation win —
producing a net +2.7% regression. Outcome: reverted.

## Related

- `multi-peer-block-download-requires-core-stalling-disconnect.md` — sibling instance of the same
  "optimize the actual bottleneck / know which paths have headroom" principle. That doc covers the
  **download/scheduler** path (the lever that *does* move IBD wall time); this one covers the
  **default script-verify** path (delegated to `bitcoinconsensus` — narrows likely Rust leverage,
  requiring empirical measurement of cache hit rates and wrapper costs). See its guidance point 1,
  which makes the identical argument for the apply/UTXO/wire path.
