---
title: Script-verify pool width was the binding constraint — 389.7s to 157.8s (2.47x), Core still leads 2.36x
date: 2026-08-07
category: docs/solutions/performance-issues
module: node apply path (crates/node/src/apply.rs, crates/consensus/src/verify_tx.rs)
problem_type: performance_issue
component: apply
severity: medium
applies_when:
  - "Measuring processing-bound 0→150k replay with full verification (assume_valid_height=0)"
  - "Optimizing txid computation or script verification preparation"
related_components:
  - consensus
  - utxo
tags:
  - txid
  - parallelization
  - processing-bound
  - replay
---

# Script-verify pool width was the binding constraint — 389.7s → 157.8s (2.47×), Core still leads 2.36×

## Context

Processing-bound replay `mainnet_prefix_replay --rest-url 127.0.0.1:18443 --assume-valid-height 0 --stop-height 150000` over local `bitcoind -rest` (fjall backend, full script verification both sides) is the correct instrument for CPU work per `small-window-benchmarks-do-not-predict-at-scale-throughput.md`. Baseline at `4700c25` was **389.7s / 385 blk/s** vs Core `67s` / 2240 blk/s (5.8×).

Commit `f76d43a` (`perf(apply): parallelize txid computation for blocks with many transactions`) parallelizes `plan_block_transactions` for `block.txdata.len() > 32` via `par_iter().map(compute_txid)`. Synthetic proxy benches (≤32 txs) do not exercise this path, so they show no signal.

## Measurement

Same machine (128 cores), serial runs, local REST blocks (fjall, full verification):

| Node | Commit | Elapsed 0→150k | blk/s | RSS high-water | Source | Notes |
|---|---|---|---|---|---|---|
| bitcoin-rs | `4700c25` | 389.7s | 385 | 2.36 GB | `processing-bound-150k-verdict.md` | baseline |
| bitcoin-rs | `f76d43a` | 178.93s | 838 | 223 MB | `~/bench-g14/results/replay-postopt-150k-f76d43a.json` (150001 blocks, 687 MB, `git_head f76d43a`) | single clean run, txid parallel |
| bitcoin-rs | `e540b91` (code-identical to `f76d43a`) | 173.1s median (166.4, 173.1, 177.8) | 867 | 223 MB | `taskset -c 0-31` 3×, no IBD contention (`/tmp/replay-taskset-*.json`) | txid parallel, 16-thread pool |
| bitcoin-rs | `0e2dda5` | **157.8s median** (163.8, 155.9, 157.8) | **950** | 223 MB | `taskset -c 0-31` 3× (`/tmp/replay-t32-*.json`) | + 32-thread script-verify pool |
| Core 31.0 | — | 67s | 2240 | n/a | `-reindex-chainstate -assumevalid=0 -connect=0` debug.log | |

Gap to Core: **5.8× → 2.36×** (157.8/67). Total win over the `4700c25` baseline is **2.47×**. Remaining gap is 90.8s.

## Where the 157.8s goes — clean stage decomposition

From `/tmp/replay-t32-3.json` (`0e2dda5`, `taskset -c 0-31`, uncontaminated):

```
elapsed              157.8s      fetch 22.4s   decode 3.6s   RSS 212 MB
  apply total        128.9s
    script_verify     84.9s      (66% of apply)
      script_parallel 55.2s
      script_prepare  19.4s
      script_resolution 6.1s
    utxo_commit        7.0s
    block_rules        5.2s
    (remainder <5s each)
  non-script apply    44.0s
```

Two things this reframes:

1. **~22.4s of the 157.8s is REST fetch**, a harness cost Core's `-reindex-chainstate` never pays — it reads local `blk` files. Apply-only is **128.9s vs Core's 67s = 1.92×**, so the headline 2.36× overstates the engine gap; 1.92× is the defensible lower bound (Core's 67s does include its own block reads).
2. **`script_verify` at 84.9s already exceeds Core's entire 67s run**, and non-script apply (44.0s) is by itself two-thirds of Core's total. Both halves need work; neither alone closes the gap.

An earlier instrumented run (`53feecb`, 201.84s) attributed the then-uninstrumented remainder to `utxo_resolve` 25.7s and `txid_plan` 21.6s, but that run was contaminated (concurrent full-tip IBD writing `blk00817→867`) **and** inflated ~23s by the per-block histograms themselves. Treat its absolute numbers as indicative only; the clean decomposition above supersedes it.

**Levers tried and rejected on clean `taskset -c 0-31` 3× medians (all against the 173.1s serial baseline):**

| Change | Median | Speedup | Verdict |
|---|---|---|---|
| Parallel `prepare_block_input_checks` (`0302a0c`) | 173.5s (170.6/173.5/173.9) | 1.00× | rejected — reverted `6d9c3b8` |
| Thread-local serialize buffer in `prepare_kernel_tx` (avoids per-tx `encode::serialize` alloc) | 173.2s (173.2/173.9/172.4) | 1.00× | rejected — `script_prepare` 20.4s → 18.2s but total unchanged |
| Skip `kernel_txout` construction for witness-free txs (empty `spent_outputs` to `PrecomputedTransactionData`) | not benchmarked | — | **rejected by tests**: kernel returns `Script verification error: Spent outputs required for verification`. Core's `Init` computes no midstates without a witness, but `btck_script_pubkey_verify` still gates on `m_spent_outputs_ready`, so the prevout `TxOut` objects must be built even when never hashed |
| Feed kernel the block's already-serialized tx byte ranges instead of re-serializing | not implemented | ~1.01× (costed) | rejected on analysis — the replay moves 687 MB of tx bytes, so removing the Rust serialize entirely is order 1–2s of 173s, bounded empirically by the buffer result above (2.2s off the stage → 0.1s off the total) |

The first two cleared the tests but not the 1.05× noise floor; the third never got that far. `script_prepare` is real work inside `libbitcoinkernel`, not Rust-side overhead. Even eliminating **all** of prepare leaves ~153s against Core's 67s, so prepare is not where the gap lives. `ResolvedUtxoView::resolve` (25.69s) is likewise **already parallel** (`apply.rs:1136` `into_par_iter`), so it is not a batching target either.

## Guidance

1. **Attribute a stage by disabling it, not by reading a profiler.** `perf` was unavailable here (`perf_event_paranoid=4`, no sudo), but the open question — is `script_parallel`'s ~0.93 ms/block genuine secp256k1 work or rayon dispatch overhead? — is binary, so forcing `MIN_PARALLEL_SCRIPT_CHECKS = usize::MAX` answered it in one run: the replay went 173.1s → **313.3s** and the stage 63s → **227.6s**. Genuine crypto. That immediately reframed the number: 227.6s → 63s is only **3.6× from a 16-thread pool**, so the pool width was the binding constraint, and widening it to 32 bought 1.10× (`0e2dda5`). Prefer this disable-the-stage technique whenever a hypothesis is binary; it needs no tooling and cannot be argued with.
2. **The prepare phase is closed — do not reopen it.** Prepare is ~20s of the run; zeroing it entirely still leaves ~138s against Core's 67s. Four candidates are closed (table above): two by benchmark, one by tests (`btck_script_pubkey_verify` gates on `m_spent_outputs_ready`, so prevout `TxOut`s must be built even when nothing hashes them), one by cost analysis. `ResolvedUtxoView::resolve` is already `into_par_iter` (`apply.rs:1136`) and `plan_block_transactions` already `par_iter` above 32 txs (`apply.rs:985`), so neither is a target either.
3. **Pool width has a measured optimum at 32 on this host — do not raise it further.** The sweep is non-monotonic:

   | Pool | CPU set | Median | `script_parallel` |
   |---|---|---|---|
   | 16 | 32 physical (`0-31`) | 173.1s | 63-65s |
   | **32** | 32 physical (`0-31`) | **157.8s** | 55.2s |
   | 32 | 16 physical + SMT siblings (`0-15,40-55`) | 158.9s | 63.9s |
   | 64 | 64 logical (`0-63`) | 177.9s | 60.2s |

   64 threads is *worse than 16* — coordination and oversubscription on ~22-input blocks cost more than the extra width buys. A different machine needs its own sweep; the constant stays a cap rather than `available_parallelism` so verification cannot starve the rest of the pipeline. Beyond width, the remaining structural lever is holding kernel objects across the block (`bitcoinkernel::Block::new` once, then `block.transaction(i)`) instead of reconstructing per transaction — a cross-crate change to the consensus public API.
4. **Do not re-profile with per-block histograms.** `txid_plan_seconds`/`utxo_resolve_seconds` (added `68bbb2f`, reverted `e540b91`) cost ~23s over 150k blocks — 13% of the measurement they were meant to explain. Use sampled or off-line profiling.
5. **Do not re-use full-tip IBD wall-time to validate CPU changes.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 463k/961k when stopped) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
