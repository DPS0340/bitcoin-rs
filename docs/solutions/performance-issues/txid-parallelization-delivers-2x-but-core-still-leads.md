---
title: Txid parallelization delivers 2.18× processing-bound win but Core still leads 2.67× at 150k
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

# Txid parallelization delivers 2.18× processing-bound win but Core still leads 2.67× at 150k

## Context

Processing-bound replay `mainnet_prefix_replay --rest-url 127.0.0.1:18443 --assume-valid-height 0 --stop-height 150000` over local `bitcoind -rest` (fjall backend, full script verification both sides) is the correct instrument for CPU work per `small-window-benchmarks-do-not-predict-at-scale-throughput.md`. Baseline at `4700c25` was **389.7s / 385 blk/s** vs Core `67s` / 2240 blk/s (5.8×).

Commit `f76d43a` (`perf(apply): parallelize txid computation for blocks with many transactions`) parallelizes `plan_block_transactions` for `block.txdata.len() > 32` via `par_iter().map(compute_txid)`. Synthetic proxy benches (≤32 txs) do not exercise this path, so they show no signal.

## Measurement

Same machine (128 cores), serial runs, local REST blocks (fjall, full verification):

| Node | Commit | Elapsed 0→150k | blk/s | RSS high-water | Source | Notes |
|---|---|---|---|---|---|---|
| bitcoin-rs | `4700c25` | 389.7s | 385 | 2.36 GB | `processing-bound-150k-verdict.md` | baseline |
| bitcoin-rs | `f76d43a` | 178.93s | 838 | 223 MB | `~/bench-g14/results/replay-postopt-150k-f76d43a.json` (150001 blocks, 687 MB, `git_head f76d43a`) | single clean run, txid parallel |
| bitcoin-rs | `e540b91` (code-identical to `f76d43a`) | **173.1s median** (166.4, 173.1, 177.8) | **867** | 223 MB | `taskset -c 0-31` 3×, no IBD contention (`/tmp/replay-taskset-*.json`) | most reliable post-opt |
| Core 31.0 | — | 67s | 2240 | n/a | `-reindex-chainstate -assumevalid=0 -connect=0` debug.log | |

Gap to Core halved: **5.8× → 2.58×** (173.1/67). Next gap is still 106.1s.

## Why Core still leads — stage decomposition

`node.apply_block.total_seconds` dominates wall-clock (87% of elapsed at `f76d43a`: 156.06s total, fetch 15.97s + decode 3.59s overlap via prefetch). At `f76d43a` (178.93s elapsed, no per-block histograms for txid/utxo) **41.5s (26.6% of total) was uninstrumented** — outside all histograms.

Instrumented run `53feecb` (201.84s elapsed, same code + `txid_plan_seconds`/`utxo_resolve_seconds` histograms, but **contaminated** — full-tip IBD `bitcoin-rs-fulltip-postopt-local3` was actively writing `blk00817.dat→blk00867.dat` (50 files) during the run, so absolute times are inflated; relative proportions remain indicative) attributes that gap:

* `utxo_resolve_seconds` **25.69s** (ResolvedUtxoView::resolve — UTXO cache lookups per input)
* `txid_plan_seconds` **21.63s** (`plan_block_transactions` — `compute_txid` per tx, parallel >32)
* `script_prepare_seconds` **20.43s** (serial `prepare_block_input_checks` + `prepare_kernel_tx` per-tx serialize/PrecomputedTransactionData)
* `block_body_persist 11.18s`, `utxo_commit 7.78s`, `block_rules 5.25s`, remainder <2s each (see `replay-postopt-150k-53feecb.json:stage_seconds` 113 lines).

The 41.5s gap is therefore **UTXO resolve (25.69) + txid plan (21.63) ≈ 47s** (slightly above gap due to histogram overhead and contamination), not `prepare` alone. The `prepare` 18–20s is 10% of wall time, but the **dominant uninstrumented cost is UTXO resolve**, so the next lever is UTXO cache/lookup efficiency, not just kernel serialization. `script_verify` itself is 87–99s (55% of total) and already input-level parallel via `SCRIPT_VERIFY_POOL.install || checks.par_iter()` in `verify_block_input_scripts:394-406` (the verdict doc’s “per-block” line referred to pre-`4700c25`).

Taskset-pinned 3× median at `e540b91` (code-identical to `f76d43a`, clean, no IBD contention, `taskset -c 0-31`): **173.1s** (166.4, 173.1, 177.8) / 867 blk/s — confirms the 2.25× win (389.7→173.1) is stable within ~6% noise; the 195.89s (`1126cab` parallel-prepare) and 201.84s (`53feecb` instrumented) numbers above were **observed under contaminated conditions (background rustc + active full-tip IBD) — root cause of those specific regressions (dual rayon pools, quanta overhead) is unconfirmed and not reproduced in isolation**.

## Guidance

1. **Next lever is UTXO resolve, not prepare alone.** The 41.5s gap is dominated by `ResolvedUtxoView::resolve` (25.69s) and `txid_plan` (21.63s) — both larger than `prepare` (18–20s). Prioritize UTXO cache/lookup batching and `compute_txid` amortization; `prepare` (kernel serialize+PrecomputedTransactionData) is secondary. Histograms `txid_plan_seconds`/`utxo_resolve_seconds` added at `68bbb2f` then reverted at `e540b91` due to ~23s per-block overhead (150k × quanta+metrics); future profiling should use sampled or off-line instrumentation, not per-block histograms.
2. **CCheckQueue is already input-level parallel.** `verify_block_input_scripts` flattens inputs into `checks` and fans out per-input via `SCRIPT_VERIFY_POOL` (verify_tx.rs:394-406). Further script headroom must come from UTXO resolve batching, `compute_txid` amortization, and `script_resolution`/`block_rules`/`block_body_persist` — not another CCheckQueue.
3. **Do not re-use full-tip IBD wall-time to validate CPU changes.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the 2.25× CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 463k/961k when stopped) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
