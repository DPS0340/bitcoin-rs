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

Same machine (128 cores), serial runs, local REST blocks:

| Node | Commit | Elapsed 0→150k | blk/s | RSS high-water | Source |
|---|---|---|---|---|---|
| bitcoin-rs | `4700c25` | 389.7s | 385 | 2.36 GB | `processing-bound-150k-verdict.md` |
| bitcoin-rs | `f76d43a` | **178.93s** | **838** | **223 MB** | `~/bench-g14/results/replay-postopt-150k-f76d43a.json` (150001 blocks, 687 MB, `blocks_per_second 838.32`, `git_head f76d43a`) |
| Core 31.0 | — | 67s | 2240 | n/a | `-reindex-chainstate -assumevalid=0 -connect=0` debug.log |

Gap to Core halved: **5.8× → 2.67×**. Next gap is still 111.9s.

## Why Core still leads — stage decomposition of the 178.93s run

`node.apply_block.total_seconds` 156.06s dominates wall-clock (87% of elapsed; fetch 15.97s + decode 3.59s overlap partially via prefetch).

Accounted stages sum to 114.56s; **41.5s (26.6% of total) is uninstrumented** — outside all histograms (likely `plan_block_transactions` txid work + `ResolvedUtxoView::resolve` UTXO lookups, added as histograms after this measurement).

Instrumented breakdown (from `replay-postopt-150k-f76d43a.json:stage_seconds`):

* `script_verify 87.03s` (55.8% of total) — of which `prepare 18.09s` (serial per-transaction kernel setup in `verify_tx.rs:389` `prepare_block_input_checks`, no overlap with parallel phase) + `resolution 10.09s`
* `block_body_persist 11.23s`, `utxo_commit 6.91s`, `block_rules 4.53s`, `bip30_bip34 1.14s`, `block_tree_insert 1.10s`, remainder <1s each.

The 18s `prepare` is the actionable Rust-side target named in `script-verification-delegated-to-core-c-no-rust-headroom.md:66` (“UTXO caching, input preparation, storage commits”) — it runs serially before the `par_iter` fan-out in `verify_block_input_scripts:394-406`, which already implements the per-input CCheckQueue pattern (checks `par_iter`, not per-block). The verdict doc’s line 28 describing “rs parallelizes per-block via rayon” referred to pre-refactor `4700c25`, not the current `checks.par_iter()`.

## Guidance

1. **Profile the 41.5s uninstrumented gap before declaring blocked.** The 178.93s replay had 41.5s outside all histograms (likely `plan_block_transactions` txid work + `ResolvedUtxoView::resolve`). Histograms `node.apply_block.txid_plan_seconds` and `node.apply_block.utxo_resolve_seconds` are added in the follow-up change to this doc (crates/node/src/apply.rs:502,506); the next replay will be instrumented to attribute the gap before the next optimization.
2. **Next lever is not CCheckQueue — it is already input-level parallel.** `verify_block_input_scripts` flattens all inputs into `checks` and fans out per-input via `SCRIPT_VERIFY_POOL.install || par_iter` (verify_tx.rs:394-406). Further script-verification headroom must come from overlapping or parallelizing the `prepare` phase with the check phase, and from `script_resolution` / `block_rules` / `block_body_persist` batching.
3. **Do not re-use full-tip IBD wall-time to validate this CPU change.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the 2.18× CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 306k/961k) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
