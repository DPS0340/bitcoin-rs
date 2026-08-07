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

# Script-verify parallel *granularity* was the binding constraint — 389.7s → 135.0s (2.89×), Core still leads 2.01×

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
| bitcoin-rs | `0e2dda5` | 157.8s median (163.8, 155.9, 157.8) | 950 | 223 MB | `taskset -c 0-31` 3× (`/tmp/replay-t32-*.json`) | + 32-thread script-verify pool |
| bitcoin-rs | this change | **135.0s median** (135.0, 134.0, 140.6) | **1111** | 226 MB | `taskset -c 0-31` 3× (`/tmp/rfin-*.json`) | + parallel threshold 16 → 4 |
| Core 31.0 | — | 67s | 2240 | n/a | `-reindex-chainstate -assumevalid=0 -connect=0` debug.log | |

Gap to Core: **5.8× → 2.01×** (135.0/67). Total win over the `4700c25` baseline is **2.89×**. Remaining gap is 68.0s.

**Pool width was only half of it.** Widening the pool 16 → 32 bought 1.10×, but the pool cannot help a block that never reaches it: `MIN_PARALLEL_SCRIPT_CHECKS` sent every block with fewer than 16 input checks down the serial branch, and on mainnet 0→150k that is most of them. Lowering the threshold to 4 bought a further **1.15×** and cut `script_verify` 84.0s → 66.5s. The sweep is steep and monotonic above the optimum (`taskset -c 0-31`, 3× medians for 4/8/16 interleaved round-robin so cache warming hits each equally; single runs above):

| Threshold | 4 | 8 | 16 | 48 | 128 | 512 |
|---|---|---|---|---|---|---|
| Elapsed | **139.4s** | 145.1s | 155.8s | 185.0s | 234.6s | 297.3s |

Threshold 2 measured 143.8s, so the optimum is a genuine interior minimum at 4, not "as low as possible". The ordering 4 < 8 < 16 held in all three interleaved rounds.

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

**Pinning is load control, not a core handicap.** The same `0e2dda5` build run *unpinned* on all 80 CPUs measures **190.7s** (188.0, 190.7, 191.5) — 21% *slower* than the pinned 157.8s — because this box is shared and carried load average 7.7–18.5 during the run. Giving the replay every CPU means contending for them; pinning 32 gives it 32 it mostly keeps. So `taskset -c 0-31` is the reproducible measurement, not an artificial handicap, and any cross-node ratio quoted from an unpinned run on a busy host is contention noise. The corollary matters for the Core comparison: **Core's 67s reference was captured at another time under unknown load**, so the 2.36×/1.92× figures carry that uncertainty on both sides and should be re-derived from a back-to-back idle-host pair before anyone treats them as final.

An earlier instrumented run (`53feecb`, 201.84s) attributed the then-uninstrumented remainder to `utxo_resolve` 25.7s and `txid_plan` 21.6s, but that run was contaminated (concurrent full-tip IBD writing `blk00817→867`) **and** inflated ~23s by the per-block histograms themselves. Treat its absolute numbers as indicative only; the clean decomposition above supersedes it.

**Levers tried and rejected on clean `taskset -c 0-31` 3× medians (all against the 173.1s serial baseline):**

| Change | Median | Speedup | Verdict |
|---|---|---|---|
| Parallel `prepare_block_input_checks` (`0302a0c`) | 173.5s (170.6/173.5/173.9) | 1.00× | rejected — reverted `6d9c3b8` |
| Thread-local serialize buffer in `prepare_kernel_tx` (avoids per-tx `encode::serialize` alloc) | 173.2s (173.2/173.9/172.4) | 1.00× | rejected — `script_prepare` 20.4s → 18.2s but total unchanged |
| Skip `kernel_txout` construction for witness-free txs (empty `spent_outputs` to `PrecomputedTransactionData`) | not benchmarked | — | **rejected by tests**: kernel returns `Script verification error: Spent outputs required for verification`. Core's `Init` computes no midstates without a witness, but `btck_script_pubkey_verify` still gates on `m_spent_outputs_ready`, so the prevout `TxOut` objects must be built even when never hashed |
| Feed kernel the block's already-serialized tx byte ranges instead of re-serializing | not implemented | ~1.01× (costed) | rejected on analysis — the replay moves 687 MB of tx bytes, so removing the Rust serialize entirely is order 1–2s of 173s, bounded empirically by the buffer result above (2.2s off the stage → 0.1s off the total) |
| Retain kernel `TxOut` objects in `PreparedKernelTx` and borrow `script_pubkey()`/`value()` per input, instead of rebuilding an FFI `ScriptPubkey` for each of ~3.3M inputs | 160.3s (164.1/160.3/159.7) vs **157.8s** | 0.98× | rejected — `script_parallel` 55.2s → 56.1s (no gain) and RSS 212 → 226 MB. Holding the prevout objects across the whole verify phase costs more in residency than the eliminated `malloc`+copy saves |

The first two cleared the tests but not the 1.05× noise floor; the third never got that far. `script_prepare` is real work inside `libbitcoinkernel`, not Rust-side overhead. Even eliminating **all** of prepare leaves ~153s against Core's 67s, so prepare is not where the gap lives. `ResolvedUtxoView::resolve` (25.69s) is likewise **already parallel** (`apply.rs:1136` `into_par_iter`), so it is not a batching target either.

The fourth result retires the "FFI boundary is the remaining lever" hypothesis for its allocation half. Per-input `ScriptPubkey::new` is a ~25-byte `malloc` plus copy; at 3.3M inputs that is real allocator traffic, and removing it entirely changed nothing measurable. What the kernel spends inside `btck_script_pubkey_verify` is secp256k1 work, not marshalling. Marshalling-side micro-optimization is now closed as a class: four separate attempts (parallel prepare, serialize buffer, witness-free skip, prevout reuse) all landed at 0.98–1.00×.

## Guidance

1. **Attribute a stage by disabling it, not by reading a profiler.** `perf` was unavailable here (`perf_event_paranoid=4`, no sudo), but the open question — is `script_parallel`'s ~0.93 ms/block genuine secp256k1 work or rayon dispatch overhead? — is binary, so forcing `MIN_PARALLEL_SCRIPT_CHECKS = usize::MAX` answered it in one run: the replay went 173.1s → **313.3s** and the stage 63s → **227.6s**. Genuine crypto. That immediately reframed the number: 227.6s → 63s is only **3.6× from a 16-thread pool**, so the pool width was the binding constraint, and widening it to 32 bought 1.10× (`0e2dda5`). Prefer this disable-the-stage technique whenever a hypothesis is binary; it needs no tooling and cannot be argued with.
2. **The prepare and marshalling phases are closed — do not reopen them.** Prepare is ~20s of the run; zeroing it entirely still leaves ~138s against Core's 67s. Five candidates are closed (table above): three by benchmark, one by tests (`btck_script_pubkey_verify` gates on `m_spent_outputs_ready`, so prevout `TxOut`s must be built even when nothing hashes them), one by cost analysis. `ResolvedUtxoView::resolve` is already `into_par_iter` (`apply.rs:1136`) and `plan_block_transactions` already `par_iter` above 32 txs (`apply.rs:985`), so neither is a target either.
3. **Pool width has a measured optimum at 32 on this host — do not raise it further.** The sweep is non-monotonic:

   | Pool | CPU set | Median | `script_parallel` |
   |---|---|---|---|
   | 16 | 32 physical (`0-31`) | 173.1s | 63-65s |
   | **32** | 32 physical (`0-31`) | **157.8s** | 55.2s |
   | 32 | 16 physical + SMT siblings (`0-15,40-55`) | 158.9s | 63.9s |
   | 64 | 64 logical (`0-63`) | 177.9s | 60.2s |

   64 threads is *worse than 16* — coordination and oversubscription on ~22-input blocks cost more than the extra width buys. A different machine needs its own sweep; the constant stays a cap rather than `available_parallelism` so verification cannot starve the rest of the pipeline. Beyond width, the often-proposed structural lever is holding kernel objects across the block (`bitcoinkernel::Block::new` once, then `block.transaction(i)`) instead of reconstructing per transaction. Treat that as unproven and probably weak: the prevout-reuse experiment above tested exactly the retain-kernel-objects-longer half of it and came back 0.98× with +14 MB RSS, because kernel object residency is itself a cost. Any future attempt must show it removes *work*, not just allocations, and must be measured before the cross-crate API change is written.

   **Width was re-swept after the threshold moved to 4 and did not move.** The two constants interact — a lower threshold sends far more blocks to the pool — so the width result was re-derived rather than assumed. On `taskset -c 0-31`: width 16 → 152.7s, width 32 → 139.6s. Values above 32 are unmeasurable under that pin, because `available_parallelism()` reports 32 and `available.min(cap)` clamps them; runs at 48/64/80 returned 141.0/147.2/144.0s, which are replicates of 32 and put single-run noise at roughly ±5%. Given a genuinely wider CPU set (`taskset -c 0-63`), width 32 and width 64 tie (159.8/162.2s vs 159.7/158.0s) and *both* lose ~15% to the 0-31 pin from host contention. So 32 is the optimum at either threshold, and the way to test a wider pool is a wider `taskset`, not a larger constant.
4. **Do not re-profile with per-block histograms.** `txid_plan_seconds`/`utxo_resolve_seconds` (added `68bbb2f`, reverted `e540b91`) cost ~23s over 150k blocks — 13% of the measurement they were meant to explain. Use sampled or off-line profiling.
5. **Do not re-use full-tip IBD wall-time to validate CPU changes.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 463k/961k when stopped) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
