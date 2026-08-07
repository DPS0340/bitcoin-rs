---
title: Parallel granularity beat parallel width — 3.1x self-improvement, but a matched pair puts Core 2.2x ahead
date: 2026-08-07
category: docs/solutions/performance-issues
module: node apply path (crates/node/src/apply.rs, crates/consensus/src/verify_tx.rs)
problem_type: performance_issue
component: apply
severity: medium
applies_when:
  - "Measuring processing-bound 0→150k replay with full verification (assume_valid_height=0)"
  - "Optimizing txid computation or script verification preparation"
  - "Adding, removing, or tuning a rayon fan-out on the block apply path"
related_components:
  - consensus
  - utxo
tags:
  - txid
  - parallelization
  - rayon-granularity
  - processing-bound
  - replay
---

# Parallel *granularity* beat parallel *width* — 3.11× self-improvement, and a matched pair puts Core 2.22× ahead

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
| bitcoin-rs | threshold change | 135.0s median (135.0, 134.0, 140.6) | 1111 | 226 MB | `taskset -c 0-31` 3× (`/tmp/rfin-*.json`) | + parallel threshold 16 → 4 |
| bitcoin-rs | serial prevout resolve | **125.4s median** (124.1, 125.4, 128.4) | **1196** | 226 MB | `taskset -c 0-31` 3× paired (`/tmp/rp2-0-*.json`) | + both UTXO resolve stages serial |
| Core 31.0 | — | ~~67s~~ **superseded** | 2240 | n/a | 2026-06-09 debug.log, unknown load | do not quote; re-derived below |
| Core 31.0 | — | **59.6s median** (59.6, 59.4, 60.2) | 2517 | n/a | `taskset -c 0-31` 3× interleaved with rs, same idle host | `-reindex-chainstate -assumevalid=0 -connect=0 -stopatheight=150000` |
| bitcoin-rs | matched pair | **132.2s median** (132.2, 134.5, 131.6) | 1135 | 226 MB | same interleaved series | apply 95.3s; the rest is REST fetch |

**Quote the matched pair, not a cross-run ratio: 132.2s vs 59.6s = 2.22×** (1.60× comparing our apply alone against Core's whole run). Total self-improvement over the `4700c25` baseline is **3.11×**.

Core's own stage decomposition over the identical window (`-debug=bench`, aggregated from its log lines), recorded so nobody re-derives it:

| Core stage | Cost |
|---|---|
| `Verify N txins` (2,868,199 inputs) | 36.07s |
| Load block from disk | 7.18s |
| Fork checks | 3.25s |
| Flush | 2.59s |
| Connect postprocess | 1.63s |
| Sanity checks | 1.41s |
| **Connect block total** | **55.80s** |

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

## The matched pair — the only ratio worth quoting

Every earlier ratio in this note compared a bitcoin-rs median against Core's **67s** figure captured on 2026-06-09 under unknown load. That reference has now been re-derived, and the honest numbers are worse than the ones this document previously carried.

Core re-run from the same `core-datadir-reindex` that produced the original figure, same command (`-reindex-chainstate -assumevalid=0 -connect=0 -stopatheight=150000`), pinned `taskset -c 0-31`, 150,001 UpdateTip lines each time: **63.5 / 60.0 / 60.1s**. The old 67s was conservative.

Then both nodes interleaved back-to-back on the same idle host, so neither gets a quieter machine:

| Node | Runs | Median | Ratio |
|---|---|---|---|
| Core 31.0 | 59.6 / 59.4 / 60.2s | **59.6s** | 1.00× |
| bitcoin-rs | 132.2 / 134.5 / 131.6s | **132.2s** | **2.22× slower** |
| bitcoin-rs, apply only | 95.3s median | **95.3s** | **1.60× slower** |

Two corrections fall out of this:

1. **The gap is 2.22×, not the 1.87× computed from a best-case rs run against a stale Core reference.** Comparing your best run to someone else's old run is not a measurement. Interleave, or do not quote a ratio.
2. **Harness cost is larger than the 22.4s quoted below.** Measured back-to-back, rs spends ~37s outside apply, because the `bitcoind` serving REST competes for the same cores. Core reads local `blk` files and pays nothing equivalent. Apply-only (1.60×) is the fair engine comparison; total (2.22×) is what a user experiences from this harness.

Core reaches this with **15** script threads (`MAX_SCRIPTCHECK_THREADS`) against our 32, which makes the gap a per-unit-work gap rather than a parallelism gap. That is the shape of the remaining problem.

## Core's crypto is not faster — ours is surrounded by work Core never does

Core re-run with `-debug=bench` over the identical window, aggregating its own stage lines:

| Core stage | Cost |
|---|---|
| `Verify N txins` (2,868,199 inputs) | **36.07s** |
| Load block from disk | 7.18s |
| Fork checks | 3.25s |
| Flush | 2.59s |
| Connect postprocess | 1.63s |
| Sanity checks | 1.41s |
| **Connect block (total)** | **55.80s** |

Our `script_parallel` is **36.42s**. Core's `Verify txins` is **36.07s**. Within a percent of each other, on the same inputs, through the same libsecp256k1. **The crypto is a tie.**

That kills three hypotheses at once, and they should not be re-opened without new evidence:

* **Not the signature cache.** Core's `CachingTransactionSignatureChecker` and CuckooCache sigcache cannot be worth much here, because Core's measured verify time already equals ours. There is no hidden 2× being saved by cache hits.
* **Not compiler tuning.** The kernel is built `-O2 -g` with no `-march` (generic x86-64), and it still matches Core. `-C target-cpu=native` on the Rust side measured 1.016×. Build flags are not where the gap lives.
* **Not parallel width.** Core reaches this with 15 script threads against our 32, and still ties on verify.

The gap is the ~40s of apply that is **not** crypto:

| | Core | bitcoin-rs | Delta |
|---|---|---|---|
| script verify | 36.07s | 36.42s | ~0 |
| transaction marshalling (`script_prepare`) | none | 18.6s | **+18.6s** |
| txid computation | free during deserialization | 10.3s | **+10.3s** |
| remaining apply | 16.1s | 23.9s | +7.8s |
| total | 55.8s | 95.3s | +39.5s |

Core never pays the first two. It deserializes each block once into `CTransaction` objects and validates those in place; the txid falls out of deserialization, and `PrecomputedTransactionData` is built over objects it already holds. We decode raw bytes into `bitcoin::Transaction`, then `encode::serialize` every transaction back into bytes so `bitcoinkernel::Transaction::new` can parse it a **third** time.

So the marshalling class closed earlier was closed at the wrong altitude. Four micro-optimizations inside that round-trip each measured 0.98-1.00×, and that remains true: shaving allocations off a redundant round-trip cannot pay. Removing the round-trip is a different change, and it is now quantified at **~29s of the 39.5s gap**. That is the only lever left that is worth its risk.

## The marshalling refactor: first closed wrongly, then reopened by a better measurement

The obvious conclusion from the table above is "stop round-tripping transactions through Rust structs: parse the block once with `bitcoinkernel::Block::new` and validate `block.transaction(i)` in place." The API supports it — `TransactionRef<'a>` is `Send + Sync` and implements `TransactionExt` — at the cost of threading a block lifetime through `PreparedTx`, `prepare_block_input_checks`, `verify_block_input_scripts`, and `PreparedKernelTx` across three crates.

It is not worth doing. Sub-stage probes inside `prepare_kernel_tx` split the 19.2s prepare stage:

| Sub-stage | Cost | Fate under the refactor |
|---|---|---|
| `encode::serialize` (per tx) | **2.74s** | removed |
| `bitcoinkernel::Transaction::new` (1.7M calls) | **9.67s** | replaced |
| `PrecomputedTransactionData::new` | 2.61s | stays |
| other | 2.84s | stays |

The replacement is not free, and that is the whole point. Timing one `bitcoinkernel::Block::new` per block over the same bytes:

```
per-tx serialize + parse   12.42s   (removed)
whole-block Block::new     10.88s   (added, 150k calls)
                         --------
net                        +1.54s   (1.1% of a 138s run)
```

`Block::new` is more expensive per byte than the 1.7M individual `Transaction::new` calls it would replace, so on those two line items alone the refactor loses.

**That accounting was wrong, and the correction reverses the verdict.** It priced only the parse and the serialize, and ignored that `Block::new` *also* produces every txid as a side effect: Core's `CTransaction` hashes itself during deserialization, so `TransactionExt::txid()` is a getter over an already-computed hash. And it computes it with the implementation Core selects at runtime, which this host logs as:

```
Using the 'sse4(1way);sse41(4way);avx2(8way)' SHA256 implementation
```

That is a software **AVX2 8-way multi-buffer** SHA-256, already linked into this binary through `libbitcoinkernel`. Our `compute_txid` uses `bitcoin_hashes`' scalar SHA-256. The earlier note here that beating it would need "a cryptographic-library project" was wrong — the library is already a dependency.

Timing `Block::new` plus harvesting every txid from it, and checking each against the `tx_plan` txids:

```
Block::new + harvest all txids   10.93s   (150k blocks, 1.7M txids, 0 mismatches)

replaces:
  compute_txid (scalar SHA-256)  10.30s
  encode::serialize               2.74s
  Transaction::new                9.67s
                                --------
                                 22.71s
net                              -11.78s   (~1.10x on a 132s run)
```

Zero mismatches over 1.7M transactions, so the kernel txids are consensus-identical to rust-bitcoin's.

**This is the largest remaining lever and it is worth its refactor**, because one `Block::new` retires three separate costs at once. The shape: parse the block once in `apply_block_inner`, harvest txids from it instead of calling `plan_block_transactions`' hasher, and pass `&Block` down through `verify_block_transactions` → `verify_block_input_scripts` → `prepare_block_input_checks` so `PreparedKernelTx` can hold a `TransactionRef<'block>` instead of re-serializing. Lifetimes flow as ordinary parameters, so nothing is self-referential.

The lesson generalizes past this case: **price a replacement by everything it subsumes, not by the line item that motivated it.** Costed against parse-and-serialize the change looks like +1.54s; costed against parse, serialize, and hash it is -11.78s.

Probe methodology, for anyone repeating this: the probes were `AtomicU64` nanosecond accumulators exported from `crates/consensus/src/kernel.rs` and printed by the replay example, all reverted afterwards. They are cheap enough to leave in during a measurement run (138.2s probed against a ~132s unprobed median, most of that ordinary drift).

## What the remaining apply time is

Two temporary probes (removed after measurement) attributed the last unmeasured slice of apply. They cost nothing detectable — the probed run measured 123.3s and 126.0s against a 124.2s unprobed median — which **retires the earlier claim that per-block histograms cost ~23s**. That figure came from a contaminated run; the apply path already carries 13 per-block histograms, so two more are free at this scale.

| Component | Cost | Note |
|---|---|---|
| `script_parallel` | 36.4s | secp256k1, already input-parallel at threshold 4 |
| `script_prepare` | 18.6s | kernel serialize + `PrecomputedTransactionData`, serial on purpose |
| `plan_block_transactions` (txid) | 10.3s | `compute_txid` streams into the hash engine, no intermediate `Vec` |
| named non-script apply | 19.5s | `utxo_commit` 6.1s, `block_rules` 5.3s, `block_body_persist` 4.1s |
| `ResolvedUtxoView::resolve` | 2.8s | now serial |
| `script_resolution` | 1.6s | now serial |
| genuinely unmeasured | 2.0s | |

Txid is the largest single item outside script verification, and it splits into two parts that are each already near their floor:

* **Feeding the hasher (~2.7s).** `compute_txid` streams `consensus_encode` into the engine with no intermediate `Vec`. The proposal to hash the raw transaction bytes instead — the `bitcoin_slices` approach already used by `crates/index` — removes exactly this encode step. Its size is bounded directly: `encode::serialize` over the same 687 MB of transactions measured **2.74s**. That is the whole prize, and it is under the 1.05× gate on a 132s run.
* **The hash itself (~7.6s).** 687 MB hashed twice at roughly 200 MB/s per core is the remainder, and it is identical whichever way the bytes arrive. Only SIMD or hardware SHA changes it, and this host cannot: the Xeon Gold 6138 is Skylake-SP with **no `sha_ni`**, only AVX2/AVX512F. A software AVX2 multi-buffer SHA-256 across independent transactions is the only remaining path, and that is a cryptographic-library project, not a node change.

Txid also does not respond to parallelism — the threshold swept flat — because the bytes are concentrated in later blocks that already exceed the 32-tx parallel threshold.

**`-C target-cpu=native` is real but too small to ship.** The build sets no `target-cpu`, so it is generic x86-64. Rebuilding native and pairing 3× against generic: **132.0s vs 129.9s (1.016×)**, native winning all three rounds, with apply alone 96.8s → 90.8s (~1.066×). The whole-run figure misses the gate because roughly 22s of the run is REST fetch that codegen cannot touch. It is deliberately **not** made the default: the binary would be pinned to this CPU. Use it only as a documented opt-in for a known host.

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

   **The threshold lesson does not generalize to `plan_block_transactions`.** The obvious follow-up — `apply.rs:985` parallelizes txid computation only above 32 txs, the same too-high-threshold shape — was swept and rejected: 1 → 139.8s, 4 → 138.1s, 16 → 141.9s, 32 → 136.4s, every value inside the ±5% single-run noise with the incumbent 32 nominally best. A txid is one SHA256d (order 1 µs) while a script check is order 100 µs, so per-item work decides whether a fan-out pays. Check the item cost before assuming a low threshold wins.
4. **Unnecessary parallelism is its own cost class — audit fan-outs by per-item work.** Two rayon fan-outs over UTXO lookups were pure loss, because a sharded hashmap hit is order 500 ns while a rayon dispatch is more. Removing them, each measured as pinned 3× medians with parallel and serial interleaved and serial winning every round:

   | Fan-out | Parallel | Serial | Stage effect |
   |---|---|---|---|
   | `ResolvedUtxoView::resolve` (`into_par_iter`, no threshold) | 143.8s | 134.7s | apply 116.2s → 103.6s |
   | `resolve_block_prevouts` non-overlay branch (`par_iter` per tx) | 139.4s | 125.4s | `script_resolution` 6.9s → 1.63s |

   **A stage-local win can be a global loss — always gate on elapsed, never on the stage.** Parallel prepare (`0302a0c`, reverted `6d9c3b8`) was re-tested at the current balance, because the original rejection was measured at threshold 16 with both resolve stages still parallel. It makes its own stage measurably faster and the run measurably slower:

   | | prepare stage | apply | elapsed |
   |---|---|---|---|
   | serial prepare | 17.7-18.5s | 92.3-95.3s | **124.2s** |
   | parallel prepare | 12.8-14.0s | 98.9-101.6s | 129.0s |

   It buys ~5s in `script_prepare` and gives back ~7s across the rest of apply, because its threads contend with the script-verify pool for the same cores. Reading `script_prepare_seconds` alone would have shipped a 4% regression as a 30% stage win. This re-confirms the original verdict and supplies the mechanism it lacked; prepare stays serial.

   The clearest evidence for the removal class: 5.3s of dispatch layered on 1.6s of work. This is the mirror of the threshold finding — there the fix was *more* parallelism for 100 µs script checks, here it is *none* for 500 ns lookups. Same question either way: does per-item work exceed dispatch? Distinct from the marshalling class closed above, which was about removing allocations rather than removing threads. Remaining fan-outs and their verdicts: `verify_block_input_scripts` (keep, ~100 µs per input), `UtxoSet::commit` over shards (keep, a batch write per item), `plan_block_transactions` (keep, swept flat).
5. **Per-block histograms are cheap here — the earlier warning was wrong.** `txid_plan_seconds`/`utxo_resolve_seconds` (added `68bbb2f`, reverted `e540b91`) were blamed for ~23s, but that run was contaminated by a concurrent full-tip IBD. Re-probing the same two stages on a quiet host cost nothing measurable (123.3s and 126.0s against a 124.2s unprobed median). The apply path already records 13 per-block histograms; two more do not move the number. Probe freely, but re-measure unprobed before quoting a figure.
6. **Do not re-use full-tip IBD wall-time to validate CPU changes.** IBD is download-bandwidth-bound (`multi-peer-block-download-requires-core-stalling-disconnect.md:41` apply 50–250× faster than single-peer download); the CPU win is invisible in IBD. Use the processing-bound replay (full verification) for CPU work, and the local-fixture full-tip IBD (`full-tip-rs-assumevalid.toml` 938343, `bitcoin-rs-fulltip-postopt-local3` at 463k/961k when stopped) only for the complementary bandwidth regime.

## Related

* `small-window-benchmarks-do-not-predict-at-scale-throughput.md` — correct harness; supersedes 0→1000 window
* `multi-peer-block-download-requires-core-stalling-disconnect.md` — download-bound regime analysis
* `script-verification-delegated-to-core-c-no-rust-headroom.md:66` — “UTXO caching, input preparation, storage commits” as Rust-side lever
* `processing-bound-150k-verdict.md` (bench results) — original 389.7s vs 67s baseline superseded by this measurement for the `f76d43a` line
