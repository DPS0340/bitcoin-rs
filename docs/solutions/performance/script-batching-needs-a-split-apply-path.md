# Cross-block script batching: reverted once, then shipped

Status: **shipped.** The first attempt was a wash and was reverted; the second,
built on a split apply path so preparation happens once, holds up.

Current shipped capture:

| blocks 0..150,000, full verification | wall | CPU |
|---|---|---|
| Bitcoin Core 31.0 | 60.7s | 466.5s |
| bitcoin-rs after | **69.6s** | **558.4s** |

Historical pre-batching capture:

| blocks 0..150,000, full verification | wall | CPU |
|---|---|---|
| Bitcoin Core 31.0 | 61.2s | 470.7s |
| bitcoin-rs before | 78.4s | 643.4s |

Each panel reports the median of its own three interleaved pairs, pinned to
`taskset -c 0-31`. The captures are separate and must not be combined as one
run. In the current capture, Core leads by 1.15x on wall and 1.20x on CPU. In
the historical capture, it led by 1.28x and 1.37x.

Script verification inside apply fell from 49.26s to 6.91s, and the dispatch it
replaced from 44.08s across 21,474 fan-outs to 12.55s across 2,343.

The rest of this note is why the first attempt failed and what the second had to
do differently. It is kept because the failure is more instructive than the
success.

## The gap

The historical pre-batching panel measured the original cross-node gap. Its
78.4s bitcoin-rs value is a benchmark median, not the same run as the 77.5s
instrumented profile below.

## Where our time goes

In that separate 77.5s instrumented run, script verification took 49.26s
(63.6%). Inside it:

| | |
|---|---|
| input checks | 2,868,199 |
| single-threaded cost of those checks | 199.1s |
| mean cost per check | **69.4 us** |
| raw `secp256k1` ECDSA verify on this host | **38.25 us** |

An earlier version of this note claimed 69.4 us *is* the crypto floor and that
no per-input overhead exists. That was wrong twice over, and both errors are
worth naming because they are the same mistake in different clothes.

First, the floor was asserted from recalled typical timings rather than
measured. Measured here, a single `secp256k1` ECDSA verification takes
**38.25 us** (20,000 rounds, release build, same host).

Second, and more importantly, **the two numbers cannot simply be subtracted.**
One input check is not one signature verification: an input may perform none
(anyone-can-spend), one (P2PKH, P2PK), or several (bare multisig), and it also
pays script parsing, interpretation, and a legacy sighash that re-serializes
the spending transaction. Dividing one by the other, or subtracting them to
get a per-input overhead, assumes a signature count nobody has counted.

So the honest position is narrower than the original claim and narrower than
its first correction: **the per-check cost and the per-verification cost are
both measured, and the relationship between them is not yet established.**

## The open question this leaves

Count the actual `CHECKSIG` / `CHECKMULTISIG` operations executed across the
window, then compare like with like: run the same captured input corpus through
the verifier and through a bare signature loop. Only that answers whether the
per-check cost is near its floor or well above it. Until it does, no conclusion
about per-input overhead is supportable in either direction.

What IS established by direct measurement, independent of any of the above:
199.1s of check work becomes 45.66s on 32 threads, a **4.4x speedup**, and
enlarging the dispatch 64-fold cuts that stage 3.5x. Those are the numbers the
rest of this note rests on.

That 4.4x decomposes:

| | checks | blocks | cost |
|---|---|---|---|
| below `MIN_PARALLEL_SCRIPT_CHECKS` (32), fully serial | 417,394 (14.6%) | 46,417 | ~29s |
| above it, 10.2x on 32 threads | 2,450,805 | 21,474 | ~16.7s, of which ~11s is dispatch |

A block in the parallel row carries about 114 input checks. Fanning those items
across 32 workers costs more in wakeups than the work being spread.

## Four hypotheses, all refuted by measurement

Do not retry these.

| Hypothesis | Result |
|---|---|
| rayon `with_min_len(N)` to coarsen jobs | N=4 105.3s, N=8 132.1s, N=16 184.1s vs N=1 77.6s. Throttles the big blocks that were scaling fine. |
| Bounded split for small blocks only (2/4/8 tasks below the threshold) | 120.4s / 102.0s / 98.2s vs 79.1s serial. Dispatching tiny blocks costs more than the serial work it saves. |
| Per-input FFI overhead in the kernel path | Not refuted, and not established either. See the open question above: the per-check cost is measured, the per-verification cost is measured, and the signature count that would relate them is not. |
| Script pool width | 1 thread 334.8s, 4 threads 185.4s, 32 threads 81.1s. 32 is the measured optimum; 8, 16 and 64 were worse in an earlier sweep. |

The shape of these results is consistent: rayon's default splitting is already
right, and the problem is not *how* each dispatch splits but *how many*
dispatches there are.

## What was built, and what it proved

Batch the input checks of 64 consecutive blocks into one dispatch:

1. Capture each block's height, verify flags, and locktime cutoff **before any
   block applies**, because applying inserts headers into the shared block tree
   and would move median-time-past and softfork state under the later blocks.
2. Resolve every block's prevouts through one **ordered live overlay** that
   walks blocks, then transactions, then inputs, spending before creating.
3. Prepare each block, concatenate the checks, run **one** parallel dispatch.
4. Issue an ephemeral per-block proof only if every check passes.
5. Apply blocks normally; script execution is skipped only where a proof
   matches the hash, height, flags, cutoff, and predecessor the apply computes.

It worked, and the tip hash at 150_000 was correct:

| | before | after |
|---|---|---|
| `script_verify` inside apply | 49.26s | **6.70s** |
| crypto dispatch | 44.08s across 21,474 dispatches | **12.53s across 2,343** |

**31.5 seconds of dispatch overhead, removed.**

## Why it did not pay

Wall time did not move: 79.3s against a 78.4s baseline.

| batch stage | cost |
|---|---|
| verify (the crypto) | 12.53s |
| resolve | 12.35s |
| kernel parse | 6.12s |
| prepare | 4.05s |

The listed stages total 35.05s. A separate aggregate batch timer recorded
41.9s.

The batch resolves every prevout and parses every block, and then `apply_block`
does both again for its own purposes: the resolved view feeds coinbase
maturity, BIP68, and the UTXO change set, not just scripts. Apply fell from
71.80s to 36.08s, a 35.72s saving bought for 41.9s.

## The shape that would work

The front half of `apply_block_inner` must run **once**, not twice. That means
splitting it:

```text
prepare_apply(block, captured_context) -> PreparedApply   // resolve, parse, plan
commit_apply(PreparedApply)                                // utxo, index, tip
```

A window then runs every `prepare_apply` against the ordered overlay, one batch
verify, then every `commit_apply` in order. No duplication, and the 31.5s win
survives. Rough arithmetic puts that near 60s, so it is worth doing and it is
not a tweak: it is a restructuring of the consensus-critical apply path and
deserves its own effort with its own tests.

There is no cheaper variant. Block `w+1`'s front half needs `w`'s committed
state, which is precisely what the overlay substitutes for, so the front half
cannot be hoisted without the overlay and cannot be shared without the split.

## Where the time goes now

| stage | seconds |
|---|---|
| apply (all blocks, everything but scripts) | 26.51 |
| script dispatch | 12.55 |
| window preparation (kernel parse, tx plan, resolution) | 11.28 |
| check preparation | 5.09 |
| decode | 3.2 |

The dispatch is no longer the largest term, which is the point. Closing the
remaining ~9s means broad work across apply's own stages, not one more
structural change.

## What was kept from the first attempt

Nothing. The building blocks were correct and mutation-verified, but without a
caller they are scaffolding, and a wired version that costs what it saves is
worse than neither. Two pieces are worth rebuilding verbatim when the split
lands, and both survived adversarial review:

- **The ordered overlay.** A prepopulated map of every window output resolves
  outputs *before the transaction that creates them*, which a red-team review
  caught. The walk must lookup, then spend, then create, per transaction. The
  test that pins this is a forward reference: block 1 spending an output only
  block 2 creates must miss, and prepopulating makes that test pass wrongly.
- **Earliest-block-first error ordering.** Slice each unit's results from a
  precomputed offset table, never a running counter. With a counter, reversing
  the scan misaligns every slice instead of reporting a different block, so the
  ordering test passes for the wrong reason. This was found by mutation, not by
  reading.

## The reviewed design for the next attempt

A planner and an adversarial reviewer both examined the prepare/commit split.
Verdict: feasible, and **ship-with-mitigations** — with the invariants below
enforced, the reviewer could not construct a consensus divergence.

### The rule that collapses the error-ordering risk

Treat the captured per-block context (height, median-time-past, softfork state,
locktime cutoff, verify flags, predecessor) as a **hypothesis**. `commit_apply`
re-derives it from committed state and compares. Any mismatch, any batch
failure, an assume-valid block, or a coinbase-only block degrades to
`ScriptOutcome::Unverified`, under which commit runs today's
`verify_block_transactions` unchanged.

One rule, and the entire "did the batch change which error surfaces" class
disappears: on any doubt the block takes the path it takes today.

### The cut line

Only four stages move to prepare, and they are exactly the measured
duplication: `KernelBlock::parse` (6.12s), `plan_block_transactions_with_txids`,
`ResolvedUtxoView::resolve` (12.35s, the only step whose *source* changes), and
per-transaction script-check preparation. Everything else stays in commit in
today's order, so error identity is preserved by construction rather than by
argument.

Two placements are load-bearing rather than incidental:

- **The admission guard is taken once per window.** `ApplyAdmission::enter`
  returns a `parking_lot` read guard; nesting two while `close()` waits on the
  write side can deadlock. `commit_apply` must not re-enter.
- **`applied_predecessor` stays in commit.** It is the guard that catches an
  interloping applier: any foreign apply moves `applied_tip` and produces a
  predecessor mismatch before a stale overlay can be acted on.

### Three defects the plan found in the proposal

1. `PreparedApply` **cannot** own the `KernelBlock` and the `PreparedTx<'b>`
   values borrowed from it in one struct — that is self-referential. The
   borrows must live in a sibling collection dropped before commit.
2. The overlay must reproduce `build_utxo_changes`'s skip rules — OP_RETURN,
   scripts over `MAX_SCRIPT_SIZE`, same-block-spent, genesis — or it is not
   equivalent for the undo record, BIP68, or coinbase maturity.
3. Every window block's header must already be in the `BlockTree`. Production
   sync satisfies this by construction; the replay driver does not and must
   insert them first, exactly as header-first sync does.

### The six invariants the reviewer requires

1. **Point-in-time per-block resolved maps.** Emit each block's map at the
   moment its inputs resolve — resolve, then spend, then create, per
   transaction. Never derive a per-block map from the overlay's final state, or
   an output created by A and spent by B is absent when B's undo record needs
   it.
2. **True per-block predecessor for BIP68.** Time-based relative locks need the
   median-time-past at `creation_height - 1`, walked from the block's actual
   predecessor. During a window that predecessor may itself be unapplied, so
   capture its node identity from the window's header chain, not from
   `applied_tip`.
3. **BIP30 stays in commit**, ordered, querying the real UTXO set. An earlier
   window block may spend the last live output of a reused txid, which makes a
   later reuse legal; a stale snapshot gets that backwards in both directions.
4. **Single-use proofs, revalidated against the current applied tip** before any
   mutation. Non-cloneable, consumed once, never cached or requeued.
5. **Undo persisted immediately before its own block's commit**, preserving the
   existing undo-before-mutation ordering.
6. **Any failure destroys the failed block and the entire prepared suffix.**
   Commit progress is the only progress. No `PreparedApply` survives a sync
   tick, a retry, a peer redelivery, or a reorg.

### Sequencing

Seven commits, each independently verifiable and green, with production sync
untouched until step 6 and a go/no-go measurement gate at step 5 requiring an
identical tip hash, an identical UTXO digest, and an identical coinstats MuHash
between `--window 1` and `--window 64`.

## Also corrected

The BIP30 duplicate-coinbase blocks are **91,842 and 91,880**. 91,722 and
91,812 are the originals they duplicate. Both duplicates are inside this
measurement window.
