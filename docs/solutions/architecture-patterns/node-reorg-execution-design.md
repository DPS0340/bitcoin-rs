---
title: Node-level reorg execution — the design, and why the two stores differ
date: 2026-08-08
category: docs/solutions/architecture-patterns
module: crates/node (apply path), crates/index, crates/utxo, crates/chain
problem_type: architecture_pattern
component: consensus
severity: high
applies_when:
  - "Implementing block disconnect / chain reorganization in the node"
  - "Deciding where the commit point of a multi-store mutation sits"
  - "Adding a consumer that must roll back when a block is disconnected"
related_components:
  - apply_path
  - utxo
  - index
tags:
  - reorg
  - undo-data
  - crash-recovery
  - commit-point
---

# Node-level reorg execution — the design, and why the two stores differ

## Status

**Layers 1-2 implemented. Layer 3 is a primitive with no caller. Layer 4 not
started.**

Done, all in `crates/node/src/apply.rs` unless noted:

* `ColumnFamily::UndoData` across all four backends, and a versioned undo codec
  bound to the block hash (`crates/utxo/src/undo_codec.rs`).
* Undo generation in the same pass as the forward UTXO changes, so the two
  cannot drift. `UndoStore` is a mandatory handle, not an `Option`, and the
  record is written before the block body, the index, and the UTXO commit.
* `disconnect_block`, which restores the UTXO set, the transaction index, and
  `applied_tip`. Its four ordering claims are mutation-verified.
* The index half: `IndexerLike::rollback_block` exists, is tested, and refuses
  by default rather than reporting a false success.

Not done: `bitcoin_rs_chain::plan_reorg` still has no production caller, and
`bin/bitcoin-rs/tests/gates/g10_reorg_deep.rs` is still `#[ignore]`d.

`disconnect_block` also has no production caller, deliberately. The derived
state connection touches is now accounted for and the answers were not uniform:
`coin_stats` needed an explicit inverse for its block-level fields only, the
filter index needed no rollback because its rows are hash-addressed, the
`blocks` RPC cache needed an opportunistic pop, and `transactions` needed
nothing because connection never populates it. What still blocks wiring is
recovery and routing, not derived state: the durable poison marker, returning a
disconnected block's transactions to the mempool, publishing a disconnect
notification, backfilling the filter index after a gap, and routing a block that
extends a known side branch. The function's own doc comment carries the same
table.

## Why it matters

A Bitcoin full node that cannot disconnect a block cannot follow the most-work
chain. Everything else — sync throughput, index correctness, mempool policy —
is downstream of being on the right chain.

## The two stores have different crash models

This is the load-bearing insight and the one most likely to be got wrong. Do
not reach for a single mechanism.

| | UTXO set | Index |
|---|---|---|
| Lives in | RAM, 256 shards | On disk |
| Durability | checkpoints, not per-block writes | every write batch |
| A crash mid-mutation | discards ALL uncommitted mutation | leaves partial state |
| Recovery | reload checkpoint, replay forward | must be atomic per block |

Consequences:

1. **Undo records serve live reorgs, not crash recovery.** A crash cannot leave
   a half-applied UTXO undo, because the in-memory set does not survive the
   crash at all.

   An earlier version of this note said recovery is checkpoint-plus-replay.
   Only the checkpoint half exists. `run.rs` does call `recover_if_needed`, but
   nothing in production ever writes the metadata it reads. Two functions can
   write it, `crash_recovery::set_last_committed_height` and
   `NodeState::record_synthetic_block_for_recovery`, and neither has a
   production caller; the second's own doc calls it a test helper. So on a
   normal boot `read_meta` finds no sidecar and the fresh-node path is taken.
   Nothing in block connection fsyncs either.

   Note what this does NOT mean. The two halves do not fail together, for the
   reason this whole section exists: the undo record is a journaled KV write
   and the UTXO set is RAM behind periodic checkpoints. A crash can leave a
   durable undo record for a UTXO commit that vanished, or a checkpointed UTXO
   commit whose undo record was still in the journal. Rolling either forward
   needs the replay that is not wired. Tracked below.
2. **Whether a durable phase marker is needed is undecided.** An earlier draft
   specified one and a later draft called it unnecessary, reasoning that the
   in-memory set discards uncommitted mutation on a crash so the two halves
   cannot disagree. The paragraph above refutes that: a checkpoint can retain a
   UTXO commit whose undo record was lost with the journal, which is exactly
   the mismatch a durable boundary would detect. Neither draft settled it.
   Decide it with the recovery protocol, not before.
3. **Index rollback must be one atomic write batch.** A partial index rollback
   does survive a crash, and no marker helps because the crash lands inside the
   phase. This is already implemented that way.

## Disconnect order

1. `tx_index.rollback_block(&block, height)` when present
2. `utxo.undo_block(&undo)`
3. roll `applied_tip` back to the parent
4. *(no step 4 — see retention below)*

Step 3 is the commit point. A failure before it leaves the node believing the
block is still connected, which is a recoverable state.

## Do not assume undo is idempotent

`UtxoSet::undo_block` restores the outpoints a block spent and removes those it
created. Applying it twice is **not** safe: if a competing block re-created one
of those outpoints in between — exactly what a reorg does — the second undo
deletes a live output. That is silent chainstate corruption.

Any idempotency claim in this area must be backed by a test that double-applies
the operation and asserts the state matches a single application. An untested
idempotency claim in consensus code is a defect.

## Undo record retention

Key records by **block hash**, not height alone: a stale record from an
abandoned branch must never be replayable against a different block at the same
height. Verify the hash on load and hard-error on mismatch.

**Do not delete the record when a block is disconnected.** Reorg flip-flop
between two competing branches is normal, and discarding the record means
regenerating it on every reconnect. Retention is bounded by the durable
chainstate horizon (the checkpoint height), not by disconnection.

Write the record before or in the same batch as the UTXO commit. A UTXO commit
with no recoverable undo record is an unrecoverable chainstate.

## Work remaining

Done:

| Piece | Notes |
|---|---|
| `ColumnFamily::UndoData` | enum, its `ALL` list, and all four backends |
| Versioned undo codec | first byte a format version; keyed by height **and** block hash, with 10 rejection tests |
| Undo generation in apply | built in the same pass as `BorrowedBlockChanges`, sharing one set of filters so the two halves cannot drift |
| Persistence | before the block body, the index, and the UTXO commit; ordering mutation-verified |
| `disconnect_block` | restores UTXO, index, and tip, in that order, all four orderings mutation-verified |
| `coin_stats` rewind | block-level fields only; the per-coin ones ride the `UtxoSet` change listener, which the undo already drives in reverse |
| Filter header cache | repointed at the parent; the index itself needs no rollback because its rows are hash-addressed like block bodies |
| `blocks` RPC cache | popped when the tail is ours; absence is legitimate after a restart or a prune |
| `DisconnectError` | splits `Refused` (nothing touched) from `Fatal` (partly rolled back, carries hash and height) |

Open, and prerequisites for giving `disconnect_block` a caller:

| Piece | Notes |
|---|---|
| Mempool reconsideration | a disconnected block's transactions belong back in the mempool |
| Disconnect notification | ZMQ publishes connects; disconnects are silent |
| Filter-index backfill | a gap leaves the index unavailable from that point, by design; nothing repairs it |
| Side-branch routing | a block extending a known side branch is rejected with no distinguishable error, so no caller can route it to a reorg |
| Partial-transition handling | **Retry is ruled out**, and that half is settled: each UTXO operation is idempotent on the set, but the commit fires `UtxoSet`'s listener and `coin_stats` is one, so a second pass double-counts where the set converges. `DisconnectError` now splits `Refused` (nothing touched, free) from `Fatal` (partly rolled back, carries the block hash and height). **The recovery half is not built**: the poison is a return value, so a restart clears it while the index rollback that already reached disk survives. Needs a durable marker written before mutation, a startup that refuses or recovers until it clears, and gating for RPC, P2P and Electrum rather than the apply path alone |

Open, layer 4:

| Piece | Notes |
|---|---|
| `crates/node/src/reorg.rs` | switch branches via `plan_reorg` |
| Apply-path routing | keep rejecting a non-extending block, but with a distinguishable error naming the known-side-branch case so the caller can route to reorg. Deleting the rejection outright corrupts the UTXO set |
| Failure handling | attempt a compensating rollback; if that also fails, poison the apply path and refuse further blocks rather than serving a chain the node cannot describe. Refuse cleanly, never panic mid-write |
| Real crash replay | `crash_recovery` has no production writer today, so its watermark records nothing and regenerates nothing |
| Un-ignore `g10_reorg_deep` | prove against `bitcoind` regtest |

Absolute "a failed reorg leaves the original tip" is not achievable, because the
compensating rollback can itself fail. The honest contract is: attempt it, and
on failure stop applying blocks with an operator-facing message naming the block
hash and height where it wedged.

## Guidance

1. **Name the commit point before writing any of it.** Which single mutation
   decides that the disconnect happened? Everything after it is cleanup.
   Everything before it must be atomic, compensatable, or recoverable, and you
   must say which for each store. "Safe to re-enter" was the earlier wording and
   it was wishful: it assumed each step either happens or does not, which the
   shard-walking UTXO commit does not honour.
2. **Do not add a mechanism whose failure mode cannot occur, and do not assume a
   failure mode cannot occur because one store is in RAM.** The phase marker was
   called a mistake on that reasoning. It is not settled: a checkpoint can
   retain a UTXO commit whose undo record was lost with the journal, and a
   durable boundary is one way to detect that. Decide it with the recovery
   protocol.
3. **A trait default that returns success is a silent-corruption path.** When a
   consumer must participate in rollback, make the default refuse. See
   `IndexError::UnsupportedRollback`.
