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

**Not implemented.** `crates/node/src/apply.rs` advances `applied_tip` forward
only, UTXO undo data is never persisted, and `bitcoin_rs_chain::plan_reorg` has
no production caller. `bin/bitcoin-rs/tests/gates/g10_reorg_deep.rs` is
`#[ignore]`d and says so.

The **index half is done**: `IndexerLike::rollback_block` exists, is tested, and
refuses by default rather than reporting a false success. The node half is not
written. This note records the design so the next attempt starts from it.

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
   crash at all. Recovery is checkpoint-plus-replay.
2. **A durable phase marker is not needed for the UTXO step.** An earlier draft
   of this design specified one; it solves a failure mode that cannot occur
   here.
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

| Piece | Notes |
|---|---|
| `ColumnFamily::UndoData` | touches the enum, its `ALL` list, and all four backends |
| Versioned undo codec | first byte a format version; key by height **and** block hash |
| Undo generation in apply | `ResolvedUtxoView.external` already holds every spent prevout as `LiveOutput { txout, coinbase, height }`, which is exactly `UtxoAdd`'s shape. Build the batch where `build_utxo_changes` builds `BorrowedBlockChanges` |
| Persistence | same batch as the UTXO commit |
| `crates/node/src/reorg.rs` | disconnect one tip; switch branches via `plan_reorg` |
| Apply-path routing | keep rejecting a non-extending block, but with a distinguishable error naming the known-side-branch case so the caller can route to reorg. Deleting the rejection outright corrupts the UTXO set |
| Failure handling | attempt a compensating rollback; if that also fails, poison the apply path and refuse further blocks rather than serving a chain the node cannot describe. Refuse cleanly, never panic mid-write |
| Un-ignore `g10_reorg_deep` | prove against `bitcoind` regtest |

Absolute "a failed reorg leaves the original tip" is not achievable, because the
compensating rollback can itself fail. The honest contract is: attempt it, and
on failure stop applying blocks with an operator-facing message naming the block
hash and height where it wedged.

## Guidance

1. **Name the commit point before writing any of it.** Which single mutation
   decides that the disconnect happened? Everything before it must be safe to
   re-enter; everything after is cleanup.
2. **Do not add a mechanism whose failure mode cannot occur.** The phase marker
   here was that mistake — it protects boundaries in a store whose partial
   states never persist.
3. **A trait default that returns success is a silent-corruption path.** When a
   consumer must participate in rollback, make the default refuse. See
   `IndexError::UnsupportedRollback`.
