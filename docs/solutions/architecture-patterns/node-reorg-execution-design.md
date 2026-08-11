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

**Live branch switching is implemented and called from sync. Crash replay remains
open.**

Done:

* `ColumnFamily::UndoData` across all four backends, and a versioned undo codec
  bound to the block hash (`crates/utxo/src/undo_codec.rs`).
* Undo generation in the same pass as the forward UTXO changes. The undo write
  is queued before the block body, the index, and the UTXO commit. A clean
  checkpoint makes the queued record durable.
* `disconnect_block`, which restores the UTXO set, the transaction index, and
  `applied_tip`. Its ordering claims are mutation-verified.
* `switch_to_branch` (`crates/node/src/reorg.rs`), called by sync when the
  best-work header branch outweighs the applied branch. It loads all
  disconnect bodies and the contiguous target prefix that fits in bounded
  staging. The disconnect preload remains $O(\text{disconnect depth})$. If the
  first connect body is absent, chainstate does not change. The transition
  witness recomputes the complete authoritative plan and permits mutation only
  when that plan is unchanged. Each available prefix then forms a coherent
  applied-tip checkpoint; `MissingBody` names the next suffix block. A permanent
  connect failure invalidates its header subtree, selects the best valid tip,
  and purges that subtree from staging and download ownership. Operational
  failures preserve both branch eligibility and ownership.
* Fork-aware download requests start at the common ancestor's child. A target
  change discards pending ownership from the losing branch.
* A fatal disconnect closes apply admission and sets the process shutdown token.
  The durable marker prevents a restart on torn state.

Still open: transaction reconsideration, filter-index backfill, real crash
replay, and the ignored live `g10_reorg_deep` gate. ZMQ now publishes block
disconnect notifications through `pubsequence`, but mempool `A`/`R` events remain
intentionally open.
Transaction reconsideration requires one production admission pipeline shared
by Electrum, P2P relay, and reorg handling. Raw mempool insertion cannot supply
the required fee, policy, conflict, and ancestry metadata.

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

1. **Undo records serve live reorgs, not per-block crash recovery.** Connection
   queues each record before later apply mutations. The backend write is
   deferred. A clean checkpoint flushes block and index storage, publishes the
   matching UTXO state, and then advances the durable horizon. The record is not
   a per-block fsync boundary.
2. **The durable disconnect marker is implemented.** `InFlight` is flushed
   before the first rollback mutation. A completed rollback changes the marker
   to `RolledBack`; only a clean checkpoint can clear it after publication. A
   checkpoint refuses `InFlight`, and startup refuses either phase. The marker
   prevents service on inconsistent state. It does not repair that state.
3. **Index rollback is one atomic write batch.** A partial index rollback can
   survive a crash, so one batch is the required boundary.

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
| Persistence | queued before the block body, index, and UTXO commit; flushed with a clean checkpoint, not per block |
| `disconnect_block` | restores UTXO, index, and tip, in that order, all four orderings mutation-verified |
| `coin_stats` rewind | block-level fields only; the per-coin ones ride the `UtxoSet` change listener, which the undo already drives in reverse |
| Filter header cache | repointed at the parent; the index itself needs no rollback because its rows are hash-addressed like block bodies |
| `blocks` RPC cache | popped when the tail is ours; absence is legitimate after a restart or a prune |
| `DisconnectError` | splits `Refused` (nothing touched) from `Fatal` (partly rolled back, carries hash and height), plus `MarkerStuck` (rolled back, but the interlock would not clear) |
| Durable interlock | a phased in-flight marker in `UndoData`, armed and flushed before the first mutation and above the index rollback; startup refuses while it is set. See *Disconnect marker phase* in `CONCEPTS.md` |
| Chain-transition serialization | `ChainTransition` proves that admission and the exclusive transition lock were acquired in that order. One witness covers authoritative replanning, all disconnects, and the available contiguous connect prefix. |
| Branch switching | `switch_to_branch` recomputes the complete ordered `plan_reorg` result under the transition guard and mutates only when it equals the optimistic plan. A shorter branch is eligible when its accumulated work is greater. A permanent connect failure invalidates its subtree and selects the best valid tip. |
| Body acquisition | Each attempt loads all disconnect bodies and the contiguous connect prefix available from bounded staging, durable storage, or the applied body cache. The first missing connect body prevents mutation. A later missing body follows a coherent committed prefix. Each committed connect retires its exact staging and download-window entry; invalid subtree ownership is purged. |
| Fatal lifecycle | `Fatal` and `MarkerStuck` close apply admission while the transition lock is held; sync sets the shared process shutdown token |

Open:

| Piece | Notes |
|---|---|
| Mempool reconsideration | Block transactions need the same production admission pipeline as Electrum and future P2P relay. Direct insertion is invalid because it fabricates admission metadata |
| Mempool sequence events | Mempool `A`/`R` notifications remain intentionally absent until event sequencing and removal reasons are redesigned |
| Filter-index backfill | a gap leaves the index unavailable from that point, by design; nothing repairs it |
| Real crash replay | the node detects and refuses torn disconnect state, but cannot replay or repair it in place |
| Un-ignore `g10_reorg_deep` | prove the full path against `bitcoind` regtest |

A body-load error occurs before its attempt mutates. A missing suffix body can
be reported after a coherent target prefix commits. A refused disconnect can
leave a shorter coherent applied chain when earlier disconnects completed. A
connect failure leaves a coherent prefix of the target branch. The node does
not run a
compensating rollback because that second rollback can turn a recoverable stop
into a fatal one. `Fatal` and `MarkerStuck` stop further mutation and trigger the
normal shutdown path.

## Guidance

1. **Name the commit point before writing any of it.** Which single mutation
   decides that the disconnect happened? Everything after it is cleanup.
   Everything before it must be atomic, compensatable, or recoverable, and you
   must say which for each store. "Safe to re-enter" was the earlier wording and
   it was wishful: it assumed each step either happens or does not, which the
   shard-walking UTXO commit does not honour.
2. **Do not add a mechanism whose failure mode cannot occur, and do not assume a
   failure mode cannot occur because one store is in RAM.** The phase marker is
   the durable boundary for disconnect. Keep `InFlight` until rollback completes,
   keep `RolledBack` until a clean checkpoint is durable, and refuse to clear an
   incomplete operation.
3. **A trait default that returns success is a silent-corruption path.** When a
   consumer must participate in rollback, make the default refuse. See
   `IndexError::UnsupportedRollback`.
