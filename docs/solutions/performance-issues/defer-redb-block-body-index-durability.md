---
title: Defer redb block-body index durability to checkpoints
date: 2026-08-03
category: performance-issues
module: storage
problem_type: performance_issue
component: redb block-body index
symptoms:
  - redb spent 259.43 seconds persisting block bodies during a 150,001-block replay
  - redb replay throughput was 369.94 blocks per second while fjall and RocksDB exceeded 1,099 blocks per second
root_cause: wrong_api
resolution_type: code_fix
severity: high
tags: [redb, durability, block-storage, ibd, performance]
---

# Defer redb block-body index durability to checkpoints

## Problem

The redb backend committed each block-body index batch with immediate durability. This forced one durable commit per block and made storage the main cost of initial block download.

## Symptoms

- Mainnet replay from height 0 through 150,000 took 405.48 seconds on redb.
- `node.apply_block.block_body_persist_seconds` accounted for 259.43 seconds.
- The same replay took 132.35 seconds on fjall and 136.45 seconds on RocksDB.

## What Didn't Work

- Making every redb `KvStore::write` call non-durable was unsafe. Manual pruning commits index-row deletion and then removes flat files. A crash could restore rows that point to deleted files.
- Optimizing only the flat-file append missed the cost. Profiling showed that redb's immediate index commit dominated the stage.

## Solution

Add an explicit deferred write operation to `KvStore`. Its default implementation uses the normal write path, so other backends keep their existing behavior. Redb maps only this operation to `Durability::None`; normal redb writes remain `Durability::Immediate`.

```rust
fn write_deferred(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
    self.write(batch)
}
```

Use the deferred operation only for the atomic block-position and file-height index batch:

```rust
self.index.write_deferred(batch)
```

Keep the durability barrier in this order:

```rust
self.files.sync()?;
self.index.flush()
```

The file bytes become durable before the index rows. Checkpoint publication happens only after this sync completes.

## Why This Works

Redb 4.1.0 makes a `Durability::None` commit visible to later readers without forcing it to disk. A later empty `Durability::Immediate` commit persists those earlier commits. The existing checkpoint path already flushes the flat-file store before the index store.

The scoped operation preserves the stronger behavior where it matters. Pruning, UTXO updates, and every other normal redb write still use immediate durability.

The matched replay kept the same start and stop hashes. Redb improved from 405.48 to 133.69 seconds, or 3.03 times the prior throughput. Its block-body persistence stage fell from 259.43 to 24.59 seconds. Matched fjall and RocksDB control runs also kept the same hashes and showed no regression.

## Prevention

- Profile storage stages before changing backend durability.
- Make weaker durability opt-in at the exact call site. Do not weaken a backend-wide write primitive when callers have different crash contracts.
- Put the data-file sync before the index flush.
- Keep normal writes for any batch followed by an irreversible external action.
- Benchmark all supported backends with the same block range and verify matching boundary hashes.

## Related

- `docs/benchmarks/end-to-end-sync.md`
- `crates/node/examples/mainnet_prefix_replay.rs`
- `crates/node/src/apply.rs`
- `crates/storage/src/redb_impl.rs`
