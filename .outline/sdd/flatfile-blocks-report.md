# Flat-file block body store report

## Contract

**PRE**

- `persist(height, hash, body)` receives one immutable serialized body for a block identity. Reorgs may reuse a height with a different hash.
- Restart replay may call `persist` again for an already-indexed `(height, hash)`.

**POST**

- `load(height, hash)` returns the exact persisted bytes until pruning, otherwise `Ok(None)`.
- A repeated persist is a no-op only when the indexed position has the same body length and its complete frame matches the requested height and hash.
- A different length, stale target, truncated frame, or corrupt frame appends a fresh frame and replaces the index position.

**INVARIANT**

- Crash safety: a load returns the complete matching body or `None`, never truncated, partial, or foreign bytes. The reader verifies magic, stored length, height, and hash.
- Recovery: startup scans only the highest-numbered flat file and truncates its first bad or incomplete frame before the next append.
- Pruning: files whose maximum height is strictly below the prune height are physically removed, except the current append file. Index rows commit before physical deletion; per-file metadata remains until deletion completes so interrupted reclamation is retryable.
- Backend neutrality: `BLOCK_DATA_CF`, the 37-byte `block_body_key(height, hash)`, and `KvStore` are unchanged. The unmodified backend-equivalence test remains the gate.

## Implementation

- Added `bitcoin_rs_storage::FlatFileBlockStore` using `blocks/blkNNNNN.dat`, a 128 MiB production cap, a `parking_lot::Mutex` writer/append offset, `Write::flush`, and no per-block fsync.
- Frames use the specified 44-byte header: 4-byte `BRSB` magic, `u32` LE body length, `u32` LE height, and 32 hash bytes, followed by the body.
- Added the fixed 16-byte LE position record (`u32 file_no`, `u64 header offset`, `u32 body length`).
- Rewired node persistence and reads through the flat-file store while retaining KV-backed position and per-file rows.
- Added startup legacy-row validation with an actionable resync error.
- Added two-phase pruning: commit index/undo/pruneheight rows, delete eligible non-current files, then delete their metadata rows.
- Left `crates/node/src/crash_recovery.rs` unchanged.

## Per-file metadata column family

The `b"blkfile" || file_no(u32 BE)` maximum-height row lives in `ColumnFamily::BlockBodies` (`BLOCK_DATA_CF`). This keeps the existing column-family list unchanged, permits the position row and max-height row to be written in one backend batch, and lets pruning find all block-body ownership metadata without introducing a backend-specific schema change.

## StorageError

Added `StorageError::IncompatibleData(String)`. The existing `InvalidOperation(&'static str)` cannot carry the required datadir path and actionable resync instruction; classifying legacy persisted data as I/O or a backend failure would also be misleading.

## Tests

The required behavior is guarded by:

1. round-trip with differing sizes and forced rollover;
2. independent same-height reorg hashes;
3. torn-tail recovery and overwrite;
4. wrong-height/wrong-hash reads returning `None`;
5. whole-file pruning with current-file protection and row removal;
6. actionable legacy-datadir refusal;
7. duplicate `(height, hash, body)` persistence leaving file length unchanged and loading exact bytes.

The storage core also checks that only a complete matching existing position is reused; a same-length position targeting a foreign frame is replaced.

## Framing overhead

Measured framing overhead is **44 bytes per stored block body**: the on-disk record length is `body.len() + 44`. The fixed KV position is 16 bytes per block; the 4-byte maximum-height value is one row per flat file and is not part of the flat-file frame.

## Verification

Exact command from the brief:

```text
cargo fmt --all -- --check \
 && cargo clippy -p bitcoin-rs-storage --all-targets --no-default-features --features rocksdb,fjall,redb,mdbx -- -D warnings \
 && cargo clippy -p bitcoin-rs-node --all-targets --no-default-features --features fjall,bitcoinconsensus -- -D warnings \
 && cargo test -p bitcoin-rs-storage --no-default-features --features rocksdb,fjall,redb,mdbx --no-fail-fast \
 && cargo test -p bitcoin-rs-pruning --no-fail-fast \
 && cargo test -p bitcoin-rs-node --no-default-features --features fjall,bitcoinconsensus --no-fail-fast
```

Real output (exit status 0):

```text
    Finished `dev` profile [optimized + debuginfo] target(s) in 1.19s
    Finished `dev` profile [optimized + debuginfo] target(s) in 6.31s
    Finished `test` profile [optimized + debuginfo] target(s) in 1.55s

running 5 tests
test block_file::tests::persist_reuses_only_a_matching_existing_position ... ok
test block_file::tests::recovery_discards_a_torn_tail_before_the_next_append ... ok
test block_file::tests::wrong_target_returns_none_instead_of_foreign_bytes ... ok
test block_file::tests::reorg_hashes_at_one_height_remain_independent ... ok
test block_file::tests::round_trips_and_rolls_over_without_large_allocations ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 5 tests
test fjall_equivalence_hash ... ok
test rocksdb_equivalence_hash ... ok
test mdbx_equivalence_hash ... ok
test redb_equivalence_hash ... ok
test portable_backends_have_identical_aggregate_hashes ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

bitcoin-rs-pruning: test result: ok. 2 passed; 0 failed
bitcoin-rs-node: test result: ok. 312 passed; 0 failed
```

`crates/storage/tests/backend_equivalence.rs` passed unmodified across rocksdb, mdbx, fjall, and redb.
