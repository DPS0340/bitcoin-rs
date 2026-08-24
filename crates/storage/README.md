# bitcoin-rs-storage

The backend-neutral storage layer every persisted index and chain-state store sits on: key-value access over named column families, atomic write batches with an explicit durability ladder, append-only flat files for immutable block bodies, and the streaming Core frame format.

`KvStore` is the central trait: `get`, ordered `iter_prefix` iteration, bounded `scan_prefix_bounded` scans under a `PrefixScanLimit`, and point-in-time `snapshot` reads, with all mutations going through backend-specific `WriteBatch` types applied by `write`, by `write_deferred` (visible immediately, crash durability deferred to `flush`), or by `write_durable`. `ColumnFamily` names the logical column families shared by every backend and `StorageError` is the common error type. Concrete backends are feature-gated: `FjallStore` (the default), `RocksDbStore`, `RedbStore` plus the typed `RedbTxIndexStore`, and `MdbxStore`. Immutable block bodies bypass key-value storage entirely: `FlatFileBlockStore` and `FlatFileBlockReader` manage the append-only flat files with `BlockFilePosition` addressing, and the `corpus` module streams length-prefixed Core frames through `CoreFrameReader` and `CoreFrameWriter`.

## Features

- `fjall` (default): enables the fjall-backed `FjallStore`.
- `rocksdb`: enables the Rust-RocksDB-backed `RocksDbStore`.
- `redb`: enables the redb-backed `RedbStore` and `RedbTxIndexStore`.
- `mdbx`: enables the MDBX-backed `MdbxStore`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
