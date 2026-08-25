# bitcoin-rs-utxo

The in-memory UTXO set: 256 first-byte shards, each a `hashbrown::HashTable` of compact transaction-level records behind a `parking_lot::RwLock`, together with the native snapshot format and the versioned undo codec that make checkpoint load and block disconnect possible.

`UtxoSet` owns the state. `UtxoSet::commit_block` applies a `BlockChanges` for a connected block (built with `BlockChanges::add`/`remove`), `UtxoSet::undo_block` reverses one block from its `UndoBatch` of restores and removes, and lookups go through `get`, `get_entry`, and `get_meta`, with `has_live_outputs_for_txid` supplying the transaction-level BIP30 duplicate-spend predicate. `UtxoSet::with_stable_view` blocks commits while a `UtxoSetView` reads the whole set — computing the Core `hash_serialized_3` commitment and scanning for exact scriptPubKey matches — and `set_listener` installs a batch-only `UtxoChangeListener`. Single-shard commits deliver transaction runs directly; multi-shard commits deliver collected, order-independent event batches after shard mutation. Persistence is the native snapshot codec (`write_snapshot`, `read_snapshot`, the observed-write variants, and `aggregate_hash`), while disconnect undo records round-trip through `encode_undo`/`decode_undo` under a single `UNDO_FORMAT_VERSION`.

## Features

- `bench-mimalloc`: bench-only toggle that registers mimalloc as the global allocator in `benches/utxo_commit.rs`; it changes nothing in library builds.
- `rocksdb`, `fjall`, `redb`, `mdbx`: forward the storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
