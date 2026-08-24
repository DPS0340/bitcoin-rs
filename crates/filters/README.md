# bitcoin-rs-filters

Owns BIP157/BIP158 compact block filters: the Golomb-coded-set codec, filter-header
chaining, and the persistent filter index over the workspace key-value store.

The `gcs` module implements the BIP158 codec: `key_from_block_hash` derives the `SipHash`
key from the first 16 block-hash bytes, `hash_elements` maps raw items into the set's
range, `encode`/`decode` handle the Golomb-coded byte stream, and `matches` tests a
filter against query targets (`GcsError` for malformed streams).
`cfheaders::next_header` chains headers as
`sha256d(sha256d(filter_bytes) || prev_filter_header)` in internal byte order.
`FilterIndex<S: KvStore>` wraps any workspace key-value store: `put_filter` stores a
filter and its chained header atomically and returns the new header, `filter`,
`filter_header`, and `has_filter` answer point queries, and `iter_filters`,
`iter_block_hashes`, and `filter_count` scan the stored set. `FilterIndexLike` is the
storage-agnostic ingest interface (`wants_filters`, `put_filter`).

## Features
- `rocksdb`: enables the `RocksDB` backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`
- `mdbx`: enables the MDBX backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
