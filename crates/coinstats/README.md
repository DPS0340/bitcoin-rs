# bitcoin-rs-coinstats

Owns running UTXO-set statistics: the `MuHash3072` accumulator, incremental per-block
`CoinStats`, their persistence, and the rewind that owed derived state requires when a
block disconnects.

`MuHash3072` is Bitcoin Core's 3072-bit MuHash as a running numerator/denominator
(`insert`, `remove`, `combine`, `finalize_hash` yielding the Core-compatible `uint256`).
`CoinStats` folds the live set — `insert_utxo` and `remove_utxo` feed the accumulator and
the scalar tallies — and serializes to a stable byte layout (`to_bytes`/`from_bytes`).
`CoinStatsListener` keeps stats behind a lock, applies the block-level delta in
`finish_block`, and exposes `rewind_block` as the explicit inverse for disconnects.
`CoinStatsAccumulator` serves checkpoint traversals: `with_parallel_muhash` buffers exact
coin preimages and combines ordered insert-only partial MuHash values, while
`without_muhash` skips hashing entirely. `scan_coin_stats` recomputes stats on demand
from a `UtxoSetView` (Core's on-demand model, no rolling listener required), and
`store_coin_stats`/`load_coin_stats` persist rows keyed by little-endian height.

## Features
- `bench-mimalloc`: bench-only A/B allocator toggle; gates the `#[global_allocator]`
  registration in `benches/coinstats_hotpath.rs` only, off by default
- `rocksdb`: enables the RocksDB backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`
- `mdbx`: enables the MDBX backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
