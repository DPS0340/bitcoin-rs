# bitcoin-rs

A Rust 2024 Bitcoin full node aiming at faster IBD and a tighter resident set
than `bitcoind` while remaining consensus-compatible.

## Status

**Pre-alpha scaffold.** The workspace has 18 structurally complete crates, but
the integration layer (run loop, chain, utxo, p2p, rpc, electrum) lands
in following commits. Empirical "faster than Bitcoin Core" validation requires
live mainnet IBD against reference `bitcoind` and is tracked as verification
gates G1-G14 in `PLAN.md`.

## Architecture highlights

- Production consensus verification via bitcoinkernel (libbitcoinkernel),
  ensuring full script-path and key-path consensus parity with Bitcoin Core.
- Four pluggable storage backends (fjall default, RocksDB, MDBX, redb),
  selected at runtime via `--storage-backend`. The 4-backend equivalence test
  produces an identical aggregate hash on every IBD.
- 256-shard arena-backed UTXO set (bumpalo + hashbrown) with snapshot format
  and crash-safe defrag.
- Optional utreexo (Pollard + Stump + MemForest) for stateless validation.
- Native Electrum-style index, BIP157/158 filters, coinstats (muhash), pruning
  with Core's 288-block reorg-safety floor.
- PSBT-only wallet: no signing key handling, only an external signer trait.
- `getblocktemplate` mining endpoint.
- Sync HTTP/1.1 JSON-RPC over sonic-rs with Core-compatible method names;
  signing methods return -32603 "wallet has no private keys".
- mimalloc global allocator and a crossbeam-channel event loop.

## Build

Default builds link bitcoinkernel and require system dependencies (`libboost-dev` and `cmake`).

```sh
cargo build --release -p bitcoin-rs
```

Default feature flags (`rocksdb`, `fjall`, `redb`, `mdbx`, `kernel`) are enabled automatically.
The `--no-default-features` flag builds a portable Rust-only posture without C++ build dependencies,
which cannot validate Taproot script-path transactions on mainnet.

## Tests

```sh
cargo test
```

Live-infrastructure gates are `#[ignore]`d; invoke them individually with
`-- --ignored` after wiring the documented environment.

## License

MIT OR Apache-2.0
