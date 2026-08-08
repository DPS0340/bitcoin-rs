# bitcoin-rs

A Bitcoin full node in Rust 2024, built for fast initial block download and a
small resident set, running script verification through the same library
Bitcoin Core uses.

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Why bitcoin-rs

Script verification runs through libbitcoinkernel, the same library Bitcoin
Core uses, so the hardest part of consensus is not reimplemented here. The
block-level rules around it (BIP30, BIP34, weight and coinbase checks, and the
rest) are this project's own code, and are covered by its own tests. The
resident set is 224 MB against Bitcoin Core's 643 MB on the benchmark below.

Four storage backends are selectable at runtime: fjall, RocksDB, MDBX, and
redb. An equivalence test replays the same chain through all four and requires
an identical aggregate hash.

The wallet is PSBT only. The node never handles a private key; signing happens
behind an external signer trait.

## Quick start

Building the default configuration links libbitcoinkernel, which needs `cmake`
and `libboost-dev` on the system.

```sh
cargo build --release -p bitcoin-rs
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

That starts a mainnet node storing state in `.bitcoin-rs` and serving JSON-RPC
on `127.0.0.1:8332`. See [docs/getting-started.md](docs/getting-started.md) for
backend selection, RPC authentication, and checking sync progress.

## Measured performance

Full verification replay of mainnet blocks 0 to 150,000 (1,718,407
transactions) from local block files, with `--assume-valid-height 0` so no
script verification is skipped. Host: 80-CPU Intel Xeon Gold 6138, pinned to 32
physical cores with `taskset -c 0-31`. Three interleaved runs per contender,
medians reported. Bitcoin Core 31.0 was run with `-reindex-chainstate
-assumevalid=0 -connect=0 -dbcache=450`.

| contender | wall | CPU |
|---|---|---|
| bitcoin-rs | 60.3s | 580.5s |
| Bitcoin Core 31.0 | 61.1s | 470.7s |

Measured at commit `92a324d`. Correctness fixes have landed on the apply path
since, and are not re-baselined here.

Read this per metric. On wall-clock the two are at parity. On CPU-seconds
bitcoin-rs uses about 1.23x what Core does, because it buys wall-clock time
with wider script-verification fan-out. Closing that gap is open work, not a
footnote.

Against [GoCoin](https://github.com/piotrnar/gocoin) on the same harness:
2.6x faster on replay and 3.03x on peer-to-peer sync.

These numbers describe one workload on one machine. They are not a claim about
mainnet tip sync, which is bound by download bandwidth rather than by
verification.

## Architecture

- Consensus verification via bitcoinkernel (libbitcoinkernel), covering both
  script-path and key-path spends.
- A 256-shard arena-backed UTXO set (bumpalo and hashbrown) with a snapshot
  format and crash-safe defrag.
- Block application in windows: consecutive blocks share one script
  verification dispatch, while each block still commits in order, so every rule
  that depends on committed state sees the real chain.
- Optional utreexo (Pollard, Stump, MemForest) for stateless validation.
- A native Electrum-style index, BIP157/158 filters, coinstats over MuHash, and
  pruning with Core's 288-block reorg-safety floor.
- `getblocktemplate` for mining.
- Synchronous HTTP/1.1 JSON-RPC over sonic-rs using Core's method names.
  Signing methods return -32603, "wallet has no private keys".
- mimalloc as the global allocator, over a crossbeam-channel event loop.

## Default posture

The defaults target mainnet initial block download.

| setting | default |
|---|---|
| storage backend | fjall |
| database cache | 450 MiB, matching Bitcoin Core |
| multi-peer download | on: 8 outbound peers, 128-block pending budget, 16 blocks in flight per peer |
| transaction index | off |
| block filter index | off |
| pruning | off |
| utreexo | off |

Mainnet also skips historical script verification up to height 938343, block
`00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`. Checks are
skipped only once the node confirms the active header chain contains that exact
block, so a diverged chain or a tip below the anchor gets full verification.
Pass `--assume-valid-height 0` to verify everything. Other networks default
to 0.

## Build

```sh
cargo build --release -p bitcoin-rs
```

The default features are `rocksdb`, `fjall`, `redb`, `mdbx`, and `kernel`.

A portable build drops the `kernel` feature and its C++ dependencies, but it
must still name a storage backend: bare `--no-default-features` compiles in
none, and the node then refuses to start because no backend matches its
configuration.

```sh
cargo build --release -p bitcoin-rs --no-default-features --features fjall
```

That node **cannot validate non-Taproot script-path spends on mainnet** and
stops early in a real sync. It is for development only.

## Tests

```sh
cargo test
```

Gates that need live infrastructure are `#[ignore]`d. Run them individually
with `-- --ignored` once the documented environment is in place.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — clone to synced node
- [docs/](docs/README.md) — the documentation index
- [CONCEPTS.md](CONCEPTS.md) — project vocabulary
- [PLAN.md](PLAN.md) — roadmap and the G1-G14 verification gates

## License

MIT OR Apache-2.0
