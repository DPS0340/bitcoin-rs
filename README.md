# bitcoin-rs

A Bitcoin full node in Rust 2024 with pure-Rust defaults, native consensus
validation, and an opt-in kernel oracle for differential verification.

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Features

- Native consensus validation: pure-Rust script execution covering Legacy,
  SegWit v0, and Taproot key-path and script-path spends, with sighash midstate
  caching and parallel check evaluation.
- Opt-in verification oracle: compile with `--features kernel` to enable
  `--verify-kernel` for side-by-side consensus verdict comparison against
  `libbitcoinkernel`.
- Pure-Rust storage defaults: LSM-tree storage backed by `fjall` by default,
  with `redb` compiled in, and `rocksdb`/`mdbx` available through optional Cargo
  features.
- Sharded UTXO cache: a 256-shard in-memory UTXO set (`hashbrown::HashTable` of
  compact records behind `parking_lot::RwLock`) with checkpoint-based crash
  recovery and effective `--dbcache-mb` budget allocation.
- Asynchronous index consumers: `txindex` and BIP157/158 block filters reconcile
  over a monotonic chain snapshot and event hint channel without blocking block
  validation.
- Integrated ScriptIndex and Esplora APIs: address and scripthash UTXO indexing
  and confirmed transaction history served directly over HTTP.
- Mempool mutation gateway: centralized mutation tracking publishing ordered
  accept and remove events over ZMQ `pubsequence`.
- Block template assembly: mining candidate generation via `getblocktemplate`.
- Core-compatible RPC and typed embedding: synchronous HTTP JSON-RPC using Core
  method names and wire formats (walletless, no private keys), plus a typed
  async `Node` embedding API for in-process Rust integrations.

## Quick start

Build and run the default node with the optimized quick-start profile (pure
Rust, no C++ toolchain required):

```sh
cargo build --profile quickstart -p bitcoin-rs
./target/quickstart/bitcoin-rs --data-dir .bitcoin-rs
```

This starts a mainnet node storing state in `.bitcoin-rs` and listening for
JSON-RPC on `127.0.0.1:8332`.

Verify the node is responding and syncing:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

### Optional kernel oracle build

To build with the opt-in `libbitcoinkernel` verification oracle, install C++
dependencies (`cmake` and `libboost-dev` on Debian/Ubuntu), then pass
`--features kernel`:

```sh
cargo build --release -p bitcoin-rs --features kernel
./target/release/bitcoin-rs --data-dir .bitcoin-rs --verify-kernel
```

## Measured performance

Performance measurements from the bounded disk-backed campaign documented in
[docs/benchmarks/end-to-end-sync.md](docs/benchmarks/end-to-end-sync.md) (commit
`de8001e`, mainnet blocks 0 to 150,000, full validation with
`--assume-valid-height 0`, CPU set 0–31 on Intel Xeon Gold 6138):

| Workload | bitcoin-rs median | Bitcoin Core 31.1 median | Ratio |
|---|---:|---:|---:|
| Full-validation local replay | 39.25s | 64.92s | 1.654x |
| Whole benchmark process wall | 42.03s | 67.02s | 1.595x |
| Bounded single-peer daemon IBD | 89.58s | 73.46s | 0.820x |

These measurements reflect a bounded 0–150,000 historical block range before
SegWit and Taproot activation. Full-tip live network sync measurements remain
pending fresh benchmarking runs. See
[docs/benchmarks/end-to-end-sync.md](docs/benchmarks/end-to-end-sync.md) for full
methodology, hardware constraints, and artifact custody.

## Architecture

```
Surfaces:      bin/bitcoin-rs, crates/rpc, crates/ext-api, crates/ext-blockfilterindex
Capabilities:  crates/index, crates/mining, crates/mempool
Node services: crates/node, crates/p2p, crates/storage
Core & domain: crates/consensus, crates/script, crates/utxo, crates/chain, crates/primitives
```

- Validation: native script execution runs in parallel across rayon workers,
  with sighash midstate reuse per transaction.
- Oracle boundary: `crates/consensus/src/kernel_oracle.rs` contains all
  `libbitcoinkernel` types behind `#[cfg(feature = "kernel")]`. Kernel types
  never leak into node state or apply logic.
- Storage: `crates/storage` provides backend abstraction. The active engine is
  configured at startup (`fjall`, `redb`, `rocksdb`, or `mdbx`).
- Indexing: `txindex` and `ext-blockfilterindex` run as independent consumers
  advancing their own cursors and rollback metadata atomically.

## Default posture

| Setting | Default |
|---|---|
| Storage backend | `fjall` |
| Validation engine | Native Rust |
| Kernel verification oracle | Off (opt-in via `--features kernel`) |
| Database cache | 450 MiB (`--dbcache-mb`, split 70/20/10) |
| Multi-peer download | On (8 outbound peers, 128-block window) |
| Transaction index | Off |
| Block filters | Off |
| Script index | Off |
| Pruning | Off |

Mainnet defaults to skipping historical script verification up to the pinned
assume-valid anchor. Pass `--assume-valid-height 0` to verify all scripts from
genesis.

## Build and test

```sh
# Build default binary (pure Rust)
cargo build --release -p bitcoin-rs

# Run workspace unit and integration tests
cargo test --workspace

# Lint all targets
cargo clippy --workspace --all-targets -- -D warnings
```

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for local
verification commands, CI workflows, and crate architecture conventions.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — Node setup and configuration
- [docs/README.md](docs/README.md) — Documentation index
- [docs/contracts/](docs/contracts/) — Normative architecture and protocol contracts
- [CONCEPTS.md](CONCEPTS.md) — Domain terminology and concepts
- [PLAN.md](PLAN.md) — Project roadmap and historical milestones (G1–G15 verification gates)
- [CONTRIBUTING.md](CONTRIBUTING.md) — Development workflow and CI guidelines

## License

Dual-licensed under [MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE). See
[LICENSE](LICENSE) for full details.
