# bitcoin-rs

A Bitcoin full node in Rust 2024, built for fast initial block download and a
small resident set, running script verification through the same library
Bitcoin Core uses.

[![CI](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/gosuda/bitcoin-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024%20edition-orange.svg)](https://doc.rust-lang.org/edition-guide/rust-2024/index.html)

## Why bitcoin-rs

Bitcoin Core is the most successful implementation of Bitcoin. Its
conservatism, stability, and compatibility discipline are major reasons for
that success. Over time, however, those safeguards also shape which changes are
practical: existing boundaries accumulate dependencies, and implementation
choices harden into assumptions that Bitcoin consensus does not require.

bitcoin-rs asks a simple question:

> **If a Bitcoin full node were designed again today, what would we keep, and
> what would we change?**

It is an independent implementation of the same Bitcoin, not a new protocol or
a different set of consensus rules.

**Why now?** AI changes the economics of independent implementation: work that
once demanded a large expert team over years can now be attempted by a much
smaller team. Bitcoin makes that effort unusually verifiable. Bitcoin Core,
`libbitcoinkernel`, historical chain data, consensus vectors, fuzzing, and
differential tests provide independent, reproducible ways to verify correctness
and detect divergence.

That independence benefits the broader Bitcoin ecosystem. A separately
designed codebase cross-checks consensus interpretation, reduces the risk of
correlated implementation failures, and helps keep Bitcoin defined by its
consensus rather than by the behavior or structure of any single implementation.

The project reopens several non-consensus design choices:

- **Performance is a first-class requirement.** Synchronization, storage,
  memory ownership, concurrency, caching, and indexing can all be reconsidered.
  Improvements must be demonstrated with matched whole-node benchmarks against
  Core.
- **The UTXO set is authoritative coin state.** It is the canonical spendable
  state maintained by validation. bitcoin-rs exposes it through node APIs so
  wallets and other applications can build balances and spendable-output views
  without reconstructing coin state from the chain. Transaction history and
  other application views remain derived from that shared foundation.
- **Modularity keeps the core isolated and components composable.**
  Clear boundaries contain failures and allow components to be reused
  independently. Third-party integrations can build on the node without
  becoming dependencies of the core.
- **Rust-native integration is a primary path.** The full node should be a
  native part of the Rust Bitcoin ecosystem, available through typed,
  in-process interfaces rather than only serialized RPC. This avoids
  serialization and inter-process communication overhead and lets node
  functionality be compiled and tested as part of the application.

Bitcoin is not defined by the continued preservation of one codebase. **The code
can change; consensus is what must remain.** `bitcoin-rs` aims to build a better
Bitcoin implementation: preserve Bitcoin's consensus exactly, then reconsider
and measure the architecture, performance, integration, and extensibility
choices around it.

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

### Enforcer integration

Running bitcoin-rs alongside the BIP300/301 enforcer is a separate deployment path with
its own Compose example: see [tools/bip300301-enforcer](tools/bip300301-enforcer) for
the stack and [docs/rest-interface.md](docs/rest-interface.md) for the REST surface the
enforcer consumes. It builds the production `fjall` plus `bitcoinkernel` profile and
binds RPC to the Docker host's loopback only.

## Measured performance

Full verification replay of mainnet blocks 0 to 150,000 (1,718,407
transactions) from local block files, with `--assume-valid-height 0` so no
script verification is skipped. Host: 80-CPU Intel Xeon Gold 6138, pinned to 32
physical cores with `taskset -c 0-31`. Three interleaved runs per contender,
medians reported. Bitcoin Core 31.0 was run with `-reindex-chainstate
-assumevalid=0 -connect=0 -dbcache=450`.

| contender | wall | CPU | peak RSS |
|---|---|---|---|
| bitcoin-rs | 55.3s | 389.1s | 558 MB |
| Bitcoin Core 31.0 | 61.1s | 469.9s | 659 MB |

Measured at commit `686379a` with the host near idle: 1.10x faster on
wall-clock, 1.21x less CPU, and a 1.18x smaller resident set. Both nodes reach
the same tip hash.

Full measurement conditions, session variance, and the comparative data against Bitcoin
Core and GoCoin are documented in
[docs/benchmarks/end-to-end-sync.md](docs/benchmarks/end-to-end-sync.md). Read it before
reusing any number here: only runs interleaved with Core inside one session are
comparable.

Against [GoCoin](https://github.com/piotrnar/gocoin) on the same harness:
2.6x faster on replay and 3.03x on peer-to-peer sync.

## Architecture

- Consensus verification via bitcoinkernel (libbitcoinkernel), covering both
  script-path and key-path spends.
- A 256-shard UTXO set: each shard is a `hashbrown::HashTable` of compact records
  (`ThinRecordBuf`, one pointer-sized heap allocation per record) behind a
  `parking_lot::RwLock`, with a snapshot format and checkpoint-based crash recovery.
- Block application in windows: consecutive blocks share one script
  verification dispatch, while each block still commits in order, so every rule
  that depends on committed state sees the real chain.
- A native ScriptIndex with an Esplora HTTP surface, coinstats over MuHash, and
  pruning with Core's 288-block reorg-safety floor.
- `getblocktemplate` for mining.
- Synchronous HTTP/1.1 JSON-RPC over sonic-rs using Core's method names. There
  is no wallet: private-key methods are absent, and the key-free PSBT
  utilities (`combinepsbt`, `finalizepsbt`) remain for external signers.
- mimalloc as the global allocator, over a crossbeam-channel event loop.

## Default posture

The defaults target mainnet initial block download.

| setting | default |
|---|---|
| storage backend | fjall |
| database cache | 450 MiB, matching Bitcoin Core |
| multi-peer download | on: 8 outbound peers, 128-block pending budget, 16 blocks in flight per peer |
| transaction index | off |
| pruning | off |

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

```sh
cargo build --release -p bitcoin-rs --no-default-features --features fjall
```

The portable verifier supports only Taproot key-path spends, so a mainnet sync stops
early; use it for development only. For portable builds without C++ dependencies and
their verification trade-offs, see
[docs/getting-started.md](docs/getting-started.md).

## Tests

```sh
cargo test
```

Gates that need live infrastructure are `#[ignore]`d. Run them individually
with `-- --ignored` once the documented environment is in place.

## Status

The node syncs, verifies, serves, and reorganises. The sync loop compares the
header tip against the applied tip each tick and switches branches when the
applied chain is outweighed.

It is still not the node to depend on. A disconnected block's transactions do
not return to the mempool, and the filter index is not backfilled across a gap.
The ZMQ `pubsequence` stream now publishes block connect/disconnect events, but
does not emit mempool `A`/`R` events. `docs/README.md` lists the rest.

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — clone to synced node
- [docs/](docs/README.md) — the documentation index
- [CONCEPTS.md](CONCEPTS.md) — project vocabulary
- [PLAN.md](PLAN.md) — roadmap and the G1-G15 verification gates

## License

MIT OR Apache-2.0
