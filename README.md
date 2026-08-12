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
rest) are this project's own code, and are covered by its own tests.

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

### Docker Compose

The enforcer integration Compose configuration builds the production `fjall` +
`bitcoinkernel` profile, stores node and enforcer data under `data/`, exposes
P2P, and binds RPC to the Docker host's loopback interface only. One
`BITCOIN_RS_NETWORK` selects the matching bitcoin-rs and enforcer network; the
`drynet4` selection derives its mainnet consensus rules, custom P2P magic, fixed
peer, and disabled DNS seeding inside bitcoin-rs.

Set explicit RPC credentials in `.env`, then start the node:

```sh
cp .env.example .env
# Edit .env and set BITCOIN_RS_RPC_PASSWORD before starting the node.

docker compose --env-file .env -f tools/bip300301-enforcer/docker-compose.yaml up --build -d
docker compose --env-file .env -f tools/bip300301-enforcer/docker-compose.yaml logs -f node
```

Check sync progress inside the container. This uses the credentials already
provided by Compose and does not evaluate `.env` as shell code:

```sh
docker compose --env-file .env -f tools/bip300301-enforcer/docker-compose.yaml exec node sh -c \
  'curl --user "$BITCOIN_RS_RPC_USER:$BITCOIN_RS_RPC_PASSWORD" \
    -H "content-type: application/json" \
    -d "{\"jsonrpc\":\"1.0\",\"id\":\"sync\",\"method\":\"getblockchaininfo\",\"params\":[]}" \
    http://127.0.0.1:8332/'
```

Stop the process without deleting its chain data with
`docker compose --env-file .env -f tools/bip300301-enforcer/docker-compose.yaml down`.
Compose allows up to 5 minutes for the full clean checkpoint before forcing
termination. Chain data remains under `data/` until it is explicitly removed.

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

CPU and memory are the stable margins. Wall-clock moves with host load — the
same pair has measured between 1.04x and 1.24x apart across sessions — so treat
it as parity-or-better rather than as a fixed number.

This is the replay driver, which reads blocks from local files. Peer sync does
not reach the same figure yet: it stages at most 128 blocks, so it forms
smaller script-verification windows and lands between the two. Widening that is
open work, and it is a change to the download pipeline rather than a constant.

Read the conditions before reusing these numbers. This box runs other tenants,
and the same binary has measured anywhere from 50s to 73s across sessions
depending on load. Only runs interleaved with Core inside one session are
comparable; an absolute number quoted from a different session is not.

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

The portable verifier supports only Taproot key-path spends. It cannot validate
non-Taproot spends or Taproot script-path spends, so a mainnet sync stops early.
Use it for development only.

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
- [PLAN.md](PLAN.md) — roadmap and the G1-G14 verification gates

## License

MIT OR Apache-2.0
