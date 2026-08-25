# Getting started

From a clone to a syncing node. Each step says what you should see, so you can
tell it worked before moving on.

Before you start: this node reorganises off a losing branch, but several
things around that still do not work. A disconnected block's transactions are
dropped rather than returned to the mempool, and the filter index is not
backfilled across a gap. ZMQ `pubsequence` publishes block connect/disconnect
events but intentionally omits mempool `A`/`R` events. Do not make it the node
you depend on. See [README.md](README.md) for the rest of the gaps.

## Prerequisites

A Rust toolchain for edition 2024, plus `cmake` and `libboost-dev`. The last
two are needed because the default build compiles libbitcoinkernel from C++
sources.

On Debian or Ubuntu:

```sh
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build

```sh
cargo build --release -p bitcoin-rs
```

This produces `./target/release/bitcoin-rs`. The default features are
`rocksdb`, `fjall`, `redb`, `mdbx`, and `kernel`, so all four storage backends
and the kernel verifier are compiled in.

If you cannot install the C++ dependencies, build the portable node instead.
It must still name a storage backend, because bare `--no-default-features`
compiles in none and the node then refuses to start:

```sh
cargo build --release -p bitcoin-rs --no-default-features --features fjall
```

The portable verifier supports only Taproot key-path spends. It cannot validate
non-Taproot spends or Taproot script-path spends, so a mainnet sync stops early.
Use it for development, not for following the chain.

## Step 2: choose a storage backend

fjall is the default. Pass `--storage-backend` to pick another:

```sh
./target/release/bitcoin-rs --storage-backend rocksdb
```

Valid values are `fjall`, `rocksdb`, `mdbx`, and `redb`. All four hold the same
chain state; they differ in write amplification and memory profile. If you have
no reason to change it, keep fjall.

You can also set it in the environment:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

## Step 3: start the node

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Defaults worth knowing:

| flag | default |
|---|---|
| `--data-dir` | `.bitcoin-rs` |
| `--network` | mainnet (`mainnet`, `testnet3`, `testnet4`, `signet`, `regtest`) |
| `--rpc-bind` | `127.0.0.1:8332` on mainnet, the network's Core port otherwise |
| `--rpc-user` / `--rpc-password` | `bitcoin-rs` / `bitcoin-rs` |
| `--dbcache-mb` | 450 |
| `--prune-target-mb` | 0, meaning no pruning |
| `--txindex` | off |
| `--electrum` | off |
| `--blockfilterindex` | off |

The node logs its startup and the address the RPC listener bound to. If you see
that line, it is running.

`--txindex` advertises Bitcoin Core-compatible transaction lookup support.
`--electrum <address>` starts the Electrum service and automatically builds
the internal transaction lookup plus scripthash history indexes; it does not
require `--txindex` or advertise Core txindex support unless that flag is also
set. Either index mode is incompatible with pruning because backfill and reorg
repair require durable block bodies.

Change the RPC credentials before exposing the port anywhere. The defaults are
a development convenience, not a secret. `--rpc-cookie` takes a Core-style
cookie file instead.

## Step 4: check sync progress

The JSON-RPC surface uses Bitcoin Core's method names, so Core's client tools
work against it.

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

The response carries the current height and best block hash. Call it twice a
minute apart: if the height moved, the node is syncing.

For just the tip:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:8332/
```

The full list of implemented methods is the dispatch table in
`crates/rpc/src/handlers.rs`. Signing methods are present but always return
-32603, "wallet has no private keys", because the wallet holds no keys by
design.

## Verifying everything yourself

Mainnet skips historical script verification below the pinned assume-valid
anchor. To verify every script from genesis:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

This is much slower. It is the right setting for benchmarking and for anyone
who does not want to trust the anchor.

## Next

- [../README.md](../README.md) for the full default posture and the measured
  benchmark.
- [README.md](README.md) for the documentation index.
- [solutions/](solutions/) before debugging something that smells like it has
  been hit before.
