# Getting started

From a clone to a syncing node. Each step explains what you should see so you can
verify progress before moving on.

## Prerequisites

- A Rust toolchain for edition 2024 (MSRV 1.95.0 or newer).
- The default build is pure Rust and requires no C++ compiler or system libraries.

If you plan to compile with the optional `kernel` feature for differential
verification against `libbitcoinkernel`, install `cmake` and `libboost-dev`:

```sh
# Only required for the optional kernel oracle feature
sudo apt-get install -y cmake libboost-dev
```

## Step 1: build

Build the node with default features:

```sh
cargo build --release -p bitcoin-rs
```

This produces `./target/release/bitcoin-rs`. The default configuration includes
the `fjall` storage backend, `redb`, and `zmq` sequence publishing. Consensus
validation runs natively in pure Rust across all script types (Legacy, SegWit v0,
and Taproot key-path and script-path spends).

To compile with the optional `libbitcoinkernel` verification oracle:

```sh
cargo build --release -p bitcoin-rs --features kernel
```

## Step 2: choose a storage backend

`fjall` is the default storage engine. `redb` is also compiled in default builds.
Pass `--storage-backend` to select a backend:

```sh
./target/release/bitcoin-rs --storage-backend redb
```

You can also set it via environment variable:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

Alternative C++ storage backends (`rocksdb`, `mdbx`) are available through
non-default Cargo features:

```sh
cargo build --release -p bitcoin-rs --features rocksdb
```

## Step 3: start the node

Start the node on mainnet:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Configuration defaults:

| Flag | Default |
|---|---|
| `--data-dir` | `.bitcoin-rs` |
| `--network` | `mainnet` (`mainnet`, `testnet3`, `testnet4`, `signet`, `regtest`) |
| `--storage-backend` | `fjall` |
| `--rpc-bind` | `127.0.0.1:8332` on mainnet, network Core port otherwise |
| `--rpc-user` / `--rpc-password` | `bitcoin-rs` / `bitcoin-rs` |
| `--dbcache-mb` | 450 (split 70/20/10 across chainstate, txindex, and filters, with disabled shares going to chainstate) |
| `--prune-target-mb` | 0 (no pruning) |
| `--txindex` | off |
| `--scriptindex` | off |
| `--verify-kernel` | off (requires `--features kernel` build) |

The node logs its startup banner, effective cache allocation, and the address
the JSON-RPC listener bound to.

`--txindex` enables Bitcoin Core-compatible transaction lookup support.
`--scriptindex` enables address and scripthash UTXO queries and confirmed
funding/spending history exposed via Esplora-compatible HTTP endpoints.
Address and scripthash routes return HTTP 503 until `--scriptindex` catches up,
or when it is disabled.

Change the RPC credentials before exposing the port. The defaults are a
development convenience, not a secret. Pass `--rpc-cookie` to use a Core-style
cookie file instead.

## Step 4: check sync progress

The JSON-RPC surface uses Bitcoin Core method names:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

The response includes the current validated height, best block hash, and sync
progress. Call it twice a minute apart to confirm height advances.

To query just the tip hash:

```sh
curl -s --user bitcoin-rs:bitcoin-rs \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:8332/
```

The dispatch table in `crates/rpc/src/handlers.rs` implements supported Core
methods. There is no internal wallet: private-key and wallet-construction
methods are absent, while key-free PSBT utilities (`combinepsbt`, `finalizepsbt`)
and descriptor helpers remain for external signers.

## Verifying everything yourself

Mainnet skips historical script checks below the pinned assume-valid anchor.
To verify every script from genesis:

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --assume-valid-height 0
```

This runs full script execution on every transaction from block 0. It is the
recommended mode for benchmarking and independent consensus audits.

## Next

- [../README.md](../README.md) for architecture overview and benchmark records
- [../CONTRIBUTING.md](../CONTRIBUTING.md) for development workflows and testing
- [README.md](README.md) for the documentation index
- [contracts/](contracts/) for normative architecture and protocol contracts
