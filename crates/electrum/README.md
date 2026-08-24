# bitcoin-rs-electrum

Owns the Electrum protocol server: core JSON-RPC method handling, per-connection sessions
with scripthash subscriptions, and the TCP/TLS listener.

`dispatch(method, index, mempool, params)` is the method entry point, answering requests
from an `IndexHandle` and a `MempoolHandle`. `IndexHandle` is assembled from two adapter
traits — `ConfirmedHistoryReader`, which serves confirmed-history snapshots from the
transaction index, and `BlockTreeAdapter`, which serves raw headers and blocks from the
node-owned block tree so chain data never comes from the index — plus a network selector
for `server.features`; `MempoolHandle` shares the mempool behind a lock. `Session::serve`
runs line-delimited JSON-RPC over any stream (`handle_line` answers one request), with
`SessionSubscriptions` recording scripthash and header subscriptions and `poll` emitting
status-change notifications; `status_value` shapes a status hash into its JSON value.
`ElectrumServer::bind` (or `from_listener`) starts the accept loop — one thread per
connection, bounded by `ServerConfig::max_sessions`, with optional TLS — and
`run_with_shutdown` stops it on an atomic flag.

## Features
- `rocksdb`: enables the RocksDB backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`
- `mdbx`: enables the MDBX backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
