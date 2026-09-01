# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
startup crash recovery, and the central crossbeam-driven event loop that connects the
subsystem crates.

`run` is the top-level entry point: it loads the layered `Config` (with RPC `Auth`),
recovers via `crash_recovery`, and drives `event_loop`, the central synchronous loop.
`NodeState` holds the shared state and the `apply` block-apply pipeline;
`BlockSync` orchestrates block download; `reorg` switches the applied chain from one
branch to another. Adapters expose node state to the rest of the system —
`UtxoSetView` for consensus transaction checks, `NodeBlockSource` bridging in-memory
block records to the index crate's block source, `NodeP2pChainQuery` for server-side
P2P responders, and `BlockTreeContext` for BIP9 deployment state. Notifications leave
through the `ZmqPublisher` trait and its `SocketZmqPublisher` / `TracingZmqPublisher`
/ `NoOpZmqPublisher` implementations and the `TxIndexRuntime` worker; `signal` and
`shutdown` bridge process signals into graceful shutdown.

## Contract ownership

Behavioral contracts governing node operations are defined in `docs/contracts/`:

- **Chain events and reconciliation**: `NodeState` snapshot replacement, hint emission, and consumer cursor invariants follow [`docs/contracts/chain-events.md`](../../docs/contracts/chain-events.md) (`EVT-01`–`EVT-04`).
- **Indexing runtimes**: `TxIndexRuntime` and `FilterIndexWorker` capability gating, watermark identity, query consistency, and reorg reconciliation follow [`docs/contracts/indexing.md`](../../docs/contracts/indexing.md) (`IDX-01`–`IDX-07`).
- **Extension isolation**: Descriptor registration, pre-open validation, and never-abort-core isolation follow [`docs/contracts/extensions.md`](../../docs/contracts/extensions.md) (`EXT-01`–`EXT-05`).
- **Mempool mutation observer**: Notification and ZMQ event mapping follow [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-01`–`MPL-03`).

## Live gaps

- **Application embedding**: `bitcoin-rs-node` currently runs as a standalone daemon; a typed in-process application engine API is tracked under #145 (open).
- **Consensus default**: Consensus verification default includes `kernel` for per-crate validation; native pure-Rust verification default is tracked under #166 (open).
- **Deep reorg memory bounding**: Disconnect planning preloads branch block bodies into memory; streaming bounded-memory disconnect is tracked under #206 (open).
- **Index recovery decoupling**: Startup currently initializes index stores synchronously; async index recovery and checkpoint fallback transparency are tracked under #208 and #209 (open).
- **Composition layer slimming**: Shifting domain-specific logic to owning crates and slimming `crates/node` to pure composition is tracked under #217 (open).

## Features

- `default` (enables `fjall`, `kernel`, and `zmq`): the performance-oriented fjall
  storage backend plus the bitcoinkernel consensus verifier and ZMQ notifications,
  so per-crate `cargo check` works out of the box. The `bitcoin-rs` binary's own
  defaults are the pure-Rust `fjall,redb,zmq`; `kernel` stays opt-in there.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `mdbx`: forward the mdbx backend to the crates that provide one.
- `kernel`: route consensus verification through bitcoinkernel
  (`bitcoin-rs-consensus/kernel`).
- `checksig-census`: `kernel` plus the consensus crate's checksig-census
  instrumentation.
- `mimalloc`: pulls the optional `mimalloc` dependency; the
  `mainnet_prefix_replay` example registers it as the global allocator.
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the in-process metrics recorder does not start an HTTP listener.
Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
