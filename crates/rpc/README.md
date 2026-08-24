# bitcoin-rs-rpc

The synchronous, Bitcoin Core-compatible JSON-RPC and REST surface of the node: method dispatch, HTTP Basic and cookie authentication, and the watch-only wallet boundary that disables every private-key RPC.

`RpcServer::bind` binds a TCP listener and `serve` (or `serve_with_shutdown` for controlled shutdown) runs the blocking accept loop, handing each connection to a bounded worker thread under a per-connection idle timeout. Each request is authenticated by `Auth`, then matched to a Core-compatible handler by `Handler::dispatch`, which reads shared node state through the dependency-injected `Context` — the boundary carrying `ChainControl` consensus-affecting operations, `PruneService`, `TxIndexQuery`, `NetworkState`, and `ZmqNotification`. Failures map to JSON-RPC error codes through `RpcError`, and Bitcoin Core-compatible REST endpoints (`rest`) are served on the same listener when enabled. The surface is intentionally watch-only: RPCs that would reveal, import, create, or use private keys return an internal error, `wallet has no private keys; use external signer`, while PSBT construction, combination, analysis, and finalization remain available because they are driven by external signers without this process holding private key material.

## Features

- `rocksdb`, `fjall`, `redb`: forward the storage-backend selection into the `coinstats`, `storage`, and `p2p` crates.
- `mdbx`: forwards the MDBX storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
