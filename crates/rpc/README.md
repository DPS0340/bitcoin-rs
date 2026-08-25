# bitcoin-rs-rpc

The synchronous, Bitcoin Core-compatible JSON-RPC and REST surface of the node: method dispatch, HTTP Basic and cookie authentication, and the watch-only wallet boundary that disables every private-key RPC.

`RpcServer::bind` binds a TCP listener and `serve` (or `serve_with_shutdown` for controlled shutdown) runs the blocking accept loop, handing each connection to a bounded worker thread under a per-connection idle timeout. Each request is authenticated by `Auth`, then matched to a Core-compatible handler by `Handler::dispatch`, which reads shared node state through the dependency-injected `Context` — the boundary carrying `ChainControl` consensus-affecting operations, `PruneService`, `TxIndexQuery`, `NetworkState`, and `ZmqNotification`. Failures map to JSON-RPC error codes through `RpcError`, and Bitcoin Core-compatible REST endpoints (`rest`) are served on the same listener when enabled. The surface is intentionally watch-only: RPCs that would reveal, import, create, or use private keys return an internal error, `wallet has no private keys; use external signer`, while PSBT construction, combination, analysis, and finalization remain available because they are driven by external signers without this process holding private key material.

## Interface architecture and implementation guidance

### 1. Protocol demuxing and authentication
- **Transport Demuxing**: `RpcServer::serve_connection` (`crates/rpc/src/server.rs`) demuxes incoming HTTP requests by path prefix before authentication:
  - `/rest/*`: Routed to unauthenticated `rest::route`.
  - `/` (GET/POST) and Esplora paths: Routed to unauthenticated `esplora::route`.
  - JSON-RPC POST (`/`): Authenticated via `Auth::validate_header` (`crates/rpc/src/server.rs`) (HTTP Basic / Cookie).
- **Watch-Only Boundary**: Methods requiring private keys return `RpcError::MethodDisabled` (`wallet has no private keys; use external signer`). PSBT endpoints remain fully functional without private key material.

### 2. Deep module separation and system owners
- **Adapters vs Modules**: RPC handlers, REST routes, and Esplora projections sit at the transport Seam as pure wire Adapters translating network payloads into deep Module Interfaces (`Context`, `BlockTree`, `TxIndexQuery`, `applied_tip`). They leverage domain-local concurrency and storage mechanisms without leaking database locks, indexing details, or consensus logic into protocol serialization.
- **System Owners**:
  - **Routing & Demux**: `RpcServer::serve_connection` in `crates/rpc/src/server.rs` demuxes path prefixes before authentication.
  - **Authentication**: `Auth::validate_header` in `crates/rpc/src/server.rs` guards JSON-RPC requests while keeping REST and Esplora unauthenticated.
  - **Error Codes**: All wire failures map through `RpcError` in `crates/rpc/src/error.rs` to maintain exact Bitcoin Core numeric error code parity (`-32600` through `-32603`, `-1`, `-3`, `-5`, `-8`, `-22`, `-25`, `-26`, `-27`).
  - **Read Consistency & Tip Fencing**: Multi-record queries against chain state must use two-phase optimistic fencing (`capture_chain_view` / `ensure_chain_view` in `crates/rpc/src/esplora.rs`) or active-tip ancestry verification against `BlockTree` (`crates/rpc/src/rest.rs`). If a reorg occurs during execution, return `503 Service Unavailable`.
  - **Index Query Budgets**: Statistical and script index queries must be bounded by `QueryBudget` (`crates/node/src/txindex_worker.rs`, `crates/rpc/src/esplora.rs`) to prevent memory exhaustion and disk query starvation.
  - **Multi-Format Rendering**: REST endpoints (`crates/rpc/src/rest.rs`, `crates/rpc/src/handlers/`) support `.json`, `.hex`, and `.bin` formats with explicit `Content-Type` headers (`application/json`, `text/plain`, `application/octet-stream`).

### 3. Caching and pagination rules
- **HTTP Caching (RFC 9111)**:
  - Confirmed blocks, headers, and immutable transactions: `Cache-Control: public, immutable, max-age=86400`.
  - Volatile tips, mempool, and unconfirmed transactions: `Cache-Control: no-store`.
  - REST endpoints must ignore unrecognized query parameters to maintain downstream cache efficiency.
- **Cursor Pagination**: Use immutable hash cursors (`last_seen_txid`, block hashes) rather than integer offsets for volatile datasets.

### 4. Non-blocking event notifications
- **ZMQ Framing**: ZeroMQ notifications (`ZmqPublisher` in `crates/node/src/zmq_publisher.rs`) emit 3-part multipart frames `[topic, body, 4-byte LE sequence]`.
- **Non-Blocking Delivery**: Socket writes must use non-blocking sends (`zmq::DONTWAIT`). Notification buffer saturation must drop messages at the high-water mark rather than stalling block validation or consensus execution.
- **Reorg Sequencing & Notification Order**: `apply_block_admitted` (`crates/node/src/apply.rs`) enforces block disconnect events (`D`) published before block connect events (`C`).

### 5. Architectural guardrails
- **No Generic Middleware**: Do not introduce heavy async web framework stacks (Axum, Actix, Tower) into `RpcServer`.
- **No Speculative Traits**: Reject universal query abstractions across distinct wire protocols.
- **No URL Versioning**: Reject `/v1/`, `/v2/` URL prefixes for Bitcoin Core-compatible endpoints.

## Features

- `rocksdb`, `fjall`, `redb`: forward the storage-backend selection into the `coinstats`, `storage`, and `p2p` crates.
- `mdbx`: forwards the MDBX storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
