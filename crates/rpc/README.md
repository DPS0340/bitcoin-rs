# bitcoin-rs-rpc

The synchronous, Bitcoin Core-compatible JSON-RPC and REST surface of the node: method dispatch, HTTP Basic and cookie authentication, and a wallet-free method surface — every RPC that would require private key material is simply absent.

`RpcServer::bind` binds a TCP listener and `serve` (or `serve_with_shutdown` for controlled shutdown) runs the blocking accept loop, handing each connection to a bounded worker thread under a per-connection idle timeout. Each request is authenticated by `Auth`, then matched to a Core-compatible handler by `Handler::dispatch`, which reads shared node state through the dependency-injected `Context` — the boundary carrying `ChainControl` consensus-affecting operations, `PruneService`, `TxIndexQuery`, `NetworkState`, and `ZmqNotification`. Failures map to JSON-RPC error codes through `RpcError`, and Bitcoin Core-compatible REST endpoints (`rest`) are served on the same listener when enabled. RPCs that would reveal, import, create, or use private keys are not implemented and answer `method not found`, while PSBT combination and finalization remain available because they are driven by external signers without this process holding private key material.

## Capability boundary

`ContextHandles` groups the node-owned handles by capability — `chain`,
`mempool`, `indexes`, `network`, `mining` — and `Context::from_handles` is the
single composition point. RPC consumes node capabilities through these groups;
it never names a storage backend or backend engine type, and the crate exposes
no backend cargo feature (`g17_dependency_direction` proves both from
`cargo metadata`).

## Contract ownership

External interface contracts governing RPC, REST, and ZMQ surfaces are defined in `docs/contracts/`:

- **Dispatch and manifest authority**: Method dispatch, route registration, and reference generation follow [`docs/contracts/external-api.md`](../../docs/contracts/external-api.md) (`API-01`, `API-02`).
- **Error mappings and wallet-free surface**: JSON-RPC status codes and keyless method behavior follow [`docs/contracts/external-api.md`](../../docs/contracts/external-api.md) (`API-03`).
- **Read consistency and query budgeting**: Chain-view fencing, active-tip verification, and query bounds follow [`docs/contracts/external-api.md`](../../docs/contracts/external-api.md) (`API-04`).
- **Index and capability reporting**: Index query gating and `getcapabilities`/`getindexinfo` reporting follow [`docs/contracts/indexing.md`](../../docs/contracts/indexing.md) (`IDX-01`–`IDX-03`) and [`docs/contracts/extensions.md`](../../docs/contracts/extensions.md) (`EXT-05`).
- **Mempool admission RPCs**: `sendrawtransaction` and `testmempoolaccept` validation follow [`docs/contracts/mempool-policy.md`](../../docs/contracts/mempool-policy.md) (`POL-01`) and [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-01`).
- **ZMQ event notification**: Multipart sequence framing and non-blocking notification delivery follow [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-03`) and [`docs/contracts/chain-events.md`](../../docs/contracts/chain-events.md) (`EVT-01`, `EVT-02`).

## Live gaps

- **Full Core differential coverage**: Complete differential test fixtures and versioned response types against Bitcoin Core 31.x are tracked under #78 (open).
- **Typed embedding surface**: In-process typed application engine API as an alternative to localhost JSON-RPC daemon boundary is tracked under #145 (open).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
