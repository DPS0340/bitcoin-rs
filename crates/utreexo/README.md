# bitcoin-rs-utreexo

The Utreexo accumulator types behind the node's optional `utreexo` stateless-validation capability: a compact `Accumulator` wrapping rustreexo's Stump and optional Pollard, a full-forest `Bridge` for bridge nodes, and the public `Proof` type.

`Accumulator` comes in two kinds (`AccumulatorKind`): `Accumulator::new_stump` keeps only the compact Stump state, while `Accumulator::new_pollard` also keeps a Pollard in sync so proofs can be cached and generated for remembered leaves. It `add`s leaf hashes, `delete`s leaves only against a matching `Proof` set (mismatched deletion targets are rejected), exposes its current `roots`, and round-trips its state through `serialize_state`/`deserialize_state`. `Bridge` wraps rustreexo's full in-memory `MemForest`: `Bridge::ingest_block` folds a Bitcoin block into the forest using deterministic outpoint leaf hashes, and `Bridge::generate_proof` produces inclusion proofs for target leaf hashes. Failures surface as `UtreexoError` and `BridgeError`.

## Features

- `rocksdb`, `fjall`, `redb`: no-op in this crate — this crate has no backend code; the names exist so the shared storage-backend features can be enabled uniformly across the workspace.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
