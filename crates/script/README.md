# bitcoin-rs-script

Script verification for the portable posture, plus the sigop counters, signature-hash caching, and taproot helpers that surround script execution.

`Interpreter::execute` and `Interpreter::execute_with_prevouts` run one script spend under a `VerifyFlags` set (parseable from Core test-vector flag strings via `VerifyFlags::from_core_names`): the local BIP341 path verifies Taproot key-path spends in full — multi-input spends require the complete ordered prevout set — while the portable non-taproot path accepts only bare `OP_TRUE` spends; every other script class requires the kernel production path. Around the interpreter sit `sigops` (signature-operation counting), `sighash_cache` (the signature-hash cache wrapper), `taproot` (Taproot verification helpers), `batch` (rayon-backed batch Schnorr verification, engaged by block validation once a block carries `Interpreter::BATCH_SCHNORR_THRESHOLD` taproot inputs), `opcodes` (opcode re-exports and a local opcode newtype), and `stack` (bounded stack infrastructure for a future hand-rolled interpreter). Failures surface as `ScriptError`.

## Features

- `rocksdb`, `fjall`, `redb`: no-op in this crate — this crate has no backend code; the names exist so the shared storage-backend features can be enabled uniformly across the workspace.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
