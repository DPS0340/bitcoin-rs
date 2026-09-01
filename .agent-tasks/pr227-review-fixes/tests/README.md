# Task proof

This task-local record captures verification for the PR #227 review fixes.

- `cargo fmt --all -- --check`
- `cargo metadata --no-deps --format-version 1`
- `git diff --check origin/main...HEAD`
- `cargo test -p bitcoin-rs-mempool --test pareto_ordering`
- `cargo test -p bitcoin-rs-utxo --lib --tests --no-default-features`
- `cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings`
- `cargo clippy -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- -D warnings -A clippy::unnecessary_wraps`
- `cargo check -p bitcoin-rs-node --all-targets --no-default-features --features fjall`
- `cargo check -p bitcoin-rs-utxo --bench utxo_commit`
- `cargo check -p bitcoin-rs-mempool --bench pareto`
- `cargo check -p bitcoin-rs-consensus --bench merkle`
- `cargo check -p bitcoin-rs-index --bench history_resolve --features rocksdb`
- `cargo bench -p bitcoin-rs-utxo --no-run`

The missing backticks in `crates/node/benches/sync_pipeline.rs` were fixed.
The retained UTXO, mempool, and consensus benchmark targets compile, and the
UTXO benchmark binary links successfully. The index target is blocked on
Windows because RocksDB's bindgen build cannot find `libclang`; the Linux CI
environment provides that dependency.
Mempool and consensus retained benchmark clippy pass. UTXO bench clippy is
blocked first by the pre-existing Windows `clippy::unnecessary_wraps` error in
`crates/storage/src/block_file.rs`.
The full node clippy command remains blocked first by the pre-existing Windows
`clippy::unnecessary_wraps` error in `crates/storage/src/block_file.rs`. The
narrower bench check, with that unrelated lint excluded, reaches the existing
Windows-only `signal_hook::iterator` conditional-compilation error. The
mempool and UTXO tests pass; formatting, metadata, and diff checks pass.
