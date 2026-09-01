# Task proof

Proof for this cleanup is recorded by the verification commands run for the
branch:

- `cargo fmt --all -- --check`
- `cargo metadata --no-deps --format-version 1`
- `git diff --check`
- targeted search confirming no `noop_listener` or `utxo_build_commit` arms
  remain in `crates/utxo/benches/utxo_commit.rs`
- targeted search confirming no G14 runner, benchmark-campaign, CHECKSIG-census,
  memory-attribution example, or unconsumed corpus API remains
- targeted search confirming fuzz targets do not consume retired benchmark or
  replay infrastructure
- `cargo check -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall`
- `cargo check -p bitcoin-rs-utxo --benches --no-default-features`
- `cargo check -p bitcoin-rs-mempool --benches`
- `cargo check -p bitcoin-rs-index --benches`
- `cargo check -p bitcoin-rs-rpc --benches`

## Recorded result

- Formatting, metadata, diff whitespace, all five retained non-node bench target
  checks, and the mempool/UTXO focused tests passed on Windows.
- `cargo test -p bitcoin-rs-mempool --test pareto_ordering`: 5 passed.
- `cargo test -p bitcoin-rs-utxo --lib --tests --no-default-features`: all
  unit and integration tests passed.
- The node bench check remains blocked before compiling the bench by the
  pre-existing Windows-only `signal_hook::iterator` cfg error.
- Storage's three disk-usage tests remain red on Windows because the running
  byte counter sees written bytes while the directory scan reports zero; 13
  other storage unit tests passed.
- Clippy passed for mempool benches. UTXO/index/RPC clippy reached the existing
  Windows `sync_blocks_dir` `unnecessary_wraps` diagnostic in storage.
