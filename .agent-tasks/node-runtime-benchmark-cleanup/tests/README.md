# Task proof

Proof for this cleanup is recorded by the verification commands run for the
branch:

- `cargo fmt --all -- --check`
- `cargo metadata --no-deps --format-version 1`
- `git diff --check`
- targeted search confirming no `noop_listener` or `utxo_build_commit` arms
  remain in `crates/utxo/benches/utxo_commit.rs`
