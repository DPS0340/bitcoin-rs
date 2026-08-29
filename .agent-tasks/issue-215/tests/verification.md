# Verification evidence

Environment: Ubuntu WSL, Rust/Cargo 1.95.0, `fjall` storage feature, kernel disabled.

- `cargo fmt --all -- --check`: passed on Windows.
- `cargo test -p bitcoin-rs-node --no-default-features --features fjall sync::tests::handshake_publication_preserves_pre_registered_current_lease -- --exact --nocapture`: 1 passed.
- `cargo test -p bitcoin-rs-node --no-default-features --features fjall sync::tests::peer_registration_reconnects_after_outbound_map_removal -- --exact --nocapture`: 1 passed.
- `cargo test -p bitcoin-rs-node --no-default-features --features fjall --lib`: 509 passed.
- `cargo clippy -p bitcoin-rs-node --no-default-features --features fjall --lib --tests -- -D warnings`: passed.
- `git diff --check`: passed.

The default-feature test command was also attempted on Windows, but the local environment has no native static `bitcoinkernel` library. The Windows non-kernel build is independently blocked by the existing Unix-only `signal_hook::iterator` import in `crates/node/src/signal.rs`; Linux WSL was therefore used for executable and lint verification.
