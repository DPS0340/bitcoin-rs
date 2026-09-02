//! G4 — Consensus test vectors.
//! **G4 — Consensus test vectors.** `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json` from Bitcoin Core's `src/test/data/` are vendored into `crates/consensus/tests/vectors/` and run as `#[test]`s; 100 % pass.

#![allow(clippy::expect_used)]

/// Gate G4 runs only the consensus crate's vector test binary — the
/// shippability criterion (Core's `tx_valid`, `tx_invalid`, `script_tests`,
/// `sighash` vectors pass) — rather than re-running the whole consensus crate
/// suite, whose unit tests already have their own owner.
#[test]
fn consensus_test_vectors() {
    let status = std::process::Command::new(env!("CARGO"))
        .args([
            "test",
            "-p",
            "bitcoin-rs-consensus",
            "--test",
            "vectors",
            "--no-fail-fast",
        ])
        .status()
        .expect("spawn cargo");
    assert!(
        status.success(),
        "consensus vector tests must pass — tx_valid.json, tx_invalid.json, script_tests.json, sighash.json"
    );
}
