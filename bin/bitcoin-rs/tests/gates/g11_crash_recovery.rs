//! G11 — Crash recovery.
//!
//! **G11 — Crash recovery.** Exercises the recovery-meta sidecar protocol
//! across every compiled storage backend and the recovery-evidence
//! bounded current/previous file protocol.  The gate requires each named
//! test to execute and pass; a missing test is a RED gate, not a silent
//! skip.
//!
//! Proof surface, scoped to what the named tests actually execute:
//!
//! **Recovery-meta sidecar** (`crates/node/tests/crash_recovery.rs`):
//! - Simulated interrupted apply: advance `height` past
//!   `last_committed_height`, restart, and assert the gap is replayed and
//!   the meta converges to `last_committed == height`.
//! - Atomic write protocol: after a clean commit the sidecar is readable
//!   and no `.tmp` residue remains.
//! - Torn meta refusal: a corrupt `.json` (simulating a crash that tore
//!   the sidecar) is refused on restart — `read_meta` returns `Err`, not
//!   a silent default.
//! - Stale `.tmp` tolerance: an orphaned `.tmp` left by a crashed write
//! - Periodic checkpoint publication: the worker publishes a checkpoint
//!   during sync without any clean shutdown, and a killed-and-reopened
//!   node resumes from the periodic checkpoint rather than the older
//!   clean-shutdown one (issue #219).
//!   does not interfere with recovery; the valid `.json` is read and the
//!   next `write_meta` cleans up the stale temp.
//!
//! **Recovery-evidence bounded protocol** (`crates/node/src/recovery_evidence.rs`):
//! - Witness and marker files round-trip and fall back to `.prev` when
//!   current is missing.
//! - A foreign-genesis or wrong-format current cannot displace a valid
//!   `.prev` (semantic validation before rotation).
//! - Checkpoint-fallback detection requires same-genesis, older-epoch,
//!   strictly-higher witness.
//! - An oversized evidence file is ignored.
//!
//! Not exercised here: full-stack `kill -9` of a running node process,
//! real block-body re-application through the UTXO listener, the
//! `DisconnectMarker` `InFlight`/`RolledBack` phase protocol (covered by
//! `EVT-05` unit tests in `crates/node/src/apply.rs`), and live
//! `getblockchaininfo` warning emission over RPC.

#![allow(clippy::expect_used)]

use std::process::Command;

fn cargo() -> Command {
    Command::new(env!("CARGO"))
}

/// Loud-fail guard: require each named test to appear as executed-and-passed
/// in stdout.
fn require_ran(stdout: &str, names: &[&str]) {
    for name in names {
        assert!(
            stdout.contains(&format!("{name} ... ok")),
            "expected test `{name}` did not run or did not pass:\n{stdout}"
        );
    }
}

fn output_or_panic(mut command: Command, context: &str) -> std::process::Output {
    match command.output() {
        Ok(output) => output,
        Err(error) => panic!("{context}: failed to spawn cargo: {error}"),
    }
}

#[test]
fn crash_recovery_gate() {
    // -------------------------------------------------------------------
    // 1. Recovery-meta sidecar integration tests (all backends).
    // -------------------------------------------------------------------
    let integration_tests = &[
        "recovery_replays_from_last_committed_height_to_tip",
        "recovery_meta_write_leaves_readable_sidecar_without_tmp",
        "torn_meta_after_crash_is_refused",
        "stale_tmp_after_crash_does_not_corrupt_recovery",
        "periodic_checkpoint_anchors_progress_without_clean_shutdown",
        "periodic_checkpoint_published_during_sync_without_shutdown",
    ];

    let output = output_or_panic(
        {
            let mut cmd = cargo();
            cmd.args([
                "test",
                "-p",
                "bitcoin-rs-node",
                "--no-default-features",
                "--features",
                "rocksdb,fjall,redb",
                "--test",
                "crash_recovery",
            ]);
            cmd
        },
        "spawn crash_recovery integration test",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "crash_recovery integration tests failed:\n{stdout}\n{stderr}"
    );
    require_ran(&stdout, integration_tests);

    // -------------------------------------------------------------------
    // 2. Recovery-evidence bounded protocol unit tests.
    // -------------------------------------------------------------------
    // Each required unit test runs in its own subprocess (libtest accepts a
    // single positional filter).  (package, test name, failure context).
    let evidence_tests: &[(&str, &str, &str)] = &[
        (
            "bitcoin-rs-node",
            "witness_round_trips_and_falls_back_to_prev",
            "witness current/prev fallback",
        ),
        (
            "bitcoin-rs-node",
            "foreign_genesis_current_cannot_displace_valid_prev",
            "witness semantic rotation: foreign current cannot displace valid prev",
        ),
        (
            "bitcoin-rs-node",
            "foreign_genesis_marker_current_cannot_displace_valid_prev",
            "marker semantic rotation: foreign current cannot displace valid prev",
        ),
        (
            "bitcoin-rs-node",
            "same_genesis_older_epoch_higher_witness_warns",
            "checkpoint-fallback detection: older-epoch higher witness warns",
        ),
        (
            "bitcoin-rs-node",
            "equal_or_lower_witness_does_not_warn",
            "checkpoint-fallback detection: equal/lower witness does not warn",
        ),
        (
            "bitcoin-rs-node",
            "oversized_evidence_file_is_ignored",
            "oversized evidence file is ignored",
        ),
        ("bitcoin-rs-node", "marker_round_trips", "marker round-trip"),
        (
            "bitcoin-rs-node",
            "marker_last_event_wins_preserves_prev",
            "marker last-event-wins preserves prev",
        ),
    ];

    for &(package, name, context) in evidence_tests {
        let output = output_or_panic(
            {
                let mut cmd = cargo();
                cmd.args(["test", "-p", package, name]);
                cmd
            },
            &format!("spawn cargo test for {context}"),
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{context} test failed:\n{stdout}\n{stderr}"
        );
        require_ran(&stdout, &[name]);
    }
}
