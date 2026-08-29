//! G16 — Extension model gate.
//!
//! **G16 — extension model.** The extension registry validates every enabled
//! extension combination before `NodeState::open` (so an invalid combination
//! fails before any storage opens and before networking exists), core tip
//! progression is identical whether the reference block filter extension is
//! disabled or enabled, and a lagging or failing extension can never stall
//! block application.
//!
//! Proof surface:
//! - `crates/node/tests/extensions.rs` — registry validation literals,
//!   disabled/enabled tip equivalence, restart reconciliation, and
//!   apply-outpaces-consumer progress.
//! - `crates/node/src/filterindex_worker.rs` unit tests — a failing or
//!   body-starved namespace store surfaces as a worker failure without
//!   blocking the apply path (apply never touches the extension store).
//! - the `bitcoin-rs` binary itself, spawned below, must exit non-zero on an
//!   invalid combination with the literal dependency error and without any
//!   sign of networking.

use std::path::PathBuf;
use std::process::Command;

fn cargo() -> Command {
    let mut command = Command::new(env!("CARGO"));
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|error| panic!("workspace root must resolve: {error}"));
    command.current_dir(workspace_root);
    command
}

/// Loud-fail guard: `cargo test <filter>` exits 0 even when zero tests match,
/// so each gate arm requires its named tests to appear as executed-and-passed.
fn require_ran(stdout: &str, names: &[&str]) {
    for name in names {
        let marker = format!("{name} ... ok");
        assert!(
            stdout.contains(&marker),
            "expected `{marker}` in cargo test output — gate would be theater:\n{stdout}"
        );
    }
}

fn output_or_panic(mut command: Command, context: &str) -> std::process::Output {
    match command.output() {
        Ok(output) => output,
        Err(error) => panic!("{context}: {error}"),
    }
}

#[test]
fn extension_model_gates() {
    // Arm 1: registry validation, disabled/enabled tip equivalence, restart
    // reconciliation, and lagging-consumer progress at the NodeState level.
    let output = output_or_panic(
        {
            let mut command = cargo();
            command.args(["test", "-p", "bitcoin-rs-node", "--test", "extensions"]);
            command
        },
        "spawn cargo test for node extension tests",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "node extension integration tests failed:\n{stdout}\n{stderr}"
    );
    require_ran(
        &stdout,
        &[
            "extension_validation_rejects_incompatible_capabilities",
            "filter_extension_tip_equivalence_disabled_vs_enabled",
            "filter_extension_restarts_reconcile_from_persisted_pointer",
            "filter_extension_apply_outpaces_a_lagging_consumer",
        ],
    );

    // Arm 2: worker-level failure isolation — an injected namespace write
    // failure or missing body fails the consumer, never the apply path.
    let output = output_or_panic(
        {
            let mut command = cargo();
            command.args([
                "test",
                "-p",
                "bitcoin-rs-node",
                "--lib",
                "filterindex_worker::tests",
            ]);
            command
        },
        "spawn cargo test for filterindex worker unit tests",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "filterindex worker unit tests failed:\n{stdout}\n{stderr}"
    );
    require_ran(
        &stdout,
        &[
            "store_write_failure_is_reported_not_swallowed",
            "missing_body_fails_the_pass_without_touching_the_pointer",
        ],
    );

    // Arm 3: the binary rejects an invalid combination before networking.
    let data_dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(error) => panic!("temp data dir: {error}"),
    };
    let data_path = data_dir.path().join("node");
    let output = output_or_panic(
        {
            let mut command = cargo();
            command.args([
                "run",
                "-q",
                "--package",
                "bitcoin-rs",
                "--bin",
                "bitcoin-rs",
                "--",
                "--network",
                "regtest",
                "--data-dir",
                data_path.to_str().unwrap_or_default(),
                "--blockfilterindex",
                "--txindex",
                "true",
                "--prune-target-mb",
                "10",
            ]);
            command
        },
        "spawn bitcoin-rs binary with an invalid extension combination",
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "invalid extension combination must exit non-zero:\n{combined}"
    );
    assert!(
        combined.contains("blockfilterindex requires prune disabled"),
        "the literal dependency error must reach the operator:\n{combined}"
    );
    assert!(
        !combined.contains("p2p listener bound") && !combined.contains("rpc listener bound"),
        "validation must fail before any listener binds:\n{combined}"
    );
}
