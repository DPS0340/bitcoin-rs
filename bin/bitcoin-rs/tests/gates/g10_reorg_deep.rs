//! G10 — Reorganization execution and planning gate.
//!
//! **G10 — Reorganization execution and planning.** Runs one `cargo test`
//! subprocess per required test — libtest accepts a single positional filter,
//! so multiple filters in one invocation are invalid — and requires every
//! named test to execute and pass.
//!
//! Proof surface, scoped to what the named tests actually execute:
//! - `bitcoin-rs-chain` planner test (`plans_deep_reorg_to_common_fork`):
//!   depth-100 competing-fork disconnect/connect plan calculation over an
//!   in-memory header tree — no block bodies, no chainstate mutation.
//! - `bitcoin-rs-node` unit tests: single-block disconnect restores the exact
//!   prior UTXO set and applied tip; sequence-event ordering (D before C
//!   across a rival fork; D on invalidateblock) captured through an injected
//!   recording publisher, not a live ZMQ socket; a disconnect body-load
//!   failure moves nothing.
//! - `bitcoin-rs-node` txindex worker tests: watermark rollback and
//!   stale-prefix repair on the next reconciliation pass across rival branch
//!   reorganizations.
//!
//! Not exercised here: full-stack 100-block reorg execution, coinstats
//! rewind, mempool reconsideration, and live `pubsequence` emission.

use std::process::Command;

fn cargo() -> Command {
    Command::new(env!("CARGO"))
}

/// Loud-fail guard: require each named test to appear as executed-and-passed in stdout.
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
fn reorg_deep_test() {
    // libtest accepts exactly one positional filter per invocation, so each
    // required test runs in its own subprocess: (package, test name, failure
    // context). Success and executed-and-passed checks apply to every
    // subprocess output.
    let required: &[(&str, &str, &str)] = &[
        (
            "bitcoin-rs-chain",
            "plans_deep_reorg_to_common_fork",
            "chain crate depth-100 reorg planner",
        ),
        (
            "bitcoin-rs-node",
            "disconnecting_the_tip_restores_the_exact_prior_state",
            "node disconnect state restoration",
        ),
        (
            "bitcoin-rs-node",
            "reorg_sequence_events_disconnect_old_tip_before_connecting_new_branch",
            "node reorg sequence-event ordering",
        ),
        (
            "bitcoin-rs-node",
            "invalidate_block_disconnects_active_tip_and_emits_sequence_event",
            "node invalidateblock disconnect",
        ),
        (
            "bitcoin-rs-node",
            "a_disconnect_body_store_failure_moves_nothing",
            "node disconnect body-load failure safety",
        ),
        (
            "bitcoin-rs-node",
            "forward_commit_overlapping_rival_reorg_repairs_on_next_pass",
            "txindex rival-reorg watermark repair",
        ),
        (
            "bitcoin-rs-node",
            "rollback_of_recanonicalized_watermark_repairs_on_next_pass",
            "txindex recanonicalized watermark rollback",
        ),
    ];

    for &(package, name, context) in required {
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
