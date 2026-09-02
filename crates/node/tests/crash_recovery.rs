//! Integration tests for crash recovery across all enabled storage backends.
//!
//! Exercises the recovery-meta sidecar protocol (`crates/node/src/crash_recovery.rs`)
//! over every backend compiled into this test binary.  Each test loops over
//! `available_backends()` so a single `cargo test --features rocksdb,fjall,redb`
//! invocation exercises RocksDB, fjall, and redb in one run.
//!
//! Proof surface:
//! - **Simulated interrupted apply**: advance `height` past
//!   `last_committed_height`, restart, and assert the gap is replayed and the
//!   meta converges to `last_committed == height`.
//! - **Atomic write protocol**: after a clean commit the sidecar is readable
//!   and no `.tmp` residue remains.
//! - **Torn meta refusal**: a corrupt `.json` (simulating a crash that tore
//!   the sidecar) is refused on restart — `read_meta` returns `Err`, not a
//!   silent default.
//! - **Stale `.tmp` tolerance**: a orphaned `.tmp` left by a crashed write
//!   does not interfere with recovery; the valid `.json` is read and the
//!   next `write_meta` cleans up the stale temp.

#![cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Config, Network, crash_recovery, state::NodeState};

/// Returns the list of storage backends compiled into this test binary.
fn available_backends() -> Vec<&'static str> {
    let mut backends = Vec::new();
    #[cfg(feature = "rocksdb")]
    backends.push("rocksdb");
    #[cfg(feature = "fjall")]
    backends.push("fjall");
    #[cfg(feature = "redb")]
    backends.push("redb");
    backends
}

fn make_config(temp: &tempfile::TempDir, backend: &str) -> Config {
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(format!("node-{backend}"));
    config.storage_backend = backend.to_owned();
    config.p2p_listen.clear();
    config
}

/// Simulated interrupted apply: advance `height` to 10, rewind
/// `last_committed_height` to 7, restart, and assert the gap [8, 9, 10] is
/// replayed and the meta converges.
#[test]
fn recovery_replays_from_last_committed_height_to_tip() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        {
            let state = NodeState::open(config.clone())?;
            for height in 1..=10 {
                state.record_synthetic_block_for_recovery(height)?;
            }
            crash_recovery::set_last_committed_height(&state, 7)?;
        }

        let restarted = NodeState::open(config)?;
        crash_recovery::recover_if_needed(&restarted)?;

        let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
        assert_eq!(
            meta.height, 10,
            "{backend}: height should be 10 after recovery"
        );
        assert_eq!(
            meta.last_committed_height, 10,
            "{backend}: last_committed_height should converge to 10"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![8, 9, 10],
            "{backend}: replay should cover the gap [8, 9, 10]"
        );
    }
    Ok(())
}

/// Atomic write protocol: after a clean commit the sidecar is readable and
/// no `.tmp` residue remains.
#[test]
fn recovery_meta_write_leaves_readable_sidecar_without_tmp() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        let meta_path = config.data_dir.join("recovery_meta.json");
        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        {
            let state = NodeState::open(config)?;
            state.record_synthetic_block_for_recovery(3)?;
        }

        assert!(meta_path.exists(), "{backend}: meta file should exist");
        let bytes = std::fs::read(&meta_path)
            .with_context(|| format!("read recovery metadata {}", meta_path.display()))?;
        let meta: crash_recovery::Meta = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse recovery metadata {}", meta_path.display()))?;
        assert_eq!(meta.height, 3, "{backend}: height should be 3");
        assert_eq!(
            meta.last_committed_height, 3,
            "{backend}: last_committed_height should be 3"
        );
        assert!(
            !tmp_path.exists(),
            "{backend}: no .tmp residue after atomic rename"
        );
    }
    Ok(())
}

/// Torn meta refusal: corrupt the `.json` sidecar (simulating a crash that
/// tore the file), reopen, and assert `read_meta` returns `Err` — the node
/// refuses torn state rather than silently defaulting.
#[test]
fn torn_meta_after_crash_is_refused() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        // Establish a clean state at height 5.
        {
            let state = NodeState::open(config.clone())?;
            for height in 1..=5 {
                state.record_synthetic_block_for_recovery(height)?;
            }
        }

        // Simulate a crash that tore the meta file — write garbage bytes
        // directly into recovery_meta.json.  This is the failure mode the
        // atomic-rename protocol prevents in production; the test proves the
        // read path detects and refuses it rather than silently recovering
        // from a default or stale value.
        let meta_path = config.data_dir.join("recovery_meta.json");
        std::fs::write(&meta_path, b"{ this is not valid json }")?;

        let restarted = NodeState::open(config)?;
        let result = crash_recovery::read_meta(&restarted);
        assert!(
            result.is_err(),
            "{backend}: torn meta must be refused (returned Err), not silently accepted"
        );

        // recover_if_needed propagates the error — the node does not proceed.
        let recovery_result = crash_recovery::recover_if_needed(&restarted);
        assert!(
            recovery_result.is_err(),
            "{backend}: recover_if_needed must fail when meta is torn"
        );
    }
    Ok(())
}

/// Stale `.tmp` tolerance: a `.tmp` orphaned by a crashed write does not
/// interfere with recovery.  The valid `.json` is read, recovery succeeds,
/// and a subsequent `write_meta` overwrites the stale temp cleanly.
#[test]
fn stale_tmp_after_crash_does_not_corrupt_recovery() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);

        // Establish a clean state at height 8, then simulate an interrupted
        // apply by rewinding last_committed_height to 5.
        {
            let state = NodeState::open(config.clone())?;
            for height in 1..=8 {
                state.record_synthetic_block_for_recovery(height)?;
            }
            crash_recovery::set_last_committed_height(&state, 5)?;
        }

        // Plant a stale .tmp from a crashed write — garbage that must never
        // be read as the recovery meta.
        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        std::fs::write(&tmp_path, b"garbage from a crashed write")?;

        // Restart: recovery reads the valid .json and ignores the stale .tmp.
        let restarted = NodeState::open(config)?;
        crash_recovery::recover_if_needed(&restarted)?;

        let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
        assert_eq!(meta.height, 8, "{backend}: height should be 8");
        assert_eq!(
            meta.last_committed_height, 8,
            "{backend}: last_committed_height should converge to 8"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![6, 7, 8],
            "{backend}: replay should cover the gap [6, 7, 8]"
        );

        // A subsequent write_meta overwrites the stale .tmp cleanly.
        crash_recovery::write_meta(&restarted, &meta)?;
        assert!(
            !tmp_path.exists(),
            "{backend}: stale .tmp cleaned up by subsequent write"
        );
    }
    Ok(())
}
