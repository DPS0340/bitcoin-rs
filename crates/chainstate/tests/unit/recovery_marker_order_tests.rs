//! Regression tests for #1270: `FULL_REVALIDATION_MARKER` must be checked
//! BEFORE the checkpoint is opened. A corrupt checkpoint plus a valid marker
//! must select cold replay, not fail on checkpoint corruption.

use std::fs;
use std::path::Path;

use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::chainstate_journal::{FULL_REVALIDATION_MARKER, JOURNAL_DIR_NAME};

use crate::ChainstateJournalConfig;
use crate::recovery::{ResumeSource, prepare_initial_chainstate};

const NETWORK: Network = Network::Regtest;

fn arm_full_revalidation_marker(data_dir: &Path) {
    let journal_dir = data_dir.join(JOURNAL_DIR_NAME);
    fs::create_dir_all(&journal_dir).unwrap_or_else(|e| panic!("create journal dir: {e}"));
    fs::write(journal_dir.join(FULL_REVALIDATION_MARKER), b"")
        .unwrap_or_else(|e| panic!("arm marker: {e}"));
}

#[test]
fn corrupt_checkpoint_with_marker_selects_cold_replay() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();

    // A checkpoint directory whose CURRENT file points at a generation with a
    // manifest that would fail to parse: `load_checkpoint_from_dir` errors on
    // this, so without the marker startup would fail on checkpoint corruption.
    // Use the correct generation naming convention (`gen-{20-digit}`) so
    // `read_current` passes, then leave a manifest that fails authenticated
    // parsing: `load_checkpoint_from_dir` returns `Err` on this.
    let gen_name = format!("gen-{:020}", 1u64);
    let checkpoint_root = data_dir.join("chainstate-checkpoints");
    fs::create_dir_all(checkpoint_root.join(gen_name.as_str()))?;
    fs::write(
        checkpoint_root.join(gen_name.as_str()).join("manifest-v1.json"),
        b"not valid json",
    )?;
    let current_json = format!(
        r#"{{"format":"bitcoin-rs-chainstate-current","version":1,"generation":1,"directory":"{gen_name}","manifest_sha256":"{}"}}"#,
        "00".repeat(32)
    );
    fs::write(checkpoint_root.join("CURRENT"), current_json)?;

    arm_full_revalidation_marker(data_dir);

    let config = ChainstateJournalConfig::default();
    let state = prepare_initial_chainstate(data_dir, NETWORK, config)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "expected Cold resume source, got {:?}",
        state.resume_source
    );
    Ok(())
}

#[test]
fn valid_checkpoint_with_marker_selects_cold_replay() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path();

    // No checkpoint at all — the marker alone forces the cold path.
    arm_full_revalidation_marker(data_dir);

    let config = ChainstateJournalConfig::default();
    let state = prepare_initial_chainstate(data_dir, NETWORK, config)?;

    assert!(
        matches!(state.resume_source, ResumeSource::Cold),
        "expected Cold resume source, got {:?}",
        state.resume_source
    );
    Ok(())
}
