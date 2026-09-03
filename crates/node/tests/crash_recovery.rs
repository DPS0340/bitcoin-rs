//! Integration tests for crash recovery across all enabled storage backends.
//!
//! The proof surface covers durability ordering, a bounded replay window from
//! local block bodies, atomic sidecar writes, refusal of torn metadata, and
//! tolerance of stale temporary files.

#![cfg(any(feature = "rocksdb", feature = "fjall", feature = "redb"))]

use anyhow::{Context as _, Result};
use bitcoin_rs_node::{Network, NodeConfig, crash_recovery, state::NodeState};

/// Returns the list of storage backends compiled into this test binary.
fn available_backends() -> Vec<&'static str> {
    [
        cfg!(feature = "rocksdb").then_some("rocksdb"),
        cfg!(feature = "fjall").then_some("fjall"),
        cfg!(feature = "redb").then_some("redb"),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn make_config(temp: &tempfile::TempDir, backend: &str) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(format!("node-{backend}"));
    backend.clone_into(&mut config.storage_backend);
    config.p2p_listen.clear();
    config
}

/// Atomic write protocol: after a sidecar write it is readable, names a
/// non-empty hash, and no temporary residue remains.
#[test]
fn recovery_meta_write_leaves_readable_sidecar_without_tmp() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        let meta_path = config.data_dir.join("recovery_meta.json");
        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        {
            let state = NodeState::open(config, None)?;
            state.record_synthetic_block_for_recovery(3)?;
        }

        assert!(meta_path.exists(), "{backend}: meta file should exist");
        let bytes = std::fs::read(&meta_path)
            .with_context(|| format!("read recovery metadata {}", meta_path.display()))?;
        let meta: crash_recovery::Meta = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse recovery metadata {}", meta_path.display()))?;
        assert_eq!(meta.height, 3, "{backend}: height should be 3");
        assert!(
            !meta.tip_hash_hex.is_empty(),
            "{backend}: tip_hash_hex should be non-empty"
        );
        assert!(
            !tmp_path.exists(),
            "{backend}: no .tmp residue after atomic rename"
        );
    }
    Ok(())
}

/// Torn meta refusal: corrupt the `.json` sidecar and ensure recovery refuses
/// to proceed rather than silently accepting a default or stale value.
#[test]
fn torn_meta_after_crash_is_refused() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        {
            let state = NodeState::open(config.clone(), None)?;
            state.record_synthetic_block_for_recovery(5)?;
        }

        let meta_path = config.data_dir.join("recovery_meta.json");
        std::fs::write(&meta_path, b"{ this is not valid json }")?;

        let restarted = NodeState::open(config, None)?;
        assert!(
            crash_recovery::read_meta(&restarted).is_err(),
            "{backend}: torn meta must be refused"
        );
        assert!(
            crash_recovery::recover_if_needed(&restarted).is_err(),
            "{backend}: recover_if_needed must fail when meta is torn"
        );
    }
    Ok(())
}

/// A stale temporary file does not corrupt recovery.  Synthetic metadata has
/// no matching body, so the degraded path resumes at the restored base.
#[test]
fn stale_tmp_after_crash_does_not_corrupt_recovery() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        {
            let state = NodeState::open(config.clone(), None)?;
            state.record_synthetic_block_for_recovery(8)?;
        }

        let tmp_path = config.data_dir.join("recovery_meta.json.tmp");
        std::fs::write(&tmp_path, b"garbage from a crashed write")?;

        let restarted = NodeState::open(config, None)?;
        crash_recovery::recover_if_needed(&restarted)?;
        assert!(
            restarted.replayed_heights().is_empty(),
            "{backend}: missing bodies must not create fake replay heights"
        );
        assert_eq!(
            restarted
                .applied_tip()
                .load()
                .as_ref()
                .map_or(0, |tip| tip.height),
            0,
            "{backend}: degraded recovery resumes at the restored base"
        );

        let meta = crash_recovery::read_meta(&restarted)?.context("missing recovery metadata")?;
        assert_eq!(meta.height, 8, "{backend}: metadata must remain unchanged");
        crash_recovery::write_meta(&restarted, &meta)?;
        assert!(
            !tmp_path.exists(),
            "{backend}: stale .tmp cleaned up by subsequent write"
        );
    }
    Ok(())
}

// Helpers for mining regtest blocks with valid PoW.

fn compact_to_target(bits: u32) -> [u8; 32] {
    let exponent = usize::from(u8::try_from(bits >> 24).unwrap_or(0));
    let mantissa = u64::from(bits & 0x007f_ffff);
    let mut target = [0_u8; 32];
    if mantissa == 0 || bits & 0x0080_0000 != 0 || exponent > 34 {
        return target;
    }
    let mantissa_bytes = mantissa.to_le_bytes();
    if exponent >= 3 {
        let offset = exponent - 3;
        for (index, byte) in mantissa_bytes.iter().enumerate().take(3) {
            if let Some(slot) = target.get_mut(offset + index) {
                *slot = *byte;
            }
        }
    } else {
        let shifted = mantissa >> (8 * (3 - exponent));
        target[..8].copy_from_slice(&shifted.to_le_bytes());
    }
    target
}

fn pow_met(bits: u32, hash: &bitcoin_rs_primitives::BlockHash) -> bool {
    let target = compact_to_target(bits);
    let hash_le = hash.as_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut script = Vec::with_capacity(payload.len() + 1);
            script.push(u8::try_from(payload.len()).unwrap_or_default());
            script.extend(payload);
            script
        }
    }
}

fn mine_regtest_block(
    prev_hash: bitcoin_rs_primitives::BlockHash,
    height: u32,
    time: u32,
) -> Result<bitcoin_rs_primitives::Block> {
    let coinbase = bitcoin_rs_primitives::Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![bitcoin_rs_primitives::TxIn {
            previous_output: bitcoin_rs_primitives::OutPoint::new(
                bitcoin_rs_primitives::Txid::default(),
                u32::MAX,
            ),
            script_sig: [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![bitcoin_rs_primitives::TxOut {
            value: bitcoin_rs_consensus::block_subsidy(
                height,
                Network::Regtest.subsidy_halving_interval(),
            ),
            script_pubkey: vec![0x51],
        }],
    };
    let mut block = bitcoin_rs_primitives::Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: prev_hash,
            merkle_root: coinbase.txid().into(),
            time,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase],
    };
    while !pow_met(block.header.bits, &block.block_hash()) {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .context("nonce exhausted")?;
    }
    Ok(block)
}

/// Progress is published without a checkpoint and recovery replays the
/// bounded remainder from local bodies, without redownloading any block.
#[test]
fn crash_recovery_resumes_from_local_bodies_without_checkpoint_or_redownload() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let block_count = crash_recovery::PROGRESS_INTERVAL_BLOCKS + 7;

        {
            let state = NodeState::open(config.clone(), None)?;
            let tip = state.apply_block(&genesis)?;
            assert_eq!(tip.height, 0, "{backend}: genesis should be height 0");
            state.publish_checkpoint()?;
        }

        let (published_meta, mined_hashes) = {
            let state = NodeState::open(config.clone(), None)?;
            let mut prev = genesis_hash;
            let mut mined_hashes =
                Vec::with_capacity(usize::try_from(block_count).context("block count overflow")?);
            for height in 1..=block_count {
                let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
                let tip = state.apply_block(&block)?;
                assert_eq!(
                    tip.height, height,
                    "{backend}: block {height} should apply at height {height}"
                );
                mined_hashes.push(block.block_hash());
                prev = block.block_hash();
            }
            let meta = crash_recovery::read_meta(&state)?.context("missing recovery metadata")?;
            assert!(
                meta.height >= crash_recovery::PROGRESS_INTERVAL_BLOCKS,
                "{backend}: progress must publish at the block cadence"
            );
            assert!(
                meta.height <= block_count,
                "{backend}: progress cannot exceed the applied tip"
            );
            (meta, mined_hashes)
        };

        let restarted = NodeState::open(config, None)?;
        assert_eq!(
            restarted
                .applied_tip()
                .load()
                .as_ref()
                .map_or(0, |tip| tip.height),
            0,
            "{backend}: only the clean checkpoint restores initially"
        );
        crash_recovery::recover_if_needed(&restarted)?;

        let recovered = restarted
            .applied_tip()
            .load_full()
            .as_ref()
            .map_or(0, |tip| tip.height);
        assert_eq!(
            recovered, published_meta.height,
            "{backend}: recovered progress"
        );
        assert!(
            block_count - recovered <= crash_recovery::PROGRESS_INTERVAL_BLOCKS,
            "{backend}: replay window must remain bounded"
        );
        assert_eq!(
            restarted.replayed_heights(),
            (1..=recovered).collect::<Vec<_>>(),
            "{backend}: every recovered block came from local bodies"
        );
        assert_eq!(
            restarted.applied_tip().load().as_ref().map(|tip| tip.hash),
            Some(mined_hashes[usize::try_from(recovered - 1).context("height overflow")?].into()),
            "{backend}: recovered tip hash"
        );
    }
    Ok(())
}

/// Cold recovery includes genesis so the first replayed block has a valid base.
#[test]
fn crash_recovery_resumes_before_the_first_clean_checkpoint() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        let block_count = crash_recovery::PROGRESS_INTERVAL_BLOCKS + 3;

        let (published_meta, mined_hashes) = {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
            let mut prev = genesis_hash;
            let mut mined_hashes = vec![genesis_hash];
            for height in 1..=block_count {
                let block = mine_regtest_block(prev, height, genesis.header.time + height)?;
                state.apply_block(&block)?;
                mined_hashes.push(block.block_hash());
                prev = block.block_hash();
            }
            let meta = crash_recovery::read_meta(&state)?.context("missing recovery metadata")?;
            assert!(
                meta.height >= crash_recovery::PROGRESS_INTERVAL_BLOCKS,
                "{backend}: progress must publish at the block cadence"
            );
            (meta, mined_hashes)
        };

        let restarted = NodeState::open(config, None)?;
        assert!(
            restarted.applied_tip().load().is_none(),
            "{backend}: a cold reopen must not restore an applied tip"
        );
        crash_recovery::recover_if_needed(&restarted)?;

        let recovered_tip = restarted
            .applied_tip()
            .load_full()
            .context("cold recovery did not apply the stored tip")?;
        assert_eq!(
            recovered_tip.height, published_meta.height,
            "{backend}: recovered progress"
        );
        assert_eq!(
            restarted.replayed_heights(),
            (0..=published_meta.height).collect::<Vec<_>>(),
            "{backend}: recovery must replay genesis through the durable tip"
        );
        assert_eq!(
            recovered_tip.hash,
            mined_hashes[usize::try_from(recovered_tip.height).context("height overflow")?].into(),
            "{backend}: recovered tip hash"
        );
    }
    Ok(())
}

/// A progress sidecar naming only genesis must still replay genesis on a cold
/// start, because no restored checkpoint tip exists to serve as the base.
#[test]
fn crash_recovery_replays_genesis_when_only_genesis_is_durable() -> Result<()> {
    for backend in available_backends() {
        let temp = tempfile::tempdir()?;
        let config = make_config(&temp, backend);
        let genesis = Network::Regtest.genesis_block();
        let genesis_hash = genesis.block_hash();
        {
            let state = NodeState::open(config.clone(), None)?;
            state.apply_block(&genesis)?;
            crash_recovery::write_meta(
                &state,
                &crash_recovery::Meta {
                    height: 0,
                    tip_hash_hex: genesis_hash.0.to_string_be(),
                },
            )?;
        }

        let restarted = NodeState::open(config, None)?;
        assert!(
            restarted.applied_tip().load().is_none(),
            "{backend}: a cold reopen must not restore an applied tip"
        );
        crash_recovery::recover_if_needed(&restarted)?;

        let recovered_tip = restarted
            .applied_tip()
            .load_full()
            .context("cold recovery did not apply genesis")?;
        assert_eq!(recovered_tip.height, 0, "{backend}: recovered height");
        assert_eq!(
            recovered_tip.hash,
            genesis_hash.into(),
            "{backend}: recovered genesis hash"
        );
        assert_eq!(
            restarted.replayed_heights(),
            vec![0],
            "{backend}: recovery must replay genesis"
        );
    }
    Ok(())
}
