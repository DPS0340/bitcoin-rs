use super::*;

#[test]
fn full_revalidation_marker_is_sticky_when_journal_is_disabled() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.chainstate_journal.enabled = false;
    let journal_dir = config.data_dir.join(CHAINSTATE_JOURNAL_DIR);
    let marker = journal_dir.join(crate::chainstate_journal::FULL_REVALIDATION_MARKER);
    std::fs::create_dir_all(&journal_dir)?;
    std::fs::write(&marker, b"force full validation\n")?;

    assert!(requires_full_revalidation(&config.data_dir));
    Ok(())
}

#[test]
fn checkpoint_refuses_inflight_disconnect_and_preserves_state() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    assert!(matches!(
        state.write_clean_checkpoint()?,
        crate::checkpoint::CheckpointWrite::Published { .. }
    ));

    let checkpoint_root = data_dir.join("chainstate-checkpoints");
    let armed_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xab; 32]);
    let armed_height = 10;
    state
        .chainstate()
        .undo_store
        .arm_disconnect(armed_height, armed_hash)?;
    let marker_before = state.chainstate().undo_store.load_disconnect_marker()?;
    let current_before = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let mut dirs_before = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&checkpoint_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs_before.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }

    let result = state.write_clean_checkpoint();
    let Err(crate::checkpoint::CheckpointError::DisconnectInFlight { hash, height }) = result
    else {
        anyhow::bail!("expected DisconnectInFlight refusal, got {result:?}");
    };
    assert_eq!(hash, armed_hash);
    assert_eq!(height, armed_height);

    let marker_after = state.chainstate().undo_store.load_disconnect_marker()?;
    let current_after = std::fs::read(checkpoint_root.join("CURRENT"))?;
    let mut dirs_after = std::collections::BTreeSet::new();
    for entry in std::fs::read_dir(&checkpoint_root)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs_after.insert(entry.file_name().to_string_lossy().into_owned());
        }
    }

    assert_eq!(marker_before, marker_after);
    assert_eq!(current_before, current_after);
    assert_eq!(dirs_before, dirs_after);
    Ok(())
}

#[test]
fn torn_disconnect_refusal_names_authoritative_stores_to_remove() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    state.chainstate().undo_store.arm_disconnect(
        10,
        bitcoin_rs_primitives::Hash256::from_le_bytes(&[0xcd; 32]),
    )?;
    drop(state);

    let error = match NodeState::open(config, None) {
        Ok(_) => anyhow::bail!("node reopened with an armed disconnect marker"),
        Err(error) => error,
    };
    let message = error.to_string();
    for store in ["chainstate", "chainstate-checkpoints", "txindex"] {
        let path = data_dir.join(store);
        assert!(
            message.contains(&path.display().to_string()),
            "startup refusal omitted {}: {message}",
            path.display()
        );
    }
    Ok(())
}

#[test]
fn invalidate_block_settles_disconnect_debt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    // Journal rewind disarms disconnect markers itself. These tests own the
    // checkpoint-settlement path that remains when the journal cannot.
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let current_before = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    let block_two = mined_regtest_child_at(block_one.block_hash(), genesis.header.time + 2, 2)?;
    state.apply_block(&block_two)?;

    crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_two.block_hash()),
    )?;

    assert!(
        state
            .chainstate()
            .undo_store
            .load_disconnect_marker()?
            .is_none()
    );
    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
    assert_eq!(state.durable_tip_height.load(Ordering::Acquire), 1);
    Ok(())
}

#[test]
fn invalidate_block_settlement_failure_is_not_success() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let block_two = mined_regtest_child_at(block_one.block_hash(), genesis.header.time + 2, 2)?;
    state.apply_block(&block_two)?;

    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::ManifestWrite,
    );
    let result = crate::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        Hash256::from(block_two.block_hash()),
    );
    let Err(crate::reorg::ReorgError::CheckpointSettlement(_)) = result else {
        anyhow::bail!("expected CheckpointSettlement, got {result:?}");
    };

    let marker = state
        .chainstate()
        .undo_store
        .load_disconnect_marker()?
        .ok_or_else(|| anyhow::anyhow!("settlement failure cleared the disconnect marker"))?;
    assert_eq!(
        marker.phase,
        bitcoin_rs_storage::DisconnectPhase::RolledBack
    );

    drop(state);
    let error = match NodeState::open(config, None) {
        Ok(_) => anyhow::bail!("node reopened with unsettled RolledBack debt"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("did not reach a clean checkpoint"),
        "startup refusal omitted the checkpoint debt: {error}"
    );
    Ok(())
}

#[test]
fn switch_to_branch_settles_disconnect_debt() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let current_before = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;

    let genesis_id = state
        .block_tree
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block =
            mined_regtest_child_at(previous_hash, genesis.header.time + 10 + height, height)?;
        let node_id = state.block_tree.write().insert_node(
            Some(parent),
            block.header,
            bitcoin_rs_chain::node::NodeStatus::HeaderValid,
        )?;
        fork_bodies.insert(
            Hash256::from(block.block_hash()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        parent = node_id;
        previous_hash = block.block_hash();
    }

    let handles = state.chainstate();
    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        parent,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert!(
        state
            .chainstate()
            .undo_store
            .load_disconnect_marker()?
            .is_none()
    );
    let current_after = serde_json::from_slice::<serde_json::Value>(&std::fs::read(
        data_dir.join("chainstate-checkpoints/CURRENT"),
    )?)?
    .get("generation")
    .and_then(serde_json::Value::as_u64)
    .ok_or_else(|| anyhow::anyhow!("CURRENT has no generation"))?;
    assert!(current_after > current_before);
    assert_eq!(state.durable_tip_height.load(Ordering::Acquire), 2);
    Ok(())
}

// -----------------------------------------------------------------------
// A2 cycle 3: witness is published only after CURRENT root fsync
// -----------------------------------------------------------------------

#[test]
fn witness_is_published_only_after_current_root_sync() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();

    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    let tip = state.apply_block(&genesis)?;

    // Publish a checkpoint — witness must be written after Published.
    state.publish_checkpoint()?;
    let witness_path = data_dir.join("applied-tip-witness.json");
    assert!(
        witness_path.exists(),
        "witness file must exist after checkpoint publication"
    );
    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let witness = crate::recovery_evidence::read_witness(&data_dir, &genesis_hex)
        .ok_or_else(|| anyhow::anyhow!("witness must be readable"))?;
    assert_eq!(witness.height, tip.height);
    assert_eq!(witness.block_hash, tip.hash.to_string_be());
    drop(state);

    // Now inject a failpoint at CurrentRootSync — the last stage before
    // the checkpoint is considered Published. The checkpoint must fail,
    // and no new witness must be written for the failed checkpoint.
    let dir2 = tempfile::tempdir()?;
    let data_dir2 = dir2.path().join("node");
    let mut config2 = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config2.data_dir = data_dir2.clone();
    config2.p2p.listen.clear();

    let state2 = NodeState::open(config2.clone(), None)?;
    let genesis2 = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state2.apply_block(&genesis2)?;

    // Inject failpoint at the final root fsync — checkpoint fails before
    // returning Published, so no witness should be written.
    crate::checkpoint::inject_next_checkpoint_failpoint(
        crate::checkpoint::CheckpointFailpoint::CurrentRootSync,
    );
    let result = state2.publish_checkpoint();
    assert!(
        result.is_err(),
        "checkpoint must fail when CurrentRootSync fails"
    );
    let witness_path2 = data_dir2.join("applied-tip-witness.json");
    assert!(
        !witness_path2.exists(),
        "no witness must be written when checkpoint fails before publication"
    );
    Ok(())
}

// -----------------------------------------------------------------------
// #208: a checkpoint restore far behind the durable witness must be loud
// -----------------------------------------------------------------------

#[test]
fn stale_checkpoint_restore_surfaces_warning_not_silence() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir.clone();
    config.p2p.listen.clear();
    config.indexes.script_index = crate::config::ScriptIndexMode::Disabled;

    // Apply genesis and publish a checkpoint at height 0.
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    state.write_clean_checkpoint()?;
    drop(state);

    // Simulate the #208 scenario: the node previously ran far ahead
    // (height 5000) and published a checkpoint there, writing a witness
    // at that height. A crash or clean stop left the checkpoint tree
    // pinned at height 0 while the witness records height 5000.
    let genesis_hex = config.network.genesis_block_hash().to_string_be();
    let stale_witness = crate::recovery_evidence::AppliedTipWitness::new(
        genesis_hex,
        1, // older epoch
        5000,
        "cccc",
        1000,
    );
    crate::recovery_evidence::write_witness(&data_dir, &stale_witness)?;

    // Reopen: the checkpoint at height 0 is restored, the witness at
    // 5000 triggers checkpoint-fallback detection. The warning store
    // must carry the fallback warning — the restore must not be silent.
    let resumed = NodeState::open(config.clone(), None)?;
    let warnings = resumed.warning_store().warnings();
    assert!(
        !warnings.is_empty(),
        "a stale checkpoint restore 5000 blocks behind the witness must \
         produce at least one rollback warning, not silence"
    );
    assert!(
        warnings.iter().any(|w| w.contains("height 5000")),
        "the warning must name the witness height; got: {warnings:?}"
    );
    assert_eq!(
        resumed.resume_source(),
        ResumeSource::Checkpoint,
        "the checkpoint is still accepted — it is valid, just stale"
    );
    Ok(())
}

/// Builds the two-block fork fixture: applied genesis plus one mined child,
/// a checkpoint published, and a sibling two-block fork known to the header
/// tree with staged bodies.
type ForkFixture = (
    tempfile::TempDir,
    NodeState,
    bitcoin_rs_chain::NodeId,
    HashMap<bitcoin_rs_primitives::Hash256, (bitcoin_rs_primitives::Block, bytes::Bytes)>,
);

fn forked_regtest_state() -> anyhow::Result<ForkFixture> {
    let dir = tempfile::tempdir()?;
    let data_dir = dir.path().join("node");
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = data_dir;
    config.p2p.listen.clear();
    config.chainstate_journal.enabled = false;
    let state = NodeState::open(config, None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let block_one = mined_regtest_child_at(genesis.block_hash(), genesis.header.time + 1, 1)?;
    state.apply_block(&block_one)?;
    state.publish_checkpoint()?;

    let genesis_id = state
        .block_tree
        .read()
        .lookup(Hash256::from(genesis.block_hash()))
        .ok_or_else(|| anyhow::anyhow!("missing genesis node"))?;
    let mut parent = genesis_id;
    let mut previous_hash = genesis.block_hash();
    let mut fork_bodies = HashMap::new();
    for height in 1..=2 {
        let block =
            mined_regtest_child_at(previous_hash, genesis.header.time + 10 + height, height)?;
        let node_id = state.block_tree.write().insert_node(
            Some(parent),
            block.header,
            bitcoin_rs_chain::node::NodeStatus::HeaderValid,
        )?;
        fork_bodies.insert(
            Hash256::from(block.block_hash()),
            (block.clone(), bytes::Bytes::from(consensus_bytes(&block))),
        );
        parent = node_id;
        previous_hash = block.block_hash();
    }
    Ok((dir, state, parent, fork_bodies))
}

/// A completed switch holds its retention lease only for its own duration:
/// the authority is back with pruning exactly once when it settles.
#[test]
fn switch_to_branch_releases_retention_authority_once() -> anyhow::Result<()> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    assert_eq!(handles.retention.active_leases(), 0);

    crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    )?;

    assert_eq!(handles.retention.active_leases(), 0);
    Ok(())
}

/// Old-branch history a prune already deleted refuses the switch before
/// the first mutation: typed unavailable result, applied tip untouched,
/// and no lease left behind (`RCV-08`).
#[test]
fn switch_to_branch_refuses_history_the_prune_line_crossed() -> anyhow::Result<()> {
    let (_dir, state, fork_tip, fork_bodies) = forked_regtest_state()?;
    let handles = state.chainstate();
    let tip_before = handles.applied_tip.load_full().map(|tip| tip.hash);
    handles.retention.record_pruned_below(5);

    let outcome = crate::reorg::switch_to_branch(
        &handles,
        &state.chain_followers(),
        fork_tip,
        |hash| fork_bodies.get(&hash).cloned(),
        |_| {},
    );

    assert!(matches!(
        outcome,
        Err(crate::reorg::ReorgError::RetentionUnavailable { floor: 1, .. })
    ));
    assert_eq!(
        handles.applied_tip.load_full().map(|tip| tip.hash),
        tip_before
    );
    assert_eq!(handles.retention.active_leases(), 0);
    // A refused lease must not close admission: nothing was mutated.
    assert!(handles.lock_transition().is_ok());
    Ok(())
}

// -----------------------------------------------------------------------
// #655: restart on a committed-but-unpublished gap replays the durable
// head chain and never re-commits it.
// -----------------------------------------------------------------------

/// Applies the regtest genesis plus `heights` mined children, publishing a
/// checkpoint after the first block so a later restore has a base under the
/// journal. Returns the temp dir, the node, and a config for reopening.
fn applied_regtest_chain(
    heights: u32,
) -> anyhow::Result<(tempfile::TempDir, NodeState, crate::NodeConfig)> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config.clone(), None)?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    let mut previous = genesis.block_hash();
    let mut time = genesis.header.time;
    for height in 1..=heights {
        time += 1;
        let block = mined_regtest_child_at(previous, time, height)?;
        state.apply_block(&block)?;
        previous = block.block_hash();
        if height == 1 {
            state.publish_checkpoint()?;
        }
    }
    Ok((dir, state, config))
}

/// Rewinds only the publication tail of the last `count` applied blocks.
///
/// The durable head stays where it committed; the derived state returns to
/// exactly what a crash between the batch and the publication leaves:
/// journal rewound to the parent, applied tip on the parent, transaction
/// count rewound.
fn simulate_lost_publication(state: &NodeState, count: u32) -> anyhow::Result<()> {
    for _ in 0..count {
        let tip = state
            .chainstate()
            .applied_tip
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("no applied tip to rewind"))?;
        let (parent_tip, grandparent_hash, parent_tx_count) = {
            let tree = state.block_tree.read();
            let node = tree.node(tip.tip_id)?;
            let parent_id = node
                .parent
                .ok_or_else(|| anyhow::anyhow!("tip has no parent"))?;
            let parent = tree.node(parent_id)?;
            let grandparent_hash = match parent.parent {
                Some(grandparent) => tree.node(grandparent)?.hash.to_le_bytes(),
                None => [0_u8; 32],
            };
            let snapshot = bitcoin_rs_chain::TipSnapshot {
                tip_id: parent_id,
                height: parent.height,
                chainwork: parent.chainwork,
                hash: parent.hash,
            };
            (snapshot, grandparent_hash, parent.chain_tx_count)
        };
        if let Some(journal) = state.chainstate().journal.as_ref() {
            journal.lock().rewind_to(
                parent_tip.height,
                parent_tip.hash.to_le_bytes(),
                grandparent_hash,
                parent_tx_count,
            )?;
        }
        state
            .chain_tx_count
            .store(parent_tx_count, Ordering::Release);
        state
            .chainstate()
            .applied_tip
            .store(Some(std::sync::Arc::new(parent_tip)));
    }
    Ok(())
}

/// A restart on a committed-but-unpublished gap replays the durable head
/// chain through the ordinary commit path, lands exactly on the stored
/// head, keeps its `commit_id` untouched, and leaves a node that operates
/// normally — including a second restart that finds nothing to replay.
#[test]
fn boot_replays_the_committed_gap_without_recommitting_the_head() -> anyhow::Result<()> {
    let (_dir, state, config) = applied_regtest_chain(4)?;
    let head = state
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    let config_head_tip = head.tip;
    let config_head_commit = head.commit_id;

    simulate_lost_publication(&state, 2)?;
    drop(state);

    let reopened = NodeState::open(config.clone(), None)?;
    let landed = reopened
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("replay must publish a tip"))?;
    assert_eq!(landed.hash, config_head_tip);
    assert_eq!(landed.height, 4);
    let head = reopened
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("head must survive the restart"))?;
    assert_eq!(head.tip, config_head_tip);
    assert_eq!(head.commit_id, config_head_commit);
    assert!(matches!(
        reopened.resume_source(),
        ResumeSource::Journal | ResumeSource::Checkpoint
    ));

    // The replay caught the journal up: a second restart replays nothing
    // and lands on the same head.
    drop(reopened);
    let second = NodeState::open(config, None)?;
    let landed = second
        .chainstate()
        .applied_tip
        .load_full()
        .ok_or_else(|| anyhow::anyhow!("second boot must publish a tip"))?;
    assert_eq!(landed.hash, config_head_tip);
    assert_eq!(landed.height, 4);
    Ok(())
}

/// Restart at each committed ancestor is valid: whatever prefix the
/// crash-stranded publication represents, the replay lands on the head.
#[test]
fn boot_replays_from_every_committed_ancestor() -> anyhow::Result<()> {
    for lost in 0..=2_u32 {
        let (_dir, state, config) = applied_regtest_chain(4)?;
        let head = state
            .chainstate()
            .durable_head
            .load()?
            .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
        simulate_lost_publication(&state, lost)?;
        drop(state);

        let reopened = NodeState::open(config, None)?;
        let landed = reopened
            .chainstate()
            .applied_tip
            .load_full()
            .ok_or_else(|| anyhow::anyhow!("replay must publish a tip"))?;
        assert_eq!(landed.hash, head.tip, "lost {lost} publications");
        assert_eq!(landed.height, head.height, "lost {lost} publications");
    }
    Ok(())
}

/// A gap whose durable facts are gone fails closed: the node refuses to
/// start rather than publish a fabricated history (`RCV-07`).
#[test]
fn boot_refuses_a_gap_whose_body_is_gone() -> anyhow::Result<()> {
    let (_dir, state, _config) = applied_regtest_chain(3)?;
    let head = state
        .chainstate()
        .durable_head
        .load()?
        .ok_or_else(|| anyhow::anyhow!("applied chain must have a durable head"))?;
    simulate_lost_publication(&state, 1)?;
    // Replace the gap block's locator row with one naming bytes that do
    // not exist: the body is durable-gone as far as replay can tell.
    state.storage.write_test_rows(&[(
        bitcoin_rs_storage::pruning::BLOCK_DATA_CF,
        bitcoin_rs_storage::pruning::block_body_key(head.height, head.tip).to_vec(),
        bitcoin_rs_storage::BlockFilePosition {
            file_no: 99,
            offset: 0,
            len: 1,
        }
        .encode()
        .to_vec(),
    )])?;
    let config = state.config.clone();
    drop(state);

    let opened = NodeState::open(config, None);
    let error = opened
        .err()
        .ok_or_else(|| anyhow::anyhow!("open must fail"))?;
    let rendered = error.to_string();
    assert!(
        rendered.contains("cannot be replayed"),
        "open must fail on the unrecoverable gap, not silently: {rendered}"
    );
    Ok(())
}
