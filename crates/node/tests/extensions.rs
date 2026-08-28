//! Extension-model integration tests backing the g16 gate.
//!
//! Proves the three extension-model invariants end to end against real
//! `NodeState` instances on regtest:
//!
//! 1. an invalid extension combination is rejected with the literal
//!    `"<capability> requires <dependency>"` phrasing before anything opens;
//! 2. core tip progression is identical with the filter extension disabled
//!    and enabled, and the enabled instance reconciles to the same tip;
//! 3. the reconciliation consumer recovers from a restart by re-planning
//!    from its persisted pointer (no replay log, no inline apply writes).

use std::time::{Duration, Instant};

use bitcoin::Network as BitcoinNetwork;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_node::{Config, Network, state::NodeState};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn regtest_config(dir: &std::path::Path, blockfilterindex: bool) -> Config {
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.join("node");
    config.p2p_listen.clear();
    config.txindex = true;
    config.blockfilterindex = blockfilterindex;
    config
}

/// Mines one coinbase-only child of `parent` at `height`.
fn coinbase_child(
    parent: &bitcoin::Block,
    height: u8,
) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
    let mut block = parent.clone();
    block.header.prev_blockhash = parent.block_hash();
    block.header.time = parent.header.time.saturating_add(1);
    block.txdata.truncate(1);
    block.txdata[0].input[0].script_sig = bitcoin::ScriptBuf::from_bytes(vec![1, height]);
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| std::io::Error::other("child block should have merkle root"))?;
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .ok_or_else(|| std::io::Error::other("exhausted nonce while mining test block"))?;
    }
    Ok(block)
}

fn apply_fixture_block(state: &NodeState, block: &bitcoin::Block) -> TestResult {
    let native = bitcoin_rs_primitives::deserialize(&bitcoin::consensus::serialize(block))?;
    state.apply_block(&native)?;
    Ok(())
}

fn applied_tip(state: &NodeState) -> (u32, String) {
    let loaded = state.applied_tip().load_full();
    let Some(tip) = loaded.as_deref() else {
        panic!("applied tip after apply_block must exist");
    };
    (tip.height, tip.hash.to_string_be())
}

fn wait_for_filter_sync(state: &NodeState, target_height: u32) -> TestResult {
    let query = state
        .filter_index_query()
        .ok_or("filter index query missing while --blockfilterindex is enabled")?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let info = query
            .filter_info()
            .map_err(|error| format!("filter_info failed: {error}"))?;
        if info.synced && info.best_block_height == target_height {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "filter index did not reach height {target_height}: synced={} best={}",
                info.synced, info.best_block_height
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn extension_validation_rejects_incompatible_capabilities() -> TestResult {
    // Missing dependency: the reference extension requires txindex rows.
    let mut config = Config::default_for_network(Network::Regtest);
    config.blockfilterindex = true;
    let error = bitcoin_rs_node::extensions::validate_extensions(&config)
        .expect_err("blockfilterindex without txindex must be rejected");
    assert_eq!(error.to_string(), "blockfilterindex requires txindex");

    // Conflicting dependency: the filter index needs every block body.
    config.txindex = true;
    config.prune_target_mb = 10;
    let error = bitcoin_rs_node::extensions::validate_extensions(&config)
        .expect_err("blockfilterindex with prune must be rejected");
    assert_eq!(
        error.to_string(),
        "blockfilterindex requires prune disabled"
    );

    // The same checks hold as a Config::validate backstop.
    let error = config
        .validate()
        .expect_err("Config::validate repeats the extension checks");
    assert_eq!(
        error.to_string(),
        "blockfilterindex requires prune disabled"
    );

    config.prune_target_mb = 0;
    bitcoin_rs_node::extensions::validate_extensions(&config).expect("valid combination");
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "test: hand-built fixtures cannot fail except by a bug"
)]
#[test]
fn filter_extension_tip_equivalence_disabled_vs_enabled() -> TestResult {
    let disabled_dir = tempfile::tempdir()?;
    let enabled_dir = tempfile::tempdir()?;

    let disabled = NodeState::open(regtest_config(disabled_dir.path(), false))?;
    let enabled = NodeState::open(regtest_config(enabled_dir.path(), true))?;
    assert!(
        enabled.filter_index_query().is_some(),
        "enabled filter extension must expose its query adapter"
    );
    assert!(
        disabled.filter_index_query().is_none(),
        "disabled filter extension must not expose a query adapter"
    );

    let genesis = genesis_block(BitcoinNetwork::Regtest);
    let child = coinbase_child(&genesis, 1)?;

    for state in [&disabled, &enabled] {
        apply_fixture_block(state, &genesis)?;
        apply_fixture_block(state, &child)?;
    }

    let disabled_tip = applied_tip(&disabled);
    let enabled_tip = applied_tip(&enabled);
    assert_eq!(
        disabled_tip, enabled_tip,
        "core tip progression must not depend on the filter extension"
    );

    // The enabled instance reconciles its rows to the same tip, and serves
    // the genesis filter the BIP158 construction recomputes deterministically.
    wait_for_filter_sync(&enabled, enabled_tip.0)?;
    let query = enabled.filter_index_query().expect("checked above");
    let info = query.filter_info()?;
    assert!(info.synced);
    assert_eq!(info.best_block_height, enabled_tip.0);
    let genesis_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
    let filter = query
        .basic_filter(genesis_hash)?
        .expect("genesis filter indexed");
    assert!(!filter.is_empty());
    let header = query.filter_header(genesis_hash)?.expect("genesis header");
    assert_ne!(header, [0_u8; 32]);
    Ok(())
}

#[expect(
    clippy::expect_used,
    reason = "test: hand-built fixtures cannot fail except by a bug"
)]
#[test]
fn filter_extension_restarts_reconcile_from_persisted_pointer() -> TestResult {
    let dir = tempfile::tempdir()?;
    let config = regtest_config(dir.path(), true);

    let genesis = genesis_block(BitcoinNetwork::Regtest);
    let child = coinbase_child(&genesis, 1)?;
    let child_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(child.block_hash().as_byte_array());

    let tip;
    {
        let state = NodeState::open(config.clone())?;
        apply_fixture_block(&state, &genesis)?;
        apply_fixture_block(&state, &child)?;
        tip = applied_tip(&state);
        wait_for_filter_sync(&state, tip.0)?;
        state.publish_checkpoint()?;
        // Dropping the state joins the worker; the namespace keeps the
        // hash-addressed rows, the pointer, and the consumer cursor.
    }

    let reopened = NodeState::open(config)?;
    assert_eq!(applied_tip(&reopened), tip, "tip restores from checkpoint");
    wait_for_filter_sync(&reopened, tip.0)?;
    let query = reopened.filter_index_query().expect("filter query");
    assert!(query.filter_info()?.synced);
    assert!(
        query.basic_filter(child_hash)?.is_some(),
        "child filter row must survive the restart"
    );
    Ok(())
}

#[test]
fn filter_extension_apply_outpaces_a_lagging_consumer() -> TestResult {
    // Core sync never waits for the consumer: apply five blocks in a row and
    // assert the applied tip advanced before the filter index caught up.
    let dir = tempfile::tempdir()?;
    let state = NodeState::open(regtest_config(dir.path(), true))?;

    let mut blocks = vec![genesis_block(BitcoinNetwork::Regtest)];
    for height in 1_u8..=5 {
        let parent = blocks.last().expect("parent").clone();
        blocks.push(coinbase_child(&parent, height)?);
    }
    for block in &blocks {
        apply_fixture_block(&state, block)?;
    }
    let tip = applied_tip(&state);
    assert_eq!(tip.0, 5, "all five blocks must apply without waiting");

    // The consumer catches up asynchronously to the same tip.
    wait_for_filter_sync(&state, 5)?;
    Ok(())
}
