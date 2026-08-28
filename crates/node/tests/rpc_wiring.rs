//! Integration test: `NodeState`'s source-of-truth handles share pointer
//! identity with the `rpc::Context` constructed from them.
//!
//! The pointer-identity invariant is the contract that future
//! validation-pipeline commits rely on — when the import pipeline
//! writes to `NodeState`'s `chain_tip`, RPC handlers must observe the
//! update without any additional plumbing.

use std::sync::Arc;

use anyhow::Result;
use bitcoin_rs_node::{Config, state::NodeState};
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_utxo::UtxoSet;
use tempfile::tempdir;

#[test]
#[allow(clippy::arc_with_non_send_sync)]
#[allow(clippy::too_many_lines)]
fn rpc_context_shares_arc_identity_with_node_state() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    config.txindex = true;
    config.zmqpubhashblock = vec!["inproc://rpc-wiring-zmq-pubhashblock".to_owned()];
    config.zmqpubhashblockhwm = Some(21);
    config.zmqpubsequence = vec!["inproc://rpc-wiring-zmq-pubsequence".to_owned()];
    config.zmqpubsequencehwm = Some(22);
    let state = NodeState::open(config)?;

    let chain_tip = state.chain_tip();
    let applied_tip = state.applied_tip();
    let mempool = state.mempool();
    let blocks = state.blocks();
    let transactions = state.transactions();
    let utxo = Arc::new(UtxoSet::new());
    let coin_stats = state.coin_stats();
    let network = state.network();
    let network_active = state.network_active();
    let chain_network = state.config().network;
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let block_tree = state.block_tree();
    let p2p_outbound = Some(state.p2p_outbound_sender());
    let banned = state.banned_subnets();
    let added_nodes = Arc::new(parking_lot::RwLock::new(Vec::new()));
    let Some(tx_index) = state.tx_index_query() else {
        panic!("txindex query engine missing when enabled");
    };
    let ctx = Context::from_handles(bitcoin_rs_rpc::context::ContextHandles {
        chain: bitcoin_rs_rpc::context::ChainHandles {
            chain_tip: Arc::clone(&chain_tip),
            applied_tip: Arc::clone(&applied_tip),
            blocks: Arc::clone(&blocks),
            transactions: Arc::clone(&transactions),
            utxo: Arc::clone(&utxo),
            coin_stats: Arc::clone(&coin_stats),
            block_tree: Arc::clone(&block_tree),
            chain_network,
        },
        mempool: bitcoin_rs_rpc::context::MempoolHandles {
            mempool: Arc::clone(&mempool),
        },
        indexes: bitcoin_rs_rpc::context::IndexHandles {
            tx_index: Some(tx_index),
            script_index: None,
        },
        network: bitcoin_rs_rpc::context::NetworkHandles {
            network: Arc::clone(&network),
            network_active: Arc::clone(&network_active),
            peers: Arc::clone(&peers),
            peer_outbound: Arc::clone(&peer_outbound),
            p2p_outbound_sender: p2p_outbound,
            banned: Arc::clone(&banned),
            added_nodes: Arc::clone(&added_nodes),
        },
        mining: bitcoin_rs_rpc::context::MiningHandles {
            mining_control: None,
        },
        filter_index: None,
        capabilities: None,
    })
    .with_zmq_notifications(state.active_zmq_notifications());

    assert!(
        Arc::ptr_eq(&ctx.chain_tip, &chain_tip),
        "chain_tip must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.applied_tip, &applied_tip),
        "applied_tip must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.mempool, &mempool),
        "mempool must share identity"
    );
    assert!(
        ctx.zmq_notifications()
            .iter()
            .any(|notification| notification.notification_type == "pubsequence")
    );
    assert!(
        Arc::ptr_eq(&ctx.blocks, &blocks),
        "blocks must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.transactions, &transactions),
        "transactions must share identity"
    );
    assert!(Arc::ptr_eq(&ctx.utxo, &utxo), "utxo must share identity");
    assert!(
        Arc::ptr_eq(&ctx.coin_stats, &coin_stats),
        "coin_stats must share identity"
    );
    assert!(
        ctx.tx_index.is_some(),
        "txindex query adapter must be wired"
    );
    assert!(
        Arc::ptr_eq(&ctx.network, &network),
        "network must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.network_active, &network_active),
        "network activity must share identity"
    );
    assert_eq!(
        ctx.chain_network,
        state.config().network,
        "chain_network must match"
    );
    assert!(Arc::ptr_eq(&ctx.peers, &peers), "peers must share identity");
    assert!(
        Arc::ptr_eq(&ctx.peer_outbound, &peer_outbound),
        "peer_outbound must share identity"
    );
    assert!(
        Arc::ptr_eq(&ctx.block_tree, &block_tree),
        "block_tree must share identity"
    );
    assert!(
        ctx.p2p_outbound_sender.is_some(),
        "p2p_outbound_sender must be Some"
    );
    assert!(
        Arc::ptr_eq(&ctx.banned, &banned),
        "banned must share identity"
    );
    let notifications = ctx.zmq_notifications();
    assert_eq!(notifications.len(), 2);
    assert_eq!(notifications[0].notification_type.as_str(), "pubhashblock");
    assert_eq!(notifications[0].hwm, 21);
    assert_eq!(notifications[1].notification_type.as_str(), "pubsequence");
    assert_eq!(notifications[1].hwm, 22);

    Ok(())
}

#[test]
fn rpc_context_omits_indexer_when_node_txindex_is_disabled() -> Result<()> {
    let dir = tempdir()?;
    let mut config = Config::default();
    config.data_dir = dir.path().join("node");
    config.txindex = false;
    let state = NodeState::open(config)?;

    assert!(state.tx_index_query().is_none());
    Ok(())
}
