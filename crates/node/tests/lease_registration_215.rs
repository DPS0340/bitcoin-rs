//! Cross-crate regression test for issue #215: production P2P handshake
//! publication cancels the current peer lease.
//!
//! The bug: the p2p listener inserts the current `PeerLease` into
//! `peer_outbound` *before* the handshake, then the production registration
//! callback (`BlockSync::peer_registration_handle`) removes and cancels the
//! lease at the same address. With pre-handshake registration, `prior` is the
//! current connection's lease, not a predecessor — so the first post-handshake
//! loop exits before reading any message.
//!
//! The existing unit tests in `sync.rs` exercise the callback in isolation
//! but do not model the cross-crate production combination: a real p2p
//! listener pre-handshake registration followed by the node callback. This
//! test exercises that exact sequence through the public API.

use std::net::SocketAddr;
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_mempool::{Mempool, MempoolGateway, MempoolLimits};
use bitcoin_rs_node::{BlockSync, Network, NoOpZmqPublisher, apply::ApplyHandles};
use bitcoin_rs_p2p::{InboundBlock, InboundHeaders, Message, PeerInfo, PeerLease, PeerCounters};
use bitcoin_rs_utxo::UtxoSet;
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
use crossbeam_channel::unbounded;
use hashbrown::HashMap;
use parking_lot::{Mutex, RwLock};

fn make_sync() -> (
    BlockSync,
    Arc<RwLock<Vec<PeerInfo>>>,
    Arc<RwLock<HashMap<SocketAddr, PeerLease>>>,
) {
    let block_tree = Arc::new(RwLock::new(BlockTree::new()));
    let chain_tip = block_tree.read().tip_handle();
    let applied_tip: Arc<ArcSwapOption<bitcoin_rs_chain::TipSnapshot>> =
        Arc::new(ArcSwapOption::empty());
    let peers = Arc::new(RwLock::new(Vec::new()));
    let peer_outbound = Arc::new(RwLock::new(HashMap::new()));
    let (_headers_tx, headers_rx) = unbounded::<InboundHeaders>();
    let (_blocks_tx, blocks_rx) = unbounded::<InboundBlock>();

    let coin_stats = Arc::new(CoinStatsListener::new(CoinStats::default()));
    let mut utxo = UtxoSet::new();
    utxo.set_listener(Box::new((*coin_stats).clone()));
    let utxo = Arc::new(utxo);

    let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
    let mempool_gateway = Arc::new(MempoolGateway::shared(Arc::clone(&mempool)));
    let mining_generation = Arc::new(bitcoin_rs_node::mining::MiningGenerationSignal::new());
    let (chain_events, _chain_events_rx) =
        bitcoin_rs_node::state::ChainEventPublisher::detached(0);

    let handles = ApplyHandles::new(
        Network::Regtest,
        chain_tip,
        Arc::clone(&applied_tip),
        Arc::clone(&block_tree),
        utxo,
        Arc::clone(&coin_stats),
        None,
        mempool,
        mempool_gateway,
        mining_generation,
        Arc::new(RwLock::new(bitcoin_rs_rpc::context::BlockLog::new())),
        Arc::new(RwLock::new(HashMap::<bitcoin::Txid, bitcoin::Transaction>::new())),
        Arc::new(NoOpZmqPublisher),
        Arc::new(chain_events),
    );

    let sync = BlockSync::new(
        handles,
        Arc::clone(&peers),
        Arc::clone(&peer_outbound),
        Arc::new(Mutex::new(headers_rx)),
        Arc::new(Mutex::new(blocks_rx)),
    );
    (sync, peers, peer_outbound)
}

fn synthetic_peer(addr: SocketAddr, inbound: bool) -> PeerInfo {
    PeerInfo {
        addr,
        version: 70_016,
        services: 0,
        user_agent: String::from("/test/"),
        start_height: 0,
        conn_time: 0,
        inbound,
        addr_bind: addr,
        time_offset: 0,
        counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
    }
}

/// Regression for #215: the p2p listener pre-registers the current connection's
/// lease before the handshake. After the handshake, the node's
/// `peer_registration_handle` callback is invoked with the *same* lease. The
/// callback must detect that the prior entry is the same connection
/// (`same_connection`) and must NOT cancel it.
#[test]
fn pre_registered_lease_survives_publication_callback() {
    let (sync, peers, peer_outbound) = make_sync();
    let addr = SocketAddr::from(([127, 0, 0, 1], 18_447));

    // Step 1: the p2p listener pre-registers the connection's lease before
    // the handshake completes (mirroring listener.rs pre-handshake path).
    let (tx, rx) = unbounded::<Message>();
    let lease = PeerLease::new(tx);
    peer_outbound.write().insert(addr, lease.clone());

    // Step 2: the handshake completes and the production registration callback
    // fires with the SAME lease (same connection). This is the cross-crate
    // production combination that #215 identified as uncovered.
    let registration = sync.peer_registration_handle();
    let replaced = registration(addr, lease.clone(), synthetic_peer(addr, true));

    // The callback must report `false` (not replaced) because the prior entry
    // is the same connection, not a predecessor.
    assert!(
        !replaced,
        "publication callback must not report replacement for same connection"
    );

    // The lease must NOT be cancelled — the session must survive to read its
    // first post-handshake message.
    assert!(
        !lease.is_cancelled(),
        "pre-registered lease must not be cancelled by its own publication"
    );

    // The lease in the map must be the same connection (not a cancelled clone).
    assert!(
        peer_outbound
            .read()
            .get(&addr)
            .is_some_and(|current| current.same_connection(&lease)),
        "outbound map must retain the same connection after publication"
    );

    // The peer must be registered.
    assert_eq!(&*peers.read(), &[synthetic_peer(addr, true)]);

    // The lease must still be usable — a message sent through it must arrive.
    lease.send(Message::Ping(42)).unwrap();
    assert_eq!(rx.recv().unwrap(), Message::Ping(42));
}

/// A genuinely different predecessor at the same address MUST be cancelled.
/// This verifies the callback still protects against stale connections — the
/// fix only spares the *current* connection, not a real predecessor.
#[test]
fn predecessor_lease_is_cancelled_by_publication_callback() {
    let (sync, peers, peer_outbound) = make_sync();
    let addr = SocketAddr::from(([127, 0, 0, 1], 18_448));

    // A stale predecessor occupies the address.
    let (old_tx, _old_rx) = unbounded::<Message>();
    let old_lease = PeerLease::new(old_tx);
    peer_outbound.write().insert(addr, old_lease.clone());

    // A new connection arrives with a different lease.
    let (new_tx, new_rx) = unbounded::<Message>();
    let new_lease = PeerLease::new(new_tx);

    let registration = sync.peer_registration_handle();
    let replaced = registration(addr, new_lease.clone(), synthetic_peer(addr, false));

    // The predecessor must be replaced and cancelled.
    assert!(
        replaced,
        "a genuine predecessor must be reported as replaced"
    );
    assert!(
        old_lease.is_cancelled(),
        "predecessor lease must be cancelled"
    );
    assert!(
        !new_lease.is_cancelled(),
        "new lease must not be cancelled"
    );

    // The new lease must be in the map and usable.
    assert!(
        peer_outbound
            .read()
            .get(&addr)
            .is_some_and(|current| current.same_connection(&new_lease)),
        "outbound map must hold the new connection"
    );
    new_lease.send(Message::Ping(99)).unwrap();
    assert_eq!(new_rx.recv().unwrap(), Message::Ping(99));
    assert_eq!(&*peers.read(), &[synthetic_peer(addr, false)]);
}
