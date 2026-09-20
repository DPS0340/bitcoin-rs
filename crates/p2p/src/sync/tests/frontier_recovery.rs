//! P2P-05: canonical progress, not a scheduler cursor, owns the next body.

use super::*;

/// Returns the next `getheaders` from `rx`, skipping other traffic; fails
/// when none is queued.
fn next_getheaders(
    rx: &crossbeam_channel::Receiver<Message>,
) -> Result<bitcoin::p2p::message_blockdata::GetHeadersMessage, Box<dyn std::error::Error>> {
    while let Ok(message) = rx.try_recv() {
        if let Message::GetHeaders(request) = message {
            return Ok(request);
        }
    }
    Err(std::io::Error::other("expected getheaders").into())
}

#[test]
fn applied_rewind_with_unchanged_headers_refetches_the_missing_prefix()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, applied, blocks, incoming) = sync_with_mined_chain(3)?;
    let peer = test_addr(9760, 0)?;
    let outbound = connect_peer(&peers, eligible_peer(peer, 3));
    sync.tick();
    let genesis = applied.load_full().ok_or("missing genesis")?;
    let hashes: Vec<_> = blocks.iter().map(Block::block_hash).collect();
    assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
    for block in blocks {
        incoming.send(crate::InboundBlock::from_decoded(block))?;
    }
    sync.tick();
    assert_eq!(applied.load_full().ok_or("missing applied tip")?.height, 3);
    assert_no_getdata(&outbound)?;

    // The chain owner may disconnect independently of this executor. Headers
    // still select the same branch; the old forward cursor is not authority.
    applied.store(Some(genesis));
    sync.tick();
    assert_eq!(witness_block_inventory(next_getdata(&outbound)?)?, hashes);
    sync.tick();
    assert_no_getdata(&outbound)?;
    Ok(())
}

#[test]
fn cancelled_ready_event_does_not_wait_for_an_unrelated_body_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let peer = test_addr(9760, 1)?;
    let _old = connect_peer(&peers, eligible_peer(peer, 1));
    let stale = current_source(&peers, peer);
    let _replacement = connect_peer(&peers, eligible_peer(peer, 1));
    let sync = Arc::new(sync);
    let body = sync.body_sync.lock();
    let (finished, completed) = crossbeam_channel::bounded(1);
    let worker_sync = Arc::clone(&sync);
    let worker = std::thread::spawn(move || {
        worker_sync.on_peer_ready(stale);
        let _ = finished.send(());
    });
    let result = completed.recv_timeout(Duration::from_secs(1));
    drop(body);
    worker.join().map_err(|_| "ready handler panicked")?;
    result?;
    assert!(peers.is_current(current_source(&peers, peer)));
    Ok(())
}

#[test]
fn empty_header_probe_is_paced_then_rotates_to_another_peer()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let first = test_addr(9760, 2)?;
    let second = test_addr(9760, 3)?;
    let first_rx = connect_peer(&peers, eligible_peer(first, 0));
    let second_rx = connect_peer(&peers, eligible_peer(second, 0));
    let (headers, receiver) = unbounded();
    *sync.inbound_headers_rx.lock() = receiver;
    sync.tick();
    assert!(matches!(first_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(second_rx.try_recv().is_err());
    headers.send(InboundHeaders {
        headers: vec![],
        source: Some(current_source(&peers, first)),
    })?;
    sync.tick();
    assert!(first_rx.try_recv().is_err());
    assert!(second_rx.try_recv().is_err());
    sync.pending_getheaders
        .lock()
        .as_mut()
        .ok_or("probe lost its deadline")?
        .requested_at -= super::super::HEADER_REQUEST_TIMEOUT;
    sync.tick();
    assert!(matches!(second_rx.try_recv()?, Message::GetHeaders(_)));
    assert!(first_rx.try_recv().is_err());
    Ok(())
}

#[test]
fn staged_successors_behind_a_rejected_frontier_still_probe()
-> Result<(), Box<dyn std::error::Error>> {
    use bitcoin_rs_primitives::Amount;
    let (sync, peers, _, blocks, incoming) = sync_with_mined_chain(3)?;
    let peer = test_addr(9761, 0)?;
    // start_height 0: not getdata-eligible (height must exceed the floor of
    // 0) but probe-eligible (services carry NETWORK|WITNESS), so any
    // GetHeaders this peer observes can only come from the idle probe.
    let outbound = connect_peer(&peers, eligible_peer(peer, 0));

    // Malformed frontier body: the header still hashes to block 1's hash, but
    // the txid Merkle root no longer binds to the header, so the body fails
    // the binding gate and is rejected instead of staged.
    let mut malformed_frontier = blocks[0].clone();
    malformed_frontier.txs[0].outputs[0].value = Amount::from_sat(2);
    assert_eq!(
        malformed_frontier.block_hash(),
        blocks[0].block_hash(),
        "altering body transaction bytes must retain the header-derived hash"
    );
    incoming.send(crate::InboundBlock::from_decoded(malformed_frontier))?;
    incoming.send(crate::InboundBlock::from_decoded(blocks[1].clone()))?;
    incoming.send(crate::InboundBlock::from_decoded(blocks[2].clone()))?;

    // One tick: bootstraps genesis, drains and stages, and probes. No earlier
    // tick ran, so the probe decision is the one under test.
    sync.tick();

    // The rejected frontier leaves the apply-frontier block unowned, so the
    // idle probe must fire despite the two staged successors.
    let probe = next_getheaders(&outbound)?;
    assert_eq!(
        probe
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*Network::Regtest.genesis_block().block_hash().as_bytes()),
        "the probe must start from the applied chain"
    );

    // The successors staged; the malformed frontier body did not.
    let body = sync.body_sync.lock();
    assert_eq!(body.stager.received_len(), 2);
    assert!(!body.stager.contains(&Hash256::from(blocks[0].block_hash())));
    drop(body);

    Ok(())
}

#[test]
fn superseded_session_gets_no_probe_and_cannot_send_getheaders()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, _) = sync_with_header_chain(1)?;
    let peer = test_addr(9762, 0)?;
    let old_rx = connect_peer(&peers, eligible_peer(peer, 1));
    let old_source = current_source(&peers, peer);

    // A handshaking replacement takes the address; it never publishes
    // handshake metadata, so it cannot be selected by either header path.
    let (replacement_tx, replacement_rx) = unbounded::<Message>();
    peers.register(peer, PeerLease::new(replacement_tx));

    sync.tick();

    let mut saw_getheaders = false;
    while let Ok(message) = replacement_rx.try_recv() {
        if matches!(message, Message::GetHeaders(_)) {
            saw_getheaders = true;
        }
    }
    assert!(
        !saw_getheaders,
        "handshaking replacement must receive no probe"
    );
    let mut stale_getheaders = false;
    while let Ok(message) = old_rx.try_recv() {
        if matches!(message, Message::GetHeaders(_)) {
            stale_getheaders = true;
        }
    }
    assert!(
        !stale_getheaders,
        "superseded session must receive no probe"
    );

    // The superseded identity must be rejected by the source-validated lease
    // even when addressed directly, and it must leave no pending request.
    let genesis = Network::Regtest.genesis_block().block_hash();
    let locator = vec![Hash256::from_le_bytes(genesis.as_bytes())];
    assert!(
        !sync.send_getheaders(old_source, 0, 10, locator),
        "lease_source must reject a superseded session identity"
    );
    assert!(
        sync.pending_getheaders.lock().is_none(),
        "a rejected send must not leave scheduler state behind"
    );
    Ok(())
}

#[test]
fn failed_probe_send_falls_back_to_best_peer_in_the_same_tick()
-> Result<(), Box<dyn std::error::Error>> {
    let (sync, peers, _, _, expected) = sync_with_header_chain(1)?;
    // Inert getdata: an exhausted staging byte budget closes the request gate
    // before any scan, so no pending body work can suppress the probe.
    install_budget(
        &sync,
        super::super::SyncBudget {
            max_pending_bytes: 0,
            max_received_bytes: 0,
            ..super::super::default_sync_budget()
        },
    );
    let low = test_addr(9763, 0)?;
    let high = test_addr(9763, 1)?;
    // Lowest address wins the probe's min_by_key(addr) rotation, but its
    // channel is dead: dropping the receiver disconnects the crossbeam
    // sender, so the lease's try_send fails and the lease cancels itself.
    let dead_rx = connect_peer(&peers, eligible_peer(low, 1));
    drop(dead_rx);
    let high_rx = connect_peer(&peers, eligible_peer(high, 5));

    sync.tick();

    // The failed probe must hand off to request_headers_from_best_peer in the
    // same tick, which sends to the live higher peer.
    let request = next_getheaders(&high_rx)?;
    assert_eq!(
        request
            .locator_hashes
            .first()
            .map(|hash| *hash.as_byte_array()),
        Some(*expected[0].as_bytes()),
        "the fallback request must start at the header tip"
    );

    // The dead peer must not have inherited the pending request, and no
    // further getheaders lands anywhere in this tick.
    assert_eq!(
        sync.pending_getheaders
            .lock()
            .as_ref()
            .map(|request| request.peer_addr),
        Some(high),
        "the fallback owner must hold the pending request"
    );
    assert!(high_rx.try_recv().is_err());
    Ok(())
}
