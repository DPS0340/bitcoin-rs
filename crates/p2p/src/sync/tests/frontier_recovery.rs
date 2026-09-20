//! P2P-05: canonical progress, not a scheduler cursor, owns the next body.

use super::*;

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
