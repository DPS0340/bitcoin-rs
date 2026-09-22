//! Live head-sync: announcements learned inside bodies, and gaps between
//! delivered headers and the tree, must still reach admission and become
//! fetchable — a staged body can never apply while the tree does not know
//! its hash, and a batch that cannot attach must not end the conversation.

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
fn body_delivered_without_headers_announcement_admits_and_applies()
-> Result<(), Box<dyn std::error::Error>> {
    // A block body carries its own header. Bodies arriving via `inv`
    // getdata, compact-block reconstruction, or an unsolicited push
    // otherwise stage a body whose hash the tree does not know — it can
    // never become the expected block, so it times out and is dropped
    // while nothing re-requests it. The staged-header retry must admit
    // the embedded header and let the apply drain catch up.
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        applied_tip,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let unannounced =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    let expected = unannounced.block_hash();
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(unannounced))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(expected),
        "the body-carried header must admit and the body must apply"
    );
    Ok(())
}

#[test]
fn body_arriving_ahead_of_its_header_chain_requests_the_gap()
-> Result<(), Box<dyn std::error::Error>> {
    // A body two blocks past the applied tip has an unannounced parent.
    // Header admission fails MissingParent — sync must ask an eligible
    // peer for the missing ancestry instead of retaining the body until
    // its staged timeout drops it.
    let (tree, blocks) = mined_chain(1, 0)?;
    let SyncHarness {
        sync,
        peers,
        applied_tip,
        inbound_headers_tx,
        inbound_blocks_tx,
        ..
    } = SyncHarness::new(tree);
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(blocks[0].clone()))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(blocks[0].block_hash()),
    );

    let peer = test_addr(9700, 0)?;
    let rx = connect_peer(&peers, eligible_peer(peer, 3));

    let block2 =
        mined_block_with_prev_hash(blocks[0].block_hash(), 2, vec![coinbase_transaction(2)]);
    let block3 = mined_block_with_prev_hash(block2.block_hash(), 3, vec![coinbase_transaction(3)]);
    // Only the tip-of-gap body arrives — its parent's header is unknown.
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block3.clone()))?;
    sync.tick();
    next_getheaders(&rx)?;

    // The ancestry fill lands: the gap headers admit, both bodies stage,
    // and the chain applies through the delivered tip.
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![block2.header, block3.header],
        source: Some(current_source(&peers, peer)),
    })?;
    inbound_blocks_tx.send(crate::InboundBlock::from_decoded(block2))?;
    sync.tick();
    assert_eq!(
        applied_tip.load_full().ok_or("missing applied tip")?.hash,
        Hash256::from(block3.block_hash()),
        "the staged tip body must apply once its parent headers land"
    );
    Ok(())
}

#[test]
fn headers_batch_missing_parent_requests_ancestry() -> Result<(), Box<dyn std::error::Error>> {
    // An announce of a tip whose parent is unknown cannot attach. The
    // announcer demonstrably has the gap, so sync asks it for the ancestry
    // rather than dropping the batch and wedging the live tip.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);

    let peer = test_addr(9701, 0)?;
    let rx = connect_peer(&peers, eligible_peer(peer, 10));

    let gap_parent = test_header(genesis.compute_hash(), 1);
    let orphan_tip = test_header(gap_parent.compute_hash(), 2);
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![orphan_tip],
        source: Some(current_source(&peers, peer)),
    })?;

    sync.drain_inbound_headers();

    next_getheaders(&rx)?;
    Ok(())
}

#[test]
fn known_header_batch_still_credits_the_announcer() -> Result<(), Box<dyn std::error::Error>> {
    // The all-known fast path must keep the announced-tip credit the
    // admission path produced — the delivering peer's demonstrated height
    // raises its best-known watermark.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = test_header(genesis.compute_hash(), 1);
    tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9702, 0)?;
    let _rx = connect_peer(&peers, eligible_peer(peer, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip1],
        source: Some(current_source(&peers, peer)),
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .infos()
            .into_iter()
            .find(|info| info.addr == peer)
            .ok_or("peer info missing")?
            .best_known_height,
        1,
        "a known tip still credits the announcer"
    );
    Ok(())
}

#[test]
fn delivered_tip_evidence_is_compacted_to_the_max_resolving_tip()
-> Result<(), Box<dyn std::error::Error>> {
    // Every delivered body's embedded header forwards through the headers
    // sink (P2P-06) and pushes a demonstrated tip per block. The credit
    // refresh compacts retained evidence to the max-resolving tip —
    // resolved tips below it can never raise the watermark again — or the
    // record would grow with every download.
    let mut tree = BlockTree::new();
    let genesis = genesis_header();
    let genesis_id = tree.insert_node(None, genesis, NodeStatus::HeaderValid)?;
    let tip1 = test_header(genesis.compute_hash(), 1);
    let tip1_id = tree.insert_node(Some(genesis_id), tip1, NodeStatus::HeaderValid)?;
    let tip2 = test_header(tip1.compute_hash(), 2);
    tree.insert_node(Some(tip1_id), tip2, NodeStatus::HeaderValid)?;
    let SyncHarness {
        sync,
        peers,
        inbound_headers_tx,
        ..
    } = SyncHarness::new(tree);
    let peer = test_addr(9703, 0)?;
    let _rx = connect_peer(&peers, eligible_peer(peer, 0));

    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip1],
        source: Some(current_source(&peers, peer)),
    })?;
    inbound_headers_tx.send(InboundHeaders {
        headers: vec![tip2],
        source: Some(current_source(&peers, peer)),
    })?;
    sync.drain_inbound_headers();

    assert_eq!(
        peers
            .sessions()
            .into_iter()
            .find(|session| session.addr == peer)
            .ok_or("peer session missing")?
            .demonstrated_tips,
        vec![Hash256::from(tip2.compute_hash())],
        "retained evidence compacts to the max-resolving tip"
    );
    Ok(())
}
