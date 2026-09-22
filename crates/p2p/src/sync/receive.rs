//! Bounded inbound body draining and exact staged-body admission.

use super::BlockSync;
use super::HEADER_REQUEST_TIMEOUT;
use super::chain::HeaderAdmission;
use super::chain::SyncChainError;
use super::peers::is_peer_fault;
use crate::InboundBlock;
use crate::RejectDelivery;
use crate::StagedBlock;
use crate::connection::PeerSource;
use crate::download_window::INBOUND_BLOCK_STAGE_CHUNK;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainError;
use bitcoin_rs_chain::NodeId;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use hashbrown::HashMap;
use hashbrown::HashSet;
use smallvec::SmallVec;
use std::time::Instant;
use std::vec::Vec;

/// Which window credit a staged delivery earns once the delivering
/// connection is proven current under table authority.
#[derive(Clone, Copy)]
enum DeliveryCredit {
    /// The block was already staged: only the pending-timeout observation
    /// resolves.
    Duplicate,
    /// A first-copy delivery: timeout, cold-front, probe, and stall progress,
    /// gated on the height the pending carried at removal.
    Delivery(Option<u32>),
}

impl BlockSync {
    pub(super) fn drain_inbound_blocks(&self) {
        let mut apply_head_check = None;
        let mut next_expected_hash = None;
        let mut blocks = Vec::with_capacity(INBOUND_BLOCK_STAGE_CHUNK);
        let mut received = 0_usize;
        let mut receiver_empty = false;
        let mut saw_block = false;
        while !receiver_empty {
            receiver_empty = self.fill_inbound_block_chunk(
                &mut blocks,
                &mut saw_block,
                &mut next_expected_hash,
                &mut apply_head_check,
            );
            if !blocks.is_empty() {
                received = received.saturating_add(
                    self.buffer_received_block_chunk(&mut blocks, next_expected_hash),
                );
            }
        }
        if received == 0 && self.scheduler.lock().stager.received_len() == 0 {
            return;
        }

        let now = Instant::now();
        let dropped = self.scheduler.lock().stager.prune_expired(now);
        let pruned = !dropped.is_empty();
        if pruned {
            let tree = self.chain.block_tree().read();
            let height_updates: Vec<(Hash256, u32)> = dropped
                .iter()
                .filter_map(|dropped| {
                    let node_id = tree.lookup(dropped.hash)?;
                    tree.node(node_id)
                        .ok()
                        .map(|node| (dropped.hash, node.height))
                })
                .collect();
            drop(tree);
            let mut scheduler = self.scheduler.lock();
            let window = &mut scheduler.window;
            for (hash, height) in height_updates {
                window.update_received_height(&hash, height);
            }
            for dropped in dropped {
                window.drop_received_for_retry(&dropped.hash);
            }
        }

        self.switch_branch_if_outweighed();
        let (applied, failed) = self.apply_buffered_blocks(apply_head_check);
        if received > 0 || applied > 0 || failed > 0 {
            tracing::debug!(
                received,
                applied,
                failed,
                "block sync: drained inbound blocks"
            );
        }
        if received > 0 || pruned || applied > 0 || failed > 0 {
            self.record_sync_metrics();
        }
    }

    pub(super) fn fill_inbound_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        saw_block: &mut bool,
        next_expected_hash: &mut Option<Hash256>,
        apply_head_check: &mut Option<Hash256>,
    ) -> bool {
        let receiver = self.inbound_blocks_rx.lock();
        while blocks.len() < INBOUND_BLOCK_STAGE_CHUNK {
            let Ok(inbound) = receiver.try_recv() else {
                return true;
            };
            if !*saw_block {
                *next_expected_hash = self.next_expected_block_hash();
                *apply_head_check = next_expected_hash
                    .as_ref()
                    .copied()
                    .filter(|hash| *hash != Hash256::from(inbound.block.block_hash()));
            }
            blocks.push(inbound);
            *saw_block = true;
        }
        false
    }

    /// Uses the active-chain height index only while the applied tip is its prefix.
    ///
    /// During a header-first reorg the caller retains old-height blocks rather
    /// than walking the applied ancestry or dropping a body from the new branch.
    pub(super) fn indexed_applied_ancestry_tip(
        tree: &BlockTree,
        applied_tip: &TipSnapshot,
    ) -> Option<NodeId> {
        let active_tip = tree.tip()?;
        Self::is_ancestor_at_height(
            tree,
            applied_tip.tip_id,
            applied_tip.height,
            active_tip.tip_id,
        )
        .then_some(active_tip.tip_id)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn buffer_received_block_chunk(
        &self,
        blocks: &mut Vec<InboundBlock>,
        next_expected_hash: Option<Hash256>,
    ) -> usize {
        // A live-head `inv` or compact announcement fetches the body
        // directly — no `headers` batch travels — so a body whose hash the
        // tree does not know carries the only copy of its header. Admitting
        // it here lets the block schedule and apply; skipped, the staged
        // copy silently expires with the announced tip never learned.
        self.admit_delivered_block_headers(blocks);

        // Admission may have advanced the header tip past the frontier
        // captured in `fill_inbound_block_chunk`; the stager protects the
        // apply-frontier body from budget eviction only under the fresh one.
        let next_expected_hash = self.next_expected_block_hash().or(next_expected_hash);

        // A cold-start hedge can arrive after its original copy was applied.
        // Drop only blocks proven to lie on the applied ancestry; a known
        // side-chain block at the same or lower height must remain eligible.
        if let Some(applied_tip) = self.chain.applied_tip().load_full() {
            let tree = self.chain.block_tree().read();
            let indexed_tip = Self::indexed_applied_ancestry_tip(&tree, &applied_tip);
            blocks.retain(|inbound| {
                let hash = Hash256::from(inbound.block.block_hash());
                let Some(node_id) = tree.lookup(hash) else {
                    return true;
                };
                let Ok(node) = tree.node(node_id) else {
                    return true;
                };
                node.height > applied_tip.height
                    || indexed_tip.is_none_or(|tip_id| {
                        tree.node_at_height_from(tip_id, node.height) != Some(node_id)
                    })
            });
        }

        // Already-staged precheck: skip the expensive body-binding hashes for
        // blocks whose hash is already in the stager. A correct body already
        // staged must not be displaced by a late malformed duplicate (P2-3).
        let already_staged: Vec<bool> = {
            let scheduler = self.scheduler.lock();
            let stager = &scheduler.stager;
            blocks
                .iter()
                .map(|inbound| stager.contains(&Hash256::from(inbound.block.block_hash())))
                .collect()
        };

        // For non-staged blocks, the chain side derives segwit_active from
        // the tree (the same canonical softfork_state path as apply) and runs
        // the consensus body-binding check, so the gate reproduces exact
        // consensus semantics without the executor owning the rule.
        let binding_results: Vec<Result<(), SyncChainError>> = blocks
            .iter()
            .zip(&already_staged)
            .map(|(inbound, already_staged)| {
                if *already_staged {
                    Ok(())
                } else {
                    self.chain.check_body_binding(&inbound.block)
                }
            })
            .collect();

        // Stager lock: TOCTOU recheck + insert. Binding-failed blocks are
        // tracked separately for the window's source-aware reject_delivery.
        let mut staged_blocks = Vec::with_capacity(blocks.len());
        let mut reject_deliveries = Vec::new();
        let now = Instant::now();
        {
            let mut scheduler = self.scheduler.lock();
            let stager = &mut scheduler.stager;
            for (inbound, (already_staged, binding_result)) in blocks
                .drain(..)
                .zip(already_staged.into_iter().zip(binding_results))
            {
                let hash = Hash256::from(inbound.block.block_hash());
                let source = inbound.source;
                if already_staged {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                // Issue #1070: the header-derived block hash does not bind the
                // delivered transaction or witness bytes by itself. The
                // stager keeps the first body per hash, so reject any body
                // whose txid Merkle tree or witness commitment does not bind
                // to the header before it can occupy that slot.
                if let Err(error) = binding_result {
                    metrics::counter!("node.sync.body_binding_drops").increment(1);
                    let witness = inbound
                        .block
                        .txs
                        .first()
                        .and_then(|tx| tx.inputs.first())
                        .map(|input| &input.witness);
                    tracing::warn!(
                        %hash, %error, ?source,
                        serialized_bytes = inbound.serialized.len(),
                        transactions = inbound.block.txs.len(),
                        coinbase_witness_items = witness.map_or(0, bitcoin_rs_primitives::Witness::len),
                        coinbase_witness_first_bytes = witness.and_then(|stack| stack.first()).map_or(0, Vec::len),
                        "block sync: body/header binding failed; rejecting delivery"
                    );
                    reject_deliveries.push((hash, source));
                    continue;
                }
                // TOCTOU: recheck under the stager lock before inserting.
                if stager.contains(&hash) {
                    staged_blocks.push((hash, source, StagedBlock::AlreadyStaged));
                    continue;
                }
                let staged = stager.insert(
                    hash,
                    next_expected_hash,
                    inbound.block,
                    inbound.serialized,
                    now,
                );
                staged_blocks.push((hash, source, staged));
            }
        }

        // Resolve staged sources before taking the scheduler lock. Request
        // sends hold PeerTable's read lock while marking the window, so no
        // scheduler holder may acquire PeerTable in the opposite order.
        //
        // The source is the whole connection identity: a cancelled lease is
        // not a schedulable peer, so deliveries from one carry no credit.
        let staged_blocks: Vec<_> = staged_blocks
            .into_iter()
            .map(|(hash, source, staged)| {
                let source_peer = source.filter(|source| self.peer_table.is_current(*source));
                (hash, source_peer, staged)
            })
            .collect();

        // Resolve heights the window cannot see: an untracked delivery (inv
        // announcement, cold-front hedge) enters `received` at height 0, and
        // `mark_received_from` reports `needs_height_lookup` for exactly those
        // entries so this pass can pin the tree height. The same lookup covers
        // staged bodies this insert count-evicts: a body that arrived before
        // its header stayed at height 0, and `drop_received_for_retry` must
        // place the retry at the tree height, not rewind the request cursor.
        // A hash not yet in the tree stays 0 until the prune path's own
        // re-evaluation.
        let staged_blocks: Vec<_> = {
            let tree = self.chain.block_tree().read();
            staged_blocks
                .into_iter()
                .map(|(hash, source_peer, staged)| {
                    let resolve = |hash: Hash256| {
                        tree.lookup(hash)
                            .and_then(|node_id| tree.node(node_id).ok())
                            .map(|node| node.height)
                    };
                    let known_height = resolve(hash);
                    let dropped_heights = match &staged {
                        StagedBlock::Memory { dropped, .. } => {
                            dropped.iter().map(|entry| resolve(entry.hash)).collect()
                        }
                        _ => Vec::new(),
                    };
                    (hash, source_peer, staged, known_height, dropped_heights)
                })
                .collect()
        };
        let mut retry_count = 0_u64;
        let staged_count = staged_blocks.len() + reject_deliveries.len();
        let mut delivery_credits: SmallVec<[(Hash256, PeerSource, DeliveryCredit); 8]> =
            SmallVec::new();
        {
            let mut scheduler = self.scheduler.lock();
            let window = &mut scheduler.window;
            for (hash, source_peer, staged, known_height, dropped_heights) in staged_blocks {
                match staged {
                    StagedBlock::AlreadyStaged => {
                        metrics::counter!("node.sync.duplicate_deliveries").increment(1);
                        if let Some(source_peer) = source_peer {
                            delivery_credits.push((hash, source_peer, DeliveryCredit::Duplicate));
                        }
                    }
                    StagedBlock::Memory { bytes, dropped } => {
                        let pending_height = window.mark_received_from(hash, bytes, None, now);
                        // A body that arrived before its header entered the
                        // tree has no pending height: adopt the tree-resolved
                        // height so a later retry lands at the right cursor.
                        if pending_height.is_none()
                            && let Some(height) = known_height
                        {
                            window.update_received_height(&hash, height);
                        }
                        if let Some(source_peer) = source_peer {
                            delivery_credits.push((
                                hash,
                                source_peer,
                                DeliveryCredit::Delivery(pending_height),
                            ));
                        }
                        for (entry, height) in dropped.into_iter().zip(dropped_heights) {
                            if let Some(height) = height {
                                window.update_received_height(&entry.hash, height);
                            }
                            window.drop_received_for_retry(&entry.hash);
                            retry_count = retry_count.saturating_add(1);
                        }
                    }
                    StagedBlock::DroppedForRetry { dropped } => {
                        window.drop_for_retry(&dropped.hash);
                        retry_count = retry_count.saturating_add(1);
                        tracing::warn!(%hash, "block sync: received block buffer full; dropping block for retry");
                    }
                }
            }
        }
        // Delivery credit is stamped only while the delivering connection is
        // still current: `with_current` holds the table authority across the
        // window mutation, so a same-address replacement registering between
        // the liveness check above and this point voids the credit rather
        // than clearing stall or timeout state for a retired connection.
        for (hash, source_peer, credit) in delivery_credits {
            self.peer_table.with_current(source_peer, || {
                let mut scheduler = self.scheduler.lock();
                match credit {
                    DeliveryCredit::Duplicate => {
                        scheduler
                            .window
                            .credit_duplicate_delivery(hash, source_peer);
                    }
                    DeliveryCredit::Delivery(pending_height) => {
                        scheduler.window.credit_delivery_from(
                            hash,
                            source_peer,
                            pending_height,
                            now,
                        );
                    }
                }
            });
        }
        for (hash, source) in reject_deliveries {
            let mut rejected = RejectDelivery::DiscardedUnsolicited;
            let current = source.is_some_and(|source| {
                self.peer_table.with_current(source, || {
                    rejected = self
                        .scheduler
                        .lock()
                        .window
                        .reject_delivery(hash, Some(source));
                })
            });
            if !current {
                self.scheduler.lock().window.reject_delivery(hash, None);
            }
            if rejected == RejectDelivery::ReleasedPending {
                retry_count = retry_count.saturating_add(1);
                if let Some(source) = source {
                    if self.peer_table.disconnect_source(source) {
                        self.scheduler
                            .lock()
                            .window
                            .mark_peer_unresponsive(source.addr, now);
                        tracing::warn!(peer_addr = %source.addr, %hash, "block sync: peer served mutated block body; disconnecting");
                    }
                }
            }
        }
        if retry_count > 0 {
            metrics::counter!("node.sync.retry_count").increment(retry_count);
        }
        staged_count
    }

    /// Admits headers carried by delivered bodies whose hashes are not yet
    /// in the tree, so the staging pass below resolves their heights from
    /// the tree like any other known hash.
    ///
    /// Live-head announcements can reach the body stage without a `headers`
    /// batch: an `inv` block item or a compact-block fallback fetches the
    /// body directly, so the delivered block carries the only copy of its
    /// header. Admission reuses the `headers`-batch seam, but one chunk can
    /// mix deliverers, so unknown headers are grouped by source and admitted
    /// to a fixed point: a validation fault then blames only its deliverer,
    /// and a group whose parents arrive through a sibling's admission
    /// attaches on a later round. Within a group, `header_components`
    /// admits each connected chain separately — `admit_headers` stops at
    /// its first failure, so a gap component ordered early would otherwise
    /// strand attachable components behind it. A missing ancestor is not a
    /// peer fault — the delivering peer necessarily holds the chain it
    /// announced — so one gap per pass heals with a `getheaders` back to
    /// the first gapped deliverer: sibling gaps on the same chain heal from
    /// that reply, and divergent gaps stay bounded by staged expiry rather
    /// than racing the single tracked header request. The send is skipped
    /// when the loop itself healed the gap, when the deliverer left, or
    /// when a header request is already in flight — the slot tracks one
    /// send, so recovery never displaces an unrelated live request.
    ///
    /// Runs outside `scheduler`: `admit_headers` takes the chain transition
    /// lock and the tree write, both of which rank above the window lock.
    fn admit_delivered_block_headers(&self, blocks: &[InboundBlock]) {
        self.drain_deferred_gap_recovery();
        let mut heights = HashMap::with_capacity(blocks.len());
        let mut groups: HashMap<Option<PeerSource>, HashMap<Hash256, Header>> = HashMap::new();
        let mut deliverers: HashMap<Hash256, Vec<PeerSource>> = HashMap::new();
        {
            let tree = self.chain.block_tree().read();
            for inbound in blocks {
                let hash = Hash256::from(inbound.block.block_hash());
                if let Some(node) = tree
                    .lookup(hash)
                    .and_then(|node_id| tree.node(node_id).ok())
                {
                    heights.insert(hash, node.height);
                } else {
                    groups
                        .entry(inbound.source)
                        .or_default()
                        .entry(hash)
                        .or_insert(inbound.block.header);
                    if let Some(source) = inbound.source {
                        let delivered = deliverers.entry(hash).or_default();
                        if !delivered.contains(&source) {
                            delivered.push(source);
                        }
                    }
                }
            }
        }
        if groups.is_empty() {
            return;
        }
        let mut gap_source: Option<(PeerSource, Hash256)> = None;
        loop {
            let mut progressed = false;
            for (&source, group) in &mut groups {
                group.retain(|hash, _| !heights.contains_key(hash));
                if group.is_empty() {
                    continue;
                }
                let admissions: Vec<HeaderAdmission> = header_components(group)
                    .into_iter()
                    .map(|component| self.chain.admit_headers(&component))
                    .collect();
                {
                    // Re-resolve under one read: every hash the tree now knows
                    // was admitted, so delivering it demonstrates possession
                    // of the block — and EVERY deliverer of that hash earns
                    // the same demonstrated-tip credit a `headers`
                    // announcement earns, not just the first-iterating one.
                    let tree = self.chain.block_tree().read();
                    for hash in group.keys() {
                        let Some(node) = tree.lookup(*hash).and_then(|id| tree.node(id).ok())
                        else {
                            continue;
                        };
                        if heights.insert(*hash, node.height).is_none() {
                            progressed = true;
                            if let Some(sources) = deliverers.get(hash) {
                                for &deliverer in sources {
                                    self.peer_table.note_announced_tip(deliverer, *hash, None);
                                }
                            }
                        }
                    }
                }
                for admission in admissions {
                    self.handle_carried_header_admission(admission, source, &mut gap_source);
                }
            }
            if !progressed {
                break;
            }
        }
        if let Some((source, prev_hash)) = gap_source
            && !self.try_gap_recovery(source, prev_hash)
        {
            // Keep the earliest outstanding gap: its staged body expires
            // soonest, so a same-tick sibling gap queues behind it rather
            // than displacing it and silently losing its retry.
            let mut scheduler = self.scheduler.lock();
            if scheduler.deferred_gap_recovery.is_none() {
                scheduler.deferred_gap_recovery = Some((source, prev_hash));
            }
        }
        // Bodies staged before their headers landed (an earlier chunk's
        // refused or re-delivered admission) would otherwise keep the
        // 0-height sentinel forever.
        {
            let tree = self.chain.block_tree().read();
            self.scheduler
                .lock()
                .window
                .reconcile_received_heights(&tree);
        }
        self.refresh_active_peer_credit();
    }

    /// Sends the pass's single recovery `getheaders` for a missing-parent
    /// gap. Returns `true` when no retry is owed — the request went out,
    /// a sibling admission healed the gap, or the deliverer left — and
    /// `false` only when an unrelated in-flight request suppressed the
    /// send, in which case the caller defers it to `deferred_gap_recovery`.
    fn try_gap_recovery(&self, source: PeerSource, prev_hash: Hash256) -> bool {
        // A sibling group or a later round may have admitted the missing
        // ancestor since the gap was recorded; a healed gap makes the
        // request void. Sending to a deliverer already disconnected for a
        // peer fault is equally void.
        if self.chain.block_tree().read().lookup(prev_hash).is_some()
            || !self.peer_table.is_current(source)
        {
            return true;
        }
        // The single tracked slot must never displace an unrelated
        // in-flight request — that response could not clear the tracker
        // and later ticks would issue competing sends. Snapshot the slot,
        // then drop the guard before touching the table: peer-table reads
        // under the scheduler lock invert the table→scheduler order
        // `with_current` callers rely on.
        let pending_request = self.scheduler.lock().header_request;
        let live_pending = pending_request.is_some_and(|request| {
            Instant::now().duration_since(request.requested_at) < HEADER_REQUEST_TIMEOUT
                && self.peer_table.is_current(request.source)
        });
        if live_pending {
            return false;
        }
        let our_height = self
            .chain
            .chain_tip()
            .load_full()
            .map_or(0, |tip| tip.height);
        self.send_getheaders(source, our_height, i32::MAX, self.build_locator());
        true
    }

    /// Fires a recovery deferred behind an occupied request slot once a
    /// pass finds it free; clears the slot when the gap healed, the
    /// deliverer left, or the send went out. Called wherever header
    /// progress can free the slot — the body-admission pass and accepted
    /// `headers` batches.
    pub(super) fn drain_deferred_gap_recovery(&self) {
        let Some((source, prev_hash)) = self.scheduler.lock().deferred_gap_recovery else {
            return;
        };
        if self.try_gap_recovery(source, prev_hash) {
            self.scheduler.lock().deferred_gap_recovery = None;
        }
    }

    /// Reacts to one deliverer's component admission with the same
    /// semantics a `headers` batch gets: a validation fault disconnects
    /// that deliverer; a missing ancestor records the deliverer and the
    /// missing hash for the pass's single recovery `getheaders`
    /// (`i32::MAX`: unbounded).
    fn handle_carried_header_admission(
        &self,
        admission: HeaderAdmission,
        source: Option<PeerSource>,
        gap_source: &mut Option<(PeerSource, Hash256)>,
    ) {
        match admission {
            HeaderAdmission::Accepted { .. } => {}
            HeaderAdmission::Rejected(error) if is_peer_fault(&error) => {
                if let Some(source) = source
                    && self.peer_table.disconnect_source(source)
                {
                    self.scheduler
                        .lock()
                        .window
                        .mark_peer_unresponsive(source.addr, Instant::now());
                    tracing::warn!(
                        peer_addr = %source.addr,
                        %error,
                        "block sync: delivered block carried an invalid header; disconnecting",
                    );
                }
            }
            HeaderAdmission::Rejected(ChainError::MissingParent { prev_hash }) => {
                if let Some(source) = source {
                    gap_source.get_or_insert((source, prev_hash));
                }
            }
            HeaderAdmission::Rejected(error) => {
                tracing::warn!(
                    %error,
                    "block sync: rejected headers carried by delivered blocks",
                );
            }
            HeaderAdmission::Refused(error) => {
                tracing::debug!(
                    %error,
                    "block sync: delivered-header admission refused; dropping batch",
                );
            }
        }
    }
}

/// Splits `headers` into connected components, each ordered
/// parent-before-child so a delivered chain admits in one `admit_headers`
/// call per component: each emitted prefix walks back to its deepest batch
/// ancestor. Components are independent — a gap component's `MissingParent`
/// cannot strand the attachable components ordered behind it.
fn header_components(headers: &HashMap<Hash256, Header>) -> Vec<Vec<Header>> {
    let mut components = Vec::new();
    let mut emitted = HashSet::with_capacity(headers.len());
    for hash in headers.keys() {
        let mut chain = Vec::new();
        let mut cursor = *hash;
        while !emitted.contains(&cursor) {
            let Some(header) = headers.get(&cursor) else {
                break;
            };
            chain.push(cursor);
            emitted.insert(cursor);
            cursor = Hash256::from(header.prev_blockhash);
        }
        if chain.is_empty() {
            continue;
        }
        components.push(chain.into_iter().rev().map(|hash| headers[&hash]).collect());
    }
    components
}
