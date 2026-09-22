//! Header request ownership, locator construction, and inbound header admission.

use super::BlockSync;
use super::HEADER_REQUEST_TIMEOUT;
use super::IdleFrontierProbeOutcome;
use super::LOCATOR_MAX_ENTRIES;
use super::PROTOCOL_VERSION;
use super::PendingHeaderRequest;
use super::chain::HeaderAdmission;
use super::peers::active_demonstrated_height;
use super::peers::is_peer_fault;
use super::peers::outranks;
use super::peers::sync_peer_candidate;
use crate::InboundHeaders;
use crate::Message;
use crate::PeerSource;
use crate::download_window::SyncPeer;
use bitcoin::hashes::Hash;
use bitcoin::p2p::message_blockdata::GetHeadersMessage;
use bitcoin_rs_primitives::Hash256;
use std::net::SocketAddr;
use std::time::Instant;
use std::vec::Vec;

impl BlockSync {
    pub(super) fn drain_inbound_headers(&self) {
        let receiver = self.inbound_headers_rx.lock();
        let mut total_headers = 0_usize;
        while let Ok(InboundHeaders { headers, source }) = receiver.try_recv() {
            let batch_len = headers.len();
            total_headers = total_headers.saturating_add(batch_len);

            // A nonempty response consumes the request even when rejected.
            // An empty response supplies no new capability: retain its
            // deadline so idle discovery is paced and rotates to another peer.
            if let Some(source) = source.filter(|_| !headers.is_empty()) {
                if self.peer_table.is_current(source) {
                    let mut pending = self.pending_getheaders.lock();
                    if pending.is_some_and(|request| request.peer_addr == source.addr) {
                        *pending = None;
                    }
                }
            }

            // Header admission moves the header tip, which the apply path
            // reads under the transition; the implementation holds that lock
            // inside `admit_headers` until commit.
            match self.chain.admit_headers(&headers) {
                HeaderAdmission::Accepted {
                    accepted,
                    announced_tip,
                    active_height,
                } => {
                    if let (Some(tip_hash), Some(source)) = (announced_tip, source) {
                        self.peer_table
                            .note_announced_tip(source, tip_hash, active_height);
                    }
                    self.refresh_active_peer_credit();
                    // Bodies staged while their carried headers were missing
                    // keep the 0-height sentinel; an accepted batch that
                    // supplies those headers repairs them here.
                    {
                        let tree = self.chain.block_tree().read();
                        self.body_sync
                            .lock()
                            .window
                            .reconcile_received_heights(&tree);
                    }
                    tracing::debug!(
                        accepted,
                        received = batch_len,
                        "block sync: accepted inbound headers batch",
                    );
                }
                HeaderAdmission::Rejected(error) if is_peer_fault(&error) => {
                    let mut blamed_peer = None;
                    if let Some(source) = source {
                        if self.peer_table.disconnect_source(source) {
                            self.body_sync
                                .lock()
                                .window
                                .mark_peer_unresponsive(source.addr, Instant::now());
                            blamed_peer = Some(source.addr);
                        }
                    }
                    if let Some(peer_addr) = blamed_peer {
                        tracing::warn!(
                            peer_addr = %peer_addr,
                            received = batch_len,
                            %error,
                            "block sync: peer served invalid headers; disconnecting",
                        );
                    } else {
                        tracing::warn!(
                            received = batch_len,
                            %error,
                            "block sync: rejected source-less or stale headers batch",
                        );
                    }
                }
                HeaderAdmission::Rejected(error) => {
                    tracing::warn!(
                        received = batch_len,
                        %error,
                        "block sync: rejected inbound headers batch",
                    );
                }
                HeaderAdmission::Refused(error) => {
                    tracing::debug!(%error, "block sync: header admission refused; dropping batch");
                }
            }
        }
        // Any consumed response — accepted or rejected — frees the tracked
        // request slot; a gap recovery deferred behind it retries here.
        self.drain_deferred_gap_recovery();
        if total_headers > 0 {
            tracing::debug!(total_headers, "block sync: drained inbound headers");
        }
    }

    pub(super) fn refresh_active_peer_credit(&self) {
        let sessions = self.peer_table.sessions();
        let updates: Vec<(PeerSource, i32)> = {
            let tree = self.chain.block_tree().read();
            let Some(active_tip) = tree.tip() else {
                return;
            };
            sessions
                .into_iter()
                .filter_map(|session| {
                    let info = session.info?;
                    let height = active_demonstrated_height(
                        &tree,
                        active_tip.tip_id,
                        &session.demonstrated_tips,
                    )?;
                    let height = i32::try_from(height).ok()?;
                    (height > info.best_known_height)
                        .then_some((session.lease.source(session.addr), height))
                })
                .collect()
        };
        for (source, height) in updates {
            self.peer_table.note_announced_height(source, height);
        }
    }

    /// Requests the next header batch from the highest peer above the applied
    /// tip, using a locator taken after `drain_inbound_headers` so it reflects
    /// headers accepted this tick.
    /// `exclude` carries the source whose probe send failed this tick, so the
    /// same-tick fallback cannot retry it.
    pub(super) fn request_headers_from_best_peer(&self, exclude: Option<PeerSource>) {
        let applied_tip = self.chain.applied_tip().load_full();
        let applied_height = applied_tip.as_ref().map_or(0, |tip| tip.height);
        let chain_tip = self.chain.chain_tip().load_full();
        let header_height = chain_tip.as_ref().map_or(applied_height, |tip| tip.height);
        let mut header_peer: Option<(PeerSource, SyncPeer)> = None;
        for session in self.peer_table.sessions() {
            // A session whose lease already cancelled is dead regardless of
            // its published metadata; picking it wastes the tick on a failed
            // send and can wedge the fetch loop.
            if session.lease.is_cancelled() {
                continue;
            }
            let Some(info) = session.info.as_ref() else {
                continue;
            };
            let Some(candidate) = sync_peer_candidate(info, applied_height) else {
                continue;
            };
            let source = session.lease.source(session.addr);
            if exclude.is_some_and(|excluded| excluded == source) {
                continue;
            }
            if header_peer
                .as_ref()
                .is_none_or(|(_, current)| outranks(*current, candidate))
            {
                header_peer = Some((source, candidate));
            }
        }
        if let Some((source, peer)) = header_peer {
            let peer_best_height = u32::try_from(peer.best_known_height).unwrap_or(0);
            if peer_best_height > header_height {
                self.send_getheaders(
                    source,
                    header_height,
                    peer.best_known_height,
                    self.build_locator(),
                );
            }
        }
    }

    /// P2P-05: learn current peer capability when the known-header gap has no
    /// body work on the apply frontier: the probe fires only when the
    /// apply-frontier block itself is neither in flight nor staged. Staged
    /// successors behind an unowned or rejected frontier are stuck inventory
    /// awaiting the staged-body timeout, not progress. Start at the applied
    /// chain so a peer at our header tip returns branch evidence. Reuse the
    /// existing header-request deadline.
    pub(super) fn probe_idle_frontier(&self, now: Instant) -> IdleFrontierProbeOutcome {
        let (Some(applied), Some(headers)) = (
            self.chain.applied_tip().load_full(),
            self.chain.chain_tip().load_full(),
        ) else {
            return IdleFrontierProbeOutcome::NotSent;
        };
        if applied.hash == headers.hash
            || self.apply_halted.load(std::sync::atomic::Ordering::Acquire)
        {
            return IdleFrontierProbeOutcome::NotSent;
        }
        // The frontier hash is derived under a short tree read; body_sync is
        // taken only after the guard drops (tree before body_sync is the
        // codebase's lock order). An unresolvable frontier is conservative:
        // no probe.
        let frontier_hash = {
            let tree = self.chain.block_tree().read();
            Self::first_connect_height(&tree, applied.hash, headers.tip_id)
                .and_then(|height| tree.node_at_height_from(headers.tip_id, height))
                .and_then(|frontier_id| tree.node(frontier_id).ok().map(|node| node.hash))
        };
        let Some(frontier_hash) = frontier_hash else {
            return IdleFrontierProbeOutcome::NotSent;
        };
        {
            let state = self.body_sync.lock();
            if state.window.contains_pending(&frontier_hash)
                || state.stager.contains(&frontier_hash)
            {
                return IdleFrontierProbeOutcome::NotSent;
            }
        }
        let pending = *self.pending_getheaders.lock();
        if pending.is_some_and(|request| {
            now.saturating_duration_since(request.requested_at) < HEADER_REQUEST_TIMEOUT
                && self.peer_table.ready_source(request.peer_addr).is_some()
        }) {
            return IdleFrontierProbeOutcome::Sent;
        }
        let required = bitcoin::p2p::ServiceFlags::NETWORK.to_u64()
            | bitcoin::p2p::ServiceFlags::WITNESS.to_u64();
        let sessions = self.peer_table.sessions();
        let eligible = || {
            sessions.iter().filter(|session| {
                // Same guard as the height-ranked selection: a cancelled lease
                // is a dead send target.
                !session.lease.is_cancelled()
                    && session
                        .info
                        .as_ref()
                        .is_some_and(|info| info.services & required == required)
            })
        };
        // Rotate after the existing request expires, without a second queue.
        let session = eligible()
            .filter(|session| pending.is_none_or(|request| session.addr > request.peer_addr))
            .min_by_key(|session| session.addr)
            .or_else(|| eligible().min_by_key(|session| session.addr));
        let Some(session) = session else {
            return IdleFrontierProbeOutcome::NotSent;
        };
        let source = session.lease.source(session.addr);
        // Anchor on the active chain at the applied height, not on the
        // applied tip's branch. During a deep header-first reorg the applied
        // tip may still sit on the losing branch. A locator from that branch
        // can match only at a common ancestor more than the 2,000-header wire
        // page behind us, so every probe repeats the same insufficient page
        // and never demonstrates a height above the applied tip.
        let locator = {
            let tree = self.chain.block_tree().read();
            let Some(active_anchor) = tree.node_at_height_from(headers.tip_id, applied.height)
            else {
                return IdleFrontierProbeOutcome::NotSent;
            };
            tree.block_locator(active_anchor, LOCATOR_MAX_ENTRIES)
        };
        let sent = self.send_getheaders(
            source,
            applied.height,
            i32::try_from(headers.height).unwrap_or(i32::MAX),
            locator,
        );
        if sent {
            metrics::counter!("node.sync.idle_frontier_probes").increment(1);
            IdleFrontierProbeOutcome::Sent
        } else {
            IdleFrontierProbeOutcome::SendFailed(source)
        }
    }

    pub(super) fn send_getheaders(
        &self,
        source: crate::PeerSource,
        our_height: u32,
        target_height: i32,
        locator: Vec<Hash256>,
    ) -> bool {
        let Some(locator_tip_hash) = locator.first().copied() else {
            return false;
        };
        let target_height = u32::try_from(target_height).unwrap_or(0);
        let now = Instant::now();
        if self.has_pending_getheaders(source.addr, locator_tip_hash, target_height, now) {
            tracing::trace!(
                peer_addr = %source.addr,
                our_height,
                target_height,
                "block sync: getheaders already pending",
            );
            return false;
        }
        let locator_hashes: Vec<bitcoin::BlockHash> = locator
            .into_iter()
            .map(|hash| bitcoin::BlockHash::from_byte_array(*hash.as_byte_array()))
            .collect();
        let msg = Message::GetHeaders(GetHeadersMessage::new(
            locator_hashes,
            bitcoin::BlockHash::all_zeros(),
        ));
        let tx = self.peer_table.lease_source(source);
        let Some(tx) = tx else {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: target peer no longer has outbound channel"
            );
            return false;
        };
        let mut sent = false;
        self.peer_table.with_current(source, || {
            if tx.send(msg).is_ok() {
                *self.pending_getheaders.lock() = Some(PendingHeaderRequest {
                    peer_addr: source.addr,
                    locator_tip_hash,
                    target_height,
                    requested_at: now,
                });
                sent = true;
            }
        });
        if !sent {
            tracing::warn!(
                peer_addr = %source.addr,
                "block sync: outbound channel disconnected"
            );
            // The send failure means this connection is gone: evict it so the
            // scheduler cannot re-pick a dead peer every tick. The identity
            // check inside `disconnect_source` keeps a same-address
            // replacement untouched, and only then is a pending request keyed
            // to this address dropped so a fast reconnect does not inherit a
            // stale deadline gate.
            if self.peer_table.disconnect_source(source) {
                let mut pending = self.pending_getheaders.lock();
                if pending.is_some_and(|request| request.peer_addr == source.addr) {
                    *pending = None;
                }
            }
            return false;
        }
        tracing::debug!(
            peer_addr = %source.addr,
            our_height,
            target_height,
            protocol_version = PROTOCOL_VERSION,
            "block sync: sent getheaders"
        );
        true
    }

    pub(super) fn has_pending_getheaders(
        &self,
        peer_addr: SocketAddr,
        locator_tip_hash: Hash256,
        target_height: u32,
        now: Instant,
    ) -> bool {
        let pending = *self.pending_getheaders.lock();
        let Some(pending) = pending else {
            return false;
        };
        pending.peer_addr == peer_addr
            && pending.locator_tip_hash == locator_tip_hash
            && pending.target_height == target_height
            && now.duration_since(pending.requested_at) < HEADER_REQUEST_TIMEOUT
    }

    pub(super) fn build_locator(&self) -> Vec<Hash256> {
        if let Some(tip) = self.chain.chain_tip().load_full() {
            return self
                .chain
                .block_tree()
                .read()
                .block_locator(tip.tip_id, LOCATOR_MAX_ENTRIES);
        }
        std::vec![self.chain.network().genesis_block_hash()]
    }
}
