//! Filter-index reconciliation worker: the second chain-event consumer.
//!
//! Mirrors the txindex worker shape (`crates/node/src/txindex_worker.rs`) on
//! the seam documented in `docs/contracts/chain-events.md`: a persisted
//! [`StoredCursor`] plus an active filter-header pointer name the exact chain
//! state the rows mirror; the worker wakes on a chain-event hint or a
//! one-second poll tick, reads a fresh snapshot, and re-plans positionally
//! over the `BlockTree`. Filter and header rows are hash-addressed, so a
//! reorg rewinds only the pointer and the cursor — rows are retained, and
//! re-derived rows are idempotent overwrites. Every pass commits its rows,
//! the pointer, the cursor, and the lifecycle state in one atomic namespace
//! batch, so the persisted pointer, cursor, and state always describe one
//! coherent chain position: a rewind moves all three to the ancestor, and a
//! caught-up claim is committed only alongside a cursor that names the
//! snapshot it mirrors.
//!
//! Failure isolation: the worker runs on its own thread under
//! `catch_unwind`; any failure publishes on the runtime and never blocks
//! block application, sync, or other indexes. The apply path never touches
//! this worker's store.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{OutPoint, ScriptBuf, Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_ext_api::{Extension, ExtensionDescriptor, HealthStatus};
use bitcoin_rs_ext_blockfilterindex::{
    ActivePointer, DESCRIPTOR as FILTER_DESCRIPTOR, FilterBatch, FilterStoreError, FilterStoreOps,
    LifecycleState, StoredCursor, basic_filter_for_block, filter_header, zero_filter_header,
};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::context::{FilterIndexInfo, FilterIndexQuery, TxIndexQuery, TxQueryError};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::RwLock;

use crate::apply::PruneBodyStore;
use crate::reconcile::{ConsumerCursor, ReconcilePlan, plan};

/// Interval between poll ticks when no hint arrives.
const POLL_TICK: Duration = Duration::from_secs(1);

/// Shared wake and health state for the filter consumer.
#[derive(Debug)]
pub(crate) struct FilterIndexRuntime {
    shutdown: AtomicBool,
    failed: AtomicBool,
    wake_tx: Sender<()>,
    failure_message: RwLock<Option<compact_str::CompactString>>,
}

impl FilterIndexRuntime {
    /// Creates a runtime attached to `wake_tx`.
    #[must_use]
    pub(crate) fn new(wake_tx: Sender<()>) -> Self {
        Self {
            shutdown: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            wake_tx,
            failure_message: RwLock::new(None),
        }
    }

    /// Coalescing wake; lost wakes are recovered by the next poll tick.
    pub(crate) fn wake(&self) {
        let _ = self.wake_tx.try_send(());
    }

    /// Marks the worker failed with an explanatory message.
    pub(crate) fn publish_failed(&self, message: impl Into<compact_str::CompactString>) {
        *self.failure_message.write() = Some(message.into());
        self.failed.store(true, Ordering::Release);
    }

    /// True once a failure or shutdown has been published.
    #[must_use]
    pub(crate) fn should_stop(&self) -> bool {
        self.shutdown.load(Ordering::Acquire) || self.failed.load(Ordering::Acquire)
    }

    /// Requests graceful shutdown.
    pub(crate) fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = self.wake_tx.try_send(());
    }

    /// Returns the published failure message, if any.
    #[must_use]
    pub(crate) fn failure_message(&self) -> Option<compact_str::CompactString> {
        self.failure_message.read().clone()
    }
}

/// Handle owning the spawned worker thread.
pub(crate) struct FilterIndexWorker {
    runtime: Arc<FilterIndexRuntime>,
    join_handle: Option<JoinHandle<()>>,
}

impl FilterIndexWorker {
    /// Spawns the reconciliation worker over the namespace `store`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn spawn(
        runtime: Arc<FilterIndexRuntime>,
        store: Arc<dyn FilterStoreOps>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        body_store: Arc<dyn PruneBodyStore>,
        tx_lookup: Option<Arc<dyn TxIndexQuery>>,
        chain_events: Arc<crate::state::ChainEventPublisher>,
        wake: Receiver<()>,
        hints: Receiver<crate::state::ChainEventHint>,
    ) -> std::io::Result<Self> {
        let worker = Worker {
            runtime: Arc::clone(&runtime),
            store,
            applied_tip,
            block_tree,
            body_store,
            tx_lookup,
            chain_events,
            wake,
            hints,
            window: PrevoutWindow::new(),
        };
        let runtime_for_error = Arc::clone(&runtime);
        let join_handle = thread::Builder::new()
            .name("bitcoin-rs-blockfilterindex".to_owned())
            .spawn(move || {
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| worker.run()));
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::error!(%error, "filter index worker failed");
                        runtime_for_error.publish_failed(error.to_string());
                    }
                    Err(payload) => {
                        let message = payload
                            .downcast_ref::<&str>()
                            .copied()
                            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
                            .unwrap_or("filter index worker panicked");
                        tracing::error!(%message, "filter index worker panicked");
                        runtime_for_error.publish_failed(message);
                    }
                }
            })?;
        Ok(Self {
            runtime,
            join_handle: Some(join_handle),
        })
    }

    /// Requests shutdown and joins the worker thread.
    pub(crate) fn join(mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for FilterIndexWorker {
    fn drop(&mut self) {
        self.runtime.request_shutdown();
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum FilterWorkerError {
    /// Shutdown was requested; the loop exits without publishing a failure.
    #[error("filter index worker stopped")]
    Stopped,
    /// The namespace store refused a read or write.
    #[error("filter index namespace error: {0}")]
    Store(#[from] FilterStoreError),
    /// Block-body or other storage I/O failed.
    #[error("filter index storage error: {0}")]
    Storage(#[source] bitcoin_rs_storage::StorageError),
    /// A required body is not (yet) available; the pass stalls and retries.
    #[error("filter index worker: missing body at height {height}, hash {hash}")]
    MissingBody {
        /// Height of the missing body.
        height: u32,
        /// Hash of the missing body.
        hash: Hash256,
    },
    /// A stored body failed to decode; the body store is inconsistent.
    #[error("filter index worker: block body at height {height} failed to decode")]
    BodyDecode {
        /// Height of the undecodable body.
        height: u32,
    },
    /// The parent's header row is missing, so the header chain cannot extend.
    #[error("filter index worker: parent header row missing before height {height}")]
    MissingParentHeader {
        /// Height of the block whose parent row was missing.
        height: u32,
    },
    /// A spent prevout could not be resolved anywhere; the filter would be
    /// incomplete, so the block is refused rather than mis-indexed.
    #[error("filter index worker: cannot resolve prevout {0} for the basic filter")]
    UnresolvablePrevout(OutPoint),
    /// The active-chain identity for `height` is not resolvable.
    #[error("filter index worker: target chain node missing at height {height}")]
    MissingTargetChain {
        /// Unresolvable height.
        height: u32,
    },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Action {
    /// At least one namespace batch was committed this pass.
    Progressed,
    /// The namespace mirrors the applied tip, or there is no applied tip.
    CaughtUp,
}

/// Identity of one active-chain block, copied under a short tree lock.
struct BlockIdentity {
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
}

/// Bounded recency cache of `txid -> output scripts`, fed by every block the
/// worker walks. Deep prevouts fall through to the transaction-index query.
struct PrevoutWindow {
    entries: hashbrown::HashMap<Txid, Vec<ScriptBuf>>,
    order: VecDeque<Txid>,
    capacity: usize,
}

impl PrevoutWindow {
    const DEFAULT_CAPACITY: usize = 50_000;

    fn new() -> Self {
        Self {
            entries: hashbrown::HashMap::new(),
            order: VecDeque::new(),
            capacity: Self::DEFAULT_CAPACITY,
        }
    }

    fn remember(&mut self, tx: &Transaction) {
        let txid = tx.compute_txid();
        if self.entries.contains_key(&txid) {
            return;
        }
        self.entries.insert(
            txid,
            tx.output
                .iter()
                .map(|output| output.script_pubkey.clone())
                .collect(),
        );
        self.order.push_back(txid);
        while self.order.len() > self.capacity {
            let Some(evicted) = self.order.pop_front() else {
                break;
            };
            self.entries.remove(&evicted);
        }
    }

    fn script_for(&self, outpoint: &OutPoint) -> Option<ScriptBuf> {
        self.entries
            .get(&outpoint.txid)?
            .get(usize::try_from(outpoint.vout).ok()?)
            .cloned()
    }
}

struct Worker {
    runtime: Arc<FilterIndexRuntime>,
    store: Arc<dyn FilterStoreOps>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Arc<dyn PruneBodyStore>,
    tx_lookup: Option<Arc<dyn TxIndexQuery>>,
    chain_events: Arc<crate::state::ChainEventPublisher>,
    wake: Receiver<()>,
    hints: Receiver<crate::state::ChainEventHint>,
    window: PrevoutWindow,
}

impl Worker {
    fn run(mut self) -> Result<(), FilterWorkerError> {
        loop {
            if self.runtime.should_stop() {
                break;
            }
            match self.reconcile_once() {
                Ok(Action::Progressed | Action::CaughtUp) => {
                    if self.wait_for_wake().is_none() {
                        break;
                    }
                }
                Err(FilterWorkerError::Stopped) => break,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    /// Waits for an extension wake, chain-event hint, or the poll tick.
    fn wait_for_wake(&self) -> Option<()> {
        if self.runtime.should_stop() {
            return None;
        }
        crossbeam_channel::select! {
            recv(self.wake) -> message => message.ok(),
            recv(self.hints) -> message => message.ok().map(|_| ()),
            default(POLL_TICK) => Some(()),
        }
    }

    /// One reconciliation pass against the current applied tip.
    fn reconcile_once(&mut self) -> Result<Action, FilterWorkerError> {
        let target = self.applied_tip.load_full();
        let Some(target) = target else {
            return Ok(Action::CaughtUp);
        };
        let pointer = self.store.pointer()?;
        let stored_cursor = self.store.cursor()?;

        match {
            let tree = self.block_tree.read();
            match pointer {
                None => ReconcilePlan::Forward { from_height: 0 },
                Some(pointer) => {
                    let cursor = ConsumerCursor {
                        epoch: stored_cursor.map_or(0, |cursor| cursor.epoch),
                        sequence: stored_cursor.map_or(0, |cursor| cursor.sequence),
                        height: pointer.height,
                        hash: Hash256::from_le_bytes(&pointer.hash),
                    };
                    plan(&cursor, &target, &tree)
                }
            }
        } {
            ReconcilePlan::CaughtUp => {
                if self.commit_caught_up(&target)? {
                    Ok(Action::CaughtUp)
                } else {
                    Ok(Action::Progressed)
                }
            }
            ReconcilePlan::Forward { from_height } => self.forward_to(&target, from_height),
            ReconcilePlan::RollbackAndForward { ancestor_height } => {
                self.rewind_to(&target, ancestor_height)?;
                self.forward_to(&target, ancestor_height.saturating_add(1))
            }
            // The pointer block is absent from the tree (pruned or never
            // seen): rows are hash-addressed and idempotent, so re-derive
            // the whole active chain from genesis.
            ReconcilePlan::Rebuild => self.forward_to(&target, 0),
        }
    }

    /// Rewinds the active pointer and cursor to the common ancestor, retaining rows.
    fn rewind_to(
        &self,
        target: &TipSnapshot,
        ancestor_height: u32,
    ) -> Result<(), FilterWorkerError> {
        let ancestor = self.identity_at(target, ancestor_height)?;
        let snapshot = self.chain_events.snapshot();
        let mut batch = FilterBatch::new();
        batch.put_pointer(ActivePointer {
            height: ancestor.height,
            hash: ancestor.hash,
        });
        batch.put_cursor(&StoredCursor {
            epoch: snapshot.epoch,
            sequence: snapshot.sequence,
            height: ancestor.height,
            hash: ancestor.hash,
        });
        batch.put_state(LifecycleState::Building);
        self.apply_batch(batch)
    }

    /// Connects `from_height..=target.height`, one atomic batch per block.
    fn forward_to(
        &mut self,
        target: &TipSnapshot,
        from_height: u32,
    ) -> Result<Action, FilterWorkerError> {
        let mut height = from_height;
        while height <= target.height {
            if self.runtime.should_stop() {
                return Err(FilterWorkerError::Stopped);
            }
            let identity = self.identity_at(target, height)?;
            let parent_header = if identity.height == 0 {
                zero_filter_header()
            } else {
                self.store.header_row(identity.parent_hash)?.ok_or(
                    FilterWorkerError::MissingParentHeader {
                        height: identity.height,
                    },
                )?
            };

            let hash = Hash256::from_le_bytes(&identity.hash);
            let body = self
                .body_store
                .load_block_body(identity.height, hash)
                .map_err(FilterWorkerError::Storage)?
                .ok_or(FilterWorkerError::MissingBody {
                    height: identity.height,
                    hash,
                })?;
            let block: bitcoin::Block =
                deserialize(&body).map_err(|_| FilterWorkerError::BodyDecode {
                    height: identity.height,
                })?;
            drop(body);

            let filter =
                basic_filter_for_block(&block, |outpoint| self.resolve_prevout(&block, outpoint))
                    .map_err(|error| match error {
                    bitcoin::bip158::Error::UtxoMissing(outpoint) => {
                        FilterWorkerError::UnresolvablePrevout(outpoint)
                    }
                    bitcoin::bip158::Error::Io(io) => {
                        FilterWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(io))
                    }
                    // `bip158::Error` is `#[non_exhaustive]`: route future
                    // variants through the storage-backed error.
                    other => {
                        FilterWorkerError::Storage(bitcoin_rs_storage::StorageError::backend(
                            other,
                        ))
                    }
                })?;
            for tx in &block.txdata {
                self.window.remember(tx);
            }
            let header = filter_header(&filter, &parent_header);

            let snapshot = self.chain_events.snapshot();
            let mut batch = FilterBatch::new();
            batch.put_filter(identity.hash, &filter);
            batch.put_header(identity.hash, header);
            batch.put_pointer(ActivePointer {
                height: identity.height,
                hash: identity.hash,
            });
            batch.put_cursor(&StoredCursor {
                epoch: snapshot.epoch,
                sequence: snapshot.sequence,
                height: identity.height,
                hash: identity.hash,
            });
            batch.put_state(LifecycleState::Building);
            self.apply_batch(batch)?;
            height = identity.height.saturating_add(1);
        }
        Ok(Action::Progressed)
    }

    /// Marks the namespace caught up only when the current publisher snapshot
    /// still names exactly the pointer block. The cursor and lifecycle claim
    /// are committed together, so snapshot drift can only leave Building.
    fn commit_caught_up(&self, target: &TipSnapshot) -> Result<bool, FilterWorkerError> {
        let pointer = self.store.pointer()?;
        let snapshot = self.chain_events.snapshot();
        let matches_target = pointer.is_some_and(|pointer| {
            pointer.height == target.height
                && pointer.hash == target.hash.to_le_bytes()
                && snapshot.tip_height == target.height
                && snapshot.tip_hash == target.hash
        });
        let mut batch = FilterBatch::new();
        if matches_target {
            batch.put_cursor(&StoredCursor {
                epoch: snapshot.epoch,
                sequence: snapshot.sequence,
                height: snapshot.tip_height,
                hash: snapshot.tip_hash.to_le_bytes(),
            });
            batch.put_state(LifecycleState::CaughtUp);
        } else {
            batch.put_state(LifecycleState::Building);
        }
        self.apply_batch(batch)?;
        Ok(matches_target)
    }

    fn apply_batch(&self, batch: FilterBatch) -> Result<(), FilterWorkerError> {
        if batch.is_empty() {
            return Ok(());
        }
        self.store.apply(batch).map_err(FilterWorkerError::from)
    }

    /// Copies one block identity plus its parent hash under a short tree lock.
    fn identity_at(
        &self,
        target: &TipSnapshot,
        height: u32,
    ) -> Result<BlockIdentity, FilterWorkerError> {
        let tree = self.block_tree.read();
        let node_id = tree
            .node_at_height_from(target.tip_id, height)
            .ok_or(FilterWorkerError::MissingTargetChain { height })?;
        let node = tree
            .node(node_id)
            .map_err(|_| FilterWorkerError::MissingTargetChain { height })?;
        let parent_hash = if height == 0 {
            [0_u8; 32]
        } else {
            let parent_id = tree
                .parent_id(node_id)
                .map_err(|_| FilterWorkerError::MissingTargetChain { height })?
                .ok_or(FilterWorkerError::MissingTargetChain { height })?;
            let parent = tree
                .node(parent_id)
                .map_err(|_| FilterWorkerError::MissingTargetChain { height })?;
            parent.hash.to_le_bytes()
        };
        Ok(BlockIdentity {
            height,
            hash: node.hash.to_le_bytes(),
            parent_hash,
        })
    }

    /// Resolves the script of one spent prevout: same block first, then the
    /// recency window, then the transaction-index query.
    fn resolve_prevout(
        &mut self,
        block: &bitcoin::Block,
        outpoint: &OutPoint,
    ) -> Option<ScriptBuf> {
        for tx in &block.txdata {
            if tx.compute_txid() == outpoint.txid {
                return tx
                    .output
                    .get(usize::try_from(outpoint.vout).ok()?)
                    .map(|output| output.script_pubkey.clone());
            }
        }
        if let Some(script) = self.window.script_for(outpoint) {
            return Some(script);
        }
        let native_txid = bitcoin_rs_primitives::Txid::from(Hash256::from_le_bytes(
            outpoint.txid.as_byte_array(),
        ));
        let tx = self
            .tx_lookup
            .as_ref()?
            .transaction(&native_txid)
            .ok()??;
        tx.outputs
            .get(usize::try_from(outpoint.vout).ok()?)
            .map(|output| ScriptBuf::from_bytes(output.script_pubkey.clone()))
    }
}

/// Live status handle for the filter extension instance.
///
/// Implements [`Extension`] so the registry can drive and report the
/// instance; `on_block_*` wake the same runtime the worker polls.
///
/// Readiness is coherent by construction: [`Extension::health`] reports
/// `Ready` only when the lifecycle state, the active pointer, the consumer
/// cursor, and the publisher snapshot all name the applied tip, and any
/// namespace metadata read failure surfaces as
/// [`HealthStatus::Failed`] — never as ordinary catch-up.
pub(crate) struct FilterIndexStatus {
    runtime: Arc<FilterIndexRuntime>,
    store: Arc<dyn FilterStoreOps>,
    applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
    chain_events: Arc<crate::state::ChainEventPublisher>,
}

/// Upper bound for failure reasons surfaced through `HealthStatus::Failed`.
const HEALTH_REASON_LIMIT: usize = 256;

/// Bounds a namespace metadata read-failure reason for the health vocabulary.
fn bounded_health_reason(error: &FilterStoreError) -> String {
    let text = error.to_string();
    if text.chars().count() <= HEALTH_REASON_LIMIT {
        return text;
    }
    let mut bounded: String = text.chars().take(HEALTH_REASON_LIMIT).collect();
    bounded.push('…');
    bounded
}

/// Whether persisted metadata coherently claims the applied tip.
///
/// One coherent chain position means lifecycle `CaughtUp`, pointer and
/// cursor naming the same block, and the publisher snapshot still naming
/// that block as the applied tip. Anything less is catch-up.
fn metadata_claims_tip(
    pointer: Option<ActivePointer>,
    state: Option<LifecycleState>,
    cursor: Option<StoredCursor>,
    applied: Option<&TipSnapshot>,
    snapshot: &crate::state::ChainSnapshot,
) -> bool {
    pointer
        .zip(state)
        .zip(cursor)
        .is_some_and(|((pointer, state), cursor)| {
            state == LifecycleState::CaughtUp
                && cursor.height == pointer.height
                && cursor.hash == pointer.hash
                && applied.is_some_and(|tip| {
                    tip.height == pointer.height
                        && tip.hash.to_le_bytes() == pointer.hash
                        && snapshot.tip_height == tip.height
                        && snapshot.tip_hash == tip.hash
                })
        })
}

impl FilterIndexStatus {
    pub(crate) fn new(
        runtime: Arc<FilterIndexRuntime>,
        store: Arc<dyn FilterStoreOps>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        chain_events: Arc<crate::state::ChainEventPublisher>,
    ) -> Self {
        Self {
            runtime,
            store,
            applied_tip,
            chain_events,
        }
    }

    #[cfg(test)]
    pub(crate) fn runtime(&self) -> Arc<FilterIndexRuntime> {
        Arc::clone(&self.runtime)
    }

    /// Progress report for `getindexinfo`.
    pub(crate) fn info(&self) -> Result<FilterIndexInfo, TxQueryError> {
        if let Some(message) = self.runtime.failure_message() {
            return Err(TxQueryError::Unavailable(message));
        }
        if self.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("filter index stopped".into()));
        }
        let pointer = self
            .store
            .pointer()
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let state = self
            .store
            .state()
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let cursor = self
            .store
            .cursor()
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))?;
        let applied = self.applied_tip.load_full();
        let snapshot = self.chain_events.snapshot();
        let synced = metadata_claims_tip(
            pointer,
            state,
            cursor,
            applied.as_deref(),
            &snapshot,
        );
        Ok(FilterIndexInfo {
            synced,
            best_block_height: pointer.map_or(0, |pointer| pointer.height),
        })
    }
}

impl Extension for FilterIndexStatus {
    fn descriptor(&self) -> &'static ExtensionDescriptor {
        &FILTER_DESCRIPTOR
    }

    fn on_block_connected(&self, _height: u32, _hash: Hash256) {
        self.runtime.wake();
    }

    fn on_block_disconnected(&self, _height: u32, _hash: Hash256) {
        self.runtime.wake();
    }

    fn health(&self) -> HealthStatus {
        if let Some(message) = self.runtime.failure_message() {
            return HealthStatus::Failed {
                reason: message.to_string(),
            };
        }
        // Metadata read failures fail closed: a namespace that cannot be
        // read is a broken extension, not a lagging one.
        let pointer = match self.store.pointer() {
            Ok(pointer) => pointer,
            Err(error) => {
                return HealthStatus::Failed {
                    reason: bounded_health_reason(&error),
                };
            }
        };
        let state = match self.store.state() {
            Ok(state) => state,
            Err(error) => {
                return HealthStatus::Failed {
                    reason: bounded_health_reason(&error),
                };
            }
        };
        let cursor = match self.store.cursor() {
            Ok(cursor) => cursor,
            Err(error) => {
                return HealthStatus::Failed {
                    reason: bounded_health_reason(&error),
                };
            }
        };
        let applied = self.applied_tip.load_full();
        let snapshot = self.chain_events.snapshot();
        if metadata_claims_tip(pointer, state, cursor, applied.as_deref(), &snapshot) {
            HealthStatus::Ready
        } else {
            HealthStatus::CatchingUp {
                processed_height: pointer.map_or(0, |pointer| pointer.height),
                target_height: applied.as_ref().map_or(0, |tip| tip.height),
            }
        }
    }

    fn shutdown(&self) {
        self.runtime.request_shutdown();
    }
}

/// Lockless read adapter serving `getindexinfo` and `getblockfilter`.
pub(crate) struct FilterIndexQueryEngine {
    status: Arc<FilterIndexStatus>,
    store: Arc<dyn FilterStoreOps>,
}

impl FilterIndexQueryEngine {
    pub(crate) fn new(status: Arc<FilterIndexStatus>, store: Arc<dyn FilterStoreOps>) -> Self {
        Self { status, store }
    }

    fn require_live(&self) -> Result<(), TxQueryError> {
        if let Some(message) = self.status.runtime.failure_message() {
            return Err(TxQueryError::Unavailable(message));
        }
        if self.status.runtime.shutdown.load(Ordering::Acquire) {
            return Err(TxQueryError::Unavailable("filter index stopped".into()));
        }
        Ok(())
    }
}

impl FilterIndexQuery for FilterIndexQueryEngine {
    fn filter_info(&self) -> Result<FilterIndexInfo, TxQueryError> {
        self.require_live()?;
        self.status.info()
    }

    fn basic_filter(&self, block_hash: Hash256) -> Result<Option<Vec<u8>>, TxQueryError> {
        self.require_live()?;
        self.store
            .filter_row(block_hash.to_le_bytes())
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))
    }

    fn filter_header(&self, block_hash: Hash256) -> Result<Option<[u8; 32]>, TxQueryError> {
        self.require_live()?;
        self.store
            .header_row(block_hash.to_le_bytes())
            .map_err(|error| TxQueryError::Storage(error.to_string().into()))
    }
}

/// Bundle the node owns for one enabled filter extension instance.
pub(crate) struct FilterIndexHandle {
    /// Live status (also the [`Extension`] instance).
    pub(crate) status: Arc<FilterIndexStatus>,
    /// Spawned worker.
    pub(crate) worker: FilterIndexWorker,
    /// RPC query adapter.
    pub(crate) query: Arc<FilterIndexQueryEngine>,
}

impl FilterIndexHandle {
    /// Shuts the worker down and joins it; used by `NodeState` teardown.
    pub(crate) fn shutdown(self) {
        self.status.shutdown();
        self.worker.join();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::absolute;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::transaction::{Transaction, TxOut, Version};
    use bitcoin::{Amount, Network, ScriptBuf, Sequence, TxIn, Witness};
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_ext_blockfilterindex::FilterOp;
    use bitcoin_rs_storage::StorageError;
    use parking_lot::Mutex;

    use crate::state::{ChainEventPublisher, HintKind};

    /// Fully in-memory namespace double that records every applied batch.
    struct MemStore {
        rows: Mutex<hashbrown::HashMap<Vec<u8>, Vec<u8>>>,
        allowed_writes: std::sync::atomic::AtomicUsize,
        fail_reads: std::sync::atomic::AtomicBool,
    }

    impl MemStore {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                rows: Mutex::new(hashbrown::HashMap::new()),
                allowed_writes: std::sync::atomic::AtomicUsize::new(usize::MAX),
                fail_reads: std::sync::atomic::AtomicBool::new(false),
            })
        }

        fn fail_writes(&self) {
            self.allowed_writes
                .store(0, std::sync::atomic::Ordering::SeqCst);
        }

        fn fail_reads(&self) {
            self.fail_reads
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }

        /// Reads one row, honoring injected metadata read failures.
        fn read(&self, key: &[u8]) -> Result<Option<Vec<u8>>, FilterStoreError> {
            if self.fail_reads.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(FilterStoreError::Storage(StorageError::Backend(
                    "injected read failure".to_owned(),
                )));
            }
            Ok(self.row(key))
        }

        fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.rows.lock().get(key).cloned()
        }
    }

    const POINTER_KEY: &[u8] = &[0x00, b'P'];

    fn decode_pointer(bytes: &[u8]) -> ActivePointer {
        let mut height = [0_u8; 4];
        height.copy_from_slice(&bytes[..4]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes[4..]);
        ActivePointer {
            height: u32::from_le_bytes(height),
            hash,
        }
    }

    impl FilterStoreOps for MemStore {
        fn schema_version(&self) -> Result<Option<u32>, FilterStoreError> {
            Ok(self
                .row(&[0x00, b'V'])
                .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("4 bytes"))))
        }

        fn is_fresh(&self) -> Result<bool, FilterStoreError> {
            Ok(self.rows.lock().is_empty())
        }

        fn apply(&self, batch: FilterBatch) -> Result<(), FilterStoreError> {
            if self
                .allowed_writes
                .load(std::sync::atomic::Ordering::SeqCst)
                == 0
            {
                return Err(FilterStoreError::Storage(StorageError::Backend(
                    "injected write failure".to_owned(),
                )));
            }
            let mut rows = self.rows.lock();
            for op in batch.into_ops() {
                match op {
                    FilterOp::Put { key, value } => {
                        rows.insert(key, value);
                    }
                }
            }
            Ok(())
        }

        fn filter_row(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, FilterStoreError> {
            let mut key = vec![b'f'];
            key.extend_from_slice(&hash);
            Ok(self.row(&key))
        }

        fn header_row(&self, hash: [u8; 32]) -> Result<Option<[u8; 32]>, FilterStoreError> {
            let mut key = vec![b'h'];
            key.extend_from_slice(&hash);
            Ok(self
                .row(&key)
                .map(|bytes| bytes.try_into().expect("32 bytes")))
        }

        fn pointer(&self) -> Result<Option<ActivePointer>, FilterStoreError> {
            Ok(self
                .read(POINTER_KEY)?
                .map(|bytes| decode_pointer(&bytes)))
        }

        fn cursor(&self) -> Result<Option<StoredCursor>, FilterStoreError> {
            Ok(self
                .read(&[0x00, b'C'])?
                .and_then(|bytes| StoredCursor::from_bytes(&bytes)))
        }

        fn state(&self) -> Result<Option<LifecycleState>, FilterStoreError> {
            Ok(self
                .read(&[0x00, b'S'])?
                .and_then(|bytes| LifecycleState::from_u8(bytes[0])))
        }
    }

    /// Body double serving in-memory block bodies.
    struct MapBodyStore {
        bodies: Mutex<hashbrown::HashMap<Hash256, Vec<u8>>>,
    }

    impl MapBodyStore {
        fn new(blocks: &[bitcoin::Block]) -> Arc<Self> {
            let mut bodies = hashbrown::HashMap::new();
            for block in blocks {
                bodies.insert(
                    Hash256::from_le_bytes(block.block_hash().as_byte_array()),
                    bitcoin::consensus::encode::serialize(block),
                );
            }
            Arc::new(Self {
                bodies: Mutex::new(bodies),
            })
        }

        fn clear(&self) {
            self.bodies.lock().clear();
        }
    }

    impl PruneBodyStore for MapBodyStore {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: Hash256,
            _bytes: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            _height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.bodies.lock().get(&hash).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    fn coinbase_child(parent: &bitcoin::Block) -> bitcoin::Block {
        let coinbase = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::from_hex("51").expect("op_true"),
            }],
        };
        let mut block = bitcoin::Block {
            header: parent.header,
            txdata: vec![coinbase],
        };
        block.header.prev_blockhash = parent.block_hash();
        block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
        while block.header.validate_pow(block.header.target()).is_err() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        block
    }

    /// Tree + tip + namespace + bodies fixture over a fixed block list.
    struct Fixture {
        tree: Arc<RwLock<BlockTree>>,
        applied_tip: Arc<arc_swap::ArcSwapOption<TipSnapshot>>,
        chain_events: Arc<ChainEventPublisher>,
        store: Arc<MemStore>,
        bodies: Arc<MapBodyStore>,
        blocks: Vec<bitcoin::Block>,
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    fn fixture(blocks: &[bitcoin::Block]) -> Fixture {
        let mut tree = BlockTree::new();
        let mut parent_id = None;
        for block in blocks {
            let header = bitcoin_rs_primitives::Header::consensus_decode(
                &bitcoin::consensus::serialize(&block.header),
            )
            .expect("decode native header");
            let node_id = tree
                .insert_node(parent_id, header, NodeStatus::Active)
                .expect("insert node");
            parent_id = Some(node_id);
        }
        let tree = Arc::new(RwLock::new(tree));
        let applied_tip = tree.read().tip_handle();
        // Publish the tip snapshot explicitly: insert_node need not write the
        // shared handle, and the worker reconciles against this handle.
        let snapshot = {
            let guard = tree.read();
            let tip_id = parent_id.expect("fixture has a tip");
            let node = guard.node(tip_id).expect("tip node");
            TipSnapshot {
                tip_id,
                height: node.height,
                chainwork: node.chainwork,
                hash: node.hash,
            }
        };
        applied_tip.store(Some(Arc::new(snapshot.clone())));
        let (publisher, _hints) = ChainEventPublisher::detached(1);
        publisher.record(HintKind::Connected, snapshot.height, snapshot.hash);
        let chain_events = Arc::new(publisher);
        Fixture {
            tree,
            applied_tip,
            chain_events,
            store: MemStore::new(),
            bodies: MapBodyStore::new(blocks),
            blocks: blocks.to_vec(),
        }
    }

    impl Fixture {
        /// Moves the applied tip and the publisher snapshot together, the
        /// way the committed apply path publishes both.
        fn advance_tip_to(&self, height: u32) {
            let target = snapshot_for(self, height);
            let tip = Arc::new(target);
            self.applied_tip.store(Some(Arc::clone(&tip)));
            self.chain_events
                .record(HintKind::Connected, tip.height, tip.hash);
        }

        /// Moves only the publisher snapshot: the drift a tip change
        /// between planning and a caught-up commit produces.
        fn drift_publisher(&self) {
            let genesis = snapshot_for(self, 0);
            self.chain_events
                .record(HintKind::Disconnected, genesis.height, genesis.hash);
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    fn snapshot_for(fixture: &Fixture, height: u32) -> TipSnapshot {
        let guard = fixture.tree.read();
        let block = fixture
            .blocks
            .get(usize::try_from(height).expect("height fits usize"))
            .expect("fixture block at height");
        let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let node_id = guard.lookup(hash).expect("active node");
        let node = guard.node(node_id).expect("node");
        TipSnapshot {
            tip_id: node_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        }
    }

    fn worker_for(fixture: &Fixture) -> Worker {
        // The worker under test is driven synchronously; the runtime wake
        // channel is exercised only through FilterIndexStatus.
        let (wake_tx, wake_rx) = crossbeam_channel::bounded::<()>(1);
        let runtime = Arc::new(FilterIndexRuntime::new(wake_tx));
        let (_hint_tx, hint_rx) = crossbeam_channel::unbounded::<crate::state::ChainEventHint>();
        Worker {
            runtime,
            store: fixture.store.clone(),
            applied_tip: Arc::clone(&fixture.applied_tip),
            block_tree: Arc::clone(&fixture.tree),
            body_store: fixture.bodies.clone(),
            tx_lookup: None,
            chain_events: Arc::clone(&fixture.chain_events),
            wake: wake_rx,
            hints: hint_rx,
            window: PrevoutWindow::new(),
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn worker_indexes_genesis_then_child_with_retained_rows() {
        let genesis = genesis_block(Network::Regtest);
        let child = coinbase_child(&genesis);
        let fixture = fixture(&[genesis, child.clone()]);
        let mut worker = worker_for(&fixture);

        // Tip at genesis: fresh namespace indexes height 0 only.
        fixture.advance_tip_to(0);
        assert_eq!(
            worker.reconcile_once().expect("genesis pass"),
            Action::Progressed
        );
        assert_eq!(
            worker.reconcile_once().expect("caught-up pass"),
            Action::CaughtUp
        );
        let genesis_block_hash = fixture.blocks[0].block_hash();
        let genesis_hash = genesis_block_hash.as_byte_array();
        assert!(
            fixture
                .store
                .filter_row(*genesis_hash)
                .expect("row")
                .is_some()
        );
        assert_eq!(
            fixture.store.pointer().expect("pointer"),
            Some(ActivePointer {
                height: 0,
                hash: *genesis_hash,
            })
        );

        // Advance the tip to the child: the pointer follows, rows stay.
        fixture.advance_tip_to(1);
        assert_eq!(
            worker.reconcile_once().expect("child pass"),
            Action::Progressed
        );
        assert_eq!(
            worker.reconcile_once().expect("caught-up pass"),
            Action::CaughtUp
        );
        let child_block_hash = child.block_hash();
        let child_hash = child_block_hash.as_byte_array();
        assert_eq!(
            fixture.store.pointer().expect("pointer"),
            Some(ActivePointer {
                height: 1,
                hash: *child_hash,
            })
        );
        assert!(
            fixture
                .store
                .filter_row(*genesis_hash)
                .expect("retained")
                .is_some()
        );
        assert!(
            fixture
                .store
                .filter_row(*child_hash)
                .expect("new")
                .is_some()
        );
        let cursor = fixture.store.cursor().expect("cursor");
        assert!(cursor.is_some(), "caught-up pass must persist the cursor");
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn forward_persists_cursor_before_caught_up_completes() {
        let genesis = genesis_block(Network::Regtest);
        let child = coinbase_child(&genesis);
        let fixture = fixture(&[genesis, child.clone()]);
        let mut worker = worker_for(&fixture);

        // One committed forward transition, then a reopen before the
        // caught-up pass ever runs: exactly the crash window the per-block
        // batch must survive on its own.
        fixture.advance_tip_to(1);
        assert_eq!(
            worker.reconcile_once().expect("forward pass"),
            Action::Progressed
        );
        drop(worker);

        // Reopen: fresh reads of the persisted namespace must already see
        // one coherent position — rows, pointer, cursor, and lifecycle
        // state written by the same batch for the same block.
        let genesis_block_hash = fixture.blocks[0].block_hash();
        let genesis_hash = genesis_block_hash.as_byte_array();
        let child_block_hash = child.block_hash();
        let child_hash = child_block_hash.as_byte_array();
        assert!(
            fixture
                .store
                .filter_row(*child_hash)
                .expect("row")
                .is_some()
        );
        assert_eq!(
            fixture.store.pointer().expect("pointer"),
            Some(ActivePointer {
                height: 1,
                hash: *child_hash,
            })
        );
        assert_eq!(
            fixture.store.state().expect("state"),
            Some(LifecycleState::Building),
            "a reopen before caught-up completion must stay Building"
        );
        let cursor = fixture
            .store
            .cursor()
            .expect("cursor")
            .expect("forward batch must persist the cursor before any caught-up pass");
        assert_eq!(cursor.height, 1);
        assert_eq!(cursor.hash, *child_hash);
        assert_ne!(cursor.hash, *genesis_hash);
        let snapshot = fixture.chain_events.snapshot();
        assert_eq!(cursor.epoch, snapshot.epoch);
        assert_eq!(
            cursor.sequence, snapshot.sequence,
            "cursor carries the chain-event snapshot's epoch and sequence"
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn rewind_keeps_hash_addressed_rows() {
        let genesis = genesis_block(Network::Regtest);
        let fixture = fixture(&[genesis]);
        let mut worker = worker_for(&fixture);

        let target = snapshot_for(&fixture, 0);
        let _ = worker.reconcile_once().expect("index genesis");
        worker.rewind_to(&target, 0).expect("rewind");

        let genesis_block_hash = fixture.blocks[0].block_hash();
        let genesis_hash = genesis_block_hash.as_byte_array();
        assert_eq!(
            fixture.store.pointer().expect("pointer"),
            Some(ActivePointer {
                height: 0,
                hash: *genesis_hash,
            })
        );
        assert!(
            fixture
                .store
                .filter_row(*genesis_hash)
                .expect("retained")
                .is_some()
        );
        assert_eq!(
            fixture.store.state().expect("state"),
            Some(LifecycleState::Building)
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn missing_body_fails_the_pass_without_touching_the_pointer() {
        let genesis = genesis_block(Network::Regtest);
        let fixture = fixture(&[genesis]);
        fixture.bodies.clear();
        let mut worker = worker_for(&fixture);

        let error = worker
            .reconcile_once()
            .expect_err("missing body surfaces as error");
        assert!(matches!(
            error,
            FilterWorkerError::MissingBody { height: 0, .. }
        ));
        assert_eq!(fixture.store.pointer().expect("pointer"), None);
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn store_write_failure_is_reported_not_swallowed() {
        let genesis = genesis_block(Network::Regtest);
        let fixture = fixture(&[genesis]);
        fixture.store.fail_writes();
        let mut worker = worker_for(&fixture);

        let error = worker.reconcile_once().expect_err("injected failure");
        assert!(matches!(error, FilterWorkerError::Store(_)));
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn extension_health_reports_catchup_then_ready() {
        let genesis = genesis_block(Network::Regtest);
        let fixture = fixture(&[genesis]);
        let mut worker = worker_for(&fixture);
        let status = FilterIndexStatus::new(
            Arc::clone(&worker.runtime),
            Arc::clone(&fixture.store) as Arc<dyn FilterStoreOps>,
            Arc::clone(&fixture.applied_tip),
            Arc::clone(&fixture.chain_events),
        );

        assert!(matches!(
            status.health(),
            HealthStatus::CatchingUp {
                processed_height: 0,
                ..
            }
        ));

        let _ = worker.reconcile_once().expect("index");
        let target = fixture.applied_tip.load_full();
        assert!(
            worker
                .commit_caught_up(target.as_deref().expect("tip"))
                .expect("caught up"),
            "coherent snapshot must commit CaughtUp"
        );
        assert_eq!(status.health(), HealthStatus::Ready);
        assert!(status.info().expect("info").synced);

        status.shutdown();
        assert!(status.runtime().should_stop());
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn rewind_persists_one_coherent_position_immediately() {
        let genesis = genesis_block(Network::Regtest);
        let child = coinbase_child(&genesis);
        let fixture = fixture(&[genesis, child.clone()]);
        let mut worker = worker_for(&fixture);

        fixture.advance_tip_to(1);
        assert_eq!(
            worker.reconcile_once().expect("genesis and child pass"),
            Action::Progressed
        );
        assert_eq!(
            worker.reconcile_once().expect("caught-up pass"),
            Action::CaughtUp
        );

        // Reorg back to genesis: the rewind batch must move the pointer, the
        // cursor, and the lifecycle state together, so a crash right here
        // reopens at the ancestor, never at the disconnected tip.
        let target = snapshot_for(&fixture, 1);
        worker.rewind_to(&target, 0).expect("rewind");

        // Reopen: fresh reads of the persisted namespace see one position.
        let genesis_block_hash = fixture.blocks[0].block_hash();
        let genesis_hash = genesis_block_hash.as_byte_array();
        let child_block_hash = child.block_hash();
        let child_hash = child_block_hash.as_byte_array();
        assert_eq!(
            fixture.store.pointer().expect("pointer"),
            Some(ActivePointer {
                height: 0,
                hash: *genesis_hash,
            })
        );
        let cursor = fixture
            .store
            .cursor()
            .expect("cursor")
            .expect("rewind must persist the ancestor cursor");
        assert_eq!(cursor.height, 0);
        assert_eq!(cursor.hash, *genesis_hash);
        assert_ne!(cursor.hash, *child_hash);
        assert_eq!(
            fixture.store.state().expect("state"),
            Some(LifecycleState::Building)
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn snapshot_drift_leaves_caught_up_uncommitted() {
        let genesis = genesis_block(Network::Regtest);
        let child = coinbase_child(&genesis);
        let fixture = fixture(&[genesis, child.clone()]);
        let mut worker = worker_for(&fixture);

        fixture.advance_tip_to(1);
        assert_eq!(
            worker.reconcile_once().expect("genesis and child pass"),
            Action::Progressed
        );

        // The publisher snapshot moved off the reconciliation target while
        // the pointer names the target: the CaughtUp claim must not commit.
        fixture.drift_publisher();
        assert_eq!(
            worker.reconcile_once().expect("drifted caught-up pass"),
            Action::Progressed,
            "snapshot drift must leave the namespace Building"
        );
        assert_eq!(
            fixture.store.state().expect("state"),
            Some(LifecycleState::Building)
        );

        // Once the snapshot re-coheres, the same pass commits the cursor and
        // the CaughtUp claim in one batch.
        fixture.advance_tip_to(1);
        assert_eq!(
            worker.reconcile_once().expect("coherent caught-up pass"),
            Action::CaughtUp
        );
        assert_eq!(
            fixture.store.state().expect("state"),
            Some(LifecycleState::CaughtUp)
        );
        let child_block_hash = child.block_hash();
        let child_hash = child_block_hash.as_byte_array();
        let cursor = fixture
            .store
            .cursor()
            .expect("cursor")
            .expect("caught-up commit persists the cursor");
        assert_eq!(cursor.height, 1);
        assert_eq!(cursor.hash, *child_hash);
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn metadata_read_failure_reports_failed_health() {
        let genesis = genesis_block(Network::Regtest);
        let fixture = fixture(&[genesis]);
        let mut worker = worker_for(&fixture);
        let status = FilterIndexStatus::new(
            Arc::clone(&worker.runtime),
            Arc::clone(&fixture.store) as Arc<dyn FilterStoreOps>,
            Arc::clone(&fixture.applied_tip),
            Arc::clone(&fixture.chain_events),
        );

        let _ = worker.reconcile_once().expect("index genesis");
        let target = fixture.applied_tip.load_full();
        assert!(
            worker
                .commit_caught_up(target.as_deref().expect("tip"))
                .expect("caught up"),
            "coherent snapshot must commit CaughtUp"
        );
        assert_eq!(status.health(), HealthStatus::Ready);

        fixture.store.fail_reads();
        let reason = match status.health() {
            HealthStatus::Failed { reason } => reason,
            other => panic!("metadata read failure must report Failed, got {other:?}"),
        };
        assert!(
            reason.contains("injected read failure"),
            "reason must name the storage fault: {reason}"
        );
        assert!(
            reason.chars().count() <= HEALTH_REASON_LIMIT,
            "health reasons must stay bounded"
        );
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn prevout_window_resolves_spent_scripts() {
        let genesis = genesis_block(Network::Regtest);
        let mut window = PrevoutWindow::new();
        for tx in &genesis.txdata {
            window.remember(tx);
        }
        let outpoint = OutPoint {
            txid: genesis.txdata[0].compute_txid(),
            vout: 0,
        };
        let script = window.script_for(&outpoint).expect("windowed script");
        assert_eq!(script, genesis.txdata[0].output[0].script_pubkey);

        let missing = window.script_for(&OutPoint {
            txid: genesis.txdata[0].compute_txid(),
            vout: 9,
        });
        assert!(missing.is_none());
    }
}
