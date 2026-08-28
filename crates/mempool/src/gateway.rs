//! The single mutation gateway in front of the mempool.
//!
//! Every production mempool mutation routes through [`MempoolGateway`]: it
//! owns the pool's write lock, commits the mutation, and then publishes the
//! ordered [`MutationResult`] to the optional [`MempoolObserver`] — always in
//! commit order, by construction. After this, no production code outside the
//! gateway takes the mempool write lock — lookups go through the
//! [`MempoolGateway::read`] passthrough.

use alloc::sync::Arc;

use bitcoin_rs_primitives::{Tx, Txid};
use hashbrown::HashSet;
use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

use crate::EntryId;
use crate::entry::MempoolEntry;
use crate::mutation::MutationResult;
use crate::pool::{Mempool, MempoolError, PrioritiseError};
use crate::rbf::{RbfError, ReplacementCandidate};

/// Receives every committed mempool mutation, in commit order.
///
/// Observers are best-effort mirrors: they run after the mutation is already
/// committed, so their failures never affect pool state, and a panic in
/// `on_mutation` is contained by the gateway. They must never route
/// mutations back through the gateway (or otherwise take the mempool write
/// lock): the next queued mutation holds that write lock while waiting for
/// the publish mutex, so a re-entrant call can deadlock.
pub trait MempoolObserver: Send + Sync {
    /// Called once per committed, non-empty [`MutationResult`].
    fn on_mutation(&self, result: &MutationResult);
}

/// Owns the mempool's write lock and publishes ordered mutation events.
///
/// # Ordering invariant
///
/// Every mutating method flows through exactly one path, [`Self::commit`],
/// which runs, in this exact order:
///
/// 1. take the pool write lock,
/// 2. mutate and assign per-change mempool sequences,
/// 3. acquire the publish mutex while still holding the write lock,
/// 4. drop the write lock,
/// 5. call the observer under the publish mutex,
/// 6. release the publish mutex.
///
/// Taking the publish mutex before the write lock is released (step 3 before
/// step 4) makes the write lock serialize publish acquisitions: mutations
/// commit one at a time under the write lock, so their publish acquisitions
/// are totally ordered the same way, and an observer can never see a
/// later-committed batch before — or interleaved with — an earlier one.
/// The write lock is never held across an observer call itself (step 4
/// precedes step 5), but the next queued mutation waits for the publish
/// mutex under the write lock, so a slow or blocked observer delays later
/// publications and their completion. It can never roll anything back or
/// reorder the stream. Sequences were all assigned inside step 2, so an
/// observer that lags still sees a gap-free, ordered stream. Observer
/// errors and panics never affect the committed mutation.
pub struct MempoolGateway {
    pool: Arc<RwLock<Mempool>>,
    observer: Option<Arc<dyn MempoolObserver>>,
    publish: Mutex<()>,
}

impl core::fmt::Debug for MempoolGateway {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MempoolGateway")
            .field("pool", &self.pool)
            .field("observer", &self.observer.as_ref().map(|_| "installed"))
            .finish_non_exhaustive()
    }
}

impl MempoolGateway {
    /// Wraps `pool` and optionally installs `observer`.
    ///
    /// Pass `None` — or use the node's no-op publisher behind its observer —
    /// when no `--zmq-pub-sequence` endpoint is configured.
    #[must_use]
    pub fn new(pool: Arc<RwLock<Mempool>>, observer: Option<Arc<dyn MempoolObserver>>) -> Self {
        Self {
            pool,
            observer,
            publish: Mutex::new(()),
        }
    }

    /// Read passthrough for lookup callers. Never mutate through this guard:
    /// mutations must go through the gateway so observers stay in the loop.
    pub fn read(&self) -> RwLockReadGuard<'_, Mempool> {
        self.pool.read()
    }

    /// Commits `pool.insert_entry` and publishes its result.
    pub fn insert_entry(&self, entry: MempoolEntry) -> Result<MutationResult, MempoolError> {
        self.commit(move |pool| pool.insert_entry(entry))
    }

    /// Reconsiders transactions that left the pool with a disconnected block.
    ///
    /// `entries` must arrive in dependency order — parents before the
    /// transactions spending them — which is the order the reversed
    /// disconnect walk produces. Each candidate gets exactly one
    /// commit-and-publish insert; a candidate the pool refuses is recorded,
    /// and any later candidate spending a refused txid is withheld, so a
    /// rejected parent can never leave a partially admitted family behind.
    /// The same withholding follows a parent whose own successful insert
    /// removed it again — size-limit eviction, for example — because a
    /// parent is available to descendants only while it remains in the
    /// pool: every `Removed` change a committed insert reports marks that
    /// txid unavailable to the rest of the batch. An empty iterator is a
    /// no-op: nothing is committed, nothing is published, and the mempool
    /// sequence does not move.
    pub fn reconsider_disconnected(
        &self,
        entries: impl IntoIterator<Item = MempoolEntry>,
    ) -> Vec<MutationResult> {
        let mut refused: HashSet<Txid> = HashSet::new();
        let mut committed = Vec::new();
        for entry in entries {
            let txid = entry.txid;
            let spends_refused = entry
                .tx
                .inputs
                .iter()
                .any(|input| refused.contains(&input.previous_output.txid));
            if spends_refused {
                refused.insert(txid);
                continue;
            }
            match self.insert_entry(entry) {
                Ok(result) => {
                    // A successful insert does not promise the entry stayed:
                    // the same commit can evict it — or any other entry —
                    // under size pressure. Whatever the result says left the
                    // pool is unavailable to later spenders, exactly as if
                    // the pool had refused it up front.
                    for removed in result.removed_txids() {
                        refused.insert(removed);
                    }
                    committed.push(result);
                }
                Err(_) => {
                    refused.insert(txid);
                }
            }
        }
        committed
    }

    /// Commits `pool.replace_transaction` and publishes its result.
    pub fn replace_transaction(
        &self,
        candidate: ReplacementCandidate,
        time: u64,
        height: u32,
        sigop_cost: u32,
    ) -> Result<MutationResult, RbfError> {
        self.commit(move |pool| pool.replace_transaction(candidate, time, height, sigop_cost))
    }

    /// Commits `pool.remove_entry_and_descendants` and publishes its result.
    pub fn remove_entry_and_descendants(&self, id: EntryId) -> MutationResult {
        self.commit_infallible(|pool| pool.remove_entry_and_descendants(id))
    }

    /// Commits `pool.remove_by_txid` and publishes its result.
    pub fn remove_by_txid(&self, txid: &Txid) -> MutationResult {
        self.commit_infallible(|pool| pool.remove_by_txid(txid))
    }

    /// Commits `pool.remove_for_block` and publishes its result.
    pub fn remove_for_block(
        &self,
        block_txs: &[&Tx],
        block_txids: &[Txid],
        height: u32,
    ) -> MutationResult {
        self.commit_infallible(|pool| pool.remove_for_block(block_txs, block_txids, height))
    }

    /// Commits `pool.evict_below_fee_rate` and publishes its result.
    pub fn evict_below_fee_rate(&self, threshold_sat_per_kvb: u64) -> MutationResult {
        self.commit_infallible(|pool| pool.evict_below_fee_rate(threshold_sat_per_kvb))
    }

    /// Commits `pool.enforce_size_limit` and publishes its result.
    pub fn enforce_size_limit(&self, max_bytes: u64) -> MutationResult {
        self.commit_infallible(|pool| pool.enforce_size_limit(max_bytes))
    }

    /// Commits `pool.clear` and publishes its result.
    pub fn clear(&self) -> MutationResult {
        self.commit_infallible(Mempool::clear)
    }

    /// Commits `pool.prioritise`. Never publishes: prioritisation emits no
    /// mutation change, so there is nothing to order.
    pub fn prioritise(&self, txid: Txid, fee_delta: i64) -> Result<(), PrioritiseError> {
        let mut pool = self.pool.write();
        pool.prioritise(txid, fee_delta)
    }

    /// The single commit-and-publish path every mutating method flows
    /// through. Guard scoping enforces the ordering invariant by
    /// construction: the publish mutex is locked while the write guard is
    /// still alive, and the write guard drops — reverse declaration order —
    /// before the observer runs under the still-held publish guard. A failed
    /// `mutate` returns before the publish mutex is ever taken.
    fn commit<E>(
        &self,
        mutate: impl FnOnce(&mut Mempool) -> Result<MutationResult, E>,
    ) -> Result<MutationResult, E> {
        let (result, publish) = {
            let mut pool = self.pool.write();
            let result = mutate(&mut pool)?;
            let publish = self.publish.lock();
            (result, publish)
        };
        self.publish(&result, publish);
        Ok(result)
    }

    /// The same path for pool methods that cannot fail.
    fn commit_infallible(
        &self,
        mutate: impl FnOnce(&mut Mempool) -> MutationResult,
    ) -> MutationResult {
        let Ok(result) = self.commit(|pool| Ok::<_, core::convert::Infallible>(mutate(pool)));
        result
    }

    /// Invokes the observer for a committed, non-empty result while
    /// `publish` — acquired inside [`Self::commit`] before the write lock
    /// was released — is still held. Empty results publish nothing. A
    /// panicking observer is contained: the mutation already committed, and
    /// the panic must not take the caller down with it. The default panic
    /// hook still prints the panic before it is caught here.
    fn publish(&self, result: &MutationResult, _publish: MutexGuard<'_, ()>) {
        if result.changes.is_empty() {
            return;
        }
        let Some(observer) = &self.observer else {
            return;
        };
        let outcome = std::panic::catch_unwind(core::panic::AssertUnwindSafe(|| {
            observer.on_mutation(result);
        }));
        if let Err(panic_payload) = outcome {
            let message = panic_payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| {
                    panic_payload
                        .downcast_ref::<&str>()
                        .map(|message| (*message).to_string())
                })
                .unwrap_or_else(|| "non-string panic payload".to_owned());
            tracing::warn!(
                message = %message,
                "mempool observer panicked; the committed mutation stands"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{MempoolGateway, MempoolObserver};
    use crate::mutation::{MutationOutcome, MutationResult, RemovalReason};
    use crate::{Mempool, MempoolEntry, MempoolLimits};
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use parking_lot::{Mutex, RwLock};

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Vec::new(),
                sequence: 0xFFFF_FFFF,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51, label],
            }],
        }
    }

    fn entry(tx: &Tx) -> MempoolEntry {
        MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7)
    }

    fn hash(txid: &Txid) -> Hash256 {
        Hash256::from_le_bytes(txid.as_bytes())
    }

    /// Records the txid and outcome of every change the observer sees.
    #[derive(Default)]
    struct RecordingObserver {
        seen: Mutex<Vec<(Hash256, MutationOutcome)>>,
    }

    impl MempoolObserver for RecordingObserver {
        fn on_mutation(&self, result: &MutationResult) {
            let mut seen = self.seen.lock();
            for change in &result.changes {
                seen.push((change.txid, change.outcome));
            }
        }
    }

    struct PanickingObserver;

    impl MempoolObserver for PanickingObserver {
        fn on_mutation(&self, _result: &MutationResult) {
            panic!("observer exploded");
        }
    }

    fn gateway_with(observer: Option<Arc<dyn MempoolObserver>>) -> MempoolGateway {
        MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            observer,
        )
    }

    /// Clones a concrete observer as its trait object without an `as` cast.
    fn dyn_observer<T: MempoolObserver + 'static>(observer: &Arc<T>) -> Arc<dyn MempoolObserver> {
        observer.clone()
    }

    fn removed(reason: RemovalReason) -> MutationOutcome {
        MutationOutcome::Removed(reason)
    }

    #[test]
    fn accepted_and_removed_events_arrive_in_commit_order() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let parent = tx(1);
        let parent_txid = parent.txid();
        let mut child = tx(2);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        gateway.insert_entry(entry(&parent)).expect("parent in");
        gateway.insert_entry(entry(&child)).expect("child in");
        gateway.remove_by_txid(&parent_txid);

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![
                (hash(&parent_txid), MutationOutcome::Accepted),
                (hash(&child.txid()), MutationOutcome::Accepted),
                (hash(&parent_txid), removed(RemovalReason::Explicit)),
                // The child sweeps with its parent, after it.
                (hash(&child.txid()), removed(RemovalReason::Explicit)),
            ],
            "one event per change, in commit order"
        );
    }

    #[test]
    fn remove_for_block_reports_block_inclusion_not_explicit() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let mined = tx(3);
        let mined_txid = mined.txid();
        gateway.insert_entry(entry(&mined)).expect("in");
        observer.seen.lock().clear();
        gateway.remove_for_block(&[&mined], &[mined_txid], 8);

        let seen = observer.seen.lock();
        assert_eq!(
            *seen,
            vec![(hash(&mined_txid), removed(RemovalReason::BlockInclusion))],
        );
    }

    #[test]
    fn failed_insert_and_noop_remove_publish_nothing() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));
        let before = gateway.read().sequence_number();

        // Below the default min-relay floor (1_000 sat/kvB): rejected before
        // any commit.
        let poor = MempoolEntry::new(Arc::new(tx(4)), 100, 50, 1, 7);
        assert!(gateway.insert_entry(poor).is_err());
        let stranger = tx(5);
        gateway.remove_by_txid(&stranger.txid());
        gateway.clear();

        assert!(observer.seen.lock().is_empty());
        assert_eq!(
            gateway.read().sequence_number(),
            before,
            "no change may move the sequence"
        );
    }

    #[test]
    fn replacement_tags_direct_conflicts_and_descendants() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let parent = tx(6);
        let parent_txid = parent.txid();
        gateway.insert_entry(entry(&parent)).expect("parent in");
        let mut child = tx(7);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        child.inputs[0].sequence = 0xFFFF_FFFD;
        let child_txid = child.txid();
        gateway.insert_entry(entry(&child)).expect("child in");
        let mut grandchild = tx(8);
        grandchild.inputs[0].previous_output = OutPoint::new(child_txid, 0);
        grandchild.inputs[0].sequence = 0xFFFF_FFFD;
        let grandchild_txid = grandchild.txid();
        gateway
            .insert_entry(entry(&grandchild))
            .expect("grandchild in");
        observer.seen.lock().clear();

        // The replacement double-spends the child's input, so the child is
        // the direct conflict (Replaced) and the grandchild sweeps with it
        // (Descendant). The parent survives.
        let mut replacement = tx(9);
        replacement.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        replacement.inputs[0].sequence = 0xFFFF_FFFD;
        let replacement_txid = replacement.txid();
        let result = gateway
            .replace_transaction(
                crate::ReplacementCandidate::new(Arc::new(replacement), 100, 5_000, 1),
                1,
                7,
                0,
            )
            .expect("replacement lands");

        assert_eq!(result.changes.len(), 3);
        assert_eq!(
            result.changes,
            vec![
                crate::mutation::change(&child_txid, removed(RemovalReason::Replaced)),
                crate::mutation::change(&grandchild_txid, removed(RemovalReason::Descendant),),
                crate::mutation::change(&replacement_txid, MutationOutcome::Accepted),
            ],
            "conflicts first (parent before descendant), then the replacement"
        );
        let seen = observer.seen.lock();
        assert_eq!(
            &*seen,
            &result
                .changes
                .iter()
                .map(|c| (c.txid, c.outcome))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn observer_panic_does_not_roll_back_the_mutation() {
        let gateway = gateway_with(Some(Arc::new(PanickingObserver)));

        let committed = tx(9);
        let committed_txid = committed.txid();
        gateway
            .insert_entry(entry(&committed))
            .expect("still returns");

        assert!(
            gateway.read().contains_txid(&committed_txid),
            "the mutation stands after the observer panicked"
        );
    }

    #[test]
    fn no_observer_still_mutates() {
        let gateway = gateway_with(None);
        let result = gateway.insert_entry(entry(&tx(10))).expect("in");
        assert_eq!(result.changes.len(), 1);
        assert_eq!(result.sequence_base, 1);
        assert_eq!(gateway.read().sequence_number(), 1);
    }

    #[test]
    fn sequence_base_matches_per_change_assignment() {
        let gateway = gateway_with(None);
        let parent = tx(11);
        let parent_txid = parent.txid();
        let mut child = tx(12);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        gateway.insert_entry(entry(&parent)).expect("in");
        gateway.insert_entry(entry(&child)).expect("in");
        let removed = gateway.remove_by_txid(&parent_txid);

        assert_eq!(removed.changes.len(), 2);
        assert_eq!(removed.sequence_base, 3);
        assert_eq!(removed.sequence_of(0), Some(3));
        assert_eq!(removed.sequence_of(1), Some(4));
        assert_eq!(gateway.read().sequence_number(), 4);
    }

    #[test]
    fn insert_reports_accepted_then_policy_evictions() {
        let observer = Arc::new(RecordingObserver::default());
        // 150-byte budget, 100 vbyte entries at 0 min-relay: the second
        // insert overflows and evicts the lowest-fee package.
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: 150,
                ..MempoolLimits::default()
            }))),
            Some(dyn_observer(&observer)),
        );

        let low = MempoolEntry::new(Arc::new(tx(13)), 100, 100, 1, 7);
        let high = MempoolEntry::new(Arc::new(tx(14)), 100, 900, 1, 7);
        gateway.insert_entry(low).expect("low in");
        let result = gateway.insert_entry(high).expect("high in");

        assert_eq!(
            result.changes.len(),
            2,
            "the eviction is part of the insert"
        );
        assert_eq!(result.changes[0].outcome, MutationOutcome::Accepted);
        assert_eq!(result.changes[0].txid, hash(&tx(14).txid()));
        assert_eq!(
            result.changes[1].outcome,
            MutationOutcome::Removed(RemovalReason::PolicyEviction)
        );
        assert_eq!(result.changes[1].txid, hash(&tx(13).txid()));
        // Sequences are contiguous across the batch and assigned in order.
        assert_eq!(result.sequence_base, 2);
        assert_eq!(result.sequence_of(1), Some(3));
        assert!(
            observer.seen.lock().ends_with(
                &result
                    .changes
                    .iter()
                    .map(|change| (change.txid, change.outcome))
                    .collect::<Vec<_>>()
            )
        );
    }

    #[test]
    fn clear_reports_every_entry_and_empty_clear_moves_nothing() {
        let gateway = gateway_with(None);
        let first = tx(15);
        let second = tx(16);
        gateway.insert_entry(entry(&first)).expect("in");
        gateway.insert_entry(entry(&second)).expect("in");
        let before = gateway.read().sequence_number();

        let cleared = gateway.clear();
        assert_eq!(cleared.changes.len(), 2);
        assert!(
            cleared
                .changes
                .iter()
                .all(|change| { change.outcome == MutationOutcome::Removed(RemovalReason::Clear) })
        );
        assert_eq!(cleared.sequence_base, before + 1);
        assert_eq!(gateway.read().sequence_number(), before + 2);

        let empty = gateway.clear();
        assert!(empty.is_empty());
        assert_eq!(empty.sequence_base, 0);
        assert_eq!(
            gateway.read().sequence_number(),
            before + 2,
            "clear-on-empty assigns nothing"
        );
    }

    /// A test observer whose first `on_mutation` records the batch and then
    /// blocks until released.
    struct GatedObserver {
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
        stream: Mutex<Vec<u64>>,
    }

    impl MempoolObserver for GatedObserver {
        fn on_mutation(&self, result: &MutationResult) {
            let mut stream = self.stream.lock();
            let first_call = stream.is_empty();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
            drop(stream);
            if first_call {
                self.entered
                    .lock()
                    .take()
                    .expect("entered sender armed once")
                    .send(())
                    .expect("main thread still waiting");
                self.release
                    .lock()
                    .take()
                    .expect("release receiver armed once")
                    .recv()
                    .expect("main thread still alive to release us");
            }
        }
    }

    /// Pins the observable signature of the ordering invariant. While the
    /// first observer call is gated on the publish mutex, the next
    /// mutation's `commit` has already taken the write lock and parks on
    /// the publish mutex while still holding it — so a `try_read` on the
    /// pool fails for as long as the gate is closed. Under the old
    /// release-the-write-lock-then-take-the-publish-mutex shape the write
    /// lock was free here, and this test fails at the engagement check.
    /// After the gate opens, the queued batch publishes next: publish order
    /// matches sequence order, and both mutations are in the pool.
    #[test]
    fn gated_observer_pins_the_write_lock_and_keeps_publish_order() {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let observer = Arc::new(GatedObserver {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
        });
        let gateway = Arc::new(MempoolGateway::new(
            Arc::clone(&pool),
            Some(dyn_observer(&observer)),
        ));

        let first_txid = tx(20).txid();
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || first.insert_entry(entry(&tx(20))).expect("first in"));
        entered_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("first observer call started");

        let second_txid = tx(21).txid();
        let second = Arc::clone(&gateway);
        let second_handle =
            std::thread::spawn(move || second.insert_entry(entry(&tx(21))).expect("second in"));

        // Wait until the second mutation has engaged: it holds the write
        // lock while parked on the publish mutex behind the gated observer.
        // `try_read` failing continuously for 50ms — far longer than any
        // in-lock mutation work — proves the hold is the gate, not a window.
        let engaged = std::time::Instant::now() + core::time::Duration::from_secs(10);
        loop {
            if pool.try_read().is_none() {
                let since = std::time::Instant::now();
                while since.elapsed() < core::time::Duration::from_millis(50) {
                    assert!(
                        pool.try_read().is_none(),
                        "write lock freed while the observer is still gated"
                    );
                    std::thread::sleep(core::time::Duration::from_millis(1));
                }
                break;
            }
            assert!(
                std::time::Instant::now() < engaged,
                "the next mutation never took the write lock behind the gate"
            );
            std::thread::sleep(core::time::Duration::from_millis(1));
        }

        // Nothing may publish while the gate is closed.
        assert_eq!(
            observer.stream.lock().len(),
            1,
            "only the gated first batch is published so far"
        );

        release_tx.send(()).expect("gate thread alive");
        first_handle.join().expect("first publisher");
        second_handle.join().expect("second publisher");

        assert_eq!(
            *observer.stream.lock(),
            vec![1, 2],
            "publish order matches sequence order"
        );
        let pool_read = gateway.read();
        assert!(pool_read.contains_txid(&first_txid));
        assert!(pool_read.contains_txid(&second_txid));
    }

    /// Records every change sequence the observer sees, in publish order.
    #[derive(Default)]
    struct SequenceStreamObserver {
        stream: Mutex<Vec<u64>>,
    }

    impl MempoolObserver for SequenceStreamObserver {
        fn on_mutation(&self, result: &MutationResult) {
            let mut stream = self.stream.lock();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
        }
    }

    /// Races mutations from several threads and requires the published
    /// stream to be exactly the full sequence range in order. Sequences are
    /// assigned in commit order under the write lock, so an in-order stream
    /// proves publish order == commit order. Under the old
    /// release-the-write-lock-then-take-the-publish-mutex shape, a thread
    /// slipping from its write-lock release into the publish mutex while
    /// another thread completes a whole mutation cycle in between published
    /// out of order; since the invariant is now enforced inside `commit`,
    /// the publish mutex is always taken before the write lock is released,
    /// which makes that interleaving impossible rather than merely unlikely.
    #[test]
    fn concurrent_mutations_publish_in_sequence_order() {
        const CYCLES: usize = 1_500;
        const MEMBER_LABELS: [u8; 4] = [20, 21, 22, 23];
        let observer = Arc::new(SequenceStreamObserver::default());
        let gateway = Arc::new(gateway_with(Some(dyn_observer(&observer))));

        let handles: Vec<_> = MEMBER_LABELS
            .iter()
            .map(|&label| {
                let gateway = Arc::clone(&gateway);
                std::thread::spawn(move || {
                    let member = tx(label);
                    let member_txid = member.txid();
                    for _ in 0..CYCLES {
                        gateway.insert_entry(entry(&member)).expect("admitted");
                        gateway.remove_by_txid(&member_txid);
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("mutator thread");
        }

        let total = u64::try_from(MEMBER_LABELS.len() * CYCLES * 2).expect("change count fits u64");
        let stream = observer.stream.lock();
        assert_eq!(
            u64::try_from(stream.len()).expect("stream length fits u64"),
            total,
            "every committed change published exactly once"
        );
        let expected: Vec<u64> = (1..=total).collect();
        assert_eq!(*stream, expected, "publish order must equal commit order");
    }

    #[test]
    fn reconsider_disconnected_admits_in_order_once_per_candidate() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(Arc::clone(&observer) as Arc<dyn MempoolObserver>));
        let parent = tx(30);
        let parent_txid = parent.txid();
        let mut child = tx(31);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);

        let committed = gateway.reconsider_disconnected([entry(&parent), entry(&child)]);

        assert_eq!(committed.len(), 2, "one committed result per candidate");
        for result in &committed {
            assert_eq!(result.changes.len(), 1);
        }
        assert_eq!(gateway.read().sequence_number(), 2);
        let seen = observer.seen.lock();
        assert_eq!(seen.len(), 2, "one publish per committed candidate");
        assert_eq!(seen[0].0, hash(&parent_txid), "parent commits first");
        assert_eq!(
            seen[1].0,
            hash(&child.txid()),
            "child commits second"
        );
    }

    #[test]
    fn reconsider_disconnected_withholds_descendants_of_a_refused_parent() {
        let gateway = gateway_with(None);
        let parent = tx(32);
        let parent_txid = parent.txid();
        let mut child = tx(33);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        // Fee 50 over 100 vbytes is 500 sat/kvB, under the 1 000 sat/kvB
        // floor; the child itself is fine and only the refused parent can
        // keep it out.
        let refused_parent = MempoolEntry::new(Arc::new(parent), 100, 50, 1, 7);

        let committed = gateway.reconsider_disconnected([refused_parent, entry(&child)]);

        assert!(
            committed.is_empty(),
            "a refused parent must keep its descendant out"
        );
        assert!(!gateway.read().contains_txid(&parent_txid));
        assert!(!gateway.read().contains_txid(&child.txid()));
    }

    #[test]
    fn reconsider_disconnected_withholds_descendants_of_an_immediately_evicted_parent() {
        let observer = Arc::new(RecordingObserver::default());
        // A 150-byte pool already holding 100 vbytes of high-fee filler: the
        // parent's own insert succeeds and then immediately evicts the parent
        // as the lowest-fee package. The child pays far more than everything
        // else, so once admitted it fits and survives — only the parent's
        // eviction inside the parent's own MutationResult can keep it out.
        let gateway = MempoolGateway::new(
            Arc::new(RwLock::new(Mempool::new(MempoolLimits {
                min_relay_fee_sat_per_kvb: 0,
                max_total_bytes: 150,
                ..MempoolLimits::default()
            }))),
            Some(Arc::clone(&observer) as Arc<dyn MempoolObserver>),
        );
        let filler_txid = tx(36).txid();
        gateway
            .insert_entry(MempoolEntry::new(Arc::new(tx(36)), 100, 9_000, 1, 7))
            .expect("filler in");

        let parent = tx(34);
        let parent_txid = parent.txid();
        let mut child = tx(35);
        child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
        let child_txid = child.txid();
        let parent = MempoolEntry::new(Arc::new(parent), 100, 100, 1, 7);
        let child = MempoolEntry::new(Arc::new(child), 100, 9_000, 1, 7);

        let committed = gateway.reconsider_disconnected([parent, child]);

        assert_eq!(
            committed.len(),
            1,
            "only the parent's insert commits; the child is withheld"
        );
        assert_eq!(
            committed[0].changes,
            vec![
                crate::mutation::change(&parent_txid, MutationOutcome::Accepted),
                crate::mutation::change(&parent_txid, removed(RemovalReason::PolicyEviction)),
            ],
            "the parent was admitted and immediately evicted by its own insert"
        );
        let pool = gateway.read();
        assert!(!pool.contains_txid(&parent_txid));
        assert!(
            !pool.contains_txid(&child_txid),
            "an evicted parent must not admit its descendant"
        );
        assert!(
            pool.contains_txid(&filler_txid),
            "no orphan replaced the parent"
        );
        assert_eq!(
            pool.sequence_number(),
            3,
            "the withheld child assigns nothing"
        );
        assert_eq!(
            *observer.seen.lock(),
            vec![
                (hash(&parent_txid), MutationOutcome::Accepted),
                (hash(&parent_txid), removed(RemovalReason::PolicyEviction)),
            ],
            "the parent's two changes publish once each; the child publishes nothing"
        );
    }

    #[test]
    fn reconsider_disconnected_no_ops_on_an_empty_batch() {
        let observer = Arc::new(RecordingObserver::default());
        let gateway = gateway_with(Some(Arc::clone(&observer) as Arc<dyn MempoolObserver>));
        let before = gateway.read().sequence_number();

        let committed = gateway.reconsider_disconnected([]);

        assert!(committed.is_empty());
        assert_eq!(gateway.read().sequence_number(), before);
        assert!(observer.seen.lock().is_empty(), "nothing may publish");
    }
}
