//! Reconciliation regressions for the txindex worker: forward and
//! rival-branch repair, watermark rollback, missing-body reset-and-rebuild,
//! cursor identity, and interrupted-run convergence over a real
//! `FjallStore` writer.
//!
//! Named proving surface of `docs/contracts/indexing.md` (`IDX-04`
//! selective reset preserves the sibling capability, `IDX-06` reorg
//! rollback and forward reconciliation, `IDX-07` supervised reset and
//! rebuild) and `docs/contracts/chain-events.md` (`EVT-03` consumer-cursor
//! identity and positional reconciliation, `EVT-04` hash-addressed row
//! retention and cursor repair).
#![cfg(all(test, feature = "fjall"))]

use hashbrown::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_index::PreparedBatchLimits;
use bitcoin_rs_primitives::encode::{consensus_bytes, double_sha256};
use bitcoin_rs_primitives::{Hash256, Header as BlockHeader, TxIn, TxOut};
use bitcoin_rs_script::script::push_int;
use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore as _, StorageError, WriteBatch as _};
use crossbeam_channel::{Receiver, Sender};
use parking_lot::{Mutex, RwLock};

use super::*;
use crate::apply::PruneBodyStore;

struct SyncGate {
    reached: Sender<()>,
    release: Receiver<()>,
}

type BodyMap = HashMap<(u32, [u8; 32]), Vec<u8>>;

/// In-memory body store with an optional one-shot sync gate.
struct MapBodyStore {
    bodies: Mutex<BodyMap>,
    sync_count: AtomicUsize,
    sync_gate: Mutex<Option<SyncGate>>,
}

impl MapBodyStore {
    fn new(bodies: BodyMap, sync_gate: Option<SyncGate>) -> Self {
        Self {
            bodies: Mutex::new(bodies),
            sync_count: AtomicUsize::new(0),
            sync_gate: Mutex::new(sync_gate),
        }
    }

    fn sync_count(&self) -> usize {
        self.sync_count.load(Ordering::Acquire)
    }
}

impl PruneBodyStore for MapBodyStore {
    fn persist_block_body(
        &self,
        height: u32,
        hash: Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.bodies
            .lock()
            .insert((height, hash.to_le_bytes()), body.to_vec());
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .bodies
            .lock()
            .get(&(height, hash.to_le_bytes()))
            .cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.sync_count.fetch_add(1, Ordering::AcqRel);
        let gate = self.sync_gate.lock().take();
        if let Some(gate) = gate {
            gate.reached
                .send(())
                .expect("sync observer must remain live");
            gate.release
                .recv_timeout(Duration::from_secs(5))
                .expect("sync release must arrive");
        }
        Ok(())
    }
}

fn coinbase_tx(height: u32, extra: i64) -> Tx {
    let mut script_sig = push_int(i64::from(height));
    script_sig.extend_from_slice(&push_int(extra));
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig,
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 1,
            script_pubkey: Vec::new(),
        }],
    }
}

fn mine_block(prev_hash: Hash256, height: u32, extra: i64) -> (Block, Hash256) {
    let mut block = Block {
        header: BlockHeader {
            version: 1,
            prev_blockhash: BlockHash(prev_hash),
            merkle_root: Hash256::default(),
            time: height,
            bits: 0x207f_ffff,
            nonce: 0,
        },
        txs: vec![coinbase_tx(height, extra)],
    };
    block.header.merkle_root = merkle_root(&block).unwrap_or_default();
    let hash = block.block_hash().0;
    (block, hash)
}

/// Pairwise double-SHA256 fold over little-endian txid bytes, duplicating the
/// last leaf on odd levels (the native stand-in for `compute_merkle_root`).
fn merkle_root(block: &Block) -> Option<Hash256> {
    let mut leaves: Vec<[u8; 32]> = block
        .txs
        .iter()
        .map(|tx| tx.txid().0.to_le_bytes())
        .collect();
    if leaves.is_empty() {
        return None;
    }
    while leaves.len() > 1 {
        let original_len = leaves.len();
        let mut next = Vec::with_capacity(original_len.div_ceil(2));
        for pos in 0..original_len.div_ceil(2) {
            let left = leaves[2 * pos];
            let right = leaves[(2 * pos + 1).min(original_len - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(double_sha256(&pair).to_le_bytes());
        }
        leaves = next;
    }
    Some(Hash256::from_le_bytes(&leaves[0]))
}

struct ForkFixture {
    tree: BlockTree,
    genesis: (Block, Hash256),
    a1_id: NodeId,
    a1: (Block, Hash256),
    a2_id: NodeId,
    a2: (Block, Hash256),
    b1: (Block, Hash256),
    b2_id: NodeId,
    b2: (Block, Hash256),
}

fn fork_fixture() -> ForkFixture {
    let mut tree = BlockTree::new();
    let (genesis_block, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0);
    tree.insert_header(genesis_block.header, NodeStatus::HeaderValid)
        .expect("genesis");

    let (a1_block, a1_hash) = mine_block(genesis_hash, 1, 0);
    let a1_id = tree
        .insert_header(a1_block.header, NodeStatus::HeaderValid)
        .expect("a1");
    let (a2_block, a2_hash) = mine_block(a1_hash, 2, 0);
    let a2_id = tree
        .insert_header(a2_block.header, NodeStatus::HeaderValid)
        .expect("a2");

    let (b1_block, b1_hash) = mine_block(genesis_hash, 1, 1);
    tree.insert_header(b1_block.header, NodeStatus::HeaderValid)
        .expect("b1");
    let (b2_block, b2_hash) = mine_block(b1_hash, 2, 1);
    let b2_id = tree
        .insert_header(b2_block.header, NodeStatus::HeaderValid)
        .expect("b2");

    ForkFixture {
        tree,
        genesis: (genesis_block, genesis_hash),
        a1_id,
        a1: (a1_block, a1_hash),
        a2_id,
        a2: (a2_block, a2_hash),
        b1: (b1_block, b1_hash),
        b2_id,
        b2: (b2_block, b2_hash),
    }
}

fn tip_for(tree: &BlockTree, node_id: NodeId) -> TipSnapshot {
    let node = tree.node(node_id).expect("node");
    TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    }
}

fn bodies_map(bodies: &[(u32, Hash256, &Block)]) -> BodyMap {
    bodies
        .iter()
        .map(|(height, hash, block)| ((*height, hash.to_le_bytes()), consensus_bytes(*block)))
        .collect()
}

fn fjall_writer() -> (tempfile::TempDir, Arc<dyn TxIndexWriter>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(store, 1).expect("index writer open"),
    ));
    (temp, writer)
}

fn tx_lookup_watermark(writer: &dyn TxIndexWriter) -> Option<IndexWatermark> {
    writer
        .fenced_watermarks()
        .expect("fenced watermarks")
        .1
        .tx_lookup
}

fn make_worker(
    writer: &Arc<dyn TxIndexWriter>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    tree: &Arc<RwLock<BlockTree>>,
    body_store: Arc<dyn PruneBodyStore>,
    batch_limits: PreparedBatchLimits,
    rollback_rebuild_cutover: u32,
) -> (Arc<TxIndexRuntime>, Worker) {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
    let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
    let worker = Worker {
        runtime: Arc::clone(&runtime),
        writer: Arc::clone(writer),
        applied_tip: Arc::clone(applied_tip),
        block_tree: Arc::clone(tree),
        body_store: Some(body_store),
        batch_limits,
        rollback_rebuild_cutover,
        enabled: bitcoin_rs_index::IndexCapabilities::ALL,
        wake_rx,
        chain_events: detached_chain_publisher(),
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
    };
    (runtime, worker)
}

fn make_applied_tip() -> Arc<ArcSwapOption<TipSnapshot>> {
    Arc::new(ArcSwapOption::empty())
}

fn sync_gate() -> (SyncGate, Receiver<()>, Sender<()>) {
    let (reached_tx, reached_rx) = crossbeam_channel::bounded(1);
    let (release_tx, release_rx) = crossbeam_channel::bounded(1);
    (
        SyncGate {
            reached: reached_tx,
            release: release_rx,
        },
        reached_rx,
        release_tx,
    )
}

#[test]
fn forward_commit_overlapping_tip_extension_repairs_on_next_pass() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = bodies_map(&[
        (0, f.genesis.1, &f.genesis.0),
        (1, f.a1.1, &f.a1.0),
        (2, f.a2.1, &f.a2.0),
    ]);
    let (gate, reached_rx, release_tx) = sync_gate();
    let body_store = Arc::new(MapBodyStore::new(bodies, Some(gate)));
    let body_arc: Arc<dyn PruneBodyStore> = body_store.clone();
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_arc,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("prepare pass"),
        ReconcileAction::Buffered
    ));
    let handle = std::thread::spawn(move || {
        let action = worker.reconcile_once(&mut pending);
        (worker, pending, action)
    });
    reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("body sync must overlap the tip change");
    applied_tip.store(Some(Arc::new(tip_for(&tree.read(), f.a2_id))));
    release_tx.send(()).expect("worker must remain live");

    let (worker, mut pending, action) = handle.join().expect("worker thread");
    assert!(matches!(
        action.expect("first pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("A1 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (1, f.a1.1.to_le_bytes())
    );

    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("repair pass"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settled pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("A2 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (2, f.a2.1.to_le_bytes())
    );
    assert_eq!(body_store.sync_count(), 2);
}

#[test]
fn forward_commit_overlapping_rival_reorg_repairs_on_next_pass() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = bodies_map(&[
        (0, f.genesis.1, &f.genesis.0),
        (1, f.a1.1, &f.a1.0),
        (2, f.a2.1, &f.a2.0),
        (1, f.b1.1, &f.b1.0),
        (2, f.b2.1, &f.b2.0),
    ]);
    let (gate, reached_rx, release_tx) = sync_gate();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(bodies, Some(gate)));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );

    let mut pending = None;
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("prepare pass"),
        ReconcileAction::Buffered
    ));
    let handle = std::thread::spawn(move || {
        let action = worker.reconcile_once(&mut pending);
        (worker, pending, action)
    });
    reached_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("body sync must overlap the reorg");
    applied_tip.store(Some(Arc::new(tip_for(&tree.read(), f.b2_id))));
    release_tx.send(()).expect("worker must remain live");

    let (worker, mut pending, action) = handle.join().expect("worker thread");
    assert!(matches!(
        action.expect("stale pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("complete stale prefix");
    assert_eq!(
        (watermark.height, watermark.hash),
        (2, f.a2.1.to_le_bytes())
    );

    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("repair pass"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settled pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("B2 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (2, f.b2.1.to_le_bytes())
    );
}

#[test]
fn rollback_of_recanonicalized_watermark_repairs_on_next_pass() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = bodies_map(&[
        (0, f.genesis.1, &f.genesis.0),
        (1, f.a1.1, &f.a1.0),
        (2, f.a2.1, &f.a2.0),
    ]);
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(bodies, None));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;

    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle A2"),
        ReconcileAction::CaughtUp
    ));
    let a2_watermark = tx_lookup_watermark(writer.as_ref()).expect("A2 watermark");
    let (fence, watermarks) = writer.fenced_watermarks().expect("fresh rollback fence");

    // The tip is still A2. An already-selected rollback can nevertheless land.
    let a1_watermark = worker
        .rollback_one(
            fence,
            watermarks,
            bitcoin_rs_index::IndexCapabilities::ALL,
            a2_watermark,
        )
        .expect("rollback")
        .expect("A1 watermark");
    assert_eq!(
        (a1_watermark.height, a1_watermark.hash),
        (1, f.a1.1.to_le_bytes())
    );

    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("repair pass"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settled pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("repaired A2 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (2, f.a2.1.to_le_bytes())
    );
}

#[test]
fn absent_tip_rolls_index_back_to_none() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = bodies_map(&[(0, f.genesis.1, &f.genesis.0), (1, f.a1.1, &f.a1.0)]);
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(bodies, None));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;

    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    applied_tip.store(None);
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("publish stale prefix"),
        ReconcileAction::Progressed
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("rollback pass"),
        ReconcileAction::CaughtUp
    ));
    assert!(tx_lookup_watermark(writer.as_ref()).is_none());
}

#[test]
fn missing_disconnected_body_resets_and_rebuilds_selected_capabilities() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let body_store: Arc<dyn PruneBodyStore> = bodies.clone();
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle A2"),
        ReconcileAction::CaughtUp
    ));

    bodies.bodies.lock().remove(&(2, f.a2.1.to_le_bytes()));
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    applied_tip.store(Some(Arc::clone(&b2_tip)));

    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("reset and rebuild pass"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle B2"),
        ReconcileAction::CaughtUp
    ));
    let watermarks = writer.fenced_watermarks().expect("watermarks").1;
    let expected = Some(IndexWatermark {
        height: 2,
        hash: f.b2.1.to_le_bytes(),
    });
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.script_history, expected);
}

fn settle_and_diverge_watermarks(
    worker: &mut Worker,
    writer: &Arc<dyn TxIndexWriter>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    tree: &Arc<RwLock<BlockTree>>,
    a2_id: NodeId,
    b2_id: NodeId,
    pending: &mut Option<PendingForward>,
) {
    let a2_tip = Arc::new(tip_for(&tree.read(), a2_id));
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                IndexCapabilities::ALL,
                pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(pending).expect("settle A2"),
        ReconcileAction::CaughtUp
    ));

    worker.enabled = IndexCapabilities::TX_LOOKUP;
    let b2_tip = Arc::new(tip_for(&tree.read(), b2_id));
    applied_tip.store(Some(Arc::clone(&b2_tip)));
    assert!(matches!(
        worker
            .reconcile_once(pending)
            .expect("move tx lookup to B2"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker
            .reconcile_once(pending)
            .expect("settle tx lookup at B2"),
        ReconcileAction::CaughtUp
    ));
}

#[test]
fn stale_script_index_reset_preserves_ready_tx_lookup_then_rebuilds() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let body_store: Arc<dyn PruneBodyStore> = bodies.clone();
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (_runtime, mut worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;

    settle_and_diverge_watermarks(
        &mut worker,
        &writer,
        &applied_tip,
        &tree,
        f.a2_id,
        f.b2_id,
        &mut pending,
    );
    let a2 = Some(IndexWatermark {
        height: 2,
        hash: f.a2.1.to_le_bytes(),
    });
    let b2 = Some(IndexWatermark {
        height: 2,
        hash: f.b2.1.to_le_bytes(),
    });
    assert_eq!(
        writer.fenced_watermarks().expect("divergent watermarks").1,
        IndexWatermarks {
            tx_lookup: b2,
            script_history: a2,
        }
    );

    bodies.bodies.lock().remove(&(2, f.a2.1.to_le_bytes()));
    worker.enabled = IndexCapabilities::ALL;
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("selectively reset ScriptIndex and prepare B2"),
        ReconcileAction::Buffered
    ));
    assert_eq!(
        writer
            .fenced_watermarks()
            .expect("watermarks during rebuild")
            .1,
        IndexWatermarks {
            tx_lookup: b2,
            script_history: None,
        },
        "TxLookup must remain ready while the ScriptIndex rebuild is pending"
    );

    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("commit ScriptIndex rebuild"),
        ReconcileAction::CaughtUp
    ));
    assert_eq!(
        writer.fenced_watermarks().expect("rebuilt watermarks").1,
        IndexWatermarks {
            tx_lookup: b2,
            script_history: b2,
        }
    );
}

#[test]
fn missing_rollback_identity_resets_and_rebuilds_selected_capabilities() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
    ));
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle A2"),
        ReconcileAction::CaughtUp
    ));

    let mut corrupt = store.new_batch();
    corrupt.delete(ColumnFamily::BlockHeaders, &consensus_bytes(&f.a2.0.header));
    store.write_durable(corrupt).expect("remove identity row");
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    applied_tip.store(Some(Arc::clone(&b2_tip)));

    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("reset and rebuild pass"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle B2"),
        ReconcileAction::CaughtUp
    ));
    let expected = Some(IndexWatermark {
        height: 2,
        hash: f.b2.1.to_le_bytes(),
    });
    let watermarks = writer.fenced_watermarks().expect("watermarks").1;
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.script_history, expected);
}

#[test]
fn overflow_block_is_reprepared_and_committed_on_next_pass() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let bodies = bodies_map(&[(0, f.genesis.1, &f.genesis.0), (1, f.a1.1, &f.a1.0)]);
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(bodies, None));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let batch_limits = PreparedBatchLimits {
        max_rows: 3,
        max_bytes: DEFAULT_BATCH_LIMITS.max_bytes,
    };
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        batch_limits,
        u32::MAX,
    );
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));
    let mut pending = None;

    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("first pass"),
        ReconcileAction::Progressed
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("genesis watermark");
    assert_eq!(watermark.height, 0);

    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
                fence,
                watermarks,
                Some(watermark),
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending,
            )
            .expect("second pass"),
        ReconcileAction::Progressed
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settled pass"),
        ReconcileAction::CaughtUp
    ));
    let watermark = tx_lookup_watermark(writer.as_ref()).expect("A1 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (1, f.a1.1.to_le_bytes())
    );
}

// ---------------------------------------------------------------------------
// #77 convergence harness: an interrupted consumer must converge to the same
// index state as an uninterrupted one.
// ---------------------------------------------------------------------------

/// Fjall store plus writer, keeping the store handle for state dumps.
fn fjall_store_writer() -> (tempfile::TempDir, Arc<FjallStore>, Arc<dyn TxIndexWriter>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
    ));
    (temp, store, writer)
}
/// Reserved consumer-cursor slot in `UtxoMeta` (`0x00, b'C'`), mirrored from
/// the index crate's metadata-key family so the dump can exclude it.
const CURSOR_META_KEY: &[u8] = &[0x00, b'C'];

/// Reserved permanent capability-reset slot in `UtxoMeta` (`0x00, b'R'`,
/// `Idle(version)` / `Claim(mask, process_epoch, base)`), mirrored from the
/// index crate's metadata-key family so the dump can exclude it.
const RESET_META_KEY: &[u8] = &[0x00, b'R'];

/// Reserved monotonic ordinary-state revision slot in `UtxoMeta`.
const STATE_REVISION_META_KEY: &[u8] = &[0x00, b'O'];

/// Drives reconciliation passes until the worker reports `CaughtUp`.
fn run_until_caught_up(worker: &Worker, pending: &mut Option<PendingForward>) {
    for pass in 0..64 {
        if matches!(
            worker.reconcile_once(pending).expect("reconcile pass"),
            ReconcileAction::CaughtUp
        ) {
            return;
        }
        assert!(
            pass < 63,
            "consumer did not converge within the pass budget"
        );
    }
}

/// Byte dump of every derived index row and all unrelated metadata, skipping
/// the three synchronization slots in `UtxoMeta`: the consumer cursor, reset
/// marker, and ordinary-state revision. Their histories can differ while the
/// derived rows and capability watermarks remain byte-identical.
fn dump_index_state(store: &FjallStore) -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let families = [
        ColumnFamily::TxConfirmed,
        ColumnFamily::BlockHeaders,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::UtxoMeta,
    ];
    let mut rows = Vec::new();
    for family in families {
        for pair in store.iter_prefix(family, &[]).expect("index family scan") {
            let (key, value) = pair.expect("iterable row");
            if family == ColumnFamily::UtxoMeta
                && [CURSOR_META_KEY, RESET_META_KEY, STATE_REVISION_META_KEY]
                    .contains(&key.as_slice())
            {
                continue;
            }
            rows.push((family, key, value));
        }
    }
    rows
}

/// Worker wired to a caller-owned publisher so tests control the epoch and
/// the recorded event stream.
fn make_worker_with_events(
    writer: &Arc<dyn TxIndexWriter>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    tree: &Arc<RwLock<BlockTree>>,
    body_store: Arc<dyn PruneBodyStore>,
    chain_events: Arc<crate::state::ChainEventPublisher>,
) -> Worker {
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
    let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
    Worker {
        runtime,
        writer: Arc::clone(writer),
        applied_tip: Arc::clone(applied_tip),
        block_tree: Arc::clone(tree),
        body_store: Some(body_store),
        batch_limits: DEFAULT_BATCH_LIMITS,
        enabled: IndexCapabilities::ALL,
        chain_events,
        rollback_rebuild_cutover: u32::MAX,
        wake_rx,
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
    }
}

/// One committed tip transition: publish the applied tip, emit the same
/// `record` the apply path emits, and reconcile rows plus cursor atomically.
fn advance_tip(
    worker: &Worker,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    publisher: &Arc<crate::state::ChainEventPublisher>,
    tree: &BlockTree,
    node_id: NodeId,
    kind: crate::state::HintKind,
    pending: &mut Option<PendingForward>,
) {
    let tip = Arc::new(tip_for(tree, node_id));
    applied_tip.store(Some(Arc::clone(&tip)));
    publisher.record(kind, tip.height, tip.hash);
    run_until_caught_up(worker, pending);
}

#[test]
fn reconciliation_plan_walks_the_tree() {
    let f = fork_fixture();
    let tree = f.tree;
    let b2_tip = tip_for(&tree, f.b2_id);

    // A genesis-anchored consumer on the winning branch only connects forward.
    let cursor = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 1,
        height: 0,
        hash: f.genesis.1,
    };
    assert_eq!(
        crate::reconcile::plan(&cursor, &b2_tip, &tree),
        crate::reconcile::ReconcilePlan::Forward { from_height: 1 }
    );

    // An A-branch consumer must roll back to the genesis common ancestor.
    let cursor = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 1,
        height: 1,
        hash: f.a1.1,
    };
    assert_eq!(
        crate::reconcile::plan(&cursor, &b2_tip, &tree),
        crate::reconcile::ReconcilePlan::RollbackAndForward { ancestor_height: 0 }
    );

    // A consumer at the live tip is caught up.
    let cursor = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 3,
        height: 2,
        hash: f.b2.1,
    };
    assert_eq!(
        crate::reconcile::plan(&cursor, &b2_tip, &tree),
        crate::reconcile::ReconcilePlan::CaughtUp
    );
    // A cursor the tree never saw asks for a rebuild, not a guess.
    let cursor = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 1,
        height: 9,
        hash: Hash256::from_le_bytes(&[9_u8; 32]),
    };
    assert_eq!(
        crate::reconcile::plan(&cursor, &b2_tip, &tree),
        crate::reconcile::ReconcilePlan::Rebuild
    );
}

#[test]
fn snapshot_identity_changes_reconcile_from_the_cursor_position() {
    let f = fork_fixture();
    let tree = f.tree;
    let target = tip_for(&tree, f.b2_id);
    let cursor = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 1,
        height: 0,
        hash: f.genesis.1,
    };
    let epoch_restart = crate::state::ChainSnapshot {
        epoch: 2,
        sequence: 0,
        tip_hash: f.b2.1,
        tip_height: 2,
    };
    assert_eq!(
        crate::reconcile::plan_from_snapshot(&cursor, &epoch_restart, &target, &tree),
        crate::reconcile::ReconcilePlan::Forward { from_height: 1 }
    );

    let sequence_gap = crate::state::ChainSnapshot {
        epoch: 1,
        sequence: 4,
        tip_hash: f.b2.1,
        tip_height: 2,
    };
    assert_eq!(
        crate::reconcile::plan_from_snapshot(&cursor, &sequence_gap, &target, &tree),
        crate::reconcile::ReconcilePlan::Forward { from_height: 1 }
    );

    let orphan = crate::reconcile::ConsumerCursor {
        epoch: 1,
        sequence: 2,
        height: 1,
        hash: f.a1.1,
    };
    assert_eq!(
        crate::reconcile::plan_from_snapshot(&orphan, &sequence_gap, &target, &tree),
        crate::reconcile::ReconcilePlan::RollbackAndForward { ancestor_height: 0 }
    );
}

#[test]
fn consumer_cursor_round_trips_bytes() {
    let snapshot = crate::state::ChainSnapshot {
        epoch: 7,
        sequence: 9,
        tip_hash: Hash256::from_le_bytes(&[0xAB_u8; 32]),
        tip_height: 11,
    };
    let cursor = crate::reconcile::ConsumerCursor::from_snapshot(&snapshot);
    let bytes = cursor.to_bytes();
    assert_eq!(bytes.len(), crate::reconcile::CURSOR_BYTE_LEN);
    assert_eq!(
        crate::reconcile::ConsumerCursor::from_bytes(&bytes),
        Some(cursor)
    );
    assert!(crate::reconcile::ConsumerCursor::from_bytes(&bytes[..51]).is_none());
}
#[test]
#[allow(clippy::too_many_lines)]
fn interrupted_consumer_converges_to_the_uninterrupted_index_state() {
    let f = fork_fixture();
    let tree = Arc::new(RwLock::new(f.tree));
    let tree_guard = tree.read();
    let genesis_id = tree_guard.lookup(f.genesis.1).expect("genesis node");
    let b1_id = tree_guard.lookup(f.b1.1).expect("b1 node");
    let bodies: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));

    // Uninterrupted run (epoch 1): connect A1, disconnect to genesis, follow B.
    let (temp_a, store_a, writer_a) = fjall_store_writer();
    let applied_a = make_applied_tip();
    let (publisher_a_raw, _hints_a) = crate::state::ChainEventPublisher::detached(1);
    let publisher_a = Arc::new(publisher_a_raw);
    let worker_a = make_worker_with_events(
        &writer_a,
        &applied_a,
        &tree,
        Arc::clone(&bodies),
        Arc::clone(&publisher_a),
    );
    let mut pending_a = None;
    advance_tip(
        &worker_a,
        &applied_a,
        &publisher_a,
        &tree_guard,
        f.a1_id,
        crate::state::HintKind::Connected,
        &mut pending_a,
    );
    advance_tip(
        &worker_a,
        &applied_a,
        &publisher_a,
        &tree_guard,
        genesis_id,
        crate::state::HintKind::Disconnected,
        &mut pending_a,
    );
    advance_tip(
        &worker_a,
        &applied_a,
        &publisher_a,
        &tree_guard,
        b1_id,
        crate::state::HintKind::Connected,
        &mut pending_a,
    );
    advance_tip(
        &worker_a,
        &applied_a,
        &publisher_a,
        &tree_guard,
        f.b2_id,
        crate::state::HintKind::Connected,
        &mut pending_a,
    );
    let uninterrupted = dump_index_state(&store_a);
    let uninterrupted_cursor = writer_a
        .consumer_cursor()
        .expect("read cursor")
        .expect("cursor persisted for the settled run");

    // Interrupted run: same committed event sequence, but the consumer
    // restarts under a new epoch after A1, the B1 hint is dropped, and B2 is
    // published while the consumer is still down.
    let (temp_b, store_b, writer_b) = fjall_store_writer();
    let applied_b = make_applied_tip();
    let (publisher_one_raw, _hints_one) = crate::state::ChainEventPublisher::detached(1);
    let publisher_one = Arc::new(publisher_one_raw);
    let worker_one = make_worker_with_events(
        &writer_b,
        &applied_b,
        &tree,
        Arc::clone(&bodies),
        Arc::clone(&publisher_one),
    );
    let mut pending_b = None;
    advance_tip(
        &worker_one,
        &applied_b,
        &publisher_one,
        &tree_guard,
        f.a1_id,
        crate::state::HintKind::Connected,
        &mut pending_b,
    );

    // Process restart: a fresh epoch takes over; only the store survives.
    let (publisher_two_raw, _hints_two) = crate::state::ChainEventPublisher::detached(2);
    let publisher_two = Arc::new(publisher_two_raw);
    let worker_two = make_worker_with_events(
        &writer_b,
        &applied_b,
        &tree,
        Arc::clone(&bodies),
        Arc::clone(&publisher_two),
    );

    // The B1 event commits but its hint never wakes the consumer; B2 commits
    // before the first wake finally arrives.
    publisher_two.record(crate::state::HintKind::Connected, 1, f.b1.1);
    let b2_tip = Arc::new(tip_for(&tree_guard, f.b2_id));
    applied_b.store(Some(Arc::clone(&b2_tip)));
    publisher_two.record(
        crate::state::HintKind::Connected,
        b2_tip.height,
        b2_tip.hash,
    );

    run_until_caught_up(&worker_two, &mut pending_b);

    let interrupted = dump_index_state(&store_b);
    assert_eq!(
        interrupted, uninterrupted,
        "interrupted consumer must converge to byte-identical index state"
    );

    let resumed = crate::reconcile::ConsumerCursor::from_bytes(
        &writer_b
            .consumer_cursor()
            .expect("read cursor")
            .expect("cursor persisted after restart"),
    )
    .expect("decode resumed cursor");
    let original =
        crate::reconcile::ConsumerCursor::from_bytes(&uninterrupted_cursor).expect("decode");
    assert_eq!(resumed.height, original.height);
    assert_eq!(resumed.hash, original.hash);
    assert_eq!(resumed.epoch, 2, "the new epoch namespaces the cursor");
    assert_eq!(resumed.sequence, 2);
    drop(temp_a);
    drop(temp_b);
}

// ---------------------------------------------------------------------------
// C1: bounded large-gap reconciliation (`rollback_depth` + cutover routing)

/// Delegating writer counting rollback commits and capability resets so the
/// cutover routing is pinned behaviorally (never via tracing capture, which is
/// racy under parallel tests per the sync/window.rs precedent).
struct RecordingWriter {
    inner: Arc<dyn TxIndexWriter>,
    rollback_commits: AtomicUsize,
    reset_calls: AtomicUsize,
    reset_capabilities: Mutex<Vec<bitcoin_rs_index::IndexCapabilities>>,
    fail_forward_once: AtomicU8,
    fail_rollback_once: AtomicBool,
    fail_cursor_once: AtomicBool,
    fenced_watermarks_failure_countdown: AtomicUsize,
    rollback_clears: AtomicUsize,
    watermark_lag: AtomicBool,
}

impl TxIndexWriter for RecordingWriter {
    fn fenced_watermarks(
        &self,
    ) -> Result<
        (
            bitcoin_rs_index::IndexWriteFence,
            bitcoin_rs_index::IndexWatermarks,
        ),
        IndexError,
    > {
        if self.fenced_watermarks_failure_countdown.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |remaining| remaining.checked_sub(1),
        ) == Ok(1)
        {
            return Err(IndexError::ResetInProgress);
        }
        let (fence, mut watermarks) = self.inner.fenced_watermarks()?;
        if self.watermark_lag.load(Ordering::Acquire) {
            // Simulate a capability watermark lagging the snapshot inside the
            // fence window.
            watermarks.tx_lookup = watermarks.tx_lookup.map(|mark| IndexWatermark {
                height: mark.height.saturating_sub(1),
                ..mark
            });
        }
        Ok((fence, watermarks))
    }

    fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.inner.prepare_block(height, hash, body)
    }

    fn prepare_block_for(
        &self,
        capabilities: bitcoin_rs_index::IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.inner
            .prepare_block_for(capabilities, height, hash, body)
    }

    fn commit_forward_with_cursor(
        &self,
        fence: bitcoin_rs_index::IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<bitcoin_rs_index::IndexWatermark, IndexError> {
        match self.fail_forward_once.swap(0, Ordering::AcqRel) {
            0 => {}
            1 => return Err(IndexError::ResetInProgress),
            2 => return Err(IndexError::StaleIndexState),
            _ => unreachable!("fail_forward_once encodes 0|1|2"),
        }
        self.inner.commit_forward_with_cursor(fence, batch, cursor)
    }

    fn commit_rollback_one_for_with_cursor(
        &self,
        fence: bitcoin_rs_index::IndexWriteFence,
        capabilities: bitcoin_rs_index::IndexCapabilities,
        prev: Option<bitcoin_rs_index::IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError> {
        if self.fail_rollback_once.swap(false, Ordering::AcqRel) {
            return Err(IndexError::ResetInProgress);
        }
        if matches!(cursor, ConsumerCursorUpdate::Clear) {
            self.rollback_clears.fetch_add(1, Ordering::AcqRel);
        }
        self.rollback_commits.fetch_add(1, Ordering::Acquire);
        self.inner
            .commit_rollback_one_for_with_cursor(fence, capabilities, prev, body, cursor)
    }

    fn reset_capabilities(
        &self,
        capabilities: bitcoin_rs_index::IndexCapabilities,
    ) -> Result<(), IndexError> {
        self.reset_calls.fetch_add(1, Ordering::Acquire);
        self.reset_capabilities.lock().push(capabilities);
        self.inner.reset_capabilities(capabilities)
    }

    fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        self.inner.consumer_cursor()
    }

    fn commit_consumer_cursor(
        &self,
        fence: bitcoin_rs_index::IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        if self.fail_cursor_once.swap(false, Ordering::AcqRel) {
            return Err(IndexError::ResetInProgress);
        }
        self.inner.commit_consumer_cursor(fence, cursor)
    }
}
fn recording_writer(inner: Arc<dyn TxIndexWriter>) -> Arc<RecordingWriter> {
    Arc::new(RecordingWriter {
        inner,
        rollback_commits: AtomicUsize::new(0),
        reset_calls: AtomicUsize::new(0),
        reset_capabilities: Mutex::new(Vec::new()),
        fail_forward_once: AtomicU8::new(0),
        fail_rollback_once: AtomicBool::new(false),
        fail_cursor_once: AtomicBool::new(false),
        fenced_watermarks_failure_countdown: AtomicUsize::new(0),
        rollback_clears: AtomicUsize::new(0),
        watermark_lag: AtomicBool::new(false),
    })
}

/// Worker whose rows are settled on the losing A-branch at `a2`, with the
/// applied tip freshly switched to the winning B-branch at `b2` and the
/// recording counters zeroed.
struct CutoverFixture {
    _temp: tempfile::TempDir,
    store: Arc<FjallStore>,
    writer: Arc<RecordingWriter>,
    worker: Worker,
    pending: Option<PendingForward>,
    b2_hash: Hash256,
    a2_hash: Hash256,
}

fn cutover_fixture(cutover: u32) -> CutoverFixture {
    let (temp, store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let (_runtime, worker) = make_worker(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        cutover,
    );
    let mut pending = None;
    let (fence, watermarks) = writer.fenced_watermarks().expect("fenced watermarks");
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
                fence,
                watermarks,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle a2"),
        ReconcileAction::CaughtUp
    ));

    writer.rollback_commits.store(0, Ordering::Release);
    writer.reset_calls.store(0, Ordering::Release);
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    applied_tip.store(Some(Arc::clone(&b2_tip)));
    CutoverFixture {
        _temp: temp,
        store,
        writer,
        worker,
        pending,
        b2_hash: f.b2.1,
        a2_hash: f.a2.1,
    }
}

fn rows_of(store: &FjallStore, family: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
    store
        .iter_prefix(family, &[])
        .expect("family scan")
        .map(|pair| pair.expect("iterable row"))
        .collect()
}

#[test]
fn rollback_depth_measures_blocks_to_shared_ancestor() {
    let f = fork_fixture();
    let a2_tip = tip_for(&f.tree, f.a2_id);

    // Losing-branch position: b2 sits two blocks above the shared genesis.
    assert_eq!(
        crate::reconcile::rollback_depth(&f.tree, f.b2.1, 2, a2_tip.tip_id),
        Some(2)
    );
    // One block down the losing branch: b1 rewinds exactly one block.
    assert_eq!(
        crate::reconcile::rollback_depth(&f.tree, f.b1.1, 1, a2_tip.tip_id),
        Some(1)
    );
    // A position already on the active chain (a1 under the a2 tip) has no
    // depth to rewind: the shared ancestor is the position itself.
    assert_eq!(
        crate::reconcile::rollback_depth(&f.tree, f.a1.1, 1, a2_tip.tip_id),
        Some(0)
    );
    // A hash the tree never saw is unresolvable: no depth, per-block route.
    let unknown = Hash256::from_le_bytes(&[0xab; 32]);
    assert_eq!(
        crate::reconcile::rollback_depth(&f.tree, unknown, 7, a2_tip.tip_id),
        None
    );
}

#[test]
fn stale_branch_below_cutover_rolls_back_per_block() {
    let mut fx = cutover_fixture(3);
    // Depth a2 -> b2 is 2; 2 <= 3 rewinds block by block.
    run_until_caught_up(&fx.worker, &mut fx.pending);

    assert_eq!(fx.writer.reset_calls.load(Ordering::Acquire), 0);
    assert_eq!(
        fx.writer.rollback_commits.load(Ordering::Acquire),
        2,
        "a2 and a1 each rewind through one per-block commit"
    );
    let expected = Some(IndexWatermark {
        height: 2,
        hash: fx.b2_hash.to_le_bytes(),
    });
    let watermarks = fx.writer.fenced_watermarks().expect("watermarks").1;
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.script_history, expected);
    assert_eq!(
        rows_of(&fx.store, ColumnFamily::BlockHeaders).len(),
        3,
        "rows converged onto the active branch: genesis, b1, b2"
    );
    drop(fx);
}

// Mechanical slim-trait edit: `fx.writer.watermarks()` is retired by the
// trait cut; the full-watermark observation below keeps the pre-edit shape
// but reads through `fenced_watermarks(...).1`.
#[test]
fn stale_branch_at_cutover_still_rewinds() {
    let mut fx = cutover_fixture(2);
    // Depth 2 == cutover 2: the boundary is strict `>`, so this rewinds.
    run_until_caught_up(&fx.worker, &mut fx.pending);

    assert_eq!(fx.writer.reset_calls.load(Ordering::Acquire), 0);
    assert_eq!(fx.writer.rollback_commits.load(Ordering::Acquire), 2);
    let expected = Some(IndexWatermark {
        height: 2,
        hash: fx.b2_hash.to_le_bytes(),
    });
    let watermarks = fx.writer.fenced_watermarks().expect("watermarks").1;
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.script_history, expected);
    drop(fx);
}

// Mechanical slim-trait edit: the byte-proven pre-edit capture spelled the
// reset mask as a struct literal `{ tx_lookup: true, script_history: true }`;
// the current bitflag form of the same mask is `IndexCapabilities::ALL`.
#[test]
fn stale_branch_past_cutover_rebuilds() {
    let mut fx = cutover_fixture(1);
    // Depth 2 > cutover 1: exactly one selective reset, no rewind commits.
    run_until_caught_up(&fx.worker, &mut fx.pending);

    assert_eq!(
        fx.writer.reset_calls.load(Ordering::Acquire),
        1,
        "the stale selection routes to exactly one reset_capabilities"
    );
    assert_eq!(
        fx.writer.rollback_commits.load(Ordering::Acquire),
        0,
        "no per-block rollback commits past the cutover"
    );
    assert_eq!(
        fx.writer.reset_capabilities.lock().as_slice(),
        &[bitcoin_rs_index::IndexCapabilities::ALL],
        "the reset names the stale mask"
    );
    let expected = Some(IndexWatermark {
        height: 2,
        hash: fx.b2_hash.to_le_bytes(),
    });
    let watermarks = fx.writer.fenced_watermarks().expect("watermarks").1;
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.script_history, expected);

    // Converged rows match a from-scratch build on the winning branch.
    let rebuilt = dump_index_state(&fx.store);
    let scratch = from_scratch_b2_dump();
    assert_eq!(
        rebuilt, scratch,
        "rebuild-after-cutover must match a from-scratch build byte for byte"
    );
    drop(fx);
}

/// Builds the B-branch index from an empty store (no stale watermark), and
/// dumps the resulting state for byte-identical comparison.
fn from_scratch_b2_dump() -> Vec<(ColumnFamily, Vec<u8>, Vec<u8>)> {
    let (_temp, store, writer) = fjall_store_writer();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    applied_tip.store(Some(b2_tip));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    dump_index_state(&store)
}

#[test]
fn past_cutover_reset_preserves_ready_sibling_capability() {
    let mut fx = cutover_fixture(1);
    for pass in 0..64 {
        if matches!(
            fx.worker.reconcile_once(&mut fx.pending),
            Ok(ReconcileAction::CaughtUp)
        ) {
            break;
        }
        assert!(pass < 63, "run1 pass {pass} did not converge");
    }

    let a2_watermark = bitcoin_rs_index::IndexWatermark {
        height: 2,
        hash: fx.a2_hash.to_le_bytes(),
    }
    .to_bytes();
    let mut stale = fx.store.new_batch();
    stale.put(ColumnFamily::UtxoMeta, &[0x00, b'S'], &a2_watermark);
    fx.store.write_durable(stale).expect("seed stale watermark");

    let tx_rows_before = rows_of(&fx.store, ColumnFamily::TxConfirmed);
    let headers_before = rows_of(&fx.store, ColumnFamily::BlockHeaders);
    let tx_watermark_before = tx_lookup_watermark(fx.writer.as_ref());
    fx.writer.reset_calls.store(0, Ordering::Release);
    fx.writer.reset_capabilities.lock().clear();

    run_until_caught_up(&fx.worker, &mut fx.pending);

    assert_eq!(
        fx.writer.reset_calls.load(Ordering::Acquire),
        1,
        "only the stale sibling routes to reset"
    );
    assert_eq!(
        fx.writer.reset_capabilities.lock().as_slice(),
        &[bitcoin_rs_index::IndexCapabilities {
            tx_lookup: false,
            script_history: true,
        }],
        "the reset mask names script_history only"
    );
    assert_eq!(
        fx.writer.rollback_commits.load(Ordering::Acquire),
        0,
        "the ready sibling never rewinds"
    );
    let watermarks = fx.writer.fenced_watermarks().expect("watermarks").1;
    assert_eq!(
        watermarks.tx_lookup, tx_watermark_before,
        "ready sibling watermark is untouched"
    );
    assert_eq!(
        rows_of(&fx.store, ColumnFamily::TxConfirmed),
        tx_rows_before,
        "ready sibling rows are byte-identical"
    );
    assert_eq!(
        rows_of(&fx.store, ColumnFamily::BlockHeaders),
        headers_before,
        "shared identity rows survive while an unselected cursor remains"
    );
    assert_eq!(
        watermarks.script_history,
        Some(IndexWatermark {
            height: 2,
            hash: fx.b2_hash.to_le_bytes(),
        }),
        "stale sibling rebuilt onto the active branch"
    );
    drop(fx);
}

// Mechanical slim-trait edit: `writer.watermark()` is retired by the trait
// cut; the final watermark observation uses `tx_lookup_watermark(...)`.
#[test]
fn reset_in_progress_discards_pending_forward_without_failing_the_worker() {
    let (_temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[(0, f.genesis.1, &f.genesis.0)]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let genesis_id = tree
        .read()
        .node_at_height_from(f.a1_id, 0)
        .expect("genesis");
    let genesis_tip = Arc::new(tip_for(&tree.read(), genesis_id));
    applied_tip.store(Some(genesis_tip));
    let (runtime, worker) = make_worker(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;

    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("prepare"),
        ReconcileAction::Buffered
    ));
    writer.fail_forward_once.store(1, Ordering::Release);
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("transient"),
        ReconcileAction::Stalled
    ));
    assert!(pending.is_none(), "stale prepared rows must be discarded");
    assert!(runtime.failure_message().is_none());

    run_until_caught_up(&worker, &mut pending);
    assert_eq!(
        tx_lookup_watermark(writer.as_ref()).map(|mark| mark.height),
        Some(0)
    );
}

// Mechanical slim-trait edit: `fx.writer.watermark()` is retired by the
// trait cut; the final watermark comparison uses `tx_lookup_watermark(...)`.
#[test]
fn reset_in_progress_stalls_rollback_then_converges() {
    let mut fx = cutover_fixture(u32::MAX);
    fx.writer.fail_rollback_once.store(true, Ordering::Release);

    assert!(matches!(
        fx.worker
            .reconcile_once(&mut fx.pending)
            .expect("transient rollback"),
        ReconcileAction::Stalled
    ));
    assert!(fx.pending.is_none());
    assert!(fx.worker.runtime.failure_message().is_none());

    run_until_caught_up(&fx.worker, &mut fx.pending);
    assert_eq!(
        tx_lookup_watermark(fx.writer.as_ref()),
        Some(IndexWatermark {
            height: 2,
            hash: fx.b2_hash.to_le_bytes(),
        })
    );
}

// Test 7 setup note: the pre-edit capture recorded events on a publisher and
// attached it to the worker via `worker.chain_events = Arc::clone(&publisher)`
// after `make_worker`; that exact setup is preserved below. RecordingReader
// observation (the cursor before the failure injection) keeps the same order:
// settle, read cursor, record, fail once, reset-reject, assert unchanged,
// assert no runtime failure, settle again, assert moved.
//
// (Body reconstructed from the byte-proven F69D_265 tail pins plus the
// surrounding setup pins in EEF7_13114; the recording attach line is
// byte-proven at pre-edit line 1804.)
#[test]
fn reset_in_progress_skips_stale_cursor_then_persists_a_fresh_one() {
    let (_temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[(0, f.genesis.1, &f.genesis.0)]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let genesis_id = tree
        .read()
        .node_at_height_from(f.a1_id, 0)
        .expect("genesis");
    let genesis_tip = Arc::new(tip_for(&tree.read(), genesis_id));
    applied_tip.store(Some(Arc::clone(&genesis_tip)));
    let (runtime, mut worker) = make_worker(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let publisher = Arc::new(crate::state::ChainEventPublisher::detached(0).0);
    publisher.record(
        crate::state::HintKind::Connected,
        genesis_tip.height,
        genesis_tip.hash,
    );
    worker.chain_events = Arc::clone(&publisher);
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    let old_cursor = writer
        .consumer_cursor()
        .expect("cursor")
        .expect("initial cursor");
    publisher.record(
        crate::state::HintKind::Connected,
        genesis_tip.height,
        genesis_tip.hash,
    );

    writer.fail_cursor_once.store(true, Ordering::Release);
    assert!(matches!(
        worker.persist_chain_cursor(),
        Ok(CursorCommit::ResetRejected)
    ));
    assert_eq!(
        writer.consumer_cursor().expect("cursor").as_deref(),
        Some(old_cursor.as_slice())
    );
    assert!(runtime.failure_message().is_none());

    assert!(matches!(
        worker.persist_chain_cursor(),
        Ok(CursorCommit::Settled)
    ));
    assert_ne!(
        writer.consumer_cursor().expect("cursor").as_deref(),
        Some(old_cursor.as_slice())
    );
}

// ---------------------------------------------------------------------------
// REC-C: worker liveness under retryable deadline and cursor-fence rejections,
// plus stale-fence pending-forward discard.
//
// A ResetInProgress or StaleIndexState rejection during a BatchWait::Deadline
// commit is retryable unless shutdown was requested; the worker must stay
// alive, converge, and keep runtime health. A ResetInProgress rejection while
// capturing the cursor fence is also retryable. A completed reset changes the
// captured IndexWriteFence; a retained PendingForward under the old fence must
// be discarded and report Stalled before the same-fence watermark invariant,
// then a later pass must converge. PendingDurableChanged remains fatal when the
// fence is unchanged — the deliberate watermarks/fence incoherence in the
// same-fence fatal case must stay fatal so the fix does not swallow corruption.
// ---------------------------------------------------------------------------

#[test]
fn cursor_fence_capture_reset_rejection_keeps_run_alive_until_explicit_stop() {
    let (_temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[(0, f.genesis.1, &f.genesis.0)]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let genesis_id = tree
        .read()
        .node_at_height_from(f.a1_id, 0)
        .expect("genesis");
    applied_tip.store(Some(Arc::new(tip_for(&tree.read(), genesis_id))));
    let (runtime, worker) = make_worker(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);

    // The first capture belongs to reconcile_once; reject the second capture,
    // which belongs to cursor publication in the CaughtUp arm.
    writer
        .fenced_watermarks_failure_countdown
        .store(2, Ordering::Release);
    let (done_tx, done_rx) = crossbeam_channel::bounded::<Result<(), TxIndexWorkerError>>(1);
    let runtime_for_shutdown = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = done_tx.send(worker.run());
    });

    if let Ok(premature) = done_rx.recv_timeout(Duration::from_secs(2)) {
        panic!(
            "worker run() returned prematurely after cursor-fence ResetInProgress \
             rejection instead of staying alive until explicit stop: {premature:?}"
        );
    }

    runtime_for_shutdown.request_shutdown();
    let run_result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker must shut down after request_shutdown");
    run_result.expect("run returned an error after shutdown");
    assert!(
        runtime_for_shutdown.failure_message().is_none(),
        "a retryable cursor-fence rejection must not publish a failure"
    );
}

/// Shared fixture for the deadline-liveness tests: a worker settled at
/// genesis with a1 bodies available and the applied tip already extended to
/// a1, so the next `run()` iteration buffers a pending batch and hits
/// `BatchWait::Deadline` → `commit_pending` on its first loop iteration
/// (`batch_delay: Duration::ZERO` makes the deadline fire immediately).
struct DeadlineLivenessFixture {
    _temp: tempfile::TempDir,
    writer: Arc<RecordingWriter>,
    runtime: Arc<TxIndexRuntime>,
    worker: Worker,
}

/// Builds the fixture and arms a one-shot forward-commit rejection of the
/// given kind (`1` = `ResetInProgress`, `2` = `StaleIndexState`).
fn deadline_liveness_fixture(fail_kind: u8) -> DeadlineLivenessFixture {
    let (temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[(0, f.genesis.1, &f.genesis.0), (1, f.a1.1, &f.a1.0)]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let genesis_id = tree
        .read()
        .node_at_height_from(f.a1_id, 0)
        .expect("genesis");
    let genesis_tip = Arc::new(tip_for(&tree.read(), genesis_id));
    applied_tip.store(Some(genesis_tip));
    let (wake_tx, wake_rx) = crossbeam_channel::bounded(16);
    let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
    let worker = Worker {
        runtime: Arc::clone(&runtime),
        writer: writer_dyn,
        applied_tip: Arc::clone(&applied_tip),
        block_tree: Arc::clone(&tree),
        body_store: Some(body_store),
        batch_limits: DEFAULT_BATCH_LIMITS,
        rollback_rebuild_cutover: u32::MAX,
        enabled: bitcoin_rs_index::IndexCapabilities::ALL,
        wake_rx,
        chain_events: detached_chain_publisher(),
        quiet_period: Duration::ZERO,
        batch_delay: Duration::ZERO,
    };
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    assert_eq!(
        tx_lookup_watermark(writer.as_ref()).map(|m| m.height),
        Some(0)
    );

    // Extend the tip to a1 so the next reconcile buffers a pending batch.
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));

    // Arm the one-shot rejection on the next forward commit. With
    // `batch_delay: Duration::ZERO`, the deadline fires immediately, so
    // `run()` hits `BatchWait::Deadline` → `commit_pending` on its first
    // loop iteration without a timing dependency.
    writer.fail_forward_once.store(fail_kind, Ordering::Release);

    DeadlineLivenessFixture {
        _temp: temp,
        writer,
        runtime,
        worker,
    }
}

/// Spawns `worker.run()`, asserts it does not return prematurely (the
/// rejection is retryable), then requests shutdown, collects the result,
/// and asserts the watermark reached a1 and runtime health stayed clear.
fn assert_deadline_liveness(fx: DeadlineLivenessFixture, rejection_label: &str) {
    let DeadlineLivenessFixture {
        _temp,
        writer,
        runtime,
        worker,
    } = fx;

    // The done-channel receives `run()`'s return value.  With the bug, the
    // deadline rejection causes `commit_pending` to return `Ok(false)` →
    // `break`, so `run()` returns immediately and this receive succeeds
    // (premature exit).  With the fix, the worker retries and stays alive,
    // so this times out.
    let (done_tx, done_rx) = crossbeam_channel::bounded::<Result<(), TxIndexWorkerError>>(1);
    let runtime_for_shutdown = Arc::clone(&runtime);
    std::thread::spawn(move || {
        let _ = done_tx.send(worker.run());
    });

    if let Ok(premature) = done_rx.recv_timeout(Duration::from_secs(2)) {
        panic!(
            "worker run() returned prematurely after deadline {rejection_label} \
             rejection instead of staying alive until explicit stop: {premature:?}"
        );
    }

    // The worker is still alive — request shutdown and collect the result.
    runtime_for_shutdown.request_shutdown();
    let run_result = done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("worker must shut down after request_shutdown");
    run_result.expect("run returned an error after shutdown");

    assert_eq!(
        tx_lookup_watermark(writer.as_ref()).map(|m| m.height),
        Some(1),
        "watermark must reach a1 after the retry"
    );
    assert!(
        runtime_for_shutdown.failure_message().is_none(),
        "a retryable {rejection_label} rejection must not publish a failure"
    );
}

#[test]
fn deadline_reset_rejection_keeps_run_alive_until_explicit_stop() {
    assert_deadline_liveness(deadline_liveness_fixture(1), "ResetInProgress");
}

#[test]
fn deadline_stale_index_state_keeps_run_alive_until_explicit_stop() {
    assert_deadline_liveness(deadline_liveness_fixture(2), "StaleIndexState");
}

#[test]
fn old_fence_pending_forward_stalls_then_converges_and_same_fence_change_stays_fatal() {
    let (_temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let genesis_id = tree
        .read()
        .node_at_height_from(f.a1_id, 0)
        .expect("genesis");
    let genesis_tip = Arc::new(tip_for(&tree.read(), genesis_id));
    applied_tip.store(Some(genesis_tip));
    let (runtime, worker) = make_worker(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
        u32::MAX,
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    assert_eq!(
        tx_lookup_watermark(writer.as_ref()).map(|m| m.height),
        Some(0)
    );

    // Extend to a1 and buffer a pending batch under the current fence.
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("buffer a1"),
        ReconcileAction::Buffered
    ));
    assert!(pending.is_some(), "pending batch buffered for a1");

    let old_fence = writer.fenced_watermarks().expect("fence").0;

    // Complete a reset — this changes the fence and clears the durable
    // watermarks.  The retained PendingForward still holds the old fence.
    writer
        .reset_capabilities(bitcoin_rs_index::IndexCapabilities::ALL)
        .expect("reset");
    let new_fence = writer.fenced_watermarks().expect("fence after reset").0;
    assert_ne!(
        old_fence, new_fence,
        "a completed reset must change the IndexWriteFence"
    );

    // With the bug, the stale-fence pending forward triggers the same-fence
    // watermark invariant and returns PendingDurableChanged (fatal).  With the
    // fix, the fence change is detected, the pending forward is discarded, and
    // Stalled is reported so the next pass can rebuild from the cleared state.
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("stalled under old fence"),
        ReconcileAction::Stalled
    ));
    assert!(
        pending.is_none(),
        "stale pending forward under the old fence must be discarded"
    );
    assert!(
        runtime.failure_message().is_none(),
        "a fence-change discard must not publish a failure"
    );

    // A later pass converges from the cleared durable state.
    run_until_caught_up(&worker, &mut pending);
    assert_eq!(
        tx_lookup_watermark(writer.as_ref()).map(|m| m.height),
        Some(1),
        "worker must rebuild to a1 after the reset"
    );

    // A watermark change under the SAME fence still produces
    // PendingDurableChanged — the fix must not swallow corruption.  The
    // `watermark_lag` flag deliberately creates a watermarks/fence
    // incoherence (lower tx_lookup watermark, unchanged fence) that a
    // real fence change would never pair with; this incoherence must
    // remain fatal so the StaleIndexState retry path cannot mask it.
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("buffer a2"),
        ReconcileAction::Buffered
    ));
    assert!(pending.is_some());

    // Simulate a durable watermark change without a reset (same fence):
    // the lag flag makes fenced_watermarks report a lower tx_lookup watermark
    // while the fence stays unchanged.
    writer.watermark_lag.store(true, Ordering::Release);
    let same_fence_result = worker.reconcile_once(&mut pending);
    writer.watermark_lag.store(false, Ordering::Release);
    assert!(
        matches!(
            same_fence_result,
            Err(TxIndexWorkerError::PendingDurableChanged)
        ),
        "a watermark change under the same fence must remain fatal"
    );
}

fn reopen_and_converge_to_b2(
    temp_path: &std::path::Path,
    reopened_bodies: Arc<dyn PruneBodyStore>,
    tree: &Arc<RwLock<BlockTree>>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    publisher: &Arc<crate::state::ChainEventPublisher>,
    b2_hash: Hash256,
) {
    let store = Arc::new(FjallStore::open(temp_path).expect("fjall reopen"));
    let inner: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store), 1).expect("writer reopen"),
    ));
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let worker = make_worker_with_events(
        &writer_dyn,
        applied_tip,
        tree,
        reopened_bodies,
        Arc::clone(publisher),
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    assert_eq!(
        writer.rollback_commits.load(Ordering::Acquire),
        0,
        "the reopened worker must not rewind again"
    );
    let cursor = writer
        .consumer_cursor()
        .expect("cursor read")
        .expect("cursor at b2");
    let decoded = crate::reconcile::ConsumerCursor::from_bytes(&cursor).expect("decode b2 cursor");
    assert_eq!((decoded.height, decoded.hash), (2, b2_hash));
    drop(store);
}

fn settle_rollback_and_reject_forward(
    temp_path: &std::path::Path,
    body_store: &Arc<dyn PruneBodyStore>,
    tree: &Arc<RwLock<BlockTree>>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    publisher: &Arc<crate::state::ChainEventPublisher>,
    a2_tip: &Arc<TipSnapshot>,
    b2_tip: &Arc<TipSnapshot>,
    a2_hash: Hash256,
) {
    let store = Arc::new(FjallStore::open(temp_path).expect("fjall open"));
    let inner: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store), 1).expect("index writer open"),
    ));
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    applied_tip.store(Some(Arc::clone(a2_tip)));
    publisher.record(
        crate::state::HintKind::Connected,
        a2_tip.height,
        a2_tip.hash,
    );
    let worker = make_worker_with_events(
        &writer_dyn,
        applied_tip,
        tree,
        Arc::clone(body_store),
        Arc::clone(publisher),
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    let a2_cursor = writer
        .consumer_cursor()
        .expect("cursor read")
        .expect("cursor at a2");
    let decoded =
        crate::reconcile::ConsumerCursor::from_bytes(&a2_cursor).expect("decode a2 cursor");
    assert_eq!((decoded.height, decoded.hash), (2, a2_hash));

    // Flip to the winning branch and reject the first forward commit: the
    // rollback pass must delete the cursor instead of republishing it.
    applied_tip.store(Some(Arc::clone(b2_tip)));
    publisher.record(
        crate::state::HintKind::Connected,
        b2_tip.height,
        b2_tip.hash,
    );
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("rollback pass"),
        ReconcileAction::Buffered
    ));
    assert_eq!(
        writer.rollback_clears.load(Ordering::Acquire),
        2,
        "both stale-branch rewinds must clear the consumer cursor"
    );
    assert!(
        writer.consumer_cursor().expect("cursor read").is_none(),
        "the stale-branch cursor must not survive its own rollback"
    );

    writer.fail_forward_once.store(1, Ordering::Release);
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("rejected forward pass"),
        ReconcileAction::Stalled
    ));
    assert!(
        pending.is_none(),
        "a rejected forward batch must be dropped"
    );
    drop(store);
}

#[test]
fn intermediate_rollback_deletes_cursor_and_survives_reopen() {
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    let (publisher_raw, _hints) = crate::state::ChainEventPublisher::detached(0);
    let publisher = Arc::new(publisher_raw);
    let temp = tempfile::tempdir().expect("tempdir");

    // Settle rows and the consumer cursor on the losing A-branch, then stop
    // after the rollback and a rejected first forward pass.
    settle_rollback_and_reject_forward(
        temp.path(),
        &body_store,
        &tree,
        &applied_tip,
        &publisher,
        &a2_tip,
        &b2_tip,
        f.a2.1,
    );

    // Reopen from disk: the deletion is durable, and reconciliation converges
    // to a fresh cursor naming the winning tip without another rewind.
    let reopened_bodies: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    reopen_and_converge_to_b2(
        temp.path(),
        reopened_bodies,
        &tree,
        &applied_tip,
        &publisher,
        f.b2.1,
    );
    drop(temp);
}

fn commit_b1_with_keep_and_verify_cursor_stays_deleted(
    worker: &Worker,
    writer: &Arc<RecordingWriter>,
    store: &Arc<FjallStore>,
    pending: &mut Option<PendingForward>,
    b1: &(Block, Hash256),
) {
    assert!(
        pending.take().is_some(),
        "the stale-branch reconciliation leaves B1 pending"
    );
    let prepared = writer
        .prepare_block_for(
            IndexCapabilities::ALL,
            1,
            b1.1.to_le_bytes(),
            &consensus_bytes(&b1.0),
        )
        .expect("prepare B1");
    let mut batch = PreparedBatch::new(DEFAULT_BATCH_LIMITS);
    assert!(batch.try_push(prepared).is_ok());
    let (fence, watermarks) = writer.fenced_watermarks().expect("fence B1 forward");
    let committed = worker
        .sync_and_commit(PendingForward {
            fence,
            watermarks,
            capabilities: IndexCapabilities::ALL,
            durable: None,
            batch,
            deadline: std::time::Instant::now(),
        })
        .expect("worker Keep forward B1");
    assert_eq!(
        committed,
        Some(IndexWatermark {
            height: 1,
            hash: b1.1.to_le_bytes(),
        }),
        "the worker returns the B1 watermark"
    );
    assert_eq!(
        tx_lookup_watermark(writer.as_ref()),
        Some(IndexWatermark {
            height: 1,
            hash: b1.1.to_le_bytes(),
        }),
        "the winning-branch ledger advances"
    );
    assert_eq!(
        rows_of(store, ColumnFamily::BlockHeaders).len(),
        2,
        "genesis and B1 rows remain committed"
    );
    assert!(
        writer
            .consumer_cursor()
            .expect("cursor after Keep")
            .is_none(),
        "Keep preserves the rollback's cursor deletion"
    );
}

#[test]
fn intermediate_rollback_removes_stale_cursor() {
    let (temp, store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
            (1, f.b1.1, &f.b1.0),
            (2, f.b2.1, &f.b2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    let (publisher_raw, _hints) = crate::state::ChainEventPublisher::detached(0);
    let publisher = Arc::new(publisher_raw);
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    publisher.record(
        crate::state::HintKind::Connected,
        a2_tip.height,
        a2_tip.hash,
    );
    let worker = make_worker_with_events(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        Arc::clone(&publisher),
    );
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    assert!(writer.consumer_cursor().expect("A-branch cursor").is_some());

    applied_tip.store(Some(Arc::clone(&b2_tip)));
    publisher.record(
        crate::state::HintKind::Connected,
        b2_tip.height,
        b2_tip.hash,
    );
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("rollback stale branch"),
        ReconcileAction::Buffered
    ));
    assert_eq!(
        writer.rollback_clears.load(Ordering::Acquire),
        2,
        "the stale-branch rewinds must clear the cursor"
    );
    assert_eq!(
        writer.rollback_commits.load(Ordering::Acquire),
        2,
        "the cutover rewinds per block below the cutover"
    );
    assert!(
        writer
            .consumer_cursor()
            .expect("cursor after rollback")
            .is_none(),
        "rollback removes the stale A-branch cursor"
    );

    // Commit the first winning-branch block through the worker while the
    // published snapshot remains B2. The B1 result must map to Keep,
    // preserving absence rather than resurrecting the deleted cursor.
    commit_b1_with_keep_and_verify_cursor_stays_deleted(
        &worker,
        &writer,
        &store,
        &mut pending,
        &f.b1,
    );
    drop(temp);
}

#[test]
fn stale_cursor_publish_is_skipped_when_watermarks_lag() {
    let (_temp, _store, inner) = fjall_store_writer();
    let writer = recording_writer(inner);
    let writer_dyn: Arc<dyn TxIndexWriter> = writer.clone();
    let f = fork_fixture();
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(
        bodies_map(&[
            (0, f.genesis.1, &f.genesis.0),
            (1, f.a1.1, &f.a1.0),
            (2, f.a2.1, &f.a2.0),
        ]),
        None,
    ));
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let a2_tip = Arc::new(tip_for(&tree.read(), f.a2_id));
    applied_tip.store(Some(Arc::clone(&a2_tip)));
    let (publisher_raw, _hints) = crate::state::ChainEventPublisher::detached(0);
    let publisher = Arc::new(publisher_raw);
    publisher.record(
        crate::state::HintKind::Connected,
        a2_tip.height,
        a2_tip.hash,
    );
    let worker = make_worker_with_events(
        &writer_dyn,
        &applied_tip,
        &tree,
        body_store,
        Arc::clone(&publisher),
    );
    let runtime = Arc::clone(&worker.runtime);
    let mut pending = None;
    run_until_caught_up(&worker, &mut pending);
    let settled_cursor = writer
        .consumer_cursor()
        .expect("cursor read")
        .expect("settled cursor");

    // A watermark lagging the snapshot inside the fence window must skip the
    // publish: the cursor would name a tip the durable rows do not support.
    writer.watermark_lag.store(true, Ordering::Release);
    publisher.record(
        crate::state::HintKind::Connected,
        a2_tip.height,
        a2_tip.hash,
    );
    assert!(matches!(
        worker.persist_chain_cursor(),
        Ok(CursorCommit::NotAligned)
    ));
    assert_eq!(
        writer.consumer_cursor().expect("cursor read").as_deref(),
        Some(settled_cursor.as_slice()),
        "a lagging watermark must preserve the old cursor"
    );
    assert!(runtime.failure_message().is_none());

    // Once the watermark catches up inside a fresh fence, the publish lands.
    writer.watermark_lag.store(false, Ordering::Release);
    assert!(matches!(
        worker.persist_chain_cursor(),
        Ok(CursorCommit::Settled)
    ));
    let advanced_cursor = writer
        .consumer_cursor()
        .expect("cursor read")
        .expect("aligned cursor");
    assert_ne!(advanced_cursor, settled_cursor);
    let advanced = crate::reconcile::ConsumerCursor::from_bytes(&advanced_cursor)
        .expect("decode aligned cursor");
    assert_eq!(advanced.height, a2_tip.height);
    assert_eq!(advanced.hash, a2_tip.hash);
}
// Grounding measurement for `DEFAULT_INDEX_ROLLBACK_REBUILD_CUTOVER`
// (run with `cargo test -p bitcoin-rs-node measure_rollback_vs_rebuild
// -- --ignored --nocapture`, three times; record medians of medians).
//
// Rebuild cost ~= tip_height x t_fw; rollback cost ~= depth x t_rb. The
// default routes the #208-style 834k stale branch to a rebuild while
// organic reorgs keep the per-block rewind.
//
// Each sample starts before fence capture. Forward and rollback therefore
// measure the same capture-plus-commit boundary, including the ordinary
// revision check and increment.
#[test]
#[ignore = "grounding measurement for the rollback-vs-rebuild cutover default"]
fn measure_rollback_vs_rebuild_per_block_medians() {
    const BLOCKS: usize = 512;

    let (_temp, writer) = fjall_writer();

    // Linear 512-block fixture: block h extends h-1; the coinbase extra
    // keeps every hash unique.
    let mut chain: Vec<(Hash256, Vec<u8>)> = Vec::with_capacity(BLOCKS + 1);
    let (genesis_block, genesis_hash) = mine_block(Hash256::from_le_bytes(&[0_u8; 32]), 0, 0);
    chain.push((genesis_hash, consensus_bytes(&genesis_block)));
    let mut prev_hash = genesis_hash;
    for height in 1..=BLOCKS {
        let height_u32 = u32::try_from(height).expect("block height fits in u32");
        let (block, hash) = mine_block(prev_hash, height_u32, i64::from(height_u32));
        prev_hash = hash;
        chain.push((hash, consensus_bytes(&block)));
    }

    // Forward ingest: one durable commit per block (t_fw samples).
    let mut forward_nanos: Vec<u128> = Vec::with_capacity(BLOCKS);
    for (height, (hash, body)) in chain.iter().enumerate() {
        let height_u32 = u32::try_from(height).expect("block height fits in u32");
        let prepared = writer
            .prepare_block(height_u32, hash.to_le_bytes(), body)
            .expect("prepare");
        let mut batch =
            bitcoin_rs_index::PreparedBatch::new(bitcoin_rs_index::PreparedBatchLimits {
                max_rows: 100_000,
                max_bytes: 64_000_000,
            });
        assert!(batch.try_push(prepared).is_ok());
        let started = std::time::Instant::now();
        let (fence, _) = writer.fenced_watermarks().expect("fenced watermarks");
        writer
            .commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)
            .expect("forward commit");
        forward_nanos.push(started.elapsed().as_nanos());
    }

    // Rollback: per-block rewind of all 512 through the worker's commit
    // path (t_rb samples).
    let mut rollback_nanos: Vec<u128> = Vec::with_capacity(BLOCKS);
    for (height, (_, body)) in chain.iter().enumerate().skip(1).rev() {
        let prev_hash = chain[height - 1].0;
        let prev_height = u32::try_from(height - 1).expect("block height fits in u32");
        let prev = IndexWatermark {
            height: prev_height,
            hash: prev_hash.to_le_bytes(),
        };
        let started = std::time::Instant::now();
        let (fence, _) = writer.fenced_watermarks().expect("fenced watermarks");
        writer
            .commit_rollback_one_for_with_cursor(
                fence,
                bitcoin_rs_index::IndexCapabilities::ALL,
                Some(prev),
                body,
                ConsumerCursorUpdate::Keep,
            )
            .expect("rollback commit");
        rollback_nanos.push(started.elapsed().as_nanos());
    }

    let median = |mut samples: Vec<u128>| {
        samples.sort_unstable();
        samples[samples.len() / 2]
    };
    let t_fw = median(forward_nanos);
    let t_rb = median(rollback_nanos);
    let derived = (100_000u128 * t_fw / t_rb.max(1)).clamp(1_000, 100_000);
    println!("t_fw median per-block forward commit: {t_fw} ns");
    println!("t_rb median per-block rollback commit: {t_rb} ns");
    println!(
        "DEFAULT_INDEX_ROLLBACK_REBUILD_CUTOVER = clamp(100_000 * t_fw / t_rb, 1_000, 100_000) = {derived}"
    );
}
