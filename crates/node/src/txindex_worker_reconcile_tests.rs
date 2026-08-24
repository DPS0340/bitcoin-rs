#![cfg(all(test, feature = "fjall"))]

use hashbrown::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bitcoin::{
    Amount, Block, BlockHash, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode, TxOut, Witness,
    block::Header as BlockHeader, block::Version, consensus::encode::serialize, hashes::Hash as _,
    pow::CompactTarget, script::Builder,
};
use bitcoin_rs_chain::{BlockTree, NodeId, NodeStatus, TipSnapshot};
use bitcoin_rs_index::PreparedBatchLimits;
use bitcoin_rs_primitives::Hash256;
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

fn coinbase_tx(height: u32, extra: i64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: Builder::new()
                .push_int(i64::from(height))
                .push_int(extra)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn mine_block(prev_hash: Hash256, height: u32, extra: i64) -> (Block, Hash256) {
    let prev_blockhash = BlockHash::from_byte_array(prev_hash.to_le_bytes());
    let txdata = vec![coinbase_tx(height, extra)];
    let mut block = Block {
        header: BlockHeader {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: height,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(TxMerkleNode::all_zeros);
    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    (block, hash)
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
        .map(|(height, hash, block)| ((*height, hash.to_le_bytes()), serialize(block)))
        .collect()
}

fn fjall_writer() -> (tempfile::TempDir, Arc<dyn TxIndexWriter>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(store).expect("index writer open"),
    ));
    (temp, writer)
}

fn make_worker(
    writer: &Arc<dyn TxIndexWriter>,
    applied_tip: &Arc<ArcSwapOption<TipSnapshot>>,
    tree: &Arc<RwLock<BlockTree>>,
    body_store: Arc<dyn PruneBodyStore>,
    batch_limits: PreparedBatchLimits,
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
        enabled: bitcoin_rs_index::IndexCapabilities::ALL,
        wake_rx,
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
fn divergent_capability_stops_at_convergence_then_advances_together() {
    let (_temp, writer) = fjall_writer();
    let f = fork_fixture();
    let tree = Arc::new(RwLock::new(f.tree));
    let applied_tip = make_applied_tip();
    let target = tip_for(&tree.read(), f.a2_id);
    let body_store: Arc<dyn PruneBodyStore> = Arc::new(MapBodyStore::new(HashMap::new(), None));
    let (_runtime, worker) = make_worker(
        &writer,
        &applied_tip,
        &tree,
        body_store,
        DEFAULT_BATCH_LIMITS,
    );
    let a1 = IndexWatermark {
        height: 1,
        hash: f.a1.1.to_le_bytes(),
    };

    let (capabilities, watermark, stop_height) = worker
        .forward_selection(
            IndexWatermarks {
                tx_lookup: Some(a1),
                electrum_history: None,
            },
            &target,
        )
        .expect("electrum catch-up selection");
    assert_eq!(capabilities, IndexCapabilities::ELECTRUM_HISTORY);
    assert_eq!(watermark, None);
    assert_eq!(stop_height, 1);

    let (capabilities, watermark, stop_height) = worker
        .forward_selection(
            IndexWatermarks {
                tx_lookup: Some(a1),
                electrum_history: Some(a1),
            },
            &target,
        )
        .expect("joint catch-up selection");
    assert_eq!(capabilities, IndexCapabilities::ALL);
    assert_eq!(watermark, Some(a1));
    assert_eq!(stop_height, 2);
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
    let (_runtime, worker) =
        make_worker(&writer, &applied_tip, &tree, body_arc, DEFAULT_BATCH_LIMITS);

    let mut pending = None;
    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
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
    let watermark = writer.watermark().unwrap().expect("A1 watermark");
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
    let watermark = writer.watermark().unwrap().expect("A2 watermark");
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
    );

    let mut pending = None;
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
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
    let watermark = writer.watermark().unwrap().expect("complete stale prefix");
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
    let watermark = writer.watermark().unwrap().expect("B2 watermark");
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
    );
    let mut pending = None;

    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
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
    let a2_watermark = writer.watermark().unwrap().expect("A2 watermark");

    // The tip is still A2. An already-selected rollback can nevertheless land.
    let a1_watermark = worker
        .rollback_one(bitcoin_rs_index::IndexCapabilities::ALL, a2_watermark)
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
    let watermark = writer.watermark().unwrap().expect("repaired A2 watermark");
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
    );
    let mut pending = None;

    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
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
    assert!(writer.watermark().unwrap().is_none());
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
    );
    let mut pending = None;
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
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
    let watermarks = writer.watermarks().expect("watermarks");
    let expected = Some(IndexWatermark {
        height: 2,
        hash: f.b2.1.to_le_bytes(),
    });
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.electrum_history, expected);
}

#[test]
fn missing_rollback_identity_resets_and_rebuilds_selected_capabilities() {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store)).expect("index writer open"),
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
    );
    let mut pending = None;
    assert!(matches!(
        worker
            .catch_up_to(
                &a2_tip,
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
    corrupt.delete(ColumnFamily::BlockHeaders, &serialize(&f.a2.0.header));
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
    let watermarks = writer.watermarks().expect("watermarks");
    assert_eq!(watermarks.tx_lookup, expected);
    assert_eq!(watermarks.electrum_history, expected);
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
    let (_runtime, worker) = make_worker(&writer, &applied_tip, &tree, body_store, batch_limits);
    let a1_tip = Arc::new(tip_for(&tree.read(), f.a1_id));
    applied_tip.store(Some(Arc::clone(&a1_tip)));
    let mut pending = None;

    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
                None,
                bitcoin_rs_index::IndexCapabilities::ALL,
                &mut pending
            )
            .expect("first pass"),
        ReconcileAction::Progressed
    ));
    let watermark = writer.watermark().unwrap().expect("genesis watermark");
    assert_eq!(watermark.height, 0);

    assert!(matches!(
        worker
            .catch_up_to(
                &a1_tip,
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
    let watermark = writer.watermark().unwrap().expect("A1 watermark");
    assert_eq!(
        (watermark.height, watermark.hash),
        (1, f.a1.1.to_le_bytes())
    );
}
