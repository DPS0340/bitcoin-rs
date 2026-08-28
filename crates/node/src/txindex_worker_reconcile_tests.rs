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
    assert_eq!(watermarks.script_history, expected);
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
    );
    let mut pending = None;

    assert!(matches!(
        worker
            .catch_up_to(&a2_tip, None, IndexCapabilities::ALL, &mut pending)
            .expect("initial catch-up"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker.reconcile_once(&mut pending).expect("settle A2"),
        ReconcileAction::CaughtUp
    ));

    worker.enabled = IndexCapabilities::TX_LOOKUP;
    let b2_tip = Arc::new(tip_for(&tree.read(), f.b2_id));
    applied_tip.store(Some(Arc::clone(&b2_tip)));
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("move tx lookup to B2"),
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        worker
            .reconcile_once(&mut pending)
            .expect("settle tx lookup at B2"),
        ReconcileAction::CaughtUp
    ));
    let a2 = Some(IndexWatermark {
        height: 2,
        hash: f.a2.1.to_le_bytes(),
    });
    let b2 = Some(IndexWatermark {
        height: 2,
        hash: f.b2.1.to_le_bytes(),
    });
    assert_eq!(
        writer.watermarks().expect("divergent watermarks"),
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
        writer.watermarks().expect("watermarks during rebuild"),
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
        writer.watermarks().expect("rebuilt watermarks"),
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

// ---------------------------------------------------------------------------
// #77 convergence harness: an interrupted consumer must converge to the same
// index state as an uninterrupted one.
// ---------------------------------------------------------------------------

/// Fjall store plus writer, keeping the store handle for state dumps.
fn fjall_store_writer() -> (tempfile::TempDir, Arc<FjallStore>, Arc<dyn TxIndexWriter>) {
    let temp = tempfile::tempdir().expect("tempdir");
    let store = Arc::new(FjallStore::open(temp.path()).expect("fjall open"));
    let writer: Arc<dyn TxIndexWriter> = Arc::new(parking_lot::Mutex::new(
        bitcoin_rs_index::IndexWriter::open(Arc::clone(&store)).expect("index writer open"),
    ));
    (temp, store, writer)
}
/// Reserved consumer-cursor slot in `UtxoMeta` (`0x00, b'C'`), mirrored from
/// the index crate's metadata-key family so the dump can exclude it.
const CURSOR_META_KEY: &[u8] = &[0x00, b'C'];

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

/// Byte dump of every index row and metadata entry except the epoch-scoped
/// consumer cursor, whose epoch/sequence legitimately differ across runs.
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
            if family == ColumnFamily::UtxoMeta && key == CURSOR_META_KEY {
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
