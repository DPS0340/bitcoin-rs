//! Deterministic regression tests for the lock-free canonical-prefix worker.
//!
//! The fixture builds two competing parent-linked branches from the regtest
//! genesis inside one `BlockTree`, stores each serialized body in a
//! map-backed `PruneBodyStore`, and drives the private `Worker` methods over
//! a real `Mutex<IndexWriter<FjallStore>>`: forward preparation may use a
//! stale same-chain target, and complete stale prefixes self-heal through the
//! normal rollback path.
//!
//! Named proving surface of `docs/contracts/indexing.md`: `IDX-05`
//! (reconciliation from a persisted watermark — ancestor connect,
//! abandoned-branch rollback to the common ancestor) and `IDX-06`
//! (prepared-prefix batching, one atomic commit per block or chunk).
use hashbrown::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_index::{IndexWatermark, IndexWriter};
use bitcoin_rs_primitives::encode::{consensus_bytes, double_sha256};
use bitcoin_rs_primitives::{Hash256, Header, Network, TxIn, TxOut};
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use parking_lot::Mutex;

use super::*;

/// Map-backed `PruneBodyStore` keyed by `(height, hash)` with a sync counter.
///
/// The default `reader()` implementation covers the worker's prefetch path.
struct MapBodyStore {
    bodies: HashMap<(u32, Hash256), Vec<u8>>,
    syncs: AtomicUsize,
}

impl MapBodyStore {
    fn new() -> Self {
        Self {
            bodies: HashMap::new(),
            syncs: AtomicUsize::new(0),
        }
    }

    fn insert(&mut self, height: u32, hash: Hash256, body: Vec<u8>) {
        self.bodies.insert((height, hash), body);
    }

    fn sync_count(&self) -> usize {
        self.syncs.load(Ordering::Acquire)
    }
}

impl PruneBodyStore for MapBodyStore {
    fn persist_block_body(
        &self,
        _height: u32,
        _hash: Hash256,
        _body: &[u8],
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn load_block_body(&self, height: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.bodies.get(&(height, hash)).cloned())
    }

    fn sync(&self) -> Result<(), StorageError> {
        self.syncs.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}

/// One parent-linked block with its serialized body and tree identity.
struct FixtureBlock {
    height: u32,
    hash: Hash256,
    block: Block,
    body: Vec<u8>,
}

/// Genesis plus two competing branches (`a` and `b`) in one `BlockTree`, a
/// real fjall-backed index writer, and the worker state around them.
struct CatchupFixture {
    worker: Worker,
    writer: Arc<Mutex<IndexWriter<bitcoin_rs_storage::FjallStore>>>,
    bodies: Arc<MapBodyStore>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    a: Vec<FixtureBlock>,
    b: Vec<FixtureBlock>,
    _dir: tempfile::TempDir,
}

impl CatchupFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let genesis = Network::Regtest.genesis_block();

        let genesis_hash = genesis.block_hash().0;
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let a = branch(&mut tree, genesis.block_hash(), 0xaa)?;
        let b = branch(&mut tree, genesis.block_hash(), 0xbb)?;

        let mut bodies = MapBodyStore::new();
        bodies.insert(0, genesis_hash, consensus_bytes(&genesis));
        for block in a.iter().chain(b.iter()) {
            bodies.insert(block.height, block.hash, block.body.clone());
        }
        let bodies = Arc::new(bodies);

        let dir = tempfile::tempdir()?;
        let store = Arc::new(bitcoin_rs_storage::FjallStore::open(dir.path())?);
        let writer = Arc::new(Mutex::new(IndexWriter::open(store, 1)?));

        let (wake_tx, wake_rx) = crossbeam_channel::bounded(4);
        let runtime = Arc::new(TxIndexRuntime::new(wake_tx));
        let applied_tip = Arc::new(ArcSwapOption::empty());
        let worker = Worker {
            runtime,
            writer: writer.clone(),
            applied_tip: Arc::clone(&applied_tip),
            block_tree: Arc::new(RwLock::new(tree)),
            body_store: Some(bodies.clone()),
            batch_limits: DEFAULT_BATCH_LIMITS,
            enabled: bitcoin_rs_index::IndexCapabilities::ALL,
            rollback_rebuild_cutover: u32::MAX,
            wake_rx,
            chain_events: crate::txindex_worker::detached_chain_publisher(),
            quiet_period: REVISION_QUIET_PERIOD,
            batch_delay: Duration::ZERO,
        };
        Ok(Self {
            worker,
            writer,
            bodies,
            applied_tip,
            a,
            b,
            _dir: dir,
        })
    }

    fn tip(&self, blocks: &[FixtureBlock]) -> Arc<TipSnapshot> {
        let last = blocks.last().expect("branch has blocks");
        let tree = self.worker.block_tree.read();
        let tip_id = tree.lookup(last.hash).expect("branch tip is in the tree");
        let node = tree.node(tip_id).expect("tree node exists");
        Arc::new(TipSnapshot {
            tip_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    }

    fn publish_tip(&self, blocks: &[FixtureBlock]) {
        self.applied_tip.store(Some(self.tip(blocks)));
    }

    fn watermark(&self) -> Result<Option<IndexWatermark>, Box<dyn std::error::Error>> {
        Ok(self.writer.lock().watermark()?)
    }

    /// True when no committed row references a block only present on `a`.
    fn no_a_only_rows(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let a_only_txids: Vec<Txid> = self
            .a
            .iter()
            .filter(|block| !self.b.iter().any(|other| other.hash == block.hash))
            .flat_map(|block| block.block.txs.iter().map(Tx::txid))
            .collect();
        let writer = self.writer.lock();
        let snapshot = writer.snapshot()?;
        for txid in a_only_txids {
            let scan = snapshot.transaction_rows(&txid, unlimited_scan())?;
            if !scan.rows.is_empty() {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

fn unlimited_scan() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    }
}
/// Mines two parent-linked blocks with distinct coinbase scripts so every
/// block hash differs, inserting each header into `tree`.
fn branch(
    tree: &mut BlockTree,
    mut prev: BlockHash,
    label: u8,
) -> Result<Vec<FixtureBlock>, Box<dyn std::error::Error>> {
    let mut blocks = Vec::new();
    for height in 1..=2 {
        let mut block = Block {
            header: Header {
                version: 1,
                prev_blockhash: prev,
                merkle_root: Hash256::default(),
                time: height,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![coinbase(label, height)],
        };
        block.header.merkle_root = merkle_root(&block)
            .ok_or_else(|| std::io::Error::other("fixture block has a merkle root"))?;
        while !pow_met(block.header.bits, block.block_hash().0) {
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("fixture nonce space"))?;
        }
        let block_hash = block.block_hash();
        let hash = block_hash.0;
        tree.insert_header(block.header, NodeStatus::HeaderValid)?;
        blocks.push(FixtureBlock {
            height,
            hash,
            body: consensus_bytes(&block),
            block,
        });
        prev = block_hash;
    }
    Ok(blocks)
}

fn coinbase(label: u8, height: u32) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint::default(),
            script_sig: vec![label, height.to_le_bytes()[0]],
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 50,
            script_pubkey: vec![0x51],
        }],
    }
}

/// Regtest-easy compact-target `PoW` check over the hash as a 256-bit
/// little-endian integer (mirrors `chain::pow::compact_is_met_by` for the
/// >3-exponent, 3-byte-mantissa forms these fixtures mine).
fn pow_met(bits: u32, hash: Hash256) -> bool {
    let exponent = u8::try_from(bits >> 24).unwrap_or(0);
    let mantissa = bits & 0x007f_ffff;
    if exponent <= 3 || exponent > 32 || mantissa > 0x00ff_ffff {
        return false;
    }
    let bytes = hash.as_byte_array();
    let low = usize::from(exponent - 3);
    let window =
        u32::from(bytes[low]) | u32::from(bytes[low + 1]) << 8 | u32::from(bytes[low + 2]) << 16;
    window <= mantissa && bytes[usize::from(exponent)..].iter().all(|&byte| byte == 0)
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

#[test]
fn catch_up_retains_prepared_prefix_until_descendant_target()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = CatchupFixture::new()?;
    fixture.worker.batch_delay = Duration::from_secs(1);
    let stale_target = fixture.tip(&fixture.a[..1]);
    fixture.publish_tip(&fixture.a);
    let mut pending = None;
    let (fence, watermarks) = fixture.writer.lock().fenced_watermarks()?;

    let action = fixture.worker.catch_up_to(
        &stale_target,
        fence,
        watermarks,
        None,
        bitcoin_rs_index::IndexCapabilities::ALL,
        &mut pending,
    )?;
    assert!(matches!(action, ReconcileAction::Progressed));
    assert_eq!(fixture.watermark()?, None);
    assert_eq!(fixture.bodies.sync_count(), 0);

    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::Buffered
    ));
    pending
        .as_mut()
        .expect("descendant extension must remain pending")
        .deadline = Instant::now();
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::CaughtUp
    ));
    let current = fixture.tip(&fixture.a);
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: current.height,
            hash: *current.hash.as_byte_array(),
        })
    );
    assert_eq!(
        fixture.bodies.sync_count(),
        1,
        "both prepared prefixes must share one durable commit"
    );
    Ok(())
}

#[test]
fn expired_pending_prefix_commits_before_descendant_extension()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = CatchupFixture::new()?;
    let stale_target = fixture.tip(&fixture.a[..1]);
    fixture.publish_tip(&fixture.a);
    let mut pending = None;
    let (fence, watermarks) = fixture.writer.lock().fenced_watermarks()?;

    assert!(matches!(
        fixture.worker.catch_up_to(
            &stale_target,
            fence,
            watermarks,
            None,
            bitcoin_rs_index::IndexCapabilities::ALL,
            &mut pending,
        )?,
        ReconcileAction::Progressed
    ));
    assert_eq!(fixture.watermark()?, None);
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::Progressed
    ));
    assert!(pending.is_none());
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: stale_target.height,
            hash: *stale_target.hash.as_byte_array(),
        })
    );
    assert_eq!(fixture.bodies.sync_count(), 1);

    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::CaughtUp
    ));
    assert_eq!(fixture.bodies.sync_count(), 2);
    Ok(())
}

#[test]
fn complete_rival_prefix_commits_and_repairs_on_next_pass() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = CatchupFixture::new()?;
    let target = fixture.tip(&fixture.a);
    fixture.publish_tip(&fixture.b);
    let mut pending = None;
    let (fence, watermarks) = fixture.writer.lock().fenced_watermarks()?;

    let action = fixture.worker.catch_up_to(
        &target,
        fence,
        watermarks,
        None,
        bitcoin_rs_index::IndexCapabilities::ALL,
        &mut pending,
    )?;

    assert!(
        matches!(action, ReconcileAction::Progressed),
        "the complete formerly-authoritative prefix must commit before repair"
    );
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: target.height,
            hash: *target.hash.as_byte_array(),
        }),
        "the complete stale prefix must remain internally consistent"
    );
    assert!(
        fixture.bodies.sync_count() >= 1,
        "bodies must be synced before the forward commit"
    );

    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::CaughtUp
    ));
    let current = fixture.tip(&fixture.b);
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: current.height,
            hash: *current.hash.as_byte_array(),
        }),
        "the next pass must replace the stale prefix"
    );
    Ok(())
}

#[test]
fn stale_watermark_self_heals_across_reorg() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = CatchupFixture::new()?;
    fixture.publish_tip(&fixture.a);
    let mut pending = None;
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::Buffered
    ));
    assert!(matches!(
        fixture.worker.reconcile_once(&mut pending)?,
        ReconcileAction::CaughtUp
    ));
    let a_tip = fixture.tip(&fixture.a);
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: a_tip.height,
            hash: *a_tip.hash.as_byte_array(),
        }),
        "the A tip must be fully indexed first"
    );

    // Reorg: the applied tip moves to the rival branch and the runtime wakes.
    fixture.publish_tip(&fixture.b);
    fixture.worker.runtime.wake();

    let mut action = ReconcileAction::Stalled;
    for _ in 0..8 {
        action = fixture.worker.reconcile_once(&mut pending)?;
        if matches!(action, ReconcileAction::CaughtUp) {
            break;
        }
    }
    assert!(
        matches!(action, ReconcileAction::CaughtUp),
        "the worker must catch up on the new chain"
    );

    let b_tip = fixture.tip(&fixture.b);
    assert_eq!(
        fixture.watermark()?,
        Some(IndexWatermark {
            height: b_tip.height,
            hash: *b_tip.hash.as_byte_array(),
        }),
        "the exact B watermark must replace the stale A one"
    );
    assert!(fixture.no_a_only_rows()?, "A-only rows must be rolled back");
    Ok(())
}
