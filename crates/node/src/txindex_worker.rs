use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context as _, Result, anyhow};
use arc_swap::ArcSwapOption;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_index::{IndexConnect, TxIndexRuntime, TxIndexWriter};
use bitcoin_rs_primitives::Hash256;
use crossbeam_channel::Receiver;
use parking_lot::RwLock;

use crate::apply::PruneBodyStore;

type TxIndexHandle = Box<dyn TxIndexWriter>;
const FORWARD_BATCH_MAX_ROWS: usize = 250_000;
const FORWARD_BATCH_MAX_ROW_BYTES: usize = 8 * 1024 * 1024;
const FORWARD_BATCH_MAX_BLOCK_BYTES: usize = 16 * 1024 * 1024;
const STALE_RETRY_MAX_BACKOFF: Duration = Duration::from_millis(64);

/// All shared inputs owned by the dedicated `TxIndex` worker thread.
pub(crate) struct TxIndexWorker {
    indexer: TxIndexHandle,
    runtime: Arc<TxIndexRuntime>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<BlockTree>>,
    body_store: Arc<dyn PruneBodyStore>,
    wake_rx: Receiver<()>,
    shutdown: Arc<AtomicBool>,
}

enum AttemptError {
    Retry,
    Fatal(anyhow::Error),
}

impl TxIndexWorker {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        indexer: TxIndexHandle,
        runtime: Arc<TxIndexRuntime>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        body_store: Arc<dyn PruneBodyStore>,
        wake_rx: Receiver<()>,
        shutdown: Arc<AtomicBool>,
    ) -> Self {
        Self {
            indexer,
            runtime,
            applied_tip,
            block_tree,
            body_store,
            wake_rx,
            shutdown,
        }
    }

    pub(crate) fn run(mut self) {
        if let Err(error) = self.run_inner() {
            tracing::error!(%error, "TxIndex worker stopped");
            self.runtime.publish_failed(error.to_string());
        }
    }

    fn run_inner(&mut self) -> Result<()> {
        self.indexer.watermark()?;
        self.runtime.publish_healthy();
        self.reconcile()?;

        while !self.shutdown.load(Ordering::Acquire) {
            match self.wake_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(()) => self.reconcile()?,
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
            }
        }
        Ok(())
    }

    fn reconcile(&mut self) -> Result<()> {
        let mut stale_retries = 0_u32;
        loop {
            if self.shutdown.load(Ordering::Acquire) {
                return Ok(());
            }
            let Some(target) = self.applied_tip.load_full() else {
                return Ok(());
            };
            match self.reconcile_attempt(&target) {
                Ok(()) => stale_retries = 0,
                Err(AttemptError::Retry) => {
                    std::thread::sleep(stale_retry_backoff(stale_retries));
                    stale_retries = stale_retries.saturating_add(1);
                }
                Err(AttemptError::Fatal(error)) => return Err(error),
            }
            let watermark = self.indexer.watermark()?;
            let fresh = self.applied_tip.load_full();
            if fresh.as_deref().is_some_and(|tip| {
                watermark.is_some_and(|watermark| {
                    watermark.height == tip.height && watermark.hash == tip.hash
                })
            }) {
                return Ok(());
            }
        }
    }

    fn reconcile_attempt(
        &mut self,
        target: &TipSnapshot,
    ) -> core::result::Result<(), AttemptError> {
        let mut watermark = self.indexer.watermark().map_err(fatal)?;

        while let Some(current) = watermark {
            let on_target = if current.height > target.height {
                false
            } else {
                match self.hash_at(target, current.height) {
                    Some(hash) => hash == current.hash,
                    None => return Err(self.forward_lookup_failure(target, current.height)),
                }
            };
            if on_target {
                break;
            }
            if current.height == 0 {
                return Err(fatal(anyhow!(
                    "TxIndex and applied chain have no common genesis"
                )));
            }
            let block = self
                .load_body(current.height, current.hash)
                .map_err(fatal)?
                .ok_or_else(|| {
                    fatal(anyhow!(
                        "missing retained body for durable TxIndex watermark {} {}",
                        current.height,
                        current.hash
                    ))
                })?;
            self.indexer
                .rollback_block_atomic(&block, current)
                .map_err(fatal)?;
            watermark = Some(bitcoin_rs_index::IndexWatermark {
                height: current.height - 1,
                hash: Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array()),
            });
        }

        let start = watermark.map_or(0, |cursor| cursor.height.saturating_add(1));
        let mut batch = Vec::<(bitcoin::Block, u32, Hash256)>::new();
        let mut batch_rows = 0_usize;
        let mut batch_row_bytes = 0_usize;
        let mut batch_block_bytes = 0_usize;
        for height in start..=target.height {
            let Some(hash) = self.hash_at(target, height) else {
                return Err(self.forward_lookup_failure(target, height));
            };
            let (block, block_bytes) =
                match self.load_body_with_size(height, hash).map_err(fatal)? {
                    Some(loaded) => loaded,
                    None => return Err(self.forward_lookup_failure(target, height)),
                };
            let (rows, row_bytes) = estimated_index_work(&block);
            let exceeds_limit = !batch.is_empty()
                && (batch_rows.saturating_add(rows) > FORWARD_BATCH_MAX_ROWS
                    || batch_row_bytes.saturating_add(row_bytes) > FORWARD_BATCH_MAX_ROW_BYTES);
            let exceeds_limit = exceeds_limit
                || (!batch.is_empty()
                    && batch_block_bytes.saturating_add(block_bytes)
                        > FORWARD_BATCH_MAX_BLOCK_BYTES);
            if exceeds_limit {
                self.commit_forward_batch(&batch).map_err(fatal)?;
                batch.clear();
                batch_rows = 0;
                batch_row_bytes = 0;
                batch_block_bytes = 0;
            }
            batch.push((block, height, hash));
            batch_rows = batch_rows.saturating_add(rows);
            batch_row_bytes = batch_row_bytes.saturating_add(row_bytes);
            batch_block_bytes = batch_block_bytes.saturating_add(block_bytes);
        }
        if !batch.is_empty() {
            self.commit_forward_batch(&batch).map_err(fatal)?;
        }
        Ok(())
    }

    fn commit_forward_batch(&mut self, batch: &[(bitcoin::Block, u32, Hash256)]) -> Result<()> {
        let transitions = batch
            .iter()
            .map(|(block, height, hash)| IndexConnect {
                block,
                height: *height,
                hash: *hash,
            })
            .collect::<Vec<_>>();
        // The source bodies must reach stable storage before an independently
        // durable TxIndex watermark can claim them.
        self.body_store.sync()?;
        self.indexer.connect_blocks_atomic(&transitions)?;
        Ok(())
    }

    fn hash_at(&self, target: &TipSnapshot, height: u32) -> Option<Hash256> {
        let tree = self.block_tree.read();
        let id = tree.node_at_height_from(target.tip_id, height)?;
        tree.node(id).ok().map(|node| node.hash)
    }

    fn load_body(&self, height: u32, hash: Hash256) -> Result<Option<bitcoin::Block>> {
        Ok(self
            .load_body_with_size(height, hash)?
            .map(|(block, _)| block))
    }

    fn load_body_with_size(
        &self,
        height: u32,
        hash: Hash256,
    ) -> Result<Option<(bitcoin::Block, usize)>> {
        let Some(bytes) = self
            .body_store
            .load_block_body(height, hash)
            .with_context(|| format!("load retained block body {height} {hash}"))?
        else {
            return Ok(None);
        };
        let byte_len = bytes.len();
        let block = deserialize(&bytes)
            .with_context(|| format!("decode retained block body {height} {hash}"))?;
        Ok(Some((block, byte_len)))
    }

    fn forward_lookup_failure(&self, target: &TipSnapshot, height: u32) -> AttemptError {
        if self.applied_tip.load_full().as_deref() == Some(target) {
            fatal(anyhow!(
                "authoritative TxIndex target cannot resolve height/body {height}"
            ))
        } else {
            tracing::debug!(height, "TxIndex abandoned stale reconciliation target");
            AttemptError::Retry
        }
    }
}

fn fatal(error: impl Into<anyhow::Error>) -> AttemptError {
    AttemptError::Fatal(error.into())
}

fn stale_retry_backoff(consecutive_retries: u32) -> Duration {
    Duration::from_millis(1_u64 << consecutive_retries.min(6)).min(STALE_RETRY_MAX_BACKOFF)
}

fn estimated_index_work(block: &bitcoin::Block) -> (usize, usize) {
    let txids = block.txdata.len();
    let spending = block
        .txdata
        .iter()
        .flat_map(|tx| &tx.input)
        .filter(|input| !input.previous_output.is_null())
        .count();
    let funding = block
        .txdata
        .iter()
        .flat_map(|tx| &tx.output)
        .filter(|output| !matches!(output.script_pubkey.as_bytes().first(), Some(0x6a)))
        .count();
    let prefix_rows = txids.saturating_add(spending).saturating_add(funding);
    let rows = prefix_rows.saturating_add(1);
    let bytes = prefix_rows
        .saturating_mul(bitcoin_rs_index::HASH_PREFIX_ROW_SIZE)
        .saturating_add(bitcoin_rs_index::HEADER_ROW_SIZE);
    (rows, bytes)
}

#[cfg(all(test, feature = "fjall"))]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_index::{IndexWatermark, Indexer};
    use bitcoin_rs_storage::{FjallStore, StorageError};
    use crossbeam_channel::bounded;
    use hashbrown::HashMap;
    use parking_lot::Mutex;

    use super::*;

    #[derive(Default)]
    struct MapBodyStore {
        bodies: Mutex<HashMap<(u32, Hash256), Vec<u8>>>,
    }

    impl MapBodyStore {
        fn insert(&self, height: u32, block: &bitcoin::Block) -> Hash256 {
            let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            self.bodies
                .lock()
                .insert((height, hash), bitcoin::consensus::encode::serialize(block));
            hash
        }
    }

    impl PruneBodyStore for MapBodyStore {
        fn persist_block_body(
            &self,
            height: u32,
            hash: Hash256,
            body: &[u8],
        ) -> Result<(), StorageError> {
            self.bodies.lock().insert((height, hash), body.to_vec());
            Ok(())
        }

        fn load_block_body(
            &self,
            height: u32,
            hash: Hash256,
        ) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(self.bodies.lock().get(&(height, hash)).cloned())
        }

        fn sync(&self) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn child_block(parent: &bitcoin::Block, discriminator: u32) -> bitcoin::Block {
        let mut block = parent.clone();
        block.header.prev_blockhash = parent.block_hash();
        block.header.time = block.header.time.saturating_add(discriminator);
        block.header.nonce = discriminator;
        block
    }

    fn snapshot(tree: &BlockTree, id: bitcoin_rs_chain::NodeId) -> Result<TipSnapshot> {
        let node = tree.node(id)?;
        Ok(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
        })
    }

    fn worker(
        indexer: TxIndexHandle,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        tree: Arc<RwLock<BlockTree>>,
        bodies: Arc<MapBodyStore>,
    ) -> TxIndexWorker {
        let (_wake_tx, wake_rx) = bounded(1);
        TxIndexWorker::new(
            indexer,
            Arc::new(TxIndexRuntime::new()),
            applied_tip,
            tree,
            bodies,
            wake_rx,
            Arc::new(AtomicBool::new(false)),
        )
    }

    #[test]
    fn empty_index_bootstraps_to_captured_tip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let indexer: TxIndexHandle = Box::new(Indexer::new(Arc::clone(&store)));
        let bodies = Arc::new(MapBodyStore::default());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let child = child_block(&genesis, 1);
        bodies.insert(0, &genesis);
        let child_hash = bodies.insert(1, &child);

        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::Active)?;
        let child_id = tree.insert_header(child.header, NodeStatus::Active)?;
        let target = snapshot(&tree, child_id)?;
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(target)));

        worker(indexer, applied_tip, Arc::new(RwLock::new(tree)), bodies).reconcile()?;

        assert_eq!(
            Indexer::new(store).watermark()?,
            Some(IndexWatermark {
                height: 1,
                hash: child_hash,
            })
        );
        Ok(())
    }

    #[test]
    fn consumer_ahead_rolls_back_to_shorter_authoritative_tip() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut concrete = Indexer::new(Arc::clone(&store));
        let bodies = Arc::new(MapBodyStore::default());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let child = child_block(&genesis, 2);
        let genesis_hash = bodies.insert(0, &genesis);
        let child_hash = bodies.insert(1, &child);
        concrete.connect_block_atomic(&genesis, 0, genesis_hash)?;
        concrete.connect_block_atomic(&child, 1, child_hash)?;
        let indexer: TxIndexHandle = Box::new(concrete);

        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::Active)?;
        tree.insert_header(child.header, NodeStatus::Stale)?;
        let target = snapshot(&tree, genesis_id)?;
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(target)));

        worker(indexer, applied_tip, Arc::new(RwLock::new(tree)), bodies).reconcile()?;

        assert_eq!(
            Indexer::new(store).watermark()?,
            Some(IndexWatermark {
                height: 0,
                hash: genesis_hash,
            })
        );
        Ok(())
    }

    #[test]
    fn stale_fork_rolls_back_then_connects_authoritative_suffix() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut concrete = Indexer::new(Arc::clone(&store));
        let bodies = Arc::new(MapBodyStore::default());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let stale = child_block(&genesis, 3);
        let active = child_block(&genesis, 4);
        let genesis_hash = bodies.insert(0, &genesis);
        let stale_hash = bodies.insert(1, &stale);
        let active_hash = bodies.insert(1, &active);
        concrete.connect_block_atomic(&genesis, 0, genesis_hash)?;
        concrete.connect_block_atomic(&stale, 1, stale_hash)?;
        let indexer: TxIndexHandle = Box::new(concrete);

        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::Active)?;
        tree.insert_header(stale.header, NodeStatus::Stale)?;
        let active_id = tree.insert_header(active.header, NodeStatus::Active)?;
        let target = snapshot(&tree, active_id)?;
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(target)));

        worker(indexer, applied_tip, Arc::new(RwLock::new(tree)), bodies).reconcile()?;

        assert_eq!(
            Indexer::new(store).watermark()?,
            Some(IndexWatermark {
                height: 1,
                hash: active_hash,
            })
        );
        Ok(())
    }

    #[test]
    fn missing_body_for_unchanged_authoritative_target_fails_only_worker() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let indexer: TxIndexHandle = Box::new(Indexer::new(store));
        let bodies = Arc::new(MapBodyStore::default());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let mut tree = BlockTree::new();
        let genesis_id = tree.insert_header(genesis.header, NodeStatus::Active)?;
        let target = snapshot(&tree, genesis_id)?;
        let applied_tip = Arc::new(ArcSwapOption::empty());
        applied_tip.store(Some(Arc::new(target)));
        let runtime = Arc::new(TxIndexRuntime::new());
        let (_wake_tx, wake_rx) = bounded(1);
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker = TxIndexWorker::new(
            indexer,
            Arc::clone(&runtime),
            applied_tip,
            Arc::new(RwLock::new(tree)),
            bodies,
            wake_rx,
            Arc::clone(&shutdown),
        );

        worker.run();

        assert!(matches!(
            runtime.health(),
            bitcoin_rs_index::IndexWorkerHealth::Failed(_)
        ));
        assert!(
            !shutdown.load(Ordering::Acquire),
            "optional index failure must not request core shutdown"
        );
        Ok(())
    }

    #[test]
    fn stale_retry_backoff_is_bounded() {
        assert_eq!(stale_retry_backoff(0), Duration::from_millis(1));
        assert_eq!(stale_retry_backoff(3), Duration::from_millis(8));
        assert_eq!(stale_retry_backoff(32), STALE_RETRY_MAX_BACKOFF);
    }
}
