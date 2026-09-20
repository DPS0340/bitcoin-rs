//! Shared node runtime state and capability handles.
//!
//! Shared handles, checkpoint publication, and index lifecycle live with
//! `NodeState`. Construction, recovery, storage, events, and pruning retain
//! separate private implementations.

use crate::ApplyError;
use crate::NodeConfig;
use anyhow::Context as _;
use anyhow::Result;
use anyhow::bail;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::block_log::BlockLog;
use bitcoin_rs_index::runtime::DEFAULT_BATCH_LIMITS;
use bitcoin_rs_index::runtime::OpenDerivedIndex;
use bitcoin_rs_index::runtime::REDB_BATCH_LIMITS;
use bitcoin_rs_index::runtime::open_derived_index_store_on_worker;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::Block;
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_primitives::Txid;
use bitcoin_rs_rpc::context::NetworkState;
use bitcoin_rs_rpc::context::PruneService;
use bitcoin_rs_storage::KvStore;
use bitcoin_rs_storage::StorageBackend;
use bitcoin_rs_utxo::UtxoSet;
use crossbeam_channel::Receiver;
use crossbeam_channel::Sender;
pub use events::ChainEventHint;
pub use events::ChainEventPublisher;
pub use events::ChainSnapshot;
pub use events::HintKind;
use hashbrown::HashMap;
use parking_lot::Mutex;
use parking_lot::RwLock;
pub use prune::NodePruneService;
#[cfg(test)]
pub(crate) use restore::ResumeSource;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicU64;
use std::time::Duration;
use storage::NodeStorage;
use storage::StoredBlockBodySource;

#[path = "state_events.rs"]
mod events;
#[path = "state_maintenance.rs"]
pub(crate) mod maintenance;
#[path = "state_open.rs"]
mod open;
#[path = "state_prune.rs"]
mod prune;
#[path = "state_restore.rs"]
mod restore;
#[path = "state_storage.rs"]
mod storage;

// One active generation of outbound requests is enough to keep the drain fed;
// extra backlog is overload and must fail fast at producers.
pub(crate) const P2P_OUTBOUND_QUEUE_LIMIT: usize = 8;

// Bounds transient inbound-block buffering between the per-peer listener
// threads and the single-threaded `BlockSync::tick` drain. Decoded inbound
// blocks carry the full `Block` plus preserved wire bytes (up to ~4 MiB each),
// so an unbounded channel lets a fast or flooding peer accumulate blocks faster
// than they drain — an OOM vector. A full channel applies TCP backpressure to
// the sending peer's listener thread; `tick` drains independently and holds no
// lock a listener needs, so the bound cannot deadlock. Sized well above the
// in-flight request window (`PENDING_BUDGET` = 256) so honest delivery, which
// wakes the drain on every block, is never throttled.
pub(crate) const INBOUND_BLOCK_CHANNEL_LIMIT: usize = 512;

// Bounds inbound peer transactions between the per-peer listener threads and
// the single ingress consumer. A full channel applies TCP backpressure to
// that peer's read loop; other peers keep their own threads. Sized to absorb
// a burst of honest `tx` deliveries without stalling header/block traffic on
// the same connection under normal load.
pub(crate) const INBOUND_TX_CHANNEL_LIMIT: usize = 1_024;

/// Aggregate handle to a running node.
pub struct NodeState {
    /// Height the last clean checkpoint would restore to, 0 when none exists.
    ///
    /// Published by `write_clean_checkpoint` and read by the pruner, which must
    /// not delete an undo record a crash-restore would still need.
    durable_tip_height: Arc<AtomicU32>,
    config: NodeConfig,
    data_dir: PathBuf,
    #[cfg(test)]
    resume_source: ResumeSource,
    storage: NodeStorage,
    block_body_store: Arc<dyn bitcoin_rs_storage::block_body::BlockBodyStore>,
    utxo: Arc<UtxoSet>,
    coin_stats: Arc<bitcoin_rs_utxo::stats::CoinStatsListener>,
    derived_index_runtime: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexRuntime>>,
    derived_index_spawn: Option<TxIndexSpawn>,
    derived_index_worker: Option<bitcoin_rs_index::runtime::DerivedIndexWorker>,
    derived_index_lifecycle:
        Option<Arc<arc_swap::ArcSwap<bitcoin_rs_index::runtime::DerivedIndexLifecycle>>>,
    /// Stable query adapter for txindex/script-index, constructed before open.
    derived_index_adapter: Option<Arc<bitcoin_rs_index::runtime::DerivedIndexQueryAdapter>>,
    /// Live txindex facts for the RPC `getcapabilities` projection.
    derived_index_status: Arc<bitcoin_rs_index::runtime::DerivedIndexCapability>,
    prune_service: Option<Arc<dyn PruneService>>,
    zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    mempool: Arc<RwLock<Mempool>>,
    /// The single mutation gateway in front of `mempool`.
    mempool_gateway: Arc<bitcoin_rs_mempool::MempoolGateway>,
    /// Template-coordinator wake for authoritative mutations and tip moves.
    mining_generation: Arc<crate::mining::MiningGenerationSignal>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Cumulative transaction count through `applied_tip`, `0` when unknown.
    /// Shared with `Chainstate`, which maintains it, and with the RPC context.
    chain_tx_count: Arc<AtomicU64>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<BlockLog>>,
    transactions: Arc<RwLock<HashMap<Txid, Tx>>>,
    network: Arc<RwLock<NetworkState>>,
    /// Shared P2P admission switch controlled by `setnetworkactive`.
    network_active: Arc<AtomicBool>,
    /// Runtime owner of P2P workers, session table, and inbound channels.
    p2p: Arc<bitcoin_rs_p2p::P2pService>,
    peer_table: Arc<bitcoin_rs_p2p::PeerTable>,
    banned: Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>,
    p2p_outbound_tx: crossbeam_channel::Sender<std::net::SocketAddr>,
    inbound_blocks_tx: Sender<bitcoin_rs_p2p::InboundBlock>,
    inbound_tx_tx: Sender<bitcoin_rs_p2p::InboundTx>,
    inbound_tx_rx: Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>>,
    chain_events: Arc<ChainEventPublisher>,
    apply_handles: crate::apply::Chainstate,
    /// Derived consumers of committed chain events. Not held by `Chainstate`.
    followers: crate::chain_effects::ChainFollowers,
    sync: Arc<crate::BlockSync>,
    /// Process-wide rollback-evidence reporter (warning snapshot + marker).
    recovery_reporter: Arc<crate::recovery_reporter::RecoveryReporter>,
}

impl Drop for NodeState {
    fn drop(&mut self) {
        let _admission = self.apply_handles.admission.close();
        // Safety net: if `bounded_index_shutdown` was not called (e.g. in
        // tests that drop `NodeState` directly), request shutdown and join
        // any worker not already taken by `bounded_index_shutdown`.
        if let Some(runtime) = &self.derived_index_runtime {
            runtime.request_shutdown();
        }
        if let Some(worker) = self.derived_index_worker.take() {
            worker.join();
        }
    }
}

impl NodeState {
    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    #[cfg(test)]
    pub(crate) const fn resume_source(&self) -> ResumeSource {
        self.resume_source
    }

    /// Returns the configured storage backend that was opened.
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    /// Returns the shared UTXO set handle.
    #[must_use]
    pub fn utxo(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the shared coinstats listener handle.
    #[must_use]
    pub fn coin_stats(&self) -> Arc<bitcoin_rs_utxo::stats::CoinStatsListener> {
        Arc::clone(&self.coin_stats)
    }

    /// Returns the manual pruning service when pruning is enabled.
    #[must_use]
    pub fn prune_service(&self) -> Option<Arc<dyn PruneService>> {
        self.prune_service.as_ref().map(Arc::clone)
    }

    /// Returns the configured ZMQ publisher handle (default: `NoOpZmqPublisher`).
    #[must_use]
    pub fn zmq_publisher(&self) -> Arc<dyn crate::ZmqPublisher> {
        Arc::clone(&self.zmq_publisher)
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Returns the node-owned mutation gateway in front of `mempool`.
    ///
    /// Every mempool mutation in this process — RPC admission, embedded
    /// broadcast, reorg re-admission, block-connect eviction — commits
    /// through this one instance, so observers observe a single ordered
    /// stream.
    #[must_use]
    pub fn mempool_gateway(&self) -> Arc<bitcoin_rs_mempool::MempoolGateway> {
        Arc::clone(&self.mempool_gateway)
    }

    /// Returns the mining generation wake shared with the apply path and the
    /// gateway observer. The template coordinator attaches itself here.
    #[must_use]
    pub fn mining_generation_signal(&self) -> Arc<crate::mining::MiningGenerationSignal> {
        Arc::clone(&self.mining_generation)
    }

    /// Returns the shared best-chain tip handle.
    #[must_use]
    pub fn chain_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.chain_tip)
    }

    /// Returns the shared best-applied-block tip handle.
    ///
    /// This handle lags `chain_tip()` when headers are accepted ahead of blocks
    /// being downloaded and applied. RPC consumers showing user-visible state
    /// (best block hash, block count) read this; sync-progress consumers read
    /// `chain_tip()`.
    #[must_use]
    pub fn applied_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.applied_tip)
    }

    /// Returns the shared block-tree handle.
    #[must_use]
    pub fn block_tree(&self) -> Arc<RwLock<bitcoin_rs_chain::BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Shares the cumulative chain transaction-count handle with the RPC layer.
    #[must_use]
    pub fn chain_tx_count_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.chain_tx_count)
    }

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<BlockLog>> {
        Arc::clone(&self.blocks)
    }

    /// Returns a durable block body reader for metadata-only block records.
    #[must_use]
    pub(crate) fn block_body_source(&self) -> Arc<dyn BlockBodySource> {
        Arc::new(StoredBlockBodySource::new(Arc::clone(
            &self.block_body_store,
        )))
    }

    /// Returns the shared txid → transaction map exposed to RPC handlers.
    #[must_use]
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Tx>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared P2P admission switch exposed to RPC and P2P workers.
    #[must_use]
    pub fn network_active(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.network_active)
    }

    /// Returns the shared manual IP/subnet ban list exposed to RPC and P2P.
    #[must_use]
    pub fn banned_subnets(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>> {
        Arc::clone(&self.banned)
    }

    /// Returns the P2P runtime that owns workers and the session table.
    #[must_use]
    pub fn p2p(&self) -> Arc<bitcoin_rs_p2p::P2pService> {
        Arc::clone(&self.p2p)
    }

    #[must_use]
    /// Returns the authoritative table of live peer sessions.
    pub fn peer_table(&self) -> Arc<bitcoin_rs_p2p::PeerTable> {
        Arc::clone(&self.peer_table)
    }

    /// Returns the service-owned persistent addnode view.
    #[must_use]
    pub fn added_nodes(&self) -> Arc<RwLock<Vec<std::net::SocketAddr>>> {
        self.p2p.added_nodes_handle()
    }
    /// Returns a cloned sender that RPC `addnode` uses to request outbound P2P connections.
    #[must_use]
    pub fn p2p_outbound_sender(&self) -> crossbeam_channel::Sender<std::net::SocketAddr> {
        self.p2p_outbound_tx.clone()
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// blocks into for verification and relay.
    pub fn inbound_blocks_sender(&self) -> Sender<bitcoin_rs_p2p::InboundBlock> {
        self.inbound_blocks_tx.clone()
    }

    /// Returns the rollback-evidence reporter for `getblockchaininfo`.
    #[must_use]
    pub(crate) fn recovery_reporter(&self) -> Arc<crate::recovery_reporter::RecoveryReporter> {
        Arc::clone(&self.recovery_reporter)
    }

    /// Returns a cloned `Sender` that the P2P listener pushes inbound
    /// transactions into for mempool admission.
    pub fn inbound_tx_sender(&self) -> Sender<bitcoin_rs_p2p::InboundTx> {
        self.inbound_tx_tx.clone()
    }

    /// Returns the shared receiver handle drained by the tx-ingress consumer.
    #[must_use]
    pub fn inbound_tx_rx_handle(&self) -> Arc<Mutex<Receiver<bitcoin_rs_p2p::InboundTx>>> {
        Arc::clone(&self.inbound_tx_rx)
    }

    /// Returns the current coherent chain snapshot: the applied tip stamped
    /// with the process epoch and the commit sequence.
    #[must_use]
    pub fn active_chain_snapshot(&self) -> ChainSnapshot {
        self.chain_events.snapshot()
    }

    /// Returns the shared block-download orchestrator.
    #[must_use]
    pub fn sync(&self) -> Arc<crate::BlockSync> {
        Arc::clone(&self.sync)
    }

    /// Returns the process-wide shutdown signal shared by all runtime workers.
    #[must_use]
    pub fn shutdown(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.apply_handles.shutdown)
    }

    /// Clone of the chainstate facade used by apply, reorg, and sync.
    #[must_use]
    pub fn chainstate(&self) -> crate::apply::Chainstate {
        self.apply_handles.clone()
    }

    /// Clone of the derived-consumer set used after committed transitions.
    #[must_use]
    pub fn chain_followers(&self) -> crate::chain_effects::ChainFollowers {
        self.followers.clone()
    }

    /// Synthetically applies `block` as the next tip after consensus checks.
    ///
    /// Holds the chain transition through follower dispatch (`ARCH-07`).
    pub fn apply_block(&self, block: &Block) -> core::result::Result<TipSnapshot, ApplyError> {
        let outcome = self.followers.apply_connect(&self.apply_handles, block)?;
        Ok(outcome.tip)
    }

    /// Publishes a durable clean checkpoint and returns the published
    /// generation, or an error if there is no applied tip.
    ///
    /// This is the public boundary for the private checkpoint machinery; it
    /// keeps `CheckpointWrite`, `CheckpointError`, and the checkpoint module
    /// internal to the crate.
    pub fn publish_checkpoint(&self) -> Result<u64> {
        match self.write_clean_checkpoint()? {
            crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip => {
                bail!("checkpoint refused: no applied tip to publish")
            }
            crate::checkpoint::CheckpointWrite::Published { generation } => Ok(generation),
        }
    }

    /// Creates a [`crate::checkpoint::publisher::CheckpointPublisher`] from
    /// this state's shared handles, for the maintenance and publication
    /// paths that move it into a background thread.
    ///
    /// The publisher owns its own `Dir` handle (reopened from the data-dir
    /// path) and cloned `Arc`s, so it can be moved into a background thread
    /// without borrowing from `self`.
    pub(crate) fn checkpoint_publisher(
        &self,
    ) -> core::result::Result<
        crate::checkpoint::publisher::CheckpointPublisher,
        crate::checkpoint::CheckpointError,
    > {
        Ok(crate::checkpoint::publisher::CheckpointPublisher {
            admission: Arc::clone(&self.apply_handles.admission),
            undo_store: Arc::clone(&self.apply_handles.undo_store),
            durable_head: Arc::clone(&self.apply_handles.durable_head),
            block_body_store: Arc::clone(&self.block_body_store),
            applied_tip: Arc::clone(&self.applied_tip),
            checkpoint_data_dir: bitcoin_rs_storage::checkpoint::fs::open_data_dir(&self.data_dir)
                .map_err(crate::checkpoint::CheckpointError::Io)?,
            network: self.config.network,
            genesis_hash: self.config.network.genesis_block_hash(),
            block_tree: Arc::clone(&self.block_tree),
            utxo: Arc::clone(&self.utxo),
            coin_stats: Arc::clone(&self.coin_stats),
            chain_tx_count: Arc::clone(&self.chain_tx_count),
            journal: self.apply_handles.journal.clone(),
            data_dir: self.data_dir.clone(),
            chain_events: Arc::clone(&self.chain_events),
            durable_tip_height: Arc::clone(&self.durable_tip_height),
        })
    }

    pub(crate) fn write_clean_checkpoint(
        &self,
    ) -> core::result::Result<crate::checkpoint::CheckpointWrite, crate::checkpoint::CheckpointError>
    {
        self.checkpoint_publisher()?.publish()
    }

    /// Returns the node-owned complete transaction-index query adapter.
    #[must_use]
    pub fn derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        if !self.config.indexes.txindex {
            return None;
        }
        self.derived_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns transaction lookup for internal Esplora projections.
    ///
    /// `--scriptindex` builds this dependency as well, but that does not
    /// enable or advertise the Core `--txindex` contract.
    #[must_use]
    pub fn esplora_derived_index_query(
        &self,
    ) -> Option<Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery>> {
        self.derived_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::DerivedIndexQuery> = adapter.clone();
            q
        })
    }

    /// Returns the node-owned complete generic script-index query adapter.
    #[must_use]
    pub fn script_index_query(&self) -> Option<Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery>> {
        if !self.config.indexes.script_index.is_enabled() {
            return None;
        }
        self.derived_index_adapter.as_ref().map(|adapter| {
            let q: Arc<dyn bitcoin_rs_rpc::context::ScriptIndexQuery> = adapter.clone();
            q
        })
    }

    /// Starts the derived-index workers. Call only once the applied tip is
    /// authoritative — after crash recovery — so the index reconciles against
    /// the real chainstate and never mistakes a recovered gap for a stale branch.
    pub fn start_index_workers(&mut self) -> anyhow::Result<()> {
        let Some(spawn) = self.derived_index_spawn.take() else {
            return Ok(());
        };
        let runtime = self
            .derived_index_runtime
            .as_ref()
            .context("txindex runtime missing for a pending worker spawn")?;
        let lifecycle = self
            .derived_index_lifecycle
            .as_ref()
            .context("txindex lifecycle missing for a pending worker spawn")?;
        let worker = bitcoin_rs_index::runtime::DerivedIndexWorker::spawn_with_open(
            Arc::clone(runtime),
            spawn.spec,
            Arc::clone(lifecycle),
            spawn.generation,
            Arc::clone(&self.applied_tip),
            Arc::clone(&self.block_tree),
            Some(Arc::clone(&self.block_body_store)),
            spawn.block_source,
            Some(spawn.body_source),
            self.chain_events.clone(),
            spawn.recovery_reporter,
            Arc::clone(&self.apply_handles.shutdown),
            spawn.wake_rx,
        )
        .context("spawn txindex worker")?;
        self.derived_index_worker = Some(worker);
        Ok(())
    }

    /// Returns the live txindex status source for `getcapabilities`.
    #[must_use]
    pub fn derived_index_status(
        &self,
    ) -> Arc<dyn bitcoin_rs_rpc::capabilities::DerivedIndexCapabilitySource> {
        self.derived_index_status.clone()
    }

    /// Bounded txindex-worker shutdown: requests the worker shutdown, waits up
    /// to `deadline` for a clean join, and detaches on
    /// expiry. On detach, revokes the generation token and publishes
    /// `ShutdownAbandoned` so queries return typed `Unavailable` instead of
    /// hitting a torn reader.
    pub(crate) fn bounded_index_shutdown(&mut self, deadline: Duration) {
        let start = std::time::Instant::now();
        if let Some(runtime) = &self.derived_index_runtime {
            runtime.request_shutdown();
        }
        // Take the worker out of self so we can join it without holding self
        // mutably across the wait.
        let derived_index_worker = self.derived_index_worker.take();
        let tx_deadline = start + deadline;
        if let Some(mut worker) = derived_index_worker {
            while std::time::Instant::now() < tx_deadline {
                if worker.is_finished() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if worker.is_finished() {
                worker.join();
            } else {
                tracing::warn!("txindex worker still blocked; abandoning join");
                // Revoke the generation token so late publication is a no-op.
                if let Some(generation_token) = &worker.generation {
                    generation_token.revoke();
                }
                if let Some(lifecycle) = &self.derived_index_lifecycle {
                    lifecycle.store(Arc::new(
                        bitcoin_rs_index::runtime::DerivedIndexLifecycle::ShutdownAbandoned,
                    ));
                }
                // Poison the namespace so it cannot be reclaimed in this process.
                worker.poison_namespace();
                // Detach the join handle so Drop does not block on join.
                // The worker thread continues running but will exit after
                // shutdown is observed; Drop is a no-op for the handle.
                worker.detach();
            }
        }
    }
}

fn derived_index_capabilities(config: &NodeConfig) -> bitcoin_rs_index::IndexCapabilities {
    bitcoin_rs_index::IndexCapabilities {
        // Full ScriptIndex-backed Esplora responses need exact historical
        // transactions to render prevouts and calculate fees. `utxo` owns
        // only the compact live-output view and must not pay for TxLookup.
        // `derived_index_query` still exposes TxLookup to Core RPCs only for an
        // explicit --txindex configuration.
        tx_lookup: config.indexes.txindex || config.indexes.script_index.keeps_history(),
        script_history: config.indexes.script_index.keeps_history(),
        script_live: config.indexes.script_index.is_enabled(),
    }
}

fn build_derived_index_open_spec(
    config: &NodeConfig,
    txindex_cache_bytes: u64,
    epoch: u64,
) -> Result<Option<bitcoin_rs_index::runtime::DerivedIndexOpenSpec>> {
    let enabled = derived_index_capabilities(config);
    if enabled.is_empty() {
        return Ok(None);
    }
    if config.storage.prune_target_mb > 0 {
        bail!("transaction and script indexing are not compatible with -prune");
    }
    let canonical_data_root = config
        .data_dir
        .canonicalize()
        .unwrap_or_else(|_| config.data_dir.clone());
    let backend = config.storage.backend;
    let cache_bytes = txindex_cache_bytes;
    Ok(Some(bitcoin_rs_index::runtime::DerivedIndexOpenSpec {
        data_dir: config.data_dir.clone(),
        namespace: "txindex",
        storage_backend: config.storage.backend,
        epoch,
        enabled,
        rollback_rebuild_cutover: bitcoin_rs_index::runtime::DEFAULT_ROLLBACK_REBUILD_CUTOVER,
        canonical_data_root,
        open_store: Arc::new(move |dir| {
            crate::storage_backend::open_txindex(
                backend,
                dir,
                Some(cache_bytes),
                DerivedIndexComposer { backend, epoch },
            )
        }),
        utxo: None,
        chain_transition: None,
    }))
}

struct DerivedIndexComposer {
    backend: StorageBackend,
    epoch: u64,
}

impl crate::storage_backend::StoreConsumer for DerivedIndexComposer {
    type Output = OpenDerivedIndex;
    type Error = bitcoin_rs_index::runtime::DerivedIndexWorkerError;

    fn consume<S>(self, store: Arc<S>) -> Result<Self::Output, Self::Error>
    where
        S: KvStore,
    {
        let batch_limits = match self.backend {
            StorageBackend::RocksDb | StorageBackend::Fjall => DEFAULT_BATCH_LIMITS,
            StorageBackend::Redb => REDB_BATCH_LIMITS,
        };
        open_derived_index_store_on_worker(store, batch_limits, self.epoch)
    }
}

struct TxIndexSpawn {
    spec: bitcoin_rs_index::runtime::DerivedIndexOpenSpec,
    generation: bitcoin_rs_index::runtime::Generation,
    block_source: bitcoin_rs_index::runtime::IndexBlockSource,
    body_source: Arc<dyn BlockBodySource>,
    wake_rx: Receiver<()>,
    recovery_reporter: Arc<crate::recovery_reporter::RecoveryReporter>,
}

#[cfg(test)]
#[path = "../tests/unit/state/tests/mod.rs"]
mod tests;
