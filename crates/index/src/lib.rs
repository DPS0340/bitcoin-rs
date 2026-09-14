#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Applied-block records shared with derived-index readers.
pub mod block_log;
/// Core-compatible capability status projection.
pub mod capabilities;
/// Confirmed block indexing over the workspace key-value store.
pub mod index;
/// Unconfirmed transaction row writing over the workspace key-value store.
pub mod mempool;
/// Derived-index query contracts shared with surface adapters.
pub mod query_api;
/// Derived-index reconciliation phase and exact capability watermark alignment.
pub mod reconcile;
/// Open-time recovery for disposable derived index storage.
pub mod recovery;
/// Asynchronous durable derived-index runtime.
pub mod runtime;
/// Stable electrs-shaped row types.
pub mod types;
/// Object-safe, fenced access to the durable index writer.
pub mod writer;

pub use block_log::{
    BlockLog, BlockRecord, cumulative_tx_count_through, record_at_height, record_at_height_hash,
};
pub use capabilities::{
    CapabilitySnapshot, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    TXINDEX_CAPABILITY, derived_index_status, disabled_txindex, txindex_snapshot,
};
pub use index::{
    BlockSource, ConsumerCursorUpdate, INDEX_FORMAT_VERSION, IndexCapabilities, IndexCapability,
    IndexError, IndexFormat, IndexReader, IndexRowCounts, IndexWatermark, IndexWatermarks,
    IndexWriteFence, IndexWriter, Indexer, MAX_LIVE_SCRIPT_SIZE, NoSpentScripts, PreparedBatch,
    PreparedBatchLimits, PreparedBlock, ScriptHistoryEntry, ScriptLiveScan, SpentCoinScripts,
    TxIndexScan, TxIndexScanRow, TxIndexSnapshot,
};
pub use mempool::{MempoolRowCounts, MempoolRowWriter};
pub use query_api::{
    DerivedIndexInfo, DerivedIndexQuery, RollbackWarningSource, ScriptHistoryRecord,
    ScriptIndexQuery, ScriptIndexRecord, ScriptIndexSnapshot, SpendingRecord, TxQueryError,
};
pub use runtime::{
    DEFAULT_BATCH_LIMITS, DEFAULT_ROLLBACK_REBUILD_CUTOVER, DerivedIndexCapability,
    DerivedIndexLifecycle, DerivedIndexOpenSpec, DerivedIndexQueryAdapter, DerivedIndexQueryEngine,
    DerivedIndexRuntime, DerivedIndexWorker, DerivedIndexWorkerError, Generation, IndexAheadSink,
    IndexBlockSource, OpenDerivedIndex, QueryEngineLive, REDB_BATCH_LIMITS, ROCKSDB_BATCH_LIMITS,
    open_derived_index_store_on_worker,
};
pub use types::{
    HASH_PREFIX_LEN, HASH_PREFIX_ROW_SIZE, HEADER_ROW_SIZE, HashPrefix, HashPrefixRow, HeaderRow,
    SCRIPT_LIVE_ROW_SIZE, ScriptHash, ScriptHashRow, ScriptLiveRow, SpendingPrefixRow, TxidRow,
};
