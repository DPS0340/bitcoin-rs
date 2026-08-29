//! BIP157/158 basic block filter index as a reconciliation consumer extension.
//!
//! This crate owns the *domain* half of the reference extension: BIP158 filter
//! construction, BIP157 filter-header chaining, and the durable namespace
//! schema. The node crate (`bitcoin-rs-node`) owns the worker loop that
//! reconciles this schema against the chain-event seam, mirroring how
//! `bitcoin-rs-index` and the txindex worker split responsibilities.
//!
//! Namespace layout: the extension opens its own store directory
//! (`data_dir/<namespace>`); every row lives in one byte-keyed column family
//! available on every backend. Keys carry ASCII/0x00 namespaces:
//!
//! | key | value |
//! |---|---|
//! | `0x00,V` | schema version, u32 LE |
//! | `0x00,P` | active filter-header pointer: height u32 LE + block hash 32 |
//! | `0x00,C` | consumer cursor, [`CURSOR_BYTE_LEN`] bytes |
//! | `0x00,S` | lifecycle state, u8 (`0` building, `1` caught up) |
//! | `b'f'` + hash32 | serialized BIP158 basic filter |
//! | `b'h'` + hash32 | BIP157 filter header, 32 bytes |
//!
//! Filter and header rows are hash-addressed and therefore reorg-safe: a
//! disconnect rewinds only the active pointer and the consumer cursor; rows
//! are retained and re-derived rows are idempotent overwrites. The row batch,
//! the pointer, the cursor, and the lifecycle state commit in one atomic
//! store batch, so a crash can tear nothing apart.

use std::sync::Arc;

use bitcoin::bip158::{BlockFilter, BlockFilterWriter, FilterHeader};
use bitcoin::hashes::Hash as _;
use bitcoin_rs_ext_api::ExtensionDescriptor;
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};
use thiserror::Error;

/// Durable consumer-cursor byte length; matches the shared reconciliation
/// layout (`epoch` 8 LE, `sequence` 8 LE, `height` 4 LE, `hash` 32).
pub const CURSOR_BYTE_LEN: usize = 52;

/// Schema version of this extension's namespace.
pub const SCHEMA_VERSION: u32 = bitcoin_rs_ext_api::EXT_SCHEMA_VERSION;

/// Capability id provided by this extension.
pub const CAPABILITY_ID: &str = "blockfilterindex";

/// Namespace directory name under the node data dir.
pub const NAMESPACE: &str = "blockfilterindex";

/// Static descriptor contributed by this compiled extension.
pub const DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: CAPABILITY_ID,
    name: "Basic block filter index (BIP157/158)",
    namespace: NAMESPACE,
    schema_version: SCHEMA_VERSION,
    requires: &["txindex"],
    incompatible_with: &["prune"],
};

/// Reserved metadata keys and row prefixes in the namespace store.
mod keys {
    /// Schema version marker.
    pub(crate) const SCHEMA: &[u8] = &[0x00, b'V'];
    /// Active filter-header pointer.
    pub(crate) const POINTER: &[u8] = &[0x00, b'P'];
    /// Consumer cursor.
    pub(crate) const CURSOR: &[u8] = &[0x00, b'C'];
    /// Lifecycle state.
    pub(crate) const STATE: &[u8] = &[0x00, b'S'];
    /// Prefix of hash-addressed filter rows.
    pub(crate) const FILTER_ROW: u8 = b'f';
    /// Prefix of hash-addressed filter-header rows.
    pub(crate) const HEADER_ROW: u8 = b'h';
}
/// Lifecycle state persisted with every batch.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// Rows do not yet mirror the pointer block's active-chain prefix.
    Building,
    /// Rows mirror the pointer block's active-chain prefix.
    CaughtUp,
}

impl LifecycleState {
    /// Encodes the durable one-byte form.
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Building => 0,
            Self::CaughtUp => 1,
        }
    }

    /// Decodes the durable one-byte form; `None` on unknown values.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Building),
            1 => Some(Self::CaughtUp),
            _ => None,
        }
    }
}

/// Active filter-header pointer: the newest block whose filter header the
/// namespace's header chain provably ends at.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ActivePointer {
    /// Pointer block height.
    pub height: u32,
    /// Pointer block hash, consensus little-endian.
    pub hash: [u8; 32],
}

/// Durable consumer cursor in the shared 52-byte reconciliation layout.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StoredCursor {
    /// Process epoch the consumed events belong to.
    pub epoch: u64,
    /// Commit-counter value of the last consumed event.
    pub sequence: u64,
    /// Height of the last consumed block.
    pub height: u32,
    /// Hash of the last consumed block, consensus little-endian.
    pub hash: [u8; 32],
}

impl StoredCursor {
    /// Encodes the durable representation.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; CURSOR_BYTE_LEN] {
        let mut bytes = [0_u8; CURSOR_BYTE_LEN];
        bytes[..8].copy_from_slice(&self.epoch.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.height.to_le_bytes());
        bytes[20..].copy_from_slice(&self.hash);
        bytes
    }

    /// Decodes the durable representation; `None` on any length mismatch.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != CURSOR_BYTE_LEN {
            return None;
        }
        let mut epoch = [0_u8; 8];
        epoch.copy_from_slice(&bytes[..8]);
        let mut sequence = [0_u8; 8];
        sequence.copy_from_slice(&bytes[8..16]);
        let mut height = [0_u8; 4];
        height.copy_from_slice(&bytes[16..20]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes[20..]);
        Some(Self {
            epoch: u64::from_le_bytes(epoch),
            sequence: u64::from_le_bytes(sequence),
            height: u32::from_le_bytes(height),
            hash,
        })
    }
}

/// Errors raised while reading or writing the filter namespace.
#[derive(Debug, Error)]
pub enum FilterStoreError {
    /// Backend storage failed.
    #[error("filter index storage error: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    /// The namespace holds rows but carries no schema version.
    #[error("filter index namespace has rows but no schema version")]
    UnversionedRows,
    /// The namespace was written by an incompatible schema version.
    #[error("filter index schema version {found} is not supported (expected {expected})")]
    SchemaMismatch {
        /// Version found in the namespace.
        found: u32,
        /// Version this build supports.
        expected: u32,
    },
    /// A persisted pointer, cursor, or state value is malformed.
    #[error("filter index metadata is corrupt: {0}")]
    CorruptMetadata(&'static str),
}

/// The column family holding every row of the filter namespace.
///
/// The namespace owns its own store directory, so this logical family is
/// private to the extension; byte keys and variable-length values keep the
/// layout identical across every backend.
pub const NAMESPACE_CF: ColumnFamily = ColumnFamily::UtxoMeta;

/// One mutation inside an atomic namespace batch.
#[derive(Debug)]
pub enum FilterOp {
    /// Insert or replace one key.
    Put {
        /// Namespaced key.
        key: Vec<u8>,
        /// Row value.
        value: Vec<u8>,
    },
}

/// Builder for one atomic namespace write.
///
/// Every mutation a reconciliation pass produces — new filter and header
/// rows, the active pointer, the consumer cursor, and the lifecycle state —
/// is collected here and applied in a single [`KvStore::write`], so readers
/// never observe a torn namespace.
#[derive(Debug, Default)]
pub struct FilterBatch {
    ops: Vec<FilterOp>,
}

impl FilterBatch {
    /// Creates an empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether nothing has been collected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }

    /// Collects one hash-addressed filter row.
    pub fn put_filter(&mut self, hash: [u8; 32], filter: &[u8]) {
        self.put(row_key(keys::FILTER_ROW, hash), filter.to_vec());
    }

    /// Collects one hash-addressed filter-header row.
    pub fn put_header(&mut self, hash: [u8; 32], header: [u8; 32]) {
        self.put(row_key(keys::HEADER_ROW, hash), header.to_vec());
    }

    /// Collects the active filter-header pointer.
    pub fn put_pointer(&mut self, pointer: ActivePointer) {
        let mut value = Vec::with_capacity(36);
        value.extend_from_slice(&pointer.height.to_le_bytes());
        value.extend_from_slice(&pointer.hash);
        self.put(keys::POINTER.to_vec(), value);
    }

    /// Collects the consumer cursor.
    pub fn put_cursor(&mut self, cursor: &StoredCursor) {
        self.put(keys::CURSOR.to_vec(), cursor.to_bytes().to_vec());
    }

    /// Collects the lifecycle state.
    pub fn put_state(&mut self, state: LifecycleState) {
        self.put(keys::STATE.to_vec(), vec![state.to_u8()]);
    }

    /// Collects the schema version marker.
    pub fn put_schema_version(&mut self) {
        self.put(keys::SCHEMA.to_vec(), SCHEMA_VERSION.to_le_bytes().to_vec());
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.ops.push(FilterOp::Put { key, value });
    }

    /// Consumes the batch and returns the collected mutations.
    pub fn into_ops(self) -> Vec<FilterOp> {
        self.ops
    }
}

fn row_key(prefix: u8, hash: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(33);
    key.push(prefix);
    key.extend_from_slice(&hash);
    key
}

/// Object-safe facade over the typed namespace store.
///
/// The node worker and query engine hold this trait object so the store can
/// be instantiated per storage backend without the node depending on concrete
/// backend types. Test doubles implement it to drive failure injection.
pub trait FilterStoreOps: Send + Sync {
    /// Reads the stored schema version, `None` when absent.
    fn schema_version(&self) -> Result<Option<u32>, FilterStoreError>;

    /// Returns whether the namespace holds no schema marker and no rows.
    fn is_fresh(&self) -> Result<bool, FilterStoreError>;

    /// Applies one batch atomically.
    fn apply(&self, batch: FilterBatch) -> Result<(), FilterStoreError>;

    /// Reads one filter row.
    fn filter_row(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, FilterStoreError>;

    /// Reads one filter-header row.
    fn header_row(&self, hash: [u8; 32]) -> Result<Option<[u8; 32]>, FilterStoreError>;

    /// Reads the active pointer.
    fn pointer(&self) -> Result<Option<ActivePointer>, FilterStoreError>;

    /// Reads the consumer cursor.
    fn cursor(&self) -> Result<Option<StoredCursor>, FilterStoreError>;

    /// Reads the lifecycle state; a fresh namespace reads `None`.
    fn state(&self) -> Result<Option<LifecycleState>, FilterStoreError>;
}

/// Typed namespace store over any workspace backend.
pub struct FilterStore<S: KvStore + Send + Sync> {
    store: Arc<S>,
}

impl<S: KvStore + Send + Sync> FilterStore<S> {
    /// Wraps an already-opened namespace store.
    #[must_use]
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, FilterStoreError> {
        self.store
            .get(NAMESPACE_CF, key)
            .map_err(FilterStoreError::from)
    }
}

impl<S: KvStore + Send + Sync> FilterStoreOps for FilterStore<S> {
    fn schema_version(&self) -> Result<Option<u32>, FilterStoreError> {
        let bytes = self.get(keys::SCHEMA)?;
        Ok(match bytes {
            None => None,
            Some(bytes) if bytes.len() == 4 => {
                Some(u32::from_le_bytes(bytes.try_into().map_err(|_| {
                    FilterStoreError::CorruptMetadata("schema version")
                })?))
            }
            Some(_) => return Err(FilterStoreError::CorruptMetadata("schema version")),
        })
    }

    fn is_fresh(&self) -> Result<bool, FilterStoreError> {
        if self.schema_version()?.is_some() {
            return Ok(false);
        }
        Ok(self.get(keys::POINTER)?.is_none()
            && self.get(keys::CURSOR)?.is_none()
            && self.get(keys::STATE)?.is_none())
    }

    fn apply(&self, batch: FilterBatch) -> Result<(), FilterStoreError> {
        if batch.is_empty() {
            return Ok(());
        }
        let mut write_batch = self.store.new_batch();
        for op in batch.into_ops() {
            match op {
                FilterOp::Put { key, value } => write_batch.put(NAMESPACE_CF, &key, &value),
            }
        }
        self.store
            .write(write_batch)
            .map_err(FilterStoreError::from)
    }

    fn filter_row(&self, hash: [u8; 32]) -> Result<Option<Vec<u8>>, FilterStoreError> {
        self.get(&row_key(keys::FILTER_ROW, hash))
    }

    fn header_row(&self, hash: [u8; 32]) -> Result<Option<[u8; 32]>, FilterStoreError> {
        let bytes = self.get(&row_key(keys::HEADER_ROW, hash))?;
        match bytes {
            None => Ok(None),
            Some(bytes) if bytes.len() == 32 => {
                Ok(Some(bytes.try_into().map_err(|_| {
                    FilterStoreError::CorruptMetadata("filter header row")
                })?))
            }
            Some(_) => Err(FilterStoreError::CorruptMetadata("filter header row")),
        }
    }

    fn pointer(&self) -> Result<Option<ActivePointer>, FilterStoreError> {
        let bytes = self.get(keys::POINTER)?;
        match bytes {
            None => Ok(None),
            Some(bytes) if bytes.len() == 36 => {
                let mut height = [0_u8; 4];
                height.copy_from_slice(&bytes[..4]);
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(&bytes[4..]);
                Ok(Some(ActivePointer {
                    height: u32::from_le_bytes(height),
                    hash,
                }))
            }
            Some(_) => Err(FilterStoreError::CorruptMetadata("active pointer")),
        }
    }

    fn cursor(&self) -> Result<Option<StoredCursor>, FilterStoreError> {
        let bytes = self.get(keys::CURSOR)?;
        match bytes {
            None => Ok(None),
            Some(bytes) => StoredCursor::from_bytes(&bytes)
                .map(Some)
                .ok_or(FilterStoreError::CorruptMetadata("consumer cursor")),
        }
    }

    fn state(&self) -> Result<Option<LifecycleState>, FilterStoreError> {
        let bytes = self.get(keys::STATE)?;
        match bytes {
            None => Ok(None),
            Some(bytes) if bytes.len() == 1 => Ok(LifecycleState::from_u8(bytes[0])),
            Some(_) => Err(FilterStoreError::CorruptMetadata("lifecycle state")),
        }
    }
}

/// Computes the BIP158 basic filter for `block`.
///
/// Spent-output scripts are resolved through `script_for_coin`; the closure
/// returns `None` when the prevout cannot be resolved, which fails the whole
/// filter rather than silently indexing an incomplete set.
pub fn basic_filter_for_block(
    block: &bitcoin::Block,
    mut script_for_coin: impl FnMut(&bitcoin::OutPoint) -> Option<bitcoin::ScriptBuf>,
) -> Result<Vec<u8>, bitcoin::bip158::Error> {
    let mut encoded = Vec::new();
    let mut writer = BlockFilterWriter::new(&mut encoded, block);
    writer.add_output_scripts();
    // rust-bitcoin's `add_input_scripts` binds its provider as `Fn`, so the
    // mutable resolver sits behind a `RefCell` and the closure stays `Fn`.
    let script_for_coin = core::cell::RefCell::new(&mut script_for_coin);
    writer.add_input_scripts(|outpoint| {
        let mut resolve = script_for_coin.borrow_mut();
        (*resolve)(outpoint).ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
    })?;
    writer.finish()?;
    Ok(encoded)
}

/// Chains one BIP157 filter header onto `previous_header`.
#[must_use]
pub fn filter_header(content: &[u8], previous_header: &[u8; 32]) -> [u8; 32] {
    let filter = BlockFilter::new(content);
    let previous = FilterHeader::from_byte_array(*previous_header);
    filter.filter_header(&previous).to_byte_array()
}

/// The all-zero parent header anchoring the filter-header chain at genesis.
#[must_use]
pub fn zero_filter_header() -> [u8; 32] {
    [0_u8; 32]
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::absolute;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::transaction::{Transaction, TxOut, Version};
    use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, TxIn, Witness};
    use bitcoin_rs_storage::{StorageError, WriteBatch};

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    fn child_block(parent: &bitcoin::Block) -> bitcoin::Block {
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
        let spent = Transaction {
            version: Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent.txdata[0].compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_hex("52").expect("op_2"),
            }],
        };
        let mut block = bitcoin::Block {
            header: parent.header,
            txdata: vec![coinbase, spent],
        };
        block.header.prev_blockhash = parent.block_hash();
        block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
        block
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn genesis_basic_filter_encodes_and_headers_chain() {
        let genesis = genesis_block(Network::Regtest);
        let filter = basic_filter_for_block(&genesis, |_| None).expect("genesis filter");
        assert!(!filter.is_empty());

        let zero = zero_filter_header();
        let genesis_header = filter_header(&filter, &zero);
        assert_ne!(genesis_header, zero);

        let child = child_block(&genesis);
        let parent_txid = genesis.txdata[0].compute_txid();
        let parent_script = genesis.txdata[0].output[0].script_pubkey.clone();
        let child_filter = basic_filter_for_block(&child, |outpoint| {
            (outpoint.txid == parent_txid && outpoint.vout == 0).then(|| parent_script.clone())
        })
        .expect("child filter");
        let child_header = filter_header(&child_filter, &genesis_header);
        assert_ne!(child_header, genesis_header);

        // Deterministic recomputation is byte-identical (idempotent rows).
        let again = basic_filter_for_block(&genesis, |_| None).expect("again");
        assert_eq!(again, filter);
    }

    #[test]
    fn cursor_round_trips_durable_bytes() {
        let cursor = StoredCursor {
            epoch: 7,
            sequence: 1_000_000_003,
            height: 0xdead_beef,
            hash: [0xab; 32],
        };
        let bytes = cursor.to_bytes();
        assert_eq!(bytes.len(), CURSOR_BYTE_LEN);
        assert_eq!(StoredCursor::from_bytes(&bytes), Some(cursor));
        assert_eq!(StoredCursor::from_bytes(&bytes[..51]), None);
    }

    #[test]
    fn lifecycle_state_round_trips() {
        assert_eq!(
            LifecycleState::from_u8(LifecycleState::Building.to_u8()),
            Some(LifecycleState::Building)
        );
        assert_eq!(
            LifecycleState::from_u8(LifecycleState::CaughtUp.to_u8()),
            Some(LifecycleState::CaughtUp)
        );
        assert_eq!(LifecycleState::from_u8(2), None);
    }

    /// Batch double collecting writes without applying them.
    struct MemBatch;

    impl WriteBatch for MemBatch {
        fn put(&mut self, _cf: ColumnFamily, _key: &[u8], _value: &[u8]) {}
        fn delete(&mut self, _cf: ColumnFamily, _key: &[u8]) {}
        fn delete_range(&mut self, _cf: ColumnFamily, _start: &[u8], _end: &[u8]) {}
    }

    /// In-memory backend double carrying only the schema marker.
    struct MemStore {
        schema: Option<Vec<u8>>,
    }

    impl MemStore {
        fn with_schema() -> Arc<Self> {
            Arc::new(Self {
                schema: Some(SCHEMA_VERSION.to_le_bytes().to_vec()),
            })
        }
    }

    impl KvStore for MemStore {
        type WriteBatch = MemBatch;

        fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            assert_eq!(cf, NAMESPACE_CF);
            if key == keys::SCHEMA {
                return Ok(self.schema.clone());
            }
            Ok(None)
        }

        fn iter_prefix<'a>(
            &'a self,
            _cf: ColumnFamily,
            _prefix: &[u8],
        ) -> Result<bitcoin_rs_storage::KvIter<'a>, StorageError> {
            Ok(Box::new(core::iter::empty()))
        }

        fn new_batch(&self) -> Self::WriteBatch {
            MemBatch
        }

        fn write(&self, _batch: Self::WriteBatch) -> Result<(), StorageError> {
            Ok(())
        }

        fn flush(&self) -> Result<(), StorageError> {
            Ok(())
        }

        fn snapshot(&self) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot>, StorageError> {
            Err(StorageError::InvalidOperation(
                "snapshot unsupported in the MemStore double",
            ))
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "test: hand-built fixtures cannot fail except by a bug"
    )]
    #[test]
    fn typed_store_reports_version_and_absent_metadata() {
        let store = FilterStore::new(MemStore::with_schema());
        assert_eq!(
            store.schema_version().expect("version"),
            Some(SCHEMA_VERSION)
        );
        assert!(!store.is_fresh().expect("fresh"));
        assert_eq!(store.pointer().expect("pointer"), None);
        assert_eq!(store.cursor().expect("cursor"), None);
        assert_eq!(store.state().expect("state"), None);
        assert_eq!(store.filter_row([0; 32]).expect("filter row"), None);
        assert_eq!(store.header_row([0; 32]).expect("header row"), None);
    }
}
