//! Roundtrip tests for electrs-shaped index rows over a small in-memory `KvStore`.
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bitcoin::hashes::Hash as _;
use parking_lot::RwLock;

#[cfg(feature = "redb")]
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{
    IndexCapabilities, IndexError, IndexReader, IndexRowCounts, IndexWatermark, IndexWriter,
    Indexer, PreparedBatch, PreparedBatchLimits,
};
use bitcoin_rs_storage::{
    ColumnFamily, KvIter, KvSnapshot, KvStore, PrefixScanLimit, StorageError, WriteBatch,
};

#[derive(Default)]
struct MemoryStore {
    cfs: RwLock<[BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()]>,
}

impl MemoryStore {
    fn count(&self, cf: ColumnFamily) -> usize {
        let guard = self.cfs.read();
        guard[cf.index()].len()
    }

    fn rows(&self, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
        let guard = self.cfs.read();
        guard[cf.index()]
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect()
    }
}

impl KvStore for MemoryStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        let guard = self.cfs.read();
        Ok(guard[cf.index()].get(key).cloned())
    }

    #[allow(clippy::needless_collect)] // SPEC: returned KvIter must own cloned rows after the lock guard is dropped.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let guard = self.cfs.read();
        let rows = guard[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }

    fn new_batch(&self) -> Self::WriteBatch {
        MemoryBatch::default()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        let mut guard = self.cfs.write();
        for op in batch.ops {
            match op {
                MemoryOp::Put { cf, key, value } => {
                    guard[cf.index()].insert(key, value);
                }
                MemoryOp::Delete { cf, key } => {
                    guard[cf.index()].remove(&key);
                }
                MemoryOp::DeleteRange { cf, start, end } => {
                    let keys = guard[cf.index()]
                        .keys()
                        .filter(|key| {
                            key.as_slice() >= start.as_slice() && key.as_slice() < end.as_slice()
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    for key in keys {
                        guard[cf.index()].remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), StorageError> {
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        let guard = self.cfs.read();
        Ok(Box::new(MemorySnapshot { cfs: guard.clone() }))
    }
}

#[derive(Default)]
struct CallTrackingStore {
    inner: MemoryStore,
    writes: AtomicUsize,
    durable_writes: AtomicUsize,
    flushes: AtomicUsize,
}

impl KvStore for CallTrackingStore {
    type WriteBatch = MemoryBatch;

    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        self.inner.get(cf, key)
    }

    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        self.inner.iter_prefix(cf, prefix)
    }

    fn new_batch(&self) -> Self::WriteBatch {
        self.inner.new_batch()
    }

    fn write(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(batch)
    }

    fn write_durable(&self, batch: Self::WriteBatch) -> Result<(), StorageError> {
        self.durable_writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(batch)
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn snapshot(&self) -> Result<Box<dyn KvSnapshot + '_>, StorageError> {
        self.inner.snapshot()
    }
}

#[derive(Default)]
struct MemoryBatch {
    ops: Vec<MemoryOp>,
}

impl WriteBatch for MemoryBatch {
    fn put(&mut self, cf: ColumnFamily, key: &[u8], value: &[u8]) {
        self.ops.push(MemoryOp::Put {
            cf,
            key: key.to_vec(),
            value: value.to_vec(),
        });
    }

    fn delete(&mut self, cf: ColumnFamily, key: &[u8]) {
        self.ops.push(MemoryOp::Delete {
            cf,
            key: key.to_vec(),
        });
    }

    fn delete_range(&mut self, cf: ColumnFamily, start: &[u8], end: &[u8]) {
        self.ops.push(MemoryOp::DeleteRange {
            cf,
            start: start.to_vec(),
            end: end.to_vec(),
        });
    }
}

enum MemoryOp {
    Put {
        cf: ColumnFamily,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    Delete {
        cf: ColumnFamily,
        key: Vec<u8>,
    },
    DeleteRange {
        cf: ColumnFamily,
        start: Vec<u8>,
        end: Vec<u8>,
    },
}

struct MemorySnapshot {
    cfs: [BTreeMap<Vec<u8>, Vec<u8>>; ColumnFamily::ALL.len()],
}

impl KvSnapshot for MemorySnapshot {
    fn get(&self, cf: ColumnFamily, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.cfs[cf.index()].get(key).cloned())
    }

    #[allow(clippy::needless_collect)] // SPEC: returned KvIter owns cloned rows to match backend iterator ownership.
    fn iter_prefix<'a>(
        &'a self,
        cf: ColumnFamily,
        prefix: &[u8],
    ) -> Result<KvIter<'a>, StorageError> {
        let rows = self.cfs[cf.index()]
            .iter()
            .filter(|(key, _value)| key.starts_with(prefix))
            .map(|(key, value)| Ok((key.clone(), value.clone())))
            .collect::<Vec<_>>();
        Ok(Box::new(rows.into_iter()))
    }
}

#[test]
fn ingest_golden_blocks_writes_expected_electrs_rows() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (
            0_u32,
            IndexRowCounts {
                txids: 1,
                funding: 1,
                spending: 0,
                headers: 1,
            },
        ),
        (
            170_u32,
            IndexRowCounts {
                txids: 2,
                funding: 3,
                spending: 1,
                headers: 1,
            },
        ),
        (
            481_824_u32,
            IndexRowCounts {
                txids: 1_866,
                funding: 3_740,
                spending: 5_192,
                headers: 1,
            },
        ),
    ];

    for (height, expected) in cases {
        let store = std::sync::Arc::new(MemoryStore::default());
        let mut indexer = Indexer::new(std::sync::Arc::clone(&store));
        let block = read_fixture(height)?;

        let counts = indexer.ingest_block(&block, height)?;

        assert_eq!(counts, expected, "height {height} returned counts");
        assert_eq!(
            store.count(ColumnFamily::TxConfirmed),
            expected.txids,
            "height {height} txid rows"
        );
        assert_eq!(
            store.count(ColumnFamily::Funding),
            expected.funding,
            "height {height} funding rows"
        );
        assert_eq!(
            store.count(ColumnFamily::Spending),
            expected.spending,
            "height {height} spending rows"
        );
        assert_eq!(
            store.count(ColumnFamily::BlockHeaders),
            expected.headers,
            "height {height} header rows"
        );
    }
    Ok(())
}

#[test]
fn ingest_with_precomputed_txids_matches_standard_ingest() -> Result<(), Box<dyn std::error::Error>>
{
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let txids = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect::<Vec<_>>();

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &txids)
}

#[test]
fn ingest_with_verified_txids_matches_standard_ingest() -> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let txids = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect::<Vec<_>>();

    assert_verified_ingest_matches_standard(&block_bytes, height, &txids)
}

#[test]
fn ingest_with_mismatched_precomputed_txids_falls_back_to_standard_ingest()
-> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &[])
}

#[test]
fn ingest_with_same_length_wrong_precomputed_txids_falls_back_to_standard_ingest()
-> Result<(), Box<dyn std::error::Error>> {
    let height = 170_u32;
    let block_bytes = read_fixture(height)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&block_bytes)?;
    let stale_txids = vec![bitcoin::Txid::from_byte_array([0x42; 32]); block.txdata.len()];

    assert_precomputed_ingest_matches_standard(&block_bytes, height, &stale_txids)
}

fn read_fixture(height: u32) -> Result<Vec<u8>, std::io::Error> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../primitives/tests/testdata")
        .join(format!("{height}.bin"));
    std::fs::read(path)
}

fn assert_precomputed_ingest_matches_standard(
    block: &[u8],
    height: u32,
    txids: &[bitcoin::Txid],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_ingest_matches_standard(block, height, |indexer| {
        indexer.ingest_block_with_txids(block, height, txids)
    })
}

fn assert_verified_ingest_matches_standard(
    block: &[u8],
    height: u32,
    txids: &[bitcoin::Txid],
) -> Result<(), Box<dyn std::error::Error>> {
    assert_ingest_matches_standard(block, height, |indexer| {
        indexer.ingest_block_with_verified_txids(block, height, txids)
    })
}

fn assert_ingest_matches_standard(
    block: &[u8],
    height: u32,
    ingest: impl FnOnce(
        &mut Indexer<MemoryStore>,
    ) -> Result<IndexRowCounts, bitcoin_rs_index::IndexError>,
) -> Result<(), Box<dyn std::error::Error>> {
    let standard_store = std::sync::Arc::new(MemoryStore::default());
    let mut standard_indexer = Indexer::new(std::sync::Arc::clone(&standard_store));
    let candidate_store = std::sync::Arc::new(MemoryStore::default());
    let mut candidate_indexer = Indexer::new(std::sync::Arc::clone(&candidate_store));

    let standard_counts = standard_indexer.ingest_block(block, height)?;
    let candidate_counts = ingest(&mut candidate_indexer)?;

    assert_eq!(candidate_counts, standard_counts);
    for &cf in ColumnFamily::ALL {
        assert_eq!(candidate_store.rows(cf), standard_store.rows(cf));
    }
    Ok(())
}

fn block_hash(body: &[u8]) -> [u8; 32] {
    bitcoin::BlockHash::hash(&body[..80]).to_byte_array()
}

fn parent_hash(body: &[u8]) -> [u8; 32] {
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&body[4..36]);
    hash
}

#[test]
fn watermark_roundtrip_and_invalid_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let watermark = IndexWatermark {
        height: 123,
        hash: [0xab; 32],
    };
    let bytes = watermark.to_bytes();
    let decoded = IndexWatermark::from_bytes(&bytes)?;
    assert_eq!(decoded, watermark);

    let result = IndexWatermark::from_bytes(&bytes[..3]);
    assert!(matches!(result, Err(IndexError::InvalidWatermark)));
    Ok(())
}

#[test]
fn format_version_rejection() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[4, 0, 0, 0],
    )?;
    assert!(matches!(
        IndexWriter::open(store),
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 4 })
    ));
    Ok(())
}

#[test]
fn unversioned_rows_are_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    let body = read_fixture(0)?;
    indexer.ingest_block(&body, 0)?;

    assert!(matches!(
        IndexWriter::open(Arc::clone(&store)),
        Err(IndexError::LegacyCursorlessIndex)
    ));
    Ok(())
}

#[test]
fn reset_index_replaces_an_incompatible_derived_format() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &2_u32.to_le_bytes(),
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::TxConfirmed,
        b"old",
        b"row",
    )?;

    IndexWriter::reset_index(store.as_ref())?;

    assert!(
        IndexWriter::open(Arc::clone(&store))?
            .watermark()?
            .is_none()
    );
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::TxConfirmed),
        0
    );
    Ok(())
}

#[test]
fn invalid_watermark_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[3, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &[0u8; 2],
    )?;
    let writer = IndexWriter::open(Arc::clone(&store))?;
    assert!(matches!(
        writer.watermark(),
        Err(IndexError::InvalidWatermark)
    ));
    Ok(())
}

#[test]
fn prepare_block_verifies_header_identity_and_parent() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);

    let block = writer.prepare_block(0, hash, &body)?;
    assert_eq!(block.height, 0);
    assert_eq!(block.hash, hash);
    assert_eq!(block.parent_hash, [0u8; 32]);
    assert_eq!(block.row_count, 3); // txid + funding + header
    assert_eq!(block.encoded_bytes, 120);

    let wrong_hash = [0x42u8; 32];
    assert!(matches!(
        writer.prepare_block(0, wrong_hash, &body),
        Err(IndexError::BlockIdentityMismatch {
            height: 0,
            expected,
            actual,
        }) if expected == wrong_hash && actual == hash
    ));
    Ok(())
}

#[test]
fn commit_forward_and_rollback_are_atomic_and_ordered() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let block0_watermark = block0.watermark();
    let block1_watermark = block1.watermark();
    assert_eq!(block1.parent_hash, block0.hash);
    assert_eq!(block1.parent_hash, parent_hash(&body1));

    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 1_000,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_ok());
    let watermark = writer.commit_forward(batch)?;
    assert_eq!(watermark, block1_watermark);
    assert_eq!(writer.watermark()?, Some(watermark));
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
        2
    );

    // A mismatched parent watermark must fail without changing the tip.
    let wrong_prev = IndexWatermark {
        height: 0,
        hash: [0x42; 32],
    };
    assert!(matches!(
        writer.commit_rollback_one(Some(wrong_prev), &body1),
        Err(IndexError::WatermarkMismatch { .. })
    ));
    assert_eq!(writer.watermark()?, Some(block1_watermark));

    // Roll back block 1, returning to block 0.
    writer.commit_rollback_one(Some(block0_watermark), &body1)?;
    assert_eq!(writer.watermark()?, Some(block0_watermark));
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::BlockHeaders),
        1
    );
    assert_eq!(
        store.count(bitcoin_rs_storage::ColumnFamily::TxConfirmed),
        1
    );

    // Rolling back with a body that does not match the current watermark fails.
    assert!(matches!(
        writer.commit_rollback_one(Some(block0_watermark), &body1),
        Err(IndexError::BlockIdentityMismatch { .. })
    ));

    Ok(())
}

#[test]
fn snapshot_scan_preserves_position_values() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&body)?;
    let txid = block.txdata[0].compute_txid();
    let prepared = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;

    let snapshot = writer.snapshot()?;
    let scan = snapshot.transaction_rows(
        &txid,
        PrefixScanLimit {
            max_rows: 10,
            max_bytes: 1_024,
        },
    )?;

    assert!(scan.complete);
    assert_eq!(scan.rows.len(), 1);
    assert_eq!(scan.rows[0].row.height(), 0);
    assert_eq!(
        TxPositionValue::decode(&scan.rows[0].value).map(<[TxPosition]>::len),
        Some(1)
    );
    Ok(())
}

#[test]
fn commit_forward_uses_one_durable_write() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    writer.commit_forward(batch)?;

    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
    assert_eq!(store.writes.load(Ordering::Relaxed), 0);
    assert_eq!(store.flushes.load(Ordering::Relaxed), 0);
    Ok(())
}

#[test]
fn capability_commits_own_only_their_rows_and_watermarks() -> Result<(), Box<dyn std::error::Error>>
{
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let limits = PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    };

    let tx_block = writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, hash, &body)?;
    assert_eq!(tx_block.row_count, 2, "tx row plus shared block identity");
    let mut tx_batch = PreparedBatch::new(limits);
    assert!(tx_batch.try_push(tx_block).is_ok());
    writer.commit_forward(tx_batch)?;

    let watermark = IndexWatermark { height: 0, hash };
    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: None,
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);

    let script_index_block =
        writer.prepare_block_for(IndexCapabilities::SCRIPT_HISTORY, 0, hash, &body)?;
    assert_eq!(
        script_index_block.row_count, 2,
        "funding row plus shared block identity"
    );
    let mut script_index_batch = PreparedBatch::new(limits);
    assert!(script_index_batch.try_push(script_index_block).is_ok());
    writer.commit_forward(script_index_batch)?;

    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: Some(watermark),
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 1);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
    Ok(())
}

#[test]
fn aligned_capabilities_share_one_atomic_commit() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(CallTrackingStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    writer.commit_forward(batch)?;

    assert_eq!(store.durable_writes.load(Ordering::Relaxed), 1);
    let watermark = IndexWatermark { height: 0, hash };
    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(watermark),
            script_history: Some(watermark),
        }
    );
    Ok(())
}

#[test]
fn script_index_reset_preserves_tx_lookup_and_shared_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    writer.reset_capabilities(IndexCapabilities::SCRIPT_HISTORY)?;

    assert_eq!(
        writer.watermarks()?,
        bitcoin_rs_index::IndexWatermarks {
            tx_lookup: Some(IndexWatermark { height: 0, hash }),
            script_history: None,
        }
    );
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 1);
    assert!(store.get(ColumnFamily::UtxoMeta, &[0x00, b'R'])?.is_none());
    Ok(())
}

#[test]
fn rollback_preserves_shared_ancestors_for_a_disabled_capability()
-> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;
    let block0 = writer.prepare_block_for(IndexCapabilities::ALL, 0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block_for(IndexCapabilities::ALL, 1, block_hash(&body1), &body1)?;
    let watermark0 = block0.watermark();
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_ok());
    writer.commit_forward(batch)?;

    writer.commit_rollback_one_for(IndexCapabilities::TX_LOOKUP, Some(watermark0), &body1)?;
    writer.commit_rollback_one_for(IndexCapabilities::TX_LOOKUP, None, &body0)?;
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 2);

    writer.commit_rollback_one_for(IndexCapabilities::SCRIPT_HISTORY, Some(watermark0), &body1)?;
    writer.commit_rollback_one_for(IndexCapabilities::SCRIPT_HISTORY, None, &body0)?;
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn resetting_the_only_cursor_removes_shared_identity() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    writer.reset_capabilities(IndexCapabilities::TX_LOOKUP)?;

    assert_eq!(store.count(ColumnFamily::TxConfirmed), 0);
    assert_eq!(store.count(ColumnFamily::BlockHeaders), 0);
    Ok(())
}

#[test]
fn open_resumes_interrupted_capability_reset() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let hash = block_hash(&body);
    let block = writer.prepare_block_for(IndexCapabilities::ALL, 0, hash, &body)?;
    let mut prepared = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(prepared.try_push(block).is_ok());
    writer.commit_forward(prepared)?;
    drop(writer);

    let mut interrupted = store.new_batch();
    interrupted.put(ColumnFamily::UtxoMeta, &[0x00, b'R'], &[0b10]);
    interrupted.delete(ColumnFamily::UtxoMeta, &[0x00, b'S']);
    store.write_durable(interrupted)?;

    let writer = IndexWriter::open(Arc::clone(&store))?;

    assert!(writer.watermarks()?.tx_lookup.is_some());
    assert!(writer.watermarks()?.script_history.is_none());
    assert_eq!(store.count(ColumnFamily::TxConfirmed), 1);
    assert_eq!(store.count(ColumnFamily::Funding), 0);
    assert_eq!(store.count(ColumnFamily::Spending), 0);
    assert!(store.get(ColumnFamily::UtxoMeta, &[0x00, b'R'])?.is_none());
    Ok(())
}

#[test]
fn batch_caps_admit_oversized_first_block() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let writer = IndexWriter::open(Arc::clone(&store))?;
    let body0 = read_fixture(0)?;
    let body1 = read_fixture(1)?;

    // Exact boundary: one block of three rows fits, a second does not.
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 3,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_err());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.row_count(), 3);
    assert!(batch.is_full());
    assert_eq!(
        batch.watermark(),
        Some(IndexWatermark {
            height: 0,
            hash: block_hash(&body0),
        })
    );

    // Oversized first block: empty batch accepts it, then refuses another.
    let block0 = writer.prepare_block(0, block_hash(&body0), &body0)?;
    let block1 = writer.prepare_block(1, block_hash(&body1), &body1)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 0,
        max_bytes: 0,
    });
    assert!(batch.try_push(block0).is_ok());
    assert!(batch.try_push(block1).is_err());
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.encoded_bytes(), 120);
    assert!(batch.is_full());
    assert_eq!(
        batch.watermark(),
        Some(IndexWatermark {
            height: 0,
            hash: block_hash(&body0),
        })
    );

    Ok(())
}

#[test]
fn format_version_requires_exact_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    // Extra trailing byte must be rejected even though the prefix is version 3.
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[3, 0, 0, 0, 0],
    )?;
    assert!(matches!(
        IndexWriter::open(store),
        Err(IndexError::UnsupportedTxIndexFormatVersion { version: 3 })
    ));
    Ok(())
}

#[test]
fn commit_forward_accepts_terminal_height() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let current = IndexWatermark {
        height: u32::MAX - 1,
        hash: [0; 32],
    };
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[3, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &current.to_bytes(),
    )?;

    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let expected_hash = block_hash(&body);
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, u32::MAX, expected_hash, &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());

    let watermark = writer.commit_forward(batch)?;
    assert_eq!(
        watermark,
        IndexWatermark {
            height: u32::MAX,
            hash: expected_hash,
        }
    );
    Ok(())
}

#[test]
fn commit_forward_rejects_height_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let overflow = IndexWatermark {
        height: u32::MAX,
        hash: [0xab; 32],
    };
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'V'],
        &[3, 0, 0, 0],
    )?;
    store.put(
        bitcoin_rs_storage::ColumnFamily::UtxoMeta,
        &[0x00, b'T'],
        &overflow.to_bytes(),
    )?;

    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block =
        writer.prepare_block_for(IndexCapabilities::TX_LOOKUP, 0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    assert!(matches!(
        writer.commit_forward(batch),
        Err(IndexError::NonContiguousPrepared { watermark })
            if watermark == Some(overflow)
    ));
    Ok(())
}

#[test]
fn rollback_rejects_prev_at_genesis() -> Result<(), Box<dyn std::error::Error>> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(block).is_ok());
    writer.commit_forward(batch)?;

    assert!(matches!(
        writer.commit_rollback_one(
            Some(IndexWatermark {
                height: 0,
                hash: [0u8; 32]
            }),
            &body
        ),
        Err(IndexError::NonContiguousPrepared { .. })
    ));
    Ok(())
}

#[cfg(feature = "redb")]
#[test]
fn redb_snapshot_preserves_position_values() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::TempDir::new()?;
    let store = Arc::new(bitcoin_rs_storage::open_redb_tx_index_store(temp.path())?);
    let mut writer = IndexWriter::open(Arc::clone(&store))?;
    let body = read_fixture(0)?;
    let block: bitcoin::Block = bitcoin::consensus::deserialize(&body)?;
    let txid = block.txdata[0].compute_txid();
    let scripthash = ScriptHash::new(&block.txdata[0].output[0].script_pubkey);
    let prepared = writer.prepare_block(0, block_hash(&body), &body)?;
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: 100,
        max_bytes: 1_000_000,
    });
    assert!(batch.try_push(prepared).is_ok());
    writer.commit_forward(batch)?;

    let snapshot = writer.snapshot()?;
    let limit = PrefixScanLimit {
        max_rows: 10,
        max_bytes: 1_024,
    };
    let transaction_rows = snapshot.transaction_rows(&txid, limit)?;
    let funding_rows = snapshot.funding_rows(scripthash, limit)?;

    assert_eq!(transaction_rows.rows.len(), 1);
    assert_eq!(funding_rows.rows.len(), 1);
    assert_eq!(transaction_rows.rows[0].value, funding_rows.rows[0].value);
    assert_eq!(
        TxPositionValue::decode(&transaction_rows.rows[0].value).map(<[TxPosition]>::len),
        Some(1)
    );
    Ok(())
}
