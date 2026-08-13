use std::ops::ControlFlow;

use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch as _};
use bitcoin_slices::{Visit as _, Visitor, bsl};
use hashbrown::{HashMap, HashSet};
use thiserror::Error;
use tracing::debug;
use zerocopy::IntoBytes;

use crate::types::{
    HashPrefixRow, HeaderRow, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow,
};

/// Errors returned while indexing confirmed blocks.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Backend storage failed while applying index rows.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// `bitcoin_slices` rejected the serialized block.
    #[error("invalid serialized block: {0:?}")]
    BlockParse(bitcoin_slices::Error),
    /// This indexer cannot undo a block, so a reorg cannot be made consistent.
    #[error("this indexer does not support block disconnect")]
    UnsupportedRollback,
    /// A block header did not have the consensus 80-byte length.
    #[error("invalid block header length {len}")]
    InvalidHeaderLength {
        /// Actual header length observed by the visitor.
        len: usize,
    },
    /// A worker-only atomic transition was requested from an indexer that does not implement it.
    #[error("this indexer does not support atomic watermark transitions")]
    UnsupportedWatermarkTransition,
    /// The durable watermark bytes do not use the supported codec.
    #[error("invalid TxIndex watermark encoding")]
    InvalidWatermark,
    /// A transition did not begin at the durable watermark it expected.
    #[error("TxIndex watermark mismatch: expected {expected:?}, found {actual:?}")]
    WatermarkMismatch {
        /// Watermark the caller reconciled from.
        expected: Option<IndexWatermark>,
        /// Watermark found in the store.
        actual: Option<IndexWatermark>,
    },
    /// A block body did not match the height/hash selected by reconciliation.
    #[error("block body identity mismatch at height {height}: expected {expected}, found {actual}")]
    BlockIdentityMismatch {
        /// Expected height.
        height: u32,
        /// Expected block hash.
        expected: Hash256,
        /// Decoded block hash.
        actual: Hash256,
    },
    /// The decoded block's Merkle root does not match its transactions.
    #[error("block body has an invalid Merkle root at height {height} ({hash})")]
    InvalidMerkleRoot {
        /// Block height.
        height: u32,
        /// Block hash.
        hash: Hash256,
    },
    /// A bounded complete query exceeded the work its caller permits.
    #[error("{resource} query exceeds the limit of {limit} rows")]
    QueryLimitExceeded {
        /// Logical row or result kind that crossed the bound.
        resource: &'static str,
        /// Maximum number of rows or results permitted.
        limit: usize,
    },
    /// A complete query could not exact-resolve an indexed candidate height.
    #[error("indexed block body is unavailable at height {height}")]
    QueryBlockUnavailable {
        /// Indexed candidate height whose active-chain body was unavailable.
        height: u32,
    },
    /// A forward transition does not extend the durable watermark.
    #[error("block at height {height} does not extend TxIndex watermark {watermark:?}")]
    NonContiguousConnect {
        /// Candidate height.
        height: u32,
        /// Existing durable watermark.
        watermark: Option<IndexWatermark>,
    },
    /// The watermark names a block whose identity row is absent.
    #[error("TxIndex watermark block identity row is missing at height {height} ({hash})")]
    MissingWatermarkIdentity {
        /// Watermark height.
        height: u32,
        /// Watermark hash.
        hash: Hash256,
    },
}

const WATERMARK_KEY: &[u8] = b"txindex/watermark";
const WATERMARK_VERSION: u8 = 1;
const WATERMARK_LEN: usize = 1 + 4 + 32;

/// Exact durable point represented by all committed `TxIndex` rows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IndexWatermark {
    /// Applied-chain height represented by the index.
    pub height: u32,
    /// Full block identity at `height`.
    pub hash: Hash256,
}

/// One exact forward transition included in an atomic `TxIndex` batch.
#[derive(Copy, Clone)]
pub struct IndexConnect<'a> {
    /// Decoded and identity-checked block body.
    pub block: &'a bitcoin::Block,
    /// Height of `block` on the captured target ancestry.
    pub height: u32,
    /// Full expected header hash from that ancestry.
    pub hash: Hash256,
}

impl IndexWatermark {
    fn encode(self) -> [u8; WATERMARK_LEN] {
        let mut bytes = [0_u8; WATERMARK_LEN];
        bytes[0] = WATERMARK_VERSION;
        bytes[1..5].copy_from_slice(&self.height.to_be_bytes());
        bytes[5..].copy_from_slice(self.hash.as_byte_array());
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, IndexError> {
        if bytes.len() != WATERMARK_LEN || bytes.first() != Some(&WATERMARK_VERSION) {
            return Err(IndexError::InvalidWatermark);
        }
        let mut height = [0_u8; 4];
        height.copy_from_slice(&bytes[1..5]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes[5..]);
        Ok(Self {
            height: u32::from_be_bytes(height),
            hash: Hash256::from_le_bytes(&hash),
        })
    }
}

/// Counts of rows written by a confirmed block ingest.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRowCounts {
    /// Transaction-id index rows written to [`ColumnFamily::TxConfirmed`].
    pub txids: usize,
    /// Script funding rows written to [`ColumnFamily::Funding`].
    pub funding: usize,
    /// Previous-outpoint spending rows written to [`ColumnFamily::Spending`].
    pub spending: usize,
    /// Header rows written to [`ColumnFamily::BlockHeaders`].
    pub headers: usize,
}

/// Fully validated `TxIndex` rows ready for one atomic forward commit.
///
/// Construction is CPU-only and may run before the query/mutation write gate.
pub struct PreparedIndexConnect {
    expected_watermark: Option<IndexWatermark>,
    terminal_watermark: IndexWatermark,
    rows: PendingRows,
}

/// Fully validated `TxIndex` rows ready for one atomic rollback commit.
pub struct PreparedIndexRollback {
    watermark: IndexWatermark,
    parent: IndexWatermark,
    rows: PendingRows,
}

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
pub struct Indexer<S: KvStore> {
    store: std::sync::Arc<S>,
    last_counts: IndexRowCounts,
    pending_rows: PendingRows,
    batch_depth: u32,
}

impl<S: KvStore> Indexer<S> {
    /// Creates an indexer over `store`.
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self {
            store,
            last_counts: IndexRowCounts::default(),
            pending_rows: PendingRows::default(),
            batch_depth: 0,
        }
    }

    /// Returns the underlying key-value store.
    pub const fn store(&self) -> &std::sync::Arc<S> {
        &self.store
    }

    /// Returns the row counts from the last successful ingest.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.last_counts
    }

    /// Loads the exact durable `TxIndex` watermark, or `None` for an empty v2 index.
    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.store
            .get(ColumnFamily::UtxoMeta, WATERMARK_KEY)?
            .map(|bytes| IndexWatermark::decode(&bytes))
            .transpose()
    }

    /// Atomically connects one exact block and advances the durable watermark.
    pub fn connect_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        expected_hash: Hash256,
    ) -> Result<IndexRowCounts, IndexError> {
        self.connect_blocks_atomic(&[IndexConnect {
            block,
            height,
            hash: expected_hash,
        }])
    }

    /// Atomically connects a non-empty contiguous block slice and advances the
    /// watermark to its terminal block.
    pub fn connect_blocks_atomic(
        &mut self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<IndexRowCounts, IndexError> {
        let prepared = self.prepare_connect_blocks(blocks)?;
        let Some(prepared) = prepared else {
            return Ok(IndexRowCounts::default());
        };
        self.commit_prepared_connect(&prepared)
    }

    /// Validates a contiguous block slice and constructs all rows without writing.
    pub fn prepare_connect_blocks(
        &self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<Option<PreparedIndexConnect>, IndexError> {
        let Some(first) = blocks.first() else {
            return Ok(None);
        };
        let current = self.watermark()?;
        let mut expected_height = match current {
            None => 0,
            Some(watermark) => watermark.height.saturating_add(1),
        };
        let mut expected_parent = current.map(|watermark| watermark.hash);
        let mut rows = PendingRows::default();
        for transition in blocks {
            validate_block_identity(transition.block, transition.height, transition.hash)?;
            let contiguous = transition.height == expected_height
                && match expected_parent {
                    None => transition.height == 0,
                    Some(parent) => {
                        Hash256::from_le_bytes(
                            transition.block.header.prev_blockhash.as_byte_array(),
                        ) == parent
                    }
                };
            if !contiguous {
                return Err(IndexError::NonContiguousConnect {
                    height: transition.height,
                    watermark: current,
                });
            }
            let txids: Vec<_> = transition
                .block
                .txdata
                .iter()
                .map(bitcoin::Transaction::compute_txid)
                .collect();
            rows.append(pending_rows_for_decoded_block(
                transition.block,
                transition.height,
                &txids,
            )?);
            expected_height = expected_height.saturating_add(1);
            expected_parent = Some(transition.hash);
        }
        let terminal = blocks.last().unwrap_or(first);
        rows.sort();
        Ok(Some(PreparedIndexConnect {
            expected_watermark: current,
            terminal_watermark: IndexWatermark {
                height: terminal.height,
                hash: terminal.hash,
            },
            rows,
        }))
    }

    /// Atomically commits preconstructed rows after rechecking their starting watermark.
    pub fn commit_prepared_connect(
        &mut self,
        prepared: &PreparedIndexConnect,
    ) -> Result<IndexRowCounts, IndexError> {
        self.flush()?;
        let actual = self.watermark()?;
        if actual != prepared.expected_watermark {
            return Err(IndexError::WatermarkMismatch {
                expected: prepared.expected_watermark,
                actual,
            });
        }
        let counts = prepared.rows.counts();
        let mut batch = self.store.new_batch();
        put_rows(&mut batch, &prepared.rows);
        batch.put(
            ColumnFamily::UtxoMeta,
            WATERMARK_KEY,
            &prepared.terminal_watermark.encode(),
        );
        self.store.write(batch)?;
        self.last_counts = counts;
        Ok(counts)
    }

    /// Atomically removes the durable watermark block and retreats to its parent.
    ///
    /// Unlike the legacy idempotent rollback, absence of the watermark block's
    /// header identity is an inconsistency and leaves both rows and watermark unchanged.
    pub fn rollback_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<IndexRowCounts, IndexError> {
        let prepared = self.prepare_rollback_block(block, watermark)?;
        self.commit_prepared_rollback(&prepared)
    }

    /// Validates and constructs rollback rows without mutating storage.
    pub fn prepare_rollback_block(
        &self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<PreparedIndexRollback, IndexError> {
        validate_block_identity(block, watermark.height, watermark.hash)?;
        let actual = self.watermark()?;
        if actual != Some(watermark) {
            return Err(IndexError::WatermarkMismatch {
                expected: Some(watermark),
                actual,
            });
        }
        if watermark.height == 0 {
            return Err(IndexError::NonContiguousConnect {
                height: 0,
                watermark: Some(watermark),
            });
        }

        let txids: Vec<_> = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect();
        let mut rows = pending_rows_for_decoded_block(block, watermark.height, &txids)?;
        rows.sort();
        let parent = IndexWatermark {
            height: watermark.height - 1,
            hash: Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array()),
        };
        Ok(PreparedIndexRollback {
            watermark,
            parent,
            rows,
        })
    }

    /// Atomically commits a preconstructed rollback after rechecking its watermark.
    pub fn commit_prepared_rollback(
        &mut self,
        prepared: &PreparedIndexRollback,
    ) -> Result<IndexRowCounts, IndexError> {
        self.flush()?;
        let actual = self.watermark()?;
        if actual != Some(prepared.watermark) {
            return Err(IndexError::WatermarkMismatch {
                expected: Some(prepared.watermark),
                actual,
            });
        }
        let counts = prepared.rows.counts();
        let identity_present = match prepared.rows.header_rows.first() {
            Some(header) => self
                .store
                .get(ColumnFamily::BlockHeaders, header)?
                .is_some(),
            None => false,
        };
        if !identity_present {
            return Err(IndexError::MissingWatermarkIdentity {
                height: prepared.watermark.height,
                hash: prepared.watermark.hash,
            });
        }
        let mut batch = self.store.new_batch();
        delete_rows(&mut batch, &prepared.rows);
        batch.put(
            ColumnFamily::UtxoMeta,
            WATERMARK_KEY,
            &prepared.parent.encode(),
        );
        self.store.write(batch)?;
        self.last_counts = counts;
        Ok(counts)
    }

    /// Iterates every persisted block header in the `BlockHeaders` column family.
    ///
    /// Returns the raw 80-byte header rows in storage order (lexicographic by key).
    /// Used by SPV-style range queries that need contiguous headers from genesis.
    pub fn iter_block_headers(&self) -> Result<Vec<[u8; crate::HEADER_ROW_SIZE]>, IndexError> {
        let iter = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        let mut rows = Vec::new();
        for entry in iter {
            let (key, _value) = entry?;
            if key.len() == crate::HEADER_ROW_SIZE {
                let mut header = [0_u8; crate::HEADER_ROW_SIZE];
                header.copy_from_slice(&key);
                rows.push(header);
            }
        }
        Ok(rows)
    }

    /// Returns the hash of every indexed block header in storage order.
    ///
    /// Cheaper than `iter_block_headers` when only the hash list matters:
    /// computes `BlockHash` from the 80-byte raw header bytes during iteration
    /// without retaining the payload.
    pub fn iter_block_header_hashes(
        &self,
    ) -> Result<Vec<bitcoin_rs_primitives::Hash256>, IndexError> {
        use bitcoin::hashes::Hash as _;

        let iter = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        let mut out = Vec::new();
        for entry in iter {
            let (key, _value) = entry?;
            if key.len() == crate::HEADER_ROW_SIZE {
                // BlockHeader hash is the double-SHA256 of the 80-byte serialized header.
                let block_hash = bitcoin::BlockHash::hash(&key);
                out.push(bitcoin_rs_primitives::Hash256::from_le_bytes(
                    &block_hash.to_byte_array(),
                ));
            }
        }
        Ok(out)
    }

    /// Returns the number of persisted block headers via `iter_block_headers`.
    ///
    /// Cost O(N) since the iterator pulls each row; cache if called frequently.
    pub fn header_count(&self) -> Result<usize, IndexError> {
        self.iter_block_headers().map(|rows| rows.len())
    }

    /// Returns the highest indexed header height, or `None` if no headers are
    /// indexed.
    ///
    /// Cost O(N) since `header_count` pulls every row. Cache if called
    /// frequently. Convenience for IBD progress reporting and status surfaces.
    pub fn tip_height_indexed(&self) -> Result<Option<u32>, IndexError> {
        let count = self.header_count()?;
        if count == 0 {
            return Ok(None);
        }
        Ok(u32::try_from(count.saturating_sub(1)).ok())
    }

    /// Iterates confirmed funding rows for `scripthash`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the scripthash's
    /// scan prefix, decoded from `ColumnFamily::Funding`. Rows are returned in
    /// the iteration order of the underlying store (typically lexicographic, so
    /// (prefix, height) ascending).
    ///
    /// The 8-byte prefix is lossy: callers MUST resolve heights back to full
    /// transactions via block storage to confirm scripthash identity.
    pub fn iter_funding_rows(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves confirmed script-history entries for `scripthash` via `source`.
    ///
    /// Walks `iter_funding_rows(scripthash)` to get every (prefix, height) pair,
    /// fetches each block via `source.block_at_height(height)`, and yields a
    /// `HistoryEntry::confirmed` for every transaction in that block that has
    /// at least one output matching `scripthash` exactly.
    ///
    /// Entries are returned in iteration order (lexicographic by prefix||height).
    /// Heights not resolvable by `source` are skipped.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only transactions whose
    /// output scripthash matches the full 32-byte `scripthash` are emitted.
    pub fn resolve_script_history<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::HistoryEntry>, IndexError> {
        self.resolve_script_history_inner(scripthash, source, None)
    }

    /// Resolves script history while bounding funding rows and matched entries.
    pub fn resolve_script_history_limited<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
        limit: usize,
    ) -> Result<Vec<crate::HistoryEntry>, IndexError> {
        self.resolve_script_history_inner(scripthash, source, Some(limit))
    }

    fn resolve_script_history_inner<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
        limit: Option<usize>,
    ) -> Result<Vec<crate::HistoryEntry>, IndexError> {
        let rows = match limit {
            Some(limit) => {
                let prefix = ScriptHashRow::scan_prefix(scripthash);
                let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
                collect_prefix_rows_limited(iter, limit, "funding-row")?
            }
            None => self.iter_funding_rows(scripthash)?,
        };
        let mut entries = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                if limit.is_some() {
                    return Err(IndexError::QueryBlockUnavailable { height });
                }
                continue;
            };
            for tx in &block.txdata {
                let mut matched = false;
                for output in &tx.output {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        == scripthash
                    {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    if let Some(limit) = limit
                        && entries.len() >= limit
                    {
                        return Err(IndexError::QueryLimitExceeded {
                            resource: "history-entry",
                            limit,
                        });
                    }
                    entries.push(crate::HistoryEntry::confirmed(tx.compute_txid(), height));
                }
            }
        }
        Ok(entries)
    }
    /// Resolves confirmed unspent-output candidates for `scripthash` via `source`.
    ///
    /// For every funding-row (prefix, height), fetches the block and emits a
    /// triple `(txid, vout, value_sats)` for every output whose scriptPubKey
    /// hashes to `scripthash`. Spending checks are NOT performed here — callers
    /// compose with `iter_spending_rows` to filter out spent outputs.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only outputs whose script
    /// hashes match the full 32-byte `scripthash` are emitted.
    pub fn resolve_unspent_outputs<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64)>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout_idx, output) in tx.output.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        != scripthash
                    {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    outputs.push((txid, vout, output.value.to_sat()));
                }
            }
        }
        Ok(outputs)
    }

    /// Same as `resolve_unspent_outputs` but each tuple carries the funding height.
    ///
    /// Returns `(txid, vout, value_sats, funding_height)` quadruples. Use this
    /// when callers need the confirmation height (e.g. Electrum `listunspent`
    /// emits the height for each unspent output).
    pub fn resolve_unspent_outputs_with_height<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64, u32)>, IndexError> {
        self.resolve_unspent_outputs_with_height_inner(scripthash, source, None)
    }

    /// Resolves confirmed unspent-output candidates while bounding funding rows
    /// and matching outputs inspected by one complete reader.
    pub fn resolve_unspent_outputs_with_height_limited<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
        limit: usize,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64, u32)>, IndexError> {
        self.resolve_unspent_outputs_with_height_inner(scripthash, source, Some(limit))
    }

    fn resolve_unspent_outputs_with_height_inner<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
        limit: Option<usize>,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64, u32)>, IndexError> {
        let rows = match limit {
            Some(limit) => {
                let prefix = ScriptHashRow::scan_prefix(scripthash);
                let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
                collect_prefix_rows_limited(iter, limit, "funding-row")?
            }
            None => self.iter_funding_rows(scripthash)?,
        };
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                if limit.is_some() {
                    return Err(IndexError::QueryBlockUnavailable { height });
                }
                continue;
            };
            for tx in &block.txdata {
                let txid = tx.compute_txid();
                for (vout_idx, output) in tx.output.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes())
                        != scripthash
                    {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    if let Some(limit) = limit
                        && outputs.len() >= limit
                    {
                        return Err(IndexError::QueryLimitExceeded {
                            resource: "unspent-output",
                            limit,
                        });
                    }
                    outputs.push((txid, vout, output.value.to_sat(), height));
                }
            }
        }
        Ok(outputs)
    }

    /// Iterates confirmed spending rows that spent `outpoint`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the outpoint's
    /// spending scan prefix, decoded from `ColumnFamily::Spending`. The 8-byte
    /// prefix is lossy as above.
    pub fn iter_spending_rows(
        &self,
        outpoint: &bitcoin::OutPoint,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Returns whether the spending index has any row for `outpoint` without
    /// allocating and decoding the complete matching prefix.
    pub fn has_spending_rows(&self, outpoint: &bitcoin::OutPoint) -> Result<bool, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let mut iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        iter.next()
            .transpose()
            .map(|entry| entry.is_some())
            .map_err(Into::into)
    }

    /// Exact-resolves lossy spending-prefix candidates against their blocks.
    pub fn is_outpoint_spent<B: BlockSource>(
        &self,
        outpoint: &bitcoin::OutPoint,
        source: &B,
    ) -> Result<bool, IndexError> {
        let rows = self.iter_spending_rows(outpoint)?;
        let mut last_height = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            if cached_block.as_ref().is_some_and(|block| {
                block
                    .txdata
                    .iter()
                    .flat_map(|tx| &tx.input)
                    .any(|input| input.previous_output == *outpoint)
            }) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Filters funding candidates by exact-resolving all lossy spending rows in
    /// one pass over each candidate spending block.
    pub fn filter_unspent_outputs_with_height<B: BlockSource>(
        &self,
        outputs: Vec<(bitcoin::Txid, u32, u64, u32)>,
        source: &B,
    ) -> Result<Vec<(bitcoin::Txid, u32, u64, u32)>, IndexError> {
        let mut candidate_heights = HashSet::new();
        for (txid, vout, _, _) in &outputs {
            let outpoint = bitcoin::OutPoint {
                txid: *txid,
                vout: *vout,
            };
            candidate_heights.extend(
                self.iter_spending_rows(&outpoint)?
                    .into_iter()
                    .map(crate::HashPrefixRow::height),
            );
        }

        let mut spent = HashSet::new();
        for height in candidate_heights {
            let block = source
                .block_at_height(height)
                .ok_or(IndexError::QueryBlockUnavailable { height })?;
            spent.extend(
                block
                    .txdata
                    .iter()
                    .flat_map(|tx| &tx.input)
                    .map(|input| input.previous_output),
            );
        }
        Ok(outputs
            .into_iter()
            .filter(|(txid, vout, _, _)| {
                !spent.contains(&bitcoin::OutPoint {
                    txid: *txid,
                    vout: *vout,
                })
            })
            .collect())
    }

    /// Iterates confirmed transaction-id rows matching `txid`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the txid's scan
    /// prefix, decoded from `ColumnFamily::TxConfirmed`. The 8-byte prefix is
    /// lossy; multiple txids can share a prefix.
    pub fn iter_txid_rows(
        &self,
        txid: &bitcoin::Txid,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves a transaction by txid via `source`.
    ///
    /// Scans `iter_txid_rows(txid)` for candidate `(prefix, height)` entries.
    /// For each height, fetches the block and looks for the transaction whose
    /// full computed txid matches `txid` exactly. Returns the first match, or
    /// `None` if no candidates resolve to the requested txid.
    ///
    /// The 8-byte prefix is lossy; this method exact-resolves it by comparing
    /// the full 32-byte txid before returning.
    pub fn resolve_transaction<B: BlockSource + ?Sized>(
        &self,
        txid: bitcoin::Txid,
        source: &B,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                if tx.compute_txid() == txid {
                    return Ok(Some(tx.clone()));
                }
            }
        }
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    pub fn resolve_outpoint_value<B: BlockSource + ?Sized>(
        &self,
        outpoint: bitcoin::OutPoint,
        source: &B,
    ) -> Result<Option<u64>, IndexError> {
        let Some(tx) = self.resolve_transaction(outpoint.txid, source)? else {
            return Ok(None);
        };
        let Ok(vout_idx) = usize::try_from(outpoint.vout) else {
            return Ok(None);
        };
        Ok(tx.output.get(vout_idx).map(|output| output.value.to_sat()))
    }

    /// Resolves multiple outpoint values while loading and scanning each
    /// candidate block at most once.
    pub fn resolve_outpoint_values<B: BlockSource + ?Sized>(
        &self,
        outpoints: &[bitcoin::OutPoint],
        source: &B,
    ) -> Result<Vec<Option<u64>>, IndexError> {
        let wanted = outpoints
            .iter()
            .map(|outpoint| outpoint.txid)
            .collect::<HashSet<_>>();
        let mut candidate_heights = HashSet::new();
        for txid in &wanted {
            candidate_heights.extend(
                self.iter_txid_rows(txid)?
                    .into_iter()
                    .map(crate::HashPrefixRow::height),
            );
        }
        let mut transactions = HashMap::with_capacity(wanted.len());
        for height in candidate_heights {
            let block = source
                .block_at_height(height)
                .ok_or(IndexError::QueryBlockUnavailable { height })?;
            for tx in block.txdata {
                let txid = tx.compute_txid();
                if wanted.contains(&txid) {
                    transactions.entry(txid).or_insert(tx);
                }
            }
        }
        Ok(outpoints
            .iter()
            .map(|outpoint| {
                let vout = usize::try_from(outpoint.vout).ok()?;
                transactions
                    .get(&outpoint.txid)?
                    .output
                    .get(vout)
                    .map(|output| output.value.to_sat())
            })
            .collect())
    }

    /// Resolves a transaction by txid and returns it alongside the block
    /// height where it was confirmed.
    ///
    /// Same scanning strategy as [`resolve_transaction`]: iterates the
    /// `iter_txid_rows(txid)` prefix candidates, fetches each candidate height's
    /// block via `source`, and compares full-32-byte txid for exact match.
    /// Returns the first match.
    ///
    /// Cost: O(R + B) where R = number of prefix rows for `txid` and B = block
    /// fetch cost per candidate height.
    pub fn resolve_tx_with_height<B: BlockSource + ?Sized>(
        &self,
        txid: bitcoin::Txid,
        source: &B,
    ) -> Result<Option<(bitcoin::Transaction, u32)>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<bitcoin::Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txdata {
                if tx.compute_txid() == txid {
                    return Ok(Some((tx.clone(), height)));
                }
            }
        }
        Ok(None)
    }

    const FLUSH_THRESHOLD_ROWS: usize = 500_000;

    /// Walks one serialized block once with `bitcoin_slices` and writes electrs-shaped rows.
    pub fn ingest_block(
        &mut self,
        block: &[u8],
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, _txid_count) = pending_rows_for_block(block, height, TxidSource::Compute)?;
        self.ingest_rows(rows)
    }

    /// Walks one serialized block and reuses caller-supplied transaction IDs after validation.
    ///
    /// Falls back to hashing transactions from `block` for any missing or mismatched entry,
    /// preserving `ingest_block` semantics for mismatched input.
    pub fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, txid_count) =
            pending_rows_for_block(block, height, TxidSource::Validate(txids))?;
        if txids.len() != txid_count {
            return self.ingest_block(block, height);
        }
        self.ingest_rows(rows)
    }

    /// Walks one serialized block using caller-verified transaction IDs.
    ///
    /// This preserves [`Self::ingest_block_with_txids`] for untrusted callers while allowing
    /// block-apply code to avoid hashing transactions a second time after it has already built
    /// txids from the same block.
    pub fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, txid_count) = pending_rows_for_block(block, height, TxidSource::Trusted(txids))?;
        if txids.len() != txid_count {
            return self.ingest_block(block, height);
        }
        self.ingest_rows(rows)
    }

    /// Walks one decoded block using caller-verified transaction IDs.
    ///
    /// The serialized block is retained only as the safe fallback path when the caller-provided
    /// transaction-id count does not match the decoded block. Normal callers must pass the
    /// consensus serialization of `block` as `serialized_block`.
    pub fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        if txids.len() != block.txdata.len() {
            return self.ingest_block_with_verified_txids(serialized_block, height, txids);
        }
        let rows = pending_rows_for_decoded_block(block, height, txids)?;
        self.ingest_rows(rows)
    }

    /// Deletes every index row that ingesting `block` at `height` would have written.
    ///
    /// Derives the same txid, funding, spending, and header row keys as
    /// [`Self::ingest_decoded_block_with_verified_txids`] by reusing the shared
    /// row-construction code, then issues all deletions in a single atomic
    /// [`KvStore::write`] batch. Either the entire block's rows are removed or
    /// the method returns `Err` having deleted nothing observable.
    ///
    /// Deleting a row that is already absent is not an error: the indexer may
    /// have been enabled after `block` was applied, so its rows may never have
    /// existed. The returned [`IndexRowCounts`] reflects the rows targeted for
    /// deletion (the same counts a matching ingest would have written), which
    /// may be zero on a repeat call or when the block was never indexed.
    ///
    /// Any buffered rows are flushed first. Deletion writes straight to the
    /// store, so unflushed rows for the block being disconnected would survive
    /// in `pending_rows` and a later [`Self::end_batch`] would resurrect the
    /// very block just rolled back. Flushing first also keeps the all-or-
    /// nothing property: a failing flush returns `Err` before anything is
    /// deleted.
    pub fn rollback_block(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        // Buffered rows must reach the store before the deletes, or a later
        // end_batch would write back the block being disconnected.
        self.flush()?;
        let txids: Vec<bitcoin::Txid> = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect();
        self.rollback_block_inner(block, height, &txids)
    }

    /// Same as [`Self::rollback_block`] but reuses caller-verified transaction
    /// IDs, avoiding a second pass of `compute_txid` when the caller has
    /// already computed them for merkle verification.
    ///
    /// Falls back to [`Self::rollback_block`] when the supplied txid count
    /// does not match the block's transaction count, preserving semantics for
    /// mismatched input.
    pub fn rollback_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        self.flush()?;
        if txids.len() != block.txdata.len() {
            return self.rollback_block(block, height);
        }
        self.rollback_block_inner(block, height, txids)
    }

    fn rollback_block_inner(
        &self,
        block: &bitcoin::Block,
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let mut rows = pending_rows_for_decoded_block(block, height, txids)?;
        rows.sort();
        let counts = rows.counts();

        // Only delete if this block's header row is still there.
        //
        // Funding, spending, and txid keys are an 8-byte prefix plus the
        // height, carrying no block identity, so a replacement block at the
        // same height that shares any data — the same output script is enough —
        // derives the same keys. Rolling this block back a second time, after
        // the replacement was indexed, would delete the replacement's rows and
        // leave Electrum missing active-chain history.
        //
        // The header row is the identity: its key is the 80-byte serialized
        // header, and the block hash is the double-SHA256 of exactly those
        // bytes, so no two blocks share one. Its absence means this block is
        // already rolled back and the keys now belong to whatever replaced it.
        // Rekeying the other three families would carry block identity
        // directly, but it would break the electrs-compatible layout and force
        // a reindex, which is a far larger change than the bug warrants.
        // A read failure is propagated, not treated as absence: silently
        // reporting a clean rollback because storage was unreachable would
        // leave the caller believing the block is gone.
        let identity_present = match rows.header_rows.first() {
            Some(header) => self
                .store
                .get(ColumnFamily::BlockHeaders, header)?
                .is_some(),
            None => false,
        };
        if !identity_present {
            debug!(
                height,
                "rollback skipped: block header row absent, rows belong to another block"
            );
            return Ok(counts);
        }

        let mut batch = self.store.new_batch();
        for row in &rows.txid_rows {
            batch.delete(ColumnFamily::TxConfirmed, row.as_bytes());
        }
        for row in &rows.funding_rows {
            batch.delete(ColumnFamily::Funding, row.as_bytes());
        }
        for row in &rows.spending_rows {
            batch.delete(ColumnFamily::Spending, row.as_bytes());
        }
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
        self.store.write(batch)?;
        debug!(
            txids = counts.txids,
            funding = counts.funding,
            spending = counts.spending,
            headers = counts.headers,
            "rolled back block"
        );
        Ok(counts)
    }

    fn ingest_rows(&mut self, mut rows: PendingRows) -> Result<IndexRowCounts, IndexError> {
        // Dedup before counting: a block can generate the same funding or
        // spending row twice, and only one copy is ever written. Counting the
        // raw rows would report more rows than the store receives.
        rows.sort();
        let block_counts = rows.counts();
        self.pending_rows.append(rows);
        if self.batch_depth == 0 || self.pending_rows.total() >= Self::FLUSH_THRESHOLD_ROWS {
            self.flush()?;
        }
        Ok(block_counts)
    }

    fn flush(&mut self) -> Result<IndexRowCounts, IndexError> {
        self.pending_rows.sort();
        let counts = self.pending_rows.counts();
        if counts.txids + counts.funding + counts.spending + counts.headers == 0 {
            return Ok(counts);
        }
        let mut batch = self.store.new_batch();
        for row in &self.pending_rows.txid_rows {
            batch.put(ColumnFamily::TxConfirmed, row.as_bytes(), &[]);
        }
        for row in &self.pending_rows.funding_rows {
            batch.put(ColumnFamily::Funding, row.as_bytes(), &[]);
        }
        for row in &self.pending_rows.spending_rows {
            batch.put(ColumnFamily::Spending, row.as_bytes(), &[]);
        }
        for row in &self.pending_rows.header_rows {
            batch.put(ColumnFamily::BlockHeaders, row, &[]);
        }
        self.store.write(batch)?;
        self.last_counts = counts;
        self.pending_rows = PendingRows::default();
        debug!(
            txids = counts.txids,
            funding = counts.funding,
            spending = counts.spending,
            headers = counts.headers,
            "indexed batch"
        );
        Ok(counts)
    }

    /// Disables per-block flushing so multiple ingests can be written in one batch.
    pub fn begin_batch(&mut self) {
        self.batch_depth = self.batch_depth.saturating_add(1);
    }

    /// Re-enables per-block flushing and flushes any accumulated rows.
    pub fn end_batch(&mut self) -> Result<(), IndexError> {
        self.batch_depth = self.batch_depth.saturating_sub(1);
        if self.batch_depth == 0 {
            self.flush()?;
        }
        Ok(())
    }
}

fn validate_block_identity(
    block: &bitcoin::Block,
    height: u32,
    expected_hash: Hash256,
) -> Result<(), IndexError> {
    let actual = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    if actual != expected_hash {
        return Err(IndexError::BlockIdentityMismatch {
            height,
            expected: expected_hash,
            actual,
        });
    }
    if !block.check_merkle_root() {
        return Err(IndexError::InvalidMerkleRoot {
            height,
            hash: actual,
        });
    }
    Ok(())
}

fn put_rows<B: bitcoin_rs_storage::WriteBatch>(batch: &mut B, rows: &PendingRows) {
    for row in &rows.txid_rows {
        batch.put(ColumnFamily::TxConfirmed, row.as_bytes(), &[]);
    }
    for row in &rows.funding_rows {
        batch.put(ColumnFamily::Funding, row.as_bytes(), &[]);
    }
    for row in &rows.spending_rows {
        batch.put(ColumnFamily::Spending, row.as_bytes(), &[]);
    }
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
}

fn delete_rows<B: bitcoin_rs_storage::WriteBatch>(batch: &mut B, rows: &PendingRows) {
    for row in &rows.txid_rows {
        batch.delete(ColumnFamily::TxConfirmed, row.as_bytes());
    }
    for row in &rows.funding_rows {
        batch.delete(ColumnFamily::Funding, row.as_bytes());
    }
    for row in &rows.spending_rows {
        batch.delete(ColumnFamily::Spending, row.as_bytes());
    }
    for row in &rows.header_rows {
        batch.delete(ColumnFamily::BlockHeaders, row);
    }
}

fn pending_rows_for_block(
    block: &[u8],
    height: u32,
    txids: TxidSource<'_>,
) -> Result<(PendingRows, usize), IndexError> {
    let mut rows = PendingRows::default();
    let txid_count = {
        let mut visitor = IndexBlockVisitor {
            rows: &mut rows,
            height_bytes: height.to_le_bytes(),
            txids,
            txid_count: 0,
            invalid_header_len: None,
        };
        match bsl::Block::visit(block, &mut visitor) {
            Ok(_) => visitor.txid_count,
            Err(bitcoin_slices::Error::VisitBreak) => {
                if let Some(len) = visitor.invalid_header_len {
                    return Err(IndexError::InvalidHeaderLength { len });
                }
                return Err(IndexError::BlockParse(bitcoin_slices::Error::VisitBreak));
            }
            Err(error) => return Err(IndexError::BlockParse(error)),
        }
    };
    Ok((rows, txid_count))
}

fn pending_rows_for_decoded_block(
    block: &bitcoin::Block,
    height: u32,
    txids: &[bitcoin::Txid],
) -> Result<PendingRows, IndexError> {
    let mut rows = PendingRows::default();
    let header_bytes = bitcoin::consensus::encode::serialize(&block.header);
    let Some(header) = HeaderRow::from_header_bytes(&header_bytes) else {
        return Err(IndexError::InvalidHeaderLength {
            len: header_bytes.len(),
        });
    };
    rows.header_rows.push(header.to_db_row());
    for (tx, txid) in block.txdata.iter().zip(txids) {
        rows.txid_rows.push(TxidRow::row(txid, height));
        for tx_in in &tx.input {
            if !tx_in.previous_output.is_null() {
                rows.spending_rows
                    .push(SpendingPrefixRow::row(&tx_in.previous_output, height));
            }
        }
        for tx_out in &tx.output {
            if !is_op_return_script(tx_out.script_pubkey.as_bytes()) {
                let scripthash = ScriptHash::new(&tx_out.script_pubkey);
                rows.funding_rows
                    .push(ScriptHashRow::row(scripthash, height));
            }
        }
    }
    Ok(rows)
}

#[derive(Default)]
struct PendingRows {
    txid_rows: Vec<HashPrefixRow>,
    funding_rows: Vec<HashPrefixRow>,
    spending_rows: Vec<HashPrefixRow>,
    header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
}

impl PendingRows {
    fn sort(&mut self) {
        self.txid_rows.sort_unstable();
        self.funding_rows.sort_unstable();
        self.spending_rows.sort_unstable();
        self.header_rows.sort_unstable();
        self.txid_rows.dedup();
        self.funding_rows.dedup();
        self.spending_rows.dedup();
        self.header_rows.dedup();
    }

    const fn counts(&self) -> IndexRowCounts {
        IndexRowCounts {
            txids: self.txid_rows.len(),
            funding: self.funding_rows.len(),
            spending: self.spending_rows.len(),
            headers: self.header_rows.len(),
        }
    }
    fn append(&mut self, other: Self) {
        self.txid_rows.extend(other.txid_rows);
        self.funding_rows.extend(other.funding_rows);
        self.spending_rows.extend(other.spending_rows);
        self.header_rows.extend(other.header_rows);
    }

    fn total(&self) -> usize {
        self.txid_rows.len()
            + self.funding_rows.len()
            + self.spending_rows.len()
            + self.header_rows.len()
    }
}

struct IndexBlockVisitor<'a> {
    rows: &'a mut PendingRows,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    txids: TxidSource<'a>,
    txid_count: usize,
    invalid_header_len: Option<usize>,
}

impl Visitor for IndexBlockVisitor<'_> {
    fn visit_block_header(&mut self, header: &bsl::BlockHeader<'_>) -> ControlFlow<()> {
        let Some(row) = HeaderRow::from_header_bytes(header.as_ref()) else {
            self.invalid_header_len = Some(header.as_ref().len());
            return ControlFlow::Break(());
        };
        self.rows.header_rows.push(row.to_db_row());
        ControlFlow::Continue(())
    }

    fn visit_transaction(&mut self, tx: &bsl::Transaction<'_>) -> ControlFlow<()> {
        match self.txids {
            TxidSource::Compute => {
                let txid = tx.txid_sha2();
                self.rows
                    .txid_rows
                    .push(TxidRow::row_bytes(txid.as_slice(), self.height_bytes));
            }
            TxidSource::Validate(txids) => {
                if let Some(txid) = txids.get(self.txid_count) {
                    let computed = tx.txid_sha2();
                    let txid_bytes: &[u8] = txid.as_ref();
                    if txid_bytes == computed.as_slice() {
                        self.rows
                            .txid_rows
                            .push(TxidRow::row_bytes(txid_bytes, self.height_bytes));
                    } else {
                        self.rows
                            .txid_rows
                            .push(TxidRow::row_bytes(computed.as_slice(), self.height_bytes));
                    }
                } else {
                    let txid = tx.txid_sha2();
                    self.rows
                        .txid_rows
                        .push(TxidRow::row_bytes(txid.as_slice(), self.height_bytes));
                }
            }
            TxidSource::Trusted(txids) => {
                if let Some(txid) = txids.get(self.txid_count) {
                    self.rows
                        .txid_rows
                        .push(TxidRow::row_bytes(txid.as_ref(), self.height_bytes));
                } else {
                    let txid = tx.txid_sha2();
                    self.rows
                        .txid_rows
                        .push(TxidRow::row_bytes(txid.as_slice(), self.height_bytes));
                }
            }
        }
        self.txid_count += 1;
        ControlFlow::Continue(())
    }

    fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn<'_>) -> ControlFlow<()> {
        let prevout = tx_in.prevout();
        if !is_null_prevout(prevout) {
            self.rows.spending_rows.push(SpendingPrefixRow::row_parts(
                prevout.txid(),
                prevout.vout(),
                self.height_bytes,
            ));
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut<'_>) -> ControlFlow<()> {
        let script = tx_out.script_pubkey();
        if !is_op_return_script(script) {
            self.rows.funding_rows.push(HashPrefixRow {
                prefix: ScriptHash::from_script_bytes(script).prefix(),
                height: self.height_bytes,
            });
        }
        ControlFlow::Continue(())
    }
}

fn is_null_prevout(prevout: &bsl::OutPoint<'_>) -> bool {
    prevout.vout() == u32::MAX && prevout.txid().iter().all(|byte| *byte == 0)
}

#[inline]
fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
}

#[derive(Clone, Copy)]
enum TxidSource<'a> {
    Compute,
    Validate(&'a [bitcoin::Txid]),
    Trusted(&'a [bitcoin::Txid]),
}

fn collect_prefix_rows(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
    collect_prefix_rows_limited(iter, usize::MAX, "prefix-row")
}

fn collect_prefix_rows_limited(
    iter: bitcoin_rs_storage::KvIter<'_>,
    limit: usize,
    resource: &'static str,
) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, _value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            if rows.len() >= limit {
                return Err(IndexError::QueryLimitExceeded { resource, limit });
            }
            rows.push(
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
            );
        }
    }
    Ok(rows)
}

#[cfg(all(test, feature = "fjall"))]
mod watermark_tests {
    use std::sync::Arc;

    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_storage::{ColumnFamily, FjallStore, KvStore, WriteBatch as _};
    use zerocopy::IntoBytes as _;

    use super::{BlockSource, IndexConnect, IndexError, IndexWatermark, Indexer};

    struct OneBlockSource(bitcoin::Block);

    impl BlockSource for OneBlockSource {
        fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
            (height == 0).then(|| self.0.clone())
        }
    }

    fn child_of(parent: &bitcoin::Block) -> bitcoin::Block {
        let mut child = parent.clone();
        child.header.prev_blockhash = parent.block_hash();
        child.header.time = child.header.time.saturating_add(1);
        child.header.nonce = child.header.nonce.wrapping_add(1);
        child
    }

    #[test]
    fn atomic_connect_publishes_rows_and_exact_watermark() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(Arc::clone(&store));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());

        indexer.connect_block_atomic(&genesis, 0, hash)?;

        assert_eq!(
            indexer.watermark()?,
            Some(IndexWatermark { height: 0, hash })
        );
        assert!(
            store
                .get(ColumnFamily::BlockHeaders, &serialize(&genesis.header))?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn limited_unspent_resolution_refuses_excess_funding_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let output = genesis
            .txdata
            .first()
            .and_then(|tx| tx.output.first())
            .ok_or_else(|| std::io::Error::other("genesis output missing"))?;
        let scripthash = crate::ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        indexer.ingest_block(&serialize(&genesis), 0)?;

        assert!(matches!(
            indexer.resolve_unspent_outputs_with_height_limited(
                scripthash,
                &OneBlockSource(genesis),
                0
            ),
            Err(IndexError::QueryLimitExceeded {
                resource: "funding-row",
                limit: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn atomic_multi_block_connect_publishes_only_terminal_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let child = child_of(&genesis);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let child_hash = Hash256::from_le_bytes(child.block_hash().as_byte_array());

        indexer.connect_blocks_atomic(&[
            IndexConnect {
                block: &genesis,
                height: 0,
                hash: genesis_hash,
            },
            IndexConnect {
                block: &child,
                height: 1,
                hash: child_hash,
            },
        ])?;

        assert_eq!(
            indexer.watermark()?,
            Some(IndexWatermark {
                height: 1,
                hash: child_hash,
            })
        );
        Ok(())
    }

    #[test]
    fn prepared_connect_does_not_publish_until_commit() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let prepared = indexer
            .prepare_connect_blocks(&[IndexConnect {
                block: &genesis,
                height: 0,
                hash,
            }])?
            .ok_or_else(|| std::io::Error::other("missing prepared transition"))?;

        assert_eq!(indexer.watermark()?, None);
        indexer.commit_prepared_connect(&prepared)?;
        assert_eq!(
            indexer.watermark()?,
            Some(IndexWatermark { height: 0, hash })
        );
        Ok(())
    }

    #[test]
    fn spending_prefix_collision_is_not_reported_as_spent() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let indexer = Indexer::new(Arc::clone(&store));
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x77; 32]),
            vout: 3,
        };
        let row = crate::SpendingPrefixRow::row(&outpoint, 0);
        store.put(ColumnFamily::Spending, row.as_bytes(), &[])?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        assert!(indexer.has_spending_rows(&outpoint)?);
        assert!(!indexer.is_outpoint_spent(&outpoint, &OneBlockSource(genesis))?);
        let outputs = vec![(outpoint.txid, outpoint.vout, 42, 0)];
        assert_eq!(
            indexer.filter_unspent_outputs_with_height(
                outputs.clone(),
                &OneBlockSource(bitcoin::blockdata::constants::genesis_block(
                    bitcoin::Network::Regtest
                ))
            )?,
            outputs
        );
        Ok(())
    }

    #[test]
    fn batch_outpoint_values_preserve_order_and_missing_entries()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let txid = genesis
            .txdata
            .first()
            .ok_or_else(|| std::io::Error::other("genesis transaction missing"))?
            .compute_txid();
        indexer.ingest_block(&serialize(&genesis), 0)?;
        let present = bitcoin::OutPoint { txid, vout: 0 };
        let missing = bitcoin::OutPoint { txid, vout: 99 };

        assert_eq!(
            indexer
                .resolve_outpoint_values(&[present, missing, present], &OneBlockSource(genesis))?,
            vec![Some(5_000_000_000), None, Some(5_000_000_000)]
        );
        Ok(())
    }

    #[test]
    fn strict_rollback_refuses_missing_identity_without_moving_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(Arc::clone(&store));
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        indexer.connect_block_atomic(&genesis, 0, genesis_hash)?;
        let child = child_of(&genesis);
        let child_hash = Hash256::from_le_bytes(child.block_hash().as_byte_array());
        let watermark = IndexWatermark {
            height: 1,
            hash: child_hash,
        };
        indexer.connect_block_atomic(&child, 1, child_hash)?;

        let mut batch = store.new_batch();
        batch.delete(ColumnFamily::BlockHeaders, &serialize(&child.header));
        store.write(batch)?;

        let error = indexer
            .rollback_block_atomic(&child, watermark)
            .expect_err("missing identity must refuse strict rollback");
        assert!(matches!(error, IndexError::MissingWatermarkIdentity { .. }));
        assert_eq!(indexer.watermark()?, Some(watermark));
        Ok(())
    }

    #[test]
    fn atomic_connect_rejects_wrong_hash_without_creating_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let wrong_hash = Hash256::from_le_bytes(&[0x55; 32]);

        let error = indexer
            .connect_block_atomic(&genesis, 0, wrong_hash)
            .expect_err("wrong block identity must fail");

        assert!(matches!(error, IndexError::BlockIdentityMismatch { .. }));
        assert_eq!(indexer.watermark()?, None);
        Ok(())
    }

    #[test]
    fn atomic_connect_rejects_invalid_merkle_without_creating_watermark()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(FjallStore::open(dir.path())?);
        let mut indexer = Indexer::new(store);
        let mut genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        genesis.txdata[0].output[0].value = bitcoin::Amount::from_sat(1);
        let header_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());

        let error = indexer
            .connect_block_atomic(&genesis, 0, header_hash)
            .expect_err("invalid Merkle identity must fail");

        assert!(matches!(error, IndexError::InvalidMerkleRoot { .. }));
        assert_eq!(indexer.watermark()?, None);
        Ok(())
    }
}

/// Storage-agnostic block-ingest interface.
///
/// Use this trait when consumers must hold the indexer behind a trait
/// object (e.g. when the storage backend is selected at runtime).
pub trait IndexerLike: Send + Sync {
    /// Loads the exact durable watermark owned by an asynchronous index worker.
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Atomically connects one exact block and advances the durable watermark.
    fn connect_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        expected_hash: Hash256,
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = (block, height, expected_hash);
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Atomically connects a contiguous slice and publishes only its terminal watermark.
    fn connect_blocks_atomic(
        &mut self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = blocks;
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Constructs a forward transition without mutating storage.
    fn prepare_connect_blocks(
        &self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<Option<PreparedIndexConnect>, IndexError> {
        let _ = blocks;
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Commits rows produced by [`IndexerLike::prepare_connect_blocks`].
    fn commit_prepared_connect(
        &mut self,
        prepared: &PreparedIndexConnect,
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = prepared;
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Atomically rolls back the exact watermark block and retreats to its parent.
    fn rollback_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = (block, watermark);
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Constructs a rollback transition without mutating storage.
    fn prepare_rollback_block(
        &self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<PreparedIndexRollback, IndexError> {
        let _ = (block, watermark);
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Commits rows produced by [`IndexerLike::prepare_rollback_block`].
    fn commit_prepared_rollback(
        &mut self,
        prepared: &PreparedIndexRollback,
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = prepared;
        Err(IndexError::UnsupportedWatermarkTransition)
    }

    /// Walks `block` once and writes index rows. See `Indexer::ingest_block`.
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError>;

    /// Walks `block` once and writes index rows, reusing precomputed transaction IDs when supported.
    ///
    /// The default implementation preserves existing implementations by ignoring `txids` and
    /// delegating to [`IndexerLike::ingest_block`].
    fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = txids;
        self.ingest_block(block, height)
    }

    /// Walks `block` once and writes index rows, trusting caller-verified transaction IDs when
    /// supported.
    ///
    /// The default implementation preserves existing implementations by validating through
    /// [`IndexerLike::ingest_block_with_txids`].
    fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        self.ingest_block_with_txids(block, height, txids)
    }

    /// Walks a decoded block and writes rows, trusting caller-verified transaction IDs when
    /// supported.
    ///
    /// The default implementation preserves existing implementations by validating through
    /// [`IndexerLike::ingest_block_with_verified_txids`].
    fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = block;
        self.ingest_block_with_verified_txids(serialized_block, height, txids)
    }

    /// Deletes every index row that ingesting `block` at `height` would have written.
    ///
    /// The inverse of the ingest methods above. The default returns
    /// [`IndexError::UnsupportedRollback`] rather than succeeding: an
    /// implementation that silently reports a successful rollback while
    /// deleting nothing would let the node advance its tip believing the index
    /// is consistent, and the Electrum server would then serve transactions
    /// that are no longer in the chain. Failing loudly is the only safe
    /// default. Concrete indexers that persist rows override this.
    fn rollback_block(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = (block, height);
        Err(IndexError::UnsupportedRollback)
    }

    /// Same as [`IndexerLike::rollback_block`] but reuses caller-verified
    /// transaction IDs when supported.
    ///
    /// The default implementation preserves existing implementations by
    /// ignoring `txids` and delegating to [`IndexerLike::rollback_block`].
    fn rollback_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = txids;
        self.rollback_block(block, height)
    }

    /// Begins a batch of block ingests; rows are not flushed until [`IndexerLike::end_batch`].
    fn begin_batch(&mut self) {}

    /// Ends a batch of block ingests, flushing any accumulated rows.
    fn end_batch(&mut self) -> Result<(), IndexError> {
        Ok(())
    }

    /// Resolves a confirmed transaction by txid via `source`.
    ///
    /// Default implementations may return `Ok(None)` when the concrete indexer
    /// does not support transaction lookup.
    fn resolve_transaction(
        &self,
        txid: bitcoin::Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        let _ = (txid, source);
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    fn resolve_outpoint_value(
        &self,
        outpoint: bitcoin::OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError>;
}

/// Provides block lookups for resolving lossy index prefixes to full identities.
///
/// The index column families store 8-byte prefixes of txids/scripthashes/outpoints.
/// To recover the full Bitcoin identities behind a `HashPrefixRow`, callers need
/// to fetch the block at the row's height and walk its transactions. `BlockSource`
/// is the trait that hides where blocks come from (in-memory store, raw-block KV
/// database, peer fetch).
pub trait BlockSource {
    /// Returns the Bitcoin block at `height` on the active chain, if known.
    fn block_at_height(&self, height: u32) -> Option<bitcoin::Block>;
}

impl<S: KvStore + Send + Sync + 'static> IndexerLike for Indexer<S> {
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        Self::watermark(self)
    }

    fn connect_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        expected_hash: Hash256,
    ) -> Result<IndexRowCounts, IndexError> {
        Self::connect_block_atomic(self, block, height, expected_hash)
    }

    fn connect_blocks_atomic(
        &mut self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::connect_blocks_atomic(self, blocks)
    }

    fn prepare_connect_blocks(
        &self,
        blocks: &[IndexConnect<'_>],
    ) -> Result<Option<PreparedIndexConnect>, IndexError> {
        Self::prepare_connect_blocks(self, blocks)
    }

    fn commit_prepared_connect(
        &mut self,
        prepared: &PreparedIndexConnect,
    ) -> Result<IndexRowCounts, IndexError> {
        Self::commit_prepared_connect(self, prepared)
    }

    fn rollback_block_atomic(
        &mut self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<IndexRowCounts, IndexError> {
        Self::rollback_block_atomic(self, block, watermark)
    }

    fn prepare_rollback_block(
        &self,
        block: &bitcoin::Block,
        watermark: IndexWatermark,
    ) -> Result<PreparedIndexRollback, IndexError> {
        Self::prepare_rollback_block(self, block, watermark)
    }

    fn commit_prepared_rollback(
        &mut self,
        prepared: &PreparedIndexRollback,
    ) -> Result<IndexRowCounts, IndexError> {
        Self::commit_prepared_rollback(self, prepared)
    }

    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block(self, block, height)
    }

    fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block_with_txids(self, block, height, txids)
    }

    fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block_with_verified_txids(self, block, height, txids)
    }

    fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_decoded_block_with_verified_txids(self, block, serialized_block, height, txids)
    }

    fn rollback_block(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        Self::rollback_block(self, block, height)
    }

    fn rollback_block_with_verified_txids(
        &mut self,
        block: &bitcoin::Block,
        height: u32,
        txids: &[bitcoin::Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::rollback_block_with_verified_txids(self, block, height, txids)
    }

    fn begin_batch(&mut self) {
        Self::begin_batch(self);
    }

    fn end_batch(&mut self) -> Result<(), IndexError> {
        Self::end_batch(self)
    }

    fn resolve_transaction(
        &self,
        txid: bitcoin::Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<bitcoin::Transaction>, IndexError> {
        Self::resolve_transaction(self, txid, source)
    }

    fn resolve_outpoint_value(
        &self,
        outpoint: bitcoin::OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError> {
        Self::resolve_outpoint_value(self, outpoint, source)
    }
}

#[cfg(all(test, feature = "rocksdb"))]
mod tests {
    use std::sync::Arc;

    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
        TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};

    use super::{BlockSource, Indexer, is_op_return_script};
    use crate::{HistoryEntry, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow};

    const HEIGHT: u32 = 42;
    type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

    #[test]
    fn raw_op_return_check_matches_script_prefix_semantics() {
        assert!(!is_op_return_script(&[]));
        assert!(is_op_return_script(&[0x6a]));
        assert!(is_op_return_script(&[0x6a, 0x01, 0x00]));
        assert!(!is_op_return_script(&[0x00, 0x6a]));
    }

    #[test]
    fn iter_block_headers_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        indexer.ingest_block(&serialize(&genesis), 0)?;

        let rows = indexer.iter_block_headers()?;
        assert_eq!(rows.len(), 1);
        Ok(())
    }

    #[test]
    fn iter_block_header_hashes_empty_index_returns_empty() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, indexer) = indexer()?;
        assert!(indexer.iter_block_header_hashes()?.is_empty());
        Ok(())
    }

    #[test]
    fn iter_block_header_hashes_returns_genesis_after_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&block);
        indexer.ingest_block(&bytes, 0)?;
        let hashes = indexer.iter_block_header_hashes()?;
        assert_eq!(hashes.len(), 1);
        let expected = bitcoin_rs_primitives::Hash256::from_le_bytes(
            &block.header.block_hash().to_byte_array(),
        );
        assert_eq!(hashes[0], expected);
        Ok(())
    }

    #[test]
    fn header_count_returns_one_after_genesis_ingest() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        assert_eq!(indexer.header_count()?, 0);

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        indexer.ingest_block(&serialize(&genesis), 0)?;

        assert_eq!(indexer.header_count()?, 1);
        Ok(())
    }

    #[test]
    fn tip_height_indexed_returns_none_for_empty_index() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        assert!(indexer.tip_height_indexed()?.is_none());
        Ok(())
    }

    #[test]
    fn tip_height_indexed_returns_zero_after_genesis_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        indexer.ingest_block(&serialize(&genesis), 0)?;

        assert_eq!(indexer.tip_height_indexed()?, Some(0));
        Ok(())
    }

    #[test]
    fn iter_funding_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let script = ScriptBuf::from_bytes(vec![0x51, 0x01]);
        let tx = tx(spent_outpoint(1, 0), script.clone());
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        let scripthash = ScriptHash::from_script_bytes(script.as_bytes());
        assert_eq!(
            indexer.iter_funding_rows(scripthash)?,
            vec![ScriptHashRow::row(scripthash, HEIGHT)]
        );
        Ok(())
    }

    #[test]
    fn iter_spending_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let outpoint = spent_outpoint(2, 3);
        let tx = tx(outpoint, ScriptBuf::from_bytes(vec![0x51, 0x02]));
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        assert_eq!(
            indexer.iter_spending_rows(&outpoint)?,
            vec![SpendingPrefixRow::row(&outpoint, HEIGHT)]
        );
        Ok(())
    }

    #[test]
    fn iter_txid_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let tx = tx(
            spent_outpoint(4, 5),
            ScriptBuf::from_bytes(vec![0x51, 0x03]),
        );
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block(vec![tx])), HEIGHT)?;

        let rows = indexer.iter_txid_rows(&txid)?;
        assert!(rows.contains(&TxidRow::row(&txid, HEIGHT)));
        Ok(())
    }

    #[test]
    fn decoded_verified_txid_ingest_matches_serialized_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let coinbase = tx(OutPoint::null(), ScriptBuf::from_bytes(vec![0x51, 0x04]));
        let spender = Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent_outpoint(9, 1),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(5_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x05]),
                },
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x6a, 0x01, 0x00]),
                },
            ],
        };
        let block = block(vec![coinbase, spender]);
        let block_bytes = serialize(&block);
        let txids = block
            .txdata
            .iter()
            .map(Transaction::compute_txid)
            .collect::<Vec<_>>();
        let (_serialized_dir, mut serialized_indexer) = indexer()?;
        let (_decoded_dir, mut decoded_indexer) = indexer()?;

        let serialized_counts =
            serialized_indexer.ingest_block_with_verified_txids(&block_bytes, HEIGHT, &txids)?;
        let decoded_counts = decoded_indexer.ingest_decoded_block_with_verified_txids(
            &block,
            &block_bytes,
            HEIGHT,
            &txids,
        )?;

        assert_eq!(decoded_counts, serialized_counts);
        assert_eq!(
            stored_rows(&decoded_indexer)?,
            stored_rows(&serialized_indexer)?
        );
        Ok(())
    }

    #[test]
    fn decoded_verified_txid_ingest_mismatch_falls_back_to_serialized_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoded_block = block(vec![tx(
            OutPoint::null(),
            ScriptBuf::from_bytes(vec![0x51, 0x08]),
        )]);
        let serialized_block = block(vec![
            tx(OutPoint::null(), ScriptBuf::from_bytes(vec![0x51, 0x06])),
            tx(
                spent_outpoint(10, 0),
                ScriptBuf::from_bytes(vec![0x51, 0x07]),
            ),
        ]);
        let serialized_block_bytes = serialize(&serialized_block);
        let (_serialized_dir, mut serialized_indexer) = indexer()?;
        let (_decoded_dir, mut decoded_indexer) = indexer()?;

        let serialized_counts = serialized_indexer.ingest_block(&serialized_block_bytes, HEIGHT)?;
        let decoded_counts = decoded_indexer.ingest_decoded_block_with_verified_txids(
            &decoded_block,
            &serialized_block_bytes,
            HEIGHT,
            &[],
        )?;

        assert_eq!(decoded_counts, serialized_counts);
        assert_eq!(
            stored_rows(&decoded_indexer)?,
            stored_rows(&serialized_indexer)?
        );
        Ok(())
    }

    #[test]
    fn resolve_script_history_returns_entries_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let entries = indexer.resolve_script_history(scripthash, &source)?;

        assert_eq!(entries, vec![HistoryEntry::confirmed(txid, 0)]);
        Ok(())
    }
    #[test]
    fn resolve_unspent_outputs_returns_txid_vout_value_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let value = output.value.to_sat();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value)]);
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_coinbase_for_genesis_block_indexed_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, Some(coinbase));
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_none_when_indexed_height_is_not_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 1,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, None);
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_genesis_coinbase_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_tx_with_height(txid, &source)?;

        assert_eq!(resolved, Some((coinbase, 0)));
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let txid = bitcoin::Txid::from_byte_array([0xff; 32]);
        let source = FakeSource {
            block: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_tx_with_height(txid, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_genesis_coinbase_subsidy()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };
        let value = indexer.resolve_outpoint_value(outpoint, &source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_via_indexerlike_dyn_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let dyn_indexer: &dyn super::IndexerLike = &indexer;
        let dyn_source: &dyn super::BlockSource = &source;
        let outpoint = bitcoin::OutPoint { txid, vout: 0 };
        let value = dyn_indexer.resolve_outpoint_value(outpoint, dyn_source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_vout_out_of_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.compute_txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = bitcoin::OutPoint { txid, vout: 99 };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xff; 32]),
            vout: 0,
        };
        let source = FakeSource {
            block: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_unspent_outputs_with_height_returns_funding_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(tx) = block.txdata.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.output.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let txid = tx.compute_txid();
        let value = output.value.to_sat();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&serialize(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs_with_height(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value, 0)]);
        Ok(())
    }

    #[test]
    fn limited_unspent_resolution_refuses_excess_funding_work()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let output = block
            .txdata
            .first()
            .and_then(|tx| tx.output.first())
            .ok_or_else(|| std::io::Error::other("genesis output missing"))?;
        let scripthash = ScriptHash::from_script_bytes(output.script_pubkey.as_bytes());
        let (_dir, mut indexer) = indexer()?;
        indexer.ingest_block(&serialize(&block), 0)?;
        let source = FakeSource {
            block,
            target_height: 0,
        };

        assert!(matches!(
            indexer.resolve_unspent_outputs_with_height_limited(scripthash, &source, 0),
            Err(IndexError::QueryLimitExceeded {
                resource: "funding-row",
                limit: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn has_spending_rows_checks_only_existence() -> Result<(), Box<dyn std::error::Error>> {
        let outpoint = spent_outpoint(2, 3);
        let candidate = tx(outpoint, ScriptBuf::from_bytes(vec![0x51, 0x02]));
        let (_dir, mut indexer) = indexer()?;

        assert!(!indexer.has_spending_rows(&outpoint)?);
        indexer.ingest_block(&serialize(&block(vec![candidate])), HEIGHT)?;
        assert!(indexer.has_spending_rows(&outpoint)?);
        Ok(())
    }

    struct FakeSource {
        block: Block,
        target_height: u32,
    }

    impl BlockSource for FakeSource {
        fn block_at_height(&self, height: u32) -> Option<Block> {
            if height == self.target_height {
                return Some(self.block.clone());
            }
            None
        }
    }

    /// A block whose rows populate all four column families: a coinbase plus a
    /// spend, so funding and spending rows both exist alongside txid and header
    /// rows.
    fn rollback_fixture_block() -> Block {
        let funded = tx(
            OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
            ScriptBuf::from_bytes(vec![0x51]),
        );
        let spender = tx(
            OutPoint::new(funded.compute_txid(), 0),
            ScriptBuf::from_bytes(vec![0x52]),
        );
        block(vec![funded, spender])
    }

    #[test]
    fn rollback_removes_every_row_a_matching_ingest_wrote() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();
        let before = stored_rows(&indexer)?;

        let written = indexer.ingest_block(&serialize(&candidate), HEIGHT)?;
        let after_ingest = stored_rows(&indexer)?;
        assert!(
            after_ingest.len() > before.len(),
            "fixture must write rows to be a meaningful rollback test"
        );
        // All four column families must be exercised, or the test proves little.
        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
        ] {
            assert!(
                after_ingest.iter().any(|(family, _)| *family == cf),
                "fixture wrote no rows to {cf:?}"
            );
        }

        let removed = indexer.rollback_block(&candidate, HEIGHT)?;
        assert_eq!(removed.txids, written.txids);
        assert_eq!(removed.funding, written.funding);
        assert_eq!(removed.spending, written.spending);
        assert_eq!(removed.headers, written.headers);
        assert_eq!(
            stored_rows(&indexer)?,
            before,
            "rollback must restore the pre-ingest row set exactly"
        );
        Ok(())
    }

    #[test]
    fn last_counts_remains_ingest_after_rollback() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let old = rollback_fixture_block();
        let old_written = indexer.ingest_block(&serialize(&old), HEIGHT)?;
        let _ = indexer.rollback_block(&old, HEIGHT)?;

        // A replacement at the same height with a different shape so its
        // ingest counts differ from the old block's rollback counts.
        let replacement = block(vec![
            tx(
                OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
                ScriptBuf::from_bytes(vec![0x51]),
            ),
            tx(
                OutPoint::new(Txid::all_zeros(), 0xffff_ffff),
                ScriptBuf::from_bytes(vec![0x52]),
            ),
        ]);
        let replacement_written = indexer.ingest_block(&serialize(&replacement), HEIGHT)?;
        assert_ne!(
            replacement_written, old_written,
            "replacement counts must differ from the old block's counts"
        );

        // Re-rolling the already-gone old block returns its original counts
        // but must not overwrite the last successful ingest counts.
        let old_again = indexer.rollback_block(&old, HEIGHT)?;
        assert_eq!(old_again, old_written);
        assert_eq!(
            indexer.last_counts(),
            replacement_written,
            "last_counts must stay the last ingest counts, not the rollback counts"
        );
        Ok(())
    }

    #[test]
    fn rollback_of_a_never_indexed_block_is_not_an_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();

        // An indexer enabled after the block was applied never wrote its rows.
        indexer.rollback_block(&candidate, HEIGHT)?;
        assert!(stored_rows(&indexer)?.is_empty());
        Ok(())
    }

    #[test]
    fn repeated_rollback_is_not_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();
        indexer.ingest_block(&serialize(&candidate), HEIGHT)?;

        indexer.rollback_block(&candidate, HEIGHT)?;
        let after_first = stored_rows(&indexer)?;
        indexer.rollback_block(&candidate, HEIGHT)?;
        assert_eq!(
            stored_rows(&indexer)?,
            after_first,
            "a second rollback must be observationally inert"
        );
        Ok(())
    }

    /// Regression: rollback writes deletions straight to the store, so rows
    /// still buffered in `pending_rows` used to survive it and a later
    /// `end_batch` resurrected the disconnected block.
    #[test]
    fn rollback_inside_an_open_batch_is_not_undone_by_end_batch()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();

        indexer.begin_batch();
        indexer.ingest_block(&serialize(&candidate), HEIGHT)?;
        indexer.rollback_block(&candidate, HEIGHT)?;
        indexer.end_batch()?;

        assert!(
            stored_rows(&indexer)?.is_empty(),
            "end_batch must not write back rows for a rolled-back block"
        );
        Ok(())
    }

    /// Delegates every operation to a real store but fails `write`, so the
    /// all-or-nothing claim on `rollback_block` can be exercised rather than
    /// merely asserted in a doc comment.
    struct FailingWriteStore(RocksDbStore);

    impl bitcoin_rs_storage::KvStore for FailingWriteStore {
        type WriteBatch = <RocksDbStore as KvStore>::WriteBatch;

        fn get(
            &self,
            cf: ColumnFamily,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.0.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError> {
            self.0.iter_prefix(cf, prefix)
        }

        fn new_batch(&self) -> Self::WriteBatch {
            self.0.new_batch()
        }

        fn write(&self, _batch: Self::WriteBatch) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn flush(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.0.flush()
        }

        fn snapshot(
            &self,
        ) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot + '_>, bitcoin_rs_storage::StorageError>
        {
            self.0.snapshot()
        }
    }

    #[test]
    fn rollback_deletes_nothing_when_the_write_fails() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let candidate = rollback_fixture_block();

        // Populate through a normal indexer, then reopen behind the failing
        // store so the rows exist but no write can land.
        {
            let store = Arc::new(RocksDbStore::open(dir.path())?);
            let mut indexer = Indexer::new(store);
            indexer.ingest_block(&serialize(&candidate), HEIGHT)?;
        }
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let before = stored_rows(&Indexer::new(Arc::clone(&store)))?;
        assert!(!before.is_empty(), "fixture must have rows to preserve");
        drop(store);

        let failing = Arc::new(FailingWriteStore(RocksDbStore::open(dir.path())?));
        let mut indexer = Indexer::new(Arc::clone(&failing));
        let outcome = indexer.rollback_block(&candidate, HEIGHT);
        assert!(outcome.is_err(), "a failing write must surface as an error");
        drop(indexer);
        drop(failing);

        let reopened = Indexer::new(Arc::new(RocksDbStore::open(dir.path())?));
        assert_eq!(
            stored_rows(&reopened)?,
            before,
            "a failed rollback must leave every row in place"
        );
        Ok(())
    }

    /// An indexer that persists nothing and does not override the rollback
    /// default. It must refuse rather than report a successful no-op, or the
    /// node would advance its tip believing a stale index is consistent.
    struct RollbackUnawareIndexer;

    impl super::IndexerLike for RollbackUnawareIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<super::IndexRowCounts, super::IndexError> {
            Ok(super::IndexRowCounts::default())
        }

        fn resolve_transaction(
            &self,
            _txid: Txid,
            _source: &dyn BlockSource,
        ) -> Result<Option<Transaction>, super::IndexError> {
            Ok(None)
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, super::IndexError> {
            Ok(None)
        }
    }

    #[test]
    fn the_rollback_default_refuses_rather_than_silently_succeeding() {
        let mut indexer = RollbackUnawareIndexer;
        let candidate = rollback_fixture_block();
        assert!(matches!(
            super::IndexerLike::rollback_block(&mut indexer, &candidate, HEIGHT),
            Err(super::IndexError::UnsupportedRollback)
        ));
    }

    /// A repeated rollback must not delete a replacement block's rows.
    ///
    /// Funding, spending, and txid keys are an 8-byte prefix plus the height
    /// and carry no block identity, so a replacement at the same height that
    /// shares an output script derives the same keys. Without the header-row
    /// identity check, rolling the old block back twice deleted the
    /// replacement's history.
    #[test]
    fn a_repeated_rollback_leaves_a_replacement_blocks_rows_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let shared_script = ScriptBuf::from_bytes(vec![0x51]);

        // Two different blocks at the same height that both pay the same
        // script, so their funding rows collide.
        // The shared `block` fixture pins a zero merkle root, so the nonce is
        // what distinguishes these two headers.
        let mut old_block = block(vec![tx(
            OutPoint::new(Txid::from_byte_array([0xa1; 32]), 0),
            shared_script.clone(),
        )]);
        old_block.header.nonce = 1;
        let mut replacement = block(vec![tx(
            OutPoint::new(Txid::from_byte_array([0xb2; 32]), 0),
            shared_script,
        )]);
        replacement.header.nonce = 2;
        assert_ne!(
            old_block.header.block_hash(),
            replacement.header.block_hash(),
            "the two blocks must differ, or there is nothing to confuse"
        );

        indexer.ingest_block(&serialize(&old_block), HEIGHT)?;
        indexer.rollback_block(&old_block, HEIGHT)?;
        indexer.ingest_block(&serialize(&replacement), HEIGHT)?;
        indexer.flush()?;
        let after_replacement = stored_rows(&indexer)?;
        assert!(
            !after_replacement.is_empty(),
            "the replacement must have written rows"
        );

        // Roll the OLD block back again. It is already gone; its keys now
        // belong to the replacement.
        indexer.rollback_block(&old_block, HEIGHT)?;
        indexer.flush()?;

        assert_eq!(
            stored_rows(&indexer)?,
            after_replacement,
            "a repeated rollback must not touch the replacement's rows"
        );
        Ok(())
    }

    fn indexer() -> Result<(tempfile::TempDir, Indexer<RocksDbStore>), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, Indexer::new(store)))
    }

    fn stored_rows(
        indexer: &Indexer<RocksDbStore>,
    ) -> Result<StoredRows, Box<dyn std::error::Error>> {
        let mut rows = Vec::new();
        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
        ] {
            for row in indexer.store().iter_prefix(cf, &[])? {
                let (key, _value) = row?;
                rows.push((cf, key));
            }
        }
        rows.sort_by(|left, right| {
            (left.0.as_str(), left.1.as_slice()).cmp(&(right.0.as_str(), right.1.as_slice()))
        });
        Ok(rows)
    }

    fn block(txdata: Vec<Transaction>) -> Block {
        Block {
            header: block::Header {
                version: block::Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: 0,
                bits: CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    fn tx(previous_output: OutPoint, script_pubkey: ScriptBuf) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000),
                script_pubkey,
            }],
        }
    }

    fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([label; 32]),
            vout,
        }
    }
}
