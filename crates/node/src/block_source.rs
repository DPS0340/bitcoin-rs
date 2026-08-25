//! Adapter that bridges in-memory block records into the index crate's
//! `BlockSource` trait, enabling resolvers like `Indexer::resolve_script_history`
//! to recover full transactions from lossy prefix rows.
//!
//! The adapter uses height-ordered block records, matching the active-chain
//! append order maintained by block application.

use alloc::sync::Arc;

use bitcoin::Block;
use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::Hash as _;
use bitcoin::hex::FromHex as _;
use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_index::BlockSource;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockBodySource, BlockLog, record_at_height, record_at_height_hash};
use parking_lot::RwLock;

/// Reads decoded Bitcoin blocks from the shared in-memory log.
///
/// Cheap-clonable; the inner Arc is shared with `NodeState`'s record store.
#[derive(Clone)]
pub struct NodeBlockSource {
    blocks: Arc<RwLock<BlockLog>>,
    block_body_source: Option<Arc<dyn BlockBodySource>>,
    block_tree: Option<Arc<RwLock<BlockTree>>>,
}

impl NodeBlockSource {
    /// Builds a source over the shared block-record vector.
    #[must_use]
    pub const fn new(blocks: Arc<RwLock<BlockLog>>) -> Self {
        Self {
            blocks,
            block_body_source: None,
            block_tree: None,
        }
    }

    /// Returns `self` with a durable body source for metadata-only block records.
    #[must_use]
    pub fn with_block_body_source(mut self, source: Arc<dyn BlockBodySource>) -> Self {
        self.block_body_source = Some(source);
        self
    }

    /// Returns `self` with a shared block tree for authoritative height→hash resolution.
    ///
    /// When attached, the tree's active chain determines which block hash is valid
    /// at each height. The session record vector is used only as a payload cache
    /// for matching `(height, hash)` pairs; otherwise the body is loaded from
    /// [`BlockBodySource`].
    #[must_use]
    pub fn with_block_tree(mut self, tree: Arc<RwLock<BlockTree>>) -> Self {
        self.block_tree = Some(tree);
        self
    }
}

impl core::fmt::Debug for NodeBlockSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeBlockSource").finish_non_exhaustive()
    }
}

impl BlockSource for NodeBlockSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        let active_hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        self.resolve_block_by_hash(height, active_hash)
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        // Only the durable body source can slice. A session record holds its
        // body as a hex string, so serving a range from it would mean decoding
        // the whole thing first — exactly the work the range read exists to
        // avoid. Returning `None` sends the caller to `block_at_height`, which
        // is correct and no slower than it is today.
        let source = self.block_body_source.as_ref()?;
        let hash = if let Some(tree) = &self.block_tree {
            tree.read().active_node_at_height(height)?.hash
        } else {
            let guard = self.blocks.read();
            record_at_height(&guard, height)?.hash
        };
        source.block_body_range(height, hash, offset, len)
    }
}

impl NodeBlockSource {
    fn cached_body_bytes(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        let block_hex = {
            let guard = self.blocks.read();
            let record = record_at_height_hash(&guard, height, hash)?;
            (!record.block_hex.is_empty()).then(|| record.block_hex.clone())
        }?;
        Vec::<u8>::from_hex(&block_hex).ok()
    }

    /// Returns serialized bytes for an exact `(height, hash)` pair from the
    /// authoritative body source, falling back to the in-memory payload cache.
    pub(crate) fn block_body_bytes_for(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
        if let Some(body_source) = self.block_body_source.as_ref()
            && let Some(bytes) = body_source.block_body(height, hash)
        {
            return Some(bytes);
        }
        self.cached_body_bytes(height, hash)
    }

    fn resolve_block_by_hash(&self, height: u32, active_hash: Hash256) -> Option<Block> {
        let bytes = self.block_body_bytes_for(height, active_hash)?;
        let block = deserialize::<Block>(&bytes).ok()?;
        let decoded_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        (decoded_hash == active_hash).then_some(block)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::Network;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin_rs_chain::NodeStatus;
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_rpc::BlockRecord;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    struct FixedBody {
        height: u32,
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for FixedBody {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }
    }

    struct CorrectBody {
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for CorrectBody {
        fn block_body(&self, _height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (hash == self.hash).then(|| self.bytes.clone())
        }
    }

    #[test]
    fn block_at_height_returns_some_after_record_added() {
        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks);
        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    /// Body source that can slice, backed by one in-memory body.
    struct RangedBody {
        height: u32,
        hash: Hash256,
        bytes: Vec<u8>,
    }

    impl BlockBodySource for RangedBody {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            (self.height == height && self.hash == hash).then(|| self.bytes.clone())
        }

        fn block_body_range(
            &self,
            height: u32,
            hash: Hash256,
            offset: u32,
            len: u32,
        ) -> Option<Vec<u8>> {
            if self.height != height || self.hash != hash {
                return None;
            }
            let start = usize::try_from(offset).ok()?;
            let end = start.checked_add(usize::try_from(len).ok()?)?;
            self.bytes.get(start..end).map(<[u8]>::to_vec)
        }
    }

    #[test]
    fn block_bytes_at_height_agrees_with_slicing_the_whole_block() -> TestResult {
        let genesis = genesis_block(Network::Regtest);
        let bytes = serialize(&genesis);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let body_source = Arc::new(RangedBody {
            height: record.height,
            hash: record.hash,
            bytes: bytes.clone(),
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        for offset in 0..u32::try_from(bytes.len())? {
            for len in [0_u32, 1, 7] {
                let end = offset.saturating_add(len);
                let ranged = source.block_bytes_at_height(0, offset, len);
                if usize::try_from(end)? > bytes.len() {
                    assert_eq!(
                        ranged, None,
                        "a range past the end must not be served short"
                    );
                    continue;
                }
                assert_eq!(
                    ranged.as_deref(),
                    Some(&bytes[usize::try_from(offset)?..usize::try_from(end)?]),
                    "range ({offset}, {len}) diverged from the serialized block"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn block_bytes_at_height_declines_without_a_durable_body_source() {
        // A session record holds its body as hex, so slicing it would mean
        // decoding the whole thing first. `None` sends the caller to
        // `block_at_height`, which is what it would have done anyway.
        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block(0, &genesis);
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks);

        assert!(source.block_bytes_at_height(0, 0, 4).is_none());
        assert!(
            source.block_at_height(0).is_some(),
            "declining a range must not mean the block is unavailable"
        );
    }

    #[test]
    fn block_at_height_returns_none_when_missing() {
        let blocks: Arc<RwLock<BlockLog>> = Arc::new(RwLock::new(BlockLog::new()));
        let source = NodeBlockSource::new(blocks);
        assert!(source.block_at_height(0).is_none());
    }

    #[test]
    fn block_at_height_reads_metadata_only_record_from_body_source() {
        struct SingleBlockSource {
            height: u32,
            hash: Hash256,
            bytes: Vec<u8>,
        }

        impl BlockBodySource for SingleBlockSource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                (self.height == height && self.hash == hash).then(|| self.bytes.clone())
            }
        }

        let genesis = genesis_block(Network::Regtest);
        let record = BlockRecord::from_block_metadata(0, &genesis);
        let body_source = Arc::new(SingleBlockSource {
            height: record.height,
            hash: record.hash,
            bytes: serialize(&genesis),
        });
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([record])));
        let source = NodeBlockSource::new(blocks).with_block_body_source(body_source);

        let Some(decoded) = source.block_at_height(0) else {
            panic!("expected block at height 0");
        };
        assert_eq!(decoded.block_hash(), genesis.block_hash());
    }

    #[test]
    fn block_at_height_returns_first_record_for_duplicate_height() {
        let anchor = genesis_block(Network::Regtest);
        let mut first = anchor.clone();
        first.header.nonce = first.header.nonce.saturating_add(1);
        let mut second = first.clone();
        second.header.nonce = second.header.nonce.saturating_add(1);
        let records = vec![
            BlockRecord::from_block(0, &anchor),
            BlockRecord::from_block(2, &first),
            BlockRecord::from_block(2, &second),
        ];
        let source = NodeBlockSource::new(Arc::new(RwLock::new(
            records.into_iter().collect::<BlockLog>(),
        )));

        let Some(decoded) = source.block_at_height(2) else {
            panic!("expected duplicate height record");
        };
        assert_eq!(decoded.block_hash(), first.block_hash());
    }

    #[test]
    fn block_at_height_resolves_from_tree_with_empty_records() -> TestResult {
        let genesis = genesis_block(Network::Regtest);
        let genesis_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        let body_bytes = serialize(&genesis);

        // Seed an active tree with the genesis header.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Empty record vector — simulates post-checkpoint-restore state.
        let blocks: Arc<RwLock<BlockLog>> = Arc::new(RwLock::new(BlockLog::new()));
        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(Arc::new(FixedBody {
                height: 0,
                hash: genesis_hash,
                bytes: body_bytes,
            }))
            .with_block_tree(tree);

        let decoded = source.block_at_height(0).ok_or_else(|| {
            std::io::Error::other("tree-authoritative resolution must succeed with empty records")
        })?;
        assert_eq!(decoded.block_hash(), genesis.block_hash());
        Ok(())
    }

    #[test]
    fn block_at_height_tree_rejects_stale_cache_entry() -> TestResult {
        let genesis = genesis_block(Network::Regtest);
        let mut stale_block = genesis.clone();
        stale_block.header.nonce = stale_block.header.nonce.wrapping_add(1);
        let stale_hash = Hash256::from_le_bytes(stale_block.block_hash().as_byte_array());
        let correct_hash = Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        assert_ne!(stale_hash, correct_hash);

        // Tree says height 0 = correct_hash.
        let mut tree = BlockTree::new();
        tree.insert_header(genesis.header, NodeStatus::HeaderValid)?;
        let tree = Arc::new(RwLock::new(tree));

        // Record vector has a STALE entry at height 0 (different hash).
        let stale_record = BlockRecord::from_block(0, &stale_block);
        let blocks = Arc::new(RwLock::new(BlockLog::from_iter([stale_record])));

        let body_source = Arc::new(CorrectBody {
            hash: correct_hash,
            bytes: serialize(&genesis),
        });

        let source = NodeBlockSource::new(blocks)
            .with_block_body_source(body_source)
            .with_block_tree(tree);

        // Must resolve via body source (stale cache hash doesn’t match tree).
        let decoded = source.block_at_height(0).ok_or_else(|| {
            std::io::Error::other(
                "must fall through to body source when cache hash mismatches tree",
            )
        })?;
        assert_eq!(decoded.block_hash(), genesis.block_hash());
        Ok(())
    }
}
