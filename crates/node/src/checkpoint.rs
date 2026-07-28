use std::io::{Read, Seek, SeekFrom, Write};

use bitcoin::block::Header;
use bitcoin::consensus::{Encodable, encode::deserialize};
use bitcoin_rs_chain::{BlockTree, ChainWork, NodeId, accept_headers};
use bitcoin_rs_primitives::{Hash256, Network};
use sha2::{Digest, Sha256};
use thiserror::Error;

const HEADER_MAGIC: [u8; 8] = *b"BRSHEAD\0";
const HEADER_VERSION: u32 = 1;
const HEADER_PREFIX_LEN: usize = 56;
const HEADER_LEN: usize = 80;
const BEST_CHAIN_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/best\0";
const APPLIED_PREFIX_DOMAIN: &[u8] = b"bitcoin-rs/headers-v1/applied\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointConfig {
    pub(crate) network: Network,
    pub(crate) genesis: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointPoint {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointTip {
    pub(crate) height: u32,
    pub(crate) hash: Hash256,
    pub(crate) chainwork: ChainWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointMetadata {
    pub(crate) header_count: u64,
    pub(crate) best: HeaderCheckpointTip,
    pub(crate) applied: HeaderCheckpointTip,
    pub(crate) best_chain_commitment: [u8; 32],
    pub(crate) applied_prefix_commitment: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HeaderCheckpointWrite {
    pub(crate) metadata: HeaderCheckpointMetadata,
    pub(crate) bytes_written: u64,
}

#[derive(Debug)]
pub(crate) struct RestoredHeaders {
    pub(crate) tree: BlockTree,
    pub(crate) best_tip_id: NodeId,
    pub(crate) applied_tip_id: NodeId,
    pub(crate) metadata: HeaderCheckpointMetadata,
}

#[derive(Debug, Error)]
pub(crate) enum HeaderCheckpointError {
    #[error("configured genesis {configured} does not match {network:?} genesis {expected}")]
    ConfiguredGenesisMismatch {
        configured: Hash256,
        expected: Hash256,
        network: Network,
    },
    #[error("header checkpoint contains zero headers")]
    ZeroHeaderCount,
    #[error("header checkpoint count {count} does not fit usize")]
    CountDoesNotFitUsize { count: u64 },
    #[error("header checkpoint count {count} exceeds the u32 block-height domain")]
    CountExceedsHeightDomain { count: u64 },
    #[error("header checkpoint byte length overflow for {count} headers")]
    SizeOverflow { count: u64 },
    #[error("header checkpoint has {actual} bytes, expected {expected}")]
    InvalidFileLength { actual: u64, expected: u64 },
    #[error("header checkpoint magic is invalid")]
    BadMagic,
    #[error("header checkpoint version {actual} is unsupported")]
    UnsupportedVersion { actual: u32 },
    #[error("header checkpoint network magic does not match configured network")]
    NetworkMismatch,
    #[error("header checkpoint genesis does not match configured genesis")]
    GenesisMismatch,
    #[error("header checkpoint count {actual} does not match manifest count {expected}")]
    CountMismatch { actual: u64, expected: u64 },
    #[error("header checkpoint best tip is not the tree's published best tip")]
    BestTipNotActive,
    #[error("header checkpoint active ancestry is malformed at height {height}")]
    MalformedAncestry { height: u32 },
    #[error("header checkpoint root is not the configured genesis")]
    RootIsNotGenesis,
    #[error("header checkpoint applied tip is not a prefix of the active best chain")]
    AppliedTipNotBestPrefix,
    #[error("header checkpoint metadata does not match reconstructed chain")]
    MetadataMismatch,
    #[error("header checkpoint commitment does not match reconstructed chain")]
    CommitmentMismatch,
    #[error("header checkpoint consensus codec failed: {0}")]
    Codec(String),
    #[error("header checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("header checkpoint consensus validation failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
}

pub(crate) fn write_headers<W: Write>(
    writer: &mut W,
    tree: &BlockTree,
    config: HeaderCheckpointConfig,
    best_tip_id: NodeId,
    applied: HeaderCheckpointPoint,
) -> Result<HeaderCheckpointWrite, HeaderCheckpointError> {
    validate_config(config)?;
    if tree.tip_id() != Some(best_tip_id) {
        return Err(HeaderCheckpointError::BestTipNotActive);
    }

    let mut ancestry = tree.ancestor_chain(best_tip_id)?;
    ancestry.reverse();
    let count = u64::try_from(ancestry.len())
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count: u64::MAX })?;
    let bytes_written = checkpoint_size(count)?;

    let root = tree.node(
        *ancestry
            .first()
            .ok_or(HeaderCheckpointError::ZeroHeaderCount)?,
    )?;
    if root.height != 0 || root.hash != config.genesis {
        return Err(HeaderCheckpointError::RootIsNotGenesis);
    }

    let best = tip_from_node(tree, best_tip_id)?;
    if u64::from(best.height).checked_add(1) != Some(count) {
        return Err(HeaderCheckpointError::MalformedAncestry {
            height: best.height,
        });
    }
    let applied_id = tree
        .lookup(applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_node = tree.node(applied_id)?;
    if applied_node.height != applied.height
        || tree.node_at_height_from(best_tip_id, applied.height) != Some(applied_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let applied = tip_from_node(tree, applied_id)?;

    writer.write_all(&prefix(config, count))?;
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);

    for (index, node_id) in ancestry.into_iter().enumerate() {
        let height = u32::try_from(index).map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain {
            count,
        })?;
        let node = tree.node(node_id)?;
        if node.height != height {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        let encoded = encode_header(&node.header)?;
        writer.write_all(&encoded)?;
        best_hasher.update(encoded);
        if node.height <= applied.height {
            applied_hasher.update(encoded);
        }
    }

    Ok(HeaderCheckpointWrite {
        metadata: HeaderCheckpointMetadata {
            header_count: count,
            best,
            applied: applied,
            best_chain_commitment: best_hasher.finalize().into(),
            applied_prefix_commitment: applied_hasher.finalize().into(),
        },
        bytes_written,
    })
}

pub(crate) fn read_headers<R: Read + Seek>(
    reader: &mut R,
    config: HeaderCheckpointConfig,
    expected: HeaderCheckpointMetadata,
) -> Result<RestoredHeaders, HeaderCheckpointError> {
    validate_config(config)?;
    let expected_size = checkpoint_size(expected.header_count)?;
    reader.seek(SeekFrom::Start(0))?;
    let actual_size = reader.seek(SeekFrom::End(0))?;
    if actual_size != expected_size {
        return Err(HeaderCheckpointError::InvalidFileLength {
            actual: actual_size,
            expected: expected_size,
        });
    }
    reader.seek(SeekFrom::Start(0))?;

    let mut encoded_prefix = [0_u8; HEADER_PREFIX_LEN];
    reader.read_exact(&mut encoded_prefix)?;
    let count = parse_prefix(encoded_prefix, config)?;
    if count != expected.header_count {
        return Err(HeaderCheckpointError::CountMismatch {
            actual: count,
            expected: expected.header_count,
        });
    }

    let mut tree = BlockTree::new();
    let mut best_hasher = Sha256::new();
    best_hasher.update(BEST_CHAIN_DOMAIN);
    let mut applied_hasher = Sha256::new();
    applied_hasher.update(APPLIED_PREFIX_DOMAIN);
    let mut last_id = None;

    for index in 0..usize::try_from(count).map_err(|_| HeaderCheckpointError::CountDoesNotFitUsize {
        count,
    })? {
        let height = u32::try_from(index).map_err(|_| HeaderCheckpointError::CountExceedsHeightDomain {
            count,
        })?;
        let mut encoded = [0_u8; HEADER_LEN];
        reader.read_exact(&mut encoded)?;
        let header: Header = deserialize(&encoded)
            .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
        let ids = accept_headers(&mut tree, core::slice::from_ref(&header), config.network)?;
        let id = ids[0];
        let node = tree.node(id)?;
        if node.height != height || tree.len() != index + 1 {
            return Err(HeaderCheckpointError::MalformedAncestry { height });
        }
        best_hasher.update(encoded);
        if height <= expected.applied.height {
            applied_hasher.update(encoded);
        }
        last_id = Some(id);
    }

    let best_tip_id = last_id.ok_or(HeaderCheckpointError::ZeroHeaderCount)?;
    let best = tip_from_node(&tree, best_tip_id)?;
    if tree.tip_id() != Some(best_tip_id) || best != expected.best {
        return Err(HeaderCheckpointError::MetadataMismatch);
    }
    let applied_tip_id = tree
        .lookup(expected.applied.hash)
        .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
    let applied_tip = tip_from_node(&tree, applied_tip_id)?;
    if applied_tip != expected.applied
        || tree.node_at_height_from(best_tip_id, expected.applied.height) != Some(applied_tip_id)
    {
        return Err(HeaderCheckpointError::AppliedTipNotBestPrefix);
    }
    let best_chain_commitment: [u8; 32] = best_hasher.finalize().into();
    let applied_prefix_commitment: [u8; 32] = applied_hasher.finalize().into();
    if best_chain_commitment != expected.best_chain_commitment
        || applied_prefix_commitment != expected.applied_prefix_commitment
    {
        return Err(HeaderCheckpointError::CommitmentMismatch);
    }

    Ok(RestoredHeaders {
        tree,
        best_tip_id,
        applied_tip_id,
        metadata: expected,
    })
}

fn validate_config(config: HeaderCheckpointConfig) -> Result<(), HeaderCheckpointError> {
    let expected = config.network.genesis_block_hash();
    if config.genesis != expected {
        return Err(HeaderCheckpointError::ConfiguredGenesisMismatch {
            configured: config.genesis,
            expected,
            network: config.network,
        });
    }
    Ok(())
}

fn checkpoint_size(count: u64) -> Result<u64, HeaderCheckpointError> {
    if count == 0 {
        return Err(HeaderCheckpointError::ZeroHeaderCount);
    }
    if usize::try_from(count).is_err() {
        return Err(HeaderCheckpointError::CountDoesNotFitUsize { count });
    }
    if count > u64::from(u32::MAX) + 1 {
        return Err(HeaderCheckpointError::CountExceedsHeightDomain { count });
    }
    let prefix_len = u64::try_from(HEADER_PREFIX_LEN)
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    let header_len = u64::try_from(HEADER_LEN)
        .map_err(|_| HeaderCheckpointError::SizeOverflow { count })?;
    prefix_len
        .checked_add(
            count
                .checked_mul(header_len)
                .ok_or(HeaderCheckpointError::SizeOverflow { count })?,
        )
        .ok_or(HeaderCheckpointError::SizeOverflow { count })
}

fn prefix(config: HeaderCheckpointConfig, count: u64) -> [u8; HEADER_PREFIX_LEN] {
    let mut out = [0_u8; HEADER_PREFIX_LEN];
    out[..8].copy_from_slice(&HEADER_MAGIC);
    out[8..12].copy_from_slice(&HEADER_VERSION.to_le_bytes());
    out[12..16].copy_from_slice(&config.network.magic());
    out[16..48].copy_from_slice(&config.genesis.to_le_bytes());
    out[48..].copy_from_slice(&count.to_le_bytes());
    out
}

fn parse_prefix(
    encoded: [u8; HEADER_PREFIX_LEN],
    config: HeaderCheckpointConfig,
) -> Result<u64, HeaderCheckpointError> {
    if encoded[..8] != HEADER_MAGIC {
        return Err(HeaderCheckpointError::BadMagic);
    }
    let version = u32::from_le_bytes([encoded[8], encoded[9], encoded[10], encoded[11]]);
    if version != HEADER_VERSION {
        return Err(HeaderCheckpointError::UnsupportedVersion { actual: version });
    }
    if encoded[12..16] != config.network.magic() {
        return Err(HeaderCheckpointError::NetworkMismatch);
    }
    if encoded[16..48] != config.genesis.to_le_bytes() {
        return Err(HeaderCheckpointError::GenesisMismatch);
    }
    let count = u64::from_le_bytes([
        encoded[48],
        encoded[49],
        encoded[50],
        encoded[51],
        encoded[52],
        encoded[53],
        encoded[54],
        encoded[55],
    ]);
    checkpoint_size(count)?;
    Ok(count)
}

fn tip_from_node(
    tree: &BlockTree,
    id: NodeId,
) -> Result<HeaderCheckpointTip, HeaderCheckpointError> {
    let node = tree.node(id)?;
    Ok(HeaderCheckpointTip {
        height: node.height,
        hash: node.hash,
        chainwork: node.chainwork,
    })
}

fn encode_header(header: &Header) -> Result<[u8; HEADER_LEN], HeaderCheckpointError> {
    let mut encoded = [0_u8; HEADER_LEN];
    let mut cursor = &mut encoded[..];
    let written = header
        .consensus_encode(&mut cursor)
        .map_err(|error| HeaderCheckpointError::Codec(error.to_string()))?;
    if written != HEADER_LEN || !cursor.is_empty() {
        return Err(HeaderCheckpointError::Codec(
            "Bitcoin header did not encode to 80 bytes".to_owned(),
        ));
    }
    Ok(encoded)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use bitcoin::block::{Header, Version};
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::{BlockTree, NodeId, accept_headers};
    use bitcoin_rs_primitives::{Hash256, Network};

    use super::{
        HEADER_PREFIX_LEN, HeaderCheckpointConfig, HeaderCheckpointError, HeaderCheckpointPoint,
        HeaderCheckpointTip, HeaderCheckpointWrite, encode_header, read_headers, write_headers,
    };

    const NETWORK: Network = Network::Regtest;

    #[test]
    fn round_trip_replays_consensus_validated_active_chain()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(3, 1)?;
        let written = write_checkpoint(&tree, best_tip_id, applied)?;
        let mut reader = Cursor::new(written.0);

        let restored = read_headers(&mut reader, config(), written.1.metadata)?;

        assert_eq!(restored.tree.len(), 4);
        assert_eq!(
            restored.tree.node(restored.best_tip_id)?.hash,
            tree.node(best_tip_id)?.hash,
            "the restored best tip identifies the same chain across distinct trees"
        );
        assert_eq!(restored.metadata, written.1.metadata);
        assert_eq!(
            restored.tree.node(restored.applied_tip_id)?.hash,
            applied.hash,
            "the applied checkpoint tip is reconstructed from the accepted prefix"
        );
        Ok(())
    }

    #[test]
    fn reader_rejects_wrong_network_and_genesis() -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
        let written = write_checkpoint(&tree, best_tip_id, applied)?;

        let wrong_network = HeaderCheckpointConfig {
            network: Network::Testnet3,
            genesis: Network::Testnet3.genesis_block_hash(),
        };
        assert!(
            read_headers(
                &mut Cursor::new(&written.0),
                wrong_network,
                written.1.metadata
            )
            .is_err()
        );
        let configured_genesis_mismatch = HeaderCheckpointConfig {
            network: NETWORK,
            genesis: Hash256::from_le_bytes(&[0x22; 32]),
        };
        assert!(matches!(
            read_headers(
                &mut Cursor::new(&written.0),
                configured_genesis_mismatch,
                written.1.metadata
            ),
            Err(HeaderCheckpointError::ConfiguredGenesisMismatch { .. })
        ));
        let mut wrong_genesis = written.0;
        wrong_genesis[16] ^= 1;
        assert!(
            read_headers(
                &mut Cursor::new(wrong_genesis),
                config(),
                written.1.metadata
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn reader_rejects_bad_prefix_count_and_trailing_bytes() -> Result<(), Box<dyn std::error::Error>>
    {
        let (tree, best_tip_id, applied) = chain_with_applied_height(1, 0)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut bad_magic = bytes.clone();
        bad_magic[0] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_magic), config(), written.metadata).is_err());
        let mut bad_version = bytes.clone();
        bad_version[8] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_version), config(), written.metadata).is_err());
        let mut bad_count = bytes.clone();
        bad_count[48] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_count), config(), written.metadata).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(read_headers(&mut Cursor::new(trailing), config(), written.metadata).is_err());
        Ok(())
    }

    #[test]
    fn reader_rejects_mutated_linkage_and_invalid_pow_or_nbits()
    -> Result<(), Box<dyn std::error::Error>> {
        let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut bad_prev = bytes.clone();
        bad_prev[HEADER_PREFIX_LEN + 80 + 4] ^= 1;
        assert!(read_headers(&mut Cursor::new(bad_prev), config(), written.metadata).is_err());

        let mut bad_pow = bytes.clone();
        let header_offset = HEADER_PREFIX_LEN + 80;
        let mut invalid = header_from_row(&bad_pow[header_offset..header_offset + 80])?;
        while invalid.validate_pow(invalid.target()).is_ok() {
            invalid.nonce = invalid.nonce.checked_add(1).ok_or("nonce exhausted")?;
        }
        bad_pow[header_offset..header_offset + 80].copy_from_slice(&encode_header(&invalid)?);
        assert!(read_headers(&mut Cursor::new(bad_pow), config(), written.metadata).is_err());

        let mut bad_nbits = bytes;
        let previous = header_from_row(&bad_nbits[header_offset..header_offset + 80])?;
        let mut nbits_mismatch = Header {
            bits: CompactTarget::from_consensus(0x207f_fffe),
            ..previous
        };
        mine_header_to_declared_target(&mut nbits_mismatch)?;
        bad_nbits[header_offset..header_offset + 80]
            .copy_from_slice(&encode_header(&nbits_mismatch)?);
        assert!(read_headers(&mut Cursor::new(bad_nbits), config(), written.metadata).is_err());
        Ok(())
    }

    #[test]
    fn reader_rejects_metadata_and_commitment_mutations() -> Result<(), Box<dyn std::error::Error>>
    {
        let (tree, best_tip_id, applied) = chain_with_applied_height(2, 1)?;
        let (bytes, written) = write_checkpoint(&tree, best_tip_id, applied)?;

        let mut wrong_best = written.metadata;
        wrong_best.best.hash = Hash256::from_le_bytes(&[0x11; 32]);
        assert!(read_headers(&mut Cursor::new(&bytes), config(), wrong_best).is_err());

        let mut wrong_applied = written.metadata;
        wrong_applied.applied = HeaderCheckpointTip {
            hash: written.metadata.best.hash,
            ..written.metadata.applied
        };
        assert!(read_headers(&mut Cursor::new(&bytes), config(), wrong_applied).is_err());

        let mut wrong_applied_prefix_commitment = written.metadata;
        wrong_applied_prefix_commitment.applied_prefix_commitment[0] ^= 1;
        assert!(read_headers(
            &mut Cursor::new(bytes.clone()),
            config(),
            wrong_applied_prefix_commitment
        )
        .is_err());

        let mut wrong_commitment = written.metadata;
        wrong_commitment.best_chain_commitment[0] ^= 1;
        assert!(read_headers(&mut Cursor::new(bytes), config(), wrong_commitment).is_err());
        Ok(())
    }

    #[test]
    fn writer_refuses_a_best_tip_that_is_not_active() -> Result<(), Box<dyn std::error::Error>> {
        let (tree, _, applied) = chain_with_applied_height(3, 1)?;

        assert!(matches!(
            write_headers(&mut Vec::new(), &tree, config(), NodeId::new(0), applied),
            Err(HeaderCheckpointError::BestTipNotActive)
        ));
        Ok(())
    }

    #[test]
    fn writer_refuses_an_applied_tip_off_the_active_best_ancestry()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut tree, best_tip_id, _) = chain_with_applied_height(3, 1)?;
        let genesis_hash = tree.node(NodeId::new(0))?.hash;
        let mut fork = next_header(
            BlockHash::from_byte_array(genesis_hash.to_le_bytes()),
            u32::from(NETWORK.genesis_block_hash().to_le_bytes()[0]) + 1,
        );
        mine_header_to_declared_target(&mut fork)?;
        let fork_id = accept_headers(&mut tree, core::slice::from_ref(&fork), NETWORK)?[0];
        let fork = tree.node(fork_id)?;
        let applied = HeaderCheckpointPoint {
            height: fork.height,
            hash: fork.hash,
        };

        assert!(matches!(
            write_headers(&mut Vec::new(), &tree, config(), best_tip_id, applied),
            Err(HeaderCheckpointError::AppliedTipNotBestPrefix)
        ));
        Ok(())
    }

    fn config() -> HeaderCheckpointConfig {
        HeaderCheckpointConfig {
            network: NETWORK,
            genesis: NETWORK.genesis_block_hash(),
        }
    }

    fn write_checkpoint(
        tree: &BlockTree,
        best_tip_id: NodeId,
        applied: HeaderCheckpointPoint,
    ) -> Result<(Vec<u8>, HeaderCheckpointWrite), HeaderCheckpointError> {
        let mut bytes = Vec::new();
        let written = write_headers(&mut bytes, tree, config(), best_tip_id, applied)?;
        assert_eq!(u64::try_from(bytes.len()).ok(), Some(written.bytes_written));
        Ok((bytes, written))
    }

    fn chain_with_applied_height(
        best_height: u32,
        applied_height: u32,
    ) -> Result<(BlockTree, NodeId, HeaderCheckpointPoint), HeaderCheckpointError> {
        let genesis =
            bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
        let mut tree = BlockTree::new();
        let mut current = accept_headers(&mut tree, core::slice::from_ref(&genesis), NETWORK)?[0];
        for height in 1..=best_height {
            let prev = BlockHash::from_byte_array(tree.node(current)?.hash.to_le_bytes());
            let mut header = next_header(prev, height);
            mine_header_to_declared_target(&mut header)?;
            current = accept_headers(&mut tree, core::slice::from_ref(&header), NETWORK)?[0];
        }
        let applied_id = tree
            .node_at_height_from(current, applied_height)
            .ok_or(HeaderCheckpointError::AppliedTipNotBestPrefix)?;
        let applied = tree.node(applied_id)?;
        let height = applied.height;
        let hash = applied.hash;
        Ok((tree, current, HeaderCheckpointPoint { height, hash }))
    }

    fn next_header(prev_blockhash: BlockHash, height: u32) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash,
            merkle_root: TxMerkleNode::all_zeros(),
            time: 1_296_688_602_u32.saturating_add(height),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        }
    }

    fn mine_header_to_declared_target(header: &mut Header) -> Result<(), HeaderCheckpointError> {
        while header.validate_pow(header.target()).is_err() {
            header.nonce = header
                .nonce
                .checked_add(1)
                .ok_or_else(|| HeaderCheckpointError::Codec("exhausted test nonce".to_owned()))?;
        }
        Ok(())
    }

    fn header_from_row(row: &[u8]) -> Result<Header, HeaderCheckpointError> {
        deserialize(row).map_err(|error| HeaderCheckpointError::Codec(error.to_string()))
    }
}
