//! Native block header type and header hash computation.

use sha2::{Digest, Sha256};

use crate::{
    BlockHash, Hash256,
    encode::{ConsensusEncode, DecodeError, Sha256Writer, deserialize, finalize_double_sha256},
};

/// A Bitcoin block header in native owned form.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    /// Block version.
    pub version: i32,
    /// Hash of the previous block.
    pub prev_blockhash: BlockHash,
    /// Merkle root of the block's transaction ids.
    pub merkle_root: Hash256,
    /// Unix epoch seconds.
    pub time: u32,
    /// Compact proof-of-work target.
    pub bits: u32,
    /// Proof-of-work nonce.
    pub nonce: u32,
}

impl Header {
    /// Computes the block hash: double-SHA256 of the 80-byte consensus serialization.
    #[must_use]
    pub fn compute_hash(&self) -> BlockHash {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        ConsensusEncode::consensus_encode(self, &mut writer)
            .unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));
        BlockHash(finalize_double_sha256(engine))
    }

    /// Decodes exactly one 80-byte header, rejecting any trailing bytes.
    pub fn consensus_decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::Header;
    use crate::{BlockHash, Hash256, encode::DecodeError};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    #[test]
    fn header_hash_matches_bitcoin_crate() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
        let header = Header::consensus_decode(&bytes[..80])?;

        let expected = BlockHash(Hash256::from_le_bytes(
            block.header.block_hash().as_byte_array(),
        ));
        let oracle_header = &block.header;

        assert_eq!(header.version, oracle_header.version.to_consensus());
        assert_eq!(header.time, oracle_header.time);
        assert_eq!(header.nonce, oracle_header.nonce);
        assert_eq!(header.bits, oracle_header.bits.to_consensus());
        assert_eq!(header.compute_hash(), expected);
        assert_eq!(crate::encode::consensus_bytes(&header), &bytes[..80]);
        Ok(())
    }

    #[test]
    fn header_decode_rejects_trailing_bytes() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        assert!(Header::consensus_decode(&bytes[..80]).is_ok());

        let mut trailing = bytes[..80].to_vec();
        trailing.push(0xFF);
        assert_eq!(
            Header::consensus_decode(&trailing),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
        Ok(())
    }
}
