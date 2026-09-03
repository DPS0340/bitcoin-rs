//! Native block type and block-level hashing helpers.

use crate::{
    BlockHash, Header, Tx, Txid,
    encode::{DecodeError, deserialize},
};

/// A Bitcoin block in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// Transactions in consensus order; the first entry is the coinbase.
    pub txs: Vec<Tx>,
}

impl Block {
    /// Computes the block hash from the block header.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.compute_hash()
    }

    /// Computes all transaction ids in block order.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.txs.iter().map(Tx::txid).collect()
    }

    /// Decodes exactly one block (80-byte header, transaction count, transactions),
    /// rejecting any trailing bytes.
    pub fn consensus_decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        deserialize(bytes)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::Block;
    use crate::encode::DecodeError;

    use crate::{BlockHash, Hash256};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    #[test]
    fn genesis_block_hash_matches_known_value() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block = Block::consensus_decode(&bytes)?;

        assert_eq!(
            block.block_hash(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse::<BlockHash>()?
        );
        Ok(())
    }

    #[test]
    fn block_reencode_and_hash_match_bitcoin_crate_for_fixture() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/363731.bin")?;
        let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;
        let block = Block::consensus_decode(&bytes)?;

        assert_eq!(crate::encode::consensus_bytes(&block), bytes);
        assert_eq!(
            block.block_hash(),
            BlockHash(Hash256::from_le_bytes(oracle.block_hash().as_byte_array()))
        );
        Ok(())
    }

    #[test]
    fn block_decode_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = std::fs::read("tests/testdata/0.bin")?;
        assert!(Block::consensus_decode(&bytes).is_ok());
        bytes.push(0xFF);

        assert_eq!(
            Block::consensus_decode(&bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
        Ok(())
    }
}
