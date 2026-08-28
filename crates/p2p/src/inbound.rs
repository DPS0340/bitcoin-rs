//! Inbound payloads received from peers.

use bitcoin_rs_primitives::{Block, Header, consensus_bytes};

/// A block received from a peer with its wire payload preserved.
///
/// `serialized` is the exact P2P message payload and matches the canonical
/// consensus serialization of `block`.
pub struct InboundBlock {
    /// Decoded block.
    pub block: Block,
    /// Wire-format block payload bytes.
    pub serialized: bytes::Bytes,
    /// Delivering connection, or `None` for local injection.
    pub source: Option<crate::PeerSource>,
}

/// A `headers` message batch and the peer that delivered it.
pub struct InboundHeaders {
    /// Decoded headers, in wire order.
    pub headers: Vec<Header>,
    /// Delivering connection, or `None` for local injection.
    pub source: Option<crate::PeerSource>,
}

impl InboundBlock {
    /// Wraps a decoded block with freshly computed canonical serialization.
    ///
    /// Used by tests and local injection paths that do not preserve wire payloads.
    #[must_use]
    pub fn from_decoded(block: Block) -> Self {
        let serialized = bytes::Bytes::from(consensus_bytes(&block));
        Self {
            block,
            serialized,
            source: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn from_decoded_is_source_less() {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&genesis);
        let block = bitcoin_rs_primitives::Block::consensus_decode(&bytes)
            .map_err(|_| panic!("genesis block must decode natively"))
            .unwrap();

        assert!(super::InboundBlock::from_decoded(block).source.is_none());
    }
}
