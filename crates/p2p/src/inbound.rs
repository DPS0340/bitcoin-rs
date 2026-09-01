//! Inbound payloads received from peers.

use bitcoin_rs_primitives::{Block, Header, Tx, consensus_bytes};

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

/// A decoded `tx` message from one peer connection.
///
/// Carries the exact [`ConnectionId`](crate::ConnectionId) stamped at
/// decode time so the node consumer can attribute the admission to the
/// originating connection — never a socket address, node id, or later
/// connection at the same address.
pub struct InboundTx {
    /// Decoded transaction.
    pub tx: Tx,
    /// Delivering connection identity.
    pub source: crate::PeerSource,
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

impl InboundTx {
    /// Wraps a decoded transaction with its delivering connection identity.
    #[must_use]
    pub fn new(tx: Tx, source: crate::PeerSource) -> Self {
        Self { tx, source }
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

    #[test]
    fn inbound_tx_carries_exact_connection_id() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let bytes = bitcoin::consensus::encode::serialize(&genesis);
        let block = bitcoin_rs_primitives::Block::consensus_decode(&bytes)
            .map_err(|_| panic!("genesis block must decode natively"))
            .unwrap();
        let tx = block.txs[0].clone();

        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 18_333);
        let lease = crate::PeerLease::new(
            crossbeam_channel::unbounded::<crate::Message>().0,
        );
        let source = lease.source(addr);
        let inbound = super::InboundTx::new(tx, source);
        assert_eq!(inbound.source.addr, addr);
        // The ConnectionId is the one stamped at lease creation, not a
        // re-wrapped address or a later connection.
        assert!(lease.is_current(inbound.source));
    }
}
