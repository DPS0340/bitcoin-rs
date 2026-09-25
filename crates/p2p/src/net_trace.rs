//! Bitcoin Core `net:*` tracepoint mapping for P2P message traffic.
//!
//! Core fires `net:inbound_message` when a message is read off a peer and
//! `net:outbound_message` when one is written to a peer, carrying the peer
//! id, address, connection type, message type, size, and message bytes. This
//! module owns that payload mapping so the read, write, and handshake
//! funnels stay free of ABI knowledge. Every call passes a lazy closure: the
//! payload is only encoded and formatted while a consumer is attached.

use std::net::SocketAddr;

use crate::wire::Message;

/// Core connection type of an accepted connection (`ConnectionTypeAsString`
/// for `ConnectionType::INBOUND`).
pub(crate) const INBOUND: &str = "inbound";

/// Core connection type of a dialed connection. bitcoin-rs has no
/// block-relay-only, addr-fetch, feeler, or manual classes yet, so every
/// outbound connection reports `outbound-full-relay`.
pub(crate) const OUTBOUND_FULL_RELAY: &str = "outbound-full-relay";

/// Identity of one peer connection, carried to the probe sites.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TracePeer {
    /// Core `nodeid`: the process-unique connection id.
    pub(crate) node_id: u64,
    /// Peer address and port, Core's `m_addr_name`.
    pub(crate) addr: SocketAddr,
    /// Whether the listener accepted this connection.
    pub(crate) inbound: bool,
}

impl TracePeer {
    /// Stamps a connection identity from its lease and address.
    pub(crate) const fn new(node_id: u64, addr: SocketAddr, inbound: bool) -> Self {
        Self {
            node_id,
            addr,
            inbound,
        }
    }

    /// Core connection-type string for this connection.
    pub(crate) const fn conn_type(self) -> &'static str {
        if self.inbound {
            INBOUND
        } else {
            OUTBOUND_FULL_RELAY
        }
    }

    fn header(self) -> (i64, String, String) {
        (
            i64::try_from(self.node_id).unwrap_or(i64::MAX),
            self.addr.to_string(),
            self.conn_type().to_owned(),
        )
    }
}

/// Fires `net:inbound_message` for one decoded inbound message.
///
/// `payload` is the checksum-validated wire payload bytes as read, which is
/// what Core passes as its message-bytes argument. `prepare` runs only while
/// a consumer is attached, so the copy into the probe slot costs nothing
/// when nobody is watching.
///
/// Lifetime: the closure only *borrows* `message`/`payload` — both belong to
/// the caller and outlive this call — and returns the strings and the
/// [`bitcoin_rs_trace::PayloadSlot`] **by value** in the argument tuple. The
/// generated probe macro binds that tuple in the same block as its `asm!`,
/// so every pointer the probe passes is backed by memory that is still alive
/// when the probe fires. Nothing addressable is created only inside the
/// closure body.
pub(crate) fn inbound_message(peer: TracePeer, message: &Message, payload: &[u8]) {
    bitcoin_rs_trace::inbound_message(move || {
        let (node_id, addr, conn_type) = peer.header();
        (
            node_id,
            addr,
            conn_type,
            message.command().to_string(),
            bitcoin_rs_trace::PayloadSlot::new(payload.to_vec()),
        )
    });
}

/// Fires `net:outbound_message` for one message written to a peer.
///
/// The message is encoded once, inside `prepare`, and only while a consumer
/// is attached — the write path never encodes twice for tracing.
pub(crate) fn outbound_message(peer: TracePeer, message: &Message) {
    bitcoin_rs_trace::outbound_message(move || {
        let (node_id, addr, conn_type) = peer.header();
        (
            node_id,
            addr,
            conn_type,
            message.command().to_string(),
            bitcoin_rs_trace::PayloadSlot::new(
                crate::wire::encode_payload(message).unwrap_or_default(),
            ),
        )
    });
}
