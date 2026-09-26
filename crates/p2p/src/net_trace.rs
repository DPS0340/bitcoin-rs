//! Emission sites for the `net:` USDT probes.
//!
//! The wrappers here translate p2p-internal types into the probe-crate
//! argument tuples, so `listener.rs`/`handshake.rs` carry no probe-format
//! knowledge. Message bytes travel as the already-encoded wire payload —
//! inbound, the checksum-validated bytes `read_message` yields; outbound,
//! the `FramedMessage` payload the vectored write emits. Only the probe
//! crate knows the `*const u8` plumbing; both call sites keep their own
//! borrow, which outlives the synchronous probe call.

use std::net::SocketAddr;

use crate::wire::Message;

/// Peer identity for the `net:` probes.
///
/// `node_id` is the process-unique connection id (`PeerLease::node_id()`),
/// which is the same `i64` Core passes as its `id` argument.
#[derive(Clone, Copy)]
pub(crate) struct TracePeer {
    node_id: u64,
    addr: SocketAddr,
    inbound: bool,
}

impl TracePeer {
    /// Records the peer identity for one connection.
    pub(crate) const fn new(node_id: u64, addr: SocketAddr, inbound: bool) -> Self {
        Self {
            node_id,
            addr,
            inbound,
        }
    }

    /// Core's `ConnectionTypeAsString` values; bitcoin-rs does not yet have
    /// the block-relay-only/addr-fetch/feeler/manual connection classes, so
    /// every outbound connection reports `outbound-full-relay` and every
    /// inbound connection reports `inbound`.
    fn conn_type(&self) -> &'static str {
        if self.inbound {
            "inbound"
        } else {
            "outbound-full-relay"
        }
    }

    /// Formats Core's first three arguments: `id`, `addr:port`, conn type.
    /// These are the cheap fields, prepared only when a consumer is attached.
    fn header(&self) -> (i64, String, String) {
        (
            i64::try_from(self.node_id).unwrap_or(i64::MAX),
            self.addr.to_string(),
            self.conn_type().to_string(),
        )
    }
}

/// Materialises the full `net:*_message` argument tuple for one message:
/// `(node_id, addr:port, conn_type, msg_type, size, payload)`.
fn message_args(
    peer: TracePeer,
    message: &Message,
    payload: &[u8],
) -> bitcoin_rs_trace::MessageArgs {
    let (node_id, addr, conn_type) = peer.header();
    (
        node_id,
        addr,
        conn_type,
        message.command().to_string(),
        u64::try_from(payload.len()).unwrap_or(u64::MAX),
        payload.as_ptr(),
    )
}

/// Fires `net:inbound_message` for a decoded wire message.
///
/// `payload` is the checksum-validated bytes `read_message` yielded — the
/// same buffer the caller holds, which outlives the probe call. Core passes
/// the bytes it received; bitcoin-rs likewise passes the wire bytes as read.
pub(crate) fn inbound_message(peer: TracePeer, message: &Message, payload: &[u8]) {
    bitcoin_rs_trace::inbound_message(move || message_args(peer, message, payload));
}

/// Fires `net:outbound_message` for a wire message handed to the socket.
///
/// `payload` is the `FramedMessage`'s encoded bytes — the same bytes the
/// vectored write emits, so the payload is encoded once per message the way
/// Core reuses `CSerializedNetMsg` for the send path and the probe.
pub(crate) fn outbound_message(peer: TracePeer, message: &Message, payload: &[u8]) {
    bitcoin_rs_trace::outbound_message(move || message_args(peer, message, payload));
}
