//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_channel::{SendError, Sender};

static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// Process-unique identity for one peer connection.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConnectionId(u64);

impl ConnectionId {
    fn allocate() -> Self {
        match NEXT_CONNECTION_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        {
            Ok(id) => Self(id),
            Err(_) => std::process::abort(),
        }
    }
}

/// Attribution token for an event delivered by one connection.
///
/// This value intentionally contains no outbound sender, so queued inbound
/// events cannot keep a retired connection's writer alive.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PeerSource {
    /// Remote socket address at delivery time.
    pub addr: SocketAddr,
    connection_id: ConnectionId,
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<crate::Message>,
    cancel: Arc<AtomicBool>,
}

impl PeerLease {
    /// Creates a lease with a fresh process-unique identity.
    #[must_use]
    pub fn new(outbound: Sender<crate::Message>) -> Self {
        Self {
            id: ConnectionId::allocate(),
            outbound,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Stamps an inbound event with this connection's identity and address.
    #[must_use]
    pub fn source(&self, addr: SocketAddr) -> PeerSource {
        PeerSource {
            addr,
            connection_id: self.id,
        }
    }

    /// Queues a message for this connection's writer.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, message: crate::Message) -> Result<(), SendError<crate::Message>> {
        self.outbound.send(message)
    }

    /// Returns whether `source` was stamped by this lease.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.id == source.connection_id
    }

    /// Returns whether both handles refer to the same connection.
    #[must_use]
    pub fn same_connection(&self, other: &Self) -> bool {
        self.id == other.id
    }

    /// Requests prompt teardown of this connection.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }

    /// Returns whether teardown has been requested.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }
}

#[cfg(test)]
mod tests {
    use super::PeerLease;

    #[test]
    fn lease_ids_are_unique_and_clones_keep_identity() {
        let (first_tx, _first_rx) = crossbeam_channel::unbounded();
        let (second_tx, _second_rx) = crossbeam_channel::unbounded();
        let first = PeerLease::new(first_tx);
        let first_clone = first.clone();
        let second = PeerLease::new(second_tx);

        assert!(first.same_connection(&first_clone));
        assert!(!first.same_connection(&second));
    }

    #[test]
    fn cancellation_is_shared_by_clones() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        let lease = PeerLease::new(tx);
        let clone = lease.clone();

        lease.cancel();

        assert!(clone.is_cancelled());
    }
}
