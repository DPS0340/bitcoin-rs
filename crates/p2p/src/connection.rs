//! Per-connection identity and cancellation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crossbeam_channel::{SendError, Sender};
use parking_lot::RwLock;

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

    /// Returns the process-unique numeric id backing this identity.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
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

/// A ready peer snapshot that keeps the connection identity beside its
/// handshake metadata.
///
/// The source must be carried through selection to the eventual send or
/// disconnect; resolving its address again can target a same-address
/// replacement.
#[derive(Clone, Debug)]
pub struct ReadyPeer {
    /// Identity of the connection that supplied `info`.
    pub source: PeerSource,
    /// Handshake metadata published by that connection.
    pub info: crate::PeerInfo,
}

/// Sole mutation boundary for live peer leases and ready-peer metadata.
///
/// Connection threads register, publish, replace, and remove peers through
/// this handle. Higher layers may observe snapshots and request an
/// identity-checked disconnect, but never mutate the shared maps directly.
#[derive(Clone, Debug)]
pub struct PeerLifecycle {
    registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    leases: Arc<RwLock<hashbrown::HashMap<SocketAddr, PeerLease>>>,
}

impl PeerLifecycle {
    /// Wraps the shared stores used by the listener and its observers.
    #[must_use]
    pub const fn new(
        registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
        leases: Arc<RwLock<hashbrown::HashMap<SocketAddr, PeerLease>>>,
    ) -> Self {
        Self { registry, leases }
    }

    /// Registers a connection before its handshake, cancelling a genuinely
    /// different predecessor and hiding its ready metadata.
    pub fn register(&self, addr: SocketAddr, lease: &PeerLease) -> bool {
        let mut leases = self.leases.write();
        let prior = leases.insert(addr, lease.clone());
        if prior
            .as_ref()
            .is_some_and(|prior| prior.same_connection(lease))
        {
            return false;
        }
        let replaced = prior.is_some();
        if let Some(prior) = prior {
            prior.cancel();
        }
        self.registry.write().retain(|peer| peer.addr != addr);
        replaced
    }

    /// Publishes handshake metadata only while `lease` remains current.
    pub fn publish_ready(
        &self,
        addr: SocketAddr,
        lease: &PeerLease,
        info: crate::PeerInfo,
    ) -> bool {
        let leases = self.leases.read();
        if !leases
            .get(&addr)
            .is_some_and(|current| current.same_connection(lease))
        {
            return false;
        }
        let mut registry = self.registry.write();
        registry.retain(|peer| peer.addr != addr);
        registry.push(info);
        true
    }

    /// Removes `lease` only if it is still the current connection.
    pub fn remove_current(&self, addr: SocketAddr, lease: &PeerLease) -> bool {
        self.disconnect_if(addr, |current| current.same_connection(lease))
    }

    /// Disconnects the connection that produced `source`, preserving any
    /// newer same-address replacement.
    pub fn disconnect_source(&self, source: PeerSource) -> bool {
        self.disconnect_if(source.addr, |current| current.is_current(source))
    }

    /// Disconnects every matching current lease while holding the lease
    /// mutation lock. A replacement can therefore never be selected by a
    /// predicate for the predecessor it replaced.
    pub fn disconnect_matching(
        &self,
        predicate: impl Fn(&SocketAddr, &PeerLease) -> bool,
    ) -> Vec<SocketAddr> {
        let mut leases = self.leases.write();
        let targets: Vec<SocketAddr> = leases
            .iter()
            .filter(|(addr, lease)| predicate(addr, lease))
            .map(|(addr, _)| *addr)
            .collect();
        if targets.is_empty() {
            return Vec::new();
        }
        let mut registry = self.registry.write();
        targets
            .into_iter()
            .filter_map(|addr| {
                let removed = leases.remove(&addr)?;
                removed.cancel();
                registry.retain(|peer| peer.addr != addr);
                Some(addr)
            })
            .collect()
    }

    /// Cancels all current connection leases without removing them. The
    /// connection owners observe cancellation and perform their own identity-
    /// checked teardown.
    pub fn cancel_all(&self) {
        for lease in self.leases.read().values() {
            lease.cancel();
        }
    }

    fn disconnect_if(&self, addr: SocketAddr, predicate: impl FnOnce(&PeerLease) -> bool) -> bool {
        let mut leases = self.leases.write();
        if !leases.get(&addr).is_some_and(predicate) {
            return false;
        }
        if let Some(removed) = leases.remove(&addr) {
            removed.cancel();
        }
        self.registry.write().retain(|peer| peer.addr != addr);
        true
    }

    /// Returns the current connection source only when `addr` is published as
    /// ready. Registration hides predecessor metadata before replacing it, so
    /// a handshaking replacement cannot inherit an old scheduler decision.
    #[must_use]
    pub fn ready_source(&self, addr: SocketAddr) -> Option<PeerSource> {
        let leases = self.leases.read();
        let lease = leases.get(&addr)?;
        if !self.registry.read().iter().any(|peer| peer.addr == addr) {
            return None;
        }
        Some(lease.source(addr))
    }

    /// Returns whether `source` still identifies the current connection.
    #[must_use]
    pub fn is_current(&self, source: PeerSource) -> bool {
        self.leases
            .read()
            .get(&source.addr)
            .is_some_and(|lease| lease.is_current(source))
    }

    /// Runs `operation` while the source remains current. Registration of a
    /// same-address replacement is excluded for the whole operation, making
    /// identity validation and an address-scoped scheduler mutation one
    /// transition.
    pub fn with_current(&self, source: PeerSource, operation: impl FnOnce()) -> bool {
        let leases = self.leases.read();
        if !leases
            .get(&source.addr)
            .is_some_and(|lease| lease.is_current(source))
        {
            return false;
        }
        operation();
        true
    }

    /// Clones the lease only when it is still the connection identified by
    /// `source`.
    #[must_use]
    pub(crate) fn lease_source(&self, source: PeerSource) -> Option<PeerLease> {
        self.leases
            .read()
            .get(&source.addr)
            .filter(|lease| lease.is_current(source))
            .cloned()
    }

    /// Selects and disconnects a ready address while excluding same-address
    /// replacement registration from the selection through the removal.
    pub(crate) fn disconnect_selected_ready(
        &self,
        select: impl FnOnce() -> Option<SocketAddr>,
    ) -> Option<(SocketAddr, PeerSource)> {
        let mut leases = self.leases.write();
        let addr = select()?;
        let lease = leases.get(&addr)?;
        if !self.registry.read().iter().any(|peer| peer.addr == addr) {
            return None;
        }
        let source = lease.source(addr);
        let removed = leases.remove(&addr)?;
        removed.cancel();
        self.registry.write().retain(|peer| peer.addr != addr);
        Some((addr, source))
    }

    /// Sends a message only while `source` remains the current connection.
    ///
    /// The source check and lease lookup share one read-side critical section,
    /// so callers never send through a same-address replacement selected after
    /// an earlier address lookup.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, source: PeerSource, message: crate::Message) -> Result<(), crate::Message> {
        let Some(lease) = self
            .leases
            .read()
            .get(&source.addr)
            .filter(|lease| lease.is_current(source))
            .cloned()
        else {
            return Err(message);
        };
        lease.send(message).map_err(|error| error.0)
    }

    /// Snapshots ready-peer metadata.
    #[must_use]
    pub fn ready_peers(&self) -> Vec<ReadyPeer> {
        let leases = self.leases.read();
        self.registry
            .read()
            .iter()
            .filter_map(|info| {
                let lease = leases.get(&info.addr)?;
                Some(ReadyPeer {
                    source: lease.source(info.addr),
                    info: info.clone(),
                })
            })
            .collect()
    }

    /// Snapshots all live leases with their connection identities.
    #[must_use]
    pub fn live_leases(&self) -> Vec<(PeerSource, PeerLease)> {
        self.leases
            .read()
            .iter()
            .map(|(addr, lease)| (lease.source(*addr), lease.clone()))
            .collect()
    }

    /// Returns whether any live connection currently occupies `addr`.
    #[must_use]
    pub fn contains(&self, addr: SocketAddr) -> bool {
        self.leases.read().contains_key(&addr)
    }

    /// Snapshots every live connection address, including handshaking peers.
    #[must_use]
    pub fn live_addresses(&self) -> Vec<SocketAddr> {
        self.leases.read().keys().copied().collect()
    }
}

/// Cloneable handle for one live peer connection.
#[derive(Clone, Debug)]
pub struct PeerLease {
    id: ConnectionId,
    outbound: Sender<crate::Message>,
    cancel: Arc<AtomicBool>,
    inbound: bool,
}

impl PeerLease {
    /// Creates an outbound-direction lease with a fresh process-unique identity.
    #[must_use]
    pub fn new(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(outbound, false)
    }

    /// Creates an inbound-direction lease with a fresh process-unique identity.
    #[must_use]
    pub fn new_inbound(outbound: Sender<crate::Message>) -> Self {
        Self::with_direction(outbound, true)
    }

    fn with_direction(outbound: Sender<crate::Message>, inbound: bool) -> Self {
        Self {
            id: ConnectionId::allocate(),
            outbound,
            cancel: Arc::new(AtomicBool::new(false)),
            inbound,
        }
    }

    /// Stable process-unique node id for this connection (Core `nodeid`).
    #[must_use]
    pub const fn node_id(&self) -> u64 {
        self.id.get()
    }

    /// Whether this connection was accepted by the listener.
    #[must_use]
    pub const fn is_inbound(&self) -> bool {
        self.inbound
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
    use std::net::SocketAddr;
    use std::sync::Arc;

    use parking_lot::RwLock;

    use super::{PeerLease, PeerLifecycle};

    type PeerRegistry = Arc<RwLock<Vec<crate::PeerInfo>>>;
    type PeerLeases = Arc<RwLock<hashbrown::HashMap<SocketAddr, PeerLease>>>;

    fn peer_info(addr: SocketAddr, conn_time: u64) -> crate::PeerInfo {
        crate::PeerInfo {
            addr,
            version: 70_016,
            services: 0,
            user_agent: String::from("/test/"),
            start_height: 0,
            conn_time,
            inbound: false,
        }
    }

    fn lifecycle() -> (PeerLifecycle, PeerRegistry, PeerLeases) {
        let registry = Arc::new(RwLock::new(Vec::new()));
        let leases = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        (
            PeerLifecycle::new(Arc::clone(&registry), Arc::clone(&leases)),
            registry,
            leases,
        )
    }

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

    #[test]
    fn node_ids_are_stable_and_distinct() {
        let (first_tx, _first_rx) = crossbeam_channel::unbounded();
        let (second_tx, _second_rx) = crossbeam_channel::unbounded();
        let first = PeerLease::new(first_tx);
        let clone = first.clone();
        let second = PeerLease::new(second_tx);

        assert_eq!(first.node_id(), clone.node_id());
        assert_ne!(first.node_id(), second.node_id());
    }

    #[test]
    fn direction_distinguishes_inbound_from_outbound_leases() {
        let (tx, _rx) = crossbeam_channel::unbounded();
        assert!(!PeerLease::new(tx.clone()).is_inbound());
        assert!(PeerLease::new_inbound(tx).is_inbound());
    }

    #[test]
    fn stale_connection_cannot_publish_over_replacement() {
        let (lifecycle, registry, leases) = lifecycle();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_450));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        assert!(!lifecycle.register(addr, &old));
        assert!(lifecycle.publish_ready(addr, &old, peer_info(addr, 1)));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        assert!(lifecycle.register(addr, &replacement));
        assert!(old.is_cancelled());
        assert!(registry.read().is_empty());
        assert_eq!(lifecycle.ready_source(addr), None);
        assert!(!lifecycle.publish_ready(addr, &old, peer_info(addr, 2)));
        assert!(registry.read().is_empty());

        assert!(lifecycle.publish_ready(addr, &replacement, peer_info(addr, 3)));
        assert_eq!(&*registry.read(), &[peer_info(addr, 3)]);
        assert_eq!(lifecycle.ready_source(addr), Some(replacement.source(addr)));
        assert!(
            leases
                .read()
                .get(&addr)
                .is_some_and(|current| current.same_connection(&replacement))
        );
    }

    #[test]
    fn stale_disconnect_source_preserves_replacement() {
        let (lifecycle, registry, leases) = lifecycle();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_451));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        lifecycle.register(addr, &old);
        let stale_source = old.source(addr);

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        lifecycle.register(addr, &replacement);
        lifecycle.publish_ready(addr, &replacement, peer_info(addr, 2));

        assert!(!lifecycle.disconnect_source(stale_source));
        assert!(!replacement.is_cancelled());
        assert!(leases.read().contains_key(&addr));
        assert_eq!(&*registry.read(), &[peer_info(addr, 2)]);

        assert!(lifecycle.disconnect_source(replacement.source(addr)));
        assert!(replacement.is_cancelled());
        assert!(leases.read().is_empty());
        assert!(registry.read().is_empty());
    }

    #[test]
    fn ready_snapshot_keeps_identity_across_same_address_replacement() {
        let (lifecycle, _registry, _leases) = lifecycle();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_452));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        lifecycle.register(addr, &old);
        assert!(lifecycle.publish_ready(addr, &old, peer_info(addr, 1)));
        let snapshot = lifecycle
            .ready_peers()
            .pop()
            .unwrap_or_else(|| panic!("ready peer snapshot missing"));

        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        lifecycle.register(addr, &replacement);

        assert!(lifecycle.lease_source(snapshot.source).is_none());
        assert!(lifecycle.lease_source(replacement.source(addr)).is_some());
    }

    #[test]
    fn current_guard_rejects_stale_scheduler_mutation() {
        let (lifecycle, _registry, _leases) = lifecycle();
        let addr = SocketAddr::from(([127, 0, 0, 1], 18_453));
        let (old_tx, _old_rx) = crossbeam_channel::unbounded();
        let old = PeerLease::new(old_tx);
        lifecycle.register(addr, &old);
        let stale = old.source(addr);
        let (replacement_tx, _replacement_rx) = crossbeam_channel::unbounded();
        let replacement = PeerLease::new(replacement_tx);
        lifecycle.register(addr, &replacement);

        let mut called = false;
        assert!(!lifecycle.with_current(stale, || called = true));
        assert!(!called);
    }
}
