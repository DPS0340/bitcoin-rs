use std::io::{Read, Write};
use std::net::{SocketAddr, ToSocketAddrs};

use crate::wire::{Message, PeerError, write_message};
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_network::VersionMessage;

/// Peer connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// No version negotiation has started.
    Disconnected,
    /// Version negotiation is in progress.
    VersionExchange,
    /// Version was exchanged and verack is outstanding.
    Verack,
    /// Peer may exchange ordinary P2P messages.
    Ready,
    /// Peer is being disconnected.
    Disconnecting,
}

/// One peer connection and its handshake state.
#[derive(Debug)]
pub struct Peer<S> {
    /// Underlying byte stream.
    pub stream: S,
    /// Current protocol state.
    pub state: PeerState,
    /// Expected network magic.
    pub magic: Magic,
    /// Last remote version message.
    pub remote_version: Option<VersionMessage>,
    /// Whether a remote verack has been received.
    pub received_verack: bool,
}

impl<S> Peer<S> {
    /// Create a peer for the supplied wire stream.
    pub fn new(stream: S, magic: Magic) -> Self {
        Self {
            stream,
            state: PeerState::Disconnected,
            magic,
            remote_version: None,
            received_verack: false,
        }
    }

    /// Mark the peer ready once both version and verack have arrived.
    pub const fn refresh_ready_state(&mut self) {
        if self.remote_version.is_some() && self.received_verack {
            self.state = PeerState::Ready;
        }
    }
}

impl<S: Read + Write> Peer<S> {
    /// Write one outbound message to the wire stream.
    pub fn send(&mut self, message: &Message) -> Result<(), PeerError> {
        write_message(&mut self.stream, self.magic, message).map(|_| ())
    }
}

/// DNS resolver injection point for peer discovery.
pub trait DnsResolver: Send + Sync {
    /// Resolve a DNS seed name into socket addresses.
    fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError>;
}

/// DNS resolver backed by the operating system resolver.
#[derive(Debug, Clone, Copy)]
pub struct SystemDnsResolver {
    port: u16,
}

impl SystemDnsResolver {
    /// Create a DNS resolver that attaches `port` to each resolved seed host.
    #[must_use]
    pub const fn new(port: u16) -> Self {
        Self { port }
    }
}

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, seed: &str) -> Result<Vec<SocketAddr>, PeerError> {
        let seed = seed.trim_end_matches('.');
        (seed, self.port)
            .to_socket_addrs()
            .map(std::iter::Iterator::collect)
            .map_err(PeerError::Io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_dns_resolver_uses_configured_port_for_literal_hosts() -> Result<(), PeerError> {
        let resolver = SystemDnsResolver::new(8333);

        assert!(
            resolver
                .resolve("127.0.0.1.")?
                .contains(&SocketAddr::from(([127, 0, 0, 1], 8333)))
        );
        Ok(())
    }
}
