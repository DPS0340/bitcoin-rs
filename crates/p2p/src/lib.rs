#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

/// Per-connection identity and cancellation.
pub mod connection;
/// Inbound message dispatcher.
pub mod dispatch;
/// Core-faithful block-download window policy.
#[allow(missing_docs)]
pub mod download;
/// Peer finite-state machine.
pub mod fsm;
/// Version/verack negotiation helpers.
pub mod handshake;
/// Inbound block payloads with preserved wire bytes.
pub mod inbound;
/// Inventory relay helpers.
pub mod inv;
/// TCP listener skeleton with graceful shutdown.
pub mod listener;
/// Peer connection state and handshake data.
pub mod peer;
/// Peer metadata published after a successful handshake.
pub mod peer_info;
/// Runtime owner for P2P control state and workers.
pub mod service;
/// Manual IP subnet banning primitives.
pub mod subnet;
/// Bitcoin P2P wire codec.
pub mod wire;
pub use connection::{ConnectionId, PeerLease, PeerLifecycle, PeerSource, ReadyPeer};
pub use dispatch::{ChainQuery, InventoryResponse};
pub use download::{
    DownloadWindow, PeerRequest, SyncBudget, SyncPeer, SyncPeerSelection, select_download_peers,
    statically_fanout_eligible,
};
pub use inbound::{InboundBlock, InboundHeaders};
pub use peer::{DnsResolver, Peer, PeerState, SystemDnsResolver};
pub use peer_info::PeerInfo;
pub use service::{P2pControlError, P2pService, P2pServiceConfig, P2pServiceError};
pub use subnet::{BannedSubnet, IpSubnet, SubnetParseError};
pub use wire::{Message, PeerError};
