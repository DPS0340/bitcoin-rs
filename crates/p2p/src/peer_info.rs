//! Public peer metadata published after a successful handshake.

use std::net::SocketAddr;

use bitcoin::p2p::message_network::VersionMessage;

/// Information collected during a successful Bitcoin v1 handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerInfo {
    /// Remote socket address.
    pub addr: SocketAddr,
    /// Protocol version advertised by the remote.
    pub version: u32,
    /// Service flags advertised by the remote (`ServiceFlags::to_u64`).
    pub services: u64,
    /// User-agent string advertised by the remote.
    pub user_agent: String,
    /// Best-chain height the remote reports.
    pub start_height: i32,
    /// Unix-epoch seconds of handshake completion.
    pub conn_time: u64,
    /// Whether this connection was inbound (`true` for listener-accepted peers).
    pub inbound: bool,
}

impl PeerInfo {
    /// Constructs a `PeerInfo` for an inbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn inbound_from_version(
        addr: SocketAddr,
        version: &VersionMessage,
        conn_time: u64,
    ) -> Self {
        Self {
            addr,
            version: version.version,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            conn_time,
            inbound: true,
        }
    }

    /// Constructs a `PeerInfo` for an outbound peer from the captured remote `VersionMessage`.
    #[must_use]
    pub fn outbound_from_version(
        addr: SocketAddr,
        version: &VersionMessage,
        conn_time: u64,
    ) -> Self {
        Self {
            addr,
            version: version.version,
            services: version.services.to_u64(),
            user_agent: version.user_agent.clone(),
            start_height: version.start_height,
            conn_time,
            inbound: false,
        }
    }

    /// Returns Bitcoin Core service-flag names decoded from `self.services`.
    ///
    /// Order follows Bitcoin Core's bit assignment. Unrecognized bits are dropped.
    #[must_use]
    pub fn services_names(&self) -> Vec<&'static str> {
        let mut names: Vec<&'static str> = Vec::new();

        if self.services & 1_u64 != 0 {
            names.push("NETWORK");
        }
        if self.services & (1_u64 << 1) != 0 {
            names.push("GETUTXO");
        }
        if self.services & (1_u64 << 2) != 0 {
            names.push("BLOOM");
        }
        if self.services & (1_u64 << 3) != 0 {
            names.push("WITNESS");
        }
        if self.services & (1_u64 << 6) != 0 {
            names.push("COMPACT_FILTERS");
        }
        if self.services & (1_u64 << 10) != 0 {
            names.push("NETWORK_LIMITED");
        }
        if self.services & (1_u64 << 11) != 0 {
            names.push("P2P_V2");
        }

        names
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer_info_with_services(services: u64) -> PeerInfo {
        PeerInfo {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333),
            version: 70_016,
            services,
            user_agent: String::new(),
            start_height: 0,
            conn_time: 0,
            inbound: false,
        }
    }

    /// `services_names` is Bitcoin Core-compatible `getpeerinfo` output: the
    /// recognized service bits decode to Core's canonical names in bit order,
    /// and unrecognized bits are dropped. This pins the external RPC contract,
    /// not the helper's internal representation.
    #[test]
    fn services_names_match_bitcoin_core_service_flag_names() {
        let all_known = (1_u64 << 0)  // NETWORK
            | (1_u64 << 1)            // GETUTXO
            | (1_u64 << 2)            // BLOOM
            | (1_u64 << 3)            // WITNESS
            | (1_u64 << 6)            // COMPACT_FILTERS
            | (1_u64 << 10)           // NETWORK_LIMITED
            | (1_u64 << 11); // P2P_V2

        assert_eq!(
            peer_info_with_services(all_known).services_names(),
            vec![
                "NETWORK",
                "GETUTXO",
                "BLOOM",
                "WITNESS",
                "COMPACT_FILTERS",
                "NETWORK_LIMITED",
                "P2P_V2",
            ]
        );

        // No recognized bits -> no names (Core reports an empty array).
        assert!(peer_info_with_services(0).services_names().is_empty());

        // Unrecognized bits (e.g. bit 63) contribute no names.
        assert!(
            peer_info_with_services(1_u64 << 63)
                .services_names()
                .is_empty()
        );
    }
}
