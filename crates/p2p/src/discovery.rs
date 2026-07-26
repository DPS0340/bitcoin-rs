//! Bounded data passed from peer connections to address management.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use bitcoin::p2p::{
    ServiceFlags,
    address::{AddrV2, AddrV2Message, Address},
};

/// A routable peer endpoint announced by another node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveredPeer {
    /// Announced endpoint.
    pub addr: SocketAddr,
    /// Services advertised for the endpoint.
    pub services: ServiceFlags,
    /// Announcement time as Unix seconds.
    pub seen_at: u32,
}

/// A compact terminal classification for an outbound connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerTerminalOutcome {
    /// The connection closed without an error.
    Clean,
    /// Network I/O failed.
    Io,
    /// The remote peer violated the wire protocol.
    Protocol,
    /// Policy rejected the remote endpoint.
    Policy,
    /// Node shutdown ended the connection.
    Shutdown,
    /// The failure did not fit a stable class.
    Other,
}

/// A bounded event emitted by an outbound peer connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerDiscoveryEvent {
    /// A remote peer announced a usable endpoint.
    Announced(DiscoveredPeer),
    /// An outbound handshake completed.
    HandshakeReady {
        /// Connected endpoint.
        addr: SocketAddr,
        /// Services advertised by the connected peer.
        services: ServiceFlags,
    },
    /// An outbound connection attempt ended.
    Terminal {
        /// Attempted endpoint.
        addr: SocketAddr,
        /// Whether the version handshake completed before termination.
        handshake_completed: bool,
        /// Time spent connected after handshake completion.
        connected_for: Option<Duration>,
        /// Stable terminal classification.
        outcome: PeerTerminalOutcome,
    },
}

/// Converts one legacy `addr` entry into a usable peer candidate.
#[must_use]
pub fn candidate_from_addr(time: u32, address: &Address) -> Option<DiscoveredPeer> {
    let addr = address.socket_addr().ok()?;
    candidate(time, address.services, addr)
}

/// Converts one BIP155 `addrv2` entry into a usable peer candidate.
#[must_use]
pub fn candidate_from_addr_v2(message: &AddrV2Message) -> Option<DiscoveredPeer> {
    if !matches!(message.addr, AddrV2::Ipv4(_) | AddrV2::Ipv6(_)) {
        return None;
    }
    let addr = message.socket_addr().ok()?;
    candidate(message.time, message.services, addr)
}

fn candidate(time: u32, services: ServiceFlags, addr: SocketAddr) -> Option<DiscoveredPeer> {
    if time == 0 || addr.port() == 0 || !has_block_service(services) || !is_routable(addr.ip()) {
        return None;
    }
    Some(DiscoveredPeer {
        addr,
        services,
        seen_at: time,
    })
}

fn has_block_service(services: ServiceFlags) -> bool {
    services.has(ServiceFlags::NETWORK) || services.has(ServiceFlags::WITNESS)
}

/// Returns whether an IP address is suitable for public peer discovery.
///
/// Mirrors Bitcoin Core `CNetAddr::IsRoutable`, with conservative exclusions
/// from the IANA IPv4/IPv6 special-purpose registries.
#[must_use]
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            a != 0
                && !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && !ip.is_broadcast()
                && !ip.is_documentation()
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 192 && b == 0 && c == 0)
                && !(a == 192 && b == 88 && c == 99)
                && !(a == 198 && (b == 18 || b == 19))
                && a < 240
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            !ip.is_unspecified()
                && ip.to_ipv4().is_none()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_unique_local()
                && !ip.is_unicast_link_local()
                && segments[0] & 0xffc0 != 0xfec0
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && !(segments[0] == 0x2001 && segments[1] == 0x0002)
                && !(segments[0] == 0x2001 && matches!(segments[1] & 0xfff0, 0x0010 | 0x0020))
                && !(segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                && !(segments[0] == 0x3fff && segments[1] & 0xf000 == 0)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use bitcoin::p2p::{
        ServiceFlags,
        address::{AddrV2, AddrV2Message, Address},
    };

    use super::{candidate_from_addr, candidate_from_addr_v2, is_routable};

    #[test]
    fn accepts_routable_legacy_ipv4_with_block_service() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 8333));
        let message = Address::new(&addr, ServiceFlags::NETWORK);

        let candidate = candidate_from_addr(1, &message);

        assert_eq!(candidate.map(|peer| peer.addr), Some(addr));
    }

    #[test]
    fn accepts_routable_addrv2_ipv6_with_witness_service() {
        let ip = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let addr = SocketAddr::V6(SocketAddrV6::new(ip, 8333, 0, 0));
        let message = AddrV2Message {
            time: 1,
            services: ServiceFlags::WITNESS,
            addr: AddrV2::Ipv6(ip),
            port: 8333,
        };

        let candidate = candidate_from_addr_v2(&message);

        assert_eq!(candidate.map(|peer| peer.addr), Some(addr));
    }

    #[test]
    fn accepts_each_supported_address_encoding() {
        let ipv6 = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
        let legacy_addr = SocketAddr::V6(SocketAddrV6::new(ipv6, 8333, 0, 0));
        let legacy = Address::new(&legacy_addr, ServiceFlags::WITNESS);
        assert_eq!(
            candidate_from_addr(1, &legacy).map(|peer| peer.addr),
            Some(legacy_addr)
        );

        let ipv4 = Ipv4Addr::new(8, 8, 4, 4);
        let addrv2_addr = SocketAddr::V4(SocketAddrV4::new(ipv4, 8333));
        let addrv2 = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(ipv4),
            port: 8333,
        };
        assert_eq!(
            candidate_from_addr_v2(&addrv2).map(|peer| peer.addr),
            Some(addrv2_addr)
        );
    }

    #[test]
    fn rejects_unusable_legacy_entries() {
        let cases = [
            (
                0,
                Address::new(
                    &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 8333)),
                    ServiceFlags::NETWORK,
                ),
            ),
            (
                1,
                Address::new(
                    &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8333)),
                    ServiceFlags::NETWORK,
                ),
            ),
            (
                1,
                Address::new(
                    &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 0)),
                    ServiceFlags::NETWORK,
                ),
            ),
            (
                1,
                Address::new(
                    &SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 8333)),
                    ServiceFlags::NONE,
                ),
            ),
        ];

        for (time, address) in cases {
            assert!(candidate_from_addr(time, &address).is_none());
        }
    }

    #[test]
    fn rejects_addrv2_zero_timestamp_and_port() {
        let mut message = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 8333,
        };
        assert!(candidate_from_addr_v2(&message).is_none());

        message.time = 1;
        message.port = 0;
        assert!(candidate_from_addr_v2(&message).is_none());
    }

    #[test]
    fn rejects_unsupported_addrv2_networks() {
        let unsupported = [
            AddrV2::TorV2([0; 10]),
            AddrV2::TorV3([0; 32]),
            AddrV2::I2p([0; 32]),
            AddrV2::Cjdns(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            AddrV2::Unknown(99, vec![1, 2, 3]),
        ];

        for addr in unsupported {
            let message = AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK,
                addr,
                port: 8333,
            };
            assert!(candidate_from_addr_v2(&message).is_none());
        }
    }

    #[test]
    fn rejects_unroutable_addrv2_addresses_and_missing_service() {
        let cases = [
            AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
                port: 8333,
            },
            AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv6(Ipv6Addr::LOCALHOST),
                port: 8333,
            },
            AddrV2Message {
                time: 1,
                services: ServiceFlags::NONE,
                addr: AddrV2::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 8333,
            },
            AddrV2Message {
                time: 1,
                services: ServiceFlags::NETWORK_LIMITED,
                addr: AddrV2::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
                port: 8333,
            },
        ];

        for message in cases {
            assert!(candidate_from_addr_v2(&message).is_none());
        }
    }

    #[test]
    fn rejects_every_explicit_special_purpose_range() {
        let ipv4 = [
            Ipv4Addr::new(0, 1, 2, 3),
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::new(169, 254, 1, 1),
            Ipv4Addr::new(224, 0, 0, 1),
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(192, 0, 2, 1),
            Ipv4Addr::new(100, 64, 0, 1),
            Ipv4Addr::new(192, 0, 0, 1),
            Ipv4Addr::new(192, 88, 99, 1),
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(240, 0, 0, 1),
        ];
        for ip in ipv4 {
            assert!(!is_routable(IpAddr::V4(ip)), "{ip} must be rejected");
        }

        let ipv6 = [
            Ipv6Addr::UNSPECIFIED,
            Ipv6Addr::LOCALHOST,
            Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0020, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 1),
            Ipv4Addr::LOCALHOST.to_ipv6_compatible(),
        ];
        for ip in ipv6 {
            assert!(!is_routable(IpAddr::V6(ip)), "{ip} must be rejected");
        }
    }

    #[test]
    fn accepts_addresses_immediately_outside_excluded_ranges() {
        let ipv4 = [
            Ipv4Addr::new(100, 63, 255, 255),
            Ipv4Addr::new(100, 128, 0, 1),
            Ipv4Addr::new(192, 0, 1, 1),
            Ipv4Addr::new(192, 88, 98, 1),
            Ipv4Addr::new(198, 17, 255, 255),
            Ipv4Addr::new(198, 20, 0, 1),
            Ipv4Addr::new(223, 255, 255, 255),
        ];
        for ip in ipv4 {
            assert!(is_routable(IpAddr::V4(ip)), "{ip} must be accepted");
        }

        let ipv6 = [
            Ipv6Addr::new(0x2001, 0x0003, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0030, 0, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2001, 0x0004, 0x0112, 0, 0, 0, 0, 1),
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1),
        ];
        for ip in ipv6 {
            assert!(is_routable(IpAddr::V6(ip)), "{ip} must be accepted");
        }
    }
}
