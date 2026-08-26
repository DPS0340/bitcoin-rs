use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use core::str::FromStr;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::{BannedSubnet, IpSubnet};
use bitcoin_rs_primitives::USER_AGENT;
use corepc_types::v31::{
    AddedNode, Banned, ConnectionType, GetAddedNodeInfo, GetConnectionCount, GetNetTotals,
    GetNetworkInfo, GetNetworkInfoNetwork, GetPeerInfo, ListBanned, PeerInfo, SetNetworkActive,
    TransportProtocolType, UploadTarget,
};
use crossbeam_channel::TrySendError;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};
// `json!` remains imported for the `#[cfg(test)]` modules below, which reach it
// through `use super::*` and cannot be edited alongside this migration.
#[cfg_attr(not(test), allow(unused_imports))]
use sonic_rs::json;

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{
    corepc_to_sonic, ensure_no_params, optional_bool, params_array, required_str,
};

// Local service flags this node advertises:
// - NODE_NETWORK (1 << 0) = 1 — full block serving.
// - NODE_WITNESS (1 << 3) = 8 — segwit data.
// Sum = 9 = 0x09.
const LOCAL_SERVICES_FLAGS: u64 = (1_u64 << 0) | (1_u64 << 3);
const LOCAL_SERVICES_HEX: &str = "0000000000000009";

const _: () = assert!(LOCAL_SERVICES_FLAGS == 0x09);
/// Decodes a Bitcoin service-flags bitmask into a list of name strings.
///
/// Order follows Bitcoin Core's bit assignment. Unrecognized bits are dropped.
fn services_names_from_flags(flags: u64) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if flags & (1_u64 << 0) != 0 {
        names.push("NETWORK".to_owned());
    }
    if flags & (1_u64 << 1) != 0 {
        names.push("GETUTXO".to_owned());
    }
    if flags & (1_u64 << 2) != 0 {
        names.push("BLOOM".to_owned());
    }
    if flags & (1_u64 << 3) != 0 {
        names.push("WITNESS".to_owned());
    }
    if flags & (1_u64 << 10) != 0 {
        names.push("NETWORK_LIMITED".to_owned());
    }
    if flags & (1_u64 << 11) != 0 {
        names.push("P2P_V2".to_owned());
    }
    names
}

const DEFAULT_RELAY_FEE_BTC_PER_KVB: f64 = 0.00001;
const DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB: f64 = 0.00001;
const DEFAULT_BAN_TIME_SECS: u64 = 24 * 60 * 60;

fn parse_setban_target(raw: &str) -> Result<IpSubnet, RpcError> {
    if let Ok(subnet) = IpSubnet::from_str(raw) {
        return Ok(subnet);
    }

    if let Ok(socket) = SocketAddr::from_str(raw) {
        return Ok(IpSubnet::from_ip(socket.ip()));
    }

    if let Ok(ip) = IpAddr::from_str(raw) {
        return Ok(IpSubnet::from_ip(ip));
    }

    Err(RpcError::InvalidParams(
        "subnet must be IP, IP/prefix, or host:port",
    ))
}

fn epoch_seconds(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map_or(0, |duration| duration.as_secs())
}

fn ban_until(now: SystemTime, bantime: u64, absolute: bool) -> Option<SystemTime> {
    if absolute {
        return UNIX_EPOCH.checked_add(Duration::from_secs(bantime));
    }

    let duration = if bantime == 0 {
        Duration::from_secs(DEFAULT_BAN_TIME_SECS)
    } else {
        Duration::from_secs(bantime)
    };
    now.checked_add(duration)
}

fn optional_u64(params: &Value, index: usize, default: u64) -> Result<u64, RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(default);
    };
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_u64()
        .ok_or(RpcError::InvalidType("parameter must be unsigned integer"))
}

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peers.read();
    let total = peers.len();
    let inbound = peers.iter().filter(|p| p.inbound).count();
    let outbound = total.saturating_sub(inbound);
    corepc_to_sonic(&GetNetworkInfo {
        version: 10000,
        subversion: USER_AGENT.to_owned(),
        protocol_version: 70016,
        local_services: LOCAL_SERVICES_HEX.to_owned(),
        local_services_names: services_names_from_flags(LOCAL_SERVICES_FLAGS),
        local_relay: true,
        time_offset: 0,
        connections: total,
        connections_in: inbound,
        connections_out: outbound,
        network_active: true,
        networks: vec![
            network_info_network("ipv4", false, true),
            network_info_network("ipv6", false, true),
            network_info_network("onion", true, false),
        ],
        relay_fee: DEFAULT_RELAY_FEE_BTC_PER_KVB,
        incremental_fee: DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        local_addresses: Vec::new(),
        warnings: Vec::new(),
    })
}

/// Builds one `networks` entry for `getnetworkinfo`. No proxy is configured,
/// so the proxy fields carry their empty Core defaults.
fn network_info_network(name: &str, limited: bool, reachable: bool) -> GetNetworkInfoNetwork {
    GetNetworkInfoNetwork {
        name: name.to_owned(),
        limited,
        reachable,
        proxy: String::new(),
        proxy_randomize_credentials: false,
    }
}

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peers.read();
    let entries: Vec<PeerInfo> = peers
        .iter()
        .enumerate()
        .map(|(id, peer)| PeerInfo {
            id: u32::try_from(id).unwrap_or(u32::MAX),
            address: peer.addr.to_string(),
            address_bind: Some(peer.addr.to_string()),
            address_local: None,
            network: peer_network_name(&peer.addr),
            mapped_as: None,
            services: format!("{:016x}", peer.services),
            services_names: peer
                .services_names()
                .into_iter()
                .map(str::to_owned)
                .collect(),
            relay_transactions: true,
            last_send: 0,
            last_received: 0,
            last_transaction: 0,
            last_block: 0,
            bytes_sent: 0,
            bytes_received: 0,
            connection_time: i64::try_from(peer.conn_time).unwrap_or(i64::MAX),
            time_offset: 0,
            ping_time: Some(0.0),
            minimum_ping: Some(0.0),
            ping_wait: None,
            version: peer.version,
            subversion: peer.user_agent.clone(),
            inbound: peer.inbound,
            bip152_hb_to: false,
            bip152_hb_from: false,
            starting_height: Some(i64::from(peer.start_height)),
            presynced_headers: Some(-1),
            synced_headers: Some(-1),
            synced_blocks: Some(-1),
            inflight: Some(Vec::new()),
            addresses_relay_enabled: None,
            addresses_processed: Some(0),
            addresses_rate_limited: Some(0),
            permissions: Vec::new(),
            minimum_fee_filter: 0.0,
            bytes_sent_per_message: BTreeMap::new(),
            bytes_received_per_message: BTreeMap::new(),
            inv_to_send: 0,
            last_inv_sequence: 0,
            connection_type: Some(if peer.inbound {
                ConnectionType::Inbound
            } else {
                ConnectionType::OutboundFullRelay
            }),
            transport_protocol_type: TransportProtocolType::V1,
            session_id: String::new(),
        })
        .collect();
    corepc_to_sonic(&GetPeerInfo(entries))
}

/// Classifies a peer socket address into Core's `network` vocabulary. Only IP
/// sockets reach the peer registry, so Tor/I2P/CJDNS families cannot appear.
fn peer_network_name(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(_) => "ipv4".to_owned(),
        IpAddr::V6(_) => "ipv6".to_owned(),
    }
}

pub(crate) fn getaddednodeinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let _ = params_array(params)?;
    let added = ctx.added_nodes.read();
    let entries: Vec<AddedNode> = added
        .iter()
        .map(|addr| AddedNode {
            added_node: addr.to_string(),
            connected: false,
            addresses: Vec::new(),
        })
        .collect();
    corepc_to_sonic(&GetAddedNodeInfo(entries))
}

pub(crate) fn listbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let banned = ctx.banned.read();
    let now = epoch_seconds(SystemTime::now());
    let entries: Vec<Banned> = banned
        .iter()
        .map(|entry| {
            let created = epoch_seconds(entry.ban_created);
            let until = entry.banned_until.map_or(0, epoch_seconds);
            Banned {
                address: entry.subnet.to_string(),
                ban_created: epoch_u32(created),
                banned_until: epoch_u32(until),
                ban_duration: epoch_u32(until.saturating_sub(created)),
                time_remaining: epoch_u32(until.saturating_sub(now)),
            }
        })
        .collect();
    corepc_to_sonic(&ListBanned(entries))
}

/// Narrows an epoch-seconds count into Core's u32 ban timestamps, clamping at
/// the u32 boundary rather than panicking on far-future clocks.
fn epoch_u32(seconds: u64) -> u32 {
    u32::try_from(seconds).unwrap_or(u32::MAX)
}

pub(crate) fn setban(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let subnet_str = required_str(params, 0, "subnet is required")?;
    let command = required_str(params, 1, "command is required")?;
    let subnet = parse_setban_target(subnet_str)?;
    match command {
        "add" => {
            let now = SystemTime::now();
            let bantime = optional_u64(params, 2, 0)?;
            let absolute = optional_bool(params, 3, false)?;
            let mut banned = ctx.banned.write();
            banned.retain(|entry| entry.subnet != subnet);
            banned.push(BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            });
        }
        "remove" => {
            ctx.banned.write().retain(|entry| entry.subnet != subnet);
        }
        _ => return Err(RpcError::InvalidParams("command must be 'add' or 'remove'")),
    }
    Ok(Value::new_null())
}

pub(crate) fn clearbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    ctx.banned.write().clear();
    Ok(Value::new_null())
}

pub(crate) fn setnetworkactive(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let state = array
        .first()
        .and_then(JsonValueTrait::as_bool)
        .ok_or(RpcError::InvalidParams("state must be a boolean"))?;
    // No-op until P2P kill-switch is wired; echo back the requested state.
    corepc_to_sonic(&SetNetworkActive(state))
}
pub(crate) fn ping(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    // Core's `ping` schedules a P2P ping; we don't have async-ping wiring yet,
    // so we return null per the Core contract. Per-peer pingtime surfaces via
    // getpeerinfo when measurements are available.
    Ok(Value::new_null())
}

pub(crate) fn addnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let node = required_str(params, 0, "node is required")?;
    let command = required_str(params, 1, "command is required")?;
    let addr = SocketAddr::from_str(node)
        .map_err(|_| RpcError::InvalidParams("node must be a valid host:port address"))?;
    match command {
        "add" | "onetry" => {
            let now = SystemTime::now();
            let banned = ctx.banned.read();
            if bitcoin_rs_p2p::subnet::is_banned(banned.as_slice(), addr.ip(), now) {
                return Err(RpcError::InvalidParams("node is banned"));
            }
            drop(banned);

            let persist = command == "add";
            if persist {
                let mut list = ctx.added_nodes.write();
                if !list.contains(&addr) {
                    list.push(addr);
                }
            }

            if let Some(sender) = &ctx.p2p_outbound_sender {
                match sender.try_send(addr) {
                    Ok(()) => {}
                    Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) if persist => {}
                    Err(TrySendError::Full(_)) => {
                        return Err(RpcError::Internal("p2p outbound queue full".to_owned()));
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        return Err(RpcError::Internal("p2p outbound channel closed".to_owned()));
                    }
                }
            }
        }
        "remove" => {
            let mut list = ctx.added_nodes.write();
            list.retain(|a| *a != addr);
        }
        _ => {
            return Err(RpcError::InvalidParams(
                "command must be one of: add, remove, onetry",
            ));
        }
    }
    Ok(Value::new_null())
}

pub(crate) fn disconnectnode(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let address = required_str(params, 0, "address is required")?;
    SocketAddr::from_str(address)
        .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;
    // TODO(p2p-outbound): wire to a disconnection sender on Context.
    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let count = ctx.peers.read().len();
    corepc_to_sonic(&GetConnectionCount(
        u64::try_from(count).unwrap_or(u64::MAX),
    ))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let network = ctx.network.read();
    corepc_to_sonic(&GetNetTotals {
        total_bytes_received: network.bytes_recv,
        total_bytes_sent: network.bytes_sent,
        time_millis: network.timestamp,
        upload_target: UploadTarget {
            timeframe: 0,
            target: 0,
            target_reached: true,
            serve_historical_blocks: true,
            bytes_left_in_cycle: 0,
            time_left_in_cycle: 0,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn getnetworkinfo_reports_zero_connections_on_fresh_context() {
        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        let Some(connections) = result.get("connections").and_then(JsonValueTrait::as_u64) else {
            panic!("connections missing: {result:?}");
        };
        assert_eq!(connections, 0);
        let Some(connections_in) = result
            .get("connections_in")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("connections_in missing: {result:?}");
        };
        assert_eq!(connections_in, 0);
    }

    #[test]
    fn getnetworkinfo_emits_relayfee_default_of_one_sat_per_vbyte() {
        use alloc::sync::Arc;

        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        let Some(relayfee) = result.get("relayfee").and_then(JsonValueTrait::as_f64) else {
            panic!("relayfee missing: {result:?}");
        };
        assert!(
            (relayfee - 0.00001).abs() < 1e-9,
            "expected ~0.00001, got {relayfee}"
        );
    }

    #[test]
    fn getnetworkinfo_localservices_advertises_only_supported_services() {
        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result.get("localservices").and_then(|v| v.as_str()),
            Some("0000000000000009")
        );
        let names: Vec<String> = result
            .get("localservicesnames")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|n| n.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();
        assert!(names.contains(&"NETWORK".to_owned()));
        assert!(names.contains(&"WITNESS".to_owned()));
        assert!(!names.contains(&"COMPACT_FILTERS".to_owned()));
    }

    #[test]
    fn local_services_flags_hex_matches_bitmask() {
        assert_eq!(format!("{LOCAL_SERVICES_FLAGS:016x}"), LOCAL_SERVICES_HEX);
    }

    #[test]
    fn services_names_from_flags_decodes_known_bits() {
        let names = services_names_from_flags(0_u64);
        assert!(names.is_empty());

        let names = services_names_from_flags((1_u64 << 0) | (1_u64 << 3));
        assert_eq!(names, vec!["NETWORK".to_owned(), "WITNESS".to_owned()]);

        let names = services_names_from_flags((1_u64 << 0) | (1_u64 << 3) | (1_u64 << 10));
        assert_eq!(
            names,
            vec![
                "NETWORK".to_owned(),
                "WITNESS".to_owned(),
                "NETWORK_LIMITED".to_owned()
            ]
        );
    }

    #[test]
    fn getpeerinfo_servicesnames_matches_peer_info_services_names() {
        use bitcoin_rs_p2p::PeerInfo;

        let info = PeerInfo {
            addr: "127.0.0.1:8333".parse().unwrap_or_else(|_| panic!("addr")),
            version: 70_016,
            services: (1_u64 << 0) | (1_u64 << 3),
            user_agent: "stub".to_owned(),
            start_height: 0,
            conn_time: 0,
            inbound: false,
        };

        assert_eq!(info.services_names(), vec!["NETWORK", "WITNESS"]);
    }

    #[test]
    fn services_names_from_flags_ignores_unknown_bits() {
        // Bit 63 is not in the decoder's recognized set.
        let names = services_names_from_flags(1_u64 << 63);
        assert!(names.is_empty());
    }
}
#[cfg(test)]
mod ping_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn ping_returns_null() {
        let ctx = Arc::new(Context::new());
        let result = ping(&ctx, &json!([])).unwrap_or_else(|err| panic!("ping failed: {err}"));
        assert!(result.is_null());
    }
}

#[cfg(test)]
mod addnode_validation_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::JsonValueTrait;

    #[test]
    fn addnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["definitely-not-an-address", "add"]));
        assert!(result.is_err());
    }

    #[test]
    fn addnode_rejects_unknown_command() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn addnode_accepts_well_formed_input() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "onetry"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        assert!(result.is_null());
    }

    #[test]
    fn addnode_add_sends_outbound_request() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let Ok(sent) = rx.try_recv() else {
            panic!("addnode did not send outbound request");
        };
        assert_eq!(sent, std::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    }

    #[test]
    fn addnode_returns_error_when_outbound_queue_is_full() {
        let (tx, rx) = crossbeam_channel::bounded(1);
        tx.try_send(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)))
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));

        assert!(matches!(
            result,
            Err(RpcError::Internal(message)) if message == "p2p outbound queue full"
        ));
        assert_eq!(rx.try_iter().count(), 1);
    }

    #[test]
    fn addnode_add_persists_when_outbound_queue_is_full() {
        let (tx, _rx) = crossbeam_channel::bounded(1);
        tx.try_send(std::net::SocketAddr::from(([127, 0, 0, 1], 8333)))
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let added = ctx.added_nodes.read();
        assert_eq!(
            added.as_slice(),
            [std::net::SocketAddr::from(([127, 0, 0, 2], 8333))]
        );
    }

    #[test]
    fn addnode_rejects_manually_banned_subnet() {
        let (tx, rx) = crossbeam_channel::unbounded();
        let mut ctx = Context::new();
        ctx.p2p_outbound_sender = Some(tx);
        let ctx = Arc::new(ctx);
        if let Err(err) = setban(&ctx, &json!(["127.0.0.0/24", "add"])) {
            panic!("setban failed: {err}");
        }

        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams("node is banned"))
        ));
        assert!(ctx.added_nodes.read().is_empty());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn disconnectnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
        assert!(result.is_err());
    }

    #[test]
    fn disconnectnode_accepts_well_formed_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
    }
}

#[cfg(test)]
mod admin_rpc_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    #[test]
    fn getaddednodeinfo_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn listbanned_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result =
            listbanned(&ctx, &json!(null)).unwrap_or_else(|err| panic!("listbanned failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn setban_accepts_add_and_remove() {
        let ctx = Arc::new(Context::new());
        assert!(setban(&ctx, &json!(["10.0.0.1:8333", "add"])).is_ok());
        let result = match listbanned(&ctx, &json!(null)) {
            Ok(result) => result,
            Err(err) => panic!("listbanned failed: {err}"),
        };
        let Some(arr) = result.as_array() else {
            panic!("expected array, got {result:?}");
        };
        let Some(entry) = arr.first() else {
            panic!("expected one ban entry");
        };
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("10.0.0.1/32")
        );
        assert!(setban(&ctx, &json!(["10.0.0.1:8333", "remove"])).is_ok());
        assert!(ctx.banned.read().is_empty());
    }

    #[test]
    fn setban_rejects_unknown_command() {
        let ctx = Arc::new(Context::new());
        let result = setban(&ctx, &json!(["10.0.0.1:8333", "frobnicate"]));
        assert!(result.is_err());
    }

    #[test]
    fn setnetworkactive_echoes_state() {
        let ctx = Arc::new(Context::new());
        let result = setnetworkactive(&ctx, &json!([true]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
    }
}
#[cfg(test)]
mod ban_state_tests {
    use super::*;
    use alloc::sync::Arc;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value};

    fn listbanned_ok(ctx: &Arc<Context>) -> Value {
        match listbanned(ctx, &json!(null)) {
            Ok(result) => result,
            Err(err) => panic!("listbanned failed: {err}"),
        }
    }

    fn setban_ok(ctx: &Arc<Context>, target: &str, command: &str) {
        if let Err(err) = setban(ctx, &json!([target, command])) {
            panic!("setban failed: {err}");
        }
    }

    fn clearbanned_ok(ctx: &Arc<Context>) {
        if let Err(err) = clearbanned(ctx, &json!(null)) {
            panic!("clearbanned failed: {err}");
        }
    }

    fn list_addresses(ctx: &Arc<Context>) -> Vec<String> {
        let result = listbanned_ok(ctx);
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        arr.iter()
            .filter_map(|entry| entry.get("address").and_then(JsonValueTrait::as_str))
            .map(str::to_owned)
            .collect()
    }

    fn sole_address(ctx: &Arc<Context>) -> String {
        let addresses = list_addresses(ctx);
        assert_eq!(addresses.len(), 1);
        let Some(address) = addresses.first() else {
            panic!("expected one ban address");
        };
        address.to_owned()
    }

    #[test]
    fn setban_add_persists_in_context() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "127.0.0.1:8333", "add");
        let banned = ctx.banned.read();
        assert_eq!(banned.len(), 1);
    }

    #[test]
    fn listbanned_returns_added_entries() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.1:8333", "add");
        let result = listbanned_ok(&ctx);
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        let Some(entry) = arr.first() else {
            panic!("expected one ban entry");
        };
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("192.168.1.1/32")
        );
        let Some(created) = entry.get("ban_created").and_then(JsonValueTrait::as_u64) else {
            panic!("ban_created missing");
        };
        let Some(until) = entry.get("banned_until").and_then(JsonValueTrait::as_u64) else {
            panic!("banned_until missing");
        };
        assert!(until >= created);
    }

    #[test]
    fn setban_cidr_add_list_roundtrip() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "10.0.0.0/8", "add");

        assert_eq!(sole_address(&ctx), "10.0.0.0/8");
    }

    #[test]
    fn setban_normalizes_host_bits() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.99/24", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.0/24");
    }

    #[test]
    fn setban_bare_ip_stores_single_address_subnet() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.99", "add");

        assert_eq!(sole_address(&ctx), "192.168.1.99/32");
    }

    #[test]
    fn setban_ipv6_cidr_canonicalizes() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "2001:db8::1/64", "add");

        assert_eq!(sole_address(&ctx), "2001:db8::/64");
    }

    #[test]
    fn setban_rejects_invalid_subnet() {
        let ctx = Arc::new(Context::new());
        let result = setban(&ctx, &json!(["10.0.0.1/33", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams(
                "subnet must be IP, IP/prefix, or host:port"
            ))
        ));
    }

    #[test]
    fn setban_remove_matches_exact_subnet() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "10.0.0.0/24", "add");
        setban_ok(&ctx, "10.0.0.1", "add");

        setban_ok(&ctx, "10.0.0.1", "remove");

        assert_eq!(list_addresses(&ctx), vec!["10.0.0.0/24".to_owned()]);
    }

    #[test]
    fn clearbanned_empties_vec() {
        let ctx = Arc::new(Context::new());
        setban_ok(&ctx, "192.168.1.1", "add");
        clearbanned_ok(&ctx);
        assert!(ctx.banned.read().is_empty());
    }

    #[test]
    fn addnode_add_persists_in_added_nodes_list() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let added = ctx.added_nodes.read();
        assert_eq!(added.len(), 1);
    }

    #[test]
    fn getaddednodeinfo_returns_persisted_entries() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let result = getaddednodeinfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getaddednodeinfo failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }
}
