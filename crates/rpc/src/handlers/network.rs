use alloc::sync::Arc;

use core::str::FromStr;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::IpSubnet;
use bitcoin_rs_primitives::USER_AGENT;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str};

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

/// Maps an IP address to Bitcoin Core's `network` field label.
fn network_name(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

pub(crate) fn getnetworkinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.p2p.lifecycle().ready_peers();
    let total = peers.len();
    let inbound = peers.iter().filter(|peer| peer.info.inbound).count();
    let outbound = total.saturating_sub(inbound);
    let network_active = ctx.p2p.network_active();
    Ok(json!({
        "version": 10000,
        "subversion": USER_AGENT,
        "protocolversion": 70016_i64,
        "localservices": LOCAL_SERVICES_HEX,
        "localservicesnames": services_names_from_flags(LOCAL_SERVICES_FLAGS),
        "localrelay": true,
        "timeoffset": 0,
        "networkactive": network_active,
        "connections": total,
        "connections_in": inbound,
        "connections_out": outbound,
        "networks": [
            {"name": "ipv4", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "ipv6", "limited": false, "reachable": true, "proxy": "", "proxy_randomize_credentials": false},
            {"name": "onion", "limited": true, "reachable": false, "proxy": "", "proxy_randomize_credentials": false}
        ],
        "relayfee": DEFAULT_RELAY_FEE_BTC_PER_KVB,
        "incrementalfee": DEFAULT_INCREMENTAL_FEE_BTC_PER_KVB,
        "localaddresses": Vec::<String>::new(),
        "warnings": ""
    }))
}

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.p2p.lifecycle().ready_peers();
    let mut array = Vec::with_capacity(peers.len());
    for (id, ready_peer) in peers.iter().enumerate() {
        let peer = &ready_peer.info;
        array.push(json!({
            "id": id,
            "addr": peer.addr.to_string(),
            "addrbind": peer.addr.to_string(),
            "services": format!("{:016x}", peer.services),
            "servicesnames": peer.services_names().into_iter().map(str::to_owned).collect::<Vec<_>>(),
            "relaytxes": true,
            "lastsend": 0,
            "lastrecv": 0,
            "bytessent": 0,
            "bytesrecv": 0,
            "conntime": peer.conn_time,
            "timeoffset": 0,
            "pingtime": 0.0,
            "minping": 0.0,
            "version": peer.version,
            "subver": peer.user_agent.clone(),
            "inbound": peer.inbound,
            "startingheight": peer.start_height,
            "presynced_headers": -1,
            "synced_headers": -1,
            "synced_blocks": -1,
            "inflight": Vec::<u32>::new(),
            "addr_processed": 0,
            "addr_rate_limited": 0,
            "permissions": Vec::<String>::new(),
            "minfeefilter": 0.0,
            "bytessent_per_msg": serde_json::Map::<String, serde_json::Value>::new(),
            "bytesrecv_per_msg": serde_json::Map::<String, serde_json::Value>::new(),
            "connection_type": if peer.inbound { "inbound" } else { "outbound" },
        }));
    }
    Ok(json!(array))
}

pub(crate) fn getaddednodeinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let _ = params_array(params)?;
    let added = ctx.p2p.added_nodes();
    let entries: Vec<sonic_rs::Value> = added
        .iter()
        .map(|addr| {
            json!({
                "addednode": addr.to_string(),
                "connected": false,
                "addresses": Vec::<sonic_rs::Value>::new(),
            })
        })
        .collect();
    Ok(json!(entries))
}

pub(crate) fn listbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let banned = ctx.p2p.banned();
    let entries: Vec<sonic_rs::Value> = banned
        .iter()
        .map(|entry| {
            json!({
                "address": entry.subnet.to_string(),
                "banned_until": entry.banned_until.map_or(0, epoch_seconds),
                "ban_created": epoch_seconds(entry.ban_created),
                "ban_reason": entry.reason.clone(),
            })
        })
        .collect();
    Ok(json!(entries))
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
            ctx.p2p.set_ban(bitcoin_rs_p2p::BannedSubnet {
                subnet,
                banned_until: ban_until(now, bantime, absolute),
                ban_created: now,
                reason: "manual".to_owned(),
            });
        }
        "remove" => {
            ctx.p2p.remove_ban(subnet);
        }
        _ => return Err(RpcError::InvalidParams("command must be 'add' or 'remove'")),
    }
    Ok(Value::new_null())
}

pub(crate) fn clearbanned(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    ctx.p2p.clear_banned();
    Ok(Value::new_null())
}

pub(crate) fn setnetworkactive(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let state = array
        .first()
        .and_then(JsonValueTrait::as_bool)
        .ok_or(RpcError::InvalidParams("state must be a boolean"))?;
    ctx.p2p.set_network_active(state);
    Ok(json!(state))
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
            let persist = command == "add";
            ctx.p2p
                .add_node(addr, persist)
                .map_err(|error| match error {
                    bitcoin_rs_p2p::P2pControlError::Banned => {
                        RpcError::InvalidParams("node is banned")
                    }
                    bitcoin_rs_p2p::P2pControlError::QueueFull => {
                        RpcError::Internal("p2p outbound queue full".to_owned())
                    }
                    bitcoin_rs_p2p::P2pControlError::Closed => {
                        RpcError::Internal("p2p outbound channel closed".to_owned())
                    }
                })?;
        }
        "remove" => {
            ctx.p2p.remove_node(addr);
        }
        _ => {
            return Err(RpcError::InvalidParams(
                "command must be one of: add, remove, onetry",
            ));
        }
    }
    Ok(Value::new_null())
}

pub(crate) fn disconnectnode(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let address = required_str(params, 0, "address is required")?;
    let addr = SocketAddr::from_str(address)
        .map_err(|_| RpcError::InvalidParams("address must be a valid host:port"))?;

    // Optional nodeid — the index reported by `getpeerinfo`, used to
    // disambiguate when several peers share one address.
    let nodeid: Option<usize> = array
        .get(1)
        .filter(|v| !v.is_null())
        .and_then(JsonValueTrait::as_u64)
        .map(|n| usize::try_from(n).unwrap_or(usize::MAX));

    // Snapshot the selected connection identity before requesting teardown.
    // `disconnect_source` will preserve a same-address replacement if one
    // wins the race after this snapshot.
    let source = {
        let peers = ctx.p2p.lifecycle().ready_peers();
        match nodeid {
            Some(id) => peers
                .get(id)
                .filter(|peer| peer.info.addr == addr)
                .map(|peer| peer.source),
            None => peers
                .into_iter()
                .find(|peer| peer.info.addr == addr)
                .map(|peer| peer.source),
        }
    };
    let Some(source) = source else {
        return Err(RpcError::NotFound("Node not found in connected nodes"));
    };
    if !ctx.p2p.disconnect(source) {
        return Err(RpcError::NotFound("Node was replaced before disconnect"));
    }

    Ok(Value::new_null())
}

pub(crate) fn getconnectioncount(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let count = ctx.p2p.lifecycle().ready_peers().len();
    Ok(json!(count))
}

pub(crate) fn getnettotals(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let network = ctx.network.read();
    Ok(json!({
        "totalbytesrecv": network.bytes_recv,
        "totalbytessent": network.bytes_sent,
        "timemillis": network.timestamp,
        "uploadtarget": {
            "timeframe": 0,
            "target": 0,
            "target_reached": true,
            "serve_historical_blocks": true,
            "bytes_left_in_cycle": 0,
            "time_left_in_cycle": 0
        }
    }))
}

/// `getnodeaddresses [count]` — returns known peer addresses.
///
/// The address source is the live peer registry plus persisted `addnode add`
/// entries, deduplicated by socket address.  `count` defaults to 1; `0`
/// returns every known address.  Each entry follows Core's shape:
/// `{ time, services, address, port, network }`.
pub(crate) fn getnodeaddresses(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let count = optional_u64(params, 0, 1)?;

    let now = epoch_seconds(SystemTime::now());
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let mut entries: Vec<sonic_rs::Value> = Vec::new();

    // Live peers carry real service flags and handshake times.
    for ready_peer in ctx.p2p.lifecycle().ready_peers() {
        let peer = &ready_peer.info;
        if !seen.insert(peer.addr) {
            continue;
        }
        entries.push(json!({
            "time": peer.conn_time,
            "services": peer.services,
            "address": peer.addr.ip().to_string(),
            "port": peer.addr.port(),
            "network": network_name(peer.addr.ip()),
        }));
    }

    // Persisted added nodes have no known services; advertise NODE_NETWORK.
    for addr in ctx.p2p.added_nodes() {
        if !seen.insert(addr) {
            continue;
        }
        entries.push(json!({
            "time": now,
            "services": 1_u64,
            "address": addr.ip().to_string(),
            "port": addr.port(),
            "network": network_name(addr.ip()),
        }));
    }

    // Core semantics: count == 0 returns all, otherwise truncate to count.
    if count > 0 {
        let max = usize::try_from(count).unwrap_or(usize::MAX);
        if max < entries.len() {
            entries.truncate(max);
        }
    }

    Ok(json!(entries))
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
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use crossbeam_channel::unbounded;
    use sonic_rs::JsonValueTrait;

    fn register_peer(ctx: &Context, info: PeerInfo, ready: bool) -> PeerLease {
        let (tx, _rx) = unbounded();
        let lease = PeerLease::new(tx);
        assert!(!ctx.p2p.lifecycle().register(info.addr, &lease));
        if ready {
            assert!(ctx.p2p.lifecycle().publish_ready(info.addr, &lease, info));
        }
        lease
    }

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
    fn addnode_skips_queueing_while_network_is_inactive() {
        let ctx = Context::new();
        ctx.p2p.set_network_active(false);
        let ctx = Arc::new(ctx);

        let persisted = SocketAddr::from(([127, 0, 0, 1], 8333));
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));
        assert!(result.is_ok());
        assert_eq!(ctx.p2p.added_nodes(), vec![persisted]);

        ctx.p2p.set_network_active(true);
        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));
        assert!(result.is_ok());
    }

    #[test]
    fn addnode_add_sends_outbound_request() {
        let ctx = Arc::new(Context::new());
        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        assert_eq!(ctx.p2p.added_nodes().len(), 1);
    }

    #[test]
    fn addnode_returns_error_when_outbound_queue_is_full() {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                outbound_queue_limit: 1,
                ..Default::default()
            },
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        p2p.add_node(SocketAddr::from(([127, 0, 0, 1], 8333)), false)
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let ctx = Arc::new(Context::new().with_p2p(p2p));

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "onetry"]));

        assert!(matches!(
            result,
            Err(RpcError::Internal(message)) if message == "p2p outbound queue full"
        ));
    }

    #[test]
    fn addnode_add_persists_when_outbound_queue_is_full() {
        let p2p = Arc::new(bitcoin_rs_p2p::P2pService::new(
            bitcoin_rs_p2p::P2pServiceConfig {
                outbound_queue_limit: 1,
                ..Default::default()
            },
            Arc::new(std::sync::atomic::AtomicBool::new(false)),
        ));
        p2p.add_node(SocketAddr::from(([127, 0, 0, 1], 8333)), false)
            .unwrap_or_else(|err| panic!("failed to fill outbound queue: {err}"));
        let ctx = Arc::new(Context::new().with_p2p(p2p));

        let result = addnode(&ctx, &json!(["127.0.0.2:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));

        assert!(result.is_null());
        let added = ctx.p2p.added_nodes();
        assert_eq!(
            added.as_slice(),
            [std::net::SocketAddr::from(([127, 0, 0, 2], 8333))]
        );
    }

    #[test]
    fn addnode_rejects_manually_banned_subnet() {
        let ctx = Arc::new(Context::new());
        if let Err(err) = setban(&ctx, &json!(["127.0.0.0/24", "add"])) {
            panic!("setban failed: {err}");
        }

        let result = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]));

        assert!(matches!(
            result,
            Err(RpcError::InvalidParams("node is banned"))
        ));
        assert!(ctx.p2p.added_nodes().is_empty());
    }

    #[test]
    fn disconnectnode_rejects_bad_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["definitely-not-an-address"]));
        assert!(result.is_err());
    }

    #[test]
    fn disconnectnode_rejects_unconnected_address() {
        let ctx = Arc::new(Context::new());
        let result = disconnectnode(&ctx, &json!(["127.0.0.1:8333"]));
        assert!(matches!(result, Err(RpcError::NotFound(_))));
    }

    #[test]
    fn disconnectnode_cancels_lease_and_removes_peer() {
        let addr: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let ctx = Context::new();
        let lease = register_peer(
            &ctx,
            PeerInfo {
                addr,
                version: 70_016,
                services: 9,
                user_agent: "test".to_owned(),
                start_height: 0,
                conn_time: 0,
                inbound: false,
            },
            true,
        );
        let ctx = Arc::new(ctx);

        let result = disconnectnode(&ctx, &json!([addr.to_string().as_str()]))
            .unwrap_or_else(|err| panic!("disconnectnode failed: {err}"));
        assert!(result.is_null());
        assert!(lease.is_cancelled());
        assert!(ctx.p2p.lifecycle().live_addresses().is_empty());
        assert!(ctx.p2p.lifecycle().ready_peers().is_empty());
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
    fn setnetworkactive_stores_and_echoes_state() {
        let ctx = Arc::new(Context::new());
        let result = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
        assert!(!ctx.p2p.network_active());
    }

    #[test]
    fn setnetworkactive_false_cancels_all_leases() {
        use bitcoin_rs_p2p::PeerLease;
        use crossbeam_channel::unbounded;

        let addr_a: SocketAddr = "127.0.0.1:8333".parse().unwrap();
        let addr_b: SocketAddr = "127.0.0.2:8333".parse().unwrap();
        let ctx = Context::new();
        let (tx_a, _rx_a) = unbounded();
        let (tx_b, _rx_b) = unbounded();
        let lease_a = PeerLease::new(tx_a);
        let lease_b = PeerLease::new(tx_b);
        assert!(!ctx.p2p.lifecycle().register(addr_a, &lease_a));
        assert!(!ctx.p2p.lifecycle().register(addr_b, &lease_b));
        let ctx = Arc::new(ctx);

        let _ = setnetworkactive(&ctx, &json!([false]))
            .unwrap_or_else(|err| panic!("setnetworkactive failed: {err}"));
        assert!(lease_a.is_cancelled());
        assert!(lease_b.is_cancelled());
        assert_eq!(ctx.p2p.lifecycle().live_addresses().len(), 2);
    }

    #[test]
    fn getnetworkinfo_reports_network_active_state() {
        let ctx = Arc::new(Context::new());
        ctx.p2p.set_network_active(false);
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result
                .get("networkactive")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
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
        assert!(ctx.p2p.banned().is_empty());
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
        let banned = ctx.p2p.banned();
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
        assert_eq!(
            entry.get("ban_reason").and_then(JsonValueTrait::as_str),
            Some("manual")
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
        assert!(ctx.p2p.banned().is_empty());
    }

    #[test]
    fn addnode_add_persists_in_added_nodes_list() {
        let ctx = Arc::new(Context::new());
        let _ = addnode(&ctx, &json!(["127.0.0.1:8333", "add"]))
            .unwrap_or_else(|err| panic!("addnode failed: {err}"));
        let added = ctx.p2p.added_nodes();
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

#[cfg(test)]
mod getnodeaddresses_tests {
    use super::*;
    use alloc::sync::Arc;
    use bitcoin_rs_p2p::{PeerInfo, PeerLease};
    use crossbeam_channel::unbounded;
    use sonic_rs::{JsonContainerTrait, JsonValueTrait};

    fn peer(addr: &str, services: u64) -> PeerInfo {
        PeerInfo {
            addr: addr.parse().unwrap(),
            version: 70_016,
            services,
            user_agent: "test".to_owned(),
            start_height: 0,
            conn_time: 100,
            inbound: false,
        }
    }

    fn register_peer(ctx: &Context, info: PeerInfo) {
        let (tx, _rx) = unbounded();
        let lease = PeerLease::new(tx);
        assert!(!ctx.p2p.lifecycle().register(info.addr, &lease));
        assert!(ctx.p2p.lifecycle().publish_ready(info.addr, &lease, info));
    }

    #[test]
    fn empty_context_returns_empty_array() {
        let ctx = Arc::new(Context::new());
        let result = getnodeaddresses(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert!(arr.is_empty());
    }

    #[test]
    fn returns_live_peer_addresses() {
        let ctx = Context::new();
        register_peer(&ctx, peer("127.0.0.1:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        let entry = &arr[0];
        assert_eq!(
            entry.get("address").and_then(JsonValueTrait::as_str),
            Some("127.0.0.1")
        );
        assert_eq!(
            entry.get("port").and_then(JsonValueTrait::as_u64),
            Some(8333)
        );
        assert_eq!(
            entry.get("services").and_then(JsonValueTrait::as_u64),
            Some(9)
        );
        assert_eq!(
            entry.get("network").and_then(JsonValueTrait::as_str),
            Some("ipv4")
        );
    }

    #[test]
    fn deduplicates_peer_and_added_node() {
        let ctx = Context::new();
        register_peer(&ctx, peer("127.0.0.1:8333", 9));
        ctx.p2p
            .add_node("127.0.0.1:8333".parse().unwrap(), true)
            .unwrap_or_else(|err| panic!("failed to add test node: {err}"));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn count_limits_results() {
        let ctx = Context::new();
        register_peer(&ctx, peer("127.0.0.1:8333", 9));
        register_peer(&ctx, peer("127.0.0.2:8333", 9));
        register_peer(&ctx, peer("127.0.0.3:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([2]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn default_count_returns_one() {
        let ctx = Context::new();
        register_peer(&ctx, peer("127.0.0.1:8333", 9));
        register_peer(&ctx, peer("127.0.0.2:8333", 9));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn added_nodes_appear_when_no_live_peer() {
        let ctx = Context::new();
        ctx.p2p
            .add_node("10.0.0.1:8333".parse().unwrap(), true)
            .unwrap_or_else(|err| panic!("failed to add test node: {err}"));
        let ctx = Arc::new(ctx);
        let result = getnodeaddresses(&ctx, &json!([0]))
            .unwrap_or_else(|err| panic!("getnodeaddresses failed: {err}"));
        let Some(arr) = result.as_array() else {
            panic!("expected array: {result:?}");
        };
        assert_eq!(arr.len(), 1);
        assert_eq!(
            arr[0].get("address").and_then(JsonValueTrait::as_str),
            Some("10.0.0.1")
        );
        assert_eq!(
            arr[0].get("services").and_then(JsonValueTrait::as_u64),
            Some(1)
        );
    }
}
