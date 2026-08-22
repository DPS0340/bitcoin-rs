use alloc::sync::Arc;

use core::str::FromStr;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitcoin_rs_p2p::{BannedSubnet, IpSubnet};
use bitcoin_rs_primitives::USER_AGENT;
use crossbeam_channel::TrySendError;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str};

// Local service flags this node advertises:
// - NODE_NETWORK (1 << 0) = 1 — full block serving.
// - NODE_WITNESS (1 << 3) = 8 — segwit data.
// - NODE_COMPACT_FILTERS (1 << 6) = 64 — BIP157 filters.
// Sum = 73 = 0x49.
const LOCAL_SERVICES_FLAGS: u64 = (1_u64 << 0) | (1_u64 << 3) | (1_u64 << 6);
const LOCAL_SERVICES_HEX: &str = "0000000000000049";

const _: () = assert!(LOCAL_SERVICES_FLAGS == 0x49);
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
    if flags & (1_u64 << 6) != 0 {
        names.push("COMPACT_FILTERS".to_owned());
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
    Ok(json!({
        // Core reports its own `CLIENT_VERSION` here. The 10000 this replaced
        // was a constant that named no release and never moved.
        "version": bitcoin_rs_primitives::client_version(),
        "subversion": USER_AGENT,
        "protocolversion": 70016_i64,
        "localservices": LOCAL_SERVICES_HEX,
        "localservicesnames": services_names_from_flags(LOCAL_SERVICES_FLAGS),
        "localrelay": true,
        "timeoffset": median_time_offset(&peers),
        "networkactive": true,
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

/// The node's clock offset, as the median of what its peers claim.
///
/// Bitcoin Core samples each peer's declared time at handshake and reports the
/// median of those samples. A single peer cannot move it, which is the point:
/// the figure exists to warn an operator that their own clock is wrong, and one
/// peer lying about the time must not produce that warning.
///
/// With no peers there is nothing to compare against, so the offset is zero --
/// the same answer Core gives, and there the zero really is the measurement.
fn median_time_offset(peers: &[bitcoin_rs_p2p::PeerInfo]) -> i64 {
    if peers.is_empty() {
        return 0;
    }
    let mut offsets: Vec<i64> = peers.iter().map(|peer| peer.time_offset).collect();
    offsets.sort_unstable();
    let middle = offsets.len() / 2;
    if offsets.len() % 2 == 1 {
        return offsets.get(middle).copied().unwrap_or(0);
    }
    // Even sample count: Core averages the two middle values.
    let lower = offsets.get(middle.saturating_sub(1)).copied().unwrap_or(0);
    let upper = offsets.get(middle).copied().unwrap_or(0);
    lower.saturating_add(upper) / 2
}

pub(crate) fn getpeerinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let peers = ctx.peers.read();
    let mut array = Vec::with_capacity(peers.len());
    for (id, peer) in peers.iter().enumerate() {
        array.push(json!({
            "id": id,
            "addr": peer.addr.to_string(),
            "addrbind": peer.addr_bind.to_string(),
            "services": format!("{:016x}", peer.services),
            "servicesnames": peer.services_names().into_iter().map(str::to_owned).collect::<Vec<_>>(),
            "relaytxes": true,
            "lastsend": peer.counters.last_send(),
            "lastrecv": peer.counters.last_recv(),
            "bytessent": peer.counters.bytes_sent(),
            "bytesrecv": peer.counters.bytes_recv(),
            "conntime": peer.conn_time,
            "timeoffset": peer.time_offset,
            // No `pingtime`, `minping` or `pingwait`. This node never sends a
            // ping, so it has never measured a round trip, and Core omits all
            // three until it has one. Reporting `0.0` would state a round trip
            // of zero seconds -- a placeholder in the shape of a measurement,
            // and the best-looking latency a peer could possibly have.
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
    let added = ctx.added_nodes.read();
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
    let banned = ctx.banned.read();
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
    fn getnetworkinfo_localservices_advertises_network_witness_filters() {
        let ctx = Arc::new(Context::new());
        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result.get("localservices").and_then(|v| v.as_str()),
            Some("0000000000000049")
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
        assert!(names.contains(&"COMPACT_FILTERS".to_owned()));
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

        let names =
            services_names_from_flags((1_u64 << 0) | (1_u64 << 3) | (1_u64 << 6) | (1_u64 << 10));
        assert_eq!(
            names,
            vec![
                "NETWORK".to_owned(),
                "WITNESS".to_owned(),
                "COMPACT_FILTERS".to_owned(),
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
            addr_bind: "127.0.0.1:8333".parse().unwrap_or_else(|_| panic!("addr")),
            time_offset: 0,
            counters: Arc::new(bitcoin_rs_p2p::PeerCounters::default()),
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

#[cfg(test)]
mod peer_counter_tests {
    use alloc::sync::Arc;
    use std::io::{Read as _, Write as _};
    use std::net::SocketAddr;

    use bitcoin_rs_p2p::{CountingStream, PeerCounters, PeerInfo};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

    use super::{getnetworkinfo, getpeerinfo};
    use crate::context::Context;

    fn peer(addr: &str, bind: &str, time_offset: i64, counters: Arc<PeerCounters>) -> PeerInfo {
        let parse = |text: &str| -> SocketAddr {
            text.parse()
                .unwrap_or_else(|_| panic!("test address {text} must parse"))
        };
        PeerInfo {
            addr: parse(addr),
            version: 70_016,
            services: 0,
            user_agent: "/test/".to_owned(),
            start_height: 0,
            conn_time: 0,
            inbound: true,
            addr_bind: parse(bind),
            time_offset,
            counters,
        }
    }

    fn context_with(peers: Vec<PeerInfo>) -> Arc<Context> {
        let ctx = Arc::new(Context::new());
        ctx.peers.write().extend(peers);
        ctx
    }

    fn first_peer(ctx: &Arc<Context>) -> sonic_rs::Value {
        let result = getpeerinfo(ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getpeerinfo failed: {err}"));
        let Some(entry) = result.as_array().and_then(|array| array.first()) else {
            panic!("getpeerinfo returned no peers: {result:?}");
        };
        entry.clone()
    }

    /// The byte counts are the connection's own, not a placeholder.
    ///
    /// The traffic is put through a `CountingStream`, the way a real connection
    /// does it, so this covers the wiring and not just the rendering.
    #[test]
    fn getpeerinfo_reports_what_the_connection_actually_moved() {
        let counters = Arc::new(PeerCounters::default());
        {
            let mut sent = CountingStream::new(Vec::new(), Arc::clone(&counters));
            let _written = sent
                .write(&[0_u8; 42])
                .unwrap_or_else(|error| panic!("write failed: {error}"));
            let mut received =
                CountingStream::new(std::io::Cursor::new(vec![1_u8; 7]), Arc::clone(&counters));
            let mut buffer = [0_u8; 7];
            let _read = received
                .read(&mut buffer)
                .unwrap_or_else(|error| panic!("read failed: {error}"));
        }

        let ctx = context_with(vec![peer(
            "127.0.0.1:8333",
            "10.0.0.2:51234",
            0,
            Arc::clone(&counters),
        )]);
        let entry = first_peer(&ctx);

        assert_eq!(
            entry.get("bytessent").and_then(JsonValueTrait::as_u64),
            Some(42)
        );
        assert_eq!(
            entry.get("bytesrecv").and_then(JsonValueTrait::as_u64),
            Some(7)
        );
        assert_ne!(
            entry.get("lastsend").and_then(JsonValueTrait::as_u64),
            Some(0),
            "a connection that sent something has a last-send time"
        );
        assert_ne!(
            entry.get("lastrecv").and_then(JsonValueTrait::as_u64),
            Some(0)
        );
    }

    /// `addrbind` is this node's end of the connection.
    ///
    /// It used to repeat `addr`, which told an operator listening on several
    /// interfaces nothing at all about which one carried the peer.
    #[test]
    fn getpeerinfo_reports_the_bind_address_not_the_peer_address() {
        let ctx = context_with(vec![peer(
            "203.0.113.7:8333",
            "10.0.0.2:51234",
            0,
            Arc::new(PeerCounters::default()),
        )]);
        let entry = first_peer(&ctx);

        assert_eq!(
            entry.get("addr").and_then(JsonValueTrait::as_str),
            Some("203.0.113.7:8333")
        );
        assert_eq!(
            entry.get("addrbind").and_then(JsonValueTrait::as_str),
            Some("10.0.0.2:51234")
        );
    }

    /// A peer's clock offset is reported with its sign.
    #[test]
    fn getpeerinfo_reports_the_peers_clock_offset() {
        for offset in [-90_i64, 0, 120] {
            let ctx = context_with(vec![peer(
                "127.0.0.1:8333",
                "127.0.0.1:1234",
                offset,
                Arc::new(PeerCounters::default()),
            )]);
            assert_eq!(
                first_peer(&ctx)
                    .get("timeoffset")
                    .and_then(JsonValueTrait::as_i64),
                Some(offset)
            );
        }
    }

    /// The node's own offset is the median, so one peer cannot move it.
    ///
    /// The figure exists to tell an operator their clock is wrong. A single
    /// peer claiming an absurd time must not be able to raise that alarm, which
    /// is exactly what a mean would let it do.
    #[test]
    fn getnetworkinfo_timeoffset_is_the_median_of_its_peers() {
        let counters = || Arc::new(PeerCounters::default());
        let ctx = context_with(vec![
            peer("127.0.0.1:1", "127.0.0.1:1000", 10, counters()),
            peer("127.0.0.1:2", "127.0.0.1:1001", 20, counters()),
            peer("127.0.0.1:3", "127.0.0.1:1002", 100_000, counters()),
        ]);

        let result = getnetworkinfo(&ctx, &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

        assert_eq!(
            result.get("timeoffset").and_then(JsonValueTrait::as_i64),
            Some(20),
            "the outlier must not move the median"
        );
    }

    /// A round trip that was never measured is not reported as zero.
    ///
    /// Core omits `pingtime` and `minping` until it has a measurement. These
    /// used to be `0.0`, which is not merely wrong but flattering: zero is the
    /// best latency a peer could possibly have.
    #[test]
    fn getpeerinfo_omits_ping_times_it_has_never_measured() {
        let ctx = context_with(vec![peer(
            "127.0.0.1:8333",
            "127.0.0.1:1234",
            0,
            Arc::new(PeerCounters::default()),
        )]);
        let entry = first_peer(&ctx);

        assert!(entry.get("pingtime").is_none(), "{entry:?}");
        assert!(entry.get("minping").is_none(), "{entry:?}");
        assert!(entry.get("pingwait").is_none(), "{entry:?}");
    }

    /// The reported client version follows the release, not a constant.
    ///
    /// The expected number is derived here from the package version rather than
    /// read back from the function under test, which could not disagree with
    /// itself.
    #[test]
    fn getnetworkinfo_version_tracks_the_release() {
        let mut expected = 0_i64;
        for (field, scale) in bitcoin_rs_primitives::PKG_VERSION
            .split('.')
            .zip([10_000_i64, 100, 1])
        {
            let digits: String = field.chars().take_while(char::is_ascii_digit).collect();
            expected += digits.parse::<i64>().unwrap_or(0) * scale;
        }
        assert_ne!(
            expected, 10_000,
            "the fixture must not match the old constant"
        );

        let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));

        assert_eq!(
            result.get("version").and_then(JsonValueTrait::as_i64),
            Some(expected)
        );
    }

    /// With no peers there is nothing to compare against.
    #[test]
    fn getnetworkinfo_timeoffset_is_zero_without_peers() {
        let result = getnetworkinfo(&Arc::new(Context::new()), &json!(null))
            .unwrap_or_else(|err| panic!("getnetworkinfo failed: {err}"));
        assert_eq!(
            result.get("timeoffset").and_then(JsonValueTrait::as_i64),
            Some(0)
        );
    }
}
