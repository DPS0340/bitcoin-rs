//! P2P E2E against a pinned Bitcoin Core 31.1 peer: initial sync, peer
//! introspection, connection management, banning, and network toggles.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use bitcoin_rs_e2e::helpers::spawn_synced_pair;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

/// A fresh node syncs a Core-mined regtest chain to the same tip.
#[test]
fn node_syncs_core_chain_to_tip() -> Result<()> {
    let (mut core, mut node) = spawn_synced_pair(12)?;

    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(12));
    let node_tip = node.rpc("getbestblockhash", &json!([]))?;
    let core_tip = core.rpc("getbestblockhash", &json!([]))?;
    assert_eq!(node_tip, core_tip);

    // Hash-by-hash agreement over the synced range.
    for height in [1_u64, 6, 12] {
        assert_eq!(
            node.rpc("getblockhash", &json!([height]))?,
            core.rpc("getblockhash", &json!([height]))?,
            "height {height} diverged"
        );
    }
    node.stop()?;
    core.stop()
}

/// `getpeerinfo` and `getconnectioncount` reflect the live Core peer.
#[test]
fn peer_info_and_connection_count() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(5)?;

    assert!(
        node.rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .is_some_and(|c| c >= 1)
    );
    let peers = node.rpc("getpeerinfo", &json!([]))?;
    let peers = peers
        .as_array()
        .ok_or_else(|| Error::Assertion("getpeerinfo not array".into()))?;
    assert!(!peers.is_empty());
    let peer = &peers[0];
    assert_eq!(
        peer.str_field("addr")?,
        format!("127.0.0.1:{}", core.p2p_addr.port())
    );
    assert!(peer.get("conntime").is_some(), "peer lacks conntime");
    assert!(peer.get("subver").is_some(), "peer lacks subver");
    // `synced_blocks`/`synced_headers` are honest "not measured" (-1) in this
    // node rather than a guessed height; assert the fields exist and are ints.
    for field in ["synced_blocks", "synced_headers", "presynced_headers"] {
        assert!(
            peer.get(field).is_some_and(serde_json::Value::is_i64),
            "peer lacks int {field}: {peer}"
        );
    }
    node.stop()?;
    core.stop()
}

/// `getnetworkinfo`/`getnettotals` describe the connected transport.
#[test]
fn network_info_and_totals() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(3)?;

    let info = node.rpc("getnetworkinfo", &json!([]))?;
    assert!(info.u64_field("connections")? >= 1, "connections: {info}");
    assert_eq!(
        info.str_field("subversion")?,
        concat!("/bitcoin-rs:", env!("CARGO_PKG_VERSION"), "/")
    );
    assert_eq!(info.u64_field("protocolversion")?, 70016);
    let services = info["localservicesnames"]
        .as_array()
        .ok_or_else(|| Error::Assertion("localservicesnames".into()))?;
    for svc in ["NETWORK", "WITNESS"] {
        assert!(services.iter().any(|s| s == svc), "missing {svc}");
    }

    let totals = node.rpc("getnettotals", &json!([]))?;
    assert!(totals.u64_field("totalbytesrecv")? > 0);
    assert!(totals.u64_field("totalbytessent")? > 0);
    node.stop()?;
    core.stop()
}

/// `ping` answers immediately (documented deviation from Core's
/// scheduled pong measurement).
#[test]
fn ping_answers_immediately() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    assert_eq!(node.rpc("ping", &json!([]))?, Value::Null);
    node.stop()
}

/// `addnode`/`getaddednodeinfo`/`disconnectnode` manage outbound peers.
#[test]
fn addnode_disconnect_flow() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(2)?;
    let core_addr = format!("127.0.0.1:{}", core.p2p_addr.port());

    let added = node.rpc("getaddednodeinfo", &json!([]))?;
    assert!(added.as_array().is_some());

    // Disconnect the live peer by address, then wait for the drop.
    assert_eq!(
        node.rpc("disconnectnode", &json!([core_addr]))?,
        Value::Null
    );
    node.wait_for("peer disconnect", Duration::from_secs(15), |node| {
        Ok(node
            .rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .map(|c| c == 0))
    })?;

    // Reconnect through addnode and wait for the handshake.
    assert_eq!(
        node.rpc("addnode", &json!([core.p2p_addr.to_string(), "add"]))?,
        Value::Null
    );
    node.wait_for("reconnect", Duration::from_secs(20), |node| {
        Ok(node
            .rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .map(|c| c >= 1))
    })?;
    node.stop()?;
    core.stop()
}

/// `setban`/`listbanned`/`clearbanned` maintain the ban list.
#[test]
fn ban_list_round_trip() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    assert_eq!(
        node.rpc("setban", &json!(["192.0.2.1", "add", 3600]))?,
        Value::Null
    );
    let banned = node.rpc("listbanned", &json!([]))?;
    let list = banned
        .as_array()
        .ok_or_else(|| Error::Assertion("listbanned not array".into()))?;
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].str_field("address")?, "192.0.2.1/32");
    assert_eq!(list[0].u64_field("ban_duration")?, 3600);

    assert_eq!(node.rpc("clearbanned", &json!([]))?, Value::Null);
    assert_eq!(node.rpc("listbanned", &json!([]))?, json!([]));
    node.stop()
}

/// `setnetworkactive` drops and restores connectivity.
#[test]
fn setnetworkactive_toggles_peers() -> Result<()> {
    let (core, mut node) = spawn_synced_pair(2)?;
    let core_addr = format!("127.0.0.1:{}", core.p2p_addr.port());

    assert_eq!(node.rpc("setnetworkactive", &json!([false]))?, json!(false));
    node.wait_for("network off", Duration::from_secs(15), |node| {
        Ok(node
            .rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .map(|c| c == 0))
    })?;
    assert_eq!(
        node.rpc("getnetworkinfo", &json!([]))?
            .get("networkactive")
            .and_then(Value::as_bool),
        Some(false)
    );

    assert_eq!(node.rpc("setnetworkactive", &json!([true]))?, json!(true));
    assert_eq!(
        node.rpc("addnode", &json!([core_addr, "add"]))?,
        Value::Null
    );
    node.wait_for("network on", Duration::from_secs(20), |node| {
        Ok(node
            .rpc("getconnectioncount", &json!([]))?
            .as_u64()
            .map(|c| c >= 1))
    })?;
    node.stop()?;
    core.stop()
}

/// `getnodeaddresses` reports the empty address manager on a fresh node.
#[test]
fn node_addresses_empty() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    assert_eq!(node.rpc("getnodeaddresses", &json!([]))?, json!([]));
    node.stop()
}

/// The node keeps syncing while the peer mines more blocks — not only
/// at startup.
#[test]
fn node_follows_extended_core_chain() -> Result<()> {
    let (mut core, mut node) = spawn_synced_pair(4)?;
    core.rpc(
        "generatetoaddress",
        &json!([6, bitcoin_rs_e2e::helpers::funding_address()?.to_string()]),
    )?;
    node.wait_block_count(10, Duration::from_secs(90))?;
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    node.stop()?;
    core.stop()
}
