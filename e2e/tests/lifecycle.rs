//! Node lifecycle E2E: startup identity, readiness, graceful restart,
//! config rejection, and the non-node CLI exits.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::Duration;

use bitcoin_rs_e2e::helpers::{genesis_block, mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::node::{bitcoin_rs_binary, workspace};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use serde_json::json;

/// The node becomes ready on an empty datadir, reports the regtest
/// genesis as its tip, and answers the identity RPCs.
#[test]
fn startup_reports_regtest_identity() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let info = node.rpc("getblockchaininfo", &json!([]))?;
    assert_eq!(info.str_field("chain")?, "regtest");
    let genesis = genesis_block().block_hash().to_string();
    assert_eq!(info.str_field("bestblockhash")?, genesis);
    assert_eq!(info.u64_field("blocks")?, 0);
    assert_eq!(info.u64_field("headers")?, 0);

    let count = node.rpc("getblockcount", &json!([]))?;
    assert_eq!(count, json!(0));
    let best = node.rpc("getbestblockhash", &json!([]))?;
    assert_eq!(best, json!(genesis));
    let at_zero = node.rpc("getblockhash", &json!([0]))?;
    assert_eq!(at_zero, best);

    node.stop()
}

/// The node-info RPCs answer with their documented shapes.
#[test]
fn node_info_rpcs_answer() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let uptime = node.rpc("uptime", &json!([]))?;
    assert!(uptime.as_u64().is_some(), "uptime is an integer: {uptime}");

    let rpcinfo = node.rpc("getrpcinfo", &json!([]))?;
    rpcinfo.field("active_commands")?;

    let memory = node.rpc("getmemoryinfo", &json!([]))?;
    memory.field("locked")?;

    let network = node.rpc("getnetworkinfo", &json!([]))?;
    network.u64_field("connections")?;
    network.str_field("subversion")?;

    let totals = node.rpc("getnettotals", &json!([]))?;
    totals.u64_field("totalbytesrecv")?;
    totals.u64_field("totalbytessent")?;

    let capabilities = node.rpc("getcapabilities", &json!([]))?;
    assert!(
        capabilities.is_object(),
        "capabilities reply: {capabilities}"
    );

    // No indexes configured: the manifest reports an empty object.
    let indexes = node.rpc("getindexinfo", &json!([]))?;
    assert_eq!(indexes, json!({}));

    let peers = node.rpc("getpeerinfo", &json!([]))?;
    assert_eq!(peers, json!([]));
    let connections = node.rpc("getconnectioncount", &json!([]))?;
    assert_eq!(connections, json!(0));

    node.stop()
}

/// A mined tip survives SIGTERM and is visible after a clean restart
/// over the same datadir.
#[test]
fn restart_preserves_chain_tip() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let hashes = mine_bare_blocks(&mut node, 5)?;
    let tip = hashes.last().unwrap().clone();
    assert_eq!(node.rpc("getblockcount", &json!([]))?, json!(5));
    assert_eq!(node.rpc("getbestblockhash", &json!([]))?, json!(tip));

    let datadir = node.take_datadir()?;
    node.stop()?;

    let mut restarted =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    assert_eq!(restarted.rpc("getblockcount", &json!([]))?, json!(5));
    assert_eq!(restarted.rpc("getbestblockhash", &json!([]))?, json!(tip));
    restarted.stop()
}

/// A malformed config file must fail startup — the process exits and the
/// harness reports the exit instead of a ready node.
#[test]
fn malformed_config_fails_startup() -> Result<()> {
    let outcome = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            toml_override: Some("this is [not = toml\n"),
            timeout: Some(Duration::from_secs(30)),
            ..SpawnOptions::default()
        },
    );
    match outcome {
        Err(Error::ChildExit { .. }) => Ok(()),
        Err(other) => Err(Error::Assertion(format!(
            "unexpected failure mode: {other}"
        ))),
        Ok(_) => Err(Error::Assertion(
            "node started on a malformed config".into(),
        )),
    }
}

/// An unparseable CLI flag is rejected before the node binds anything.
#[test]
fn invalid_cli_flag_rejected() {
    let outcome = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &["--network", "no-such-net"],
            timeout: Some(Duration::from_secs(30)),
            ..SpawnOptions::default()
        },
    );
    assert!(
        matches!(outcome, Err(Error::ChildExit { .. })),
        "invalid --network must not start a node: {outcome:?}"
    );
}

/// `--measure-storage` reports the datadir footprint as JSON on stdout and
/// exits without starting the node.
#[test]
fn measure_storage_exits_with_report() -> Result<()> {
    let datadir = tempfile::tempdir()?;
    let node_dir = datadir.path().join("node");
    std::fs::create_dir_all(&node_dir)?;
    let _ = workspace();
    let output = std::process::Command::new(bitcoin_rs_binary()?)
        .args([
            "--config",
            "/dev/null",
            "--storage-backend",
            "fjall",
            "--data-dir",
        ])
        .arg(&node_dir)
        .arg("--measure-storage")
        .env_remove("RUST_LOG")
        .output()?;
    assert!(
        output.status.success(),
        "measure-storage failed: {output:?}"
    );
    let parsed: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| Error::Assertion(format!("measure-storage stdout not JSON: {e}")))?;
    assert!(parsed.is_object(), "report shape: {parsed}");
    Ok(())
}

/// The node's RPC listener cannot bind a port that is already held:
/// `bind()` fails and the process exits instead of hanging or serving.
#[test]
fn rpc_bind_conflict_fails_startup() -> Result<()> {
    // Occupy a port ourselves, then point the node's sole `--rpc-bind` at
    // it. The squatter stays held until spawn reports the child's exit.
    let squatter = std::net::TcpListener::bind("127.0.0.1:0")?;
    let held = squatter.local_addr()?;
    let outcome = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            rpc_bind: Some(held),
            timeout: Some(Duration::from_secs(30)),
            ..SpawnOptions::default()
        },
    );
    drop(squatter);
    assert!(
        matches!(outcome, Err(Error::ChildExit { .. })),
        "rpc bind conflict must fail startup: {outcome:?}"
    );
    Ok(())
}
