//! Mempool and transaction E2E: broadcast, entry/ancestor/descendant views,
//! preview, raw-transaction codecs, prioritisation, and fee estimation.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::transaction::OutPoint;
use bitcoin_rs_e2e::helpers::{
    COINBASE_MATURITY, coinbase_at, funding_address, funding_output, mempool_txids,
    mine_bare_blocks, op_true_script, raw_spend_to, signed_spend, spend_anyone, submit_genesis,
    tx_hex,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

/// Mine `COINBASE_MATURITY + 1` blocks so the first coinbase is spendable,
/// then return the spendable funding outpoint.
fn mature_funding(node: &mut ProcessNode) -> Result<(OutPoint, bitcoin::TxOut)> {
    submit_genesis(node)?;
    let _ = mine_bare_blocks(node, COINBASE_MATURITY + 1)?;
    let coinbase = coinbase_at(node, 1)?;
    funding_output(node, &coinbase)
}

/// A broadcast enters the mempool with a complete entry view.
#[test]
fn broadcast_enters_mempool_with_entry() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;
    assert!(mempool_txids(&mut node)?.is_empty());

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    let returned = node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?;
    assert_eq!(returned, json!(txid));

    let ids = mempool_txids(&mut node)?;
    assert_eq!(ids, vec![txid.clone()]);

    let info = node.rpc("getmempoolinfo", &json!([]))?;
    assert_eq!(info.u64_field("size")?, 1);
    assert_eq!(info.u64_field("bytes")?, 82);

    let entry = node.rpc("getmempoolentry", &json!([txid]))?;
    // Like Core, the entry omits txid (it is the lookup key) and carries wtxid.
    assert_eq!(entry.str_field("wtxid")?, txid);
    assert_eq!(entry.u64_field("vsize")?, 82);
    assert_eq!(entry.u64_field("ancestorcount")?, 1);
    assert_eq!(entry.u64_field("descendantcount")?, 1);
    let base_fee = entry["fees"]["base"]
        .as_f64()
        .ok_or_else(|| Error::Assertion("fees.base missing".into()))?;
    assert!(
        (base_fee - 0.00001).abs() < 1e-9,
        "fee 1000 sats: {base_fee}"
    );

    let missing = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "getmempoolentry",
        "params": ["0000000000000000000000000000000000000000000000000000000000000000"]
    }))?;
    assert_eq!(missing["error"]["code"], json!(-5));
    node.stop()
}

/// Re-submitting an already-pooled transaction is idempotent here
/// (Core's `-27 txn-already-in-mempool` divergence is intentional).
#[test]
fn resubmit_is_idempotent() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;
    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    let hex = tx_hex(&spend);

    assert_eq!(node.rpc("sendrawtransaction", &json!([hex]))?, json!(txid));
    assert_eq!(
        node.rpc("sendrawtransaction", &json!([hex]))?,
        json!(txid),
        "second submit must be idempotent"
    );
    node.stop()
}

/// `testmempoolaccept` previews admission without mutating the pool.
#[test]
fn mempool_accept_preview() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    let rows = node.rpc("testmempoolaccept", &json!([[tx_hex(&spend)]]))?;
    let row = &rows[0];
    assert_eq!(row["allowed"], json!(true), "valid spend must pass: {row}");
    assert_eq!(row["txid"], json!(txid));
    assert_eq!(row["vsize"], json!(82));
    assert!(
        mempool_txids(&mut node)?.is_empty(),
        "preview must not pool"
    );

    // A spend of an unknown outpoint reports a frozen reject reason.
    let phantom = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1_000),
        script_pubkey: op_true_script(),
    };
    let bad = spend_anyone(
        OutPoint::new(bitcoin::Txid::from_byte_array([0xaa; 32]), 0),
        &phantom,
        100,
    );
    let rows = node.rpc("testmempoolaccept", &json!([[tx_hex(&bad)]]))?;
    assert_eq!(rows[0]["allowed"], json!(false));
    assert_eq!(rows[0]["reject-reason"], json!("missing-inputs"));

    // Malformed hex is a request error, not a reject row.
    let reply = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "testmempoolaccept",
        "params": [["deadbeef"]]
    }))?;
    assert_eq!(reply["error"]["code"], json!(-32602));
    node.stop()
}

/// Parent/child submissions populate `depends`/`spentby` and the
/// ancestors/descendants views.
#[test]
fn ancestors_and_descendants_views() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    // OP_TRUE outputs are non-standard for mempool admission, so the
    // parent pays the P2PKH funding address and the child signs for it.
    let parent = raw_spend_to(
        outpoint,
        &prevout,
        1_000,
        bitcoin::Sequence::MAX,
        &funding_address()?.script_pubkey(),
    );
    let parent_txid = parent.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&parent)]))?;

    let parent_out = bitcoin::TxOut {
        value: parent.output[0].value,
        script_pubkey: funding_address()?.script_pubkey(),
    };
    let child = signed_spend(
        OutPoint::new(parent.compute_txid(), 0),
        &parent_out,
        1_000,
        bitcoin::Sequence::MAX,
    )?;
    let child_txid = child.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&child)]))?;

    let ancestors = node.rpc("getmempoolancestors", &json!([child_txid]))?;
    assert_eq!(ancestors, json!([parent_txid]));
    let descendants = node.rpc("getmempooldescendants", &json!([parent_txid]))?;
    assert_eq!(descendants, json!([child_txid]));

    let parent_entry = node.rpc("getmempoolentry", &json!([parent_txid]))?;
    assert_eq!(parent_entry["spentby"], json!([child_txid]));
    let child_entry = node.rpc("getmempoolentry", &json!([child_txid]))?;
    assert_eq!(child_entry["depends"], json!([parent_txid]));
    assert_eq!(child_entry.u64_field("ancestorcount")?, 2);
    node.stop()
}

/// `getrawtransaction` serves mempool entries and (with a block hash)
/// confirmed transactions; without a block hash and no txindex it is -5.
#[test]
fn raw_transaction_lookup_rules() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    // A confirmed coinbase is only reachable via its block hash.
    let coinbase_txid = outpoint.txid.to_string();
    let not_found = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "getrawtransaction",
        "params": [coinbase_txid]
    }))?;
    assert_eq!(not_found["error"]["code"], json!(-5));

    let block_hash = node
        .rpc("getblockhash", &json!([1]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("getblockhash(1)".into()))?
        .to_owned();
    let via_block = node.rpc(
        "getrawtransaction",
        &json!([coinbase_txid, false, block_hash]),
    )?;
    assert!(
        via_block.as_str().is_some(),
        "raw hex via block: {via_block}"
    );

    // A mempool transaction resolves without a block hash.
    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?;
    let raw = node.rpc("getrawtransaction", &json!([txid]))?;
    assert_eq!(raw.as_str(), Some(tx_hex(&spend).as_str()));

    let verbose = node.rpc("getrawtransaction", &json!([txid, true]))?;
    assert!(verbose["confirmations"].is_null());
    assert_eq!(verbose["vin"][0]["txid"], json!(outpoint.txid.to_string()));
    node.stop()
}

/// `createrawtransaction` + `decoderawtransaction` round-trip.
#[test]
fn create_and_decode_raw_transaction() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    let created = node.rpc(
        "createrawtransaction",
        &json!([
            [{"txid": outpoint.txid.to_string(), "vout": outpoint.vout}],
            {funding_address()?.to_string(): 1.0}
        ]),
    )?;
    let hex = created
        .as_str()
        .ok_or_else(|| Error::Assertion("createrawtransaction not hex".into()))?;
    let decoded = node.rpc("decoderawtransaction", &json!([hex]))?;
    assert_eq!(decoded["vin"][0]["txid"], json!(outpoint.txid.to_string()));
    let out_value = decoded["vout"][0]["value"]
        .as_f64()
        .ok_or_else(|| Error::Assertion("vout value".into()))?;
    assert!((out_value - 1.0).abs() < 1e-9);
    let spk = &decoded["vout"][0]["scriptPubKey"];
    assert_eq!(spk["address"], json!(funding_address()?.to_string()));

    let raw: bitcoin::Transaction =
        deserialize_hex(hex).map_err(|e| Error::Assertion(format!("decode: {e}")))?;
    assert_eq!(
        raw.compute_txid().to_string(),
        decoded["txid"].as_str().unwrap()
    );

    let bad = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "decoderawtransaction", "params": ["00ff"]
    }))?;
    assert_eq!(bad["error"]["code"], json!(-32602));
    let _ = prevout;
    node.stop()
}

/// A signed P2PKH spend is admitted — the signature-checking path is
/// exercised, not just the anyone-can-spend one.
#[test]
fn signed_p2pkh_spend_accepted() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let address = funding_address()?.to_string();
    node.rpc(
        "generatetoaddress",
        &json!([COINBASE_MATURITY + 1, address]),
    )?;

    // Find the funding UTXO paid to our address at height 1.
    let coinbase = coinbase_at(&mut node, 1)?;
    let (outpoint, prevout) = funding_output(&mut node, &coinbase)?;
    assert_eq!(
        prevout.script_pubkey,
        funding_address()?.script_pubkey(),
        "coinbase must pay the funding address"
    );

    let spend = signed_spend(outpoint, &prevout, 1_000, bitcoin::Sequence::MAX)?;
    let txid = spend.compute_txid().to_string();
    assert_eq!(
        node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?,
        json!(txid)
    );
    node.stop()
}

/// `prioritisetransaction` overlays a fee delta that
/// `getprioritisedtransactions` reports.
#[test]
fn prioritise_and_list() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;
    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?;

    assert_eq!(
        node.rpc("prioritisetransaction", &json!([txid, 0, 5000]))?,
        json!(true)
    );
    let listed = node.rpc("getprioritisedtransactions", &json!([]))?;
    let entry = &listed[&txid];
    assert_eq!(entry["fee_delta"], json!(5000));
    assert_eq!(entry["in_mempool"], json!(true));

    // A non-zero dummy argument is Core's -8.
    let reply = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "prioritisetransaction",
        "params": [txid, 1, 5000]
    }))?;
    assert_eq!(reply["error"]["code"], json!(-8));
    node.stop()
}

/// With no confirmation history `estimatesmartfee` reports an `errors`
/// array and `estimaterawfee` an empty object; invalid targets are -8/-32602.
#[test]
fn fee_estimates_on_empty_history() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;

    let smart = node.rpc("estimatesmartfee", &json!([6]))?;
    assert!(
        smart
            .get("errors")
            .and_then(Value::as_array)
            .is_some_and(|e| !e.is_empty()),
        "no history must produce errors: {smart}"
    );
    let raw = node.rpc("estimaterawfee", &json!([3]))?;
    assert_eq!(raw, json!({}));

    let bad = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "estimatesmartfee", "params": [0]
    }))?;
    assert!(
        bad.get("error").is_some(),
        "conf_target 0 must be rejected: {bad}"
    );
    node.stop()
}

/// `generateblock` mines the listed mempool transactions and the pool
/// drains; the confirmed transaction gains a blockhash/confirmations.
#[test]
fn generateblock_confirms_mempool_tx() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (outpoint, prevout) = mature_funding(&mut node)?;

    let spend = spend_anyone(outpoint, &prevout, 1_000);
    let txid = spend.compute_txid().to_string();
    node.rpc("sendrawtransaction", &json!([tx_hex(&spend)]))?;

    let mined = node.rpc("generateblock", &json!(["raw(51)", [txid]]))?;
    let hash = mined
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Assertion("generateblock reply".into()))?
        .to_owned();
    assert!(mempool_txids(&mut node)?.is_empty(), "mined tx leaves pool");

    let block = node.rpc("getblock", &json!([hash, 2]))?;
    let txids: Vec<&str> = block["tx"]
        .as_array()
        .map(|txs| txs.iter().filter_map(|t| t["txid"].as_str()).collect())
        .unwrap_or_default();
    assert_eq!(txids.len(), 2);
    assert_eq!(txids[1], txid, "listed tx is tx[1] after the coinbase");

    // Without txindex a confirmed tx needs its block hash to be served.
    let confirmed = node.rpc("getrawtransaction", &json!([txid, true, hash]))?;
    assert_eq!(confirmed.u64_field("confirmations")?, 1);
    assert_eq!(confirmed.str_field("blockhash")?, hash);
    node.stop()
}

/// Bad-hex and missing-input broadcast failures carry distinct codes.
#[test]
fn broadcast_failure_codes() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let (_outpoint, _prevout) = mature_funding(&mut node)?;

    let bad_hex = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 1, "method": "sendrawtransaction", "params": ["deadbeef"]
    }))?;
    assert_eq!(bad_hex["error"]["code"], json!(-32602));

    let phantom = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(1_000),
        script_pubkey: op_true_script(),
    };
    let missing = spend_anyone(
        OutPoint::new(bitcoin::Txid::from_byte_array([0xaa; 32]), 0),
        &phantom,
        100,
    );
    let reply = node.rpc_raw(&json!({
        "jsonrpc": "2.0", "id": 2, "method": "sendrawtransaction",
        "params": [tx_hex(&missing)]
    }))?;
    assert_eq!(reply["error"]["code"], json!(-26));
    node.stop()
}
