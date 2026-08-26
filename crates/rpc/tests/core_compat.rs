//! Bitcoin Core schema compatibility tests for the RPC crate.
//!
//! Handlers for supported JSON-RPC response objects serialize the published
//! `corepc-types` v31 structs (Bitcoin Core v31), so the compatibility
//! contract is checked by deserializing each object response back into the
//! same [`corepc_types::v31`] struct: a response that drops or mistypes a
//! Core-required field fails to deserialize. Required-field access in the
//! assertions below is compile-checked against those structs.
//!
//! Primitive results (scalars, bare arrays, JSON null) keep direct shape
//! assertions and use a v31 result wrapper only where corepc publishes one.
//! Documented exceptions where no v31 type can express the response are noted
//! inline at each assertion.
extern crate alloc;

use alloc::sync::Arc;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::context::Context;
use corepc_types::v31::{
    EstimateSmartFee, GetBestBlockHash, GetBlockCount, GetBlockTemplate, GetBlockchainInfo,
    GetConnectionCount, GetDifficulty, GetMemoryInfoStats, GetMempoolInfo, GetMiningInfo,
    GetNetTotals, GetNetworkInfo, GetPeerInfo, GetRawMempool, GetRawMempoolSequence,
    GetRawTransactionVerbose, GetRpcInfo, ListBanned, TestMempoolAccept, ValidateAddress,
};
use serde::de::DeserializeOwned;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

/// Deserializes a dispatched sonic-rs result into a `corepc_types::v31`
/// response struct by round-tripping through `serde_json`, without touching
/// handler code. Deserialization — not a hand-maintained key list — is the
/// schema check, so any missing or mistyped Core-required field fails here
/// with the method named.
fn core_result<T: DeserializeOwned>(
    handler: &Handler,
    method: &str,
    params: &sonic_rs::Value,
) -> Result<T, Box<dyn std::error::Error>> {
    let result = handler.dispatch(method, params)?;
    let text = sonic_rs::to_string(&result)?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    serde_json::from_value(value).map_err(|error| format!("{method}: {error}").into())
}

/// Fresh mainnet context whose published and applied tips both point at one
/// height-42 block, so scalar and object responses observe stable inputs.
fn handler_at_height_42() -> (Handler, String) {
    let ctx = Arc::new(Context::new());
    let tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        chainwork: ChainWork::ZERO,
        hash: Hash256::from_le_bytes(&[42_u8; 32]),
    };
    ctx.set_chain_tip(tip.clone());
    ctx.set_applied_tip(tip);
    let best_block_hash = Hash256::from_le_bytes(&[42_u8; 32]).to_string_be();
    (Handler::new(ctx), best_block_hash)
}

/// Minimal decodable transaction; `decoderawtransaction` and
/// `testmempoolaccept` only parse it, so no chain state is required.
fn raw_tx_hex() -> String {
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    };
    serialize_hex(&tx)
}

#[test]
fn chain_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, best_block_hash) = handler_at_height_42();

    let info: GetBlockchainInfo = core_result(&handler, "getblockchaininfo", &json!([]))?;
    assert_eq!(info.chain, "main");
    assert_eq!(info.blocks, 42);
    assert_eq!(info.headers, 42);
    assert_eq!(info.best_block_hash, best_block_hash);
    assert!(!info.pruned);

    let count: GetBlockCount = core_result(&handler, "getblockcount", &json!([]))?;
    assert_eq!(count.0, 42);

    let best: GetBestBlockHash = core_result(&handler, "getbestblockhash", &json!([]))?;
    assert_eq!(best.0, best_block_hash);

    let difficulty: GetDifficulty = core_result(&handler, "getdifficulty", &json!([]))?;
    assert!(difficulty.0.is_finite());
    Ok(())
}

#[test]
fn mempool_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, _best_block_hash) = handler_at_height_42();

    let info: GetMempoolInfo = core_result(&handler, "getmempoolinfo", &json!([]))?;
    assert!(info.loaded);
    assert_eq!(info.size, 0);
    assert_eq!(info.bytes, 0);

    let txids: GetRawMempool = core_result(&handler, "getrawmempool", &json!([]))?;
    assert!(txids.0.is_empty());

    // mempool_sequence lives on this response, not on getmempoolinfo.
    let sequenced: GetRawMempoolSequence =
        core_result(&handler, "getrawmempool", &json!([false, true]))?;
    assert!(sequenced.txids.is_empty());
    Ok(())
}

#[test]
fn network_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, _best_block_hash) = handler_at_height_42();

    let info: GetNetworkInfo = core_result(&handler, "getnetworkinfo", &json!([]))?;
    assert_eq!(info.connections, 0);
    assert_eq!(info.connections_in + info.connections_out, info.connections);
    assert!(!info.networks.is_empty());

    let totals: GetNetTotals = core_result(&handler, "getnettotals", &json!([]))?;
    assert_eq!(totals.total_bytes_received, 0);

    let count: GetConnectionCount = core_result(&handler, "getconnectioncount", &json!([]))?;
    assert_eq!(count.0, 0);

    let peers: GetPeerInfo = core_result(&handler, "getpeerinfo", &json!([]))?;
    assert!(peers.0.is_empty());

    let banned: ListBanned = core_result(&handler, "listbanned", &json!([]))?;
    assert!(banned.0.is_empty());

    // Core's `ping` produces no result object: JSON null.
    assert!(handler.dispatch("ping", &json!([]))?.is_null());
    Ok(())
}

#[test]
fn mining_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, best_block_hash) = handler_at_height_42();

    let info: GetMiningInfo = core_result(&handler, "getmininginfo", &json!([]))?;
    assert_eq!(info.blocks, 42);
    assert_eq!(info.chain, "main");
    assert_eq!(info.next.height, info.blocks + 1);

    let template: GetBlockTemplate = core_result(&handler, "getblocktemplate", &json!([{}]))?;
    assert_eq!(template.height, 43);
    assert_eq!(template.previous_block_hash, best_block_hash);

    // prioritisetransaction returns a bare boolean; corepc publishes no
    // result wrapper for it.
    let raw_txid = "a".repeat(64);
    let prioritised =
        handler.dispatch("prioritisetransaction", &json!([raw_txid.as_str(), 0, 0]))?;
    assert!(prioritised.is_boolean());
    Ok(())
}

#[test]
fn transaction_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, _best_block_hash) = handler_at_height_42();
    let raw = raw_tx_hex();

    // Core's gettxout returns JSON null for an unknown outpoint; there is no
    // wrapper type for that reduced result.
    let unknown_txid = "0".repeat(64);
    let spent = handler.dispatch("gettxout", &json!([unknown_txid.as_str(), 0]))?;
    assert!(spent.is_null());

    let decoded: GetRawTransactionVerbose =
        core_result(&handler, "decoderawtransaction", &json!([raw.as_str()]))?;
    assert_eq!(decoded.version, 2);
    assert_eq!(decoded.inputs.len(), 1);
    assert_eq!(decoded.outputs.len(), 1);

    let acceptance: TestMempoolAccept =
        core_result(&handler, "testmempoolaccept", &json!([[raw.as_str()]]))?;
    let [row] = acceptance.0.as_slice() else {
        panic!("testmempoolaccept must return one row per submitted raw tx");
    };
    assert!(row.allowed);
    assert_eq!(row.txid, decoded.txid);
    let fees = row
        .fees
        .as_ref()
        .ok_or("allowed result must include fees")?;
    assert_eq!(fees.effective_fee_rate, Some(0.0));
    assert_eq!(fees.effective_includes, vec![row.wtxid.clone()]);

    let rejected: TestMempoolAccept =
        core_result(&handler, "testmempoolaccept", &json!([["deadbeef"]]))?;
    let [row] = rejected.0.as_slice() else {
        panic!("malformed testmempoolaccept must return one row");
    };
    assert!(!row.allowed);
    assert!(row.vsize.is_none());
    assert!(row.fees.is_none());
    Ok(())
}

#[test]
fn utility_results_match_core_v31_types() -> Result<(), Box<dyn std::error::Error>> {
    let (handler, _best_block_hash) = handler_at_height_42();

    let rpc_info: GetRpcInfo = core_result(&handler, "getrpcinfo", &json!([]))?;
    assert!(rpc_info.active_commands.is_empty());

    let memory: GetMemoryInfoStats = core_result(&handler, "getmemoryinfo", &json!([]))?;
    let locked = memory
        .0
        .get("locked")
        .ok_or("getmemoryinfo must report the locked pool")?;
    assert!(locked.used <= locked.total);

    let estimate: EstimateSmartFee = core_result(&handler, "estimatesmartfee", &json!([6]))?;
    assert_eq!(estimate.blocks, 6);
    assert!(estimate.fee_rate.is_some());

    let address = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    let validated: ValidateAddress = core_result(&handler, "validateaddress", &json!([address]))?;
    assert!(validated.is_valid);
    assert_eq!(validated.address, address);

    // Exception: Core returns only {"isvalid": false} for an invalid address,
    // and the v31 ValidateAddress struct cannot express that reduced shape
    // (address, scriptPubKey, isscript and iswitness are not optional).
    let invalid = handler.dispatch("validateaddress", &json!(["not-a-bitcoin-address"]))?;
    assert_eq!(
        invalid.get("isvalid").and_then(|value| value.as_bool()),
        Some(false)
    );

    // uptime returns a bare numeric; corepc documents it as "returns numeric"
    // with no result wrapper.
    assert!(handler.dispatch("uptime", &json!([]))?.is_u64());

    // getzmqnotifications returns a bare array of {type, address, hwm}
    // objects; corepc only models the per-notification struct, not the array.
    let notifications = handler.dispatch("getzmqnotifications", &json!([]))?;
    assert!(
        notifications
            .as_array()
            .is_some_and(|entries| entries.is_empty())
    );
    Ok(())
}
