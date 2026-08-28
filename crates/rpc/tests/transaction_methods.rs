//! Behavioral tests for transaction RPC methods: real mempool admission,
//! mempool-aware gettxout, createrawtransaction, and testmempoolaccept
//! evaluation.

extern crate alloc;

use alloc::sync::Arc;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::{Handler, RpcError};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

/// A standard P2WPKH script paid to a known key.
const P2WPKH_SCRIPT_HEX: &str = "00141111111111111111111111111111111111111111";

fn make_tx(prevout: OutPoint, output_value: u64, script: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(output_value),
            script_pubkey: script,
        }],
    }
}

fn fund_utxo(ctx: &Context, txid_byte: u8, value: u64, script: ScriptBuf) -> OutPoint {
    let txid = Hash256::from_le_bytes(&[txid_byte; 32]);
    let outpoint = bitcoin_rs_primitives::OutPoint::new(txid, 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script,
        },
        false,
        1,
    ));
    ctx.utxo
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xaa; 32]))
        .expect("commit_block");
    OutPoint {
        txid: Txid::from_byte_array([txid_byte; 32]),
        vout: 0,
    }
}

// ---------------------------------------------------------------------------
// sendrawtransaction — real mempool admission
// ---------------------------------------------------------------------------

#[test]
fn sendrawtransaction_admits_standard_tx_to_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x42, 10_000, script.clone());
    // Spend 10 000 sats, send 9 000 → fee 1 000 sats.
    let tx = make_tx(prevout, 9_000, script);
    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    let returned_txid = result.as_str().ok_or("expected txid string")?;
    assert_eq!(returned_txid, tx.compute_txid().to_string());

    // The tx must be in the mempool.
    assert!(
        ctx.mempool.read().contains_txid(&tx.compute_txid()),
        "tx was not admitted to mempool"
    );
    Ok(())
}

#[test]
fn sendrawtransaction_rejects_missing_inputs() -> Result<(), RpcError> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX).expect("script hex");
    // Reference an outpoint that does not exist anywhere.
    let prevout = OutPoint {
        txid: Txid::from_byte_array([0x99; 32]),
        vout: 0,
    };
    let tx = make_tx(prevout, 9_000, script);
    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    let err = handler
        .dispatch("sendrawtransaction", &json!([raw.as_str()]))
        .expect_err("missing-inputs tx should be rejected");
    assert_eq!(err.code(), RpcError::INTERNAL_ERROR);
    Ok(())
}

#[test]
fn sendrawtransaction_idempotent_for_already_in_mempool() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x43, 10_000, script.clone());
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.compute_txid();

    // Pre-insert into mempool.
    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1);
    ctx.mempool.write().insert_entry(entry)?;

    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    // Second submission should succeed without error.
    let result = handler.dispatch("sendrawtransaction", &json!([raw.as_str()]))?;
    assert_eq!(result.as_str(), Some(txid.to_string().as_str()));
    Ok(())
}

// ---------------------------------------------------------------------------
// testmempoolaccept — real evaluation
// ---------------------------------------------------------------------------

#[test]
fn testmempoolaccept_reports_allowed_for_valid_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x44, 10_000, script.clone());
    let tx = make_tx(prevout, 9_000, script);
    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(true));
    assert!(
        rows[0].get("reject-reason").is_none(),
        "no reject-reason for allowed tx"
    );
    Ok(())
}

#[test]
fn testmempoolaccept_reports_reject_for_already_in_mempool()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let prevout = fund_utxo(&ctx, 0x45, 10_000, script.clone());
    let tx = make_tx(prevout, 9_000, script);
    let txid = tx.compute_txid();

    let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 1);
    ctx.mempool.write().insert_entry(entry)?;

    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
    let reason = rows[0]
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reason.contains("already-in-mempool"),
        "reject-reason should mention already-in-mempool: {reason}"
    );
    // The txid must still be reported correctly.
    assert_eq!(
        rows[0].get("txid").as_str(),
        Some(txid.to_string().as_str())
    );
    Ok(())
}

#[test]
fn testmempoolaccept_reports_reject_for_missing_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX).expect("script hex");
    let prevout = OutPoint {
        txid: Txid::from_byte_array([0x77; 32]),
        vout: 0,
    };
    let tx = make_tx(prevout, 9_000, script);
    let raw = serialize_hex(&tx);
    let handler = Handler::new(Arc::clone(&ctx));

    let result = handler.dispatch("testmempoolaccept", &json!([[raw.as_str()]]))?;
    let rows = result.as_array().ok_or("expected array")?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get("allowed").as_bool(), Some(false));
    let reason = rows[0]
        .get("reject-reason")
        .and_then(JsonValueTrait::as_str)
        .ok_or("expected reject-reason")?;
    assert!(
        reason.contains("missing-inputs"),
        "reject-reason should mention missing-inputs: {reason}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// gettxout — mempool awareness
// ---------------------------------------------------------------------------

#[test]
fn gettxout_returns_unconfirmed_output_from_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xaa; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(7_500),
            script_pubkey: script,
        }],
    };
    let txid = tx.compute_txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1);
    ctx.mempool.write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64]))?;

    // Should return the output with 0 confirmations (unconfirmed).
    assert!(!result.is_null(), "expected non-null for mempool output");
    assert_eq!(result.get("confirmations").as_u64(), Some(0));
    assert_eq!(result.get("coinbase").as_bool(), Some(false));
    Ok(())
}

#[test]
fn gettxout_include_mempool_false_skips_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;
    let tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([0xbb; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(7_500),
            script_pubkey: script,
        }],
    };
    let txid = tx.compute_txid();
    let entry = MempoolEntry::new(Arc::new(tx), 100, 500, 1, 1);
    ctx.mempool.write().insert_entry(entry)?;

    let handler = Handler::new(Arc::clone(&ctx));
    // include_mempool=false → skip mempool, output not in UTXO → null.
    let result = handler.dispatch("gettxout", &json!([txid.to_string(), 0_u64, false]))?;
    assert!(result.is_null(), "expected null when mempool is excluded");
    Ok(())
}

#[test]
fn gettxout_returns_null_for_outpoint_spent_in_mempool() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let script = ScriptBuf::from_hex(P2WPKH_SCRIPT_HEX)?;

    // Fund a UTXO.
    let prevout = fund_utxo(&ctx, 0x55, 10_000, script.clone());

    // Create a spending tx that spends the UTXO but is only in mempool.
    let spending_tx = make_tx(prevout, 9_000, script);
    let entry = MempoolEntry::new(Arc::new(spending_tx), 100, 1_000, 1, 1);
    ctx.mempool.write().insert_entry(entry)?;

    // The original outpoint is now spent in mempool.
    let handler = Handler::new(Arc::clone(&ctx));
    let result = handler.dispatch("gettxout", &json!([prevout.txid.to_string(), 0_u64]))?;
    assert!(
        result.is_null(),
        "expected null for outpoint spent in mempool"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// createrawtransaction — requires parent to register the dispatch arm
// ---------------------------------------------------------------------------

#[test]
fn createrawtransaction_builds_valid_hex_tx() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let handler = Handler::new(Arc::clone(&ctx));

    let inputs = json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000001",
        "vout": 0
    }]);
    // Context::new() defaults to Mainnet, so use a valid mainnet address.
    let outputs = json!({
        "1BoatSLRHtKNngkdXEeobR76b53LETtpyT": 0.001
    });

    let result = handler.dispatch("createrawtransaction", &json!([inputs, outputs]))?;

    let hex = result
        .as_str()
        .ok_or("createrawtransaction should return a hex string")?;
    let tx: Transaction = deserialize_hex(hex)?;
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.input[0].previous_output.txid.to_string(),
        "0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(tx.input[0].previous_output.vout, 0);
    Ok(())
}

#[test]
fn createrawtransaction_creates_op_return_data_output() -> Result<(), Box<dyn std::error::Error>> {
    // Use a regtest context so the address network matches.
    let mut ctx = Context::new();
    ctx.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));

    let inputs = json!([{
        "txid": "0000000000000000000000000000000000000000000000000000000000000002",
        "vout": 1
    }]);
    let outputs = json!({
        "data": "48656c6c6f"
    });

    let result = handler.dispatch(
        "createrawtransaction",
        &json!([inputs, outputs, 0_u64, true]),
    )?;

    let hex = result
        .as_str()
        .ok_or("createrawtransaction should return a hex string")?;
    let tx: Transaction = deserialize_hex(hex)?;
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 1);
    assert!(tx.output[0].script_pubkey.is_op_return());
    assert_eq!(tx.output[0].value, Amount::ZERO);
    // replaceable=true → sequence < 0xFFFF_FFFE
    assert!(tx.input[0].sequence.to_consensus_u32() < 0xFFFF_FFFE);
    Ok(())
}

#[test]
fn createrawtransaction_rejects_duplicate_input() -> Result<(), RpcError> {
    let mut ctx = Context::new();
    ctx.chain_network = bitcoin_rs_primitives::Network::Regtest;
    let handler = Handler::new(Arc::new(ctx));

    let inputs = json!([
        {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0},
        {"txid": "0000000000000000000000000000000000000000000000000000000000000003", "vout": 0}
    ]);
    let outputs = json!({"data": "00"});

    let err = handler
        .dispatch("createrawtransaction", &json!([inputs, outputs]))
        .expect_err("duplicate input should be rejected");
    assert_eq!(err.code(), RpcError::INVALID_PARAMS);
    Ok(())
}
