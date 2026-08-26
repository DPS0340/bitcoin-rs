//! Shared transaction-to-JSON rendering for handlers.

use bitcoin::Transaction;
use bitcoin::consensus::encode::serialize;
use bitcoin::hex::DisplayHex as _;
use corepc_types::ScriptSig;
use corepc_types::v31::{
    GetRawTransactionVerbose, RawTransactionInput, RawTransactionOutput, ScriptPubKey,
};
use sonic_rs::Value;

use crate::error::RpcError;
use crate::handlers::corepc_to_sonic;

pub(crate) fn tx_to_value(tx: &Transaction) -> Result<Value, RpcError> {
    let raw = serialize(tx);
    let inputs = tx
        .input
        .iter()
        .map(|input| RawTransactionInput {
            coinbase: None,
            txid: Some(input.previous_output.txid.to_string()),
            vout: Some(input.previous_output.vout),
            script_sig: Some(ScriptSig {
                asm: String::new(),
                hex: input.script_sig.as_bytes().to_lower_hex_string(),
            }),
            txin_witness: Some(
                input
                    .witness
                    .iter()
                    .map(bitcoin::hex::DisplayHex::to_lower_hex_string)
                    .collect(),
            ),
            sequence: input.sequence.to_consensus_u32(),
        })
        .collect::<Vec<_>>();
    let outputs = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            Ok(RawTransactionOutput {
                value: btc_value(output.value.to_sat()),
                index: usize_to_u64(index)?,
                script_pubkey: ScriptPubKey {
                    asm: String::new(),
                    descriptor: Some("raw()".to_owned()),
                    hex: output.script_pubkey.as_bytes().to_lower_hex_string(),
                    required_signatures: None,
                    type_: "nonstandard".to_owned(),
                    address: None,
                    addresses: None,
                },
            })
        })
        .collect::<Result<Vec<_>, RpcError>>()?;
    let verbose = GetRawTransactionVerbose {
        in_active_chain: None,
        hex: raw.to_lower_hex_string(),
        txid: tx.compute_txid().to_string(),
        hash: tx.compute_wtxid().to_string(),
        size: usize_to_u64(raw.len())?,
        vsize: usize_to_u64(tx.vsize())?,
        weight: tx.weight().to_wu(),
        version: tx.version.0,
        lock_time: tx.lock_time.to_consensus_u32(),
        inputs,
        outputs,
        block_hash: None,
        confirmations: None,
        transaction_time: None,
        block_time: None,
    };
    corepc_to_sonic(&verbose)
}

pub(crate) fn usize_to_u64(value: usize) -> Result<u64, RpcError> {
    u64::try_from(value).map_err(|_| RpcError::Internal("usize does not fit u64".to_owned()))
}

pub(crate) fn btc_value(sats: u64) -> f64 {
    bitcoin::Amount::from_sat(sats).to_btc()
}
