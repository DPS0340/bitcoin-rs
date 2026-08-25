//! Esplora-compatible HTTP routes backed directly by node state.

use core::str::FromStr as _;

use bitcoin::hex::FromHex as _;
use bitcoin_rs_index::ScriptHash;
use sonic_rs::{JsonValueTrait as _, Value, json};

use crate::context::{Context, ScriptIndexRecord, TxQueryError};
use crate::handlers::Handler;
use crate::rest::Response;

/// Routes a read-only Esplora request from the dedicated public listener.
#[must_use]
pub fn route(handler: &Handler, path: &str) -> Response {
    let ctx = handler.context();
    let segments: Vec<_> = path.trim_matches('/').split('/').collect();
    match segments.as_slice() {
        ["blocks", "tip", "height"] => text(ctx.applied_height().to_string()),
        ["blocks", "tip", "hash"] => text(ctx.applied_hash().to_string_be()),
        ["tx", txid, "hex"] => core_value(handler, "getrawtransaction", json!([txid, false]), true),
        ["tx", txid] => core_value(handler, "getrawtransaction", json!([txid, true]), false),
        ["block", hash, "header"] => {
            core_value(handler, "getblockheader", json!([hash, false]), true)
        }
        ["block", hash] => core_value(handler, "getblock", json!([hash, 1]), false),
        ["block-height", height] => core_value(handler, "getblockhash", json!([height]), true),
        ["mempool"] => core_value(handler, "getmempoolinfo", json!([]), false),
        ["mempool", "txids"] => core_value(handler, "getrawmempool", json!([false]), false),
        ["fees", "recommended"] => recommended_fees(handler),
        ["scripthash", hash, "utxo"] => script_utxos(ctx, hash),
        ["scripthash", hash, "txs"] => script_history(ctx, hash),
        ["address", address, "utxo"] => address_utxos(ctx, address),
        ["address", address, "txs"] => address_history(ctx, address),
        _ => not_found(),
    }
}

/// Routes Esplora's raw-transaction broadcast endpoint.
#[must_use]
pub fn route_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    if path != "/tx" {
        return None;
    }
    let Ok(hex) = core::str::from_utf8(body) else {
        return Some(bad_request("transaction body must be UTF-8 hex"));
    };
    Some(core_value(
        handler,
        "sendrawtransaction",
        json!([hex.trim()]),
        true,
    ))
}

fn script_utxos(ctx: &Context, hash: &str) -> Response {
    let hash = match parse_scripthash(hash) {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let Some(index) = ctx.script_index.as_ref() else {
        return unavailable("script index is disabled");
    };
    match index.unspent_outputs(hash) {
        Ok(records) => json_response(records.into_iter().map(utxo_value).collect::<Vec<_>>()),
        Err(error) => query_error(error),
    }
}

fn script_history(ctx: &Context, hash: &str) -> Response {
    if !ctx.script_index_history {
        return unavailable("ScriptIndex=current does not retain history");
    }
    let hash = match parse_scripthash(hash) {
        Ok(hash) => hash,
        Err(response) => return response,
    };
    let Some(index) = ctx.script_index.as_ref() else {
        return unavailable("script index is disabled");
    };
    match index.history_snapshot(hash) {
        Ok(snapshot) => {
            let txids = snapshot
                .history
                .into_iter()
                .map(|record| record.txid.to_string())
                .collect::<Vec<_>>();
            json_response(txids)
        }
        Err(error) => query_error(error),
    }
}

fn address_utxos(ctx: &Context, address: &str) -> Response {
    address_script_hash(ctx, address)
        .map_or_else(|response| response, |hash| script_utxos_for(ctx, hash))
}

fn address_history(ctx: &Context, address: &str) -> Response {
    address_script_hash(ctx, address)
        .map_or_else(|response| response, |hash| script_history_for(ctx, hash))
}

fn script_utxos_for(ctx: &Context, hash: ScriptHash) -> Response {
    let Some(index) = ctx.script_index.as_ref() else {
        return unavailable("script index is disabled");
    };
    match index.unspent_outputs(hash) {
        Ok(records) => json_response(records.into_iter().map(utxo_value).collect::<Vec<_>>()),
        Err(error) => query_error(error),
    }
}

fn script_history_for(ctx: &Context, hash: ScriptHash) -> Response {
    if !ctx.script_index_history {
        return unavailable("ScriptIndex=current does not retain history");
    }
    let Some(index) = ctx.script_index.as_ref() else {
        return unavailable("script index is disabled");
    };
    match index.history_snapshot(hash) {
        Ok(snapshot) => json_response(
            snapshot
                .history
                .into_iter()
                .map(|record| record.txid.to_string())
                .collect::<Vec<_>>(),
        ),
        Err(error) => query_error(error),
    }
}

fn address_script_hash(ctx: &Context, address: &str) -> Result<ScriptHash, Response> {
    let network = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let unchecked =
        bitcoin::Address::from_str(address).map_err(|_| bad_request("invalid address"))?;
    let address = unchecked
        .require_network(network)
        .map_err(|_| bad_request("address network does not match node"))?;
    Ok(ScriptHash::from_script_bytes(
        address.script_pubkey().as_bytes(),
    ))
}

fn parse_scripthash(text: &str) -> Result<ScriptHash, Response> {
    let bytes = <[u8; 32]>::from_hex(text)
        .map_err(|_| bad_request("scripthash must be 64 hex characters"))?;
    Ok(ScriptHash::from_byte_array(bytes))
}

fn utxo_value(record: ScriptIndexRecord) -> Value {
    json!({
        "txid": record.txid.to_string(),
        "vout": record.vout,
        "value": record.value,
        "status": { "confirmed": true, "block_height": record.height }
    })
}

fn recommended_fees(handler: &Handler) -> Response {
    let estimate = |target| {
        handler
            .dispatch("estimatesmartfee", &json!([target]))
            .ok()
            .and_then(|value| value.get("feerate").and_then(Value::as_f64))
            .map(|btc_per_kvb| (btc_per_kvb * 100_000_000.0 / 1_000.0).ceil() as u64)
            .unwrap_or(1)
    };
    json_response(json!({
        "fastestFee": estimate(1), "halfHourFee": estimate(3), "hourFee": estimate(6),
        "economyFee": estimate(12), "minimumFee": 1
    }))
}

fn core_value(handler: &Handler, method: &str, params: Value, plain: bool) -> Response {
    match handler.dispatch(method, &params) {
        Ok(value) if plain => match value.as_str() {
            Some(body) => text(body.to_owned()),
            None => json_response(value),
        },
        Ok(value) => json_response(value),
        Err(error) => match error {
            crate::RpcError::NotFound(_) => not_found(),
            crate::RpcError::InvalidParams(_) | crate::RpcError::InvalidType(_) => {
                bad_request(&error.to_string())
            }
            _ => unavailable(&error.to_string()),
        },
    }
}

fn query_error(error: TxQueryError) -> Response {
    match error {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => unavailable(&error.to_string()),
        TxQueryError::Storage(_) => internal(&error.to_string()),
    }
}

fn json_response(value: impl serde::Serialize) -> Response {
    match sonic_rs::to_string(&value) {
        Ok(body) => Response {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: body.into_bytes(),
        },
        Err(_) => internal("failed to serialize response"),
    }
}

fn text(body: String) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type: "text/plain",
        body: body.into_bytes(),
    }
}
fn bad_request(message: &str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}
fn not_found() -> Response {
    Response {
        status: 404,
        reason: "Not Found",
        content_type: "text/plain",
        body: b"not found".to_vec(),
    }
}
fn unavailable(message: &str) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}
fn internal(message: &str) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: message.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn tip_routes_are_available_without_a_script_index() {
        let handler = Handler::new(Arc::new(Context::new()));
        let height = route(&handler, "/blocks/tip/height");
        assert_eq!(height.status, 200);
        assert_eq!(height.body, b"0");
        let utxo = route(
            &handler,
            "/scripthash/0000000000000000000000000000000000000000000000000000000000000000/utxo",
        );
        assert_eq!(utxo.status, 503);
    }
}
