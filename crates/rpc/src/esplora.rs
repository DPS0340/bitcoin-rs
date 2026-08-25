//! Esplora HTTP projections over confirmed indexes and the live mempool.
#![allow(
    clippy::as_conversions,
    clippy::cast_precision_loss,
    clippy::map_unwrap_or,
    clippy::needless_borrow,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::semicolon_if_nothing_returned,
    clippy::significant_drop_in_scrutinee,
    clippy::unnecessary_semicolon
)]

use core::ops::Bound;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{Block, OutPoint, Transaction, TxOut, Txid};
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_mempool::ScriptHash as MempoolScriptHash;
use bitcoin_rs_primitives::Hash256;
use serde_json::{Value, json};
use sonic_rs::{JsonValueTrait as _, json as sonic_json};

use crate::context::{Context, ScriptHistoryRecord, ScriptIndexRecord, TxQueryError};
use crate::handlers::Handler;
use crate::rest::Response;

const CHAIN_PAGE: usize = 25;
const MEMPOOL_PAGE: usize = 50;

#[derive(Clone, Copy)]
struct Status {
    height: u32,
    hash: Hash256,
    time: u32,
}

/// Routes a read-only Esplora request from the node HTTP listener.
#[must_use]
pub fn route(handler: &Handler, path: &str) -> Response {
    let ctx = handler.context();
    let parts: Vec<_> = path.trim_matches('/').split('/').collect();
    match parts.as_slice() {
        ["blocks", "tip", "height"] => text(ctx.applied_height().to_string()),
        ["blocks", "tip", "hash"] => text(ctx.applied_hash().to_string_be()),
        ["tx", id, "hex"] => tx_hex(&ctx, id),
        ["tx", id, "raw"] => tx_raw(&ctx, id),
        ["tx", id, "status"] => tx_status(&ctx, id),
        ["tx", id] => tx(&ctx, id),
        ["block", hash, "header"] => block_header(&ctx, hash),
        ["block", hash, "txs"] => block_txs(&ctx, hash, 0),
        ["block", hash, "txs", start] => match start.parse::<usize>() {
            Ok(n) if n % CHAIN_PAGE == 0 => block_txs(&ctx, hash, n),
            _ => bad("transaction start index must be a multiple of 25"),
        },
        ["block", hash, "txids"] => block_txids(&ctx, hash),
        ["block", hash] => block(&ctx, hash),
        ["block-height", height] => height
            .parse::<u32>()
            .ok()
            .and_then(|h| ctx.block_hash_at_height(h))
            .map_or_else(not_found, |h| text(h.to_string_be())),
        ["mempool"] => mempool(&ctx),
        ["mempool", "txids"] => json_response(
            ctx.mempool
                .read()
                .iter_txids()
                .into_iter()
                .map(|id| id.to_string())
                .collect::<Vec<_>>(),
        ),
        ["mempool", "recent"] => mempool_recent(&ctx),
        ["fee-estimates"] => fee_estimates(handler),
        ["scripthash", hash] => summary(&ctx, hash, None),
        ["address", address] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| summary_for(&ctx, h, Some(address)))
        }
        ["scripthash", hash, "utxo"] => parse_script(hash).map_or_else(|r| r, |h| utxos(&ctx, h)),
        ["address", address, "utxo"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| utxos(&ctx, h))
        }
        ["scripthash", hash, "txs"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, None, true))
        }
        ["address", address, "txs"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, None, true))
        }
        ["scripthash", hash, "txs", "mempool"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, Some(""), true))
        }
        ["address", address, "txs", "mempool"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, Some(""), true))
        }
        ["scripthash", hash, "txs", "chain"] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, None, false))
        }
        ["address", address, "txs", "chain"] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, None, false))
        }
        ["scripthash", hash, "txs", "chain", last] => {
            parse_script(hash).map_or_else(|r| r, |h| history(&ctx, h, Some(last), false))
        }
        ["address", address, "txs", "chain", last] => {
            address_hash(&ctx, address).map_or_else(|r| r, |h| history(&ctx, h, Some(last), false))
        }
        _ => not_found(),
    }
}

/// Routes Esplora raw-transaction broadcast.
#[must_use]
pub fn route_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    if path != "/tx" {
        return None;
    }
    let Ok(hex) = core::str::from_utf8(body) else {
        return Some(bad("transaction body must be UTF-8 hex"));
    };
    Some(
        match handler.dispatch("sendrawtransaction", &sonic_json!([hex.trim()])) {
            Ok(value) => match value.as_str() {
                Some(id) => text(id.to_owned()),
                None => json_response(value),
            },
            Err(error) => dispatch_error(error),
        },
    )
}

fn tx(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(
        |r| r,
        |(tx, status)| json_response(tx_value(ctx, &tx, status)),
    )
}
fn tx_hex(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(|r| r, |(tx, _)| text(serialize(&tx).to_lower_hex_string()))
}
fn tx_raw(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(
        |r| r,
        |(tx, _)| Response {
            status: 200,
            reason: "OK",
            content_type: "application/octet-stream",
            body: serialize(&tx),
        },
    )
}
fn tx_status(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(|r| r, |(_, status)| json_response(status_value(status)))
}

fn lookup(ctx: &Context, id: &str) -> Result<(Transaction, Option<Status>), Response> {
    let id = Txid::from_str(id).map_err(|_| bad("txid must be 64 hex characters"))?;
    if let Some(tx) = ctx.mempool.read().transaction_by_txid(&id) {
        return Ok(((*tx).clone(), None));
    }
    let index = ctx.tx_index.as_ref().ok_or_else(not_found)?;
    let tx = index
        .transaction(&id)
        .map_err(query_error)?
        .ok_or_else(not_found)?;
    let status = index
        .transaction_height(&id)
        .map_err(query_error)?
        .and_then(|h| status(ctx, h));
    Ok((tx, status))
}

fn block(ctx: &Context, text_hash: &str) -> Response {
    let Ok(hash) = Hash256::from_str(text_hash) else {
        return bad("block hash must be 64 hex characters");
    };
    let Some(record) = ctx.block_by_hash(hash) else {
        return not_found();
    };
    let Some(header) = record
        .header_bytes()
        .and_then(|b| deserialize::<bitcoin::block::Header>(b).ok())
    else {
        return unavailable("block header unavailable");
    };
    let Some(bytes) = ctx.block_body_bytes(&record) else {
        return unavailable("block body unavailable");
    };
    let Ok(decoded) = deserialize::<Block>(&bytes) else {
        return internal("stored block body is corrupt");
    };
    json_response(
        json!({"id":record.hash.to_string_be(),"height":record.height,"version":header.version.to_consensus(),"timestamp":header.time,"mediantime":ctx.median_time_past_for_hash(record.hash).unwrap_or(0),"bits":header.bits.to_consensus(),"nonce":header.nonce,"difficulty":ctx.difficulty_for_bits(header.bits),"merkle_root":header.merkle_root.to_string(),"tx_count":decoded.txdata.len(),"size":bytes.len(),"weight":decoded.weight().to_wu(),"previousblockhash":header.prev_blockhash.to_string()}),
    )
}
fn block_header(ctx: &Context, h: &str) -> Response {
    let Ok(hash) = Hash256::from_str(h) else {
        return bad("block hash must be 64 hex characters");
    };
    ctx.block_by_hash(hash)
        .and_then(|r| r.header_bytes().map(|b| text(b.to_lower_hex_string())))
        .unwrap_or_else(not_found)
}
fn block_txs(ctx: &Context, h: &str, start: usize) -> Response {
    let Some((record, block)) = decode_block(ctx, h) else {
        return not_found();
    };
    let state = status(ctx, record.height);
    json_response(
        block
            .txdata
            .iter()
            .skip(start)
            .take(CHAIN_PAGE)
            .map(|tx| tx_value(ctx, tx, state))
            .collect::<Vec<_>>(),
    )
}
fn block_txids(ctx: &Context, h: &str) -> Response {
    let Some((_, block)) = decode_block(ctx, h) else {
        return not_found();
    };
    json_response(
        block
            .txdata
            .iter()
            .map(|tx| tx.compute_txid().to_string())
            .collect::<Vec<_>>(),
    )
}
fn decode_block(ctx: &Context, h: &str) -> Option<(crate::context::BlockRecord, Block)> {
    let hash = Hash256::from_str(h).ok()?;
    let r = ctx.block_by_hash(hash)?;
    Some((r.clone(), deserialize(&ctx.block_body_bytes(&r)?).ok()?))
}

fn mempool(ctx: &Context) -> Response {
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let mut bins = std::collections::BTreeMap::new();
    for (_, entry) in &pool.entries {
        *bins.entry(entry.fee_rate).or_insert(0_u64) += u64::from(entry.vsize);
    }
    json_response(
        json!({"count":stats.txs,"vsize":stats.bytes,"total_fee":stats.total_fee,"fee_histogram":bins.into_iter().rev().map(|(r,s)|json!([r as f64/1000.0,s])).collect::<Vec<_>>() }),
    )
}
fn mempool_recent(ctx: &Context) -> Response {
    let pool = ctx.mempool.read();
    let mut entries = pool.entries.iter().map(|(_, e)| e).collect::<Vec<_>>();
    entries.sort_by_key(|e| core::cmp::Reverse(e.time));
    json_response(entries.into_iter().take(10).map(|e|json!({"txid":e.txid.to_string(),"fee":e.fee,"vsize":e.vsize,"value":e.tx.output.iter().fold(0_u64,|n,o|n.saturating_add(o.value.to_sat()))})).collect::<Vec<_>>())
}
fn fee_estimates(handler: &Handler) -> Response {
    let mut values = serde_json::Map::new();
    for target in (1_u32..=25).chain([144, 504, 1008]) {
        let fee = handler
            .dispatch("estimatesmartfee", &sonic_json!([target]))
            .ok()
            .and_then(|v| v.get("feerate").and_then(sonic_rs::JsonValueTrait::as_f64))
            .map(|v| v * 100_000_000.0 / 1000.0)
            .unwrap_or(1.0);
        values.insert(target.to_string(), json!(fee));
    }
    json_response(values)
}

fn summary(ctx: &Context, text: &str, address: Option<&str>) -> Response {
    parse_script(text).map_or_else(|r| r, |h| summary_for(ctx, h, address))
}
fn summary_for(ctx: &Context, h: ScriptHash, address: Option<&str>) -> Response {
    let confirmed = match confirmed(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let us = match combined_utxos(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mem = mempool_activity(ctx, h, &us);
    let (cc, cs) = funded(&confirmed, h);
    let (mc, ms) = funded_mempool(&mem, h);
    let mut v = json!({"chain_stats":{"tx_count":confirmed.len(),"funded_txo_count":cc,"funded_txo_sum":cs,"spent_txo_count":cc.saturating_sub(us.len() as u64),"spent_txo_sum":cs.saturating_sub(us.iter().fold(0,|s,o|s.saturating_add(o.value)))},"mempool_stats":{"tx_count":mem.len(),"funded_txo_count":mc,"funded_txo_sum":ms,"spent_txo_count":0,"spent_txo_sum":0}});
    if let Some(a) = address {
        v["address"] = json!(a)
    } else {
        v["scripthash"] = json!(h.to_byte_array().to_lower_hex_string())
    };
    json_response(v)
}
fn utxos(ctx: &Context, h: ScriptHash) -> Response {
    combined_utxos(ctx,h).map_or_else(|r|r,|v|json_response(v.into_iter().map(|r|json!({"txid":r.txid.to_string(),"vout":r.vout,"value":r.value,"status":if r.height==0{json!({"confirmed":false})}else{status_value(status(ctx,r.height))}})).collect::<Vec<_>>()))
}
fn history(ctx: &Context, h: ScriptHash, last: Option<&str>, include_mempool: bool) -> Response {
    let confirmed = match confirmed(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let us = match combined_utxos(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mut chain = confirmed.into_iter().collect::<Vec<_>>();
    chain.sort_by(|a, b| {
        b.0.height
            .cmp(&a.0.height)
            .then_with(|| b.0.txid.cmp(&a.0.txid))
    });
    if last == Some("") {
        return json_response(
            mempool_activity(ctx, h, &us)
                .into_iter()
                .take(MEMPOOL_PAGE)
                .map(|t| tx_value(ctx, &t, None))
                .collect::<Vec<_>>(),
        );
    };
    let start = last.and_then(|x| {
        chain
            .iter()
            .position(|v| v.0.txid.to_string() == x)
            .map(|n| n + 1)
    });
    if last.is_some() && start.is_none() {
        return not_found();
    }
    let mut out = if include_mempool {
        mempool_activity(ctx, h, &us)
            .into_iter()
            .take(MEMPOOL_PAGE)
            .map(|t| tx_value(ctx, &t, None))
            .collect()
    } else {
        Vec::new()
    };
    out.extend(
        chain
            .into_iter()
            .skip(start.unwrap_or(0))
            .take(CHAIN_PAGE)
            .map(|(_, t, s)| tx_value(ctx, &t, Some(s))),
    );
    json_response(out)
}
fn confirmed(
    ctx: &Context,
    h: ScriptHash,
) -> Result<Vec<(ScriptHistoryRecord, Transaction, Status)>, Response> {
    let index = ctx
        .script_index
        .as_ref()
        .ok_or_else(|| unavailable("script index is disabled"))?;
    index
        .history_snapshot(h)
        .map_err(query_error)?
        .history
        .into_iter()
        .map(|r| {
            let s =
                status(ctx, r.height).ok_or_else(|| unavailable("confirming block unavailable"))?;
            let tx = ctx
                .block_by_height(r.height)
                .and_then(|b| ctx.block_body_bytes(&b))
                .and_then(|b| deserialize::<Block>(&b).ok())
                .and_then(|b| b.txdata.into_iter().find(|t| t.compute_txid() == r.txid))
                .ok_or_else(|| unavailable("confirming transaction unavailable"))?;
            Ok((r, tx, s))
        })
        .collect()
}
fn combined_utxos(ctx: &Context, h: ScriptHash) -> Result<Vec<ScriptIndexRecord>, Response> {
    let index = ctx
        .script_index
        .as_ref()
        .ok_or_else(|| unavailable("script index is disabled"))?;
    let mut v = index.unspent_outputs(h).map_err(query_error)?;
    let pool = ctx.mempool.read();
    v.retain(|r| !pool.is_outpoint_spent(&OutPoint::new(r.txid, r.vout)));
    let mh = MempoolScriptHash::from_byte_array(h.to_byte_array());
    for (_, id) in pool
        .funding
        .range((Bound::Included((mh, 0)), Bound::Included((mh, u32::MAX))))
    {
        let Some(e) = pool.entry(*id) else { continue };
        for (n, o) in e.tx.output.iter().enumerate() {
            let Ok(n) = u32::try_from(n) else { continue };
            if MempoolScriptHash::from_script(&o.script_pubkey) == mh
                && !pool.is_outpoint_spent(&OutPoint::new(e.txid, n))
            {
                v.push(ScriptIndexRecord {
                    txid: e.txid,
                    height: 0,
                    value: o.value.to_sat(),
                    vout: n,
                })
            }
        }
    }
    Ok(v)
}
fn mempool_activity(ctx: &Context, h: ScriptHash, us: &[ScriptIndexRecord]) -> Vec<Transaction> {
    let pool = ctx.mempool.read();
    let mh = MempoolScriptHash::from_byte_array(h.to_byte_array());
    let mut ids = std::collections::BTreeSet::new();
    let mut ops = us
        .iter()
        .map(|r| OutPoint::new(r.txid, r.vout))
        .collect::<std::collections::BTreeSet<_>>();
    for (_, id) in pool
        .funding
        .range((Bound::Included((mh, 0)), Bound::Included((mh, u32::MAX))))
    {
        if let Some(e) = pool.entry(*id) {
            ids.insert(e.txid);
            for (n, o) in e.tx.output.iter().enumerate() {
                if MempoolScriptHash::from_script(&o.script_pubkey) == mh {
                    if let Ok(n) = u32::try_from(n) {
                        ops.insert(OutPoint::new(e.txid, n));
                    }
                }
            }
        }
    }
    for (_, e) in &pool.entries {
        if e.tx.input.iter().any(|i| ops.contains(&i.previous_output)) {
            ids.insert(e.txid);
        }
    }
    ids.into_iter()
        .filter_map(|id| pool.transaction_by_txid(&id).map(|t| (*t).clone()))
        .collect()
}
fn funded(h: &[(ScriptHistoryRecord, Transaction, Status)], s: ScriptHash) -> (u64, u64) {
    h.iter()
        .flat_map(|(_, t, _)| &t.output)
        .filter(|o| ScriptHash::new(&o.script_pubkey) == s)
        .fold((0, 0), |(c, v), o| {
            (c + 1, v.saturating_add(o.value.to_sat()))
        })
}
fn funded_mempool(h: &[Transaction], s: ScriptHash) -> (u64, u64) {
    h.iter()
        .flat_map(|t| &t.output)
        .filter(|o| ScriptHash::new(&o.script_pubkey) == s)
        .fold((0, 0), |(c, v), o| {
            (c + 1, v.saturating_add(o.value.to_sat()))
        })
}
fn tx_value(ctx: &Context, tx: &Transaction, status: Option<Status>) -> Value {
    let vin=tx.input.iter().map(|i|{let coinbase=i.previous_output.is_null();json!({"txid":(!coinbase).then(||i.previous_output.txid.to_string()),"vout":(!coinbase).then_some(i.previous_output.vout),"is_coinbase":coinbase,"scriptsig":i.script_sig.as_bytes().to_lower_hex_string(),"scriptsig_asm":i.script_sig.to_asm_string(),"sequence":i.sequence.to_consensus_u32(),"witness":i.witness.iter().map(|w|w.to_lower_hex_string()).collect::<Vec<_>>(),"prevout":(!coinbase).then(||prevout(ctx,&i.previous_output)).flatten()})}).collect::<Vec<_>>();
    let out = tx
        .output
        .iter()
        .map(|o| out_value(ctx, o))
        .collect::<Vec<_>>();
    json!({"txid":tx.compute_txid().to_string(),"version":tx.version.0,"locktime":tx.lock_time.to_consensus_u32(),"size":serialize(tx).len(),"weight":tx.weight().to_wu(),"fee":0,"vin":vin,"vout":out,"status":status_value(status)})
}
fn prevout(ctx: &Context, o: &OutPoint) -> Option<Value> {
    let tx = ctx
        .mempool
        .read()
        .transaction_by_txid(&o.txid)
        .map(|t| (*t).clone())
        .or_else(|| ctx.tx_index.as_ref()?.transaction(&o.txid).ok().flatten())?;
    tx.output
        .get(usize::try_from(o.vout).ok()?)
        .map(|x| out_value(ctx, x))
}
fn out_value(ctx: &Context, o: &TxOut) -> Value {
    let s = &o.script_pubkey;
    let n = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    json!({"scriptpubkey":s.as_bytes().to_lower_hex_string(),"scriptpubkey_asm":s.to_asm_string(),"scriptpubkey_type":if s.is_p2tr(){"v1_p2tr"}else if s.is_p2wsh(){"v0_p2wsh"}else if s.is_p2wpkh(){"v0_p2wpkh"}else if s.is_p2sh(){"p2sh"}else if s.is_p2pkh(){"p2pkh"}else if s.is_op_return(){"op_return"}else{"unknown"},"scriptpubkey_address":bitcoin::Address::from_script(s,n).ok().map(|a|a.to_string()),"value":o.value.to_sat()})
}
fn status(ctx: &Context, h: u32) -> Option<Status> {
    let r = ctx.block_by_height(h)?;
    Some(Status {
        height: h,
        hash: r.hash,
        time: r.time,
    })
}
fn status_value(s: Option<Status>) -> Value {
    s.map_or_else(||json!({"confirmed":false}),|s|json!({"confirmed":true,"block_height":s.height,"block_hash":s.hash.to_string_be(),"block_time":s.time}))
}
fn address_hash(ctx: &Context, a: &str) -> Result<ScriptHash, Response> {
    let n = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let a = bitcoin::Address::from_str(a)
        .map_err(|_| bad("invalid address"))?
        .require_network(n)
        .map_err(|_| bad("address network does not match node"))?;
    Ok(ScriptHash::from_script_bytes(a.script_pubkey().as_bytes()))
}
fn parse_script(s: &str) -> Result<ScriptHash, Response> {
    Ok(ScriptHash::from_byte_array(
        <[u8; 32]>::from_hex(s).map_err(|_| bad("scripthash must be 64 hex characters"))?,
    ))
}
fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => unavailable(&e.to_string()),
        TxQueryError::Storage(_) => internal(&e.to_string()),
    }
}
fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        crate::RpcError::InvalidParams(_) | crate::RpcError::InvalidType(_) => bad(&e.to_string()),
        _ => unavailable(&e.to_string()),
    }
}
fn json_response(v: impl serde::Serialize) -> Response {
    sonic_rs::to_string(&v).map_or_else(
        |_| internal("failed to serialize response"),
        |b| Response {
            status: 200,
            reason: "OK",
            content_type: "application/json",
            body: b.into_bytes(),
        },
    )
}
fn text(b: String) -> Response {
    Response {
        status: 200,
        reason: "OK",
        content_type: "text/plain",
        body: b.into_bytes(),
    }
}
fn bad(m: &str) -> Response {
    Response {
        status: 400,
        reason: "Bad Request",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
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
fn unavailable(m: &str) -> Response {
    Response {
        status: 503,
        reason: "Service Unavailable",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}
fn internal(m: &str) -> Response {
    Response {
        status: 500,
        reason: "Internal Server Error",
        content_type: "text/plain",
        body: m.as_bytes().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use super::*;

    #[test]
    fn tip_routes_remain_available_without_script_index() {
        let handler = Handler::new(Arc::new(Context::new()));
        assert_eq!(route(&handler, "/blocks/tip/height").status, 200);
        assert_eq!(
            route(
                &handler,
                "/scripthash/0000000000000000000000000000000000000000000000000000000000000000/utxo"
            )
            .status,
            503
        );
    }
}
