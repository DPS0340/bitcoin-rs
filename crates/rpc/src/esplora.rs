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
use bitcoin::hashes::{Hash as _, sha256d};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
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
        ["tx", id, "merkleblock-proof"] => tx_merkleblock_proof(&ctx, id),
        ["tx", id, "merkle-proof"] => tx_merkle_proof(&ctx, id),
        ["tx", id, "outspend", vout] => tx_outspend(&ctx, id, vout),
        ["tx", id, "outspends"] => tx_outspends(&ctx, id),
        ["tx", id] => tx(&ctx, id),
        ["block", hash, "header"] => block_header(&ctx, hash),
        ["block", hash, "status"] => block_status(&ctx, hash),
        ["block", hash, "raw"] => block_raw(&ctx, hash),
        ["block", hash, "txs"] => block_txs(&ctx, hash, 0),
        ["block", hash, "txs", start] => match start.parse::<usize>() {
            Ok(n) if n % CHAIN_PAGE == 0 => block_txs(&ctx, hash, n),
            _ => bad("transaction start index must be a multiple of 25"),
        },
        ["block", hash, "txids"] => block_txids(&ctx, hash),
        ["block", hash, "txid", index] => block_txid(&ctx, hash, index),
        ["block", hash] => block(&ctx, hash),
        ["block-height", height] => height
            .parse::<u32>()
            .ok()
            .and_then(|h| ctx.block_hash_at_height(h))
            .map_or_else(not_found, |h| text(h.to_string_be())),
        ["blocks"] => blocks(&ctx, None),
        ["blocks", height] => height.parse::<u32>().map_or_else(
            |_| bad("start height must be an unsigned integer"),
            |h| blocks(&ctx, Some(h)),
        ),
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
        ["block-template"] => block_template(handler),
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
        ["address-prefix", _] => unavailable("address prefix search requires an address index"),
        _ => not_found(),
    }
}

/// Routes Esplora raw-transaction broadcast.
#[must_use]
pub fn route_post(handler: &Handler, path: &str, body: &[u8]) -> Option<Response> {
    match path {
        "/tx" => {
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
        "/txs/package" => Some(broadcast_package(handler, body)),
        _ => None,
    }
}

fn broadcast_package(handler: &Handler, body: &[u8]) -> Response {
    let Ok(raw_transactions) = serde_json::from_slice::<Vec<String>>(body) else {
        return bad("package body must be a JSON array of transaction hex strings");
    };
    if raw_transactions.is_empty() {
        return bad("transaction package must not be empty");
    }
    let mut results = serde_json::Map::new();
    for raw in raw_transactions {
        let result = match handler.dispatch("sendrawtransaction", &sonic_json!([raw])) {
            Ok(value) => value,
            Err(error) => return dispatch_error(error),
        };
        let Some(txid) = result.as_str() else {
            return internal("transaction broadcast did not return a txid");
        };
        results.insert(txid.to_owned(), json!({"txid":txid}));
    }
    json_response(json!({"package_msg":"success","tx-results":results}))
}

fn tx(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(
        |r| r,
        |(tx, status)| tx_value(ctx, &tx, status).map_or_else(|r| r, json_response),
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

fn tx_merkleblock_proof(ctx: &Context, id: &str) -> Response {
    confirmed_block(ctx, id).map_or_else(
        |r| r,
        |(_, block, txid)| {
            let proof =
                MerkleBlock::from_block_with_predicate(&block, |candidate| *candidate == txid);
            text(serialize(&proof).to_lower_hex_string())
        },
    )
}

fn tx_merkle_proof(ctx: &Context, id: &str) -> Response {
    confirmed_block(ctx, id).map_or_else(
        |r| r,
        |(record, block, txid)| {
            let txids = block
                .txdata
                .iter()
                .map(Transaction::compute_txid)
                .collect::<Vec<_>>();
            let Some(position) = txids.iter().position(|candidate| *candidate == txid) else {
                return internal("confirmed transaction is absent from its block");
            };
            let proof = merkle_proof(txids, position);
            json_response(json!({"block_height":record.height,"merkle":proof,"pos":position}))
        },
    )
}

fn confirmed_block(
    ctx: &Context,
    id: &str,
) -> Result<(crate::context::BlockRecord, Block, Txid), Response> {
    let txid = Txid::from_str(id).map_err(|_| bad("txid must be 64 hex characters"))?;
    let (_, Some(status)) = lookup(ctx, id)? else {
        return Err(not_found());
    };
    let record = ctx
        .block_by_height(status.height)
        .ok_or_else(|| unavailable("confirming block unavailable"))?;
    let bytes = ctx
        .block_body_bytes(&record)
        .ok_or_else(|| unavailable("confirming block body unavailable"))?;
    let block = deserialize(&bytes).map_err(|_| internal("stored block body is corrupt"))?;
    Ok((record, block, txid))
}

fn merkle_proof(mut level: Vec<Txid>, mut position: usize) -> Vec<String> {
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling = if position.is_multiple_of(2) {
            level.get(position + 1).unwrap_or(&level[position])
        } else {
            &level[position - 1]
        };
        proof.push(sibling.to_string());
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            let mut bytes = [0_u8; 64];
            bytes[..32].copy_from_slice(&pair[0].to_byte_array());
            bytes[32..].copy_from_slice(&right.to_byte_array());
            next.push(Txid::from_raw_hash(sha256d::Hash::hash(&bytes)));
        }
        level = next;
        position /= 2;
    }
    proof
}

fn tx_outspend(ctx: &Context, id: &str, vout: &str) -> Response {
    let Ok(vout) = vout.parse::<u32>() else {
        return bad("vout must be an unsigned integer");
    };
    lookup(ctx, id).map_or_else(
        |r| r,
        |(transaction, _)| {
            let Some(output) = transaction
                .output
                .get(usize::try_from(vout).unwrap_or(usize::MAX))
            else {
                return not_found();
            };
            outspend(
                ctx,
                OutPoint::new(transaction.compute_txid(), vout),
                &output.script_pubkey,
            )
            .map_or_else(|r| r, json_response)
        },
    )
}

fn tx_outspends(ctx: &Context, id: &str) -> Response {
    lookup(ctx, id).map_or_else(
        |r| r,
        |(transaction, _)| {
            transaction
                .output
                .iter()
                .enumerate()
                .map(|(vout, output)| {
                    let vout =
                        u32::try_from(vout).map_err(|_| internal("output index is too large"))?;
                    outspend(
                        ctx,
                        OutPoint::new(transaction.compute_txid(), vout),
                        &output.script_pubkey,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_or_else(|r| r, json_response)
        },
    )
}

fn outspend(
    ctx: &Context,
    outpoint: OutPoint,
    script: &bitcoin::ScriptBuf,
) -> Result<Value, Response> {
    let pool = ctx.mempool.read();
    if let Some((_, entry_id)) = pool
        .spending
        .range((
            Bound::Included((outpoint, 0)),
            Bound::Included((outpoint, u32::MAX)),
        ))
        .next()
    {
        if let Some(entry) = pool.entry(*entry_id) {
            let vin = entry
                .tx
                .input
                .iter()
                .position(|input| input.previous_output == outpoint)
                .ok_or_else(|| internal("mempool spending index is inconsistent"))?;
            return Ok(
                json!({"spent":true,"txid":entry.txid.to_string(),"vin":vin,"status":{"confirmed":false}}),
            );
        }
    }
    drop(pool);

    let index = ctx
        .script_index
        .as_ref()
        .ok_or_else(|| unavailable("script index is disabled"))?;
    for history in index
        .history_snapshot(ScriptHash::new(script))
        .map_err(query_error)?
        .history
    {
        let transaction = ctx
            .esplora_tx_index
            .as_ref()
            .ok_or_else(|| unavailable("transaction lookup index is disabled"))?
            .transaction(&history.txid)
            .map_err(query_error)?
            .ok_or_else(|| unavailable("indexed transaction unavailable"))?;
        if let Some(vin) = transaction
            .input
            .iter()
            .position(|input| input.previous_output == outpoint)
        {
            return Ok(
                json!({"spent":true,"txid":history.txid.to_string(),"vin":vin,"status":status_value(status(ctx,history.height))}),
            );
        }
    }
    Ok(json!({"spent":false}))
}

fn lookup(ctx: &Context, id: &str) -> Result<(Transaction, Option<Status>), Response> {
    let id = Txid::from_str(id).map_err(|_| bad("txid must be 64 hex characters"))?;
    if let Some(tx) = ctx.mempool.read().transaction_by_txid(&id) {
        return Ok(((*tx).clone(), None));
    }
    let index = ctx
        .esplora_tx_index
        .as_ref()
        .ok_or_else(|| unavailable("transaction lookup index is disabled"))?;
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
    block_value(ctx, &record).map_or_else(|r| r, json_response)
}
fn block_value(ctx: &Context, record: &crate::context::BlockRecord) -> Result<Value, Response> {
    let Some(header) = record
        .header_bytes()
        .and_then(|b| deserialize::<bitcoin::block::Header>(b).ok())
    else {
        return Err(unavailable("block header unavailable"));
    };
    let Some(bytes) = ctx.block_body_bytes(&record) else {
        return Err(unavailable("block body unavailable"));
    };
    let Ok(decoded) = deserialize::<Block>(&bytes) else {
        return Err(internal("stored block body is corrupt"));
    };
    Ok(
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
fn block_status(ctx: &Context, text_hash: &str) -> Response {
    let Ok(hash) = Hash256::from_str(text_hash) else {
        return bad("block hash must be 64 hex characters");
    };
    let Some(record) = ctx.block_by_hash(hash) else {
        return not_found();
    };
    let in_best_chain = ctx.active_hash_at_height(record.height) == Some(hash);
    let mut value = json!({"in_best_chain":in_best_chain});
    if in_best_chain {
        if let Some(next) = ctx.block_hash_at_height(record.height.saturating_add(1)) {
            value["next_best"] = json!(next.to_string_be());
        }
    }
    json_response(value)
}
fn block_raw(ctx: &Context, text_hash: &str) -> Response {
    let Ok(hash) = Hash256::from_str(text_hash) else {
        return bad("block hash must be 64 hex characters");
    };
    let Some(record) = ctx.block_by_hash(hash) else {
        return not_found();
    };
    let Some(bytes) = ctx.block_body_bytes(&record) else {
        return unavailable("block body unavailable");
    };
    Response {
        status: 200,
        reason: "OK",
        content_type: "application/octet-stream",
        body: bytes,
    }
}
fn block_txs(ctx: &Context, h: &str, start: usize) -> Response {
    let Some((record, block)) = decode_block(ctx, h) else {
        return not_found();
    };
    let state = status(ctx, record.height);
    block
        .txdata
        .iter()
        .skip(start)
        .take(CHAIN_PAGE)
        .map(|tx| tx_value(ctx, tx, state))
        .collect::<Result<Vec<_>, _>>()
        .map_or_else(|r| r, json_response)
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
fn block_txid(ctx: &Context, h: &str, index: &str) -> Response {
    let Ok(index) = index.parse::<usize>() else {
        return bad("transaction index must be an unsigned integer");
    };
    let Some((_, block)) = decode_block(ctx, h) else {
        return not_found();
    };
    block
        .txdata
        .get(index)
        .map_or_else(not_found, |tx| text(tx.compute_txid().to_string()))
}
fn blocks(ctx: &Context, start_height: Option<u32>) -> Response {
    let start = start_height.unwrap_or_else(|| ctx.applied_height());
    let mut values = Vec::with_capacity(10);
    for height in (0..=start).rev().take(10) {
        let Some(record) = ctx.block_by_height(height) else {
            continue;
        };
        let value = match block_value(ctx, &record) {
            Ok(value) => value,
            Err(response) => return response,
        };
        values.push(value);
    }
    json_response(values)
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
fn block_template(handler: &Handler) -> Response {
    handler
        .dispatch("getblocktemplate", &sonic_json!([]))
        .map_or_else(dispatch_error, json_response)
}

fn summary(ctx: &Context, text: &str, address: Option<&str>) -> Response {
    parse_script(text).map_or_else(|r| r, |h| summary_for(ctx, h, address))
}
fn summary_for(ctx: &Context, h: ScriptHash, address: Option<&str>) -> Response {
    let confirmed = match confirmed(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let confirmed_unspent = match confirmed_unspent(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let mem = mempool_activity(ctx, h, &confirmed_unspent);
    let (cc, cs) = funded(&confirmed, h);
    let (mc, ms) = funded_mempool(&mem, h);
    let (csc, css) = spent_confirmed(cc, cs, &confirmed_unspent);
    let (msc, mss) = spent_mempool(&mem, h, &confirmed_unspent);
    let mut v = json!({"chain_stats":{"tx_count":confirmed.len(),"funded_txo_count":cc,"funded_txo_sum":cs,"spent_txo_count":csc,"spent_txo_sum":css},"mempool_stats":{"tx_count":mem.len(),"funded_txo_count":mc,"funded_txo_sum":ms,"spent_txo_count":msc,"spent_txo_sum":mss}});
    if let Some(a) = address {
        v["address"] = json!(a)
    } else {
        v["scripthash"] = json!(h.to_byte_array().to_lower_hex_string())
    };
    json_response(v)
}
fn utxos(ctx: &Context, h: ScriptHash) -> Response {
    confirmed_unspent(ctx, h).map_or_else(
        |r| r,
        |confirmed| {
            let v = combined_utxos(ctx, h, &confirmed);
            json_response(v.into_iter().map(|r|json!({"txid":r.txid.to_string(),"vout":r.vout,"value":r.value,"status":if r.height==0{json!({"confirmed":false})}else{status_value(status(ctx,r.height))}})).collect::<Vec<_>>())
        },
    )
}
fn history(ctx: &Context, h: ScriptHash, last: Option<&str>, include_mempool: bool) -> Response {
    let confirmed = match confirmed(ctx, h) {
        Ok(v) => v,
        Err(r) => return r,
    };
    let confirmed_unspent = match confirmed_unspent(ctx, h) {
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
        return mempool_activity(ctx, h, &confirmed_unspent)
            .into_iter()
            .take(MEMPOOL_PAGE)
            .map(|t| tx_value(ctx, &t, None))
            .collect::<Result<Vec<_>, _>>()
            .map_or_else(|r| r, json_response);
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
    let out = if include_mempool {
        mempool_activity(ctx, h, &confirmed_unspent)
            .into_iter()
            .take(MEMPOOL_PAGE)
            .map(|t| tx_value(ctx, &t, None))
            .collect::<Result<Vec<_>, _>>()
    } else {
        Ok(Vec::new())
    };
    let mut out = match out {
        Ok(out) => out,
        Err(r) => return r,
    };
    let chain = match chain
        .into_iter()
        .skip(start.unwrap_or(0))
        .take(CHAIN_PAGE)
        .map(|(_, t, s)| tx_value(ctx, &t, Some(s)))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(chain) => chain,
        Err(r) => return r,
    };
    out.extend(chain);
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
                .esplora_tx_index
                .as_ref()
                .ok_or_else(|| unavailable("transaction lookup index is disabled"))?
                .transaction(&r.txid)
                .map_err(query_error)?
                .ok_or_else(|| unavailable("confirming transaction unavailable"))?;
            Ok((r, tx, s))
        })
        .collect()
}
fn confirmed_unspent(ctx: &Context, h: ScriptHash) -> Result<Vec<ScriptIndexRecord>, Response> {
    let index = ctx
        .script_index
        .as_ref()
        .ok_or_else(|| unavailable("script index is disabled"))?;
    index.unspent_outputs(h).map_err(query_error)
}
fn combined_utxos(
    ctx: &Context,
    h: ScriptHash,
    confirmed_unspent: &[ScriptIndexRecord],
) -> Vec<ScriptIndexRecord> {
    let mut v = confirmed_unspent.to_vec();
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
    v
}
fn mempool_activity(
    ctx: &Context,
    h: ScriptHash,
    confirmed_unspent: &[ScriptIndexRecord],
) -> Vec<Transaction> {
    let pool = ctx.mempool.read();
    let mh = MempoolScriptHash::from_byte_array(h.to_byte_array());
    let mut ids = std::collections::BTreeSet::new();
    let mut ops = confirmed_unspent
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
fn spent_confirmed(
    funded_count: u64,
    funded_sum: u64,
    confirmed_unspent: &[ScriptIndexRecord],
) -> (u64, u64) {
    let unspent_count = u64::try_from(confirmed_unspent.len()).unwrap_or(u64::MAX);
    let unspent_sum = confirmed_unspent
        .iter()
        .fold(0_u64, |sum, output| sum.saturating_add(output.value));
    (
        funded_count.saturating_sub(unspent_count),
        funded_sum.saturating_sub(unspent_sum),
    )
}
fn spent_mempool(
    transactions: &[Transaction],
    script_hash: ScriptHash,
    confirmed_unspent: &[ScriptIndexRecord],
) -> (u64, u64) {
    let mut target_outputs = std::collections::BTreeMap::new();
    for output in confirmed_unspent {
        target_outputs.insert(OutPoint::new(output.txid, output.vout), output.value);
    }
    for transaction in transactions {
        for (vout, output) in transaction.output.iter().enumerate() {
            let Ok(vout) = u32::try_from(vout) else {
                continue;
            };
            if ScriptHash::new(&output.script_pubkey) == script_hash {
                target_outputs.insert(
                    OutPoint::new(transaction.compute_txid(), vout),
                    output.value.to_sat(),
                );
            }
        }
    }
    transactions
        .iter()
        .flat_map(|transaction| &transaction.input)
        .filter_map(|input| target_outputs.remove(&input.previous_output))
        .fold((0, 0), |(count, sum), value| {
            (count + 1, sum.saturating_add(value))
        })
}
fn tx_value(ctx: &Context, tx: &Transaction, status: Option<Status>) -> Result<Value, Response> {
    let mut input_value = 0_u64;
    let vin = tx
        .input
        .iter()
        .map(|input| {
            let coinbase = input.previous_output.is_null();
            let prevout = if coinbase {
                None
            } else {
                let output = prevout(ctx, &input.previous_output)?
                    .ok_or_else(|| unavailable("previous transaction unavailable"))?;
                input_value = input_value.saturating_add(output.value.to_sat());
                Some(out_value(ctx, &output))
            };
            Ok(json!({"txid":(!coinbase).then(||input.previous_output.txid.to_string()),"vout":(!coinbase).then_some(input.previous_output.vout),"is_coinbase":coinbase,"scriptsig":input.script_sig.as_bytes().to_lower_hex_string(),"scriptsig_asm":input.script_sig.to_asm_string(),"sequence":input.sequence.to_consensus_u32(),"witness":input.witness.iter().map(|w|w.to_lower_hex_string()).collect::<Vec<_>>(),"prevout":prevout}))
        })
        .collect::<Result<Vec<_>, Response>>()?;
    let out = tx
        .output
        .iter()
        .map(|o| out_value(ctx, o))
        .collect::<Vec<_>>();
    let output_value = tx.output.iter().fold(0_u64, |sum, output| {
        sum.saturating_add(output.value.to_sat())
    });
    Ok(
        json!({"txid":tx.compute_txid().to_string(),"version":tx.version.0,"locktime":tx.lock_time.to_consensus_u32(),"size":serialize(tx).len(),"weight":tx.weight().to_wu(),"fee":input_value.saturating_sub(output_value),"vin":vin,"vout":out,"status":status_value(status)}),
    )
}
fn prevout(ctx: &Context, outpoint: &OutPoint) -> Result<Option<TxOut>, Response> {
    if let Some(tx) = ctx.mempool.read().transaction_by_txid(&outpoint.txid) {
        return Ok(tx
            .output
            .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
            .cloned());
    }
    let index = ctx
        .esplora_tx_index
        .as_ref()
        .ok_or_else(|| unavailable("transaction lookup index is disabled"))?;
    let Some(tx) = index.transaction(&outpoint.txid).map_err(query_error)? else {
        return Ok(None);
    };
    Ok(tx
        .output
        .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
        .cloned())
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

    use bitcoin::{Amount, ScriptBuf, TxIn, Witness, absolute, hashes::Hash as _, transaction};
    use bitcoin_rs_mempool::MempoolEntry;

    use super::*;

    fn transaction(input: Option<OutPoint>, output: TxOut) -> Transaction {
        Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: input
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![output],
        }
    }

    struct StaticTxIndex(Transaction);

    impl crate::context::TxIndexQuery for StaticTxIndex {
        fn transaction(&self, txid: &Txid) -> Result<Option<Transaction>, TxQueryError> {
            Ok((self.0.compute_txid() == *txid).then(|| self.0.clone()))
        }

        fn outpoint_value(&self, outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok((self.0.compute_txid() == outpoint.txid)
                .then(|| {
                    self.0
                        .output
                        .get(usize::try_from(outpoint.vout).unwrap_or(usize::MAX))
                })
                .flatten()
                .map(|output| output.value.to_sat()))
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

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

    #[test]
    #[allow(clippy::expect_used)]
    fn mempool_spender_of_a_confirmed_target_output_remains_in_activity_and_stats() {
        let target = ScriptBuf::from_bytes(vec![0x51]);
        let confirmed = ScriptIndexRecord {
            txid: Txid::from_byte_array([3; 32]),
            height: 42,
            value: 125,
            vout: 0,
        };
        let spending = transaction(
            Some(OutPoint::new(confirmed.txid, confirmed.vout)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            },
        );
        let ctx = Context::new();
        ctx.mempool
            .write()
            .insert_entry(MempoolEntry::new(
                Arc::new(spending.clone()),
                100,
                1_000,
                0,
                0,
            ))
            .expect("mempool entry accepted");

        let script_hash = ScriptHash::new(&target);
        let activity = mempool_activity(&ctx, script_hash, &[confirmed]);
        assert_eq!(activity, vec![spending]);
        assert!(combined_utxos(&ctx, script_hash, &[confirmed]).is_empty());
        assert_eq!(
            spent_mempool(&activity, script_hash, &[confirmed]),
            (1, 125)
        );
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn transaction_projection_uses_internal_lookup_for_prevout_and_fee() {
        let parent = transaction(
            None,
            TxOut {
                value: Amount::from_sat(125),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
        );
        let child = transaction(
            Some(OutPoint::new(parent.compute_txid(), 0)),
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: ScriptBuf::from_bytes(vec![0x52]),
            },
        );
        let mut ctx = Context::new();
        ctx.esplora_tx_index = Some(Arc::new(StaticTxIndex(parent)));

        let rendered = tx_value(&ctx, &child, None).expect("prevout indexed");
        assert_eq!(rendered["fee"], json!(25));
        assert_eq!(rendered["vin"][0]["prevout"]["value"], json!(125));
    }
}
