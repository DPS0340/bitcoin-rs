use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, required_str, required_u64};

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let blockhash_str = params_array(params)?
        .get(2)
        .and_then(JsonValueTrait::as_str);
    if let Some(hash_str) = blockhash_str {
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))?;
        let Some(record) = ctx.block_by_hash(hash) else {
            return Err(RpcError::NotFound("block not found"));
        };
        let Some(bytes) = ctx.block_body_bytes(&record) else {
            return Err(RpcError::NotFound("block data pruned"));
        };
        let block: bitcoin::Block = deserialize(&bytes)
            .map_err(|_| RpcError::Internal("stored block bytes failed decode".to_owned()))?;
        for tx in &block.txdata {
            if tx.compute_txid() == txid {
                if !verbose {
                    return Ok(json!(serialize(tx).to_lower_hex_string()));
                }
                return super::tx_render::tx_to_value(tx);
            }
        }
        return Err(RpcError::NotFound("transaction not in specified block"));
    }
    {
        let transactions = ctx.transactions.read();
        if let Some(tx) = transactions.get(&txid) {
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return super::tx_render::tx_to_value(tx);
        }
    }
    {
        let pool = ctx.mempool.read();
        if let Some(entry) = pool.entry_by_txid(&txid) {
            let tx = entry.tx.as_ref();
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return super::tx_render::tx_to_value(tx);
        }
    }
    if let Some(tx_index) = ctx.tx_index.as_ref() {
        match tx_index.transaction(&txid) {
            Ok(Some(tx)) => {
                if !verbose {
                    return Ok(json!(serialize(&tx).to_lower_hex_string()));
                }
                return super::tx_render::tx_to_value(&tx);
            }
            Ok(None) => {}
            Err(error) => return Err(error.into_rpc_error()),
        }
    }
    Err(RpcError::NotFound("transaction not found"))
}

fn classify_script(script: &bitcoin::Script) -> &'static str {
    if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2pk() {
        "pubkey"
    } else if script.is_op_return() {
        "nulldata"
    } else {
        "nonstandard"
    }
}

fn script_to_address(
    script: &bitcoin::Script,
    chain_network: bitcoin_rs_primitives::Network,
) -> Option<String> {
    let network = match chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    bitcoin::Address::from_script(script, network)
        .ok()
        .map(|address| address.to_string())
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout_u32 = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
    let outpoint = OutPoint::new(Hash256::from_le_bytes(txid.as_byte_array()), vout_u32);
    let Some(live) = ctx.utxo.get_entry(&outpoint) else {
        // Spent or never existed: Core-spec returns JSON null.
        return Ok(Value::new_null());
    };
    let applied = ctx.applied_height();
    let confirmations = applied.saturating_sub(live.height).saturating_add(1);
    let script_hex = live.txout.script_pubkey.as_bytes().to_lower_hex_string();
    let address = script_to_address(&live.txout.script_pubkey, ctx.chain_network);
    let desc = address.as_deref().map_or_else(
        || format!("raw({script_hex})"),
        |addr| format!("addr({addr})"),
    );
    let mut script_pubkey = json!({
        "asm": live.txout.script_pubkey.to_asm_string(),
        "desc": desc,
        "hex": script_hex,
        "type": classify_script(&live.txout.script_pubkey)
    });
    if let Some(addr) = address {
        let _ = script_pubkey.insert("address", json!(addr));
    }
    Ok(json!({
        "bestblock": ctx.best_hash().to_string_be(),
        "confirmations": confirmations,
        "value": super::tx_render::btc_value(live.txout.value.to_sat()),
        "scriptPubKey": script_pubkey,
        "coinbase": live.coinbase
    }))
}

pub(crate) fn gettxoutproof(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let txids_value = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("txids must be an array"))?;
    if txids_value.is_empty() {
        return Err(RpcError::InvalidParams("txids are required"));
    }

    let mut wanted = hashbrown::HashSet::new();
    for value in txids_value {
        let Some(txid) = value.as_str() else {
            return Err(RpcError::InvalidType("each txid must be a string"));
        };
        wanted.insert(parse_txid(txid)?);
    }

    if let Some(hash_str) = array.get(1).and_then(JsonValueTrait::as_str) {
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))?;
        let Some(record) = ctx.block_by_hash(hash) else {
            return Err(RpcError::NotFound("block not found"));
        };
        return proof_from_single_record(ctx, &record, &wanted);
    }

    // Without a block hash the scan below reads, deserializes and hashes every
    // block on the chain to answer one call. The txindex already knows which
    // block confirms a txid, so ask it first and scan only when it cannot
    // answer — the same route Bitcoin Core takes, which requires the block hash
    // *unless* txindex is enabled.
    if let Some(proof) = proof_via_index(ctx, &wanted) {
        return Ok(proof);
    }
    proof_from_block_log(ctx, &wanted)
}

/// Answers `gettxoutproof` from the txindex, or `None` when it cannot.
///
/// Probes the wanted txids until one resolves to a confirming height, then tries
/// to build the proof from that block alone. Probing *every* txid rather than an
/// arbitrary one matters: `wanted` is a `HashSet`, so "the first" is whichever
/// the hasher happens to yield, and one unresolvable txid would otherwise drop
/// the call into the full chain scan non-deterministically — the very cost this
/// path exists to avoid.
///
/// Every miss returns `None` so the caller falls back to that scan: no index,
/// no row, a stale row, a pruned body, or a block that does not hold *all* the
/// wanted txids. The last of those is not belt-and-braces — BIP30's duplicate
/// coinbase txids mean a txid can confirm in more than one block, so a block
/// chosen from a single txid is a candidate, never a verdict.
///
/// An index that returns an error is a miss too, logged rather than propagated.
/// Before this path existed a broken txindex could not fail this call, and the
/// scan can still answer it; an optimization must not turn a working call into
/// an error. `TxQueryError::Retry` makes that concrete rather than defensive:
/// the index reconciles asynchronously, so it reports `Retry` while it is
/// catching up, and a call the scan can answer today must not be refused
/// because the index is behind.
fn proof_via_index(ctx: &Arc<Context>, wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let tx_index = ctx.tx_index.as_ref()?;
    for probe in wanted {
        let height = match tx_index.transaction_height(probe) {
            Ok(Some(height)) => height,
            Ok(None) => continue,
            Err(error) => {
                tracing::warn!(
                    txid = %probe,
                    %error,
                    "txindex lookup failed; answering from the block scan instead"
                );
                return None;
            }
        };
        let Some(record) = ctx.block_by_height(height) else {
            continue;
        };
        if let Some(proof) = proof_from_record(ctx, &record, wanted) {
            return Some(proof);
        }
    }
    None
}

/// Builds the proof from one named block, or reports why it could not.
///
/// The explicit-`blockhash` path: the caller named the block, so there is
/// nothing to scan and the two failures are distinguishable — a body that is not
/// there, and a block that does not hold every wanted txid. Both messages are
/// the ones this handler returned before the index path existed.
fn proof_from_single_record(
    ctx: &Arc<Context>,
    record: &crate::context::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let Some(bytes) = ctx.block_body_bytes(record) else {
        return Err(RpcError::NotFound("block data pruned"));
    };
    proof_from_body(&bytes, wanted)
        .ok_or(RpcError::NotFound("no block contains all requested txids"))
}

/// Scans the whole block-record log for a block holding every wanted txid.
///
/// Deliberately does **not** clone the log, and deliberately does not hold its
/// lock either. Cloning it copies every record on the chain — about 160 MB at a
/// mainnet tip — to answer one call, on the exact path taken when the index
/// cannot. Holding the read guard instead would stall block application for the
/// length of a scan that loads a block body from disk per record.
///
/// So the length is snapshotted once and each record is copied out under a
/// momentary lock, released before its body is read. Records are only ever
/// appended, and the tail `pop` on disconnect only removes what was never in the
/// snapshot's range, so a stale length can miss a block appended mid-scan but
/// can never read a record that moved.
fn proof_from_block_log(
    ctx: &Arc<Context>,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let len = ctx.blocks.read().len();
    let mut saw_pruned_block = false;
    for index in 0..len {
        let Some(record) = ctx.blocks.read().get(index).cloned() else {
            break;
        };
        let Some(bytes) = ctx.block_body_bytes(&record) else {
            saw_pruned_block = true;
            continue;
        };
        if let Some(proof) = proof_from_body(&bytes, wanted) {
            return Ok(proof);
        }
    }

    if saw_pruned_block {
        Err(RpcError::NotFound("block data pruned"))
    } else {
        Err(RpcError::NotFound("no block contains all requested txids"))
    }
}

/// Builds the merkle proof for `wanted` from one block record, or `None` when
/// that block is pruned, undecodable, or does not hold every wanted txid.
fn proof_from_record(
    ctx: &Arc<Context>,
    record: &crate::context::BlockRecord,
    wanted: &hashbrown::HashSet<Txid>,
) -> Option<Value> {
    let bytes = ctx.block_body_bytes(record)?;
    proof_from_body(&bytes, wanted)
}

/// Builds the merkle proof for `wanted` from one serialized block, or `None`
/// when it does not decode or does not hold every wanted txid.
fn proof_from_body(bytes: &[u8], wanted: &hashbrown::HashSet<Txid>) -> Option<Value> {
    let block = deserialize::<bitcoin::Block>(bytes).ok()?;
    let block_txids = block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect::<hashbrown::HashSet<Txid>>();
    if !wanted.iter().all(|txid| block_txids.contains(txid)) {
        return None;
    }

    let merkle_block = MerkleBlock::from_block_with_predicate(&block, |txid| wanted.contains(txid));
    Some(json!(serialize(&merkle_block).to_lower_hex_string()))
}

pub(crate) fn verifytxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let proof_hex = required_str(params, 0, "proof is required")?;
    let bytes = Vec::<u8>::from_hex(proof_hex)
        .map_err(|_| RpcError::InvalidParams("proof must be valid hex"))?;
    let Ok(merkle_block) = deserialize::<MerkleBlock>(&bytes) else {
        return Ok(json!([]));
    };

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();
    if merkle_block
        .extract_matches(&mut matched_txids, &mut indexes)
        .is_err()
    {
        return Ok(json!([]));
    }

    let result = matched_txids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    Ok(json!(result))
}

/// Fee rate above which `sendrawtransaction` refuses by default, in sat/kvB.
///
/// Bitcoin Core's `DEFAULT_MAX_RAW_TX_FEE_RATE`, `COIN / 10` — 0.1 BTC per kvB.
/// The guard exists because a change-output mistake shows up as an enormous
/// fee, and a fee is not recoverable once the transaction confirms.
const DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB: u64 = 10_000_000;

/// One whole coin per kvB, which Core refuses to accept even as a ceiling.
const MAX_ACCEPTED_FEE_RATE_SAT_PER_KVB: u64 = 100_000_000;

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    let txid = tx.compute_txid();
    let max_fee = max_fee_for(params, &tx)?;
    match ctx.accept_transaction(tx, now_seconds(), max_fee) {
        Ok(result) => Ok(json!(result.checks.txid.to_string())),
        // Core does not treat a resubmission as a failure: `BroadcastTransaction`
        // finds the transaction already in the mempool, rebroadcasts it, and
        // returns the txid. Callers retry on a dropped connection and expect
        // that to be idempotent.
        Err(bitcoin_rs_mempool::AcceptError::AlreadyInPool) => Ok(json!(txid.to_string())),
        // A capped fee is not a rejection by the network's rules -- the
        // transaction is acceptable and the sender asked not to send it. Core
        // separates the two: -25 for a guard the caller configured, -26 for
        // what policy or consensus refused.
        Err(bitcoin_rs_mempool::AcceptError::FeeExceedsMaximum { .. }) => {
            Err(RpcError::TxVerifyError(
                "Fee exceeds maximum configured by user (e.g. -maxtxfee, maxfeerate)".to_owned(),
            ))
        }
        Err(error) => Err(RpcError::TxRejected(error.to_string())),
    }
}

/// The absolute fee ceiling for this submission, from `maxfeerate`.
///
/// Bitcoin Core takes a rate in BTC/kvB, turns it into an absolute fee for this
/// transaction's vsize, and refuses the submission when the fee it computed is
/// larger. `0` disables the guard; the argument's absence means the default,
/// which is *not* the same thing.
fn max_fee_for(params: &Value, tx: &bitcoin::Transaction) -> Result<Option<u64>, RpcError> {
    let requested = params_array(params)
        .ok()
        .and_then(|array| array.get(1).cloned())
        .filter(|value| !value.is_null());

    let rate_sat_per_kvb = match requested {
        None => DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB,
        Some(value) => {
            let btc = value.as_f64().ok_or(RpcError::InvalidType(
                "maxfeerate must be an amount in BTC/kvB",
            ))?;
            let amount = bitcoin::Amount::from_btc(btc)
                .map_err(|_| RpcError::InvalidType("maxfeerate must be an amount in BTC/kvB"))?;
            let rate = amount.to_sat();
            if rate >= MAX_ACCEPTED_FEE_RATE_SAT_PER_KVB {
                return Err(RpcError::InvalidParameter(
                    "Fee rates larger than or equal to 1BTC/kvB are not accepted".to_owned(),
                ));
            }
            rate
        }
    };

    if rate_sat_per_kvb == 0 {
        return Ok(None);
    }
    // Core's `CFeeRate::GetFee`: rounded up, and never zero for a non-empty
    // transaction at a non-zero rate.
    let vsize = u64::try_from(tx.vsize()).unwrap_or(u64::MAX);
    let fee = rate_sat_per_kvb.saturating_mul(vsize).saturating_add(999) / 1_000;
    Ok(Some(fee.max(1)))
}

pub(crate) fn testmempoolaccept(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw_txs = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let now = now_seconds();
    let mut rows = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        let Ok(tx) = decode_tx(raw) else {
            rows.push(json!({
                "txid": Hash256::default().to_string_be(),
                "allowed": false,
                "reject-reason": "transaction decode failed"
            }));
            continue;
        };
        let tx = Arc::new(tx);
        let txid = tx.compute_txid().to_string();
        // The old code reported the txid here too. A witness transaction's
        // wtxid differs, and package relay identifies transactions by it.
        let wtxid = tx.compute_wtxid().to_string();
        match ctx.check_transaction(&tx, now) {
            Ok(checks) => rows.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": true,
                "vsize": checks.vsize,
                "fees": {"base": bitcoin::Amount::from_sat(checks.fee).to_btc()}
            })),
            Err(error) => rows.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": error.to_string()
            })),
        }
    }
    Ok(json!(rows))
}

/// Wall-clock seconds since the UNIX epoch, for mempool entry timestamps.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) fn decoderawtransaction(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    super::tx_render::tx_to_value(&tx)
}

fn decode_tx(raw: &str) -> Result<Transaction, RpcError> {
    let bytes = Vec::<u8>::from_hex(raw)?;
    deserialize(&bytes).map_err(|_| RpcError::InvalidParams("transaction decode failed"))
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin::{OutPoint, Txid};
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::getrawtransaction;
    use crate::Handler;
    use crate::context::{BlockRecord, Context, TxIndexQuery, TxQueryError};
    use crate::error::RpcError;

    fn genesis_block(network: bitcoin::Network) -> bitcoin::Block {
        bitcoin::blockdata::constants::genesis_block(network)
    }

    #[test]
    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let coinbase = genesis
            .txdata
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn getrawtransaction_checks_mempool_before_failing_txindex()
    -> Result<(), Box<dyn std::error::Error>> {
        struct FailingQuery;

        impl TxIndexQuery for FailingQuery {
            fn transaction(
                &self,
                _txid: &Txid,
            ) -> Result<Option<bitcoin::Transaction>, TxQueryError> {
                Err(TxQueryError::Storage("disk full".into()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: false,
                    best_block_height: 0,
                })
            }
        }

        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(FailingQuery));
        let ctx = Arc::new(ctx);
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let coinbase = genesis
            .txdata
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn getrawtransaction_with_blockhash_finds_tx_in_specific_block() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let block_hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch(
                "getrawtransaction",
                &json!([txid.to_string(), false, block_hash.to_string_be()]),
            )
            .unwrap_or_else(|err| panic!("getrawtransaction with blockhash: {err}"));
        assert!(result.is_str(), "expected hex string, got {result:?}");
    }

    #[test]
    fn getrawtransaction_resolves_confirmed_transaction_from_txindex_without_cache() {
        struct StaticQuery {
            tx: bitcoin::Transaction,
        }

        impl TxIndexQuery for StaticQuery {
            fn transaction(
                &self,
                txid: &Txid,
            ) -> Result<Option<bitcoin::Transaction>, TxQueryError> {
                Ok((self.tx.compute_txid() == *txid).then(|| self.tx.clone()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first().cloned() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(StaticQuery {
            tx: coinbase.clone(),
        }));
        let ctx = Arc::new(ctx);

        assert!(
            ctx.transactions.read().is_empty(),
            "confirmed transaction cache must stay empty"
        );
        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))
            .unwrap_or_else(|err| panic!("txindex lookup failed: {err}"));

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
    }

    #[test]
    fn getrawtransaction_with_blockhash_reports_pruned_block_body() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut record = BlockRecord::from_block(0, &genesis);
        let block_hash = record.hash;
        record.block_hex.clear();
        ctx.add_block(record);

        let result = getrawtransaction(
            &ctx,
            &json!([txid.to_string(), false, block_hash.to_string_be()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    #[test]
    fn getrawtransaction_with_unknown_blockhash_errors() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let bogus_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();
        let result = handler.dispatch(
            "getrawtransaction",
            &json!([
                "0000000000000000000000000000000000000000000000000000000000000000",
                false,
                bogus_hash
            ]),
        );
        assert!(result.is_err());
    }

    #[test]
    fn gettxoutproof_finds_genesis_coinbase() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
            .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
        let Some(proof_hex) = result.as_str() else {
            panic!("expected string, got {result:?}");
        };

        let extracted = handler
            .dispatch("verifytxoutproof", &json!([proof_hex]))
            .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
        let Some(arr) = extracted.as_array() else {
            panic!("expected array, got {extracted:?}");
        };
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn gettxoutproof_skips_pruned_blocks_before_matching_block() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut pruned_genesis = BlockRecord::from_block(0, &genesis);
        pruned_genesis.block_hex.clear();
        ctx.add_block(pruned_genesis);
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("gettxoutproof", &json!([[txid.to_string()]]));

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "gettxoutproof should skip pruned blocks before matching retained blocks: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_with_blockhash_skips_unrelated_records() {
        struct PanicBodySource;

        impl crate::BlockBodySource for PanicBodySource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                panic!("specified blockhash proof should not load unrelated body {height}:{hash}");
            }
        }

        let ctx = Arc::new(Context::new().with_block_body_source(Arc::new(PanicBodySource)));
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let unrelated_hash = Hash256::from_le_bytes(&[7_u8; 32]);
        ctx.add_block(BlockRecord::synthetic(0, unrelated_hash));
        let record = BlockRecord::from_block(1, &genesis);
        let block_hash = record.hash;
        ctx.add_block(record);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], block_hash.to_string_be()]),
        );

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "gettxoutproof should inspect only the specified block: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_with_blockhash_reports_pruned_block_body() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut record = BlockRecord::from_block(0, &genesis);
        let block_hash = record.hash;
        record.block_hex.clear();
        ctx.add_block(record);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], block_hash.to_string_be()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    /// Builds a block distinguishable from the blocks of other markers: the
    /// coinbase script makes the txid differ, and the merkle root is recomputed
    /// so `verifytxoutproof` can still extract matches from a proof over it.
    fn distinct_block(marker: u8) -> bitcoin::Block {
        let mut block = genesis_block(bitcoin::Network::Regtest);
        if let Some(tx) = block.txdata.first_mut()
            && let Some(input) = tx.input.first_mut()
        {
            input.script_sig = bitcoin::ScriptBuf::from_bytes(vec![marker; 4]);
        }
        if let Some(root) = block.compute_merkle_root() {
            block.header.merkle_root = root;
        }
        block
    }

    /// Adds a second transaction so one block can hold two wanted txids.
    fn block_with_two_txs(marker: u8) -> bitcoin::Block {
        let mut block = distinct_block(marker);
        let extra = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000 + u64::from(marker)),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        block.txdata.push(extra);
        if let Some(root) = block.compute_merkle_root() {
            block.header.merkle_root = root;
        }
        block
    }

    /// Stands in for the txindex, answering only the query these tests are about.
    ///
    /// `gettxoutproof` calls nothing else on `TxIndexQuery`, so the other three
    /// methods answer emptily and every probe behaviour these tests need — a
    /// fixed height, a selective one, an error, a panic, a counter — is the
    /// closure rather than another stub type.
    struct HeightQuery<F>(F);

    impl<F> TxIndexQuery for HeightQuery<F>
    where
        F: Fn(&Txid) -> Result<Option<u32>, TxQueryError> + Send + Sync,
    {
        fn transaction(&self, _txid: &Txid) -> Result<Option<bitcoin::Transaction>, TxQueryError> {
            Ok(None)
        }

        fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
            Ok(crate::context::TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }

        fn transaction_height(&self, txid: &Txid) -> Result<Option<u32>, TxQueryError> {
            (self.0)(txid)
        }
    }

    fn ctx_with_index<F>(probe: F) -> Arc<Context>
    where
        F: Fn(&Txid) -> Result<Option<u32>, TxQueryError> + Send + Sync + 'static,
    {
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(HeightQuery(probe)));
        Arc::new(ctx)
    }

    fn ctx_with_height_index(height: Option<u32>) -> Arc<Context> {
        ctx_with_index(move |_| Ok(height))
    }

    /// Resolves only the txids it was told about, so a probe can be made to miss.
    fn resolving(
        resolvable: Vec<(Txid, u32)>,
    ) -> impl Fn(&Txid) -> Result<Option<u32>, TxQueryError> {
        move |txid| {
            Ok(resolvable
                .iter()
                .find(|(known, _)| known == txid)
                .map(|(_, height)| *height))
        }
    }

    fn seed_blocks(ctx: &Arc<Context>, blocks: &[bitcoin::Block]) {
        for (height, block) in blocks.iter().enumerate() {
            let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
            ctx.add_block(BlockRecord::from_block(height, block));
        }
    }

    fn proof_for(ctx: &Arc<Context>, txids: &[Txid]) -> Result<sonic_rs::Value, RpcError> {
        let names = txids.iter().map(ToString::to_string).collect::<Vec<_>>();
        super::gettxoutproof(ctx, &json!([names]))
    }

    #[test]
    fn gettxoutproof_index_path_matches_the_scan_it_replaces() {
        let blocks = [distinct_block(1), distinct_block(2), distinct_block(3)];
        let Some(wanted) = blocks[2]
            .txdata
            .first()
            .map(bitcoin::Transaction::compute_txid)
        else {
            panic!("block has no transactions");
        };

        let scan_ctx = Arc::new(Context::new());
        seed_blocks(&scan_ctx, &blocks);
        let scanned =
            proof_for(&scan_ctx, &[wanted]).unwrap_or_else(|err| panic!("scan path failed: {err}"));

        let index_ctx = ctx_with_height_index(Some(2));
        seed_blocks(&index_ctx, &blocks);
        let indexed = proof_for(&index_ctx, &[wanted])
            .unwrap_or_else(|err| panic!("index path failed: {err}"));

        assert_eq!(
            indexed.as_str(),
            scanned.as_str(),
            "the index path must return the proof the scan would have returned"
        );
    }

    #[test]
    fn gettxoutproof_index_path_does_not_read_unrelated_block_bodies() {
        struct PanicBodySource;

        impl crate::BlockBodySource for PanicBodySource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                panic!("index path should not load unrelated body {height}:{hash}");
            }
        }

        // Records without a body force a `BlockBodySource` read, so a scan over
        // them panics; only skipping them entirely keeps this test green.
        let mut ctx = Context::new().with_block_body_source(Arc::new(PanicBodySource));
        ctx.tx_index = Some(Arc::new(HeightQuery(|_: &Txid| Ok(Some(2)))));
        let ctx = Arc::new(ctx);
        ctx.add_block(BlockRecord::synthetic(
            0,
            Hash256::from_le_bytes(&[7_u8; 32]),
        ));
        ctx.add_block(BlockRecord::synthetic(
            1,
            Hash256::from_le_bytes(&[8_u8; 32]),
        ));
        let block = distinct_block(3);
        let Some(wanted) = block.txdata.first().map(bitcoin::Transaction::compute_txid) else {
            panic!("block has no transactions");
        };
        ctx.add_block(BlockRecord::from_block(2, &block));

        let result = proof_for(&ctx, &[wanted]);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "index path should answer from the indexed block alone: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_falls_back_to_the_scan_when_the_index_cannot_answer() {
        let blocks = [distinct_block(1), distinct_block(2)];
        let Some(wanted) = blocks[1]
            .txdata
            .first()
            .map(bitcoin::Transaction::compute_txid)
        else {
            panic!("block has no transactions");
        };

        let ctx = ctx_with_height_index(None);
        seed_blocks(&ctx, &blocks);

        let result = proof_for(&ctx, &[wanted]);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "an index that cannot answer must not turn a findable proof into an error: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_falls_back_when_the_indexed_block_lacks_some_wanted_txids() {
        // The candidate block holds one wanted txid; only the second block holds
        // both. A block chosen from a single txid is a candidate, not a verdict,
        // so pointing the index at the wrong one must still produce the proof.
        let both = block_with_two_txs(9);
        let blocks = [distinct_block(1), both.clone()];
        let wanted = both
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();

        let scan_ctx = Arc::new(Context::new());
        seed_blocks(&scan_ctx, &blocks);
        let scanned =
            proof_for(&scan_ctx, &wanted).unwrap_or_else(|err| panic!("scan path failed: {err}"));

        let index_ctx = ctx_with_height_index(Some(0));
        seed_blocks(&index_ctx, &blocks);
        let fell_back = proof_for(&index_ctx, &wanted)
            .unwrap_or_else(|err| panic!("fallback path failed: {err}"));

        assert_eq!(
            fell_back.as_str(),
            scanned.as_str(),
            "a candidate block missing some wanted txids must fall back to the scan"
        );
    }

    #[test]
    fn gettxoutproof_keeps_its_error_when_no_block_holds_every_txid() {
        let blocks = [distinct_block(1), distinct_block(2)];
        let wanted = blocks
            .iter()
            .filter_map(|block| block.txdata.first().map(bitcoin::Transaction::compute_txid))
            .collect::<Vec<_>>();

        let index_ctx = ctx_with_height_index(Some(0));
        seed_blocks(&index_ctx, &blocks);

        let result = proof_for(&index_ctx, &wanted);

        assert!(
            matches!(
                result,
                Err(RpcError::NotFound("no block contains all requested txids"))
            ),
            "txids spread across blocks must keep the pre-index error: {result:?}"
        );
    }

    /// A body source that refuses to serve anything, so any scan over
    /// body-less records fails loudly instead of quietly succeeding.
    struct PanicOnScan;

    impl crate::BlockBodySource for PanicOnScan {
        fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
            panic!("the index path should not have scanned: {height}:{hash}");
        }
    }

    #[test]
    fn gettxoutproof_index_path_answers_for_several_txids_in_one_block() {
        let block = block_with_two_txs(11);
        let wanted = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        let resolvable = wanted.iter().map(|txid| (*txid, 1)).collect::<Vec<_>>();

        let ctx = ctx_with_index(resolving(resolvable));
        ctx.add_block(BlockRecord::synthetic(
            0,
            Hash256::from_le_bytes(&[5_u8; 32]),
        ));
        ctx.add_block(BlockRecord::from_block(1, &block));

        let result = proof_for(&ctx, &wanted);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "several txids in one block should resolve through the index: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_probes_every_txid_before_giving_up_on_the_index() {
        // `wanted` is a HashSet, so which txid is probed first is whatever the
        // hasher yields. Making only the *second*-added txid resolvable pins that
        // an unresolvable probe does not by itself drop the call into the scan —
        // the scan here would panic.
        let block = block_with_two_txs(12);
        let wanted = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        let Some(only_one) = wanted.last().copied() else {
            panic!("block has no transactions");
        };

        let mut ctx = Context::new().with_block_body_source(Arc::new(PanicOnScan));
        ctx.tx_index = Some(Arc::new(HeightQuery(resolving(vec![(only_one, 1)]))));
        let ctx = Arc::new(ctx);
        ctx.add_block(BlockRecord::synthetic(
            0,
            Hash256::from_le_bytes(&[6_u8; 32]),
        ));
        ctx.add_block(BlockRecord::from_block(1, &block));

        let result = proof_for(&ctx, &wanted);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "one unresolvable probe must not abandon the index path: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_falls_back_to_the_scan_when_the_index_errors() {
        // Before this path existed, a broken txindex could not fail this call and
        // the scan answered it. An optimization must not turn a working call into
        // an error.
        //
        // Every variant, not just the interesting-looking ones. `Retry` is the
        // one that matters most: the index reconciles asynchronously, so it is
        // the *routine* answer while the index catches up, and it must not
        // refuse a call the scan can answer today.
        for error in [
            TxQueryError::Retry,
            TxQueryError::Unavailable("worker stopped".into()),
            TxQueryError::Storage("disk full".into()),
        ] {
            let blocks = [distinct_block(1), distinct_block(2)];
            let Some(wanted) = blocks[1]
                .txdata
                .first()
                .map(bitcoin::Transaction::compute_txid)
            else {
                panic!("block has no transactions");
            };

            let scan_ctx = Arc::new(Context::new());
            seed_blocks(&scan_ctx, &blocks);
            let scanned = proof_for(&scan_ctx, &[wanted])
                .unwrap_or_else(|err| panic!("scan path failed: {err}"));

            let failure = error.clone();
            let ctx = ctx_with_index(move |_| Err(failure.clone()));
            seed_blocks(&ctx, &blocks);

            let result = proof_for(&ctx, &[wanted]);

            // Comparing against the scan's answer, not merely asserting that
            // *some* string came back: a failing index must not get to decide
            // what the answer is, only that it is not the one supplying it.
            assert_eq!(
                result.as_ref().ok().and_then(|value| value.as_str()),
                scanned.as_str(),
                "an index reporting {error} must fall back to the scan, \
                 not fail or answer the call: {result:?}"
            );
        }
    }

    #[test]
    fn gettxoutproof_with_blockhash_never_consults_the_index() {
        // The explicit-blockhash path is unchanged by this work, and an index
        // that panics on use proves it stays that way.
        let ctx = ctx_with_index(|_| -> Result<Option<u32>, TxQueryError> {
            panic!("the explicit-blockhash path must not consult the index");
        });
        let block = distinct_block(4);
        let Some(wanted) = block.txdata.first().map(bitcoin::Transaction::compute_txid) else {
            panic!("block has no transactions");
        };
        let record = BlockRecord::from_block(0, &block);
        let block_hash = record.hash;
        ctx.add_block(record);

        let result = super::gettxoutproof(
            &ctx,
            &json!([[wanted.to_string()], block_hash.to_string_be()]),
        );

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the explicit-blockhash path should answer without the index: {result:?}"
        );
    }

    /// Counts probes so the loop can be pinned deterministically.
    ///
    /// `probes_every_txid_before_giving_up_on_the_index` pins the *outcome*, but
    /// only probabilistically: `wanted` is a `HashSet`, so a one-probe
    /// implementation happens to pick the resolvable txid about half the time.
    /// Resolving nothing and counting instead is deterministic.
    #[test]
    fn gettxoutproof_asks_the_index_about_every_wanted_txid() {
        let block = block_with_two_txs(13);
        let wanted = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

        let counter = Arc::clone(&probes);
        let ctx = ctx_with_index(move |_| {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(None)
        });
        ctx.add_block(BlockRecord::from_block(0, &block));

        // Resolves nothing, so this falls through to the scan and still answers.
        let result = proof_for(&ctx, &wanted);
        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the scan must still answer when the index resolves nothing: {result:?}"
        );

        assert_eq!(
            probes.load(core::sync::atomic::Ordering::Relaxed),
            wanted.len(),
            "every wanted txid must be probed before the index path gives up"
        );
    }

    /// Pins that a candidate block failing verification does not end the walk.
    ///
    /// `falls_back_when_the_indexed_block_lacks_some_wanted_txids` pins the
    /// outcome, but its index answers the same height for every probe, so
    /// "keeps probing after a failed candidate" and "gives up on the first
    /// candidate" reach the same place: the fallback scan, which answers either
    /// way. Counting probes separates them — a walk that returns whatever the
    /// first candidate produced asks exactly once.
    #[test]
    fn gettxoutproof_keeps_probing_after_a_candidate_block_fails_verification() {
        let block = block_with_two_txs(14);
        let wanted = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<Vec<_>>();
        let probes = Arc::new(core::sync::atomic::AtomicUsize::new(0));

        let counter = Arc::clone(&probes);
        // Every probe names height 0, whose block holds none of the wanted
        // txids, so every candidate fails verification.
        let ctx = ctx_with_index(move |_| {
            counter.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(Some(0))
        });
        ctx.add_block(BlockRecord::from_block(0, &distinct_block(15)));
        ctx.add_block(BlockRecord::from_block(1, &block));

        let result = proof_for(&ctx, &wanted);
        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the scan must still answer when no candidate verifies: {result:?}"
        );

        assert_eq!(
            probes.load(core::sync::atomic::Ordering::Relaxed),
            wanted.len(),
            "a candidate that does not hold every wanted txid must not end the walk"
        );
    }

    /// Pins that the block-record lock is released before each body load.
    ///
    /// The scan reads a block body from disk per record. Holding the log's
    /// `RwLock` across that would stall block application for the whole scan,
    /// and cloning the log to avoid it copies every record on the chain — about
    /// 160 MB at a mainnet tip. The walk does neither, and this proves it: the
    /// body source tries to take the write lock, which can only succeed if the
    /// scan is not holding a read guard.
    #[test]
    fn scan_does_not_hold_the_block_log_lock_across_a_body_load() {
        struct LockProbeSource {
            blocks: Arc<parking_lot::RwLock<crate::BlockLog>>,
            bodies: Vec<(u32, Vec<u8>)>,
        }

        impl crate::BlockBodySource for LockProbeSource {
            fn block_body(&self, height: u32, _hash: Hash256) -> Option<Vec<u8>> {
                assert!(
                    self.blocks.try_write().is_some(),
                    "the block-record lock must not be held across a body load"
                );
                self.bodies
                    .iter()
                    .find(|(known, _)| *known == height)
                    .map(|(_, bytes)| bytes.clone())
            }
        }

        let blocks = [distinct_block(21), distinct_block(22), distinct_block(23)];
        let Some(wanted) = blocks[2]
            .txdata
            .first()
            .map(bitcoin::Transaction::compute_txid)
        else {
            panic!("block has no transactions");
        };

        let ctx = Context::new();
        let log = Arc::clone(&ctx.blocks);
        let bodies = blocks
            .iter()
            .enumerate()
            .map(|(height, block)| {
                let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
                (height, serialize(block))
            })
            .collect::<Vec<_>>();
        let ctx = Arc::new(ctx.with_block_body_source(Arc::new(LockProbeSource {
            blocks: log,
            bodies,
        })));

        // Body-less records, so every body must come from the source above.
        for (height, block) in blocks.iter().enumerate() {
            let height = u32::try_from(height).unwrap_or_else(|err| panic!("height: {err}"));
            let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
            ctx.add_block(BlockRecord::synthetic(height, hash));
        }

        let result = proof_for(&ctx, &[wanted]);

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "the scan should answer from the body source: {result:?}"
        );
    }
}

#[cfg(test)]
mod classify_script_tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn classify_op_return_is_nulldata() {
        let script = ScriptBuf::new_op_return(b"hello");
        assert_eq!(classify_script(&script), "nulldata");
    }

    #[test]
    fn classify_empty_is_nonstandard() {
        let script = ScriptBuf::new();
        assert_eq!(classify_script(&script), "nonstandard");
    }

    #[test]
    fn script_to_address_returns_some_for_p2wpkh_on_mainnet() {
        use bitcoin::hex::FromHex as _;

        let script_hex = "00141111111111111111111111111111111111111111";
        let bytes = match Vec::<u8>::from_hex(script_hex) {
            Ok(bytes) => bytes,
            Err(error) => panic!("hex: {error}"),
        };
        let script = ScriptBuf::from_bytes(bytes);

        let address = script_to_address(&script, bitcoin_rs_primitives::Network::Mainnet);

        assert!(
            address.is_some(),
            "P2WPKH script must yield mainnet bech32 address"
        );
        let Some(addr) = address else {
            panic!("address");
        };
        assert!(
            addr.starts_with("bc1"),
            "mainnet P2WPKH should bech32-encode with bc1 prefix: {addr}"
        );
    }

    #[test]
    fn script_to_address_returns_none_for_nonstandard_script() {
        let script = ScriptBuf::new();

        assert!(script_to_address(&script, bitcoin_rs_primitives::Network::Mainnet).is_none());
    }
}
#[cfg(test)]
mod gettxout_via_utxo_tests {
    use super::*;

    #[test]
    fn gettxout_returns_null_for_unknown_outpoint() {
        let ctx = Arc::new(Context::new());
        let txid_hex = "a".repeat(64);
        let params = json!([txid_hex.as_str(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for unknown outpoint, got {value:?}"
        );
    }

    #[test]
    fn gettxout_returns_null_for_transaction_output_absent_from_utxo() {
        let ctx = Arc::new(Context::new());
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = ctx.add_transaction(tx);
        let params = json!([txid.to_string(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for output absent from UTXO set, got {value:?}"
        );
    }
}

#[cfg(test)]
mod acceptance_tests {
    use alloc::sync::Arc;

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::{sendrawtransaction, testmempoolaccept};
    use crate::context::Context;
    use crate::error::RpcError;

    fn internal_outpoint(tag: u8) -> bitcoin_rs_primitives::OutPoint {
        bitcoin_rs_primitives::OutPoint::new(Hash256::from_le_bytes(&[tag; 32]), 0)
    }

    fn spent_outpoint(tag: u8) -> bitcoin::OutPoint {
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([tag; 32]), 0)
    }

    /// Seeds one confirmed, anyone-can-spend output worth `value`.
    fn seed_utxo(ctx: &Context, tag: u8, value: u64) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            internal_outpoint(tag),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            false,
            7,
        ));
        ctx.utxo
            .commit_block(&changes, &Hash256::default())
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    }

    fn spending_tx(tag: u8, output_value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent_outpoint(tag),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([9_u8; 20])),
            }],
        }
    }

    fn hex_of(tx: &Transaction) -> String {
        serialize(tx).to_lower_hex_string()
    }

    /// The transaction must land in the mempool.
    ///
    /// It previously went into a side `HashMap` that nothing else treated as
    /// the mempool: `getmempoolinfo` reported an empty pool, mining saw no
    /// candidates, and no policy check ran at all.
    #[test]
    fn sendrawtransaction_admits_the_transaction_to_the_mempool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = sendrawtransaction(&ctx, &json!([hex_of(&tx)])) else {
            panic!("a standard transaction spending a confirmed output must be accepted");
        };

        assert_eq!(value.as_str(), Some(tx.compute_txid().to_string().as_str()));
        assert_eq!(ctx.mempool.read().len(), 1, "the pool must hold it");
        assert!(ctx.mempool.read().contains_txid(&tx.compute_txid()));
    }

    /// The default fee guard stops a transaction that burns its change.
    ///
    /// The classic shape: an input worth 1 BTC, an output worth a hundredth of
    /// it, and the rest handed to the miner. Core refuses that by default and
    /// the sender has to say they meant it. This node used to send it, and a
    /// fee is not recoverable once the transaction confirms.
    #[test]
    fn sendrawtransaction_refuses_an_absurd_fee_by_default() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 8, 100_000_000);
        // 1 BTC in, 0.01 BTC out: a 0.99 BTC fee on a ~110 vbyte transaction,
        // which is thousands of times the 0.1 BTC/kvB default ceiling.
        let tx = spending_tx(8, 1_000_000);

        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx)]))
            .err()
            .unwrap_or_else(|| panic!("an absurd fee must not be sent by default"));

        assert_eq!(
            error.code(),
            RpcError::CORE_VERIFY_ERROR,
            "a caller-configured guard is not a network rejection: {error:?}"
        );
        assert_eq!(ctx.mempool.read().len(), 0, "and nothing was admitted");
    }

    /// The guard is the caller's to lift, and the ceiling is a *rate*.
    ///
    /// Zero disables it outright. Any other value is BTC per kvB, turned into
    /// an absolute fee for this transaction's vsize -- so 0.99 BTC/kvB on a
    /// ~110-vbyte transaction is a ceiling near 0.109 BTC, and a 0.99 BTC fee
    /// is still far above it. Reading the argument as an absolute cap would
    /// send that transaction.
    #[test]
    fn the_fee_ceiling_is_a_rate_and_zero_disables_it() {
        let disabled = {
            let ctx = Arc::new(Context::new());
            seed_utxo(&ctx, 9, 100_000_000);
            let tx = spending_tx(9, 1_000_000);
            let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0]));
            assert_eq!(ctx.mempool.read().len(), 1, "zero sends it: {sent:?}");
            sent
        };
        assert!(disabled.is_ok(), "{disabled:?}");

        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 12, 100_000_000);
        let tx = spending_tx(12, 1_000_000);
        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 0.99]))
            .err()
            .unwrap_or_else(|| panic!("0.99 BTC/kvB is a ceiling, not a fee allowance"));
        assert_eq!(error.code(), RpcError::CORE_VERIFY_ERROR, "{error:?}");
        assert_eq!(ctx.mempool.read().len(), 0);
    }

    /// A ceiling the transaction stays under changes nothing.
    #[test]
    fn sendrawtransaction_admits_a_fee_below_the_ceiling() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 10, 100_000);
        // A ~10_000 sat fee on ~110 vbytes, well under the default ceiling.
        let tx = spending_tx(10, 90_000);

        let sent = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        assert!(sent.is_ok(), "an ordinary fee is not capped: {sent:?}");
        assert_eq!(ctx.mempool.read().len(), 1);
    }

    /// Core refuses a ceiling of one whole coin per kvB as a parameter.
    #[test]
    fn sendrawtransaction_refuses_a_fee_rate_of_a_whole_coin() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 11, 100_000);
        let tx = spending_tx(11, 90_000);

        let error = sendrawtransaction(&ctx, &json!([hex_of(&tx), 1.0]))
            .err()
            .unwrap_or_else(|| panic!("1 BTC/kvB must be refused"));

        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER, "{error:?}");
        assert_eq!(ctx.mempool.read().len(), 0);
    }

    /// A rejection must say why, under Core's `RPC_VERIFY_REJECTED` code.
    #[test]
    fn sendrawtransaction_rejects_a_transaction_whose_inputs_do_not_exist() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        let Err(error) = outcome else {
            panic!("a transaction with no resolvable inputs must not be accepted");
        };
        assert!(
            matches!(error, RpcError::TxRejected(_)),
            "expected a rejection, got {error:?}"
        );
        assert_eq!(error.code(), RpcError::CORE_VERIFY_REJECTED);
        assert!(ctx.mempool.read().is_empty());
    }

    /// Core rebroadcasts rather than failing, and callers retry on a dropped
    /// connection expecting that to be safe.
    #[test]
    fn sendrawtransaction_is_idempotent_for_a_transaction_already_in_the_pool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);
        let params = json!([hex_of(&tx)]);
        let Ok(first) = sendrawtransaction(&ctx, &params) else {
            panic!("the first submission must succeed");
        };

        let Ok(second) = sendrawtransaction(&ctx, &params) else {
            panic!("resubmitting a transaction already in the mempool must not fail");
        };

        assert_eq!(first.as_str(), second.as_str());
        assert_eq!(ctx.mempool.read().len(), 1, "it must not be inserted twice");
    }

    /// The verdict must come from the acceptance checks.
    ///
    /// This RPC used to answer `allowed: true` for anything that merely
    /// decoded, so a transaction spending outputs that do not exist was
    /// reported as acceptable.
    #[test]
    fn testmempoolaccept_rejects_a_transaction_that_only_decodes() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(rows) = value.as_array() else {
            panic!("testmempoolaccept must return an array");
        };
        let Some(row) = rows.first() else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(false));
        assert!(
            row.get("reject-reason")
                .as_str()
                .is_some_and(|r| !r.is_empty()),
            "a rejection must carry a reason"
        );
    }

    #[test]
    fn testmempoolaccept_allows_a_transaction_without_admitting_it() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(true));
        assert_eq!(
            row.get("vsize").as_u64(),
            u64::try_from(tx.vsize()).ok(),
            "vsize must be the transaction's, not a placeholder"
        );
        assert!(
            ctx.mempool.read().is_empty(),
            "testing acceptance must not accept"
        );
    }

    /// `wtxid` was a copy of `txid`. They differ for any witness transaction,
    /// and package relay identifies transactions by the witness id.
    #[test]
    fn testmempoolaccept_reports_the_witness_txid() {
        let ctx = Arc::new(Context::new());
        let mut tx = spending_tx(4, 90_000);
        tx.input[0].witness.push([1_u8; 8]);
        assert_ne!(
            tx.compute_txid().to_string(),
            tx.compute_wtxid().to_string(),
            "the fixture must carry a witness or this proves nothing"
        );

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(
            row.get("txid").as_str(),
            Some(tx.compute_txid().to_string().as_str())
        );
        assert_eq!(
            row.get("wtxid").as_str(),
            Some(tx.compute_wtxid().to_string().as_str())
        );
    }

    /// Standardness is relay policy, and Core relaxes it only on regtest.
    ///
    /// The mempool crate tests the gate itself; this covers the wiring that
    /// decides the flag, which is the half that can silently invert.
    #[test]
    fn standardness_is_relaxed_on_regtest_only() {
        let non_standard = || {
            let mut tx = spending_tx(1, 90_000);
            // Consensus-valid, non-standard.
            tx.version = Version(4);
            tx
        };

        let mainnet = Arc::new(Context::new());
        assert_eq!(
            mainnet.chain_network,
            bitcoin_rs_primitives::Network::Mainnet,
            "the fixture assumes the default context is mainnet"
        );
        seed_utxo(&mainnet, 1, 100_000);
        assert!(
            sendrawtransaction(&mainnet, &json!([hex_of(&non_standard())])).is_err(),
            "mainnet must enforce standardness"
        );

        let mut regtest = Context::new();
        regtest.chain_network = bitcoin_rs_primitives::Network::Regtest;
        let regtest = Arc::new(regtest);
        seed_utxo(&regtest, 1, 100_000);
        assert!(
            sendrawtransaction(&regtest, &json!([hex_of(&non_standard())])).is_ok(),
            "regtest must accept the same transaction"
        );
    }
}
