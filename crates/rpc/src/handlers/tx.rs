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
    if let Some(indexer) = &ctx.indexer {
        let tx = indexer
            .lock()
            .resolve_transaction(txid, ctx.as_ref())
            .map_err(|error| RpcError::Internal(format!("txindex lookup failed: {error}")))?;
        if let Some(tx) = tx {
            if !verbose {
                return Ok(json!(serialize(&tx).to_lower_hex_string()));
            }
            return super::tx_render::tx_to_value(&tx);
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
        return proof_from_records(ctx, &[record], &wanted);
    }

    // Without a block hash the scan below reads, deserializes and hashes every
    // block on the chain to answer one call. The txindex already knows which
    // block confirms a txid, so ask it first and scan only when it cannot
    // answer — the same route Bitcoin Core takes, which requires the block hash
    // *unless* txindex is enabled.
    if let Some(proof) = proof_via_index(ctx, &wanted)? {
        return Ok(proof);
    }
    let blocks = ctx.blocks.read().clone();
    proof_from_records(ctx, &blocks, &wanted)
}

/// Answers `gettxoutproof` from the txindex, or `None` when it cannot.
///
/// Resolves the confirming height of one wanted txid and tries to build the
/// proof from that block alone. Every miss — no indexer, an unresolved or stale
/// row, a pruned body, or a block that does not hold *all* the wanted txids —
/// returns `None` so the caller falls back to the scan. That fallback is not
/// belt-and-braces: BIP30's duplicate coinbase txids mean a txid can confirm in
/// more than one block, so a block chosen from a single txid is a candidate,
/// never a verdict.
fn proof_via_index(
    ctx: &Arc<Context>,
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Option<Value>, RpcError> {
    let Some(indexer) = &ctx.indexer else {
        return Ok(None);
    };
    let Some(probe) = wanted.iter().next() else {
        return Ok(None);
    };
    let height = indexer
        .lock()
        .resolve_transaction_height(*probe, ctx.as_ref())
        .map_err(|error| RpcError::Internal(format!("txindex lookup failed: {error}")))?;
    let Some(height) = height else {
        return Ok(None);
    };
    let Some(record) = ctx.block_by_height(height) else {
        return Ok(None);
    };
    Ok(proof_from_record(ctx, &record, wanted))
}

/// Builds the merkle proof from the first record whose block holds every wanted
/// txid, or reports why none did.
///
/// This is the pre-index path, kept whole: it is the fallback whenever the
/// index cannot answer, the oracle the equivalence tests compare against, and
/// the `before` arm of the benchmark.
/// Builds the merkle proof from the first record whose block holds every wanted
/// txid, or reports why none did.
///
/// This is the pre-index path, kept whole: it is the fallback whenever the
/// index cannot answer, the oracle the equivalence tests compare against, and
/// the `before` arm of the benchmark. Each record's body is loaded exactly once
/// so the arm measures the scan itself, not a doubled read.
fn proof_from_records(
    ctx: &Arc<Context>,
    records: &[crate::context::BlockRecord],
    wanted: &hashbrown::HashSet<Txid>,
) -> Result<Value, RpcError> {
    let mut saw_pruned_block = false;
    for record in records {
        let Some(bytes) = ctx.block_body_bytes(record) else {
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

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    let txid = ctx.add_transaction(tx);
    Ok(json!(txid.to_string()))
}

pub(crate) fn testmempoolaccept(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw_txs = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let mut rows = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        let decoded = decode_tx(raw);
        let txid = decoded.as_ref().map_or_else(
            |_| Hash256::default().to_string_be(),
            |tx| tx.compute_txid().to_string(),
        );
        rows.push(json!({
            "txid": txid,
            "wtxid": txid,
            "allowed": decoded.is_ok(),
            "vsize": decoded.as_ref().map_or(0, Transaction::vsize),
            "fees": {"base": 0.0}
        }));
    }
    Ok(json!(rows))
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

    use bitcoin::Txid;
    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::Hash256;
    use parking_lot::Mutex;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::getrawtransaction;
    use crate::Handler;
    use crate::context::{BlockRecord, Context};
    use crate::error::RpcError;

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
        struct FailingIndexer;

        impl IndexerLike for FailingIndexer {
            fn ingest_block(
                &mut self,
                _block: &[u8],
                _height: u32,
            ) -> Result<IndexRowCounts, IndexError> {
                Ok(IndexRowCounts::default())
            }

            fn resolve_transaction(
                &self,
                _txid: Txid,
                _source: &dyn BlockSource,
            ) -> Result<Option<bitcoin::Transaction>, IndexError> {
                Err(IndexError::InvalidHeaderLength { len: 0 })
            }

            fn resolve_outpoint_value(
                &self,
                _outpoint: bitcoin::OutPoint,
                _source: &dyn BlockSource,
            ) -> Result<Option<u64>, IndexError> {
                Ok(None)
            }
        }

        let mut ctx = Context::new();
        let indexer: Box<dyn IndexerLike> = Box::new(FailingIndexer);
        ctx.indexer = Some(Arc::new(Mutex::new(indexer)));
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
        struct StaticIndexer {
            tx: bitcoin::Transaction,
        }

        impl IndexerLike for StaticIndexer {
            fn ingest_block(
                &mut self,
                _block: &[u8],
                _height: u32,
            ) -> Result<IndexRowCounts, IndexError> {
                Ok(IndexRowCounts::default())
            }

            fn resolve_transaction(
                &self,
                txid: Txid,
                _source: &dyn BlockSource,
            ) -> Result<Option<bitcoin::Transaction>, IndexError> {
                Ok((self.tx.compute_txid() == txid).then(|| self.tx.clone()))
            }

            fn resolve_outpoint_value(
                &self,
                _outpoint: bitcoin::OutPoint,
                _source: &dyn BlockSource,
            ) -> Result<Option<u64>, IndexError> {
                Ok(None)
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first().cloned() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut ctx = Context::new();
        let indexer: Box<dyn IndexerLike> = Box::new(StaticIndexer {
            tx: coinbase.clone(),
        });
        ctx.indexer = Some(Arc::new(Mutex::new(indexer)));
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

    /// Reports whatever height it was built with, standing in for the txindex.
    struct HeightIndexer(Option<u32>);

    impl IndexerLike for HeightIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<IndexRowCounts, IndexError> {
            Ok(IndexRowCounts::default())
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: bitcoin::OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, IndexError> {
            Ok(None)
        }

        fn resolve_transaction_height(
            &self,
            _txid: Txid,
            _source: &dyn BlockSource,
        ) -> Result<Option<u32>, IndexError> {
            Ok(self.0)
        }
    }

    fn ctx_with_height_indexer(height: Option<u32>) -> Arc<Context> {
        let mut ctx = Context::new();
        let indexer: Box<dyn IndexerLike> = Box::new(HeightIndexer(height));
        ctx.indexer = Some(Arc::new(Mutex::new(indexer)));
        Arc::new(ctx)
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

        let index_ctx = ctx_with_height_indexer(Some(2));
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
        let indexer: Box<dyn IndexerLike> = Box::new(HeightIndexer(Some(2)));
        ctx.indexer = Some(Arc::new(Mutex::new(indexer)));
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

        let ctx = ctx_with_height_indexer(None);
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

        let index_ctx = ctx_with_height_indexer(Some(0));
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

        let index_ctx = ctx_with_height_indexer(Some(0));
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
