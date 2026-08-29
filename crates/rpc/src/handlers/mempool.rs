use alloc::collections::BTreeMap;
use alloc::sync::Arc;

use bitcoin_rs_mempool::MempoolEntry;
use sonic_rs::Value;

use crate::compat::convert::{i64_saturated, sat_to_btc, signed_sat_to_btc, typed_to_sonic};
use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, parse_txid, required_str};
use corepc_types::v31;

// Bitcoin Core default for incremental relay-fee policy until per-node
// configuration is wired. Units: sat/kvB (the canonical workspace internal).
// 1000 sat/kvB = 1 sat/vB = 0.00001 BTC/kvB.
const DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB: u64 = 1_000;

pub(crate) fn getmempoolinfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    crate::handlers::ensure_no_params(params)?;
    let pool = ctx.mempool.read();
    let stats = pool.stats();
    let maxmempool = pool.limits.max_total_bytes;
    let live_min_relay_sat_per_kvb = pool.min_relay_fee_sat_per_kvb();
    // `mempoolminfee` rises above `minrelaytxfee` when the pool approaches its
    // `maxmempool` byte limit. Bitcoin Core uses the eviction-floor heuristic:
    // once the pool exceeds 50% of `maxmempool`, new txs must pay strictly
    // more than the cheapest currently-evictable tx by `incrementalrelayfee`.
    let mempool_min_fee_sat_per_kvb = if maxmempool > 0
        && stats.bytes.saturating_mul(2) >= maxmempool
        && let Some(lowest) = pool.lowest_fee_rate()
    {
        live_min_relay_sat_per_kvb
            .max(lowest.saturating_add(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB))
    } else {
        live_min_relay_sat_per_kvb
    };
    typed_to_sonic(&v31::GetMempoolInfo {
        loaded: true,
        size: i64_saturated(stats.txs),
        bytes: i64_saturated(stats.bytes),
        usage: i64_saturated(stats.bytes),
        total_fee: sat_to_btc(stats.total_fee),
        max_mempool: i64_saturated(maxmempool),
        mempool_min_fee: sat_to_btc(mempool_min_fee_sat_per_kvb),
        min_relay_tx_fee: sat_to_btc(live_min_relay_sat_per_kvb),
        incremental_relay_fee: sat_to_btc(DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB),
        unbroadcast_count: 0,
        full_rbf: true,
        permit_bare_multisig: true,
        max_data_carrier_size: 83,
        limit_cluster_count: 64,
        limit_cluster_size: 101_000,
        optimal: true,
    })
}

pub(crate) fn getmempoolentry(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let pool = ctx.mempool.read();
    let entry = pool
        .entry_by_txid(&txid)
        .ok_or(RpcError::NotFound("transaction not in mempool"))?;
    typed_to_sonic(&v31::GetMempoolEntry(mempool_entry_typed(entry, &pool)))
}

pub(crate) fn getrawmempool(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let verbose = optional_bool(params, 0, false)?;
    let include_sequence = optional_bool(params, 1, false)?;
    if verbose && include_sequence {
        // Core's MempoolToJSON rejects this combination with
        // RPC_INVALID_PARAMETER; the REST twin enforces the same rule.
        return Err(RpcError::InvalidParams(
            "Verbose results cannot contain mempool sequence values.",
        ));
    }
    let pool = ctx.mempool.read();
    if verbose {
        let mut map = BTreeMap::new();
        for txid in pool.iter_txids() {
            if let Some(entry) = pool.entry_by_txid(&txid) {
                map.insert(txid.to_string(), mempool_entry_typed(entry, &pool));
            }
        }
        return typed_to_sonic(&v31::GetRawMempoolVerbose(map));
    }

    let txids: Vec<String> = pool
        .iter_txids()
        .into_iter()
        .map(|txid| txid.to_string())
        .collect();
    if include_sequence {
        return typed_to_sonic(&v31::GetRawMempoolSequence {
            txids,
            mempool_sequence: pool.sequence_number(),
        });
    }
    typed_to_sonic(&v31::GetRawMempool(txids))
}

pub(crate) fn getmempoolancestors(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(id) = pool.entry_id_by_txid(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.ancestor_ids_for_entry(id);
    render_ancestors(&pool, &related_ids, verbose)
}

pub(crate) fn getmempooldescendants(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let pool = ctx.mempool.read();
    let Some(id) = pool.entry_id_by_txid(&txid) else {
        return Err(RpcError::NotFound("transaction not in mempool"));
    };
    let related_ids = pool.descendant_ids_for_entry(id);
    render_descendants(&pool, &related_ids, verbose)
}

fn mempool_entry_typed(
    entry: &MempoolEntry,
    pool: &bitcoin_rs_mempool::Mempool,
) -> v31::MempoolEntry {
    let mut depends = entry
        .tx
        .inputs
        .iter()
        .map(|input| input.previous_output.txid)
        .filter(|txid| pool.contains_txid(txid))
        .map(|txid| txid.to_string())
        .collect::<Vec<_>>();
    depends.sort();
    depends.dedup();

    let entry_id = pool.entry_id_by_txid(&entry.txid);
    let mut spentby = entry_id
        .map(|id| pool.spender_txids(id))
        .unwrap_or_default()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    spentby.sort();
    spentby.dedup();
    let (descendantcount, ancestorcount) = entry_id.map_or((1, 1), |id| {
        (
            pool.descendant_count_inclusive(id),
            pool.ancestor_count_inclusive(id),
        )
    });

    // No cluster diagram is tracked, so `chunk*` fields approximate a
    // singleton cluster: the transaction's own weight and fee.
    let fees = v31::MempoolEntryFees {
        base: sat_to_btc(entry.fee),
        modified: signed_sat_to_btc(entry.modified_fee()),
        ancestor: signed_sat_to_btc(i128::from(entry.ancestor_fee) + entry.ancestor_fee_delta),
        descendant: signed_sat_to_btc(
            i128::from(entry.descendant_fee) + entry.descendant_fee_delta,
        ),
        chunk: sat_to_btc(entry.fee),
    };
    v31::MempoolEntry {
        vsize: i64_saturated(u64::from(entry.vsize)),
        weight: i64_saturated(entry.weight),
        time: i64_saturated(entry.time),
        height: i64::from(entry.height),
        descendant_count: i64::from(descendantcount),
        descendant_size: i64_saturated(entry.descendant_size),
        ancestor_count: i64::from(ancestorcount),
        ancestor_size: i64_saturated(entry.ancestor_size),
        chunk_weight: i64_saturated(entry.weight),
        wtxid: entry.wtxid.to_string(),
        fees,
        depends,
        spent_by: spentby,
        bip125_replaceable: entry.is_replaceable(),
        unbroadcast: false,
    }
}

fn render_ancestors(
    pool: &bitcoin_rs_mempool::Mempool,
    ids: &[bitcoin_rs_mempool::EntryId],
    verbose: bool,
) -> Result<Value, RpcError> {
    if verbose {
        let mut map = BTreeMap::new();
        for id in ids {
            if let Some(entry) = pool.entry(*id) {
                map.insert(entry.txid.to_string(), mempool_entry_typed(entry, pool));
            }
        }
        return typed_to_sonic(&v31::GetMempoolAncestorsVerbose(map));
    }
    let names = ids
        .iter()
        .filter_map(|id| pool.entry(*id))
        .map(|entry| entry.txid.to_string())
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::GetMempoolAncestors(names))
}

fn render_descendants(
    pool: &bitcoin_rs_mempool::Mempool,
    ids: &[bitcoin_rs_mempool::EntryId],
    verbose: bool,
) -> Result<Value, RpcError> {
    if verbose {
        let mut map = BTreeMap::new();
        for id in ids {
            if let Some(entry) = pool.entry(*id) {
                map.insert(entry.txid.to_string(), mempool_entry_typed(entry, pool));
            }
        }
        return typed_to_sonic(&v31::GetMempoolDescendantsVerbose(map));
    }
    let names = ids
        .iter()
        .filter_map(|id| pool.entry(*id))
        .map(|entry| entry.txid.to_string())
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::GetMempoolDescendants(names))
}

#[cfg(test)]
mod mempoolminfee_pressure_tests {
    use std::sync::Arc;

    use super::*;
    use sonic_rs::JsonValueTrait;
    use sonic_rs::json;

    #[test]
    fn mempoolminfee_equals_minrelay_when_pool_below_pressure() {
        let ctx = Arc::new(Context::new());
        // Empty pool, default limits: mempoolminfee == minrelaytxfee.
        let value =
            getmempoolinfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmempoolinfo: {err}"));
        let Some(mempool_min) = value.get("mempoolminfee").and_then(JsonValueTrait::as_f64) else {
            panic!("mempoolminfee missing");
        };
        let Some(min_relay) = value.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
            panic!("minrelaytxfee missing");
        };
        // Both should equal the default 0.00001 BTC/kvB (1000 sat/kvB).
        assert!((mempool_min - min_relay).abs() < 1e-9);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use sonic_rs::{JsonContainerTrait, JsonValueTrait, json};

    use super::*;

    #[test]
    fn getmempoolinfo_emits_one_sat_per_vbyte_default_for_relay_fees() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
        let Some(min_relay) = result.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
            panic!("minrelaytxfee missing: {result:?}");
        };

        // 1000 sat/kvB / 100_000_000 = 0.00001
        assert!(
            (min_relay - 0.00001).abs() < 1e-9,
            "expected ~0.00001, got {min_relay}"
        );
    }

    #[test]
    fn getmempoolinfo_minrelaytxfee_reflects_custom_mempool_floor() {
        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.write();
            *pool = bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits {
                min_relay_fee_sat_per_kvb: 5_000,
                ..bitcoin_rs_mempool::MempoolLimits::default()
            });
        }

        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
        let Some(min_relay) = result.get("minrelaytxfee").and_then(JsonValueTrait::as_f64) else {
            panic!("minrelaytxfee missing: {result:?}");
        };
        let Some(mempool_min_fee) = result.get("mempoolminfee").and_then(JsonValueTrait::as_f64)
        else {
            panic!("mempoolminfee missing: {result:?}");
        };

        assert!(
            (min_relay - 0.00005).abs() < 1e-9,
            "expected ~0.00005, got {min_relay}"
        );
        assert!(
            (mempool_min_fee - 0.00005).abs() < 1e-9,
            "expected ~0.00005, got {mempool_min_fee}"
        );
    }

    #[test]
    fn getmempoolinfo_maxmempool_reflects_custom_limit() {
        let ctx = Context::new();
        *ctx.mempool.write() =
            bitcoin_rs_mempool::Mempool::new(bitcoin_rs_mempool::MempoolLimits {
                max_total_bytes: 50_000_000,
                ..bitcoin_rs_mempool::MempoolLimits::default()
            });
        let ctx = Arc::new(ctx);
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
        let Some(maxmempool) = result.get("maxmempool").and_then(JsonValueTrait::as_u64) else {
            panic!("maxmempool missing: {result:?}");
        };
        assert_eq!(maxmempool, 50_000_000);
    }

    #[test]
    fn getmempoolinfo_omits_mempool_sequence_like_core() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolinfo", &json!([]))
            .unwrap_or_else(|err| panic!("getmempoolinfo failed: {err}"));
        // Core's getmempoolinfo carries no mempool_sequence; the sequence
        // counter belongs to `getrawmempool` with sequence=true. The pinned
        // v31::GetMempoolInfo shape matches, and this defends against a
        // hand-built field reappearing.
        assert!(
            result.get("mempool_sequence").is_none(),
            "mempool_sequence must stay absent from getmempoolinfo: {result:?}"
        );
    }

    #[test]
    fn getrawmempool_with_sequence_flag_wraps_response() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getrawmempool", &json!([false, true]))
            .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
        let Some(seq) = result
            .get("mempool_sequence")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("mempool_sequence missing: {result:?}");
        };
        assert_eq!(seq, 0);
        let Some(txids) = result.get("txids").and_then(JsonContainerTrait::as_array) else {
            panic!("txids missing: {result:?}");
        };
        assert!(txids.is_empty());
    }

    #[test]
    fn getrawmempool_without_sequence_flag_returns_bare_array() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getrawmempool", &json!([]))
            .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
        assert!(result.is_array(), "expected bare array: {result:?}");
    }

    #[test]
    fn getrawmempool_verbose_with_sequence_is_rejected() {
        // Core's MempoolToJSON rejects verbose=true with mempool_sequence=true
        // with RPC_INVALID_PARAMETER. The REST twin enforces the same rule.
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let error = handler
            .dispatch("getrawmempool", &json!([true, true]))
            .expect_err("verbose+sequence must be rejected");
        assert!(matches!(
            error,
            RpcError::InvalidParams(msg) if msg.contains("Verbose results cannot contain mempool sequence values")
        ));
    }

    #[test]
    fn getmempooldescendants_walks_real_descendant_graph() -> Result<(), Box<dyn std::error::Error>>
    {
        let ctx = Arc::new(Context::new());
        let parent = tx(1, Vec::new());
        let parent_txid = parent.txid();
        let child = tx(2, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid().to_string();
        {
            let mut pool = ctx.mempool.write();
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;
        }

        let result = getmempooldescendants(&ctx, &json!([parent_txid.to_string()]))?;
        let Some(array) = result.as_array() else {
            return Err("expected descendants array".into());
        };

        assert_eq!(array.len(), 1);
        assert_eq!(
            array.first().and_then(|value| value.as_str()),
            Some(child_txid.as_str())
        );
        Ok(())
    }

    #[test]
    fn getmempoolancestors_walks_real_ancestor_graph() -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let parent = tx(3, Vec::new());
        let parent_txid = parent.txid();
        let parent_txid_string = parent_txid.to_string();
        let child = tx(4, vec![OutPoint::new(parent_txid, 0)]);
        let child_txid = child.txid();
        {
            let mut pool = ctx.mempool.write();
            pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 1_000, 0, 0))?;
            pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 0, 0))?;
        }

        let result = getmempoolancestors(&ctx, &json!([child_txid.to_string()]))?;
        let Some(array) = result.as_array() else {
            return Err("expected ancestors array".into());
        };

        assert_eq!(array.len(), 1);
        assert_eq!(
            array.first().and_then(|value| value.as_str()),
            Some(parent_txid_string.as_str())
        );
        Ok(())
    }

    #[test]
    fn getmempoolentry_emits_depends_when_input_spends_mempool_tx() {
        let ctx = Arc::new(Context::new());
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let parent = Tx {
            version: 2,
            lock_time: 0,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let parent_txid = parent.txid();
        let child = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: Vec::new(),
        };
        let child_txid = child.txid();
        {
            let mut pool = ctx.mempool.write();
            let parent_entry =
                bitcoin_rs_mempool::MempoolEntry::new(Arc::new(parent), 100, 1_000, 1, 7);
            let Ok(_) = pool.insert_entry(parent_entry) else {
                panic!("parent insert failed");
            };
            let child_entry =
                bitcoin_rs_mempool::MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 7);
            let Ok(_) = pool.insert_entry(child_entry) else {
                panic!("child insert failed");
            };
        }
        let result = handler
            .dispatch("getmempoolentry", &json!([child_txid.to_string()]))
            .unwrap_or_else(|err| panic!("getmempoolentry: {err}"));
        let Some(depends) = result.get("depends").and_then(JsonContainerTrait::as_array) else {
            panic!("depends missing: {result:?}");
        };
        assert_eq!(depends.len(), 1, "expected one depends entry");
    }

    #[test]
    fn getmempoolentry_bip125_replaceable_reflects_input_sequence() {
        let ctx = Arc::new(Context::new());
        let rbf_tx = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid(Hash256::from_le_bytes(&[0xaa; 32])),
                    vout: 0,
                },
                script_sig: Vec::new(),
                sequence: 0x0000_0001,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: vec![0x51],
            }],
        };
        let rbf_txid = rbf_tx.txid();
        {
            let mut pool = ctx.mempool.write();
            let Ok(_) = pool.insert_entry(MempoolEntry::new(Arc::new(rbf_tx), 100, 10_000, 1, 7))
            else {
                panic!("mempool insert failed");
            };
        }
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolentry", &json!([rbf_txid.to_string()]))
            .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
        assert_eq!(
            result
                .get("bip125-replaceable")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
    }

    fn tx(label: u8, previous_outputs: Vec<OutPoint>) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: previous_outputs
                .into_iter()
                .map(|previous_output| TxIn {
                    previous_output,
                    script_sig: Vec::new(),
                    sequence: u32::MAX,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: vec![TxOut {
                value: 5_000 + u64::from(label),
                script_pubkey: vec![label],
            }],
        }
    }
}

#[cfg(test)]
mod spentby_tests {
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use bitcoin_rs_mempool::{Mempool, MempoolEntry};
    use bitcoin_rs_primitives::{Hash256, OutPoint, Tx, TxIn, TxOut, Txid};
    use core::str::FromStr as _;
    use sonic_rs::json;

    use super::*;

    fn entry_to_serde(entry: &MempoolEntry, pool: &Mempool) -> serde_json::Value {
        let typed = super::mempool_entry_typed(entry, pool);
        let rendered = sonic_rs::to_string(&typed)
            .unwrap_or_else(|err| panic!("re-encoding mempool entry failed: {err}"));
        serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing mempool entry failed: {err}"))
    }

    /// The answer `entry_to_serde` used to compute: for every entry in the pool,
    /// walk its inputs and keep it if any of them spends `txid`.
    ///
    /// Spelled out here instead of being shared with the implementation. An
    /// oracle that calls the code under test cannot disagree with it.
    fn spentby_by_scanning_every_entry(pool: &Mempool, txid: Txid) -> Vec<String> {
        let mut spentby = Vec::new();
        for (_id, candidate) in &pool.entries {
            for input in &candidate.tx.inputs {
                if input.previous_output.txid == txid {
                    spentby.push(candidate.tx.txid().to_string());
                    break;
                }
            }
        }
        spentby.sort();
        spentby.dedup();
        spentby
    }

    fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: inputs
                .iter()
                .map(|previous_output| TxIn {
                    previous_output: *previous_output,
                    script_sig: Vec::new(),
                    sequence: 0xFFFF_FFFD,
                    witness: Vec::new(),
                })
                .collect(),
            outputs: (0..outputs)
                .map(|vout| TxOut {
                    value: 10_000_u64
                        .saturating_add(u64::from(vout))
                        .saturating_add(tag.saturating_mul(1_000)),
                    script_pubkey: vec![0x51],
                })
                .collect(),
        }
    }

    /// A pool whose spend graph is not a chain:
    ///
    /// ```text
    ///   root ──vout 0──> child_a ──vout 0──> child_c
    ///        ──vout 1──> child_b
    ///        ──vout 2──> child_b
    ///   loner (spends nothing in the pool)
    /// ```
    ///
    /// So `root` has two spenders, `child_a` one, and everything else none.
    /// `child_b` spends two of the root's outputs, so a walk of the spend index
    /// reaches it twice — the case a missing dedup shows up in, and the case a
    /// fixture where every child spends one output cannot reach.
    fn graph_ctx() -> (Arc<Context>, Txid) {
        let confirmed = OutPoint::new(Txid(Hash256::from_le_bytes(&[7_u8; 32])), 0);
        let root = tx_with(&[confirmed], 3, 1);
        let root_txid = root.txid();
        let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
        let child_a_txid = child_a.txid();
        let child_b = tx_with(
            &[OutPoint::new(root_txid, 1), OutPoint::new(root_txid, 2)],
            1,
            3,
        );
        let child_c = tx_with(&[OutPoint::new(child_a_txid, 0)], 1, 4);
        let loner = tx_with(
            &[OutPoint::new(Txid(Hash256::from_le_bytes(&[9_u8; 32])), 0)],
            1,
            5,
        );

        // `spentby` is rendered in txid order, but the spend index answers in
        // `EntryId` — that is, insertion — order. Insert the root's two spenders
        // highest-txid-first so the two orders are opposite: a rendering that
        // forgets to sort then produces a visibly different list, instead of
        // passing because the fixture happened to be inserted in order already.
        let root_spenders = if child_a.txid() > child_b.txid() {
            [child_a, child_b]
        } else {
            [child_b, child_a]
        };
        let [first_spender, second_spender] = root_spenders;

        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.write();
            for tx in [root, first_spender, second_spender, child_c, loner] {
                let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
                let Ok(_id) = pool.insert_entry(entry) else {
                    panic!("mempool insert failed while building the fixture");
                };
            }
        }
        (ctx, root_txid)
    }

    fn rendered_spentby(value: &serde_json::Value) -> Vec<String> {
        let Some(array) = value.get("spentby").and_then(serde_json::Value::as_array) else {
            panic!("spentby missing from {value}");
        };
        array
            .iter()
            .map(|item| {
                item.as_str()
                    .unwrap_or_else(|| panic!("spentby entry is not a string: {item}"))
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn spentby_matches_the_scan_it_replaced_for_every_entry() {
        let (ctx, root_txid) = graph_ctx();
        let pool = ctx.mempool.read();

        let mut spenders_seen = 0_usize;
        for (_id, entry) in &pool.entries {
            let expected = spentby_by_scanning_every_entry(&pool, entry.txid);
            spenders_seen = spenders_seen.saturating_add(expected.len());
            assert_eq!(
                rendered_spentby(&entry_to_serde(entry, &pool)),
                expected,
                "spentby diverged from the scan for {}",
                entry.txid
            );
        }

        // Without this the equality above would pass on a pool where nothing
        // spends anything, which is exactly the fixture this bug survived.
        assert_eq!(
            spenders_seen, 3,
            "the fixture must exercise spenders: root has 2, child_a has 1"
        );
        assert_eq!(
            spentby_by_scanning_every_entry(&pool, root_txid).len(),
            2,
            "root must be spent by two transactions"
        );
    }

    #[test]
    fn getrawmempool_verbose_spentby_matches_the_scan_for_every_key() {
        let (ctx, _root_txid) = graph_ctx();
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getrawmempool", &json!([true]))
            .unwrap_or_else(|err| panic!("getrawmempool failed: {err}"));
        let rendered = sonic_rs::to_string(&result)
            .unwrap_or_else(|err| panic!("re-encoding the response failed: {err}"));
        let rendered: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing the response failed: {err}"));
        let Some(object) = rendered.as_object() else {
            panic!("verbose getrawmempool must answer an object: {rendered}");
        };

        let pool = ctx.mempool.read();
        assert_eq!(object.len(), pool.len(), "one key per mempool entry");
        for (txid, entry) in object {
            let txid = Txid::from_str(txid)
                .unwrap_or_else(|err| panic!("key {txid} is not a txid: {err}"));
            assert_eq!(
                rendered_spentby(entry),
                spentby_by_scanning_every_entry(&pool, txid),
                "spentby diverged for key {txid}"
            );
        }
    }

    #[test]
    fn getmempoolentry_reports_every_spender_of_the_root() {
        let (ctx, root_txid) = graph_ctx();
        let expected = {
            let pool = ctx.mempool.read();
            spentby_by_scanning_every_entry(&pool, root_txid)
        };
        let handler = crate::Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("getmempoolentry", &json!([root_txid.to_string()]))
            .unwrap_or_else(|err| panic!("getmempoolentry failed: {err}"));
        let rendered = sonic_rs::to_string(&result)
            .unwrap_or_else(|err| panic!("re-encoding the response failed: {err}"));
        let rendered: serde_json::Value = serde_json::from_str(&rendered)
            .unwrap_or_else(|err| panic!("re-parsing the response failed: {err}"));
        assert_eq!(rendered_spentby(&rendered), expected);
    }
}
