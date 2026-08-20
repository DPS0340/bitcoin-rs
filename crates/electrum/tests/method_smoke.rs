//! Smoke coverage for Task 17 Electrum protocol methods.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_electrum::methods::scripthash_hex;
use bitcoin_rs_electrum::{IndexHandle, MempoolHandle, dispatch};
use bitcoin_rs_index::ScriptHash;
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

#[test]
fn server_methods_return_electrum_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;

    let version = dispatch(
        "server.version",
        &fixture.index,
        &fixture.mempool,
        &json!(["client", ["1.4", "1.4"]]),
    )?;
    assert!(version.as_array().is_some_and(|array| array.len() == 2));

    assert!(
        dispatch(
            "server.banner",
            &fixture.index,
            &fixture.mempool,
            &json!([])
        )?
        .is_str()
    );
    assert!(
        dispatch(
            "server.donation_address",
            &fixture.index,
            &fixture.mempool,
            &json!([]),
        )?
        .is_null()
    );
    assert!(
        dispatch(
            "server.peers.subscribe",
            &fixture.index,
            &fixture.mempool,
            &json!([]),
        )?
        .as_array()
        .is_some()
    );
    assert!(dispatch("server.ping", &fixture.index, &fixture.mempool, &json!([]))?.is_null());

    Ok(())
}

#[test]
fn scripthash_methods_return_electrum_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let scripthash_param = json!([scripthash_hex(fixture.scripthash)]);

    let history = dispatch(
        "blockchain.scripthash.get_history",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    let Some(history_rows) = history.as_array() else {
        panic!("history response must be an array");
    };
    assert!(
        history_rows
            .iter()
            .all(|entry| { entry.get("tx_hash").is_str() && entry.get("height").is_i64() })
    );

    let balance = dispatch(
        "blockchain.scripthash.get_balance",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    assert!(balance.get("confirmed").is_u64());
    assert!(balance.get("unconfirmed").is_u64());

    let status = dispatch(
        "blockchain.scripthash.subscribe",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    assert!(status.is_str());

    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    let Some(unspent_rows) = unspent.as_array() else {
        panic!("listunspent response must be an array");
    };
    assert!(unspent_rows.iter().all(|entry| {
        entry.get("tx_hash").is_str()
            && entry.get("tx_pos").is_u64()
            && entry.get("height").is_i64()
            && entry.get("value").is_u64()
    }));

    Ok(())
}

#[test]
fn transaction_fee_and_header_methods_return_electrum_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;

    let indexed_hex = dispatch(
        "blockchain.transaction.get",
        &fixture.index,
        &fixture.mempool,
        &json!([fixture.indexed_txid.to_string()]),
    )?;
    assert!(indexed_hex.is_str());

    let mempool_txid_string = fixture.mempool_txid.to_string();
    let verbose = dispatch(
        "blockchain.transaction.get",
        &fixture.index,
        &fixture.mempool,
        &json!([mempool_txid_string.as_str(), true]),
    )?;
    assert_eq!(
        verbose.get("txid").and_then(JsonValueTrait::as_str),
        Some(mempool_txid_string.as_str())
    );

    // A transaction whose only input resolves nowhere (not in the confirmed
    // index and not funded by any mempool transaction) must be rejected
    // instead of entering the pool with the old vsize placeholder fee.
    let broadcast_tx = tx(3, ScriptBuf::from_bytes(vec![0x51, 0x03]));
    let Err(broadcast_error) = dispatch(
        "blockchain.transaction.broadcast",
        &fixture.index,
        &fixture.mempool,
        &json!([serialize_hex(&broadcast_tx)]),
    ) else {
        panic!("broadcast with unresolved prevout must fail");
    };
    assert!(
        matches!(
            broadcast_error,
            bitcoin_rs_electrum::ElectrumError::Unavailable(_)
        ),
        "expected typed unavailable rejection, got {broadcast_error:?}"
    );
    let rejected_txid = broadcast_tx.compute_txid();
    assert!(
        dispatch(
            "blockchain.transaction.get",
            &fixture.index,
            &fixture.mempool,
            &json!([rejected_txid.to_string()]),
        )
        .is_err(),
        "rejected broadcast must not be stored"
    );

    assert!(
        dispatch(
            "blockchain.estimatefee",
            &fixture.index,
            &fixture.mempool,
            &json!([6]),
        )?
        .is_i64()
    );

    let histogram = dispatch(
        "mempool.get_fee_histogram",
        &fixture.index,
        &fixture.mempool,
        &json!([]),
    )?;
    assert!(histogram.as_array().is_some());

    let headers = dispatch(
        "blockchain.block.headers",
        &fixture.index,
        &fixture.mempool,
        &json!([0, 1]),
    )?;
    assert_eq!(
        headers.get("count").and_then(JsonValueTrait::as_u64),
        Some(1)
    );
    assert!(headers.get("hex").is_str());
    assert!(headers.get("max").is_u64());

    let tip = dispatch(
        "blockchain.headers.subscribe",
        &fixture.index,
        &fixture.mempool,
        &json!([]),
    )?;
    assert!(tip.get("height").is_u64());
    assert!(tip.get("hex").is_str());

    Ok(())
}

struct Fixture {
    index: IndexHandle,
    mempool: MempoolHandle,
    scripthash: ScriptHash,
    indexed_txid: Txid,
    mempool_txid: Txid,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let scripthash = ScriptHash::new(&script);
        let indexed_tx = tx(1, script.clone());
        let indexed_txid = indexed_tx.compute_txid();
        index.add_transaction(&indexed_tx);
        index.add_history_entry(scripthash, indexed_txid, 7, 5_000, 0, false);
        index.add_header(0, [1_u8; 80]);

        let mempool_tx = tx(2, script);
        let mempool_txid = mempool.insert_transaction(mempool_tx, 2_000, 1, 7)?;

        Ok(Self {
            index,
            mempool,
            scripthash,
            indexed_txid,
            mempool_txid,
        })
    }
}

fn tx(label: u8, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey,
        }],
    }
}

fn outpoint(label: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([label; 32]),
        vout: 0,
    }
}

#[test]
fn mempool_history_includes_spending_transaction_once() -> Result<(), Box<dyn std::error::Error>> {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    }));
    let script = ScriptBuf::from_bytes(vec![0x51]);
    let scripthash_param = json!([scripthash_hex(ScriptHash::new(&script))]);

    let funding_tx = tx(9, script);
    let funding_txid = mempool.insert_transaction(funding_tx, 0, 0, 0)?;
    let spending_tx = spend_from(funding_txid, 0, ScriptBuf::from_bytes(vec![0x52]));
    let spending_txid = mempool.insert_transaction(spending_tx, 0, 0, 0)?;

    let history = dispatch(
        "blockchain.scripthash.get_history",
        &index,
        &mempool,
        &scripthash_param,
    )?;
    let Some(rows) = history.as_array() else {
        panic!("history must be an array");
    };
    let funding_hash = funding_txid.to_string();
    let funding_rows = rows
        .iter()
        .filter(|row| {
            row.get("tx_hash").and_then(JsonValueTrait::as_str) == Some(funding_hash.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(funding_rows.len(), 1, "funding tx appears once: {rows:?}");
    assert_eq!(
        funding_rows[0]
            .get("height")
            .and_then(JsonValueTrait::as_i64),
        Some(0),
        "mempool tx with confirmed parents uses height 0: {rows:?}"
    );

    let spending_hash = spending_txid.to_string();
    let spending_rows = rows
        .iter()
        .filter(|row| {
            row.get("tx_hash").and_then(JsonValueTrait::as_str) == Some(spending_hash.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(spending_rows.len(), 1, "spending tx appears once: {rows:?}");
    assert_eq!(
        spending_rows[0]
            .get("height")
            .and_then(JsonValueTrait::as_i64),
        Some(-1),
        "mempool child uses height -1: {rows:?}"
    );

    Ok(())
}

#[test]
fn mempool_history_includes_confirmed_output_spend_and_updates_status()
-> Result<(), Box<dyn std::error::Error>> {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    }));
    let script = ScriptBuf::from_bytes(vec![0x51]);
    let scripthash = ScriptHash::new(&script);
    let scripthash_param = json!([scripthash_hex(scripthash)]);
    let confirmed_txid = Txid::from_byte_array([17; 32]);
    index.add_history_entry(scripthash, confirmed_txid, 7, 5_000, 0, false);

    let before = dispatch(
        "blockchain.scripthash.subscribe",
        &index,
        &mempool,
        &scripthash_param,
    )?;
    let spending_tx = spend_from(confirmed_txid, 0, ScriptBuf::from_bytes(vec![0x52]));
    let spending_txid = mempool.insert_transaction(spending_tx, 0, 0, 0)?;

    let history = dispatch(
        "blockchain.scripthash.get_history",
        &index,
        &mempool,
        &scripthash_param,
    )?;
    let Some(rows) = history.as_array() else {
        panic!("history must be an array");
    };
    let spending_hash = spending_txid.to_string();
    let spending_rows = rows
        .iter()
        .filter(|row| {
            row.get("tx_hash").and_then(JsonValueTrait::as_str) == Some(spending_hash.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(
        spending_rows.len(),
        1,
        "confirmed-output spend appears once: {rows:?}"
    );
    assert_eq!(
        spending_rows[0]
            .get("height")
            .and_then(JsonValueTrait::as_i64),
        Some(0),
        "spend with confirmed parents uses height 0: {rows:?}"
    );

    let after = dispatch(
        "blockchain.scripthash.subscribe",
        &index,
        &mempool,
        &scripthash_param,
    )?;
    assert_ne!(before, after, "confirmed-output spend must change status");

    Ok(())
}

#[test]
fn listunspent_excludes_mempool_output_spent_by_mempool_tx()
-> Result<(), Box<dyn std::error::Error>> {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    }));
    let script = ScriptBuf::from_bytes(vec![0x51]);
    let scripthash_param = json!([scripthash_hex(ScriptHash::new(&script))]);

    let funding_tx = tx(11, script);
    let funding_txid = mempool.insert_transaction(funding_tx, 0, 0, 0)?;
    let spending_tx = spend_from(funding_txid, 0, ScriptBuf::from_bytes(vec![0x52]));
    let spending_txid = mempool.insert_transaction(spending_tx, 0, 0, 0)?;

    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &index,
        &mempool,
        &scripthash_param,
    )?;
    let Some(rows) = unspent.as_array() else {
        panic!("listunspent must be an array");
    };
    assert!(
        rows.iter()
            .all(|row| row.get("tx_hash").and_then(JsonValueTrait::as_str)
                != Some(funding_txid.to_string().as_str())),
        "spent mempool output must be omitted: {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|row| row.get("tx_hash").and_then(JsonValueTrait::as_str)
                != Some(spending_txid.to_string().as_str())),
        "spending tx creates no matching output: {rows:?}"
    );
    assert_eq!(rows.len(), 0, "no unspent outputs remain: {rows:?}");

    Ok(())
}

#[test]
fn broadcast_uses_real_fee_for_unconfirmed_parent() -> Result<(), Box<dyn std::error::Error>> {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    }));

    // Parent funds 5_000 sat in the mempool; child spends it with a 4_500 sat
    // output, so the real fee is 500 sat, not a vsize-derived placeholder.
    let parent = tx(13, ScriptBuf::new());
    let parent_txid = mempool.insert_transaction(parent, 0, 0, 0)?;
    let mut child = spend_from(parent_txid, 0, ScriptBuf::new());
    child.output[0].value = Amount::from_sat(4_500);

    let broadcast = dispatch(
        "blockchain.transaction.broadcast",
        &index,
        &mempool,
        &json!([serialize_hex(&child)]),
    )?;
    let Some(child_hex) = broadcast.as_str() else {
        panic!("broadcast must return a txid string");
    };
    let child_txid = child_hex.parse::<Txid>()?;
    assert_eq!(child_txid, child.compute_txid());

    // The child's fee (500 sat over its vsize) must land in the fee
    // histogram at the real rate, not in the 1 sat/vB bucket the old
    // vsize placeholder would have produced.
    let histogram = dispatch("mempool.get_fee_histogram", &index, &mempool, &json!([]))?;
    let Some(rows) = histogram.as_array() else {
        panic!("histogram must be an array");
    };
    let child_rate = 500_u64 / u64::try_from(child.vsize())?;
    assert!(
        rows.iter()
            .any(|row| row.get(0).and_then(JsonValueTrait::as_u64) == Some(child_rate)),
        "histogram must contain the child's real rate {child_rate}: {rows:?}"
    );
    assert!(
        rows.iter()
            .all(|row| row.get(0).and_then(JsonValueTrait::as_u64) != Some(1)),
        "no 1 sat/vB placeholder bucket: {rows:?}"
    );

    Ok(())
}

#[test]
fn broadcast_rejects_when_no_prevout_resolves() {
    let index = IndexHandle::new();
    let mempool = MempoolHandle::default();

    // Single input with an outpoint that exists nowhere: must reject with a
    // typed error and must not insert a synthetic 1 sat/vB fee transaction.
    let unresolved = tx(15, ScriptBuf::from_bytes(vec![0x51]));
    let result = dispatch(
        "blockchain.transaction.broadcast",
        &index,
        &mempool,
        &json!([serialize_hex(&unresolved)]),
    );
    assert!(
        matches!(
            result,
            Err(bitcoin_rs_electrum::ElectrumError::Unavailable(_))
        ),
        "expected Unavailable rejection, got {result:?}"
    );
    assert!(
        dispatch(
            "blockchain.transaction.get",
            &index,
            &mempool,
            &json!([unresolved.compute_txid().to_string()]),
        )
        .is_err(),
        "rejected transaction must not be retrievable"
    );
}

fn spend_from(previous_txid: Txid, vout: u32, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: previous_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey,
        }],
    }
}
