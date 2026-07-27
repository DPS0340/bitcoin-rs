//! Owned reclamation invariant coverage under churn.
//!
//! Churns same-txid records through partial spends, full spends, BIP30
//! overwrites, and undo; asserts live outputs, `record_count`,
//! `hash_serialized_3`, and listener `MuHash` return to the reference state
//! without calling any maintenance API.
use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UndoBatch, UtxoAdd, UtxoSet, aggregate_hash};

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(31).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0xbf58_476d_1ce4_e5b9).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(10);
    script.extend_from_slice(&[0x51, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    TxOut {
        value: Amount::from_sat(10_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

#[test]
fn owned_reclamation_preserves_live_entries_after_churn() -> Result<(), Box<dyn std::error::Error>>
{
    let set = UtxoSet::new();
    let mut live = Vec::<(OutPoint, TxOut)>::new();
    let mut rng = 0x1234_5678_9abc_def0_u64;
    let mut pending = BlockChanges::default();

    for i in 0_u64..5_000 {
        if !live.is_empty() && next_u64(&mut rng) & 1 == 0 {
            let live_len = u64::try_from(live.len())?;
            let idx = usize::try_from(next_u64(&mut rng) % live_len)?;
            let (outpoint, _txout) = live.swap_remove(idx);
            pending.remove(outpoint);
        } else {
            let seed = i + 100_000;
            let outpoint = OutPoint::new(txid(seed), u32::try_from(seed % 7)?);
            let txout = txout(seed);
            live.push((outpoint, txout.clone()));
            pending.add(UtxoAdd::new(outpoint, txout, false, 300));
        }

        if i % 64 == 63 {
            set.commit_block(&pending, &txid(i))?;
            pending = BlockChanges::default();
        }
    }
    if !pending.is_empty() {
        set.commit_block(&pending, &txid(5_001))?;
    }

    // After churn without any maintenance call, the aggregate hash and live
    // entries must be stable and consistent.
    let before = aggregate_hash(&set)?;
    for (outpoint, txout) in &live {
        assert_eq!(set.get(outpoint), Some(txout.clone()));
    }
    // A second pass of the same hash must be identical (no state mutation).
    assert_eq!(aggregate_hash(&set)?, before);

    Ok(())
}

#[test]
fn owned_reclamation_same_txid_partial_then_full_spend_releases_record()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(42);
    let mut preload = BlockChanges::default();
    for vout in 0_u32..8 {
        preload.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(u64::from(vout)),
            false,
            1,
        ));
    }
    set.commit_block(&preload, &txid(99))?;
    assert!(set.has_live_outputs_for_txid(&live_txid));

    // Partial spend: remove half.
    let mut partial = BlockChanges::default();
    for vout in 0_u32..4 {
        partial.remove(OutPoint::new(live_txid, vout));
    }
    set.commit_block(&partial, &txid(100))?;
    assert!(set.has_live_outputs_for_txid(&live_txid));

    // Full spend: remove the rest.
    let mut full = BlockChanges::default();
    for vout in 4_u32..8 {
        full.remove(OutPoint::new(live_txid, vout));
    }
    set.commit_block(&full, &txid(101))?;
    assert!(!set.has_live_outputs_for_txid(&live_txid));

    // Record count must reflect the removal.
    assert_eq!(set.record_count(), 0);
    assert_eq!(set.len(), 0);

    Ok(())
}

#[test]
fn owned_reclamation_bip30_overwrite_does_not_accumulate_garbage()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(77);

    // Add vout 0.
    let mut add1 = BlockChanges::default();
    add1.add(UtxoAdd::new(
        OutPoint::new(live_txid, 0),
        txout(1),
        false,
        1,
    ));
    set.commit_block(&add1, &txid(200))?;

    // Overwrite vout 0 many times (BIP30 allows this when the old output is
    // spent first; here we just add_output which replaces).
    for i in 1_u64..50 {
        let mut overwrite = BlockChanges::default();
        overwrite.add(UtxoAdd::new(
            OutPoint::new(live_txid, 0),
            txout(100 + i),
            false,
            2,
        ));
        set.commit_block(&overwrite, &txid(200 + i))?;
    }

    // The latest value must win.
    assert_eq!(set.get(&OutPoint::new(live_txid, 0)), Some(txout(149)));
    assert_eq!(set.record_count(), 1);
    assert_eq!(set.len(), 1);

    Ok(())
}

#[test]
fn owned_reclamation_undo_restores_state() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let tx1 = txid(1000);
    let tx2 = txid(2000);

    // Block 1: add tx1:vout0 and tx2:vout0.
    let mut block1 = BlockChanges::default();
    let add1 = UtxoAdd::new(OutPoint::new(tx1, 0), txout(1), false, 1);
    let add2 = UtxoAdd::new(OutPoint::new(tx2, 0), txout(2), false, 1);
    block1.add(add1.clone());
    block1.add(add2);
    set.commit_block(&block1, &txid(10_000))?;
    let hash_before = bitcoin_rs_utxo::hash_serialized_3(&set)?;

    // Block 2: spend tx1:vout0, add tx3:vout0.
    let mut block2 = BlockChanges::default();
    let mut undo = UndoBatch::default();
    block2.remove(OutPoint::new(tx1, 0));
    undo.restore(add1);
    let add3 = UtxoAdd::new(OutPoint::new(txid(3000), 0), txout(3), false, 2);
    block2.add(add3);
    undo.remove(OutPoint::new(txid(3000), 0));
    set.commit_block(&block2, &txid(10_001))?;

    // Undo block 2.
    set.undo_block(&undo)?;
    let hash_after = bitcoin_rs_utxo::hash_serialized_3(&set)?;
    assert_eq!(hash_after, hash_before);
    assert_eq!(set.get(&OutPoint::new(tx1, 0)), Some(txout(1)));
    assert_eq!(set.get(&OutPoint::new(tx2, 0)), Some(txout(2)));
    assert_eq!(set.get(&OutPoint::new(txid(3000), 0)), None);

    Ok(())
}
#[test]
fn owned_reclamation_high_fanout_partial_spend_then_small_live_set_churn()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(5000);

    // 1. High fanout: add 500 outputs crossing partition boundaries (8 -> 9+ overflow)
    let mut preload = BlockChanges::default();
    for vout in 0_u32..500 {
        preload.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(u64::from(vout) + 5000),
            false,
            100,
        ));
    }
    set.commit_block(&preload, &txid(5001))?;
    assert_eq!(set.len(), 500);
    assert_eq!(set.record_count(), 1);

    // 2. High-fanout partial spend: spend 490 outputs, leaving 10 live outputs
    let mut partial_spend = BlockChanges::default();
    for vout in 0_u32..490 {
        partial_spend.remove(OutPoint::new(live_txid, vout));
    }
    set.commit_block(&partial_spend, &txid(5002))?;
    assert_eq!(set.len(), 10);
    assert_eq!(set.record_count(), 1);
    for vout in 490_u32..500 {
        assert!(set.get(&OutPoint::new(live_txid, vout)).is_some());
    }

    // 3. Small-live-set churn on remaining outputs across 20 iterations
    for i in 0_u64..20 {
        let mut churn = BlockChanges::default();
        // Replace one remaining output with updated height/txout
        let target_vout = 490 + u32::try_from(i % 10)?;
        churn.add(UtxoAdd::new(
            OutPoint::new(live_txid, target_vout),
            txout(6000 + i),
            i % 2 == 0,
            u32::try_from(105 + i)?,
        ));
        set.commit_block(&churn, &txid(5003 + i))?;
        assert_eq!(set.len(), 10);
        assert_eq!(set.record_count(), 1);
    }

    Ok(())
}

#[test]
fn owned_reclamation_full_record_reclamation_after_multi_tx_sweep()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();

    // Preload 10 transactions with 64 outputs each (640 total outputs)
    let mut preload = BlockChanges::default();
    for t in 0_u64..10 {
        let current_txid = txid(6000 + t);
        for vout in 0_u32..64 {
            preload.add(UtxoAdd::new(
                OutPoint::new(current_txid, vout),
                txout(u64::from(vout) + t * 100),
                false,
                200,
            ));
        }
    }
    set.commit_block(&preload, &txid(7000))?;
    assert_eq!(set.len(), 640);
    assert_eq!(set.record_count(), 10);

    // Full spend sweep across all 10 transactions
    let mut sweep = BlockChanges::default();
    for t in 0_u64..10 {
        let current_txid = txid(6000 + t);
        for vout in 0_u32..64 {
            sweep.remove(OutPoint::new(current_txid, vout));
        }
    }
    set.commit_block(&sweep, &txid(7001))?;

    // Full record reclamation assertions
    assert_eq!(set.len(), 0);
    assert_eq!(set.record_count(), 0);
    assert_eq!(
        bitcoin_rs_utxo::hash_serialized_3(&set)?,
        bitcoin_rs_utxo::hash_serialized_3(&UtxoSet::new())?
    );

    // Re-add 5 single-output transactions to confirm set works cleanly post reclamation
    let mut readd = BlockChanges::default();
    for t in 0_u64..5 {
        readd.add(UtxoAdd::new(
            OutPoint::new(txid(8000 + t), 0),
            txout(8000 + t),
            true,
            300,
        ));
    }
    set.commit_block(&readd, &txid(7002))?;
    assert_eq!(set.len(), 5);
    assert_eq!(set.record_count(), 5);

    Ok(())
}
