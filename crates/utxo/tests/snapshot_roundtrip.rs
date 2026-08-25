//! Snapshot dump/load round-trip coverage.
use bitcoin::{
    Amount, ScriptBuf,
    hashes::{Hash as _, sha256},
};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{
    BlockChanges, UtxoAdd, UtxoChangeEvents, UtxoChangeListener, UtxoError, UtxoInserted, UtxoKey,
    UtxoRemoved, UtxoSet, hash_serialized_3, read_snapshot, write_snapshot,
};
use std::io::{Cursor, Read, Seek};
use tempfile::tempfile;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenSnapshotCoin {
    txid: Hash256,
    vout: u32,
    value: u64,
    script_pubkey: Vec<u8>,
    height: u32,
    coinbase: bool,
}

#[derive(Default)]
struct RecordingSnapshotObserver {
    coins: Vec<SeenSnapshotCoin>,
    replacement_trailer: Option<[u8; 384]>,
    trailer_calls: usize,
}

impl bitcoin_rs_utxo::SnapshotCoinObserver for RecordingSnapshotObserver {
    fn observe_coin(&mut self, coin: bitcoin_rs_utxo::SnapshotCoin<'_>) {
        self.coins.push(SeenSnapshotCoin {
            txid: coin.txid,
            vout: coin.vout,
            value: coin.value,
            script_pubkey: coin.script_pubkey.to_vec(),
            height: coin.height,
            coinbase: coin.coinbase,
        });
    }

    fn select_trailer(&mut self, fallback: [u8; 384]) -> [u8; 384] {
        self.trailer_calls += 1;
        self.replacement_trailer.unwrap_or(fallback)
    }
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txid_with_prefix(prefix: u64, suffix: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&prefix.to_le_bytes());
    bytes[8..16].copy_from_slice(&suffix.to_le_bytes());
    bytes[16..24].copy_from_slice(&suffix.rotate_left(7).to_le_bytes());
    bytes[24..32].copy_from_slice(&suffix.wrapping_mul(29).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(12);
    script.extend_from_slice(&[0x76, 0xa9, 0x08]);
    script.extend_from_slice(&seed.to_le_bytes());
    script.push(0x88);
    TxOut {
        value: Amount::from_sat(2_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn empty_script_txout(seed: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(3_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(Vec::new()),
    }
}

fn max_script_txout(seed: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(4_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(vec![0xAB; usize::from(u16::MAX)]),
    }
}

#[test]
fn snapshot_roundtrip_preserves_full_outpoints_hash_and_trailer()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i), u32::try_from(i % 5)?);
        changes.add(UtxoAdd::new(outpoint, txout(i), false, 200));
    }
    let collision_prefix = 0x0102_0304_0506_0708_u64;
    let first_collision = OutPoint::new(txid_with_prefix(collision_prefix, 1), 0);
    let second_collision = OutPoint::new(txid_with_prefix(collision_prefix, 2), 0);
    let first_collision_txout = txout(20_001);
    let second_collision_txout = txout(20_002);
    changes.add(UtxoAdd::new(
        first_collision,
        first_collision_txout.clone(),
        true,
        201,
    ));
    changes.add(UtxoAdd::new(
        second_collision,
        second_collision_txout.clone(),
        false,
        202,
    ));
    set.commit_block(&changes, &txid(10_000))?;

    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(99), 200, &mut file)?;
    file.rewind()?;

    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(99));
    assert_eq!(loaded.height, 200);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    assert_eq!(loaded.set.len(), set.len());
    assert_eq!(
        loaded.set.get(&first_collision),
        Some(first_collision_txout)
    );
    assert_eq!(
        loaded.set.get(&second_collision),
        Some(second_collision_txout)
    );

    Ok(())
}

#[test]
fn snapshot_roundtrip_preserves_vout_64() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(42_000);
    let low = OutPoint::new(live_txid, 63);
    let high = OutPoint::new(live_txid, 64);
    let low_txout = txout(42_001);
    let high_txout = txout(42_002);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 400));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 401));
    set.commit_block(&changes, &txid(42_003))?;

    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(42_004), 401, &mut file)?;
    file.rewind()?;

    let mut header = [0_u8; 8];
    file.read_exact(&mut header)?;
    let mut version = [0_u8; 4];
    version.copy_from_slice(&header[4..8]);
    assert_eq!(u32::from_le_bytes(version), 4);
    file.rewind()?;

    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(42_004));
    assert_eq!(loaded.height, 401);
    assert_eq!(loaded.set.get(&low), Some(low_txout));
    assert_eq!(loaded.set.get(&high), Some(high_txout));
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    Ok(())
}

#[test]
fn snapshot_roundtrip_preserves_440_outputs_from_one_transaction()
-> Result<(), Box<dyn std::error::Error>> {
    const OUTPUT_COUNT: u32 = 440;
    let set = UtxoSet::new();
    let live_txid = txid(43_000);
    let mut changes = BlockChanges::default();
    for vout in 0..OUTPUT_COUNT {
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(u64::from(vout)),
            false,
            402,
        ));
    }
    set.commit_block(&changes, &txid(43_001))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(43_002), 402, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.set.len(), usize::try_from(OUTPUT_COUNT)?);
    assert_eq!(
        loaded.set.get(&OutPoint::new(live_txid, OUTPUT_COUNT - 1)),
        Some(txout(u64::from(OUTPUT_COUNT - 1)))
    );
    Ok(())
}

#[test]
fn snapshot_v4_encoding_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(txid(1), 0),
        txout(11),
        false,
        40,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(txid(2), 64),
        txout(22),
        true,
        41,
    ));
    set.commit_block(&changes, &txid(3))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(99), 41, &mut file)?;
    file.rewind()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    assert_eq!(bytes.len(), 588);
    assert_eq!(
        sha256::Hash::hash(&bytes),
        sha256::Hash::from_byte_array([
            0x2d, 0xb8, 0xfa, 0xf3, 0x4a, 0x52, 0x3d, 0x7e, 0xb6, 0xf5, 0xfa, 0x75, 0x09, 0xe3,
            0x5d, 0x74, 0xd0, 0x69, 0x2c, 0x2b, 0x9c, 0xf2, 0x52, 0x55, 0x52, 0x6a, 0x85, 0xff,
            0x35, 0x9b, 0x0a, 0xda,
        ]),
    );
    Ok(())
}

#[test]
fn legacy_v2_snapshot_rejects_vout_64() {
    let record_txid = txid(64_000);
    let tip_hash = txid(64_001);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = Vec::new();

    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());

    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(&record_txid.to_le_bytes());
    bytes.extend_from_slice(&1_u64.to_le_bytes());
    bytes.push(1);

    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.extend_from_slice(&1_000_u64.to_le_bytes());
    bytes.extend_from_slice(&64_u32.to_le_bytes());
    bytes.push(0);
    bytes.extend_from_slice(&1_u16.to_le_bytes());
    bytes.push(0x51);

    let mut reader = Cursor::new(bytes);
    let error = match read_snapshot(&mut reader) {
        Err(error) => error,
        Ok(_) => panic!("v2 bitmap cannot encode vout 64"),
    };

    assert!(matches!(error, UtxoError::VoutOutOfRange { vout: 64 }));
}

#[test]
fn strict_v4_snapshot_requires_complete_exact_input() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut snapshot = Vec::new();
    write_snapshot(&set, &txid(64_100), 64, &mut snapshot)?;

    let loaded = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(&snapshot))?;
    assert_eq!(loaded.tip_hash, txid(64_100));
    assert_eq!(loaded.height, 64);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);

    let missing_trailer = &snapshot[..snapshot.len() - 384];
    assert!(
        bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(missing_trailer))
            .is_err()
    );
    assert!(
        bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(
            &snapshot[..snapshot.len() - 1]
        ))
        .is_err()
    );

    let mut trailing = snapshot.clone();
    trailing.push(0);
    assert!(
        bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(trailing)).is_err()
    );
    Ok(())
}

#[test]
fn strict_v4_snapshot_rejects_legacy_versions_that_compatibility_decoder_accepts()
-> Result<(), Box<dyn std::error::Error>> {
    for version in [2_u32, 3_u32] {
        let mut legacy = Vec::new();
        legacy.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
        legacy.extend_from_slice(&version.to_le_bytes());
        legacy.extend_from_slice(&txid(64_200).to_le_bytes());
        legacy.extend_from_slice(&64_u32.to_le_bytes());
        legacy.extend_from_slice(&0_u64.to_le_bytes());

        assert_eq!(read_snapshot(&mut Cursor::new(&legacy))?.height, 64);
        let error =
            match bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(legacy)) {
                Err(error) => error,
                Ok(_) => panic!("strict decoder must reject a legacy snapshot"),
            };
        assert!(matches!(
            error,
            UtxoError::UnsupportedSnapshotVersion { version: actual } if actual == version
        ));
    }
    Ok(())
}

#[cfg(target_pointer_width = "32")]
#[test]
fn strict_v4_snapshot_rejects_record_count_that_overflows_usize() {
    let mut snapshot = Vec::new();
    snapshot.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    snapshot.extend_from_slice(&4_u32.to_le_bytes());
    snapshot.extend_from_slice(&txid(64_300).to_le_bytes());
    snapshot.extend_from_slice(&64_u32.to_le_bytes());
    snapshot.extend_from_slice(&u64::MAX.to_le_bytes());

    let error = match bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(snapshot))
    {
        Err(error) => error,
        Ok(_) => panic!("record count must fit usize"),
    };
    assert!(matches!(
        error,
        UtxoError::SnapshotRecordCountTooLarge { count: u64::MAX }
    ));
}
// ─────────────────────────────────────────────────────────────────────────────
//  Task 2: adversarial / boundary coverage
// ─────────────────────────────────────────────────────────────────────────────

/// Single txid with 12 outputs crosses the legacy 8-inline threshold.
/// Pins: header bytes, record header at file offset 52, `output_count` at offset 93,
/// per-output headers at offsets 97/128/159, and each output's coinbase byte.
/// Crosses 8 → overflow outputs must appear after inline outputs in
/// snapshot record order.
#[test]
fn snapshot_roundtrip_high_fanout_overflow_record_pins_byte_layout()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    let live_txid = txid(60_000);
    for vout_n in 0u32..12 {
        let outpoint = OutPoint::new(live_txid, vout_n);
        changes.add(UtxoAdd::new(
            outpoint,
            txout(60_100 + u64::from(vout_n)),
            false,
            2000,
        ));
    }
    set.commit_block(&changes, &txid(60_999))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(61_000), 2010, &mut file)?;
    file.rewind()?;

    // ── Header ──────────────────────────────────────────────────────────────
    let mut header = [0u8; 52];
    file.read_exact(&mut header)?;
    assert_eq!(&header[0..4], &0x55_54_58_4F_u32.to_le_bytes()); // magic "UTXO" LE
    assert_eq!(&header[4..8], &4_u32.to_le_bytes()); // version 4
    assert_eq!(&header[40..44], &2010_u32.to_le_bytes()); // height
    assert_eq!(&header[44..52], &1_u64.to_le_bytes()); // record_count = 1

    // ── Record header at offset 52 ─────────────────────────────────────────
    let mut rec_header = [0u8; 45];
    file.read_exact(&mut rec_header)?;
    let key = UtxoKey::from_txid(&live_txid);
    assert_eq!(rec_header[0], key.shard()); // shard_idx
    assert_eq!(&rec_header[1..9], &key.to_prefix()); // key_prefix
    assert_eq!(&rec_header[9..41], &live_txid.to_le_bytes()); // txid
    assert_eq!(&rec_header[41..45], &12_u32.to_le_bytes()); // output_count

    // ── Per-output headers (vout u32 LE, value u64 LE, height u32 LE,
    //     coinbase u8, script_len u16 LE) at offsets 97, 128, 159 ─────────
    for (i, expect_vout) in (0u32..12).enumerate() {
        let offset = u64::try_from(97 + i * 31)?;
        file.seek(std::io::SeekFrom::Start(offset))?;
        let mut out_hdr = [0u8; 19];
        file.read_exact(&mut out_hdr)?;
        assert_eq!(
            &out_hdr[0..4],
            &expect_vout.to_le_bytes(),
            "output {i}: vout LE mismatch at offset {offset}"
        );
        assert_eq!(
            &out_hdr[12..16],
            &2000_u32.to_le_bytes(),
            "output {}: height mismatch at offset {}",
            i,
            offset + 12
        );
        assert_eq!(
            out_hdr[16],
            0u8,
            "output {}: coinbase should be 0 at offset {}",
            i,
            offset + 16
        );
        assert_eq!(
            &out_hdr[17..19],
            &12u16.to_le_bytes(),
            "output {}: script_len mismatch at offset {}",
            i,
            offset + 17
        );
    }

    // ── Re-read and verify roundtrip ───────────────────────────────────────
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;
    assert_eq!(loaded.set.len(), 12);
    for vout_n in 0u32..12 {
        let outpoint = OutPoint::new(live_txid, vout_n);
        let expect = txout(60_100 + u64::from(vout_n));
        assert_eq!(
            loaded.set.get(&outpoint),
            Some(expect.clone()),
            "vout {vout_n} missing or wrong after roundtrip"
        );
    }
    assert_eq!(hash_serialized_3(&loaded.set)?, hash_serialized_3(&set)?);
    Ok(())
}

/// Removes one inline output (vout 0) and one overflow output (vout 9),
/// then re-adds both with different `TxOuts`. After roundtrip all 12 vouts
/// must survive with correct values; no ordering assumptions.
#[test]
fn snapshot_roundtrip_inline_overflow_remove_readd_preserves_vouts()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(70_000);

    // ── Phase 1: add all 12 outputs ────────────────────────────────────────
    {
        let mut changes = BlockChanges::default();
        for vout_n in 0u32..12 {
            let op = OutPoint::new(live_txid, vout_n);
            changes.add(UtxoAdd::new(
                op,
                txout(70_100 + u64::from(vout_n)),
                false,
                1000,
            ));
        }
        set.commit_block(&changes, &txid(70_099))?;
    }
    assert_eq!(set.len(), 12);

    // ── Phase 2: remove inline (vout 0) and overflow (vout 9) ─────────────
    {
        let mut changes = BlockChanges::default();
        changes.remove(OutPoint::new(live_txid, 0));
        changes.remove(OutPoint::new(live_txid, 9));
        set.commit_block(&changes, &txid(70_100))?;
    }
    assert_eq!(set.len(), 10);

    // ── Phase 3: re-add both with new values ────────────────────────────────
    let new0 = TxOut {
        value: Amount::from_sat(9_999_000),
        script_pubkey: ScriptBuf::from_bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };
    let new9 = TxOut {
        value: Amount::from_sat(9_999_009),
        script_pubkey: ScriptBuf::from_bytes(vec![0xFE, 0xED]),
    };
    {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, 0),
            new0.clone(),
            false,
            1000,
        ));
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, 9),
            new9.clone(),
            false,
            1000,
        ));
        set.commit_block(&changes, &txid(70_101))?;
    }
    assert_eq!(set.len(), 12);

    // ── Snapshot and roundtrip ──────────────────────────────────────────────
    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(70_102), 1100, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.set.len(), 12);
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);

    // New values for re-added outputs
    assert_eq!(loaded.set.get(&OutPoint::new(live_txid, 0)), Some(new0));
    assert_eq!(loaded.set.get(&OutPoint::new(live_txid, 9)), Some(new9));

    // Original values for untouched outputs
    for vout_n in [1u32, 2, 3, 4, 5, 6, 7, 8, 10, 11] {
        let op = OutPoint::new(live_txid, vout_n);
        assert_eq!(
            loaded.set.get(&op),
            Some(txout(70_100 + u64::from(vout_n))),
            "vout {vout_n}: original value corrupted"
        );
    }
    Ok(())
}

/// 64 distinct txids in the same shard (prefix `0x0102_0304_0506_0708`), each
/// with 4 outputs (vouts 0–3). Verifies `record_count`, len, `hash_serialized_3`
/// parity, and individual lookups — without asserting `HashTable` iteration order.
#[test]
fn snapshot_roundtrip_multiple_records_per_shard_preserves_all_outpoints()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let shard_prefix = 0x0102_0304_0506_0708_u64;
    let mut changes = BlockChanges::default();

    for suffix in 0u64..64 {
        let txid = txid_with_prefix(shard_prefix, suffix);
        let base_seed = suffix * 100;
        for vout_n in 0u32..4 {
            let op = OutPoint::new(txid, vout_n);
            changes.add(UtxoAdd::new(
                op,
                txout(base_seed + u64::from(vout_n)),
                false,
                300,
            ));
        }
    }
    set.commit_block(&changes, &txid(1))?;

    let expected_hash = hash_serialized_3(&set)?;
    assert_eq!(set.len(), 256, "pre-condition: 64 txids × 4 outputs");
    assert_eq!(set.record_count(), 64, "pre-condition: 64 records");

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(2), 300, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.set.len(), 256);
    assert_eq!(loaded.set.record_count(), 64);
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);

    // Spot-check a handful of outpoints via get, avoiding any HashTable order
    for (suffix, vout_n) in [(7u64, 2u32), (31, 0), (31, 3), (63, 1)] {
        let txid = txid_with_prefix(shard_prefix, suffix);
        let op = OutPoint::new(txid, vout_n);
        let expect = txout(suffix * 100 + u64::from(vout_n));
        assert_eq!(loaded.set.get(&op), Some(expect));
    }
    Ok(())
}

// u32::MAX is a valid vout (>= 64, stored in u32 LE). This record contains
// only the u32::MAX output so vout=0 is absent — v3 has no bitmap constraint.
#[test]
fn snapshot_roundtrip_preserves_vout_u32_max() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(80_000);
    let op = OutPoint::new(live_txid, u32::MAX);
    let txout = txout(80_001);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, txout.clone(), true, 500_000));
    set.commit_block(&changes, &txid(80_099))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(80_100), 500_000, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.set.len(), 1);
    assert_eq!(loaded.set.get(&op), Some(txout));
    let entry = loaded
        .set
        .get_entry(&op)
        .ok_or_else(|| std::io::Error::other("entry must exist"))?;
    assert!(entry.coinbase);
    assert_eq!(entry.height, 500_000);
    Ok(())
}

// Both coinbase states at height u32::MAX survive roundtrip independently.
// The coinbase byte is the 17th byte of the output header (offset + 16).
#[test]
fn snapshot_roundtrip_preserves_height_u32_max_both_coinbase_states()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(90_000);
    let op0 = OutPoint::new(live_txid, 0);
    let op1 = OutPoint::new(live_txid, 1);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op0, txout(90_001), false, u32::MAX));
    changes.add(UtxoAdd::new(op1, txout(90_002), true, u32::MAX));
    set.commit_block(&changes, &txid(90_099))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(90_100), u32::MAX, &mut file)?;
    file.rewind()?;

    // Read the coinbase byte of each output directly from the file.
    // Output 0 starts at 97: snapshot header 52 + record header 45.
    let mut cb0 = [0u8; 1];
    file.seek(std::io::SeekFrom::Start(97 + 16))?;
    file.read_exact(&mut cb0)?;
    // Output 1 starts after output 0's 19-byte header and 12-byte script.
    let mut cb1 = [0u8; 1];
    file.seek(std::io::SeekFrom::Start(128 + 16))?;
    file.read_exact(&mut cb1)?;

    assert_eq!(
        cb0[0], 0u8,
        "coinbase byte for vout=0 should be 0 (not coinbase)"
    );
    assert_eq!(
        cb1[0], 1u8,
        "coinbase byte for vout=1 should be 1 (coinbase)"
    );

    // Verify full roundtrip
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;
    assert_eq!(loaded.set.len(), 2);
    let e0 = loaded
        .set
        .get_entry(&op0)
        .ok_or_else(|| std::io::Error::other("vout 0 entry"))?;
    let e1 = loaded
        .set
        .get_entry(&op1)
        .ok_or_else(|| std::io::Error::other("vout 1 entry"))?;
    assert!(!e0.coinbase);
    assert!(e1.coinbase);
    assert_eq!(e0.height, u32::MAX);
    assert_eq!(e1.height, u32::MAX);
    Ok(())
}

// Empty script_pubkey (length 0) is valid on-chain. Roundtrip must preserve it.
#[test]
fn snapshot_roundtrip_preserves_empty_script_pubkey() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(100_000);
    let op = OutPoint::new(live_txid, 0);
    let expect = empty_script_txout(100_001);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, expect.clone(), false, 600));
    set.commit_block(&changes, &txid(100_099))?;

    // Pin the script_len bytes (u16 LE = 0, 0) at file offset 111.
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(100_100), 600, &mut file)?;
    file.rewind()?;
    let mut script_len_bytes = [0u8; 2];
    file.seek(std::io::SeekFrom::Start(94 + 17))?;
    file.read_exact(&mut script_len_bytes)?;
    assert_eq!(
        &script_len_bytes,
        &0u16.to_le_bytes(),
        "script_len must be 0 for empty script"
    );

    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;
    assert_eq!(loaded.set.len(), 1);
    let got = loaded
        .set
        .get(&op)
        .ok_or_else(|| std::io::Error::other("outpoint must exist"))?;
    assert_eq!(got, expect);
    // ScriptBuf comparison compares inner bytes
    assert!(got.script_pubkey.as_bytes().is_empty());
    Ok(())
}

// u16::MAX-length script fits in the record's u16 script_len field.
#[test]
fn snapshot_roundtrip_preserves_max_length_script() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(110_000);
    let op = OutPoint::new(live_txid, 0);
    let expect = max_script_txout(110_001);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, expect.clone(), false, 700));
    set.commit_block(&changes, &txid(110_099))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(110_100), 700, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(loaded.set.len(), 1);
    let got = loaded
        .set
        .get(&op)
        .ok_or_else(|| std::io::Error::other("outpoint must exist"))?;
    assert_eq!(got.value, expect.value);
    assert_eq!(got.script_pubkey.as_bytes().len(), usize::from(u16::MAX));
    assert_eq!(
        got.script_pubkey.as_bytes(),
        expect.script_pubkey.as_bytes()
    );
    Ok(())
}

// Rejects at commit time, before the codec, because the script is too large
// for the record's u16 script_len field.
#[test]
fn commit_block_rejects_oversized_script_pubkey() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let op = OutPoint::new(txid(1), 0);
    let bad = TxOut {
        value: Amount::from_sat(1),
        script_pubkey: ScriptBuf::from_bytes(vec![0xFF; usize::from(u16::MAX) + 1]),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, bad, false, 1));
    let err = set
        .commit_block(&changes, &txid(2))
        .err()
        .ok_or_else(|| std::io::Error::other("expected error"))?;
    assert!(
        matches!(err, UtxoError::ScriptTooLarge { len } if len == usize::from(u16::MAX) + 1),
        "expected ScriptTooLarge({}), got {err:?}",
        usize::from(u16::MAX) + 1
    );
    Ok(())
}

// hash_serialized_3 is the authoritative UTXO-set commitment and must remain
// identical after remove/readd churn.
#[test]
fn snapshot_roundtrip_hash_serialized_3_parity_after_churn()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(120_000);

    // Phase 1: add 3 outputs
    {
        let mut changes = BlockChanges::default();
        for vout_n in 0u32..3 {
            changes.add(UtxoAdd::new(
                OutPoint::new(live_txid, vout_n),
                txout(120_100 + u64::from(vout_n)),
                false,
                800,
            ));
        }
        set.commit_block(&changes, &txid(120_099))?;
    }
    let hash_before_churn = hash_serialized_3(&set)?;

    // Phase 2: remove all 3 and re-add with new values
    {
        let mut changes = BlockChanges::default();
        changes.remove(OutPoint::new(live_txid, 0));
        changes.remove(OutPoint::new(live_txid, 1));
        changes.remove(OutPoint::new(live_txid, 2));
        set.commit_block(&changes, &txid(120_100))?;
    }
    {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, 0),
            txout(120_200),
            false,
            801,
        ));
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, 1),
            txout(120_201),
            false,
            801,
        ));
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, 2),
            txout(120_202),
            false,
            801,
        ));
        set.commit_block(&changes, &txid(120_101))?;
    }

    let expected_hash = hash_serialized_3(&set)?;
    assert_ne!(
        expected_hash, hash_before_churn,
        "churn should change hash_serialized_3"
    );

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(120_102), 801, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;

    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    assert_eq!(loaded.set.len(), 3);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Listener / MuHash trailer coverage
// ─────────────────────────────────────────────────────────────────────────────

struct StaticTrailer {
    trailer: [u8; 384],
}

impl UtxoChangeListener for StaticTrailer {
    fn on_insert_coins(&self, _: &[UtxoInserted<'_>]) {}
    fn on_remove_coins(&self, _: &[UtxoRemoved]) {}
    fn on_committed_event_batches(&self, _: &[UtxoChangeEvents<'_>]) {}
    fn muhash3072(&self) -> Option<[u8; 384]> {
        Some(self.trailer)
    }
}

// When a listener provides a MuHash trailer, write_snapshot returns it and
// read_snapshot preserves it verbatim.
#[test]
fn snapshot_trailer_round_trips_through_listener() -> Result<(), Box<dyn std::error::Error>> {
    let trailer: [u8; 384] = core::array::from_fn(|i| u8::try_from(i % 256).unwrap_or_default());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(StaticTrailer { trailer }));

    // Add one output so the set is non-empty (listener still required for trailer)
    let op = OutPoint::new(txid(130_000), 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, txout(130_001), false, 900));
    set.commit_block(&changes, &txid(130_099))?;

    let mut file = tempfile()?;
    let returned_trailer = write_snapshot(&set, &txid(130_100), 900, &mut file)?;
    assert_eq!(
        &returned_trailer, &trailer,
        "write_snapshot must return the listener's trailer"
    );

    file.rewind()?;
    let loaded = read_snapshot(&mut file)?;
    assert_eq!(
        &loaded.muhash_trailer, &trailer,
        "loaded snapshot must preserve the listener's trailer"
    );
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  Malformed snapshot fixture tests  (hand-rolled bytes, mirrors
//  `legacy_v2_snapshot_rejects_vout_64` pattern)
// ─────────────────────────────────────────────────────────────────────────────

fn v3_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes()); // magic
    bytes.extend_from_slice(&3_u32.to_le_bytes()); // version 3
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&record_count.to_le_bytes());
    bytes
}

fn v4_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    bytes.extend_from_slice(&4_u32.to_le_bytes());
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&record_count.to_le_bytes());
    bytes
}

fn v2_header(tip_hash: Hash256, height: u32, record_count: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(52);
    bytes.extend_from_slice(&0x55_54_58_4f_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&tip_hash.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.extend_from_slice(&record_count.to_le_bytes());
    bytes
}

fn v3_record_body(key: UtxoKey, txid_bytes: &[u8; 32], vout_count: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(txid_bytes);
    bytes.push(vout_count);
    bytes
}

fn v4_record_body(key: UtxoKey, txid_bytes: &[u8; 32], output_count: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(txid_bytes);
    bytes.extend_from_slice(&output_count.to_le_bytes());
    bytes
}

// Writes a v2 record body with the given bitmap and vout_count.
fn v2_record_body(key: UtxoKey, txid_bytes: &[u8; 32], bitmap: u64, vout_count: u8) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(txid_bytes);
    bytes.extend_from_slice(&bitmap.to_le_bytes());
    bytes.push(vout_count);
    bytes
}

#[test]
fn snapshot_read_rejects_invalid_magic() {
    let mut bytes = v3_header(txid(1), 100, 0);
    bytes[0..4].copy_from_slice(&0xDE_AD_BE_EF_u32.to_le_bytes()); // overwrite magic
    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(err, UtxoError::InvalidSnapshotMagic { actual } if actual == 0xDE_AD_BE_EF),
        "{err:?}"
    );
}

#[test]
fn snapshot_read_rejects_unsupported_version() {
    let bytes = {
        let mut b = v3_header(txid(1), 100, 0);
        b[4..8].copy_from_slice(&99_u32.to_le_bytes()); // version 99
        b
    };
    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(err, UtxoError::UnsupportedSnapshotVersion { version } if version == 99),
        "{err:?}"
    );
}

#[test]
fn snapshot_read_v3_overstated_record_count_yields_unexpected_eof() {
    let bytes = v3_header(txid(1), 100, u64::MAX);
    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(err, UtxoError::Io(ref e) if e.kind() == std::io::ErrorKind::UnexpectedEof),
        "{err:?}"
    );
}

#[test]
fn snapshot_read_v3_rejects_duplicate_vout() {
    let txid_bytes = txid(160_000).to_le_bytes();
    let key = UtxoKey::from_txid(&txid(160_000));

    let mut bytes = v3_header(txid(160_001), 1600, 1);
    let mut body = v3_record_body(key, &txid_bytes, 2);
    // First output (vout=42)
    body.extend_from_slice(&42u32.to_le_bytes());
    body.extend_from_slice(&1_000_u64.to_le_bytes());
    body.extend_from_slice(&1600_u32.to_le_bytes());
    body.push(0u8);
    body.extend_from_slice(&1u16.to_le_bytes());
    body.push(0xAA);
    // Second output (vout=42, duplicate!)
    body.extend_from_slice(&42u32.to_le_bytes());
    body.extend_from_slice(&2_000_u64.to_le_bytes());
    body.extend_from_slice(&1600_u32.to_le_bytes());
    body.push(0u8);
    body.extend_from_slice(&1u16.to_le_bytes());
    body.push(0xBB);
    bytes.extend_from_slice(&body);
    // Trailer
    bytes.extend_from_slice(&[0u8; 384]);

    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(err, UtxoError::SnapshotDuplicateVout { vout } if vout == 42),
        "{err:?}"
    );
}

#[test]
fn legacy_snapshot_duplicate_precedes_later_truncation() {
    let record_txid = txid(160_005);
    let key = UtxoKey::from_txid(&record_txid);
    let txid_bytes = record_txid.to_le_bytes();

    let mut v2 = v2_header(txid(160_006), 1600, 1);
    let bitmap = (1_u64 << 7) | (1_u64 << 8) | (1_u64 << 9);
    v2.extend_from_slice(&v2_record_body(key, &txid_bytes, bitmap, 3));
    let mut v3 = v3_header(txid(160_007), 1600, 1);
    v3.extend_from_slice(&v3_record_body(key, &txid_bytes, 3));
    for bytes in [&mut v2, &mut v3] {
        append_snapshot_output(bytes, 7, 1_000, 1600, false, &[0x51]);
        append_snapshot_output(bytes, 7, 2_000, 1600, false, &[0x52]);
    }

    for bytes in [v2, v3] {
        let error = match read_snapshot(&mut Cursor::new(bytes)) {
            Err(error) => error,
            Ok(_) => panic!("expected duplicate before truncated third output"),
        };
        assert!(matches!(
            error,
            UtxoError::SnapshotDuplicateVout { vout: 7 }
        ));
    }
}

#[test]
fn snapshot_read_v4_reports_first_duplicate_in_record_order() {
    let record_txid = txid(160_010);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = v4_header(txid(160_011), 1601, 1);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 4));
    for vout in [9, 1, 9, 1] {
        append_snapshot_output(&mut bytes, vout, 1_000, 1601, false, &[0x51]);
    }
    bytes.extend_from_slice(&[0_u8; 384]);

    let error = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(error) => error,
        Ok(_) => panic!("expected duplicate vout error"),
    };
    assert!(matches!(
        error,
        UtxoError::SnapshotDuplicateVout { vout: 9 }
    ));
}

#[test]
fn snapshot_read_v2_rejects_bitmap_count_mismatch() {
    let txid_bytes = txid(170_000).to_le_bytes();
    let key = UtxoKey::from_txid(&txid(170_000));

    // bitmap=1 (only bit 0 set → 1 output) but vout_count=2
    let mut bytes = v2_header(txid(170_001), 1700, 1);
    bytes.extend_from_slice(&v2_record_body(key, &txid_bytes, 1, 2));
    bytes.extend_from_slice(&[0u8; 384]);

    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(
            err,
            UtxoError::SnapshotVoutCountMismatch {
                bitmap: 1,
                vout_count: 2
            }
        ),
        "{err:?}"
    );
}

#[test]
fn snapshot_read_v3_rejects_shard_idx_mismatch() {
    let txid_bytes = txid(180_000).to_le_bytes();
    let key = UtxoKey::from_txid(&txid(180_000));

    let mut bytes = v3_header(txid(180_001), 1800, 1);
    // Overwrite shard_idx byte (offset 52) with wrong value
    bytes.extend_from_slice(&v3_record_body(key, &txid_bytes, 1));
    bytes.extend_from_slice(&1u32.to_le_bytes()); // vout
    bytes.extend_from_slice(&1000u64.to_le_bytes());
    bytes.extend_from_slice(&1800u32.to_le_bytes());
    bytes.push(0u8);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(0xAA);
    bytes.extend_from_slice(&[0u8; 384]);

    // Replace shard_idx at byte 52 with the wrong value
    bytes[52] = key.shard().wrapping_add(1); // definitely wrong shard

    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(
            err,
            UtxoError::SnapshotShardMismatch {
                shard,
                key_shard,
            } if shard == key.shard().wrapping_add(1) && key_shard == key.shard()
        ),
        "{err:?}"
    );
}

#[test]
fn snapshot_read_v3_rejects_txid_prefix_mismatch() {
    // Use a txid whose first 8 bytes are NOT zero, but declare key_prefix = zero
    let real_txid = txid(190_000);
    let real_prefix = UtxoKey::from_txid(&real_txid).to_prefix();

    let mut bytes = v3_header(txid(190_001), 1900, 1);

    // Record body: shard from the real txid, but wrong key_prefix (zeros)
    let shard = real_prefix[0];
    bytes.push(shard);
    bytes.extend_from_slice(&[0u8; 8]); // wrong prefix (zeros)
    bytes.extend_from_slice(&real_txid.to_le_bytes()); // txid whose prefix ≠ zero
    bytes.push(1u8); // vout_count

    // Output
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1000u64.to_le_bytes());
    bytes.extend_from_slice(&1900u32.to_le_bytes());
    bytes.push(0u8);
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.push(0xAA);
    bytes.extend_from_slice(&[0u8; 384]);

    let err = match read_snapshot(&mut Cursor::new(bytes)) {
        Err(e) => e,
        Ok(_) => panic!("expected read_snapshot error"),
    };
    assert!(
        matches!(err, UtxoError::SnapshotTxidPrefixMismatch),
        "{err:?}"
    );
}

#[test]
fn observed_snapshot_traversal_preserves_bytes_and_coin_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let first_txid = txid(200_000);
    let second_txid = txid(200_001);
    let first = txout(200_010);
    let second = empty_script_txout(200_011);
    let third = txout(200_012);
    let expected = vec![
        SeenSnapshotCoin {
            txid: first_txid,
            vout: 0,
            value: first.value.to_sat(),
            script_pubkey: first.script_pubkey.as_bytes().to_vec(),
            height: 2000,
            coinbase: false,
        },
        SeenSnapshotCoin {
            txid: first_txid,
            vout: 9,
            value: second.value.to_sat(),
            script_pubkey: second.script_pubkey.as_bytes().to_vec(),
            height: 2001,
            coinbase: true,
        },
        SeenSnapshotCoin {
            txid: second_txid,
            vout: 2,
            value: third.value.to_sat(),
            script_pubkey: third.script_pubkey.as_bytes().to_vec(),
            height: 2002,
            coinbase: false,
        },
    ];
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid, 0),
        first,
        false,
        2000,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid, 9),
        second,
        true,
        2001,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(second_txid, 2),
        third,
        false,
        2002,
    ));
    set.commit_block(&changes, &txid(200_002))?;

    let mut legacy = Vec::new();
    let legacy_trailer = write_snapshot(&set, &txid(200_003), 2002, &mut legacy)?;
    let mut observed = Vec::new();
    let (trailer, writer_observer) = bitcoin_rs_utxo::write_snapshot_observed(
        &set,
        &txid(200_003),
        2002,
        &mut observed,
        RecordingSnapshotObserver::default(),
    )?;

    assert_eq!(observed, legacy);
    assert_eq!(trailer, legacy_trailer);
    assert_eq!(writer_observer.trailer_calls, 1);
    assert_eq!(writer_observer.coins.len(), expected.len());
    for coin in &expected {
        assert!(
            writer_observer.coins.contains(coin),
            "missing observed coin {coin:?}"
        );
    }

    let writer_coins = writer_observer.coins;
    let (_, reader_observer) = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(
        &mut Cursor::new(&observed),
        RecordingSnapshotObserver::default(),
    )?;
    assert_eq!(reader_observer.coins, writer_coins);
    Ok(())
}

#[test]
fn observed_snapshot_writer_uses_observer_trailer() -> Result<(), Box<dyn std::error::Error>> {
    let replacement = [0xA5; 384];
    let mut bytes = Vec::new();
    let (trailer, observer) = bitcoin_rs_utxo::write_snapshot_observed(
        &UtxoSet::new(),
        &txid(200_010),
        2010,
        &mut bytes,
        RecordingSnapshotObserver {
            replacement_trailer: Some(replacement),
            ..RecordingSnapshotObserver::default()
        },
    )?;

    assert_eq!(trailer, replacement);
    assert_eq!(observer.trailer_calls, 1);
    assert_eq!(&bytes[bytes.len() - 384..], replacement);
    Ok(())
}

#[test]
fn strict_v4_rejects_empty_records_but_compatibility_reader_accepts_them()
-> Result<(), Box<dyn std::error::Error>> {
    let record_txid = txid(200_020);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = v4_header(txid(200_021), 2020, 1);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 0));
    bytes.extend_from_slice(&[0_u8; 384]);

    let compatibility = read_snapshot(&mut Cursor::new(&bytes))?;
    assert!(compatibility.set.is_empty());
    let Err(error) = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(bytes))
    else {
        return Err("strict snapshot accepted an empty record".into());
    };
    assert!(matches!(
        error,
        UtxoError::SnapshotRecordCountMismatch {
            declared: 1,
            actual: 0
        }
    ));
    Ok(())
}

#[test]
fn strict_v4_rejects_split_duplicate_records_but_compatibility_reader_accepts_them()
-> Result<(), Box<dyn std::error::Error>> {
    let record_txid = txid(200_030);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = v4_header(txid(200_031), 2030, 2);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 1));
    append_snapshot_output(&mut bytes, 0, 3_000, 2030, false, &[0x51]);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 1));
    append_snapshot_output(&mut bytes, 1, 3_001, 2031, true, &[0x52]);
    bytes.extend_from_slice(&[0_u8; 384]);

    let compatibility = read_snapshot(&mut Cursor::new(&bytes))?;
    assert_eq!(compatibility.set.len(), 1);
    assert!(
        compatibility
            .set
            .get(&OutPoint::new(record_txid, 0))
            .is_none()
    );
    assert!(
        compatibility
            .set
            .get(&OutPoint::new(record_txid, 1))
            .is_some()
    );
    let Err(error) = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut Cursor::new(bytes))
    else {
        return Err("strict snapshot accepted split duplicate records".into());
    };
    assert!(matches!(
        error,
        UtxoError::SnapshotRecordCountMismatch {
            declared: 2,
            actual: 1
        }
    ));
    Ok(())
}

#[test]
fn strict_v4_observer_is_dropped_on_error() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct DropObserver {
        observed: usize,
        dropped: Arc<AtomicBool>,
    }

    impl bitcoin_rs_utxo::SnapshotCoinObserver for DropObserver {
        fn observe_coin(&mut self, _: bitcoin_rs_utxo::SnapshotCoin<'_>) {
            self.observed = self.observed.saturating_add(1);
        }
    }

    impl Drop for DropObserver {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    let record_txid = txid(200_040);
    let key = UtxoKey::from_txid(&record_txid);
    let mut bytes = v4_header(txid(200_041), 2040, 2);
    for vout in 0..2 {
        bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 1));
        append_snapshot_output(
            &mut bytes,
            vout,
            4_000 + u64::from(vout),
            2040,
            false,
            &[0x51],
        );
    }
    bytes.extend_from_slice(&[0_u8; 384]);

    let dropped = Arc::new(AtomicBool::new(false));

    let result = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(
        &mut Cursor::new(bytes),
        DropObserver {
            observed: 0,
            dropped: Arc::clone(&dropped),
        },
    );
    assert!(matches!(
        result,
        Err(UtxoError::SnapshotRecordCountMismatch { .. })
    ));
    assert!(dropped.load(Ordering::SeqCst));
}

fn append_snapshot_output(
    bytes: &mut Vec<u8>,
    vout: u32,
    value: u64,
    height: u32,
    coinbase: bool,
    script_pubkey: &[u8],
) {
    let Ok(script_len) = u16::try_from(script_pubkey.len()) else {
        panic!("test script does not fit snapshot encoding");
    };
    bytes.extend_from_slice(&vout.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.push(u8::from(coinbase));
    bytes.extend_from_slice(&script_len.to_le_bytes());
    bytes.extend_from_slice(script_pubkey);
}
