//! Snapshot dump/load round-trip coverage.
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_utxo::{
    BlockChanges, SnapshotCoin, SnapshotCoinObserver, UtxoAdd, UtxoChangeEvents,
    UtxoChangeListener, UtxoError, UtxoInserted, UtxoKey, UtxoRemoved, UtxoSet, hash_serialized_3,
    read_snapshot_strict_v4, read_snapshot_strict_v4_observed, write_snapshot,
    write_snapshot_observed,
};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Seek};
use tempfile::tempfile;

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(23).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x94d0_49bb_1331_11eb).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0x0123_4567_89ab_cdef).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn txout(seed: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(2_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51, u8::try_from(seed % 256).unwrap_or(0)]),
    }
}

#[test]
fn snapshot_roundtrip_preserves_vout_and_metadata_boundaries()
-> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let live_txid = txid(42_000);
    let low = OutPoint::new(live_txid, 63);
    let high = OutPoint::new(live_txid, 64);
    let max = OutPoint::new(live_txid, u32::MAX);
    let low_txout = txout(42_001);
    let high_txout = txout(42_002);
    let max_txout = TxOut {
        value: Amount::from_sat(42_003),
        script_pubkey: ScriptBuf::new(),
    };
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(low, low_txout.clone(), false, 400));
    changes.add(UtxoAdd::new(high, high_txout.clone(), true, 401));
    changes.add(UtxoAdd::new(max, max_txout.clone(), false, u32::MAX));
    set.commit_block(&changes, &txid(42_004))?;

    let expected_hash = hash_serialized_3(&set)?;
    let mut file = tempfile()?;
    write_snapshot(&set, &txid(42_005), u32::MAX, &mut file)?;
    file.rewind()?;
    let loaded = read_snapshot_strict_v4(&mut file)?;

    assert_eq!(loaded.tip_hash, txid(42_005));
    assert_eq!(loaded.height, u32::MAX);
    assert_eq!(loaded.set.get(&low), Some(low_txout));
    assert_eq!(loaded.set.get(&high), Some(high_txout));
    assert_eq!(loaded.set.get(&max), Some(max_txout));
    assert_eq!(hash_serialized_3(&loaded.set)?, expected_hash);
    assert!(
        !loaded
            .set
            .get_entry(&low)
            .ok_or("missing low entry")?
            .coinbase
    );
    assert!(
        loaded
            .set
            .get_entry(&high)
            .ok_or("missing high entry")?
            .coinbase
    );
    assert_eq!(
        loaded
            .set
            .get_entry(&max)
            .ok_or("missing max entry")?
            .height,
        u32::MAX
    );
    Ok(())
}

#[test]
fn strict_v4_snapshot_requires_complete_exact_input() -> Result<(), Box<dyn std::error::Error>> {
    let mut snapshot = Vec::new();
    write_snapshot(&UtxoSet::new(), &txid(64_100), 64, &mut snapshot)?;

    let loaded = read_snapshot_strict_v4(&mut Cursor::new(&snapshot))?;
    assert_eq!(loaded.tip_hash, txid(64_100));
    assert_eq!(loaded.height, 64);
    assert_eq!(loaded.muhash_trailer, [0_u8; 384]);

    assert!(read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 384])).is_err());
    assert!(read_snapshot_strict_v4(&mut Cursor::new(&snapshot[..snapshot.len() - 1])).is_err());

    let mut trailing = snapshot;
    trailing.push(0);
    assert!(read_snapshot_strict_v4(&mut Cursor::new(trailing)).is_err());
    Ok(())
}

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

impl SnapshotCoinObserver for RecordingSnapshotObserver {
    fn observe_coin(&mut self, coin: SnapshotCoin<'_>) {
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
        value: 2_000 + seed,
        script_pubkey: script,
    }
}

fn empty_script_txout(seed: u64) -> TxOut {
    TxOut {
        value: 3_000 + seed,
        script_pubkey: Vec::new(),
    }
}

fn max_script_txout(seed: u64) -> TxOut {
    TxOut {
        value: 4_000 + seed,
        script_pubkey: vec![0xAB; usize::from(u16::MAX)],
    }
}
#[test]
fn observed_snapshot_traversal_matches_the_current_reader() -> Result<(), Box<dyn std::error::Error>>
{
    let set = UtxoSet::new();
    let first_txid = txid(200_000);
    let second_txid = txid(200_001);
    let first = txout(200_010);
    let second = TxOut {
        value: Amount::from_sat(200_011),
        script_pubkey: ScriptBuf::new(),
    };
    let mut changes = BlockChanges::default();

    for i in 0_u64..10_000 {
        let outpoint = OutPoint::new(txid(i).into(), u32::try_from(i % 5)?);
        changes.add(UtxoAdd::new(outpoint, txout(i), false, 200));
    }
    let collision_prefix = 0x0102_0304_0506_0708_u64;
    let first_collision = OutPoint::new(txid_with_prefix(collision_prefix, 1).into(), 0);
    let second_collision = OutPoint::new(txid_with_prefix(collision_prefix, 2).into(), 0);
    let first_collision_txout = txout(20_001);
    let second_collision_txout = txout(20_002);
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid, 0),
        first.clone(),
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
    let low = OutPoint::new(live_txid.into(), 63);
    let high = OutPoint::new(live_txid.into(), 64);
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
            OutPoint::new(live_txid.into(), vout),
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
        loaded
            .set
            .get(&OutPoint::new(live_txid.into(), OUTPUT_COUNT - 1)),
        Some(txout(u64::from(OUTPUT_COUNT - 1)))
    );
    Ok(())
}

#[test]
fn snapshot_v4_encoding_is_stable() -> Result<(), Box<dyn std::error::Error>> {
    let set = UtxoSet::new();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(txid(1).into(), 0),
        txout(11),
        false,
        40,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(txid(2).into(), 64),
        txout(22),
        true,
        2001,
    ));
    set.commit_block(&changes, &txid(3))?;

    let mut file = tempfile()?;
    write_snapshot(&set, &txid(99), 41, &mut file)?;
    file.rewind()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;

    assert_eq!(bytes.len(), 588);
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&bytes)),
        [
            0x2d, 0xb8, 0xfa, 0xf3, 0x4a, 0x52, 0x3d, 0x7e, 0xb6, 0xf5, 0xfa, 0x75, 0x09, 0xe3,
            0x5d, 0x74, 0xd0, 0x69, 0x2c, 0x2b, 0x9c, 0xf2, 0x52, 0x55, 0x52, 0x6a, 0x85, 0xff,
            0x35, 0x9b, 0x0a, 0xda,
        ],
    );
    Ok(())
}

#[test]
fn legacy_v2_snapshot_rejects_vout_64() {
    let record_txid = txid(64_000);
    let tip_hash = txid(64_001);
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
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
    set.commit_block(&changes, &txid(200_002))?;

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
        let outpoint = OutPoint::new(live_txid.into(), vout_n);
        changes.add(UtxoAdd::new(
            outpoint,
            txout(60_100 + u64::from(vout_n)),
            false,
            2000,
        ));
    }
    set.commit_block(&changes, &txid(60_999))?;

    assert_eq!(observed, ordinary);
    assert_eq!(observed_trailer, ordinary_trailer);
    assert_eq!(writer_observer.trailer_calls, 1);
    assert_eq!(writer_observer.coins.len(), 3);

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
    let key = UtxoKey::from_txid(&Txid::from(live_txid));
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
        let outpoint = OutPoint::new(live_txid.into(), vout_n);
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

#[test]
fn snapshot_trailer_round_trips_through_listener() -> Result<(), Box<dyn std::error::Error>> {
    let trailer: [u8; 384] = core::array::from_fn(|i| u8::try_from(i % 256).unwrap_or_default());
    let mut set = UtxoSet::new();
    set.set_listener(Box::new(StaticTrailer { trailer }));

    // Add one output so the set is non-empty (listener still required for trailer)
    let op = OutPoint::new(txid(130_000).into(), 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(op, txout(130_001), false, 900));
    set.commit_block(&changes, &txid(130_099))?;

    let mut file = tempfile()?;
    let returned_trailer = write_snapshot(&set, &txid(130_100), 900, &mut file)?;
    assert_eq!(returned_trailer, trailer);
    file.rewind()?;
    let loaded = read_snapshot_strict_v4(&mut file)?;
    assert_eq!(loaded.muhash_trailer, trailer);
    Ok(())
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

fn v4_record_body(key: UtxoKey, txid_bytes: &[u8; 32], output_count: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(key.shard());
    bytes.extend_from_slice(&key.to_prefix());
    bytes.extend_from_slice(txid_bytes);
    bytes.extend_from_slice(&output_count.to_le_bytes());
    bytes
}

#[test]
fn snapshot_read_rejects_invalid_magic() {
    let mut bytes = v4_header(txid(1), 100, 0);
    bytes[0..4].copy_from_slice(&0xDE_AD_BE_EF_u32.to_le_bytes());
    let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
        panic!("invalid magic was accepted");
    };
    assert!(matches!(
        error,
        UtxoError::InvalidSnapshotMagic { actual } if actual == 0xDE_AD_BE_EF
    ));
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
    let key = UtxoKey::from_txid(&Txid::from(txid(160_000)));

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
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
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
            UtxoError::UnsupportedSnapshotVersion { version: actual } if actual == version
        ));
    }
}

#[test]
fn snapshot_read_rejects_duplicate_vouts_in_a_v4_record() {
    let record_txid = txid(160_010);
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
    let mut bytes = v4_header(txid(160_011), 1601, 1);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 4));
    for vout in [9, 1, 9, 1] {
        append_snapshot_output(&mut bytes, vout, 1_000, 1601, false, &[0x51]);
    }
    bytes.extend_from_slice(&[0_u8; 384]);

    let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
        panic!("duplicate vout was accepted");
    };
    assert!(matches!(
        error,
        UtxoError::SnapshotDuplicateVout { vout: 9 }
    ));
}

#[test]
fn snapshot_read_v2_rejects_bitmap_count_mismatch() {
    let txid_bytes = txid(170_000).to_le_bytes();
    let key = UtxoKey::from_txid(&Txid::from(txid(170_000)));

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
    let key = UtxoKey::from_txid(&Txid::from(txid(180_000)));

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
    let real_prefix = UtxoKey::from_txid(&Txid::from(real_txid)).to_prefix();

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
            value: first.value,
            script_pubkey: first.script_pubkey.as_slice().to_vec(),
            height: 2000,
            coinbase: false,
        },
        SeenSnapshotCoin {
            txid: first_txid,
            vout: 9,
            value: second.value,
            script_pubkey: second.script_pubkey.as_slice().to_vec(),
            height: 2001,
            coinbase: true,
        },
        SeenSnapshotCoin {
            txid: second_txid,
            vout: 2,
            value: third.value,
            script_pubkey: third.script_pubkey.as_slice().to_vec(),
            height: 2002,
            coinbase: false,
        },
    ];
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid.into(), 0),
        first,
        false,
        2000,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(first_txid.into(), 9),
        second,
        true,
        2001,
    ));
    changes.add(UtxoAdd::new(
        OutPoint::new(second_txid.into(), 2),
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
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
    let mut bytes = v4_header(txid(200_021), 2020, 1);
    bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 0));
    bytes.extend_from_slice(&[0_u8; 384]);

    let Err(error) = read_snapshot_strict_v4(&mut Cursor::new(bytes)) else {
        panic!("record count mismatch was accepted");
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
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
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
            .get(&OutPoint::new(record_txid.into(), 0))
            .is_none()
    );
    assert!(
        compatibility
            .set
            .get(&OutPoint::new(record_txid.into(), 1))
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
        dropped: Arc<AtomicBool>,
    }

    impl SnapshotCoinObserver for DropObserver {
        fn observe_coin(&mut self, _: SnapshotCoin<'_>) {}
    }

    impl Drop for DropObserver {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    let record_txid = txid(200_040);
    let key = UtxoKey::from_txid(&Txid::from(record_txid));
    let mut bytes = v4_header(txid(200_041), 2040, 2);
    for vout in 0..2 {
        bytes.extend_from_slice(&v4_record_body(key, &record_txid.to_le_bytes(), 1));
        append_snapshot_output(
            &mut bytes,
            vout,
            4_000 + u64::from(vout),
            1800,
            false,
            &[0x51],
        );
    }
    bytes.extend_from_slice(&[0_u8; 384]);

    let dropped = Arc::new(AtomicBool::new(false));
    let result = read_snapshot_strict_v4_observed(
        &mut Cursor::new(bytes),
        DropObserver {
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
    let script_len = u16::try_from(script_pubkey.len()).expect("test script fits v4 encoding");
    bytes.extend_from_slice(&vout.to_le_bytes());
    bytes.extend_from_slice(&value.to_le_bytes());
    bytes.extend_from_slice(&height.to_le_bytes());
    bytes.push(u8::from(coinbase));
    bytes.extend_from_slice(&script_len.to_le_bytes());
    bytes.extend_from_slice(script_pubkey);
}
