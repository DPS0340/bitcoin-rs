//! Synthetic UTXO commit benchmark.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

// PERF: A/B allocator experiment. With `--features bench-mimalloc` the whole
// bench binary (criterion harness + workload) allocates through mimalloc; with
// the feature off it uses the system allocator. This is the only delta between
// the A and B runs — workloads, scenarios, and sample counts are unchanged.
#[cfg(feature = "bench-mimalloc")]
#[global_allocator]
static GLOBAL_MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};

const ENTRY_COUNT: u64 = 10_000;
const INTERLEAVED_TXID_COUNT: u32 = 256;
const INTERLEAVED_VOUTS_PER_TXID: u32 = 16;
const SPEND_PROXY_FANOUT: usize = 64;
const SPEND_PROXY_SOURCE_HEIGHT: u32 = 1;
const SPEND_PROXY_SPEND_HEIGHT: u32 = 101;
const SPEND_PROXY_COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_PROXY_SPEND_OUTPUT_VALUE: u64 = 78_124_999;

#[derive(Copy, Clone, Debug)]
enum ShardShape {
    Existing,
    TwoShard,
    FourShard,
    Concentrated,
}

#[derive(Clone)]
struct SyntheticEntry {
    outpoint: OutPoint,
    txout: TxOut,
    coinbase: bool,
    height: u32,
}

struct SyntheticWorkload {
    spends: Vec<SyntheticEntry>,
    adds: Vec<SyntheticEntry>,
}

const fn next_u64(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn txid(seed: u64) -> Hash256 {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

fn shaped_txid(seed: u64, index: u64, shape: ShardShape) -> Hash256 {
    let mut hash = txid(seed);
    match shape {
        ShardShape::Existing => {}
        ShardShape::TwoShard => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = u8::try_from(index % 2).unwrap_or(0);
            hash = Hash256::from_le_bytes(&bytes);
        }
        ShardShape::FourShard => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = u8::try_from(index % 4).unwrap_or(0);
            hash = Hash256::from_le_bytes(&bytes);
        }
        ShardShape::Concentrated => {
            let mut bytes = hash.to_le_bytes();
            bytes[0] = 0x2a;
            hash = Hash256::from_le_bytes(&bytes);
        }
    }
    hash
}

fn txout(seed: u64) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(seed).to_le_bytes());
    TxOut {
        value: Amount::from_sat(5_000 + seed),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn synthetic_workload(seed: u64, shape: ShardShape) -> SyntheticWorkload {
    let mut rng = seed;
    let mut spends = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));
    let mut adds = Vec::with_capacity(usize::try_from(ENTRY_COUNT).unwrap_or(0));

    for i in 0_u64..ENTRY_COUNT {
        let spend_seed = next_u64(&mut rng);
        let outpoint = OutPoint::new(shaped_txid(spend_seed, i, shape), 0);
        spends.push(SyntheticEntry {
            outpoint,
            txout: txout(spend_seed),
            coinbase: false,
            height: 1,
        });
    }

    for i in 0_u64..ENTRY_COUNT {
        let add_seed = next_u64(&mut rng).wrapping_add(i);
        let outpoint = OutPoint::new(shaped_txid(add_seed, i, shape), 0);
        adds.push(SyntheticEntry {
            outpoint,
            txout: txout(add_seed),
            coinbase: false,
            height: 2,
        });
    }

    SyntheticWorkload { spends, adds }
}

fn preload_set(workload: &SyntheticWorkload, seed: u64) -> UtxoSet {
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    for spend in &workload.spends {
        preload.add(utxo_add(spend));
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed)) {
        panic!("synthetic preload failed: {error}");
    }
    set
}

fn block_changes(workload: &SyntheticWorkload) -> BlockChanges {
    let mut changes = BlockChanges::default();
    for spend in &workload.spends {
        changes.remove(spend.outpoint);
    }
    for add in &workload.adds {
        changes.add(utxo_add(add));
    }
    changes
}

fn same_txid_churn_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 0_u32..256 {
        let seed = seed.wrapping_add(u64::from(vout));
        preload.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(seed),
            false,
            1,
        ));
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid preload failed: {error}");
    }

    for vout in 0_u32..128 {
        changes.remove(OutPoint::new(live_txid, vout));
    }
    for vout in 256_u32..384 {
        let seed = seed.wrapping_add(u64::from(vout));
        changes.add(UtxoAdd::new(
            OutPoint::new(live_txid, vout),
            txout(seed),
            false,
            2,
        ));
    }

    (set, changes)
}

fn same_txid_full_spend_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 0_u32..64 {
        let seed = seed.wrapping_add(u64::from(vout));
        let outpoint = OutPoint::new(live_txid, vout);
        preload.add(UtxoAdd::new(outpoint, txout(seed), false, 1));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid full-spend preload failed: {error}");
    }

    (set, changes)
}

fn same_txid_high_vout_full_spend_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let live_txid = txid(seed);
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();

    for vout in 64_u32..128 {
        let seed = seed.wrapping_add(u64::from(vout));
        let outpoint = OutPoint::new(live_txid, vout);
        preload.add(UtxoAdd::new(outpoint, txout(seed), false, 1));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("same-txid high-vout full-spend preload failed: {error}");
    }

    (set, changes)
}

fn spend_fanout_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let source_txid = txid(seed);
    let mut preload = BlockChanges::with_capacity(SPEND_PROXY_FANOUT, 0);
    let mut changes =
        BlockChanges::with_capacity(SPEND_PROXY_FANOUT.saturating_mul(2), SPEND_PROXY_FANOUT);

    for vout in 0..SPEND_PROXY_FANOUT {
        let outpoint = OutPoint::new(source_txid, u32::try_from(vout).unwrap_or(0));
        preload.add(UtxoAdd::new(
            outpoint,
            spend_proxy_coinbase_txout(),
            true,
            SPEND_PROXY_SOURCE_HEIGHT,
        ));
        changes.remove(outpoint);
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("spend-fanout preload failed: {error}");
    }

    let coinbase_txid = txid(seed.wrapping_add(2));
    for vout in 0..SPEND_PROXY_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(coinbase_txid, u32::try_from(vout).unwrap_or(0)),
            spend_proxy_coinbase_txout(),
            true,
            SPEND_PROXY_SPEND_HEIGHT,
        ));
    }
    for index in 0..SPEND_PROXY_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(
                txid(
                    seed.wrapping_add(3)
                        .wrapping_add(u64::try_from(index).unwrap_or(0)),
                ),
                0,
            ),
            spend_proxy_spend_txout(),
            false,
            SPEND_PROXY_SPEND_HEIGHT,
        ));
    }

    (set, changes)
}

fn interleaved_same_txid_churn_case(seed: u64) -> (UtxoSet, BlockChanges) {
    let set = UtxoSet::new();
    let mut preload = BlockChanges::default();
    let mut changes = BlockChanges::default();
    let mut txids = Vec::with_capacity(usize::try_from(INTERLEAVED_TXID_COUNT).unwrap_or(0));

    for tx_index in 0_u32..INTERLEAVED_TXID_COUNT {
        txids.push(shaped_txid(
            seed.wrapping_add(u64::from(tx_index)),
            u64::from(tx_index),
            ShardShape::TwoShard,
        ));
    }

    for vout in 0_u32..INTERLEAVED_VOUTS_PER_TXID {
        for (tx_index, txid) in txids.iter().enumerate() {
            let tx_index = u64::try_from(tx_index).unwrap_or(0);
            let outpoint = OutPoint::new(*txid, vout);
            preload.add(UtxoAdd::new(
                outpoint,
                txout(seed.wrapping_add(tx_index).wrapping_add(u64::from(vout))),
                false,
                1,
            ));
            changes.remove(outpoint);
        }
    }
    if let Err(error) = set.commit_block(&preload, &txid(seed.wrapping_add(1))) {
        panic!("interleaved same-txid preload failed: {error}");
    }

    for vout in INTERLEAVED_VOUTS_PER_TXID..INTERLEAVED_VOUTS_PER_TXID.saturating_mul(2) {
        for (tx_index, txid) in txids.iter().enumerate() {
            let tx_index = u64::try_from(tx_index).unwrap_or(0);
            changes.add(UtxoAdd::new(
                OutPoint::new(*txid, vout),
                txout(
                    seed.wrapping_add(0x1000)
                        .wrapping_add(tx_index)
                        .wrapping_add(u64::from(vout)),
                ),
                false,
                2,
            ));
        }
    }

    (set, changes)
}

fn utxo_add(entry: &SyntheticEntry) -> UtxoAdd {
    UtxoAdd::new(
        entry.outpoint,
        entry.txout.clone(),
        entry.coinbase,
        entry.height,
    )
}

fn synthetic_case(seed: u64, shape: ShardShape) -> (UtxoSet, BlockChanges) {
    let workload = synthetic_workload(seed, shape);
    let set = preload_set(&workload, seed);
    let changes = block_changes(&workload);
    (set, changes)
}

fn spend_proxy_coinbase_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_COINBASE_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn spend_proxy_spend_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_PROXY_SPEND_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn bench_two_shard(c: &mut Criterion) {
    c.bench_function("utxo_commit/two_shard", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::TwoShard),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic two-shard commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_four_shard(c: &mut Criterion) {
    c.bench_function("utxo_commit/four_shard", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::FourShard),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic four-shard commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_full_spend(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_full_spend", |b| {
        b.iter_batched(
            || same_txid_full_spend_case(0x0203_0405),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0212_1314)) {
                    panic!("same-txid full-spend commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_same_txid_high_vout_full_spend(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_high_vout_full_spend", |b| {
        b.iter_batched(
            || same_txid_high_vout_full_spend_case(0x0506_0708),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0512_1314)) {
                    panic!("same-txid high-vout full-spend commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn bench_spend_fanout(c: &mut Criterion) {
    c.bench_function("utxo_commit/spend_fanout_64", |b| {
        b.iter_batched(
            || spend_fanout_case(0x0405_0607),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0412_1314)) {
                    panic!("spend-fanout commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

/// Matched lookup benchmarks measuring compact-record cursor decode cost.
///
/// Reuses `same_txid_churn_case`, which preloads a single txid with 256 live
/// outputs at vouts 0..=255 — a high-fanout same-txid record. The returned
/// `BlockChanges` are intentionally not applied: lookups are read-only and the
/// preloaded state is what the timed body probes. Setup (set construction +
/// the 256-output preload commit + `OutPoint` materialization) happens once
/// outside the timed body; each iteration performs only the public-API lookup
/// call. The `Option<...>` result is wrapped in `black_box` so the decode
/// cannot be dead-code eliminated.
///
/// Hits probe first (vout 0), middle (vout 127), and last (vout 255) outputs,
/// exercising 1, 128, and 256 cursor `decode_output` steps respectively. The
/// miss probes vout 256 on the same txid: the record is found but
/// `find_output` scans all 256 entries and returns `None`, so the full cursor
/// decode cost is measured rather than a hash-table short-circuit.
fn bench_matched_lookup(c: &mut Criterion) {
    let (set, _changes) = same_txid_churn_case(0x0102_0304);
    let live_txid = txid(0x0102_0304);
    let first = OutPoint::new(live_txid, 0);
    let middle = OutPoint::new(live_txid, 127);
    let last = OutPoint::new(live_txid, 255);
    let miss = OutPoint::new(live_txid, 256);

    c.bench_function("utxo_commit/same_txid_lookup_get_first", |b| {
        b.iter(|| black_box(set.get(black_box(&first))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_middle", |b| {
        b.iter(|| black_box(set.get(black_box(&middle))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_last", |b| {
        b.iter(|| black_box(set.get(black_box(&last))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_miss", |b| {
        b.iter(|| black_box(set.get(black_box(&miss))));
    });

    c.bench_function("utxo_commit/same_txid_lookup_get_entry_first", |b| {
        b.iter(|| black_box(set.get_entry(black_box(&first))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_entry_middle", |b| {
        b.iter(|| black_box(set.get_entry(black_box(&middle))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_entry_last", |b| {
        b.iter(|| black_box(set.get_entry(black_box(&last))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_entry_miss", |b| {
        b.iter(|| black_box(set.get_entry(black_box(&miss))));
    });

    c.bench_function("utxo_commit/same_txid_lookup_get_meta_first", |b| {
        b.iter(|| black_box(set.get_meta(black_box(&first))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_meta_middle", |b| {
        b.iter(|| black_box(set.get_meta(black_box(&middle))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_meta_last", |b| {
        b.iter(|| black_box(set.get_meta(black_box(&last))));
    });
    c.bench_function("utxo_commit/same_txid_lookup_get_meta_miss", |b| {
        b.iter(|| black_box(set.get_meta(black_box(&miss))));
    });
}

fn bench_same_txid_cases(c: &mut Criterion) {
    c.bench_function("utxo_commit/same_txid_churn", |b| {
        b.iter_batched(
            || same_txid_churn_case(0x0102_0304),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0112_1314)) {
                    panic!("same-txid churn commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_same_txid_full_spend(c);
    bench_same_txid_high_vout_full_spend(c);
    bench_spend_fanout(c);
    bench_matched_lookup(c);
    c.bench_function("utxo_commit/interleaved_same_txid_churn", |b| {
        b.iter_batched(
            || interleaved_same_txid_churn_case(0x0304_0506),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0312_1314)) {
                    panic!("interleaved same-txid churn commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

fn utxo_commit_synthetic_block(c: &mut Criterion) {
    c.bench_function("utxo_commit/existing", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::Existing),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
    bench_same_txid_cases(c);
    bench_two_shard(c);
    bench_four_shard(c);
    c.bench_function("utxo_commit/concentrated", |b| {
        b.iter_batched(
            || synthetic_case(0x00ab_cdef, ShardShape::Concentrated),
            |(set, changes)| {
                if let Err(error) = set.commit_block(black_box(&changes), &txid(0x0012_3456)) {
                    panic!("synthetic commit failed: {error}");
                }
            },
            BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, utxo_commit_synthetic_block);
criterion_main!(benches);
