//! Durable CoinStats costs: direct MuHash work and one production-shaped
//! listener commit.
#![allow(missing_docs)]

#[cfg(feature = "bench-mimalloc")]
#[global_allocator]
static GLOBAL_MIMALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::hint::black_box;

use bitcoin::{Amount, ScriptBuf};
use bitcoin_rs_primitives::{Hash256, OutPoint, TxOut};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener, MuHash3072};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use zerocopy::IntoBytes;

const DIRECT_COINS: usize = 8_192;
const SPEND_FANOUT: usize = 64;
const SOURCE_HEIGHT: u32 = 1;
const SPEND_HEIGHT: u32 = 101;
const COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_OUTPUT_VALUE: u64 = 78_124_999;

fn coinstats_hotpath(c: &mut Criterion) {
    let encoded = (0..DIRECT_COINS)
        .map(|index| {
            let outpoint = OutPoint::new(txid(index), u32::try_from(index % 64).unwrap_or(0));
            preencoded_coin(&outpoint, &representative_txout(index), 100, true)
        })
        .collect::<Vec<_>>();

    c.bench_function("coinstats/muhash_insert_preencoded_8192", |b| {
        b.iter(|| {
            let mut muhash = MuHash3072::new();
            for bytes in &encoded {
                muhash.insert(black_box(bytes));
            }
            black_box(muhash.finalize_hash());
        });
    });

    c.bench_function("coinstats/muhash_remove_preencoded_8192", |b| {
        b.iter_batched(
            || {
                let mut muhash = MuHash3072::new();
                for bytes in &encoded {
                    muhash.insert(bytes);
                }
                muhash
            },
            |mut muhash| {
                for bytes in &encoded {
                    muhash.remove(black_box(bytes));
                }
                black_box(muhash.finalize_hash());
            },
            BatchSize::SmallInput,
        );
    });

    c.bench_function("coinstats/utxo_commit_listener_spend_fanout_64", |b| {
        b.iter_batched(
            listener_spend_fanout_case,
            |(set, changes)| {
                set.commit_block(black_box(&changes), &txid(0xfeed_cafe))
                    .unwrap_or_else(|error| panic!("coinstats listener commit failed: {error}"));
            },
            BatchSize::SmallInput,
        );
    });
}

fn listener_spend_fanout_case() -> (UtxoSet, BlockChanges) {
    let mut set = UtxoSet::new();
    let mut stats = CoinStats::new();
    let source_txid = txid(0x51_0000);
    let mut preload = BlockChanges::with_capacity(SPEND_FANOUT, 0);
    for vout in 0..SPEND_FANOUT {
        let outpoint = OutPoint::new(source_txid, u32::try_from(vout).unwrap_or(0));
        let txout = coinbase_txout();
        stats.insert_utxo(&outpoint, &txout, SOURCE_HEIGHT, true);
        preload.add(UtxoAdd::new(outpoint, txout, true, SOURCE_HEIGHT));
    }
    set.commit_block(&preload, &txid(0xabcd_1234))
        .unwrap_or_else(|error| panic!("coinstats preload failed: {error}"));
    set.set_listener(Box::new(CoinStatsListener::new(stats)));

    let mut changes = BlockChanges::with_capacity(SPEND_FANOUT.saturating_mul(2), SPEND_FANOUT);
    for vout in 0..SPEND_FANOUT {
        changes.remove(OutPoint::new(source_txid, u32::try_from(vout).unwrap_or(0)));
    }
    let coinbase_txid = txid(0x52_0000);
    for vout in 0..SPEND_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(coinbase_txid, u32::try_from(vout).unwrap_or(0)),
            coinbase_txout(),
            true,
            SPEND_HEIGHT,
        ));
    }
    for index in 0..SPEND_FANOUT {
        changes.add(UtxoAdd::new(
            OutPoint::new(txid(0x53_0000_usize.saturating_add(index)), 0),
            spend_txout(),
            false,
            SPEND_HEIGHT,
        ));
    }
    (set, changes)
}

fn preencoded_coin(op: &OutPoint, txout: &TxOut, height: u32, coinbase: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(36 + 4 + 8 + 9 + txout.script_pubkey.len());
    out.extend_from_slice(op.as_bytes());
    out.extend_from_slice(&((height << 1) | u32::from(coinbase)).to_le_bytes());
    out.extend_from_slice(&txout.value.to_sat().to_le_bytes());
    encode_compact_size_into(&mut out, txout.script_pubkey.len());
    out.extend_from_slice(txout.script_pubkey.as_bytes());
    out
}

fn encode_compact_size_into(out: &mut Vec<u8>, len: usize) {
    if let Ok(byte_len) = u8::try_from(len)
        && byte_len < 0xfd
    {
        out.push(byte_len);
        return;
    }
    if let Ok(word_len) = u16::try_from(len) {
        out.push(0xfd);
        out.extend_from_slice(&word_len.to_le_bytes());
        return;
    }
    if let Ok(dword_len) = u32::try_from(len) {
        out.push(0xfe);
        out.extend_from_slice(&dword_len.to_le_bytes());
        return;
    }
    out.push(0xff);
    out.extend_from_slice(&u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes());
}

fn representative_txout(index: usize) -> TxOut {
    let mut script = Vec::with_capacity(34);
    script.extend_from_slice(&[0x00, 0x20]);
    script.extend_from_slice(&txid(index).to_le_bytes());
    TxOut {
        value: Amount::from_sat(50_000 + u64::try_from(index).unwrap_or(u64::MAX)),
        script_pubkey: ScriptBuf::from_bytes(script),
    }
}

fn coinbase_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(COINBASE_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn spend_txout() -> TxOut {
    TxOut {
        value: Amount::from_sat(SPEND_OUTPUT_VALUE),
        script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
    }
}

fn txid(index: usize) -> Hash256 {
    let seed = u64::try_from(index).unwrap_or(u64::MAX);
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(&seed.rotate_left(11).to_le_bytes());
    bytes[16..24].copy_from_slice(&seed.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_le_bytes());
    bytes[24..32].copy_from_slice(&seed.wrapping_add(0xd1b5_4a32_d192_ed03).to_le_bytes());
    Hash256::from_le_bytes(&bytes)
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(50);
    targets = coinstats_hotpath
}
criterion_main!(benches);
