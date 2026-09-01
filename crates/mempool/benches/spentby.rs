//! Current-path scaling benchmark for the mempool `spentby` answer.
//!
//! `getrawmempool true` renders a `spentby` list for every entry in the pool.
//! The benchmark protects the maintained spending index over several pool
//! sizes without retaining the quadratic scan it replaced.
#![allow(missing_docs)]
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_mempool::{EntryId, Mempool, MempoolEntry, MempoolLimits};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..outputs)
            .map(|vout| TxOut {
                value: Amount::from_sat(10_000 + u64::from(vout) + tag * 1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            })
            .collect(),
    }
}

fn pool_with(pairs: u64) -> Mempool {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        ..MempoolLimits::default()
    });
    for pair in 0..pairs {
        let mut seed = [0_u8; 32];
        seed[..8].copy_from_slice(&pair.to_le_bytes());
        let funding = OutPoint::new(Txid::from_byte_array(seed), 0);
        let parent = tx_with(&[funding], 2, pair);
        let parent_txid = parent.compute_txid();
        let child = tx_with(&[OutPoint::new(parent_txid, 0)], 1, pair);
        for tx in [parent, child] {
            let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7);
            pool.insert_entry(entry)
                .expect("benchmark fixture insert must succeed");
        }
    }
    pool
}

fn spentby_by_index(pool: &Mempool) -> Vec<Vec<String>> {
    let mut rendered = Vec::with_capacity(pool.len());
    for (index, _entry) in &pool.entries {
        let id = EntryId::try_from(index).expect("entry index must fit an EntryId");
        let mut spentby: Vec<String> = pool
            .spender_txids(id)
            .iter()
            .map(ToString::to_string)
            .collect();
        spentby.sort();
        spentby.dedup();
        rendered.push(spentby);
    }
    rendered
}

fn bench_spentby(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mempool_spentby");
    for pairs in [256_u64, 1_024, 2_048] {
        let pool = pool_with(pairs);
        let entries = pool.len();
        group.bench_with_input(
            BenchmarkId::new("spending_index", entries),
            &pool,
            |b, pool| {
                b.iter(|| black_box(spentby_by_index(black_box(pool))));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_spentby);
criterion_main!(benches);
