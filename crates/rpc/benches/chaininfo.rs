//! Whole-log fold cost on the chain-info RPCs.
//!
//! `getblockchaininfo` and `getchaintxstats` both fold every block record the
//! node holds. The log grows one entry per block forever, so the cost of a call
//! that reports a handful of scalars is linear in chain length.
//!
//! This measures that at several log lengths, including the ~963k a mainnet node
//! holds at the time of writing, so the slope is measured rather than assumed.
//! Records are metadata-only, which is what a production node stores: the fold
//! reads `body_size`, `height`, `tx_count` and `time`, and nothing else.
// PERF: Criterion emits public harness items whose docs are irrelevant here.
#![allow(missing_docs)]
// A fixture that fails to build has no meaningful degraded mode.
#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::sync::Arc;

use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, Context, Handler};
use criterion::{Criterion, criterion_group, criterion_main};
use sonic_rs::json;

/// Log lengths to measure. The last is a mainnet tip at the time of writing;
/// the smaller ones are there so the slope can be read off rather than inferred
/// from a single point.
const LOG_LENGTHS: [u32; 4] = [10_000, 100_000, 500_000, 963_124];

fn context_with_records(count: u32) -> Arc<Context> {
    let ctx = Arc::new(Context::new());
    {
        let mut blocks = ctx.blocks.write();
        blocks.reserve(count as usize);
        for height in 0..count {
            let mut hash = [0_u8; 32];
            hash[..4].copy_from_slice(&height.to_le_bytes());
            let mut record = BlockRecord::synthetic(height, Hash256::from_le_bytes(&hash));
            // A real record carries the facts the fold reads. Leaving them zero
            // would still walk the log, but would not fault in the bytes the
            // fold actually touches.
            record.body_size = 1_000_000 + (height as usize % 400_000);
            record.tx_count = 1 + (height as usize % 3_000);
            record.time = 1_231_006_505 + height * 600;
            blocks.push(record);
        }
    }
    ctx
}

fn bench_chaininfo(c: &mut Criterion) {
    let mut group = c.benchmark_group("chain_info_fold");
    group.sample_size(20);

    for count in LOG_LENGTHS {
        let ctx = context_with_records(count);
        let handler = Handler::new(Arc::clone(&ctx));

        group.bench_function(format!("getblockchaininfo/{count}"), |b| {
            b.iter(|| {
                black_box(
                    handler
                        .dispatch("getblockchaininfo", &json!([]))
                        .expect("getblockchaininfo failed"),
                )
            });
        });
        group.bench_function(format!("getchaintxstats/{count}"), |b| {
            b.iter(|| {
                black_box(
                    handler
                        .dispatch("getchaintxstats", &json!([]))
                        .expect("getchaintxstats failed"),
                )
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_chaininfo
}
criterion_main!(benches);
