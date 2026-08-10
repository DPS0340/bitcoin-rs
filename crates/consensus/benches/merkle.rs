//! Merkle root computation benchmarks for the AVX2-capable reducer.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::consensus::Encodable as _;
use bitcoin::hashes::Hash as _;
use bitcoin::{TxMerkleNode, Txid};
use bitcoin_rs_consensus::verify_block::block_merkle_root_matches_txids;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};

fn make_txids(count: usize) -> Vec<Txid> {
    (0..count)
        .map(|i| {
            let mut bytes = [0u8; 32];
            let value = match u32::try_from(i) {
                Ok(value) => value,
                Err(error) => panic!("benchmark size must fit u32: {error}"),
            };
            bytes[0..4].copy_from_slice(&value.to_le_bytes());
            Txid::from_byte_array(bytes)
        })
        .collect()
}

fn scalar_merkle(level: &mut Vec<Txid>) -> Option<(Txid, bool)> {
    if level.is_empty() {
        return None;
    }
    let mut mutated = false;
    while level.len() > 1 {
        mutated |= level.chunks_exact(2).any(|pair| pair[0] == pair[1]);
        let original_len = level.len();
        for parent in 0..original_len.div_ceil(2) {
            let left = level[2 * parent];
            let right = level[(2 * parent + 1).min(original_len - 1)];
            let mut engine = Txid::engine();
            assert!(
                left.consensus_encode(&mut engine).is_ok(),
                "in-memory hash engine write failed"
            );
            assert!(
                right.consensus_encode(&mut engine).is_ok(),
                "in-memory hash engine write failed"
            );
            level[parent] = Txid::from_engine(engine);
        }
        level.truncate(original_len.div_ceil(2));
    }
    Some((level[0], mutated))
}

fn benchmark_root(input: &[Txid]) -> TxMerkleNode {
    match bitcoin::merkle_tree::calculate_root(input.iter().copied()) {
        Some(root) => TxMerkleNode::from(root),
        None => panic!("benchmark inputs must be nonempty"),
    }
}

fn benchmark_block(merkle_root: TxMerkleNode) -> bitcoin::Block {
    bitcoin::Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root,
            time: 0,
            bits: bitcoin::CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txdata: Vec::new(),
    }
}

fn validate_benchmark_input(block: &bitcoin::Block, input: &[Txid]) {
    let mut candidate = input.to_vec();
    assert!(block_merkle_root_matches_txids(block, &mut candidate));

    let mut scalar = input.to_vec();
    let expected = Txid::from_byte_array(block.header.merkle_root.to_byte_array());
    assert_eq!(scalar_merkle(&mut scalar), Some((expected, false)));
}

fn merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    for &leaf_count in &[1, 2, 15, 16, 17, 31, 32, 33] {
        let input = make_txids(leaf_count);
        let root = benchmark_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        let mut scratch = input.clone();
        group.bench_function(BenchmarkId::new("avx2_dispatch_leaves", leaf_count), |b| {
            b.iter(|| {
                scratch.clone_from(&input);
                black_box(block_merkle_root_matches_txids(&block, &mut scratch));
            });
        });
        group.bench_function(BenchmarkId::new("scalar_leaves", leaf_count), |b| {
            b.iter(|| {
                scratch.clone_from(&input);
                black_box(scalar_merkle(&mut scratch));
            });
        });
    }
    for &parent_count in &[8, 64, 1024] {
        let leaf_count = parent_count * 2;
        let input = make_txids(leaf_count);
        let root = benchmark_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        let mut scratch = input.clone();
        group.bench_function(
            BenchmarkId::new("avx2_dispatch_parents", parent_count),
            |b| {
                b.iter(|| {
                    scratch.clone_from(&input);
                    black_box(block_merkle_root_matches_txids(&block, &mut scratch));
                });
            },
        );
        group.bench_function(BenchmarkId::new("scalar_parents", parent_count), |b| {
            b.iter(|| {
                scratch.clone_from(&input);
                black_box(scalar_merkle(&mut scratch));
            });
        });
    }
    group.finish();
}

criterion_group!(benches, merkle_tree);
criterion_main!(benches);
