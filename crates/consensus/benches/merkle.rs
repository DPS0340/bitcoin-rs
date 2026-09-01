//! Merkle root computation benchmarks for the AVX2-capable reducer.
// PERF: Criterion emits public harness items whose docs are irrelevant to the benchmark report.
#![allow(missing_docs)]

use std::hint::black_box;

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
}

fn merkle_tree(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");
    for &leaf_count in &[1, 2, 15, 16, 17, 31, 32, 33] {
        let input = make_txids(leaf_count);
        let root = benchmark_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        let mut scratch = input.clone();
        group.bench_function(
            BenchmarkId::new("current_dispatch_leaves", leaf_count),
            |b| {
                b.iter(|| {
                    scratch.clone_from(&input);
                    black_box(block_merkle_root_matches_txids(&block, &mut scratch));
                });
            },
        );
    }
    for &parent_count in &[8, 64, 1024] {
        let leaf_count = parent_count * 2;
        let input = make_txids(leaf_count);
        let root = benchmark_root(&input);
        let block = benchmark_block(root);
        validate_benchmark_input(&block, &input);
        let mut scratch = input.clone();
        group.bench_function(
            BenchmarkId::new("current_dispatch_parents", parent_count),
            |b| {
                b.iter(|| {
                    scratch.clone_from(&input);
                    black_box(block_merkle_root_matches_txids(&block, &mut scratch));
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, merkle_tree);
criterion_main!(benches);
