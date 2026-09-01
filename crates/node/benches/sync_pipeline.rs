//! Canonical current-path block-apply benchmarks.
//!
//! The two retained shapes protect distinct production costs: a contiguous
//! coinbase-only prefix and a mature, spend-heavy prefix that exercises UTXO
//! removal plus `CoinStats` listener work. Protocol-ordering and burst cases are
//! correctness tests, not separate long-lived performance contracts.
#![allow(missing_docs)]

use std::hint::black_box;

use bitcoin::absolute;
use bitcoin::block::Header;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::{
    Amount, Block, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxMerkleNode,
    TxOut, Txid, Witness, transaction,
};
use bitcoin_rs_node::{Config, Network, state::NodeState};
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use tempfile::TempDir;

const PROXY_BLOCKS: u32 = 32;
const COINBASE_MATURITY: u32 = 100;
const SPEND_BLOCKS: u32 = 16;
const SPEND_FANOUT: u32 = 64;
const COINBASE_OUTPUT_VALUE: u64 = 78_125_000;
const SPEND_OUTPUT_VALUE: u64 = 78_124_999;

fn sync_pipeline(c: &mut Criterion) {
    let blocks = proxy_blocks(PROXY_BLOCKS);
    c.bench_function("node_apply/contiguous_32_blocks", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for block in &blocks {
                    state
                        .apply_block(black_box(block))
                        .unwrap_or_else(|error| panic!("proxy apply failed: {error}"));
                }
                black_box(
                    state
                        .applied_tip()
                        .load_full()
                        .unwrap_or_else(|| panic!("proxy apply did not publish a tip"))
                        .height,
                );
            },
            BatchSize::SmallInput,
        );
    });

    let spend_blocks = spend_heavy_proxy_blocks();
    c.bench_function("node_apply/spend_heavy_16_blocks_fanout_64", |b| {
        b.iter_batched(
            open_regtest_state,
            |(_dir, state)| {
                for block in &spend_blocks {
                    state
                        .apply_block(black_box(block))
                        .unwrap_or_else(|error| panic!("spend-heavy apply failed: {error}"));
                }
                black_box(
                    state
                        .applied_tip()
                        .load_full()
                        .unwrap_or_else(|| panic!("spend-heavy apply did not publish a tip"))
                        .height,
                );
            },
            BatchSize::SmallInput,
        );
    });
}

fn open_regtest_state() -> (TempDir, NodeState) {
    let dir = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir failed: {error}"));
    let mut config = Config::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p_listen.clear();
    config.txindex = false;
    let state =
        NodeState::open(config).unwrap_or_else(|error| panic!("open node state failed: {error}"));
    (dir, state)
}

fn proxy_blocks(count: u32) -> Vec<Block> {
    let mut blocks = Vec::with_capacity(
        usize::try_from(count).unwrap_or_else(|error| panic!("invalid proxy count: {error}")),
    );
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..count {
        let block = child_coinbase_block(&parent, height);
        parent = block.clone();
        blocks.push(block);
    }
    blocks
}

fn spend_heavy_proxy_blocks() -> Vec<Block> {
    let spend_start_height = COINBASE_MATURITY.saturating_add(1);
    let spend_end_height = spend_start_height
        .saturating_add(SPEND_BLOCKS)
        .saturating_sub(1);
    let capacity = usize::try_from(spend_end_height.saturating_add(1))
        .unwrap_or_else(|error| panic!("invalid spend proxy capacity: {error}"));
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut blocks = Vec::with_capacity(capacity);
    blocks.push(genesis.clone());
    let mut parent = genesis;
    for height in 1..=spend_end_height {
        let block = if height < spend_start_height {
            child_fanout_coinbase_block(&parent, height)
        } else {
            let source_height = height.saturating_sub(COINBASE_MATURITY);
            let source_index = usize::try_from(source_height)
                .unwrap_or_else(|error| panic!("invalid source height: {error}"));
            child_spend_fanout_block(&parent, height, &blocks[source_index])
        };
        parent = block.clone();
        blocks.push(block);
    }
    blocks
}

fn child_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![coinbase_transaction(height)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("proxy block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
}

fn child_fanout_coinbase_block(parent: &Block, height: u32) -> Block {
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![fanout_coinbase_transaction(height)],
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("fanout block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
}

fn child_spend_fanout_block(parent: &Block, height: u32, source_block: &Block) -> Block {
    let source_txid = source_block
        .txdata
        .first()
        .unwrap_or_else(|| panic!("spend source missing coinbase"))
        .compute_txid();
    let mut txdata = Vec::with_capacity(
        usize::try_from(SPEND_FANOUT.saturating_add(1))
            .unwrap_or_else(|error| panic!("invalid spend fanout: {error}")),
    );
    txdata.push(fanout_coinbase_transaction(height));
    for vout in 0..SPEND_FANOUT {
        txdata.push(spend_proxy_transaction(source_txid, vout));
    }
    let mut block = Block {
        header: Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: parent.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: parent.header.time.saturating_add(1),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .unwrap_or_else(|| panic!("spend-heavy block should have merkle root"));
    mine_block_to_declared_target(&mut block);
    block
}

fn coinbase_transaction(height: u32) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn fanout_coinbase_transaction(height: u32) -> Transaction {
    let outputs = (0..SPEND_FANOUT)
        .map(|_| TxOut {
            value: Amount::from_sat(COINBASE_OUTPUT_VALUE),
            script_pubkey: Builder::new().push_int(1).into_script(),
        })
        .collect();
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn spend_proxy_transaction(prev_txid: Txid, vout: u32) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: prev_txid,
                vout,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(SPEND_OUTPUT_VALUE),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    }
}

fn coinbase_script_sig(height: u32) -> ScriptBuf {
    let mut script = Vec::with_capacity(5);
    script.push(4);
    script.extend_from_slice(&height.to_le_bytes());
    ScriptBuf::from_bytes(script)
}

fn mine_block_to_declared_target(block: &mut Block) {
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block
            .header
            .nonce
            .checked_add(1)
            .unwrap_or_else(|| panic!("exhausted nonce while mining proxy block"));
    }
}

criterion_group!(benches, sync_pipeline);
criterion_main!(benches);
