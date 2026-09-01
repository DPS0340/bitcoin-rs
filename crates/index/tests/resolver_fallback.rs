//! Contract tests for the index resolver's legacy and invalid-position fallbacks.
//!
//! Positions are an optimization of persisted rows, not an authority. A row
//! with no usable position must still resolve against the canonical block, and
//! any position that cannot produce the requested transaction must cause the
//! whole row to fall back to a block scan.
#![allow(clippy::expect_used)]

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
};
use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash, ScriptHistoryEntry};
use bitcoin_rs_storage::{ColumnFamily, KvStore as _, WriteBatch as _};

use common::MemoryStore;

const BASE_HEIGHT: u32 = 100;

struct FixtureSource {
    blocks: HashMap<u32, Block>,
}

impl BlockSource for FixtureSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        self.blocks.get(&height).cloned()
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let bytes = bitcoin::consensus::encode::serialize(self.blocks.get(&height)?);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        bytes.get(start..end).map(<[u8]>::to_vec)
    }
}

fn header() -> block::Header {
    block::Header {
        version: block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}

fn script(tag: u8, len: usize) -> ScriptBuf {
    ScriptBuf::from_bytes(core::iter::repeat_n(tag, len.max(1)).collect())
}

fn tx_with_outputs(seed: u8, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: u32::from(seed),
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn out(script_pubkey: ScriptBuf, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey,
    }
}

fn index_block(indexer: &mut Indexer<MemoryStore>, height: u32, block: &Block) {
    indexer
        .ingest_block(&bitcoin::consensus::encode::serialize(block), height)
        .expect("fixture block ingests");
}

#[test]
fn stale_positions_fall_back_to_the_canonical_block() {
    let target = script(0x77, 22);
    let block_a = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(10, vec![out(script(0xa1, 22), 1)]),
            tx_with_outputs(11, vec![out(target.clone(), 2)]),
            tx_with_outputs(12, vec![out(script(0xa2, 22), 3)]),
        ],
    };
    let block_b = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(20, vec![out(target.clone(), 4), out(script(0xb1, 22), 5)]),
            tx_with_outputs(21, vec![out(script(0xb2, 22), 6)]),
            tx_with_outputs(22, vec![out(target.clone(), 7)]),
        ],
    };

    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    index_block(&mut indexer, BASE_HEIGHT, &block_a);
    let source = FixtureSource {
        blocks: [(BASE_HEIGHT, block_b.clone())].into_iter().collect(),
    };
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());

    assert_eq!(
        indexer
            .resolve_script_history(scripthash, &source)
            .expect("history resolver"),
        vec![
            ScriptHistoryEntry::confirmed(block_b.txdata[0].compute_txid(), BASE_HEIGHT),
            ScriptHistoryEntry::confirmed(block_b.txdata[2].compute_txid(), BASE_HEIGHT),
        ]
    );
    assert_eq!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("unspent resolver"),
        vec![
            (block_b.txdata[0].compute_txid(), 0, 4, BASE_HEIGHT),
            (block_b.txdata[2].compute_txid(), 0, 7, BASE_HEIGHT),
        ]
    );
}

#[test]
fn a_decodable_but_mismatching_position_still_falls_back() {
    let target = script(0x99, 22);
    let decoy_a = script(0xc1, 22);
    let decoy_b = script(0xc2, 22);
    let block_a = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(40, vec![out(decoy_a.clone(), 1)]),
            tx_with_outputs(41, vec![out(target.clone(), 2)]),
            tx_with_outputs(42, vec![out(decoy_a, 3)]),
        ],
    };
    let block_b = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(50, vec![out(decoy_b.clone(), 4)]),
            tx_with_outputs(51, vec![out(decoy_b, 5)]),
            tx_with_outputs(52, vec![out(target.clone(), 6)]),
        ],
    };
    let a_bytes = bitcoin::consensus::encode::serialize(&block_a);
    let b_bytes = bitcoin::consensus::encode::serialize(&block_b);
    assert_eq!(a_bytes.len(), b_bytes.len(), "positions must land on a decoy");

    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    index_block(&mut indexer, BASE_HEIGHT, &block_a);
    let source = FixtureSource {
        blocks: [(BASE_HEIGHT, block_b.clone())].into_iter().collect(),
    };
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());

    assert_eq!(
        indexer
            .resolve_script_history(scripthash, &source)
            .expect("history resolver"),
        vec![ScriptHistoryEntry::confirmed(
            block_b.txdata[2].compute_txid(),
            BASE_HEIGHT
        )]
    );
    assert_eq!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("unspent resolver"),
        vec![(block_b.txdata[2].compute_txid(), 0, 6, BASE_HEIGHT)]
    );
}

#[test]
fn rows_without_positions_resolve_against_the_block() {
    let target = script(0x88, 22);
    let block = Block {
        header: header(),
        txdata: vec![
            tx_with_outputs(30, vec![out(target.clone(), 1)]),
            tx_with_outputs(31, vec![out(target.clone(), 2)]),
        ],
    };
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    index_block(&mut indexer, BASE_HEIGHT, &block);

    for cf in [ColumnFamily::Funding, ColumnFamily::TxConfirmed] {
        let keys = store
            .iter_prefix(cf, &[])
            .expect("iterate rows")
            .map(|entry| entry.expect("row").0)
            .collect::<Vec<_>>();
        let mut batch = store.new_batch();
        for key in keys {
            batch.put(cf, &key, &[]);
        }
        store.write(batch).expect("blank positions");
    }

    let source = FixtureSource {
        blocks: [(BASE_HEIGHT, block.clone())].into_iter().collect(),
    };
    let scripthash = ScriptHash::from_script_bytes(target.as_bytes());
    assert_eq!(
        indexer
            .resolve_script_history(scripthash, &source)
            .expect("history resolver"),
        block
            .txdata
            .iter()
            .map(|tx| ScriptHistoryEntry::confirmed(tx.compute_txid(), BASE_HEIGHT))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        indexer
            .resolve_unspent_outputs_with_height(scripthash, &source)
            .expect("unspent resolver"),
        vec![
            (block.txdata[0].compute_txid(), 0, 1, BASE_HEIGHT),
            (block.txdata[1].compute_txid(), 0, 2, BASE_HEIGHT),
        ]
    );
    assert_eq!(
        indexer
            .resolve_transaction(block.txdata[1].compute_txid(), &source)
            .expect("transaction resolver"),
        Some(block.txdata[1].clone())
    );
}
