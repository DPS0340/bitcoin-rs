//! Exact resolution of a lossy eight-byte funding-row prefix.
#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, VarInt, Witness, absolute, block, transaction,
};
use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash, ScriptHashRow, ScriptHistoryEntry};
use bitcoin_rs_storage::{ColumnFamily, KvStore as _, WriteBatch as _};

use common::MemoryStore;

const HEIGHT: u32 = 100;

struct FixtureSource {
    block: Block,
}

impl BlockSource for FixtureSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        (height == HEIGHT).then(|| self.block.clone())
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let block = self.block_at_height(height)?;
        let bytes = serialize(&block);
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

fn tx(seed: u8, script_pubkey: ScriptBuf, value: u64) -> Transaction {
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
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }],
    }
}

fn script(tag: u8) -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51, tag])
}

#[test]
fn eight_byte_prefix_collision_resolves_full_script_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let target_script = script(0x51);
    let decoy_script = script(0x52);
    let block = Block {
        header: header(),
        txdata: vec![
            tx(1, target_script.clone(), 1_000),
            tx(2, decoy_script, 2_000),
        ],
    };
    let bytes = serialize(&block);
    let first_offset = usize::from(80_u8) + VarInt::from(block.txdata.len()).size();
    let first_len = block.txdata[0].total_size();
    let target_position = TxPosition::new(u32::try_from(first_offset)?, u32::try_from(first_len)?);
    let decoy_position = TxPosition::new(
        u32::try_from(first_offset + first_len)?,
        u32::try_from(block.txdata[1].total_size())?,
    );

    let target = ScriptHash::from_script_bytes(target_script.as_bytes());
    let row = ScriptHashRow::row(target, HEIGHT).to_db_row();
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer.ingest_block(&bytes, HEIGHT)?;

    // A real eight-byte collision makes the writer merge both valid positions
    // under one row key. Model that persisted result directly; unlike the
    // removed fallback tests, every position is an exact range in this
    // canonical block and no row value is blank, stale, or malformed.
    let stored = store
        .get(ColumnFamily::Funding, &row)?
        .expect("target funding row");
    assert_eq!(
        TxPositionValue::decode(&stored),
        Some(core::slice::from_ref(&target_position))
    );
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::Funding,
        &row,
        &TxPositionValue::encode(&[target_position, decoy_position]),
    );
    store.write(batch)?;

    let source = FixtureSource {
        block: block.clone(),
    };
    let entries = indexer.resolve_script_history(target, &source)?;

    assert_eq!(
        entries,
        vec![ScriptHistoryEntry::confirmed(
            block.txdata[0].compute_txid(),
            HEIGHT,
        )]
    );
    Ok(())
}
