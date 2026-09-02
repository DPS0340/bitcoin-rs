//! Tests for the persisted transaction-position row values.
//!
//! A position is only useful if slicing the canonical block bytes at that range
//! yields the transaction the row was written for. The row encoding and legacy
//! format markers are persisted-index contracts; ingest implementation parity
//! is intentionally not tested here.
// A malformed fixture is a test failure; panicking reports it at the call site.
#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Txid, Witness, absolute, block, transaction,
};
use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{IndexFormat, Indexer, ScriptHash};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch as _};
use proptest::prelude::*;

use common::MemoryStore;

const HEIGHT: u32 = 321;

fn header() -> block::Header {
    block::Header {
        version: block::Version::ONE,
        prev_blockhash: BlockHash::all_zeros(),
        merkle_root: TxMerkleNode::all_zeros(),
        time: 7,
        bits: CompactTarget::from_consensus(0),
        nonce: 42,
    }
}

fn script(tag: u8) -> ScriptBuf {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    ScriptBuf::from_bytes(bytes)
}

fn tx(seed: u8, outputs: Vec<TxOut>, witness: bool) -> Transaction {
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
            // A segwit transaction serializes with a marker, a flag and a
            // witness. If `total_size()` and the zero-copy measurement disagree
            // anywhere, it is here.
            witness: if witness {
                Witness::from_slice(&[vec![0xab; 71], vec![0xcd; 33]])
            } else {
                Witness::new()
            },
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

/// A block mixing legacy and segwit transactions, several outputs each, with one
/// script funded from two different transactions.
fn mixed_block() -> Block {
    Block {
        header: header(),
        txdata: vec![
            tx(1, vec![out(script(0x11), 1_000)], false),
            tx(
                2,
                vec![out(script(0x22), 2_000), out(script(0x11), 3_000)],
                true,
            ),
            tx(3, vec![out(script(0x33), 4_000)], true),
            tx(
                4,
                vec![
                    out(script(0x44), 5_000),
                    out(ScriptBuf::from_bytes(vec![0x6a, 0x01]), 0),
                ],
                false,
            ),
        ],
    }
}

fn rows_with_values(store: &MemoryStore, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
    store
        .iter_prefix(cf, &[])
        .expect("iterate")
        .map(|entry| entry.expect("row"))
        .collect()
}

#[test]
fn funding_positions_address_the_transactions_that_funded_the_script() {
    let block = mixed_block();
    let bytes = serialize(&block);

    let store = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

    // Script 0x11 is funded by transaction 0 and again by transaction 1, which
    // collapse into a single row: one key, two positions.
    let target = ScriptHash::from_script_bytes(script(0x11).as_bytes());

    let rows = rows_with_values(&store, ColumnFamily::Funding);
    let (_key, value) = rows
        .iter()
        .find(|(key, _)| key.starts_with(&target.prefix()))
        .expect("funding row for the target script");

    let positions = TxPositionValue::decode(value).expect("row value decodes");
    assert_eq!(positions.len(), 2, "two transactions funded this script");

    for position in positions {
        let start = usize::try_from(position.offset()).expect("offset fits usize");
        let end = usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
        let decoded: Transaction =
            deserialize(&bytes[start..end]).expect("position slices a whole transaction");
        assert!(
            decoded
                .output
                .iter()
                .any(|o| ScriptHash::from_script_bytes(o.script_pubkey.as_bytes()) == target),
            "position must address a transaction that funded the script"
        );
    }
}

#[test]
fn txid_positions_address_their_own_transaction() {
    let block = mixed_block();
    let bytes = serialize(&block);

    let store = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

    let rows = rows_with_values(&store, ColumnFamily::TxConfirmed);
    assert_eq!(rows.len(), block.txdata.len());

    for (_key, value) in &rows {
        let positions = TxPositionValue::decode(value).expect("row value decodes");
        for position in positions {
            let start = usize::try_from(position.offset()).expect("offset fits usize");
            let end =
                usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
            let decoded: Transaction =
                deserialize(&bytes[start..end]).expect("position slices a whole transaction");
            assert!(
                block.txdata.contains(&decoded),
                "position must address a transaction of this block"
            );
        }
    }
}

#[test]
fn an_empty_index_adopts_the_current_format() {
    let store = Arc::new(MemoryStore::default());
    let indexer = Indexer::new(Arc::clone(&store));

    assert_eq!(
        indexer.ensure_format_version().expect("read format"),
        IndexFormat::Current
    );
    // The marker persists, so a later open reports the same without re-deciding.
    assert_eq!(
        Indexer::new(store).ensure_format_version().expect("reopen"),
        IndexFormat::Current
    );
}

#[test]
fn a_populated_index_without_a_marker_is_legacy() {
    // Rows but no marker is exactly what a database written before this format
    // looks like. Adopting the current version here would claim positions that
    // are not in those rows.
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer
        .ingest_block(&serialize(&mixed_block()), HEIGHT)
        .expect("ingest");
    // Undo the marker the ingest path never writes, in case a future change adds
    // one: this test is about the no-marker state specifically.
    let mut batch = store.new_batch();
    batch.delete(ColumnFamily::UtxoMeta, b"index:format_version");
    store.write(batch).expect("clear marker");

    assert_eq!(
        indexer.ensure_format_version().expect("read format"),
        IndexFormat::Legacy { found: None }
    );
}

/// None of these may be trusted as current, and an unreadable marker must be
/// distinguishable from a genuine version 0.
///
/// Both take the scan path, so the distinction is not behavioural — it is
/// diagnostic. Reporting damaged bytes as "version 0" sends the operator to
/// delete the index directory, which destroys the only evidence of whatever
/// wrote them.
#[test]
fn an_older_marker_is_legacy_and_an_unreadable_one_is_reported_as_such() {
    let store = Arc::new(MemoryStore::default());
    let indexer = Indexer::new(Arc::clone(&store));

    for (bytes, expected) in [
        (vec![0_u8; 4], IndexFormat::Legacy { found: Some(0) }),
        (
            99_u32.to_le_bytes().to_vec(),
            IndexFormat::Legacy { found: Some(99) },
        ),
        (vec![1_u8], IndexFormat::UnreadableMarker { len: 1 }),
        (vec![1_u8; 9], IndexFormat::UnreadableMarker { len: 9 }),
        (Vec::new(), IndexFormat::UnreadableMarker { len: 0 }),
    ] {
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::UtxoMeta, b"index:format_version", &bytes);
        store.write(batch).expect("write marker");
        assert_eq!(
            indexer.ensure_format_version().expect("read format"),
            expected,
            "marker {bytes:?} must not be trusted as current"
        );
    }
}

#[test]
fn an_empty_value_decodes_to_none() {
    // Rows written before this format carry an empty value. A reader must treat
    // that as "no positions available, scan the block", never as "this block has
    // zero matching transactions".
    assert!(TxPositionValue::decode(&[]).is_none());
}

#[test]
fn a_partial_position_decodes_to_none() {
    let value = TxPositionValue::encode(&[TxPosition::new(100, 200), TxPosition::new(300, 400)]);
    for truncated in 1..value.len() {
        if truncated % 8 == 0 {
            // Whole positions are a well-formed shorter list.
            continue;
        }
        assert!(
            TxPositionValue::decode(&value[..truncated]).is_none(),
            "a {truncated}-byte value must not decode"
        );
    }
}

proptest! {
    #[test]
    fn position_values_round_trip(
        raw in proptest::collection::vec((any::<u32>(), any::<u32>()), 1..32),
    ) {
        let positions = raw
            .iter()
            .map(|(offset, len)| TxPosition::new(*offset, *len))
            .collect::<Vec<_>>();
        let encoded = TxPositionValue::encode(&positions);
        let decoded = TxPositionValue::decode(&encoded).expect("decodes");
        prop_assert_eq!(decoded, positions.as_slice());
    }

}
