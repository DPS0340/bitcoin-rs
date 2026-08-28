//! Tests for the transaction-position row values written by both ingest paths.
//!
//! Two properties matter here and neither is obvious from reading the code:
//!
//! 1. The zero-copy path measures each transaction's byte range directly from
//!    the block slice, while the decoded path derives it arithmetically from
//!    `Transaction::total_size()`. Those are different computations of the same
//!    number, and nothing but a test keeps them equal.
//! 2. A position is only useful if slicing the block at that range yields the
//!    transaction the row was written for.
// A malformed fixture is a test failure; panicking reports it at the call site.
#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{IndexFormat, Indexer, ScriptHash};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    deserialize,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch as _};
use proptest::prelude::*;

use common::MemoryStore;

const HEIGHT: u32 = 321;

fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 7,
        bits: 0,
        nonce: 42,
    }
}

fn script(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    bytes
}

fn tx(seed: u8, outputs: Vec<TxOut>, witness: bool) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
                vout: u32::from(seed),
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
            // A segwit transaction serializes with a marker, a flag and a
            // witness. If `total_size()` and the zero-copy measurement disagree
            // anywhere, it is here.
            witness: if witness {
                vec![vec![0xab; 71], vec![0xcd; 33]]
            } else {
                Vec::new()
            },
        }],
        outputs,
    }
}

fn out(script_pubkey: Vec<u8>, sats: u64) -> TxOut {
    TxOut {
        value: sats,
        script_pubkey,
    }
}

/// A block mixing legacy and segwit transactions, several outputs each, with one
/// script funded from two different transactions.
fn mixed_block() -> Block {
    Block {
        header: header(),
        txs: vec![
            tx(1, vec![out(script(0x11), 1_000)], false),
            tx(
                2,
                vec![out(script(0x22), 2_000), out(script(0x11), 3_000)],
                true,
            ),
            tx(3, vec![out(script(0x33), 4_000)], true),
            tx(
                4,
                vec![out(script(0x44), 5_000), out(vec![0x6a, 0x01], 0)],
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
fn both_ingest_paths_write_identical_row_values() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);
    let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

    let zero_copy = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&zero_copy))
        .ingest_block(&bytes, HEIGHT)
        .expect("zero-copy ingest");

    let decoded = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&decoded))
        .ingest_decoded_block_with_verified_txids(&block, &bytes, HEIGHT, &txids)
        .expect("decoded ingest");

    for cf in [
        ColumnFamily::Funding,
        ColumnFamily::TxConfirmed,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
    ] {
        assert_eq!(
            rows_with_values(&zero_copy, cf),
            rows_with_values(&decoded, cf),
            "ingest paths disagree in {cf:?}"
        );
    }
}

#[test]
fn funding_positions_address_the_transactions_that_funded_the_script() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

    // Script 0x11 is funded by transaction 0 and again by transaction 1, which
    // collapse into a single row: one key, two positions.
    let target = ScriptHash::from_script_bytes(&script(0x11));

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
        let decoded: Tx =
            deserialize(&bytes[start..end]).expect("position slices a whole transaction");
        assert!(
            decoded
                .outputs
                .iter()
                .any(|o| ScriptHash::from_script_bytes(&o.script_pubkey) == target),
            "position must address a transaction that funded the script"
        );
    }
}

#[test]
fn txid_positions_address_their_own_transaction() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

    let rows = rows_with_values(&store, ColumnFamily::TxConfirmed);
    assert_eq!(rows.len(), block.txs.len());

    for (_key, value) in &rows {
        let positions = TxPositionValue::decode(value).expect("row value decodes");
        for position in positions {
            let start = usize::try_from(position.offset()).expect("offset fits usize");
            let end =
                usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
            let decoded: Tx =
                deserialize(&bytes[start..end]).expect("position slices a whole transaction");
            assert!(
                block.txs.contains(&decoded),
                "position must address a transaction of this block"
            );
        }
    }
}

/// The decoded ingest path computes the block prefix as
/// `header || varint(tx_count)`, and that varint is 1 byte below 253
/// transactions and 3 bytes at 253 or above. Every other fixture here is small
/// enough that a hardcoded 1 would pass, so without this case the arithmetic is
/// untested for real blocks — mainnet blocks carry thousands of transactions.
///
/// Verified by mutation: replacing `VarInt::from(len).size()` with a literal `1`
/// leaves every other test in this file green and fails only this one.
#[test]
fn both_ingest_paths_agree_across_the_transaction_count_varint_boundary() {
    for tx_count in [252_usize, 253, 254] {
        let txs = (0..tx_count)
            .map(|index| {
                let seed = u8::try_from(index % 256).unwrap_or(0);
                tx(
                    seed,
                    vec![out(script(u8::try_from(index % 7).unwrap_or(0)), 1_000)],
                    index % 3 == 0,
                )
            })
            .collect::<Vec<_>>();
        let block = Block {
            header: header(),
            txs,
        };
        let bytes = consensus_bytes(&block);
        let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

        let zero_copy = Arc::new(MemoryStore::default());
        Indexer::new(Arc::clone(&zero_copy))
            .ingest_block(&bytes, HEIGHT)
            .expect("zero-copy ingest");

        let decoded = Arc::new(MemoryStore::default());
        Indexer::new(Arc::clone(&decoded))
            .ingest_decoded_block_with_verified_txids(&block, &bytes, HEIGHT, &txids)
            .expect("decoded ingest");

        for cf in [ColumnFamily::Funding, ColumnFamily::TxConfirmed] {
            assert_eq!(
                rows_with_values(&zero_copy, cf),
                rows_with_values(&decoded, cf),
                "ingest paths disagree in {cf:?} at {tx_count} transactions"
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
        .ingest_block(&consensus_bytes(&mixed_block()), HEIGHT)
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

    /// The two ingest paths must agree on every block shape, not just the
    /// hand-written one. The varint boundary at 253 transactions is covered
    /// separately by `both_ingest_paths_agree_across_the_transaction_count_varint_boundary`,
    /// because generating blocks that large under proptest is too slow to be
    /// worth it here.
    #[test]
    fn both_ingest_paths_agree_on_random_blocks(
        shapes in proptest::collection::vec((0_u8..4, any::<bool>()), 1..8),
    ) {
        let txdata = shapes
            .iter()
            .enumerate()
            .map(|(index, (tag, witness))| {
                let seed = u8::try_from(index % 256).unwrap_or(0);
                tx(seed, vec![out(script(*tag), u64::from(*tag) + 1)], *witness)
            })
            .collect();
        let block = Block { header: header(), txs: txdata };
        let bytes = consensus_bytes(&block);
        let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();

        let zero_copy = Arc::new(MemoryStore::default());
        Indexer::new(Arc::clone(&zero_copy))
            .ingest_block(&bytes, HEIGHT)
            .expect("zero-copy ingest");

        let decoded = Arc::new(MemoryStore::default());
        Indexer::new(Arc::clone(&decoded))
            .ingest_decoded_block_with_verified_txids(&block, &bytes, HEIGHT, &txids)
            .expect("decoded ingest");

        for cf in [ColumnFamily::Funding, ColumnFamily::TxConfirmed] {
            prop_assert_eq!(
                rows_with_values(&zero_copy, cf),
                rows_with_values(&decoded, cf)
            );
        }
    }
}
