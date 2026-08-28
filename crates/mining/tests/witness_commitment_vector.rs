//! Fixed BIP141 witness-commitment vector.
//!
//! The candidate assembly output is pinned three ways: against hard-coded
//! commitment bytes derived out-of-band with coreutils `sha256sum`, against
//! `bitcoin::Block::witness_root` (rust-bitcoin's own BIP141 implementation),
//! and against the byte layout of the `OP_RETURN` commitment script.

use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::{Hash as _, HashEngine as _, sha256d};
use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute, block,
    transaction,
};
use bitcoin_rs_mempool::{MempoolMiningSnapshot, SnapshotEntry};
use bitcoin_rs_mining::{
    CandidateContext, WITNESS_RESERVED_VALUE, assemble_candidate, witness_commitment_script,
};
use bitcoin_rs_primitives::{Hash256, Network};

/// Pinned commitment bytes for the vector below, derived by piping
/// `witness_root || reserved_value` through `sha256sum` twice with coreutils,
const VECTOR_COMMITMENT: [u8; 32] = [
    0xd2, 0x31, 0x9f, 0x64, 0x3d, 0x27, 0xbc, 0x0e, 0xcb, 0xa4, 0xf0, 0xc8, 0xb6, 0x90, 0xef, 0x3e,
    0xb6, 0x4f, 0x69, 0x21, 0x65, 0xec, 0x29, 0x41, 0xf2, 0x3e, 0xac, 0xb0, 0x64, 0x76, 0xec, 0xe6,
];

#[test]
fn witness_commitment_matches_pinned_vector_and_rust_bitcoin_root() -> Result<(), Box<dyn Error>> {
    let parent = witnessed_tx(1, 50_000, None);
    let child = witnessed_tx(2, 40_000, Some(parent.compute_txid()));
    let snapshot = snapshot_with(&[parent.clone(), child.clone()], &[2_000, 3_000]);

    let candidate = assemble_candidate(&vector_context(true), &snapshot, &payout())?;
    let commitment = candidate
        .witness_commitment
        .ok_or("segwit-active candidate must carry a commitment")?;
    let root = candidate
        .witness_merkle_root
        .ok_or("segwit-active candidate must carry a witness root")?;

    // 1. Pinned out-of-band vector.
    assert_eq!(
        commitment.as_byte_array(),
        &VECTOR_COMMITMENT,
        "assembled commitment diverges from the pinned BIP141 vector"
    );

    // 2. rust-bitcoin's witness root over the same tx set (coinbase wtxid
    //    replaced with zeros per BIP141).
    let oracle_block = block::Block {
        header: block::Header {
            version: block::Version::from_consensus(0x2000_0000),
            prev_blockhash: block::BlockHash::from_byte_array([0xab; 32]),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1_700_000_600,
            bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata: vec![candidate.coinbase.clone(), parent, child],
    };
    let oracle_root = oracle_block
        .witness_root()
        .ok_or("oracle block must yield a witness root")?;
    assert_eq!(
        root.as_byte_array(),
        oracle_root.as_byte_array(),
        "witness merkle root diverges from the rust-bitcoin oracle"
    );

    // 3. Commitment recomputed from the oracle root over the reserved value.
    let mut engine = sha256d::Hash::engine();
    engine.input(oracle_root.as_byte_array());
    engine.input(&WITNESS_RESERVED_VALUE);
    let recomputed = sha256d::Hash::from_engine(engine);
    assert_eq!(
        commitment.as_byte_array(),
        recomputed.as_byte_array(),
        "commitment is not dSHA256(witness_root || reserved_value)"
    );

    // Byte equality of the commitment output script against the pinned bytes.
    let script = witness_commitment_script(&commitment);
    assert_eq!(
        script.as_bytes(),
        commitment_script_bytes(&VECTOR_COMMITMENT),
        "commitment output script diverges from the pinned BIP141 script bytes"
    );

    // The coinbase actually carries the commitment output and the reserved value.
    let commitment_output = candidate
        .coinbase
        .output
        .iter()
        .find(|output| output.script_pubkey == script)
        .ok_or("coinbase must carry the commitment output script")?;
    assert_eq!(commitment_output.value, Amount::ZERO);
    assert_eq!(
        candidate.coinbase.input[0].witness.to_vec(),
        vec![WITNESS_RESERVED_VALUE.to_vec()],
        "coinbase witness must be exactly the 32-byte reserved value"
    );

    // Legacy fallback: no commitment anywhere when segwit is inactive.
    let legacy = assemble_candidate(
        &vector_context(false),
        &snapshot_with(&[witnessed_tx(1, 50_000, None)], &[2_000]),
        &payout(),
    )?;
    assert!(legacy.witness_commitment.is_none());
    assert!(legacy.witness_merkle_root.is_none());
    assert!(legacy.witness_reserved_value.is_none());
    assert!(
        !legacy
            .coinbase
            .output
            .iter()
            .any(|output| output.script_pubkey.is_op_return())
    );
    assert!(legacy.coinbase.input[0].witness.is_empty());
    Ok(())
}

fn vector_context(segwit_active: bool) -> CandidateContext {
    CandidateContext {
        previous_block_hash: Hash256::from_le_bytes(&[0xab; 32]),
        height: 1,
        version: 0x2000_0000,
        bits: 0x207f_ffff,
        min_time: 1_700_000_001,
        current_time: 1_700_000_600,
        locktime_cutoff: 1_700_000_000,
        network: Network::Regtest,
        csv_active: true,
        segwit_active,
        max_weight: 4_000_000,
        max_size: 4_000_000,
        max_sigops: 80_000,
    }
}

fn payout() -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0x51])
}

fn witnessed_tx(label: u8, value: u64, parent: Option<bitcoin::Txid>) -> Transaction {
    let mut witness = Witness::new();
    witness.push([label; 32]);
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(
                parent.unwrap_or_else(|| {
                    let mut bytes = [0_u8; 32];
                    bytes[0] = label;
                    bitcoin::Txid::from_byte_array(bytes)
                }),
                0,
            ),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, label]),
        }],
    }
}

fn snapshot_entry(tx: Transaction, fee: u64) -> SnapshotEntry {
    let tx = Arc::new(tx);
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    SnapshotEntry {
        txid: tx.compute_txid(),
        wtxid: tx.compute_wtxid(),
        vsize,
        bip141_vsize: vsize,
        size: u32::try_from(tx.total_size()).unwrap_or(u32::MAX),
        weight: tx.weight().to_wu(),
        sigop_cost: u32::try_from(tx.total_sigop_cost(|_| None)).unwrap_or(0),
        fee,
        fee_delta: 0,
        time: 0,
        height: 0,
        ancestor_size: u64::from(vsize),
        ancestor_fee: fee,
        ancestor_fee_delta: i128::from(fee),
        ancestors: Vec::new(),
        tx,
    }
}

fn snapshot_with(txs: &[Transaction], fees: &[u64]) -> MempoolMiningSnapshot {
    MempoolMiningSnapshot {
        sequence: 7,
        entries: txs
            .iter()
            .zip(fees.iter())
            .map(|(tx, fee)| snapshot_entry(tx.clone(), *fee))
            .collect(),
    }
}

/// `OP_RETURN OP_PUSHBYTES_36 aa21a9ed <32-byte commitment>`.
fn commitment_script_bytes(commitment: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(38);
    bytes.push(OP_RETURN.to_u8());
    bytes.push(OP_PUSHBYTES_36.to_u8());
    bytes.extend_from_slice(&[0xaa, 0x21, 0xa9, 0xed]);
    bytes.extend_from_slice(commitment);
    bytes
}
