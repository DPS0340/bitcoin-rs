//! Witness staging-gate regressions for `check_block_witness_well_formed`.
//!
//! Independent reference: BIP141 commitment structure and Bitcoin Core v31.0
//! `CheckWitnessMalleation`. These fixtures isolate the staging-time witness
//! gate that prevents a peer from wedging sync by sending a witness-stripped
//! body (issue #1070). They are not mined or UTXO-valid chain fixtures.

use bitcoin_rs_consensus::ConsensusError;
use bitcoin_rs_consensus::check_block_witness_well_formed;
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Header, LockTime, OutPoint, Script, Sequence, Tx,
    TxIn, TxOut, Txid, Witness,
};

const PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
// SHA256d(00*32 || 00*32): coinbase-only witness root and zero reserved value.
const ZERO_RESERVED_COMMITMENT: [u8; 32] = [
    0xe2, 0xf6, 0x1c, 0x3f, 0x71, 0xd1, 0xde, 0xfd, 0x3f, 0xa9, 0x99, 0xdf, 0xa3, 0x69, 0x53, 0x75,
    0x5c, 0x69, 0x06, 0x89, 0x79, 0x99, 0x62, 0xb4, 0x8b, 0xeb, 0xd8, 0x36, 0x97, 0x4e, 0x8c, 0xf9,
];

fn commitment_output(value: [u8; 32]) -> TxOut {
    let mut script_pubkey = PREFIX.to_vec();
    script_pubkey.extend_from_slice(&value);
    TxOut {
        value: Amount::from_sat(0),
        script_pubkey: Script::from_bytes(script_pubkey),
    }
}

fn coinbase(witness: Option<Vec<Vec<u8>>>, commitment: Option<[u8; 32]>) -> Tx {
    let mut tx = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), u32::MAX),
            script_sig: Script::from_bytes(vec![1, 1]),
            sequence: Sequence::from_consensus(u32::MAX),
            witness: witness.map_or_else(Witness::new, Witness::from_stack),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    if let Some(commitment) = commitment {
        tx.outputs.push(commitment_output(commitment));
    }
    tx
}

fn block(tx: Tx) -> Block {
    let merkle_root = tx.txid().into();
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 0,
            bits: CompactTarget::from_consensus(0),
            nonce: 0,
        },
        txs: vec![tx],
    }
}

/// (a) A block with a BIP141 commitment but a witness-stripped coinbase
/// must be rejected: the peer removed the witness, and the stager must not
/// keep this body.
#[test]
fn commitment_block_with_stripped_witness_is_rejected() {
    let block = block(coinbase(None, Some(ZERO_RESERVED_COMMITMENT)));
    assert_eq!(
        check_block_witness_well_formed(&block),
        Err(ConsensusError::WitnessNonceSize)
    );
}

/// (b) A block with a well-formed coinbase witness (1×32B) but a commitment
/// that does not match the computed witness merkle root must be rejected.
#[test]
fn commitment_block_with_mismatched_commitment_is_rejected() {
    let wrong_commitment = [0xFF; 32];
    let block = block(coinbase(Some(vec![vec![0; 32]]), Some(wrong_commitment)));
    assert_eq!(
        check_block_witness_well_formed(&block),
        Err(ConsensusError::WitnessCommitment)
    );
}

/// (c) A block with a BIP141 commitment and a matching coinbase witness
/// passes the staging gate.
#[test]
fn commitment_block_with_correct_witness_passes() {
    let block = block(coinbase(
        Some(vec![vec![0; 32]]),
        Some(ZERO_RESERVED_COMMITMENT),
    ));
    assert_eq!(check_block_witness_well_formed(&block), Ok(()));
}

/// (d) A block without a BIP141 commitment output passes the staging gate
/// regardless of witness presence: pre-segwit blocks have no witness to
/// strip, and witness-without-commitment is a different invalidity class.
#[test]
fn block_without_commitment_passes() {
    let block = block(coinbase(None, None));
    assert_eq!(check_block_witness_well_formed(&block), Ok(()));
}
