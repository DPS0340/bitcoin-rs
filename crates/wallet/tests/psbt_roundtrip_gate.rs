//! What runs in place of `psbt_roundtrip` when the kernel backend is absent.
//!
//! A gated-out test file compiles to an empty binary, and an empty binary
//! reports success. That is the failure mode the gate on `psbt_roundtrip` was
//! added to remove, so replacing one silence with another would be no
//! improvement: this keeps a named test in the output, so a run that skips the
//! consensus roundtrip looks like a run that skips it.
//!
//! It also checks that the reason is the one claimed. If the portable backend
//! ever starts verifying real spends, `psbt_roundtrip` is being skipped for a
//! reason that no longer holds, and somebody should find that out here rather
//! than by wondering why coverage went quiet.
#![cfg(not(feature = "kernel"))]

use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid};
use bitcoin_rs_script::{Interpreter, VerifyFlags};

/// The portable script backend is why the consensus roundtrip is not running.
///
/// Asked of the backend directly rather than through
/// `bitcoin_rs_consensus::verify_transaction`, because the backend is the whole
/// of the reason and going through the consensus layer would add height and
/// locktime rules that have nothing to do with it.
#[test]
fn the_consensus_roundtrip_needs_the_kernel_backend() {
    let prevout = TxOut {
        value: Amount::from_sat(1_000),
        script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([7_u8; 20])),
    };
    let spending = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([3_u8; 32]), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(900),
            script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([9_u8; 20])),
        }],
    };

    let outcome = Interpreter::default().execute(
        prevout.script_pubkey.as_bytes(),
        &[],
        &[],
        VerifyFlags::P2SH,
        &prevout,
        &spending,
        0,
    );
    assert!(
        outcome.is_err(),
        "the portable backend verified a real spend, so `psbt_roundtrip` is \
         being skipped for a reason that no longer holds -- run it with \
         `--features kernel` and consider removing the gate"
    );
}
