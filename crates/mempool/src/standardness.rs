//! Bitcoin Core `IsStandardTx` / `IsStandard` policy checks.
//!
//! These are mempool/relay policy checks, not consensus rules. A transaction
//! that fails these checks may still be valid; it simply will not be accepted
//! to the mempool or relayed by default.

use bitcoin::blockdata::script::Instruction;
use bitcoin::{Script, Transaction, TxOut};
use thiserror::Error;

/// Maximum weight of a standard transaction (400 000 weight units).
const MAX_STANDARD_TX_WEIGHT: u64 = 400_000;

/// Maximum length of a standard `scriptSig` in bytes.
const MAX_STANDARD_SCRIPTSIG_SIZE: usize = 1_650;

/// Maximum number of bytes in an `OP_RETURN` payload for a standard output.
const MAX_OP_RETURN_RELAY: usize = 83;

/// Minimum transaction version considered standard.
const TX_VERSION_MIN: i32 = 1;

/// Maximum transaction version considered standard.
///
/// Current Bitcoin Core accepts version 3 at the `IsStandardTx` gate and
/// enforces TRUC's extra restrictions at the transaction and package policy
/// layers. Rejecting v3 here classifies otherwise standard transactions as
/// non-standard before any of those checks can run. Those restrictions belong
/// to that other layer and are deliberately not implemented here.
const TX_VERSION_MAX: i32 = 3;

/// Standardness policy rejection reason for a single transaction.
///
/// Each variant corresponds to a distinct `IsStandardTx` / `IsStandard`
/// failure in Bitcoin Core's mempool policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum StandardnessError {
    /// Transaction version is outside the standard range (1 or 2).
    #[error("non-standard transaction version")]
    Version,
    /// Transaction weight exceeds `MAX_STANDARD_TX_WEIGHT` (400 000).
    #[error("transaction weight exceeds maximum standard weight")]
    Weight,
    /// A `scriptSig` contains non-push opcodes.
    #[error("scriptSig is not push-only")]
    ScriptSigNotPushOnly,
    /// A `scriptSig` exceeds 1650 bytes.
    #[error("scriptSig exceeds maximum standard size")]
    ScriptSigTooLarge,
    /// An output script is not a recognized standard type.
    #[error("non-standard output script")]
    NonStandardOutput,
    /// Transaction contains more than one `OP_RETURN` output.
    #[error("transaction has multiple OP_RETURN outputs")]
    MultipleOpReturn,
    /// Non-witness serialization is below the relay minimum.
    #[error("transaction non-witness size is below the relay minimum")]
    TransactionTooSmall,
    /// An `OP_RETURN` output payload exceeds 83 bytes.
    #[error("OP_RETURN payload exceeds maximum relay size")]
    OpReturnPayloadTooLarge,
    /// A non-`OP_RETURN` output value is below the dust threshold.
    #[error("dust output")]
    DustOutput,
}

/// Checks whether a transaction satisfies Bitcoin Core's standardness policy.
///
/// This mirrors `IsStandardTx` in Bitcoin Core's `policy/policy.cpp`:
/// version, weight, `scriptSig` push-only/size, output script type,
/// `OP_RETURN` count/payload, and dust.
///
/// Returns `Ok(())` if the transaction is standard, or the first
/// `StandardnessError` encountered.
pub fn is_standard_tx(tx: &Transaction) -> Result<(), StandardnessError> {
    check_version(tx)?;
    check_weight(tx)?;
    check_script_sigs(tx)?;
    check_outputs(tx)?;
    // Last, matching Core: `IsStandardTx` runs first and `PreChecks` applies
    // `tx-size-small` after it, so a transaction that is both undersized and
    // carries a non-standard output reports the output.
    check_min_size(tx)?;
    Ok(())
}

/// Minimum non-witness serialization Core relays, `tx-size-small`.
///
/// The bound is on the stripped size. A one-input `SegWit` spend with an empty
/// scriptSig and a minimal `OP_RETURN` output serializes to 61 bytes without
/// its witness while carrying its authorization inside one, so a weight check
/// alone lets it through.
const MIN_NON_WITNESS_TX_SIZE: usize = 65;

fn check_min_size(tx: &Transaction) -> Result<(), StandardnessError> {
    if tx.base_size() < MIN_NON_WITNESS_TX_SIZE {
        return Err(StandardnessError::TransactionTooSmall);
    }
    Ok(())
}

fn check_version(tx: &Transaction) -> Result<(), StandardnessError> {
    let v = tx.version.0;
    if (TX_VERSION_MIN..=TX_VERSION_MAX).contains(&v) {
        Ok(())
    } else {
        Err(StandardnessError::Version)
    }
}

fn check_weight(tx: &Transaction) -> Result<(), StandardnessError> {
    if tx.weight().to_wu() > MAX_STANDARD_TX_WEIGHT {
        Err(StandardnessError::Weight)
    } else {
        Ok(())
    }
}

fn check_script_sigs(tx: &Transaction) -> Result<(), StandardnessError> {
    for input in &tx.input {
        let script_sig = &input.script_sig;
        if !script_sig.is_push_only() {
            return Err(StandardnessError::ScriptSigNotPushOnly);
        }
        if script_sig.len() > MAX_STANDARD_SCRIPTSIG_SIZE {
            return Err(StandardnessError::ScriptSigTooLarge);
        }
    }
    Ok(())
}

fn check_outputs(tx: &Transaction) -> Result<(), StandardnessError> {
    let mut op_return_count: u32 = 0;
    for output in &tx.output {
        let script = &output.script_pubkey;
        if script.is_op_return() {
            op_return_count += 1;
            if op_return_count > 1 {
                return Err(StandardnessError::MultipleOpReturn);
            }
            if !is_standard_nulldata(script) {
                return Err(StandardnessError::NonStandardOutput);
            }
            // The limit is on the SERIALIZED script, not the payload it
            // carries. An 81-byte push encoded with OP_PUSHDATA1 makes an
            // 84-byte script, which Core rejects and a payload-only measure
            // accepted at 81.
            if script.len() > MAX_OP_RETURN_RELAY {
                return Err(StandardnessError::OpReturnPayloadTooLarge);
            }
        } else {
            if !is_standard_output_script(script) {
                return Err(StandardnessError::NonStandardOutput);
            }
            if is_dust(output) {
                return Err(StandardnessError::DustOutput);
            }
        }
    }
    Ok(())
}

/// Returns `true` if `script` is one of the standard output script types.
///
/// Standard types: P2PKH, P2SH, P2PK, P2WPKH, P2WSH, P2TR, bare multisig
/// (up to 3 keys), and `OP_RETURN` (checked separately by the caller).
fn is_standard_output_script(script: &Script) -> bool {
    script.is_p2pkh()
        || script.is_p2sh()
        || script.is_p2pk()
        || script.is_p2wpkh()
        || script.is_p2wsh()
        || script.is_p2tr()
        || is_p2a(script)
        || is_standard_multisig(script)
}

/// Returns `true` for the pay-to-anchor output template.
///
/// `OP_1` followed by a two-byte push of `0x4e73`. Core treats this distinct
/// short witness program as standard under TRUC and ephemeral-anchor policy,
/// and none of the predicates above match it: `is_p2tr` wants a 32-byte
/// version-1 program. Its dust and package restrictions live at the policy
/// layer that owns them, not here.
fn is_p2a(script: &Script) -> bool {
    script.as_bytes() == [0x51, 0x02, 0x4e, 0x73]
}

/// Returns `true` if `script` is a bare multisig with at most 3 pubkeys.
///
/// Bitcoin Core's `IsStandard` allows bare multisig with up to 3 keys.
fn is_standard_multisig(script: &Script) -> bool {
    if !script.is_multisig() {
        return false;
    }
    multisig_key_count(script).is_some_and(|n| n <= 3)
}

/// Counts the pubkeys in a bare multisig script, or `None` if any push in it
/// is not a serialized pubkey.
///
/// Deliberately narrow. `Script::is_multisig` was measured against this exact
/// surface and it already rejects a declared count that disagrees with the keys
/// present, an `m` greater than `n`, and a script with no keys at all. The one
/// thing it does not check is the length of each push, so
/// `OP_1 <4 bytes> OP_1 OP_CHECKMULTISIG` passes it. That is the gap, and this
/// closes exactly that; duplicating the rest would be checks that can never
/// fire.
fn multisig_key_count(script: &Script) -> Option<u8> {
    let mut count: u8 = 0;
    for inst in script.instructions() {
        match inst {
            // 33 bytes compressed, 65 uncompressed. Anything else is not a key.
            Ok(Instruction::PushBytes(bytes)) => {
                if bytes.len() != 33 && bytes.len() != 65 {
                    return None;
                }
                count = count.checked_add(1)?;
            }
            Ok(Instruction::Op(_)) => {}
            Err(_) => return None,
        }
    }
    Some(count)
}

/// Returns `true` if a non-`OP_RETURN` output is dust.
fn is_dust(output: &TxOut) -> bool {
    output.value.to_sat() < output.script_pubkey.minimal_non_dust().to_sat()
}

/// Extracts the payload length from an `OP_RETURN` script.
///
/// An `OP_RETURN` script is `OP_RETURN` followed by zero or more push
/// operations. The payload length is the total number of bytes pushed.
/// Returns `None` if the script is not `OP_RETURN`.
/// Returns `true` if everything after the leading `OP_RETURN` is a data push.
///
/// Standard nulldata is `OP_RETURN` followed by pushes and nothing else. A
/// script that merely starts with `OP_RETURN` and then carries an opcode, or
/// that fails to parse partway, is not standard — and the old code accepted
/// both, because it ignored opcodes and treated a parse error as the end of
/// the payload.
fn is_standard_nulldata(script: &Script) -> bool {
    let mut instructions = script.instructions();
    // The leading OP_RETURN itself, already established by `is_op_return`.
    if instructions.next().is_none() {
        return false;
    }
    instructions.all(|inst| matches!(inst, Ok(Instruction::PushBytes(_))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, PubkeyHash, ScriptBuf, Sequence, TxIn, TxOut, Witness};

    fn empty_tx(version: Version) -> Transaction {
        Transaction {
            version,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::default(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([7_u8; 20])),
            }],
        }
    }

    #[test]
    fn accepts_standard_version_one() {
        let tx = empty_tx(Version::ONE);
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    #[test]
    fn accepts_standard_version_two() {
        let tx = empty_tx(Version::TWO);
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    #[test]
    fn rejects_version_zero() {
        let tx = empty_tx(Version(0));
        assert_eq!(is_standard_tx(&tx), Err(StandardnessError::Version));
    }

    /// Current Core relays v3 (TRUC); its extra restrictions are enforced at
    /// the package-policy layer, not by this gate.
    #[test]
    fn accepts_version_three() {
        let tx = empty_tx(Version(3));
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    #[test]
    fn rejects_version_four() {
        let tx = empty_tx(Version(4));
        assert_eq!(is_standard_tx(&tx), Err(StandardnessError::Version));
    }

    /// An 81-byte push needs `OP_PUSHDATA1`, making an 84-byte script. The limit
    /// is on the script, so this must be rejected even though the payload is
    /// under it.
    #[test]
    fn rejects_op_return_whose_script_exceeds_the_limit() {
        let mut tx = empty_tx(Version::ONE);
        let payload = [0x2b_u8; 81];
        let Ok(pushable) = <&bitcoin::script::PushBytes>::try_from(payload.as_slice()) else {
            panic!("81 bytes must be pushable");
        };
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = ScriptBuf::new_op_return(pushable);
        assert!(
            tx.output[0].script_pubkey.len() > MAX_OP_RETURN_RELAY,
            "the script must exceed the limit or this test proves nothing"
        );
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::OpReturnPayloadTooLarge)
        );
    }

    /// `OP_RETURN` followed by a non-push opcode is not standard nulldata.
    #[test]
    fn rejects_op_return_followed_by_an_opcode() {
        let mut tx = empty_tx(Version::ONE);
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// A push that is not a pubkey length still passes `Script::is_multisig`.
    ///
    /// That predicate was measured against this surface: it already rejects a
    /// declared count that disagrees with the keys present, an `m` greater than
    /// `n`, and a keyless script. Push length is the one thing it does not
    /// check, so it is the only thing worth checking here.
    #[test]
    fn rejects_bare_multisig_whose_key_is_not_a_pubkey() {
        let script = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice([0_u8; 4])
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert!(
            script.is_multisig(),
            "the shape check must accept this, or the length check is never reached"
        );

        let mut tx = empty_tx(Version::ONE);
        tx.output[0].script_pubkey = script;
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::NonStandardOutput)
        );
    }

    /// The same shape, honestly declared, stays standard.
    #[test]
    fn accepts_a_well_formed_bare_multisig() {
        let key = [0x02_u8; 33];
        let Ok(pushable) = <&bitcoin::script::PushBytes>::try_from(key.as_slice()) else {
            panic!("33 bytes must be pushable");
        };
        let mut tx = empty_tx(Version::ONE);
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pushable)
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    /// The pay-to-anchor template, `OP_1` plus a two-byte push of 0x4e73.
    ///
    /// Carries a second, ordinary output: a lone 4-byte anchor script makes the
    /// transaction smaller than the relay minimum, and this test is about the
    /// script being recognised, not about that.
    #[test]
    fn accepts_a_pay_to_anchor_output() {
        let mut tx = empty_tx(Version::ONE);
        tx.output.push(TxOut {
            value: Amount::from_sat(240),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x02, 0x4e, 0x73]),
        });
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    /// A `SegWit` spend can be consensus-valid and still below the relay
    /// minimum once its witness is stripped, which a weight check alone
    /// cannot see.
    #[test]
    fn rejects_a_transaction_below_the_non_witness_minimum() {
        let mut tx = empty_tx(Version::ONE);
        tx.output[0].value = Amount::ZERO;
        tx.output[0].script_pubkey = ScriptBuf::new_op_return([]);
        assert!(
            tx.base_size() < MIN_NON_WITNESS_TX_SIZE,
            "the fixture must be undersized or this test proves nothing"
        );
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::TransactionTooSmall)
        );
    }

    #[test]
    fn rejects_non_pushonly_scriptsig() {
        let mut tx = empty_tx(Version::ONE);
        // OP_DUP is not a push opcode.
        tx.input[0].script_sig = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DUP)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::ScriptSigNotPushOnly)
        );
    }

    #[test]
    fn rejects_oversized_scriptsig() {
        let mut tx = empty_tx(Version::ONE);
        // Build a push-only scriptSig that exceeds 1650 bytes.
        let big_data = PushBytesBuf::try_from(vec![0_u8; MAX_STANDARD_SCRIPTSIG_SIZE])
            .expect("push payload fits");
        tx.input[0].script_sig = Builder::new().push_slice(big_data).into_script();
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::ScriptSigTooLarge)
        );
    }

    #[test]
    fn rejects_two_op_returns() {
        let mut tx = empty_tx(Version::ONE);
        let op_return = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"hello")
            .into_script();
        tx.output = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return.clone(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: op_return,
            },
        ];
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::MultipleOpReturn)
        );
    }

    #[test]
    fn rejects_oversized_op_return_payload() {
        let mut tx = empty_tx(Version::ONE);
        let payload =
            PushBytesBuf::try_from(vec![0_u8; MAX_OP_RETURN_RELAY + 1]).expect("push payload fits");
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(payload)
            .into_script();
        tx.output = vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        }];
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::OpReturnPayloadTooLarge)
        );
    }

    #[test]
    fn accepts_single_op_return_within_limit() {
        let mut tx = empty_tx(Version::ONE);
        let script = Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice(b"ok")
            .into_script();
        tx.output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: script,
        });
        assert_eq!(is_standard_tx(&tx), Ok(()));
    }

    #[test]
    fn rejects_dust_output() {
        let mut tx = empty_tx(Version::ONE);
        // 1 sat to a P2PKH output is dust.
        tx.output[0].value = Amount::from_sat(1);
        assert_eq!(is_standard_tx(&tx), Err(StandardnessError::DustOutput));
    }

    #[test]
    fn rejects_non_standard_output_script() {
        let mut tx = empty_tx(Version::ONE);
        // A random non-standard script.
        tx.output[0].script_pubkey = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_DEPTH)
            .into_script();
        assert_eq!(
            is_standard_tx(&tx),
            Err(StandardnessError::NonStandardOutput)
        );
    }
}
