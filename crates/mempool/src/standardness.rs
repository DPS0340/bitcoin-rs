//! Bitcoin Core `IsStandardTx` / `IsStandard` policy checks.
//!
//! These are mempool/relay policy checks, not consensus rules. A transaction
//! that fails these checks may still be valid; it simply will not be accepted
//! to the mempool or relayed by default.

use bitcoin::blockdata::script::Instruction;
use bitcoin::opcodes::all::{OP_PUSHNUM_1, OP_PUSHNUM_16};
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
/// Bitcoin Core accepts versions 1 and 2 as standard. Version 3 is also
/// relayed under post-TRUC policy, but the base `IsStandardTx` check
/// historically rejects versions outside `1..=2`. We follow the base
/// policy: versions 1 and 2 are standard.
const TX_VERSION_MAX: i32 = 2;

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
            if op_return_payload_len(script) > MAX_OP_RETURN_RELAY {
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
        || is_standard_multisig(script)
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

/// Counts the number of pubkeys in a bare multisig script, or `None` if
/// the script is not a valid multisig.
fn multisig_key_count(script: &Script) -> Option<u8> {
    let mut instructions = script.instructions();
    // Required-sigs pushnum (OP_1..OP_16).
    instructions.next()?.ok()?;
    let mut count: u8 = 0;
    for inst in instructions.by_ref() {
        match inst {
            Ok(Instruction::PushBytes(_)) => {
                count = count.checked_add(1)?;
            }
            Ok(Instruction::Op(op)) => {
                // The pubkey-count pushnum — stop here.
                if is_pushnum(op) {
                    break;
                }
                return None;
            }
            Err(_) => return None,
        }
    }
    Some(count)
}

/// Returns `true` if `op` is one of `OP_1` through `OP_16`.
///
/// `Opcode::decode_pushnum` is `pub(crate)` in the `bitcoin` crate, so the
/// range is checked directly against the opcode byte.
fn is_pushnum(op: bitcoin::opcodes::Opcode) -> bool {
    (OP_PUSHNUM_1.to_u8()..=OP_PUSHNUM_16.to_u8()).contains(&op.to_u8())
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
fn op_return_payload_len(script: &Script) -> usize {
    let mut total: usize = 0;
    for inst in script.instructions() {
        match inst {
            Ok(Instruction::PushBytes(bytes)) => {
                total += bytes.len();
            }
            // Opcodes, including the leading `OP_RETURN`, contribute no
            // payload bytes.
            Ok(Instruction::Op(_)) => {}
            Err(_) => return total,
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::absolute::LockTime;
    use bitcoin::hashes::Hash as _;
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

    #[test]
    fn rejects_version_three() {
        let tx = empty_tx(Version(3));
        assert_eq!(is_standard_tx(&tx), Err(StandardnessError::Version));
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
