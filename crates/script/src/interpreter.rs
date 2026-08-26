//! Script evaluation context and portable execution seam.
//!
//! The `SigVersion`/`EvalContext` shape is adapted from
//! `reardencode/rbitcoin` commit `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937`
//! under MIT OR Apache-2.0. This module remains a local implementation and
//! does not import that project or its storage/query dependencies.
use std::borrow::Cow;

use crate::classify::{self, ScriptClass};
use crate::nested;
use bitcoin::Amount;
use bitcoin::hashes::Hash as _;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Script, ScriptBuf, Witness};
use bitcoin_rs_primitives::TxOut;
use thiserror::Error;

/// Verification flags passed to the delegated consensus script engine.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct VerifyFlags(u32);

impl VerifyFlags {
    /// No verification flags.
    pub const NONE: Self = Self(0);
    /// Evaluate P2SH subscripts (BIP16).
    pub const P2SH: Self = Self(1 << 0);
    /// Require strict signature and public-key encodings.
    pub const STRICTENC: Self = Self(1 << 1);
    /// Require strict DER signatures (BIP66).
    pub const DERSIG: Self = Self(1 << 2);
    /// Require low-S ECDSA signatures.
    pub const LOW_S: Self = Self(1 << 3);
    /// Require empty CHECKMULTISIG dummy element (BIP147).
    pub const NULLDUMMY: Self = Self(1 << 4);
    /// Require scriptSig push-only form.
    pub const SIGPUSHONLY: Self = Self(1 << 5);
    /// Require minimal push and numeric encodings.
    pub const MINIMALDATA: Self = Self(1 << 6);
    /// Discourage NOPs reserved for future soft forks.
    pub const DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 7);
    /// Require a single true stack item after evaluation.
    pub const CLEANSTACK: Self = Self(1 << 8);
    /// Enable `OP_CHECKLOCKTIMEVERIFY` (BIP65).
    pub const CHECKLOCKTIMEVERIFY: Self = Self(1 << 9);
    /// Enable `OP_CHECKSEQUENCEVERIFY` (BIP112).
    pub const CHECKSEQUENCEVERIFY: Self = Self(1 << 10);
    /// Enable segregated witness validation (BIP141/BIP143).
    pub const WITNESS: Self = Self(1 << 11);
    /// Discourage unknown witness program versions.
    pub const DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 12);
    /// Require minimal IF/NOTIF arguments in segwit scripts.
    pub const MINIMALIF: Self = Self(1 << 13);
    /// Require failed signature checks to consume empty signatures.
    pub const NULLFAIL: Self = Self(1 << 14);
    /// Require compressed public keys in segwit scripts.
    pub const WITNESS_PUBKEYTYPE: Self = Self(1 << 15);
    /// Make `CODESEPARATOR` and `FindAndDelete` fail non-segwit scripts.
    pub const CONST_SCRIPTCODE: Self = Self(1 << 16);
    /// Enable taproot and tapscript validation (BIP341/BIP342).
    pub const TAPROOT: Self = Self(1 << 17);
    /// Discourage unknown taproot leaf versions.
    pub const DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: Self = Self(1 << 18);
    /// Discourage unknown `OP_SUCCESS` opcodes.
    pub const DISCOURAGE_OP_SUCCESS: Self = Self(1 << 19);
    /// Discourage unknown public-key versions in tapscript.
    pub const DISCOURAGE_UPGRADABLE_PUBKEYTYPE: Self = Self(1 << 20);
    /// Mandatory consensus flags used for block validation after taproot activation.
    pub const MANDATORY: Self = Self(
        Self::P2SH.0
            | Self::DERSIG.0
            | Self::NULLDUMMY.0
            | Self::CHECKLOCKTIMEVERIFY.0
            | Self::CHECKSEQUENCEVERIFY.0
            | Self::WITNESS.0
            | Self::TAPROOT.0,
    );
    /// Standard relay flags; useful for vector tests that request policy checks.
    pub const STANDARD: Self = Self(
        Self::MANDATORY.0
            | Self::STRICTENC.0
            | Self::LOW_S.0
            | Self::MINIMALDATA.0
            | Self::DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::CLEANSTACK.0
            | Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0
            | Self::MINIMALIF.0
            | Self::NULLFAIL.0
            | Self::WITNESS_PUBKEYTYPE.0
            | Self::CONST_SCRIPTCODE.0
            | Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION.0
            | Self::DISCOURAGE_OP_SUCCESS.0
            | Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE.0,
    );

    /// Builds flags from raw Core-compatible bits.
    #[must_use]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns raw Core-compatible flag bits.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Returns the full consensus-authority bit set, including taproot for bitcoinkernel.
    #[must_use]
    pub const fn kernel_bits(self) -> u32 {
        self.0 & Self::MANDATORY.0
    }

    /// Returns true when all `other` bits are present.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Adds another flag set.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Parses a comma-separated Core test-vector flag string.
    pub fn from_core_names(names: &str) -> Result<Self, ScriptError> {
        let mut flags = Self::NONE;
        for name in names
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
        {
            flags = flags.union(match name {
                "NONE" => Self::NONE,
                "P2SH" => Self::P2SH,
                "STRICTENC" => Self::STRICTENC,
                "DERSIG" => Self::DERSIG,
                "LOW_S" => Self::LOW_S,
                "NULLDUMMY" => Self::NULLDUMMY,
                "SIGPUSHONLY" => Self::SIGPUSHONLY,
                "MINIMALDATA" => Self::MINIMALDATA,
                "DISCOURAGE_UPGRADABLE_NOPS" => Self::DISCOURAGE_UPGRADABLE_NOPS,
                "CLEANSTACK" => Self::CLEANSTACK,
                "CHECKLOCKTIMEVERIFY" => Self::CHECKLOCKTIMEVERIFY,
                "CHECKSEQUENCEVERIFY" => Self::CHECKSEQUENCEVERIFY,
                "WITNESS" => Self::WITNESS,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    Self::DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
                }
                "MINIMALIF" => Self::MINIMALIF,
                "NULLFAIL" => Self::NULLFAIL,
                "WITNESS_PUBKEYTYPE" => Self::WITNESS_PUBKEYTYPE,
                "CONST_SCRIPTCODE" => Self::CONST_SCRIPTCODE,
                "TAPROOT" => Self::TAPROOT,
                "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION" => {
                    Self::DISCOURAGE_UPGRADABLE_TAPROOT_VERSION
                }
                "DISCOURAGE_OP_SUCCESS" => Self::DISCOURAGE_OP_SUCCESS,
                "DISCOURAGE_UPGRADABLE_PUBKEYTYPE" => Self::DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                unknown => {
                    return Err(ScriptError::UnknownFlag {
                        name: unknown.to_owned(),
                    });
                }
            });
        }
        Ok(flags)
    }
}

impl From<VerifyFlags> for u32 {
    fn from(flags: VerifyFlags) -> Self {
        flags.bits()
    }
}

/// Script execution errors surfaced by the script crate.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ScriptError {
    /// The requested input index was not present in the transaction.
    #[error("input index {index} out of range for {inputs} inputs")]
    InputIndexOutOfRange {
        /// Requested input index.
        index: usize,
        /// Transaction input count.
        inputs: usize,
    },
    /// A Core vector flag name was not known by this crate.
    #[error("unknown script verify flag {name}")]
    UnknownFlag {
        /// Unknown flag name.
        name: String,
    },
    /// The transaction could not be serialized for the delegated verifier.
    #[error("transaction serialization failed: {0}")]
    Serialization(String),
    /// The delegated consensus verifier rejected the script.
    #[error("script verification failed: {0}")]
    Verification(String),
    /// Taproot key-path verification requires all prevouts for multi-input transactions.
    #[error("taproot key-path verification requires all prevouts for multi-input transactions")]
    TaprootPrevoutsUnavailable,
    /// This portable path only validates one-element Taproot key-path witnesses.
    #[error(
        "taproot witness stack with {elements} elements requires unsupported annex or script-path validation"
    )]
    TaprootUnsupportedWitness {
        /// Number of witness elements supplied for the P2TR spend.
        elements: usize,
    },
}

/// Script execution version selected by the output and witness shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigVersion {
    Base,
    WitnessV0,
    TapScript,
}

/// Immutable transaction context plus the one mutable per-transaction sighash
/// cache shared by all serial input evaluations.
///
/// The context fields that are not consumed by the current OP_TRUE/Taproot
/// slice are retained for the Stage 3 consensus evaluator.
#[allow(dead_code)]
struct EvalContext<'tx, 'script, 'prevouts, 'cache> {
    sig_version: SigVersion,
    transaction: &'tx bitcoin::Transaction,
    input_index: usize,
    amount: Amount,
    ordered_prevouts: &'prevouts [&'prevouts TxOut],
    script_code: &'script Script,
    flags: VerifyFlags,
    code_separator_position: usize,
    sighash_cache: &'cache mut SighashCache<&'tx bitcoin::Transaction>,
    tapscript_validation_weight_budget: usize,
    script_code_push_only: bool,
}

impl<'tx, 'script, 'prevouts, 'cache> EvalContext<'tx, 'script, 'prevouts, 'cache> {
    fn new(
        sig_version: SigVersion,
        transaction: &'tx bitcoin::Transaction,
        input_index: usize,
        amount: Amount,
        ordered_prevouts: &'prevouts [&'prevouts TxOut],
        script_code: &'script Script,
        flags: VerifyFlags,
        sighash_cache: &'cache mut SighashCache<&'tx bitcoin::Transaction>,
    ) -> Self {
        Self {
            sig_version,
            transaction,
            input_index,
            amount,
            ordered_prevouts,
            script_code,
            flags,
            code_separator_position: usize::MAX,
            sighash_cache,
            tapscript_validation_weight_budget: 50_000,
            script_code_push_only: nested::is_push_only(script_code),
        }
    }

    fn taproot(&self) -> bool {
        matches!(self.sig_version, SigVersion::TapScript)
    }
}

/// Public script verifier for the portable posture.
///
/// Handles taproot key-path spends via the local BIP341 path; non-taproot spends
/// (legacy, segwit-v0, taproot script-path) require the kernel production path.
/// Without the kernel the stub accepts only empty `OP_TRUE` spends and rejects
/// everything else.
#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    /// Number of taproot inputs at which block validation uses the batch Schnorr path.
    pub const BATCH_SCHNORR_THRESHOLD: usize = 16;

    /// Executes a script spend through the enabled script backend.
    ///
    /// When `script_sig` and `witness` already match the bytes stored on
    /// `tx.input[input_idx]` — true for every block/mempool validation caller,
    /// which reads them straight off the transaction — `tx` is used as-is with
    /// no clone. Only callers that pass substitute bytes (e.g. vector tests
    /// grafting a foreign witness) pay for a clone to splice them in.
    ///
    /// Taproot key-path verification needs every spent output. Callers that only
    /// have the current input's prevout should prefer
    /// [`Self::execute_with_prevouts`] when the full ordered set is available;
    /// this wrapper forwards a one-element slice and therefore still rejects
    /// multi-input taproot key-path spends with
    /// [`ScriptError::TaprootPrevoutsUnavailable`].
    pub fn execute(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevout: &TxOut,
        tx: &bitcoin::Transaction,
        input_idx: usize,
    ) -> Result<(), ScriptError> {
        self.execute_with_prevouts(
            script_pubkey,
            script_sig,
            witness,
            flags,
            &[prevout],
            tx,
            input_idx,
        )
    }

    /// Executes a script spend with the complete ordered prevout set.
    ///
    /// `prevouts` must be aligned with `tx.input` (same length, input order).
    /// BIP341 key-path sighashes commit to every spent output, so multi-input
    /// taproot spends require the full slice via [`Prevouts::All`].
    pub fn execute_with_prevouts(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[&TxOut],
        tx: &bitcoin::Transaction,
        input_idx: usize,
    ) -> Result<(), ScriptError> {
        let inputs = tx.input.len();
        if tx.input.get(input_idx).is_none() {
            return Err(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            });
        }
        let prevout = select_prevout(prevouts, inputs, input_idx)?;
        let spending = graft_transaction_if_needed(tx, input_idx, script_sig, witness)?;
        let script = Script::from_bytes(script_pubkey);
        let sig_version = match classify::classify(script) {
            ScriptClass::WitnessV0P2wpkh | ScriptClass::WitnessV0P2wsh => SigVersion::WitnessV0,
            ScriptClass::Taproot => SigVersion::TapScript,
            _ => SigVersion::Base,
        };
        let mut cache = SighashCache::new(&*spending);
        let mut context = EvalContext::new(
            sig_version,
            &spending,
            input_idx,
            prevout.value,
            prevouts,
            script,
            flags,
            &mut cache,
        );
        if context.taproot() && flags.contains(VerifyFlags::TAPROOT) {
            return verify_taproot_keypath(&mut context, witness);
        }
        verify_non_taproot_portable(&context)
    }

    /// Executes a spend while reusing the caller's per-transaction sighash
    /// cache. Production block verification calls this only when `script_sig`
    /// and `witness` are already the bytes stored in `tx.input[input_idx]`.
    pub fn execute_with_prevouts_cached<'tx>(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[&TxOut],
        tx: &'tx bitcoin::Transaction,
        input_idx: usize,
        cache: &mut SighashCache<&'tx bitcoin::Transaction>,
    ) -> Result<(), ScriptError> {
        if cache.transaction() != tx {
            return Err(ScriptError::Verification(
                "cached execution received a different transaction".to_owned(),
            ));
        }
        let inputs = tx.input.len();
        let input = tx
            .input
            .get(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            })?;
        if input.script_sig.as_bytes() != script_sig
            || input.witness.len() != witness.len()
            || !input
                .witness
                .iter()
                .zip(witness)
                .all(|(stored, provided)| stored == provided.as_slice())
        {
            return Err(ScriptError::Verification(
                "cached execution requires transaction-owned input bytes".to_owned(),
            ));
        }
        let prevout = select_prevout(prevouts, inputs, input_idx)?;
        let script = Script::from_bytes(script_pubkey);
        let sig_version = match classify::classify(script) {
            ScriptClass::WitnessV0P2wpkh | ScriptClass::WitnessV0P2wsh => SigVersion::WitnessV0,
            ScriptClass::Taproot => SigVersion::TapScript,
            _ => SigVersion::Base,
        };
        let mut context = EvalContext::new(
            sig_version,
            tx,
            input_idx,
            prevout.value,
            prevouts,
            script,
            flags,
            cache,
        );
        if context.taproot() && flags.contains(VerifyFlags::TAPROOT) {
            return verify_taproot_keypath(&mut context, witness);
        }
        verify_non_taproot_portable(&context)
    }
}

fn select_prevout<'a>(
    prevouts: &'a [&TxOut],
    inputs: usize,
    input_idx: usize,
) -> Result<&'a TxOut, ScriptError> {
    if prevouts.len() == inputs {
        prevouts
            .get(input_idx)
            .copied()
            .ok_or(ScriptError::TaprootPrevoutsUnavailable)
    } else if prevouts.len() == 1 {
        prevouts
            .first()
            .copied()
            .ok_or(ScriptError::TaprootPrevoutsUnavailable)
    } else {
        Err(ScriptError::TaprootPrevoutsUnavailable)
    }
}

fn graft_transaction_if_needed<'a>(
    tx: &'a bitcoin::Transaction,
    input_idx: usize,
    script_sig: &[u8],
    witness: &[Vec<u8>],
) -> Result<Cow<'a, bitcoin::Transaction>, ScriptError> {
    let input = tx
        .input
        .get(input_idx)
        .ok_or(ScriptError::InputIndexOutOfRange {
            index: input_idx,
            inputs: tx.input.len(),
        })?;
    let matches_tx = input.script_sig.as_bytes() == script_sig
        && input.witness.len() == witness.len()
        && input
            .witness
            .iter()
            .zip(witness)
            .all(|(stored, provided)| stored == provided.as_slice());
    if matches_tx {
        return Ok(Cow::Borrowed(tx));
    }
    let mut grafted = tx.clone();
    let grafted_input =
        grafted
            .input
            .get_mut(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs: tx.input.len(),
            })?;
    grafted_input.script_sig = ScriptBuf::from_bytes(script_sig.to_vec());
    grafted_input.witness = Witness::from_slice(witness);
    Ok(Cow::Owned(grafted))
}

/// Portable non-taproot stub: accepts only empty `OP_TRUE` spends. All other
/// non-taproot (and taproot script-path) classes require the kernel production path.
fn verify_non_taproot_portable(context: &EvalContext<'_, '_, '_, '_>) -> Result<(), ScriptError> {
    let input = context.transaction.input.get(context.input_index).ok_or(
        ScriptError::InputIndexOutOfRange {
            index: context.input_index,
            inputs: context.transaction.input.len(),
        },
    )?;
    if context.script_code.as_bytes() == [0x51]
        && input.script_sig.is_empty()
        && input.witness.is_empty()
    {
        return Ok(());
    }

    Err(ScriptError::Verification(
        "portable script backend cannot verify this non-taproot spend".to_owned(),
    ))
}

fn verify_taproot_keypath(
    context: &mut EvalContext<'_, '_, '_, '_>,
    witness: &[Vec<u8>],
) -> Result<(), ScriptError> {
    if context.ordered_prevouts.len() != context.transaction.input.len() {
        return Err(ScriptError::TaprootPrevoutsUnavailable);
    }
    let signature_bytes = taproot_keypath_signature(witness)?;
    let (signature_bytes, sighash_type) = match signature_bytes.len() {
        64 => (signature_bytes, TapSighashType::Default),
        65 => {
            let sighash_type = TapSighashType::from_consensus_u8(signature_bytes[64])
                .map_err(|error| ScriptError::Verification(error.to_string()))?;
            (&signature_bytes[..64], sighash_type)
        }
        len => {
            return Err(ScriptError::Verification(format!(
                "taproot key-path signature length {len} is not 64 or 65 bytes"
            )));
        }
    };
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(signature_bytes)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let public_key =
        bitcoin::secp256k1::XOnlyPublicKey::from_slice(&context.script_code.as_bytes()[2..34])
            .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let input_index = context.input_index;
    let prevouts = context.ordered_prevouts;
    let sighash = context
        .sighash_cache
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), sighash_type)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let message = bitcoin::secp256k1::Message::from_digest(*sighash.as_byte_array());
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &message, &public_key)
        .map(|()| ())
        .map_err(|error| ScriptError::Verification(error.to_string()))
}

fn taproot_keypath_signature(witness: &[Vec<u8>]) -> Result<&[u8], ScriptError> {
    match witness {
        [signature] => Ok(signature),
        [] => Err(ScriptError::Verification(
            "missing taproot key-path signature".to_owned(),
        )),
        _ => Err(ScriptError::TaprootUnsupportedWitness {
            elements: witness.len(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;
    use bitcoin::sighash::SighashCache;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };

    use super::{Interpreter, ScriptError, VerifyFlags};

    #[test]
    fn no_backend_accepts_only_empty_op_true_spend() {
        let interpreter = Interpreter;
        let tx = unsigned_spend();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };

        assert_eq!(
            interpreter.execute(
                prevout.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &prevout,
                &tx,
                0,
            ),
            Ok(())
        );

        assert!(matches!(
            interpreter.execute(&[0x00], &[], &[], VerifyFlags::MANDATORY, &prevout, &tx, 0,),
            Err(ScriptError::Verification(_))
        ));
    }

    #[test]
    fn execute_with_prevouts_reports_out_of_range_input() {
        let tx = unsigned_spend();
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let result = Interpreter.execute_with_prevouts(
            prevout.script_pubkey.as_bytes(),
            &[],
            &[],
            VerifyFlags::MANDATORY,
            &[&prevout],
            &tx,
            tx.input.len(),
        );
        assert!(matches!(
            result,
            Err(ScriptError::InputIndexOutOfRange {
                index: 1,
                inputs: 1
            })
        ));
    }

    #[test]
    fn cached_execution_rejects_a_different_transaction() {
        let tx = unsigned_spend();
        let mut other = tx.clone();
        other.output[0].value = Amount::from_sat(48_000);
        let prevout = TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        };
        let mut cache = SighashCache::new(&other);
        let result = Interpreter.execute_with_prevouts_cached(
            prevout.script_pubkey.as_bytes(),
            &[],
            &[],
            VerifyFlags::MANDATORY,
            &[&prevout],
            &tx,
            0,
            &mut cache,
        );
        assert_eq!(
            result,
            Err(ScriptError::Verification(
                "cached execution received a different transaction".to_owned()
            ))
        );
    }

    fn unsigned_spend() -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([1; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(49_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }
}
