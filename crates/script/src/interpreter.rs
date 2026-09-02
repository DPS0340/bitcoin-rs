//! Script verification entry points over the native transaction type.
//!
//! The interpreter executes taproot key-path spends natively (BIP341 Schnorr
//! verification against the native sighash engine); non-taproot spend classes
//! are handled by the verification backend wired into the consensus crate.

use std::borrow::Cow;
use std::fmt;

use bitcoin_rs_primitives::{Sighash, SighashCache, Tx, TxOut};
use secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr::Signature};
use thiserror::Error;

use crate::script::is_p2tr;

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

/// Core-named script error codes, one variant per case in `ScriptErrorString`.
///
/// The [`fmt::Display`] impl renders the exact Core case name (without the
/// `SCRIPT_ERR_` prefix) so error messages match Bitcoin Core's
/// `script_error.cpp` output.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum ScriptErrCode {
    /// `SCRIPT_ERR_EVAL_FALSE`
    EvalFalse,
    /// `SCRIPT_ERR_VERIFY`
    Verify,
    /// `SCRIPT_ERR_EQUALVERIFY`
    EqualVerify,
    /// `SCRIPT_ERR_CHECKMULTISIGVERIFY`
    CheckMultisigVerify,
    /// `SCRIPT_ERR_CHECKSIGVERIFY`
    CheckSigVerify,
    /// `SCRIPT_ERR_NUMEQUALVERIFY`
    NumEqualVerify,
    /// `SCRIPT_ERR_SCRIPT_SIZE`
    ScriptSize,
    /// `SCRIPT_ERR_PUSH_SIZE`
    PushSize,
    /// `SCRIPT_ERR_OP_COUNT`
    OpCount,
    /// `SCRIPT_ERR_STACK_SIZE`
    StackSize,
    /// `SCRIPT_ERR_SIG_COUNT`
    SigCount,
    /// `SCRIPT_ERR_PUBKEY_COUNT`
    PubkeyCount,
    /// `SCRIPT_ERR_BAD_OPCODE`
    BadOpcode,
    /// `SCRIPT_ERR_DISABLED_OPCODE`
    DisabledOpcode,
    /// `SCRIPT_ERR_INVALID_STACK_OPERATION`
    InvalidStackOperation,
    /// `SCRIPT_ERR_INVALID_ALTSTACK_OPERATION`
    InvalidAltstackOperation,
    /// `SCRIPT_ERR_OP_RETURN`
    OpReturn,
    /// `SCRIPT_ERR_UNBALANCED_CONDITIONAL`
    UnbalancedConditional,
    /// `SCRIPT_ERR_NEGATIVE_LOCKTIME`
    NegativeLocktime,
    /// `SCRIPT_ERR_UNSATISFIED_LOCKTIME`
    UnsatisfiedLocktime,
    /// `SCRIPT_ERR_SIG_HASHTYPE`
    SigHashtype,
    /// `SCRIPT_ERR_SIG_DER`
    SigDer,
    /// `SCRIPT_ERR_MINIMALDATA`
    MinimalData,
    /// `SCRIPT_ERR_SIG_PUSHONLY`
    SigPushonly,
    /// `SCRIPT_ERR_SIG_HIGH_S`
    SigHighS,
    /// `SCRIPT_ERR_SIG_NULLDUMMY`
    SigNullDummy,
    /// `SCRIPT_ERR_MINIMALIF`
    MinimalIf,
    /// `SCRIPT_ERR_SIG_NULLFAIL`
    SigNullFail,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS`
    DiscourageUpgradableNops,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM`
    DiscourageUpgradableWitnessProgram,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION`
    DiscourageUpgradableTaprootVersion,
    /// `SCRIPT_ERR_DISCOURAGE_OP_SUCCESS`
    DiscourageOpSuccess,
    /// `SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE`
    DiscourageUpgradablePubkeyType,
    /// `SCRIPT_ERR_PUBKEYTYPE`
    PubkeyType,
    /// `SCRIPT_ERR_CLEANSTACK`
    CleanStack,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WRONG_LENGTH`
    WitnessProgramWrongLength,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_WITNESS_EMPTY`
    WitnessProgramWitnessEmpty,
    /// `SCRIPT_ERR_WITNESS_PROGRAM_MISMATCH`
    WitnessProgramMismatch,
    /// `SCRIPT_ERR_WITNESS_MALLEATED`
    WitnessMalleated,
    /// `SCRIPT_ERR_WITNESS_MALLEATED_P2SH`
    WitnessMalleatedP2sh,
    /// `SCRIPT_ERR_WITNESS_UNEXPECTED`
    WitnessUnexpected,
    /// `SCRIPT_ERR_WITNESS_PUBKEYTYPE`
    WitnessPubkeyType,
    /// `SCRIPT_ERR_SCHNORR_SIG_SIZE`
    SchnorrSigSize,
    /// `SCRIPT_ERR_SCHNORR_SIG_HASHTYPE`
    SchnorrSigHashtype,
    /// `SCRIPT_ERR_SCHNORR_SIG`
    SchnorrSig,
    /// `SCRIPT_ERR_TAPROOT_WRONG_CONTROL_SIZE`
    TaprootWrongControlSize,
    /// `SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT`
    TapscriptValidationWeight,
    /// `SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG`
    TapscriptCheckMultiSig,
    /// `SCRIPT_ERR_TAPSCRIPT_MINIMALIF`
    TapscriptMinimalIf,
    /// `SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY`
    TapscriptEmptyPubkey,
    /// `SCRIPT_ERR_OP_CODESEPARATOR`
    OpCodeSeparator,
    /// `SCRIPT_ERR_SIG_FINDANDDELETE`
    SigFindAndDelete,
    /// `SCRIPT_ERR_SCRIPTNUM`
    ScriptNum,
}

impl fmt::Display for ScriptErrCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::EvalFalse => "EVAL_FALSE",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::CheckMultisigVerify => "CHECKMULTISIGVERIFY",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::OpCount => "OP_COUNT",
            Self::StackSize => "STACK_SIZE",
            Self::SigCount => "SIG_COUNT",
            Self::PubkeyCount => "PUBKEY_COUNT",
            Self::BadOpcode => "BAD_OPCODE",
            Self::DisabledOpcode => "DISABLED_OPCODE",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltstackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::OpReturn => "OP_RETURN",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::SigHashtype => "SIG_HASHTYPE",
            Self::SigDer => "SIG_DER",
            Self::MinimalData => "MINIMALDATA",
            Self::SigPushonly => "SIG_PUSHONLY",
            Self::SigHighS => "SIG_HIGH_S",
            Self::SigNullDummy => "SIG_NULLDUMMY",
            Self::MinimalIf => "MINIMALIF",
            Self::SigNullFail => "SIG_NULLFAIL",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableTaprootVersion => "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION",
            Self::DiscourageOpSuccess => "DISCOURAGE_OP_SUCCESS",
            Self::DiscourageUpgradablePubkeyType => "DISCOURAGE_UPGRADABLE_PUBKEYTYPE",
            Self::PubkeyType => "PUBKEYTYPE",
            Self::CleanStack => "CLEANSTACK",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessMalleated => "WITNESS_MALLEATED",
            Self::WitnessMalleatedP2sh => "WITNESS_MALLEATED_P2SH",
            Self::WitnessUnexpected => "WITNESS_UNEXPECTED",
            Self::WitnessPubkeyType => "WITNESS_PUBKEYTYPE",
            Self::SchnorrSigSize => "SCHNORR_SIG_SIZE",
            Self::SchnorrSigHashtype => "SCHNORR_SIG_HASHTYPE",
            Self::SchnorrSig => "SCHNORR_SIG",
            Self::TaprootWrongControlSize => "TAPROOT_WRONG_CONTROL_SIZE",
            Self::TapscriptValidationWeight => "TAPSCRIPT_VALIDATION_WEIGHT",
            Self::TapscriptCheckMultiSig => "TAPSCRIPT_CHECKMULTISIG",
            Self::TapscriptMinimalIf => "TAPSCRIPT_MINIMALIF",
            Self::TapscriptEmptyPubkey => "TAPSCRIPT_EMPTY_PUBKEY",
            Self::OpCodeSeparator => "OP_CODESEPARATOR",
            Self::SigFindAndDelete => "SIG_FINDANDDELETE",
            Self::ScriptNum => "SCRIPTNUM",
        };
        f.write_str(name)
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
    /// The script evaluated to a Core-named failure.
    #[error("script failed: {code}")]
    Invalid {
        /// Core's script error name for this failure.
        code: ScriptErrCode,
    },
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
    /// `tx.inputs[input_idx]` — true for every block/mempool validation caller,
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
        tx: &Tx,
        input_idx: usize,
    ) -> Result<bool, ScriptError> {
        self.execute_with_prevouts(
            script_pubkey,
            script_sig,
            witness,
            flags,
            std::slice::from_ref(prevout),
            tx,
            input_idx,
        )
    }

    /// Executes a script spend with the complete ordered prevout set.
    ///
    /// `prevouts` must be aligned with `tx.inputs` (same length, input order).
    /// BIP341 key-path sighashes commit to every spent output, so multi-input
    /// taproot spends require the full slice.
    pub fn execute_with_prevouts(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[TxOut],
        tx: &Tx,
        input_idx: usize,
    ) -> Result<bool, ScriptError> {
        let inputs = tx.inputs.len();
        let input = tx
            .inputs
            .get(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs,
            })?;
        // `execute` forwards a one-element slice for the current input. Full-set
        // callers pass `prevouts.len() == tx.inputs.len()` in input order.
        let prevout = if prevouts.len() == inputs {
            prevouts
                .get(input_idx)
                .ok_or(ScriptError::TaprootPrevoutsUnavailable)?
        } else if prevouts.len() == 1 {
            prevouts
                .first()
                .ok_or(ScriptError::TaprootPrevoutsUnavailable)?
        } else {
            return Err(ScriptError::TaprootPrevoutsUnavailable);
        };

        let matches_tx = input.script_sig.as_slice() == script_sig
            && input.witness.len() == witness.len()
            && input
                .witness
                .iter()
                .zip(witness.iter())
                .all(|(stored, provided)| stored == provided);
        let spending: Cow<'_, Tx> = if matches_tx {
            Cow::Borrowed(tx)
        } else {
            let mut grafted = tx.clone();
            let grafted_input =
                grafted
                    .inputs
                    .get_mut(input_idx)
                    .ok_or(ScriptError::InputIndexOutOfRange {
                        index: input_idx,
                        inputs,
                    })?;
            grafted_input.script_sig = script_sig.to_vec();
            grafted_input.witness = witness.to_vec();
            Cow::Owned(grafted)
        };

        if is_p2tr(script_pubkey) && flags.contains(VerifyFlags::TAPROOT) {
            return verify_taproot_keypath(&spending, input_idx, script_pubkey, witness, prevouts);
        }

        verify_non_taproot_portable(input_idx, prevout, &spending, script_pubkey)
    }
}

/// Portable non-taproot stub: accepts only empty `OP_TRUE` spends. All other
/// non-taproot (and taproot script-path) classes require the kernel production path.
fn verify_non_taproot_portable(
    input_idx: usize,
    _prevout: &TxOut,
    spending: &Tx,
    script_pubkey: &[u8],
) -> Result<bool, ScriptError> {
    let input = spending
        .inputs
        .get(input_idx)
        .ok_or(ScriptError::InputIndexOutOfRange {
            index: input_idx,
            inputs: spending.inputs.len(),
        })?;
    if script_pubkey == [0x51] && input.script_sig.is_empty() && input.witness.is_empty() {
        return Ok(true);
    }

    Err(ScriptError::Verification(
        "portable script backend cannot verify this non-taproot spend".to_owned(),
    ))
}

fn verify_taproot_keypath(
    spending: &Tx,
    input_idx: usize,
    script_pubkey: &[u8],
    witness: &[Vec<u8>],
    prevouts: &[TxOut],
) -> Result<bool, ScriptError> {
    if prevouts.len() != spending.inputs.len() {
        return Err(ScriptError::TaprootPrevoutsUnavailable);
    }
    let signature_bytes = taproot_keypath_signature(witness)?;
    let sighash_type = match signature_bytes.len() {
        64 => Sighash::Default,
        65 => Sighash::from_consensus_u8(signature_bytes[64])
            .map_err(|error| ScriptError::Verification(error.to_string()))?,
        len => {
            return Err(ScriptError::Verification(format!(
                "taproot key-path signature length {len} is not 64 or 65 bytes"
            )));
        }
    };
    let xonly_key = script_pubkey
        .get(2..34)
        .ok_or_else(|| ScriptError::Verification("taproot program is not 32 bytes".to_owned()))?;
    let signature = Signature::from_slice(signature_bytes)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let public_key = XOnlyPublicKey::from_slice(xonly_key)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let mut cache = SighashCache::new(spending);
    let sighash = cache
        .taproot_signature_hash(input_idx, prevouts, None, None, sighash_type)
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let message = Message::from_digest(*sighash.as_byte_array());
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &message, &public_key)
        .map(|()| true)
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
    use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut, Txid};

    use super::{Interpreter, ScriptError, VerifyFlags};

    #[test]
    fn no_backend_accepts_only_empty_op_true_spend() {
        let interpreter = Interpreter;
        let tx = unsigned_spend();
        let prevout = TxOut {
            value: 50_000,
            script_pubkey: vec![0x51],
        };

        assert_eq!(
            interpreter.execute(
                &prevout.script_pubkey,
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &prevout,
                &tx,
                0,
            ),
            Ok(true)
        );

        assert!(matches!(
            interpreter.execute(&[0x00], &[], &[], VerifyFlags::MANDATORY, &prevout, &tx, 0,),
            Err(ScriptError::Verification(_))
        ));
    }

    fn unsigned_spend() -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: Vec::new(),
                sequence: 0xffff_fffe,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 49_000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        }
    }
}
