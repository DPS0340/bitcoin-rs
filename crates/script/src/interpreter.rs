//! Native legacy/P2SH script evaluation and the portable execution seam.
//!
//! The opcode evaluator is adapted from `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937` (MIT OR Apache-2.0). It is a
//! local implementation: no reference storage, query, or script dependency is
//! linked into this crate.

use std::borrow::Cow;
use std::cell::{Cell, RefCell};
use std::fmt;

use bitcoin::hashes::Hash as _;
use bitcoin::script::{Instruction, Script};
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, Witness};
use bitcoin_rs_primitives::TxOut as PrimitiveTxOut;
use thiserror::Error;

use crate::classify::{self, ScriptClass};
use crate::nested;

/// Verification flags passed to the native consensus script evaluator.
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
    /// A transaction preparation or serialization failure.
    #[error("transaction serialization failed: {0}")]
    Serialization(String),
    /// The native consensus evaluator rejected the script.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SigVersion {
    Base,
    WitnessV0,
    TapScript,
}

const MAX_STACK_SIZE: usize = 1000;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const MAX_SCRIPT_SIZE_LEGACY: usize = 10_000;
const MAX_OPS_LEGACY: usize = 201;
const MAX_PUBKEYS_PER_MULTISIG: i64 = 20;

#[derive(Debug, PartialEq, Eq)]
enum EvalError {
    Script(String),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Script(message) => f.write_str(message),
        }
    }
}

fn is_disabled_legacy(code: u8) -> bool {
    matches!(
        code,
        0x7e | 0x7f
            | 0x80
            | 0x81
            | 0x83
            | 0x84
            | 0x85
            | 0x86
            | 0x8d
            | 0x8e
            | 0x95
            | 0x96
            | 0x97
            | 0x98
            | 0x99
    )
}

fn is_op_success(code: u8) -> bool {
    matches!(
        code,
        80 | 98
            | 126
            | 127
            | 128
            | 129
            | 131
            | 132
            | 133
            | 134
            | 137
            | 138
            | 141
            | 142
            | 149
            | 150
            | 151
            | 152
            | 153
    ) || (187..=254).contains(&code)
}

fn tapscript_has_op_success(script: &Script) -> bool {
    let bytes = script.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        if (1..=75).contains(&op) {
            i = i.saturating_add(1).saturating_add(op as usize);
            continue;
        }
        match op {
            0x4c => {
                if i + 1 >= bytes.len() {
                    break;
                }
                i = i.saturating_add(2).saturating_add(bytes[i + 1] as usize);
            }
            0x4d => {
                if i + 2 >= bytes.len() {
                    break;
                }
                i = i
                    .saturating_add(3)
                    .saturating_add(u16::from_le_bytes([bytes[i + 1], bytes[i + 2]]) as usize);
            }
            0x4e => {
                if i + 4 >= bytes.len() {
                    break;
                }
                i = i.saturating_add(5).saturating_add(u32::from_le_bytes([
                    bytes[i + 1],
                    bytes[i + 2],
                    bytes[i + 3],
                    bytes[i + 4],
                ]) as usize);
            }
            _ if is_op_success(op) => return true,
            _ => i += 1,
        }
    }
    false
}

/// Script context shared by one transaction's serial input evaluations.
struct EvalContext<'tx, 'script, 'prevouts, 'cache> {
    tx: &'tx Transaction,
    input_index: usize,
    #[allow(
        dead_code,
        reason = "BIP143 and Tapscript consume the amount in Stage 4"
    )]
    amount: Amount,
    prevouts: &'prevouts [&'prevouts PrimitiveTxOut],
    script_code: &'script Script,
    flags: VerifyFlags,
    sig_version: SigVersion,
    bip65_active: bool,
    bip112_active: bool,
    bip66_active: bool,
    minimal_data: bool,
    nullfail: bool,
    low_s: bool,
    strictenc: bool,
    null_dummy: bool,
    minimal_if: bool,
    witness_pubkeytype: bool,
    const_scriptcode: bool,
    codeseparator_pos: Cell<u32>,
    codeseparator_script_off: Cell<Option<usize>>,
    cache: RefCell<&'cache mut SighashCache<&'tx Transaction>>,
}

impl<'tx, 'script, 'prevouts, 'cache> EvalContext<'tx, 'script, 'prevouts, 'cache> {
    fn new(
        tx: &'tx Transaction,
        input_index: usize,
        amount: Amount,
        prevouts: &'prevouts [&'prevouts PrimitiveTxOut],
        script_code: &'script Script,
        sig_version: SigVersion,
        flags: VerifyFlags,
        cache: &'cache mut SighashCache<&'tx Transaction>,
    ) -> Self {
        Self {
            tx,
            input_index,
            amount,
            prevouts,
            script_code,
            flags,
            sig_version,
            bip65_active: flags.contains(VerifyFlags::CHECKLOCKTIMEVERIFY),
            bip112_active: flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY),
            bip66_active: flags.contains(VerifyFlags::DERSIG),
            minimal_data: flags.contains(VerifyFlags::MINIMALDATA),
            nullfail: flags.contains(VerifyFlags::NULLFAIL),
            low_s: flags.contains(VerifyFlags::LOW_S),
            strictenc: flags.contains(VerifyFlags::STRICTENC),
            null_dummy: flags.contains(VerifyFlags::NULLDUMMY),
            minimal_if: flags.contains(VerifyFlags::MINIMALIF),
            witness_pubkeytype: flags.contains(VerifyFlags::WITNESS_PUBKEYTYPE),
            const_scriptcode: flags.contains(VerifyFlags::CONST_SCRIPTCODE),
            codeseparator_pos: Cell::new(u32::MAX),
            codeseparator_script_off: Cell::new(None),
            cache: RefCell::new(cache),
        }
    }
}

mod crypto {
    use bitcoin::hashes::{Hash as _, hash160, sha1, sha256};
    use bitcoin::secp256k1::{self, Message, PublicKey, ecdsa};

    pub(super) fn sha1(data: &[u8]) -> [u8; 20] {
        sha1::Hash::hash(data).to_byte_array()
    }
    pub(super) fn sha256(data: &[u8]) -> [u8; 32] {
        sha256::Hash::hash(data).to_byte_array()
    }
    pub(super) fn hash160(data: &[u8]) -> [u8; 20] {
        hash160::Hash::hash(data).to_byte_array()
    }

    pub(super) fn is_valid_signature_encoding(sig: &[u8]) -> bool {
        if sig.len() < 9 || sig.len() > 73 || sig.first() != Some(&0x30) {
            return false;
        }
        if sig[1] as usize != sig.len() - 3 || sig[2] != 0x02 {
            return false;
        }
        let len_r = sig[3] as usize;
        if len_r == 0 || 5 + len_r >= sig.len() || sig[4 + len_r] != 0x02 {
            return false;
        }
        let len_s = sig[5 + len_r] as usize;
        if len_r + len_s + 7 != sig.len() || len_s == 0 {
            return false;
        }
        let r = &sig[4..4 + len_r];
        let s = &sig[6 + len_r..6 + len_r + len_s];
        if r[0] & 0x80 != 0 || (len_r > 1 && r[0] == 0 && r[1] & 0x80 == 0) {
            return false;
        }
        if s[0] & 0x80 != 0 || (len_s > 1 && s[0] == 0 && s[1] & 0x80 == 0) {
            return false;
        }
        true
    }

    pub(super) fn parse_der_sig(
        sig: &[u8],
        strict: bool,
    ) -> Result<(ecdsa::Signature, u8), secp256k1::Error> {
        let (&sighash, der) = sig.split_last().ok_or(secp256k1::Error::InvalidSignature)?;
        let parsed = if strict {
            ecdsa::Signature::from_der(der)?
        } else {
            ecdsa::Signature::from_der_lax(der)?
        };
        Ok((parsed, sighash))
    }

    pub(super) fn is_low_der_s(signature: &ecdsa::Signature) -> bool {
        let mut normalized = *signature;
        let before = normalized.serialize_der();
        normalized.normalize_s();
        normalized.serialize_der() == before
    }

    pub(super) fn is_defined_hashtype(sig: &[u8]) -> bool {
        let Some(&hash_type) = sig.last() else {
            return false;
        };
        let base = hash_type & 0x1f;
        (1..=3).contains(&base) && hash_type & 0x60 == 0
    }

    pub(super) fn is_compressed_pubkey(key: &[u8]) -> bool {
        key.len() == 33 && matches!(key[0], 0x02 | 0x03)
    }

    pub(super) fn is_compressed_or_uncompressed_pubkey(key: &[u8]) -> bool {
        is_compressed_pubkey(key) || (key.len() == 65 && key[0] == 0x04)
    }

    pub(super) fn parse_pubkey(key: &[u8]) -> Result<PublicKey, secp256k1::Error> {
        PublicKey::from_slice(key)
    }

    pub(super) fn verify_ecdsa(
        sighash: [u8; 32],
        signature: &ecdsa::Signature,
        public_key: &PublicKey,
    ) -> bool {
        let mut normalized = *signature;
        normalized.normalize_s();
        let secp = secp256k1::Secp256k1::verification_only();
        secp.verify_ecdsa(&Message::from_digest(sighash), &normalized, public_key)
            .is_ok()
    }
}

fn sighash_for_script(
    ctx: &EvalContext<'_, '_, '_, '_>,
    ty_raw: u32,
    script_bytes: &[u8],
) -> Result<[u8; 32], EvalError> {
    if ctx.sig_version != SigVersion::Base {
        return Err(EvalError::Script(
            "segwit-v0 script execution is not enabled".into(),
        ));
    }
    // Legacy signature serialization omits all OP_CODESEPARATOR opcodes and
    // uses the post-separator scriptCode selected by the executing context.
    let stripped = strip_op_codeseparator(script_bytes);
    let script_code = Script::from_bytes(&stripped);
    let cache = ctx.cache.borrow_mut();
    let hash = cache
        .legacy_signature_hash(ctx.input_index, script_code, ty_raw)
        .map_err(|_| EvalError::Script("legacy sighash".into()))?;
    Ok(hash.to_byte_array())
}
fn require_clean_true(stack: &[Vec<u8>]) -> Result<(), EvalError> {
    if stack.len() != 1 {
        return Err(EvalError::Script("cleanstack".into()));
    }
    if !cast_to_bool(&stack[0]) {
        return Err(EvalError::Script("script false".into()));
    }
    Ok(())
}

/// BIP16 / legacy: final stack must be non-empty with a true top element.
///
/// **Not** cleanstack — BIP62 CLEANSTACK was never activated for non-witness
/// consensus. Requiring `len==1` falsely rejected valid P2SH (signet 219477).
fn require_true_top(stack: &[Vec<u8>]) -> Result<(), EvalError> {
    if stack.is_empty() || !cast_to_bool(stack.last().unwrap()) {
        return Err(EvalError::Script("script false".into()));
    }
    Ok(())
}

/// Evaluate scriptSig as push-only onto `stack` (BIP16 P2SH / SIGPUSHONLY).
///
/// **Not** used for bare script verification — historical bare spends may run
/// non-push opcodes in scriptSig (e.g. `OP_CODESEPARATOR` + `CHECKMULTISIG` at
/// mainnet height 163685). Callers that need BIP16 push-only must use this
/// helper; bare paths use full [`eval_script`] on scriptSig.
fn eval_script_sig_pushes(script: &Script, stack: &mut Vec<Vec<u8>>) -> Result<(), EvalError> {
    if script.as_bytes().len() > MAX_SCRIPT_SIZE_LEGACY {
        return Err(EvalError::Script("script too large".into()));
    }
    for ins in script.instructions() {
        match ins.map_err(|_| EvalError::Script("scriptSig parse".into()))? {
            Instruction::PushBytes(b) => {
                push(stack, 0, b.as_bytes().to_vec())?;
            }
            Instruction::Op(op) => {
                let n = op.to_u8();
                if n == 0x00 {
                    push(stack, 0, vec![])?;
                } else if n == 0x4f {
                    push(stack, 0, vec![0x81])?;
                } else if (0x51..=0x60).contains(&n) {
                    push(stack, 0, vec![n - 0x50])?;
                } else {
                    return Err(EvalError::Script("scriptSig non-push".into()));
                }
            }
        }
    }
    Ok(())
}

/// Evaluate `script`. On success returns `true` if cleanstack must still be
/// checked; `false` if the script already fully succeeded (e.g. OP_SUCCESS).
fn eval_script(
    script: &Script,
    stack: &mut Vec<Vec<u8>>,
    ctx: &EvalContext<'_, '_, '_, '_>,
) -> Result<bool, EvalError> {
    let bytes = script.as_bytes();
    // BIP342: OP_SUCCESSx anywhere in tapscript → unconditional success *before*
    // size / stack limits (even unparseable tails pass).
    if ctx.sig_version == SigVersion::TapScript && tapscript_has_op_success(script) {
        return Ok(false);
    }
    if ctx.sig_version == SigVersion::TapScript {
        if stack.len() > MAX_STACK_SIZE {
            return Err(EvalError::Script("stack size".into()));
        }
        for item in stack.iter() {
            if item.len() > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(EvalError::Script("PUSH_SIZE".into()));
            }
        }
    }
    // Legacy / v0 only: 10k script size. Tapscript: no explicit size limit.
    if ctx.sig_version != SigVersion::TapScript && bytes.len() > MAX_SCRIPT_SIZE_LEGACY {
        return Err(EvalError::Script("script too large".into()));
    }

    let mut altstack: Vec<Vec<u8>> = Vec::new();
    let mut if_stack: Vec<bool> = Vec::new();
    let mut op_count = 0usize;
    let enforce_op_limit = ctx.sig_version != SigVersion::TapScript;
    // TapScript always MINIMALIF. SCRIPT_VERIFY_MINIMALIF applies to witness v0
    // (and tapscript); bare/Base scripts ignore the flag (Core fixture #1197).
    let minimal_if = ctx.sig_version == SigVersion::TapScript
        || (ctx.minimal_if && ctx.sig_version == SigVersion::WitnessV0);
    // BIP342 / Core: instruction index for codeseparator_pos (not byte offset).
    let mut opcode_pos: u32 = 0;
    // Prefer instruction_indices so OP_CODESEPARATOR can set Base/WitnessV0
    // scriptCode byte offsets (BIP143 / Core pbegincodehash).
    for item in script.instruction_indices() {
        let (byte_index, ins) = item.map_err(|_| EvalError::Script("script parse".into()))?;
        let this_pos = opcode_pos;
        opcode_pos = opcode_pos.saturating_add(1);
        let executing = if_stack.iter().all(|&x| x);

        match ins {
            Instruction::PushBytes(b) => {
                // Core: MAX_SCRIPT_ELEMENT_SIZE even in unexecuted branches.
                let data = b.as_bytes();
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(EvalError::Script("push too large".into()));
                }
                // Core MINIMALDATA: CheckMinimalPush only when the push executes
                // (unexecuted IF branches ignore non-minimal encodings).
                if executing {
                    if ctx.minimal_data {
                        let opcode = bytes.get(byte_index).copied().unwrap_or(0);
                        if !check_minimal_push(data, opcode) {
                            return Err(EvalError::Script("MINIMALDATA".into()));
                        }
                    }
                    push(stack, altstack.len(), data.to_vec())?;
                }
            }
            Instruction::Op(op) => {
                let code = op.to_u8();

                // Legacy / v0: opcodes > OP_16 count toward 201 even when skipped,
                // including OP_IF / NOTIF / ELSE / ENDIF (Core nOpCount).
                if enforce_op_limit && code > 0x60 {
                    op_count += 1;
                    if op_count > MAX_OPS_LEGACY {
                        return Err(EvalError::Script("op count".into()));
                    }
                }

                // IF/ELSE/ENDIF must run even when skipped (structure, not value).
                match code {
                    0x63 => {
                        let mut cond = false;
                        if executing {
                            let v = pop(stack)?;
                            if minimal_if && !is_minimal_if_arg(&v) {
                                return Err(EvalError::Script("MINIMALIF".into()));
                            }
                            cond = cast_to_bool(&v);
                        }
                        if_stack.push(executing && cond);
                        continue;
                    }
                    0x64 => {
                        let mut cond = false;
                        if executing {
                            let v = pop(stack)?;
                            if minimal_if && !is_minimal_if_arg(&v) {
                                return Err(EvalError::Script("MINIMALIF".into()));
                            }
                            cond = !cast_to_bool(&v);
                        }
                        if_stack.push(executing && cond);
                        continue;
                    }
                    0x67 => {
                        if if_stack.is_empty() {
                            return Err(EvalError::Script("OP_ELSE".into()));
                        }
                        let last = if_stack.last_mut().unwrap();
                        *last = !*last;
                        continue;
                    }
                    0x68 => {
                        if if_stack.pop().is_none() {
                            return Err(EvalError::Script("OP_ENDIF".into()));
                        }
                        continue;
                    }
                    _ => {}
                }

                // Core: OP_VERIF / OP_VERNOTIF always fail (even unexecuted).
                if code == 0x65 || code == 0x66 {
                    return Err(EvalError::Script("OP_VERIF".into()));
                }
                // Core: disabled opcodes fail even in unexecuted branches (legacy/v0).
                if ctx.sig_version != SigVersion::TapScript && is_disabled_legacy(code) {
                    return Err(EvalError::Script(format!("disabled opcode 0x{code:02x}")));
                }
                // CONST_SCRIPTCODE: OP_CODESEPARATOR rejected in Base even unexecuted.
                if code == 0xab && ctx.const_scriptcode && ctx.sig_version == SigVersion::Base {
                    return Err(EvalError::Script("OP_CODESEPARATOR".into()));
                }

                if !executing {
                    continue;
                }

                let rm = ctx.minimal_data;
                match code {
                    0x00 => push(stack, altstack.len(), vec![])?,
                    0x4f => push(stack, altstack.len(), vec![0x81])?,
                    n if (0x51..=0x60).contains(&n) => push(stack, altstack.len(), vec![n - 0x50])?,

                    0x50 => {
                        return Err(EvalError::Script("OP_RESERVED".into()));
                    }
                    0x61 => {}
                    0x62 => {
                        return Err(EvalError::Script("OP_VER".into()));
                    }
                    0x65 | 0x66 => {
                        return Err(EvalError::Script("OP_VERIF".into()));
                    }
                    0x69 => {
                        let v = pop(stack)?;
                        if !cast_to_bool(&v) {
                            return Err(EvalError::Script("OP_VERIFY".into()));
                        }
                    }
                    0x6a => return Err(EvalError::Script("OP_RETURN".into())),

                    0x6b => {
                        let v = pop(stack)?;
                        altstack.push(v);
                    }
                    0x6c => {
                        let v = altstack
                            .pop()
                            .ok_or_else(|| EvalError::Script("altstack empty".into()))?;
                        push(stack, altstack.len(), v)?;
                    }
                    0x6d => {
                        pop(stack)?;
                        pop(stack)?;
                    }
                    0x6e => {
                        require_n(stack, 2)?;
                        let a = stack[stack.len() - 2].clone();
                        let b = stack[stack.len() - 1].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                    }
                    0x6f => {
                        require_n(stack, 3)?;
                        let a = stack[stack.len() - 3].clone();
                        let b = stack[stack.len() - 2].clone();
                        let c = stack[stack.len() - 1].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                        push(stack, altstack.len(), c)?;
                    }
                    0x70 => {
                        require_n(stack, 4)?;
                        let a = stack[stack.len() - 4].clone();
                        let b = stack[stack.len() - 3].clone();
                        push(stack, altstack.len(), a)?;
                        push(stack, altstack.len(), b)?;
                    }
                    0x71 => {
                        require_n(stack, 6)?;
                        let n = stack.len();
                        let x1 = stack[n - 6].clone();
                        let x2 = stack[n - 5].clone();
                        for i in 0..4 {
                            stack[n - 6 + i] = stack[n - 4 + i].clone();
                        }
                        stack[n - 2] = x1;
                        stack[n - 1] = x2;
                    }
                    0x72 => {
                        require_n(stack, 4)?;
                        let n = stack.len();
                        stack.swap(n - 4, n - 2);
                        stack.swap(n - 3, n - 1);
                    }
                    0x73 => {
                        require_n(stack, 1)?;
                        if cast_to_bool(stack.last().unwrap()) {
                            let v = stack.last().unwrap().clone();
                            push(stack, altstack.len(), v)?;
                        }
                    }
                    0x74 => {
                        let d = stack.len() as i64;
                        push(stack, altstack.len(), scriptnum_encode(d))?;
                    }
                    0x75 => {
                        pop(stack)?;
                    }
                    0x76 => {
                        require_n(stack, 1)?;
                        let v = stack.last().unwrap().clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x77 => {
                        require_n(stack, 2)?;
                        let top = pop(stack)?;
                        pop(stack)?;
                        push(stack, altstack.len(), top)?;
                    }
                    0x78 => {
                        require_n(stack, 2)?;
                        let v = stack[stack.len() - 2].clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x79 => {
                        let n = scriptnum_decode(&pop(stack)?, rm)?;
                        if n < 0 || n as usize >= stack.len() {
                            return Err(EvalError::Script("OP_PICK".into()));
                        }
                        let v = stack[stack.len() - 1 - n as usize].clone();
                        push(stack, altstack.len(), v)?;
                    }
                    0x7a => {
                        let n = scriptnum_decode(&pop(stack)?, rm)?;
                        if n < 0 || n as usize >= stack.len() {
                            return Err(EvalError::Script("OP_ROLL".into()));
                        }
                        let idx = stack.len() - 1 - n as usize;
                        let v = stack.remove(idx);
                        push(stack, altstack.len(), v)?;
                    }
                    0x7b => {
                        require_n(stack, 3)?;
                        let n = stack.len();
                        stack.swap(n - 3, n - 2);
                        stack.swap(n - 2, n - 1);
                    }
                    0x7c => {
                        require_n(stack, 2)?;
                        let n = stack.len();
                        stack.swap(n - 1, n - 2);
                    }
                    0x7d => {
                        require_n(stack, 2)?;
                        let v = stack[stack.len() - 1].clone();
                        stack.insert(stack.len() - 2, v);
                        if stack.len() + altstack.len() > MAX_STACK_SIZE {
                            return Err(EvalError::Script("stack size".into()));
                        }
                    }
                    0x82 => {
                        require_n(stack, 1)?;
                        let sz = stack.last().unwrap().len() as i64;
                        push(stack, altstack.len(), scriptnum_encode(sz))?;
                    }
                    0x89 | 0x8a => {
                        return Err(EvalError::Script("OP_RESERVED".into()));
                    }
                    0x87 => {
                        let a = pop(stack)?;
                        let b = pop(stack)?;
                        push(stack, altstack.len(), bool_encode(a == b))?;
                    }
                    0x88 => {
                        let a = pop(stack)?;
                        let b = pop(stack)?;
                        if a != b {
                            return Err(EvalError::Script("OP_EQUALVERIFY".into()));
                        }
                    }
                    0x8b => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.saturating_add(1)))?;
                    }
                    0x8c => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.saturating_sub(1)))?;
                    }
                    0x8f => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(-v))?;
                    }
                    0x90 => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(v.abs()))?;
                    }
                    0x91 => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(v == 0))?;
                    }
                    0x92 => {
                        let v = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(v != 0))?;
                    }
                    0x93 => bin_arith(stack, altstack.len(), rm, |a, b| a.wrapping_add(b))?,
                    0x94 => bin_arith(stack, altstack.len(), rm, |a, b| a.wrapping_sub(b))?,
                    0x9a => {
                        let b = scriptnum_decode(&pop(stack)?, rm)?;
                        let a = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(a != 0 && b != 0))?;
                    }
                    0x9b => {
                        let b = scriptnum_decode(&pop(stack)?, rm)?;
                        let a = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(a != 0 || b != 0))?;
                    }
                    0x9c => bin_cmp(stack, altstack.len(), rm, |a, b| a == b)?,
                    0x9d => {
                        let b = scriptnum_decode(&pop(stack)?, rm)?;
                        let a = scriptnum_decode(&pop(stack)?, rm)?;
                        if a != b {
                            return Err(EvalError::Script("OP_NUMEQUALVERIFY".into()));
                        }
                    }
                    0x9e => bin_cmp(stack, altstack.len(), rm, |a, b| a != b)?,
                    0x9f => bin_cmp(stack, altstack.len(), rm, |a, b| a < b)?,
                    0xa0 => bin_cmp(stack, altstack.len(), rm, |a, b| a > b)?,
                    0xa1 => bin_cmp(stack, altstack.len(), rm, |a, b| a <= b)?,
                    0xa2 => bin_cmp(stack, altstack.len(), rm, |a, b| a >= b)?,
                    0xa3 => {
                        let b = scriptnum_decode(&pop(stack)?, rm)?;
                        let a = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(a.min(b)))?;
                    }
                    0xa4 => {
                        let b = scriptnum_decode(&pop(stack)?, rm)?;
                        let a = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), scriptnum_encode(a.max(b)))?;
                    }
                    0xa5 => {
                        let max = scriptnum_decode(&pop(stack)?, rm)?;
                        let min = scriptnum_decode(&pop(stack)?, rm)?;
                        let x = scriptnum_decode(&pop(stack)?, rm)?;
                        push(stack, altstack.len(), bool_encode(x >= min && x < max))?;
                    }
                    0xa6 => {
                        let v = pop(stack)?;
                        use bitcoin::hashes::ripemd160;
                        push(
                            stack,
                            altstack.len(),
                            ripemd160::Hash::hash(&v).to_byte_array().to_vec(),
                        )?;
                    }
                    0xa7 => {
                        // OP_SHA1 is consensus-enabled (was stubbed → would fail post-milestone).
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::sha1(&v).to_vec())?;
                    }
                    0xa8 => {
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::sha256(&v).to_vec())?;
                    }
                    0xa9 => {
                        let v = pop(stack)?;
                        push(stack, altstack.len(), crypto::hash160(&v).to_vec())?;
                    }
                    0xaa => {
                        let v = pop(stack)?;
                        use bitcoin::hashes::sha256d;
                        push(
                            stack,
                            altstack.len(),
                            sha256d::Hash::hash(&v).to_byte_array().to_vec(),
                        )?;
                    }
                    0xab => {
                        // Tapscript: instruction index. Base/v0: scriptCode after this opcode.
                        if ctx.const_scriptcode && ctx.sig_version == SigVersion::Base {
                            return Err(EvalError::Script("OP_CODESEPARATOR".into()));
                        }
                        ctx.codeseparator_pos.set(this_pos);
                        ctx.codeseparator_script_off
                            .set(Some(byte_index.saturating_add(1)));
                    }
                    0xac => op_checksig(stack, altstack.len(), ctx, false)?,
                    0xad => op_checksig(stack, altstack.len(), ctx, true)?,
                    0xba => return Err(EvalError::Script("CHECKSIGADD unavailable".into())),
                    0xae => {
                        // BIP342: CHECKMULTISIG disabled in tapscript (hard fail).
                        if ctx.sig_version == SigVersion::TapScript {
                            return Err(EvalError::Script(
                                "CHECKMULTISIG disabled in tapscript".into(),
                            ));
                        }
                        op_checkmultisig(stack, altstack.len(), ctx, false, &mut op_count)?;
                    }
                    0xaf => {
                        if ctx.sig_version == SigVersion::TapScript {
                            return Err(EvalError::Script(
                                "CHECKMULTISIGVERIFY disabled in tapscript".into(),
                            ));
                        }
                        op_checkmultisig(stack, altstack.len(), ctx, true, &mut op_count)?;
                    }
                    0xb1 => {
                        // BIP65: pre-activation is NOP.
                        if !ctx.bip65_active {
                            continue;
                        }
                        require_n(stack, 1)?;
                        // Core: CScriptNum(..., fRequireMinimal, 5) for locktime.
                        let locktime = scriptnum_decode_width(stack.last().unwrap(), 5, rm)?;
                        if locktime < 0 {
                            return Err(EvalError::Script("CLTV negative".into()));
                        }
                        let tx_lock = ctx.tx.lock_time.to_consensus_u32() as i64;
                        let lock_is_time = locktime >= 500_000_000;
                        let tx_is_time = tx_lock >= 500_000_000;
                        if lock_is_time != tx_is_time {
                            return Err(EvalError::Script("CLTV type".into()));
                        }
                        if locktime > tx_lock {
                            return Err(EvalError::Script("CLTV".into()));
                        }
                        if ctx.tx.input[ctx.input_index].sequence.is_final() {
                            return Err(EvalError::Script("CLTV final sequence".into()));
                        }
                    }
                    0xb2 => {
                        // BIP112: decode (5-byte) → disable-flag NOP → version < 2 fails
                        // (not NOP). docs/external_findings/004-csv-nop-and-scriptnum-width.md
                        if !ctx.bip112_active {
                            continue;
                        }
                        require_n(stack, 1)?;
                        let csv = scriptnum_decode_width(stack.last().unwrap(), 5, rm)?;
                        if csv < 0 {
                            return Err(EvalError::Script("CSV negative".into()));
                        }
                        if csv as u32 & (1 << 31) != 0 {
                            // Disabled bit makes CSV a NOP before the version gate.
                            continue;
                        }
                        // Core CheckSequence uses the serialized uint32 version.
                        if (ctx.tx.version.0 as u32) < 2 {
                            return Err(EvalError::Script("CSV version".into()));
                        }
                        let seq = ctx.tx.input[ctx.input_index].sequence;
                        if !sequence_csv_ok(seq, csv as u32) {
                            return Err(EvalError::Script("CSV".into()));
                        }
                    }
                    0xb0 | 0xb3 | 0xb4 | 0xb5 | 0xb6 | 0xb7 | 0xb8 | 0xb9 => {
                        if ctx.flags.contains(VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                            return Err(EvalError::Script("DISCOURAGE_UPGRADABLE_NOPS".into()));
                        }
                    }
                    _ => {
                        if ctx.sig_version == SigVersion::TapScript && is_op_success(code) {
                            return Ok(false);
                        }
                        if ctx.sig_version != SigVersion::TapScript && is_disabled_legacy(code) {
                            return Err(EvalError::Script(format!("disabled opcode 0x{code:02x}")));
                        }
                        return Err(EvalError::Script(format!("unknown opcode 0x{code:02x}")));
                    }
                }
                // Core: stack + altstack share MAX_STACK_SIZE (1000).
                if stack.len() + altstack.len() > MAX_STACK_SIZE {
                    return Err(EvalError::Script("stack size".into()));
                }
            }
        }
    }

    if !if_stack.is_empty() {
        return Err(EvalError::Script("unbalanced IF".into()));
    }
    Ok(true)
}

fn sequence_csv_ok(seq: Sequence, csv: u32) -> bool {
    let seq_n = seq.to_consensus_u32();
    if seq_n & (1 << 31) != 0 {
        return false; // SEQUENCE_LOCKTIME_DISABLE_FLAG on input
    }
    let mask = 0x0000_ffff | (1 << 22);
    let seq_masked = seq_n & mask;
    let csv_masked = csv & mask;
    let type_flag = 1 << 22;
    if (seq_masked ^ csv_masked) & type_flag != 0 {
        return false;
    }
    (csv_masked & 0xffff) <= (seq_masked & 0xffff)
}

fn op_checksig(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    ctx: &EvalContext<'_, '_, '_, '_>,
    verify: bool,
) -> Result<(), EvalError> {
    let pubkey = pop(stack)?;
    let sig = pop(stack)?;
    let ok = checksig_legacy(&sig, &pubkey, ctx, None)?;
    if verify {
        if !ok {
            return Err(EvalError::Script("CHECKSIGVERIFY".into()));
        }
    } else {
        push(stack, alt_len, bool_encode(ok))?;
    }
    Ok(())
}

fn op_checkmultisig(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    ctx: &EvalContext<'_, '_, '_, '_>,
    verify: bool,
    op_count: &mut usize,
) -> Result<(), EvalError> {
    // Pop order matches Core: n, n keys (top=last), m, m sigs (top=last), dummy.
    let n = scriptnum_decode(&pop(stack)?, ctx.minimal_data)?;
    if n < 0 || n > MAX_PUBKEYS_PER_MULTISIG {
        return Err(EvalError::Script("multisig n".into()));
    }
    *op_count += n as usize;
    if *op_count > MAX_OPS_LEGACY {
        return Err(EvalError::Script("op count".into()));
    }
    // Pop n keys: first pop is stack top = last pushed. Core evaluates that
    // key first (encoding + match), so keep pop order (no reverse).
    let mut pubkeys = Vec::with_capacity(n as usize);
    for _ in 0..n {
        pubkeys.push(pop(stack)?);
    }
    let m = scriptnum_decode(&pop(stack)?, ctx.minimal_data)?;
    if m < 0 || m > n {
        return Err(EvalError::Script("multisig m".into()));
    }
    let mut sigs = Vec::with_capacity(m as usize);
    for _ in 0..m {
        sigs.push(pop(stack)?);
    }
    let dummy = pop(stack)?;

    // Core Base: FindAndDelete **all** sigs from scriptCode before the loop.
    let script_code_owned: Option<Vec<u8>> = if ctx.sig_version == SigVersion::Base {
        let mut sc = script_code_bytes(ctx).to_vec();
        let original = sc.clone();
        for sig in &sigs {
            sc = find_and_delete(&sc, sig);
        }
        if ctx.const_scriptcode && sc != original {
            return Err(EvalError::Script("SIG_FINDANDDELETE".into()));
        }
        Some(sc)
    } else {
        None
    };
    let script_override = script_code_owned.as_deref();

    // Core: start at last-pushed sig/key (index 0 after pop-order storage).
    // Advance key always; advance sig only on match. Encoding checks run only
    // for pairs actually tried (early exit skips unused invalid encodings).
    let mut f_success = true;
    let mut n_sigs = sigs.len();
    let mut n_keys = pubkeys.len();
    let mut isig = 0usize;
    let mut ikey = 0usize;
    while f_success && n_sigs > 0 {
        let f_ok = checksig_legacy(&sigs[isig], &pubkeys[ikey], ctx, script_override)?;
        if f_ok {
            isig += 1;
            n_sigs -= 1;
        }
        ikey += 1;
        n_keys -= 1;
        if n_sigs > n_keys {
            f_success = false;
        }
    }

    if !f_success && ctx.nullfail && sigs.iter().any(|s| !s.is_empty()) {
        return Err(EvalError::Script("NULLFAIL".into()));
    }
    // BIP147 is checked after signature matching and NULLFAIL precedence.
    if !dummy.is_empty() && (ctx.sig_version == SigVersion::WitnessV0 || ctx.null_dummy) {
        return Err(EvalError::Script("NULLDUMMY".into()));
    }

    if verify {
        if !f_success {
            return Err(EvalError::Script("CHECKMULTISIGVERIFY".into()));
        }
    } else {
        push(stack, alt_len, bool_encode(f_success))?;
    }
    Ok(())
}

/// Core `FindAndDelete`: remove every occurrence of a data-push of `data` from `script`.
///
/// Used for legacy (Base) CHECKSIG / CHECKMULTISIG so a signature cannot sign itself
/// when it appears inside scriptCode (mainnet block 290329: P2SH redeem embeds a sig).
pub(crate) fn find_and_delete(script: &[u8], data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return script.to_vec();
    }
    let mut needle = Vec::with_capacity(data.len() + 3);
    if data.len() < 0x4c {
        needle.push(data.len() as u8);
    } else if data.len() <= 0xff {
        needle.push(0x4c);
        needle.push(data.len() as u8);
    } else if data.len() <= 0xffff {
        needle.push(0x4d);
        needle.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        needle.push(0x4e);
        needle.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    needle.extend_from_slice(data);

    let mut out = Vec::with_capacity(script.len());
    let mut i = 0usize;
    while i < script.len() {
        if i + needle.len() <= script.len() && script[i..i + needle.len()] == needle[..] {
            i += needle.len();
            continue;
        }
        let op = script[i];
        out.push(op);
        i += 1;
        let n = if (1..=75).contains(&op) {
            op as usize
        } else if op == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            out.push(script[i]);
            i += 1;
            n
        } else if op == 0x4d {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            out.extend_from_slice(&script[i..i + 2]);
            i += 2;
            n
        } else if op == 0x4e {
            if i + 3 >= script.len() {
                break;
            }
            let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                as usize;
            out.extend_from_slice(&script[i..i + 4]);
            i += 4;
            n
        } else {
            0
        };
        if n > 0 {
            let end = (i + n).min(script.len());
            out.extend_from_slice(&script[i..end]);
            i = end;
        }
    }
    out
}

/// Script bytes used as Base/WitnessV0 scriptCode (after OP_CODESEPARATOR).
fn script_code_bytes<'a>(ctx: &'a EvalContext<'_, '_, '_, '_>) -> &'a [u8] {
    let full = ctx.script_code.as_bytes();
    match ctx.codeseparator_script_off.get() {
        Some(off) if off <= full.len() => &full[off..],
        _ => full,
    }
}

/// Core `CTransactionSignatureSerializer::SerializeScriptCode`: when hashing a
/// legacy (BASE) scriptCode, **skip every `OP_CODESEPARATOR` opcode** (0xab).
///
/// This is distinct from `pbegincodehash` truncation (which only drops bytes
/// *before* the last executed CODESEPARATOR). Separators that remain *after*
/// that point are still omitted from the serialized scriptCode. Without this,
/// redeem scripts that embed CODESEPARATOR (e.g. mainnet block 443992 P2SH
/// multi-condition contracts) produce a wrong sighash and fail CHECKSIGVERIFY.
pub(crate) fn strip_op_codeseparator(script: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(script.len());
    let mut i = 0usize;
    while i < script.len() {
        let op = script[i];
        i += 1;
        if op == 0xab {
            continue;
        }
        out.push(op);
        let n = if (1..=75).contains(&op) {
            op as usize
        } else if op == 0x4c {
            if i >= script.len() {
                break;
            }
            let n = script[i] as usize;
            out.push(script[i]);
            i += 1;
            n
        } else if op == 0x4d {
            if i + 1 >= script.len() {
                break;
            }
            let n = u16::from_le_bytes([script[i], script[i + 1]]) as usize;
            out.extend_from_slice(&script[i..i + 2]);
            i += 2;
            n
        } else if op == 0x4e {
            if i + 3 >= script.len() {
                break;
            }
            let n = u32::from_le_bytes([script[i], script[i + 1], script[i + 2], script[i + 3]])
                as usize;
            out.extend_from_slice(&script[i..i + 4]);
            i += 4;
            n
        } else {
            0
        };
        if n > 0 {
            let end = (i + n).min(script.len());
            out.extend_from_slice(&script[i..end]);
            i = end;
        }
    }
    out
}

/// Legacy / witness-v0 CHECKSIG.
///
/// Empty signature → soft false. Encoding failures under DERSIG / LOW_S /
/// STRICTENC hard-fail (Core `CheckSignatureEncoding` / `CheckPubKeyEncoding`).
/// NULLFAIL hard-fails a non-empty signature that does not verify.
///
/// `script_code_override`: when `Some`, use these bytes as scriptCode for sighash
/// (CHECKMULTISIG pre-deletes **all** stack sigs). When `None`, Base path applies
/// FindAndDelete of **this** signature only (Core EvalChecksigPreTapscript).
fn checksig_legacy(
    sig: &[u8],
    pubkey: &[u8],
    ctx: &EvalContext<'_, '_, '_, '_>,
    script_code_override: Option<&[u8]>,
) -> Result<bool, EvalError> {
    // NULLFAIL is applied after the whole multisig loop, not per key attempt.
    let apply_nullfail = ctx.nullfail && script_code_override.is_none();

    // Legacy FindAndDelete is selected before signature encoding checks. Core
    // treats an empty signature as the special soft-false case and does not
    // search for an empty pushed element.
    let owned: Vec<u8>;
    let script_bytes: &[u8] = if let Some(sc) = script_code_override {
        sc
    } else {
        let base = script_code_bytes(ctx);
        if ctx.sig_version == SigVersion::Base {
            let deleted = find_and_delete(base, sig);
            if ctx.const_scriptcode && deleted.as_slice() != base {
                return Err(EvalError::Script("SIG_FINDANDDELETE".into()));
            }
            owned = deleted;
            owned.as_slice()
        } else {
            base
        }
    };

    let nonempty = !sig.is_empty();
    let need_der = ctx.bip66_active || ctx.low_s || ctx.strictenc;
    if nonempty && need_der && !crypto::is_valid_signature_encoding(sig) {
        return Err(EvalError::Script("SIG_DER".into()));
    }
    if nonempty && ctx.low_s {
        if let Ok((ecdsa, _)) = crypto::parse_der_sig(sig, false) {
            if !crypto::is_low_der_s(&ecdsa) {
                return Err(EvalError::Script("SIG_HIGH_S".into()));
            }
        }
    }
    if nonempty && ctx.strictenc && !crypto::is_defined_hashtype(sig) {
        return Err(EvalError::Script("SIG_HASHTYPE".into()));
    }
    // Core checks public-key encoding even when the signature is empty.
    if ctx.strictenc && !crypto::is_compressed_or_uncompressed_pubkey(pubkey) {
        return Err(EvalError::Script("PUBKEYTYPE".into()));
    }
    if ctx.witness_pubkeytype
        && ctx.sig_version == SigVersion::WitnessV0
        && !crypto::is_compressed_pubkey(pubkey)
    {
        return Err(EvalError::Script("WITNESS_PUBKEYTYPE".into()));
    }
    if !nonempty {
        return Ok(false);
    }

    let (ecdsa_sig, sighash_ty) = match crypto::parse_der_sig(sig, false) {
        Ok(x) => x,
        // Pre-DERSIG: malformed DER that slipped encoding → soft false.
        Err(_) => {
            if apply_nullfail {
                return Err(EvalError::Script("NULLFAIL".into()));
            }
            return Ok(false);
        }
    };
    let pk = match crypto::parse_pubkey(pubkey) {
        Ok(p) => p,
        Err(_) => {
            if apply_nullfail {
                return Err(EvalError::Script("NULLFAIL".into()));
            }
            return Ok(false);
        }
    };
    let sighash = match sighash_for_script(ctx, u32::from(sighash_ty), script_bytes) {
        Ok(h) => h,
        Err(_) => {
            if apply_nullfail {
                return Err(EvalError::Script("NULLFAIL".into()));
            }
            return Ok(false);
        }
    };
    let ok = crypto::verify_ecdsa(sighash, &ecdsa_sig, &pk);
    if !ok && apply_nullfail {
        return Err(EvalError::Script("NULLFAIL".into()));
    }
    Ok(ok)
}
fn push(stack: &mut Vec<Vec<u8>>, alt_len: usize, v: Vec<u8>) -> Result<(), EvalError> {
    if v.len() > MAX_SCRIPT_ELEMENT_SIZE {
        return Err(EvalError::Script("PUSH_SIZE".into()));
    }
    if stack.len().saturating_add(alt_len).saturating_add(1) > MAX_STACK_SIZE {
        return Err(EvalError::Script("stack size".into()));
    }
    stack.push(v);
    Ok(())
}

fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, EvalError> {
    stack
        .pop()
        .ok_or_else(|| EvalError::Script("stack empty".into()))
}

fn require_n(stack: &[Vec<u8>], n: usize) -> Result<(), EvalError> {
    if stack.len() < n {
        return Err(EvalError::Script("stack empty".into()));
    }
    Ok(())
}

fn cast_to_bool(v: &[u8]) -> bool {
    for (i, &b) in v.iter().enumerate() {
        if b != 0 {
            // Negative zero
            if i == v.len() - 1 && b == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// BIP342 MINIMALIF: IF/NOTIF argument is empty vector or single-byte 0x01 only.
fn is_minimal_if_arg(v: &[u8]) -> bool {
    v.is_empty() || v == [0x01]
}

fn bool_encode(b: bool) -> Vec<u8> {
    if b { vec![1] } else { vec![] }
}

fn scriptnum_encode(mut n: i64) -> Vec<u8> {
    if n == 0 {
        return vec![];
    }
    let neg = n < 0;
    if neg {
        n = -n;
    }
    let mut out = Vec::new();
    while n > 0 {
        out.push((n & 0xff) as u8);
        n >>= 8;
    }
    if out.last().map(|b| b & 0x80 != 0).unwrap_or(false) {
        out.push(if neg { 0x80 } else { 0x00 });
    } else if neg {
        let last = out.last_mut().unwrap();
        *last |= 0x80;
    }
    out
}

/// Core `CheckMinimalPush`: data must use the shortest opcode form.
fn check_minimal_push(data: &[u8], opcode: u8) -> bool {
    if data.is_empty() {
        return opcode == 0x00;
    }
    if data.len() == 1 && data[0] >= 1 && data[0] <= 16 {
        return opcode == 0x50 + data[0];
    }
    if data.len() == 1 && data[0] == 0x81 {
        return opcode == 0x4f;
    }
    if data.len() <= 75 {
        return opcode as usize == data.len();
    }
    if data.len() <= 255 {
        return opcode == 0x4c;
    }
    if data.len() <= 65535 {
        return opcode == 0x4d;
    }
    true
}

/// Decode a script number with Core's general 4-byte limit (arithmetic).
fn scriptnum_decode(v: &[u8], require_minimal: bool) -> Result<i64, EvalError> {
    scriptnum_decode_width(v, 4, require_minimal)
}

/// Decode a script number with explicit max byte length.
/// CLTV/CSV use `max_len = 5` so full u32 locktime/sequence ranges encode as
/// positive script numbers (Core `CScriptNum(..., 5)`).
fn scriptnum_decode_width(
    v: &[u8],
    max_len: usize,
    require_minimal: bool,
) -> Result<i64, EvalError> {
    if v.len() > max_len {
        return Err(EvalError::Script("scriptnum overflow".into()));
    }
    if require_minimal && !scriptnum_is_minimal(v) {
        return Err(EvalError::Script("SCRIPTNUM".into()));
    }
    if v.is_empty() {
        return Ok(0);
    }
    let mut result: i64 = 0;
    for (i, &b) in v.iter().enumerate() {
        result |= (b as i64) << (8 * i);
    }
    if v.last().unwrap() & 0x80 != 0 {
        result &= !(0x80i64 << (8 * (v.len() - 1)));
        result = -result;
    }
    Ok(result)
}

/// Core `CScriptNum` fRequireMinimal encoding check.
fn scriptnum_is_minimal(vch: &[u8]) -> bool {
    if vch.is_empty() {
        return true;
    }
    // If the most-significant-byte (excluding sign bit) is zero, not minimal —
    // unless the second-most-significant-byte has the high bit set (±255 edge).
    if vch[vch.len() - 1] & 0x7f == 0 {
        if vch.len() <= 1 || (vch[vch.len() - 2] & 0x80) == 0 {
            return false;
        }
    }
    true
}

fn bin_arith(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> i64,
) -> Result<(), EvalError> {
    let b = scriptnum_decode(&pop(stack)?, require_minimal)?;
    let a = scriptnum_decode(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, scriptnum_encode(f(a, b)))
}

fn bin_cmp(
    stack: &mut Vec<Vec<u8>>,
    alt_len: usize,
    require_minimal: bool,
    f: impl Fn(i64, i64) -> bool,
) -> Result<(), EvalError> {
    let b = scriptnum_decode(&pop(stack)?, require_minimal)?;
    let a = scriptnum_decode(&pop(stack)?, require_minimal)?;
    push(stack, alt_len, bool_encode(f(a, b)))
}

/// Public native script verifier.
#[derive(Debug, Default, Clone, Copy)]
pub struct Interpreter;

impl Interpreter {
    /// Number of taproot inputs at which block validation uses the batch Schnorr path.
    pub const BATCH_SCHNORR_THRESHOLD: usize = 16;

    /// Executes a script spend using a one-element prevout view.
    pub fn execute(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevout: &PrimitiveTxOut,
        tx: &Transaction,
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

    /// Executes a spend with the complete ordered prevout set.
    pub fn execute_with_prevouts(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[&PrimitiveTxOut],
        tx: &Transaction,
        input_idx: usize,
    ) -> Result<(), ScriptError> {
        if tx.input.get(input_idx).is_none() {
            return Err(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs: tx.input.len(),
            });
        }
        let _ = select_prevout(prevouts, tx.input.len(), input_idx)?;
        let spending = graft_transaction_if_needed(tx, input_idx, script_sig, witness)?;
        let script = Script::from_bytes(script_pubkey);
        let class = classify::classify(script);
        let mut cache = SighashCache::new(&*spending);
        if class == ScriptClass::Taproot && flags.contains(VerifyFlags::TAPROOT) {
            let mut context = EvalContext::new(
                &spending,
                input_idx,
                select_prevout(prevouts, tx.input.len(), input_idx)?.value,
                prevouts,
                script,
                SigVersion::TapScript,
                flags,
                &mut cache,
            );
            return verify_taproot_keypath(&mut context, witness);
        }
        if matches!(
            class,
            ScriptClass::WitnessV0P2wpkh | ScriptClass::WitnessV0P2wsh
        ) {
            return Err(ScriptError::Verification(
                "segwit-v0 script execution is not enabled".to_owned(),
            ));
        }
        if matches!(class, ScriptClass::UnknownWitness) && flags.contains(VerifyFlags::WITNESS) {
            return Err(ScriptError::Verification(
                "unknown witness version".to_owned(),
            ));
        }
        verify_legacy_spend(
            script,
            Script::from_bytes(script_sig),
            witness,
            flags,
            prevouts,
            &spending,
            input_idx,
            &mut cache,
        )
    }

    /// Executes a transaction-owned spend while reusing its sighash cache.
    pub fn execute_with_prevouts_cached<'tx>(
        &self,
        script_pubkey: &[u8],
        script_sig: &[u8],
        witness: &[Vec<u8>],
        flags: VerifyFlags,
        prevouts: &[&PrimitiveTxOut],
        tx: &'tx Transaction,
        input_idx: usize,
        cache: &mut SighashCache<&'tx Transaction>,
    ) -> Result<(), ScriptError> {
        if cache.transaction() != tx {
            return Err(ScriptError::Verification(
                "cached execution received a different transaction".to_owned(),
            ));
        }
        let input = tx
            .input
            .get(input_idx)
            .ok_or(ScriptError::InputIndexOutOfRange {
                index: input_idx,
                inputs: tx.input.len(),
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
        let _ = select_prevout(prevouts, tx.input.len(), input_idx)?;
        let script = Script::from_bytes(script_pubkey);
        let class = classify::classify(script);
        if class == ScriptClass::Taproot && flags.contains(VerifyFlags::TAPROOT) {
            let mut context = EvalContext::new(
                tx,
                input_idx,
                select_prevout(prevouts, tx.input.len(), input_idx)?.value,
                prevouts,
                script,
                SigVersion::TapScript,
                flags,
                cache,
            );
            return verify_taproot_keypath(&mut context, witness);
        }
        if matches!(
            class,
            ScriptClass::WitnessV0P2wpkh | ScriptClass::WitnessV0P2wsh
        ) {
            return Err(ScriptError::Verification(
                "segwit-v0 script execution is not enabled".to_owned(),
            ));
        }
        verify_legacy_spend(
            script,
            Script::from_bytes(script_sig),
            witness,
            flags,
            prevouts,
            tx,
            input_idx,
            cache,
        )
    }
}

fn select_prevout<'a>(
    prevouts: &'a [&'a PrimitiveTxOut],
    inputs: usize,
    input_idx: usize,
) -> Result<&'a PrimitiveTxOut, ScriptError> {
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
    tx: &'a Transaction,
    input_idx: usize,
    script_sig: &[u8],
    witness: &[Vec<u8>],
) -> Result<Cow<'a, Transaction>, ScriptError> {
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

fn verify_legacy_spend<'tx, 'script, 'prevouts, 'cache>(
    script_pubkey: &'script Script,
    script_sig: &'script Script,
    witness: &[Vec<u8>],
    flags: VerifyFlags,
    prevouts: &'prevouts [&'prevouts PrimitiveTxOut],
    tx: &'tx Transaction,
    input_idx: usize,
    cache: &'cache mut SighashCache<&'tx Transaction>,
) -> Result<(), ScriptError> {
    if flags.contains(VerifyFlags::WITNESS) && !witness.is_empty() {
        return Err(ScriptError::Verification("unexpected witness".to_owned()));
    }
    let class = classify::classify(script_pubkey);
    if class == ScriptClass::P2sh && flags.contains(VerifyFlags::P2SH) {
        if !nested::is_push_only(script_sig) {
            return Err(ScriptError::Verification(
                "scriptSig not push-only".to_owned(),
            ));
        }
        if flags.contains(VerifyFlags::MINIMALDATA) && !script_pushes_minimal(script_sig) {
            return Err(ScriptError::Verification("MINIMALDATA".to_owned()));
        }
    } else if flags.contains(VerifyFlags::SIGPUSHONLY) && !nested::is_push_only(script_sig) {
        return Err(ScriptError::Verification(
            "scriptSig not push-only".to_owned(),
        ));
    }

    let mut stack = Vec::new();
    if class == ScriptClass::P2sh && flags.contains(VerifyFlags::P2SH) {
        eval_script_sig_pushes(script_sig, &mut stack).map_err(eval_error)?;
    } else {
        let script_sig_ctx = EvalContext::new(
            tx,
            input_idx,
            select_prevout(prevouts, tx.input.len(), input_idx)
                .map_err(|_| ScriptError::TaprootPrevoutsUnavailable)?
                .value,
            prevouts,
            script_sig,
            SigVersion::Base,
            flags,
            cache,
        );
        eval_script(script_sig, &mut stack, &script_sig_ctx).map_err(eval_error)?;
        drop(script_sig_ctx);
    }
    let p2sh_stack =
        (class == ScriptClass::P2sh && flags.contains(VerifyFlags::P2SH)).then(|| stack.clone());

    {
        let script_pubkey_ctx = EvalContext::new(
            tx,
            input_idx,
            select_prevout(prevouts, tx.input.len(), input_idx)
                .map_err(|_| ScriptError::TaprootPrevoutsUnavailable)?
                .value,
            prevouts,
            script_pubkey,
            SigVersion::Base,
            flags,
            cache,
        );
        eval_script(script_pubkey, &mut stack, &script_pubkey_ctx).map_err(eval_error)?;
    }
    require_true_top(&stack).map_err(eval_error)?;

    if class == ScriptClass::P2sh && flags.contains(VerifyFlags::P2SH) {
        stack =
            p2sh_stack.ok_or_else(|| ScriptError::Verification("missing P2SH stack".to_owned()))?;
        let redeem_bytes = stack
            .pop()
            .ok_or_else(|| ScriptError::Verification("missing redeem script".to_owned()))?;
        let redeem = ScriptBuf::from_bytes(redeem_bytes);
        {
            let redeem_ctx = EvalContext::new(
                tx,
                input_idx,
                select_prevout(prevouts, tx.input.len(), input_idx)
                    .map_err(|_| ScriptError::TaprootPrevoutsUnavailable)?
                    .value,
                prevouts,
                &redeem,
                SigVersion::Base,
                flags,
                cache,
            );
            eval_script(&redeem, &mut stack, &redeem_ctx).map_err(eval_error)?;
        }
    }

    if flags.contains(VerifyFlags::CLEANSTACK) {
        require_clean_true(&stack).map_err(eval_error)
    } else {
        require_true_top(&stack).map_err(eval_error)
    }
}

fn eval_error(error: EvalError) -> ScriptError {
    ScriptError::Verification(error.to_string())
}

fn script_pushes_minimal(script: &Script) -> bool {
    script.instructions().all(|item| match item {
        Ok(Instruction::PushBytes(data)) => {
            let len = data.len();
            let opcode = script.as_bytes().get(0).copied().unwrap_or_default();
            let _ = opcode;
            // Re-parse by byte position below; this branch only rejects malformed scripts.
            len <= MAX_SCRIPT_ELEMENT_SIZE
        }
        Ok(Instruction::Op(op)) => {
            let code = op.to_u8();
            code == 0x00 || code == 0x4f || (0x51..=0x60).contains(&code) || code >= 0x61
        }
        Err(_) => false,
    }) && minimal_push_bytes(script.as_bytes())
}

fn minimal_push_bytes(bytes: &[u8]) -> bool {
    let mut i = 0usize;
    while i < bytes.len() {
        let op = bytes[i];
        i += 1;
        let len = if op == 0 {
            0
        } else if (1..=75).contains(&op) {
            op as usize
        } else if op == 0x4c {
            if i >= bytes.len() {
                return false;
            }
            let n = bytes[i] as usize;
            if n < 76 {
                return false;
            }
            i += 1;
            n
        } else if op == 0x4d {
            if i + 1 >= bytes.len() {
                return false;
            }
            let n = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
            if n <= 0xff {
                return false;
            }
            i += 2;
            n
        } else if op == 0x4e {
            if i + 3 >= bytes.len() {
                return false;
            }
            let n =
                u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]]) as usize;
            if n <= 0xffff {
                return false;
            }
            i += 4;
            n
        } else {
            0
        };
        if op == 0x00 || op == 0x4f || (0x51..=0x60).contains(&op) {
            // These are minimal only when they are not encoding a byte vector.
        }
        if i + len > bytes.len() {
            return false;
        }
        if (1..=75).contains(&op) && len == 1 {
            let value = bytes[i];
            if value == 0 || value == 0x81 || (1..=16).contains(&value) {
                return false;
            }
        }
        i += len;
    }
    true
}

fn verify_taproot_keypath(
    context: &mut EvalContext<'_, '_, '_, '_>,
    witness: &[Vec<u8>],
) -> Result<(), ScriptError> {
    if context.prevouts.len() != context.tx.input.len() {
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
    let key_bytes = context.script_code.as_bytes();
    if key_bytes.len() < 34 {
        return Err(ScriptError::Verification(
            "invalid taproot output key".to_owned(),
        ));
    }
    let public_key = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&key_bytes[2..34])
        .map_err(|error| ScriptError::Verification(error.to_string()))?;
    let input_index = context.input_index;
    let prevouts = context.prevouts;
    let sighash = context
        .cache
        .borrow_mut()
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
    use bitcoin::hashes::{Hash as _, hash160};
    use bitcoin::script::Builder;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };

    use super::{Interpreter, ScriptError, VerifyFlags};
    use bitcoin_rs_primitives::TxOut as PrimitiveTxOut;

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

    fn prevout(script: ScriptBuf) -> PrimitiveTxOut {
        PrimitiveTxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: script,
        }
    }

    #[test]
    fn op_true_and_stack_boolean_rules_are_native() {
        let tx = unsigned_spend();
        let out = prevout(ScriptBuf::from_bytes(vec![0x51]));
        assert_eq!(
            Interpreter.execute(
                out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &out,
                &tx,
                0
            ),
            Ok(())
        );
        let false_out = prevout(ScriptBuf::from_bytes(vec![0x00]));
        assert!(matches!(
            Interpreter.execute(
                false_out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &false_out,
                &tx,
                0
            ),
            Err(ScriptError::Verification(_))
        ));
    }

    #[test]
    fn arithmetic_control_flow_and_negative_zero_follow_core_rules() {
        let tx = unsigned_spend();
        let script = Builder::new()
            .push_int(2)
            .push_int(3)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .push_int(5)
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let out = prevout(script);
        assert_eq!(
            Interpreter.execute(
                out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &out,
                &tx,
                0
            ),
            Ok(())
        );

        let negative_zero = prevout(ScriptBuf::from_bytes(vec![
            1,
            0x80,
            bitcoin::opcodes::all::OP_NOT.to_u8(),
        ]));
        assert_eq!(
            Interpreter.execute(
                negative_zero.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &negative_zero,
                &tx,
                0
            ),
            Ok(())
        );
    }

    #[test]
    fn disabled_opcodes_and_nonminimal_numbers_fail_when_required() {
        let tx = unsigned_spend();
        let disabled = prevout(ScriptBuf::from_bytes(vec![
            bitcoin::opcodes::all::OP_CAT.to_u8(),
        ]));
        assert!(
            Interpreter
                .execute(
                    disabled.script_pubkey.as_bytes(),
                    &[],
                    &[],
                    VerifyFlags::MANDATORY,
                    &disabled,
                    &tx,
                    0
                )
                .is_err()
        );
        let nonminimal = prevout(ScriptBuf::from_bytes(vec![
            1,
            1,
            bitcoin::opcodes::all::OP_PUSHNUM_1.to_u8(),
            bitcoin::opcodes::all::OP_EQUAL.to_u8(),
        ]));
        assert!(
            Interpreter
                .execute(
                    nonminimal.script_pubkey.as_bytes(),
                    &[],
                    &[],
                    VerifyFlags::MINIMALDATA,
                    &nonminimal,
                    &tx,
                    0
                )
                .is_err()
        );
    }

    #[test]
    fn p2sh_executes_only_a_push_only_script_sig_and_redeem_script() {
        let tx = unsigned_spend();
        let redeem = ScriptBuf::from_bytes(vec![bitcoin::opcodes::all::OP_PUSHNUM_1.to_u8()]);
        let hash = hash160::Hash::hash(redeem.as_bytes());
        let p2sh = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_HASH160)
            .push_slice(hash.as_byte_array())
            .push_opcode(bitcoin::opcodes::all::OP_EQUAL)
            .into_script();
        let script_sig =
            ScriptBuf::from_bytes(vec![1, bitcoin::opcodes::all::OP_PUSHNUM_1.to_u8()]);
        let out = prevout(p2sh);
        assert_eq!(
            Interpreter.execute(
                out.script_pubkey.as_bytes(),
                script_sig.as_bytes(),
                &[],
                VerifyFlags::P2SH,
                &out,
                &tx,
                0
            ),
            Ok(())
        );
        let bad_sig = Builder::new()
            .push_int(1)
            .push_opcode(bitcoin::opcodes::all::OP_ADD)
            .into_script();
        assert!(
            Interpreter
                .execute(
                    out.script_pubkey.as_bytes(),
                    bad_sig.as_bytes(),
                    &[],
                    VerifyFlags::P2SH,
                    &out,
                    &tx,
                    0
                )
                .is_err()
        );
    }

    #[test]
    fn cltv_csv_and_discouraged_nops_are_flag_gated() {
        let mut tx = unsigned_spend();
        tx.lock_time = absolute::LockTime::from_consensus(10);
        tx.input[0].sequence = Sequence::from_consensus(5);
        let cltv = Builder::new()
            .push_int(10)
            .push_opcode(bitcoin::opcodes::all::OP_CLTV)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_int(1)
            .into_script();
        let out = prevout(cltv);
        assert_eq!(
            Interpreter.execute(
                out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::CHECKLOCKTIMEVERIFY,
                &out,
                &tx,
                0,
            ),
            Ok(())
        );

        tx.version = transaction::Version::TWO;
        let csv = Builder::new()
            .push_int(5)
            .push_opcode(bitcoin::opcodes::all::OP_CSV)
            .push_opcode(bitcoin::opcodes::all::OP_DROP)
            .push_int(1)
            .into_script();
        let out = prevout(csv);
        assert_eq!(
            Interpreter.execute(
                out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::CHECKSEQUENCEVERIFY,
                &out,
                &tx,
                0,
            ),
            Ok(())
        );

        let nop = prevout(ScriptBuf::from_bytes(vec![
            bitcoin::opcodes::all::OP_NOP1.to_u8(),
            bitcoin::opcodes::all::OP_PUSHNUM_1.to_u8(),
        ]));
        assert!(
            Interpreter
                .execute(
                    nop.script_pubkey.as_bytes(),
                    &[],
                    &[],
                    VerifyFlags::DISCOURAGE_UPGRADABLE_NOPS,
                    &nop,
                    &tx,
                    0,
                )
                .is_err()
        );
    }

    #[test]
    fn input_index_is_checked_before_prevout_selection() {
        let tx = unsigned_spend();
        let out = prevout(ScriptBuf::from_bytes(vec![0x51]));
        assert!(matches!(
            Interpreter.execute_with_prevouts(
                out.script_pubkey.as_bytes(),
                &[],
                &[],
                VerifyFlags::MANDATORY,
                &[&out],
                &tx,
                1
            ),
            Err(ScriptError::InputIndexOutOfRange {
                index: 1,
                inputs: 1
            })
        ));
    }
}
