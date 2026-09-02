//! Script verification, sigop counting, and native script utilities.
//!
//! ## V1 implementation note
//!
//! The interpreter executes taproot key-path spends natively (local BIP341
//! Schnorr verification); the remaining spend classes are served by the
//! verification backend wired into the consensus crate. The hand-rolled
//! per-opcode dispatcher from PLAN.md Task 3 Step 2 stays a follow-up: when
//! introduced, it lives behind a `hand-rolled` cargo feature and is gated by
//! a parity test. Public surface is stable across the swap.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Rayon-backed Schnorr verification helpers.
pub mod batch;
/// Transaction signature checker: ECDSA, Schnorr, locktime, and sequence verification.
pub mod checker;
/// Script verification wrapper.
pub mod interpreter;
/// Native script parsing, classification, and building helpers.
pub mod script;
/// Signature operation counters.
pub mod sigops;
/// Bounded stack infrastructure for the future hand-rolled interpreter.
pub mod stack;
/// Taproot verification helpers.
pub mod taproot;

pub use interpreter::{Interpreter, ScriptErrCode, ScriptError, VerifyFlags};
pub use script::{
    EarlyEndOfScript, Instruction, Instructions, is_multisig, is_op_return, is_p2a, is_p2pk,
    is_p2pkh, is_p2sh, is_p2tr, is_p2wpkh, is_p2wsh, is_push_only, is_witness_program,
    minimal_non_dust, opcode, p2pk_pubkey_bytes, push_data, push_int, witness_program,
};
pub use sigops::{count_block, count_legacy, count_segwit, count_taproot, count_tx_legacy};
pub use stack::{ScriptItem, Stack, StackError};
