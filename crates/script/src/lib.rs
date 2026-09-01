//! Script verification, sigop counting, and sighash caching.
//!
//! ## V1 implementation note
//!
//! Per-script execution delegates to `bitcoin::Script::verify_with_flags`
//! (Core's canonical Rust port, audited). The hand-rolled per-opcode dispatcher
//! from PLAN.md Task 3 Step 2 is a follow-up: when introduced, it lives behind
//! a `hand-rolled` cargo feature and is gated by a parity-vs-bitcoin-crate test.
//! Public surface is stable across the swap.

#![forbid(unsafe_op_in_unsafe_fn)]

/// Script verification wrapper.
pub mod interpreter;
/// Opcode re-exports and local opcode newtype.
pub mod opcodes;
/// Signature hash cache wrapper.
pub mod sighash_cache;
/// Signature operation counters.
pub mod sigops;
pub use interpreter::{Interpreter, ScriptError, VerifyFlags};

/// Borrowed script type from the `bitcoin` crate.
pub type Script = bitcoin::Script;
/// Owned script buffer from the `bitcoin` crate.
pub type ScriptBuf = bitcoin::ScriptBuf;
/// Project transaction wrapper.
pub type Tx = bitcoin_rs_primitives::Tx;
/// Canonical transaction output type.
pub type TxOut = bitcoin_rs_primitives::TxOut;
