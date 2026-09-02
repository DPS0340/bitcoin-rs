//! Script verification, sigop counting, and sighash caching.

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
