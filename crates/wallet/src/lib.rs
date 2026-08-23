#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

//! Watch-only wallet primitives.
//!
//! # Safety note: no private keys
//!
//! This crate is intentionally watch-only. It parses public descriptors, builds
//! unsigned PSBTs, accepts PSBTs returned by external signers, and finalizes
//! those PSBTs. It does not expose, accept, store, derive, or sign with private
//! key material anywhere in its public API.

/// Coin selection wrappers.
pub mod coin_selection;
/// Output descriptor support.
pub mod descriptor;
/// Replace-by-fee helpers.
pub mod fee_bump;
/// Signed PSBT finalization.
pub mod finalize;
/// PSBT construction.
pub mod psbt;
/// External signer interface.
pub mod signer_iface;
/// Descriptor watcher.
pub mod watcher;

pub use coin_selection::{Candidate, SelectStrategy, Selection, Target, select_coins};
pub use descriptor::{BIP32Derivation, Descriptor, DescriptorInfo, analyse, derive_addresses};
pub use fee_bump::{FeeBumpPlan, bump_fee, bump_psbt, bump_psbt_with_rate_sat_per_kvb};
pub use finalize::{FinalizeError, finalize_signed};
pub use psbt::{PrevUtxo, PsbtBuilder};
pub use signer_iface::{ExternalSigner, SignerError};
pub use watcher::Watcher;

use thiserror::Error;

/// Wallet crate error.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Descriptor parsing or derivation failed.
    #[error("descriptor error: {0}")]
    Descriptor(String),
    /// The derivation range does not match the descriptor.
    ///
    /// Separate from [`WalletError::Descriptor`] because the descriptor is
    /// fine: the caller asked for the wrong thing about it. Bitcoin Core
    /// answers the two with different RPC error codes for the same reason.
    #[error("{0}")]
    DescriptorRange(&'static str),
    /// PSBT construction failed.
    #[error("psbt error: {0}")]
    Psbt(String),
    /// Coin selection could not fund the target.
    #[error("insufficient funds: missing {missing} sats")]
    InsufficientFunds {
        /// Missing amount in satoshis.
        missing: u64,
    },
    /// No branch-and-bound solution was found before the round limit.
    #[error("no branch-and-bound solution after {rounds} of {max_rounds} rounds")]
    NoBnbSolution {
        /// Rounds completed.
        rounds: usize,
        /// Configured maximum rounds.
        max_rounds: usize,
    },
    /// The transaction is not known to this watch-only wallet state.
    #[error("transaction {txid} is not available for fee bumping")]
    MissingTransaction {
        /// Missing transaction id.
        txid: bitcoin::Txid,
    },
    /// The requested replacement does not satisfy BIP125 rules.
    #[error("replacement violates BIP125: {0}")]
    Bip125(String),
    /// Finalization failed.
    #[error(transparent)]
    Finalize(#[from] FinalizeError),
}
