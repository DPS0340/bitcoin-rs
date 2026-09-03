//! `UtxoView` adapter over the in-memory `UtxoSet`.
//!
//! Answers native `bitcoin_rs_primitives::OutPoint` lookups (the consensus
//! crate's contract) directly against the UTXO crate's internal layout. Used by
//! `NodeState::apply_block` to run per-tx script verification against the
//! committed UTXO set.

use std::sync::Arc;

use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_utxo::UtxoSet;

/// Thin lookup adapter around a shared `UtxoSet` handle.
pub struct UtxoSetView {
    set: Arc<UtxoSet>,
}

impl UtxoSetView {
    /// Constructs a view that borrows `set` for the lifetime of the view.
    #[must_use]
    pub const fn new(set: Arc<UtxoSet>) -> Self {
        Self { set }
    }
}

impl UtxoView for UtxoSetView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<bitcoin_rs_primitives::TxOut> {
        self.set.get(outpoint)
    }
}
