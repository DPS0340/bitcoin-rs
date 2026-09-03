use bitcoin_rs_primitives::{BlockHash, OutPoint, TxOut};

/// Minimal UTXO lookup contract used by the portable validator.
pub trait UtxoView {
    /// Looks up a previous output by outpoint.
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut>;
}

impl<T> UtxoView for &T
where
    T: UtxoView + ?Sized,
{
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        (*self).lookup(outpoint)
    }
}

/// Previous-tip state needed for contextual block connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TipState {
    /// Previous block height, or `None` before genesis.
    pub height: Option<u32>,
    /// Previous block hash, when known.
    pub block_hash: Option<BlockHash>,
    /// Median-time-past of the previous tip.
    pub median_time_past: u32,
}

impl TipState {
    /// Returns the height of the next block being connected.
    #[must_use]
    pub const fn next_height(&self) -> u32 {
        match self.height {
            Some(height) => height.saturating_add(1),
            None => 0,
        }
    }
}
