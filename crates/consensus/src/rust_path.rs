use bitcoin_rs_primitives::{OutPoint, TxOut};

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
