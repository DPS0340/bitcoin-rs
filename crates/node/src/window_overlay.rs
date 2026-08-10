//! Prevout lookups for a window of consecutive blocks, before any of them commit.
//!
//! Preparing several blocks at once needs each block to see the outputs its
//! predecessors in the window created, without any of them having touched the
//! committed UTXO set. This module supplies exactly that view and nothing else:
//! it answers lookups and it is advanced one block at a time.

use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_utxo::{UtxoSet, shard::LiveOutput};
use hashbrown::HashMap;

/// Where a block's prevouts are read from.
///
/// One implementation is the committed set, used by every apply today. The
/// other is [`WindowOverlay`], which answers for blocks that have been prepared
/// but not yet committed.
pub(crate) trait OutputSource {
    /// The live output an outpoint refers to, or `None` if it is unspendable
    /// from this view.
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput>;
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput> {
        Self::get_entry(self, outpoint)
    }
}

/// The committed UTXO set plus the net effect of window blocks already prepared.
///
/// Entries are tombstoned rather than removed. A window block can spend an
/// outpoint and a later one recreate it, and two separate sets would answer
/// that sequence wrongly whichever order they were consulted in.
pub(crate) struct WindowOverlay<'u> {
    base: &'u UtxoSet,
    /// `Some` for created and still live, `None` for spent. Absent means "ask
    /// the committed set".
    changed: HashMap<OutPoint, Option<LiveOutput>>,
}

impl<'u> WindowOverlay<'u> {
    pub(crate) fn new(base: &'u UtxoSet) -> Self {
        Self {
            base,
            changed: HashMap::new(),
        }
    }

    /// Folds one block's net effect into the view.
    ///
    /// `same_block_spent` holds outpoints a block both creates and spends. They
    /// are skipped on both sides, exactly as `build_utxo_changes` skips them,
    /// because such an output never reaches the committed set and a view that
    /// disagreed would resolve, or refuse, a later spend the real set would not.
    ///
    /// Genesis is a no-op for the same reason it is in the apply path: Bitcoin
    /// Core indexes it but never connects its coinbase, so it is absent from
    /// UTXO state.
    ///
    /// `same_block_spent` is required rather than optional, and empty is the
    /// way to say a block has none. An `Option` would let a caller turn the
    /// netting off by forgetting it, and the failure would be silent: the view
    /// would carry outputs the committed set never holds.
    ///
    /// # Errors
    ///
    /// Refuses a `txids` slice that does not cover every transaction. Zipping
    /// the two would drop the trailing transactions instead, leaving their
    /// creations invisible and their spends unrecorded.
    pub(crate) fn advance(
        &mut self,
        block: &bitcoin::Block,
        txids: &[bitcoin::Txid],
        height: u32,
        same_block_spent: &hashbrown::HashSet<OutPoint>,
    ) -> Result<(), WindowOverlayError> {
        use bitcoin::hashes::Hash as _;

        if block.txdata.len() != txids.len() {
            return Err(WindowOverlayError::TxidCountMismatch {
                transactions: block.txdata.len(),
                txids: txids.len(),
            });
        }
        if height == 0 {
            return Ok(());
        }
        for (tx, txid) in block.txdata.iter().zip(txids) {
            let txid = bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array());
            let coinbase = tx.is_coinbase();
            for (vout, txout) in tx.output.iter().enumerate() {
                // An OP_RETURN or oversized script is provably unspendable and
                // never enters the committed set, so it must not enter this one.
                if txout.script_pubkey.is_op_return()
                    || txout.script_pubkey.len() > bitcoin_rs_consensus::MAX_SCRIPT_SIZE
                {
                    continue;
                }
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                let outpoint = OutPoint::new(txid, vout);
                if same_block_spent.contains(&outpoint) {
                    continue;
                }
                self.changed.insert(
                    outpoint,
                    Some(LiveOutput {
                        txout: txout.clone(),
                        coinbase,
                        height,
                    }),
                );
            }
            if coinbase {
                continue;
            }
            for input in &tx.input {
                let spent = internal_outpoint(&input.previous_output);
                if same_block_spent.contains(&spent) {
                    continue;
                }
                self.changed.insert(spent, None);
            }
        }
        Ok(())
    }
}

/// Why the view refused to fold in a block.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum WindowOverlayError {
    /// The caller's txid list does not cover the block's transactions.
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch {
        /// Transactions in the block.
        transactions: usize,
        /// Txids the caller supplied.
        txids: usize,
    },
}

impl OutputSource for WindowOverlay<'_> {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<LiveOutput> {
        match self.changed.get(outpoint) {
            Some(entry) => entry.clone(),
            None => self.base.get_entry(outpoint),
        }
    }
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    use bitcoin::hashes::Hash as _;

    OutPoint::new(
        bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness, absolute::LockTime,
        hashes::Hash as _, opcodes::all::OP_RETURN, script::Builder, transaction::Version,
    };
    use bitcoin_rs_utxo::{UndoBatch, UtxoAdd, UtxoSet};

    use super::{OutputSource, WindowOverlay, internal_outpoint};

    fn none() -> hashbrown::HashSet<bitcoin_rs_primitives::OutPoint> {
        hashbrown::HashSet::new()
    }

    const HEIGHT: u32 = 7;

    #[test]
    fn an_output_created_by_a_window_block_becomes_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let tx = paying_tx(op_true(), 500);
        let txid = tx.compute_txid();
        let block = block_of(vec![tx]);

        assert!(
            overlay
                .get_entry(&internal_outpoint(&outpoint_of(txid, 0)))
                .is_none(),
            "nothing may resolve before the block is folded in"
        );
        overlay.advance(&block, &[txid], HEIGHT, &none())?;

        let found = overlay.get_entry(&internal_outpoint(&outpoint_of(txid, 0)));
        assert_eq!(
            found.map(|entry| (entry.height, entry.coinbase, entry.txout.value.to_sat())),
            Some((HEIGHT, true, 500)),
            "the created output must carry the height and coinbase flag the committed set would record"
        );
        Ok(())
    }

    #[test]
    fn a_spend_tombstones_the_outpoint_rather_than_falling_through()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let funded = outpoint_of(txid_of(0x31), 0);
        seed(&utxo, funded, 900)?;
        let mut overlay = WindowOverlay::new(&utxo);
        assert!(
            overlay.get_entry(&internal_outpoint(&funded)).is_some(),
            "the committed output must be visible before the spend"
        );

        let spend = spending_tx(funded);
        let txid = spend.compute_txid();
        overlay.advance(
            &block_of(vec![coinbase(), spend]),
            &[txid_of(1), txid],
            HEIGHT,
            &none(),
        )?;

        assert!(
            overlay.get_entry(&internal_outpoint(&funded)).is_none(),
            "a spent outpoint must not fall through to the committed set"
        );
        Ok(())
    }

    #[test]
    fn an_outpoint_recreated_after_being_spent_is_live_again()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let tx = paying_tx(op_true(), 100);
        let txid = tx.compute_txid();
        let created = outpoint_of(txid, 0);

        overlay.advance(&block_of(vec![tx.clone()]), &[txid], HEIGHT, &none())?;
        let spend = spending_tx(created);
        let spend_txid = spend.compute_txid();
        overlay.advance(
            &block_of(vec![coinbase(), spend]),
            &[txid_of(2), spend_txid],
            HEIGHT + 1,
            &none(),
        )?;
        assert!(
            overlay.get_entry(&internal_outpoint(&created)).is_none(),
            "the spend must tombstone it"
        );

        // Recreated by a later window block: the tombstone must not win.
        overlay.advance(&block_of(vec![tx]), &[txid], HEIGHT + 2, &none())?;

        assert_eq!(
            overlay
                .get_entry(&internal_outpoint(&created))
                .map(|entry| entry.height),
            Some(HEIGHT + 2),
            "a recreated outpoint must be live again at its new height"
        );
        Ok(())
    }

    #[test]
    fn unspendable_outputs_never_enter_the_view() -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let script = Builder::new().push_opcode(OP_RETURN).into_script();
        let tx = paying_tx(script, 0);
        let txid = tx.compute_txid();

        overlay.advance(&block_of(vec![tx]), &[txid], HEIGHT, &none())?;

        assert!(
            overlay
                .get_entry(&internal_outpoint(&outpoint_of(txid, 0)))
                .is_none(),
            "an OP_RETURN output never reaches the committed set, so it must not reach this one"
        );
        Ok(())
    }

    #[test]
    fn script_size_boundary_matches_the_committed_utxo_set()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let accepted = paying_tx(
            ScriptBuf::from_bytes(vec![0x51; bitcoin_rs_consensus::MAX_SCRIPT_SIZE]),
            1,
        );
        let rejected = paying_tx(
            ScriptBuf::from_bytes(vec![0x51; bitcoin_rs_consensus::MAX_SCRIPT_SIZE + 1]),
            1,
        );
        let accepted_txid = accepted.compute_txid();
        let rejected_txid = rejected.compute_txid();

        overlay.advance(&block_of(vec![accepted]), &[accepted_txid], HEIGHT, &none())?;
        overlay.advance(
            &block_of(vec![rejected]),
            &[rejected_txid],
            HEIGHT + 1,
            &none(),
        )?;

        assert!(
            overlay
                .get_entry(&internal_outpoint(&outpoint_of(accepted_txid, 0)))
                .is_some(),
            "MAX_SCRIPT_SIZE must remain spendable"
        );
        assert!(
            overlay
                .get_entry(&internal_outpoint(&outpoint_of(rejected_txid, 0)))
                .is_none(),
            "MAX_SCRIPT_SIZE + 1 must remain absent"
        );
        Ok(())
    }

    #[test]
    fn genesis_contributes_nothing() -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let tx = paying_tx(op_true(), 5_000_000_000);
        let txid = tx.compute_txid();

        overlay.advance(&block_of(vec![tx]), &[txid], 0, &none())?;

        assert!(
            overlay
                .get_entry(&internal_outpoint(&outpoint_of(txid, 0)))
                .is_none(),
            "Core indexes genesis but never connects its coinbase"
        );
        Ok(())
    }

    /// Zipping a short txid list would drop the trailing transactions and leave
    /// their creations invisible and their spends unrecorded, which is a
    /// silently wrong view rather than a failure.
    #[test]
    fn a_txid_list_that_misses_transactions_is_refused() {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let block = block_of(vec![coinbase(), spending_tx(outpoint_of(txid_of(5), 0))]);

        let outcome = overlay.advance(&block, &[txid_of(6)], HEIGHT, &none());

        assert_eq!(
            outcome,
            Err(super::WindowOverlayError::TxidCountMismatch {
                transactions: 2,
                txids: 1,
            })
        );
        assert!(
            overlay.changed.is_empty(),
            "a refused block must leave the view untouched"
        );
    }

    #[test]
    fn an_output_created_and_spent_in_one_block_is_skipped_on_both_sides()
    -> Result<(), Box<dyn std::error::Error>> {
        let utxo = UtxoSet::new();
        let mut overlay = WindowOverlay::new(&utxo);
        let tx = paying_tx(op_true(), 400);
        let txid = tx.compute_txid();
        let created = outpoint_of(txid, 0);
        let spend = spending_tx(created);
        let spend_txid = spend.compute_txid();
        let mut same_block = hashbrown::HashSet::new();
        same_block.insert(internal_outpoint(&created));

        overlay.advance(
            &block_of(vec![tx, spend]),
            &[txid, spend_txid],
            HEIGHT,
            &same_block,
        )?;

        assert!(
            !overlay.changed.contains_key(&internal_outpoint(&created)),
            "an output created and spent in one block never reaches the committed set, \
             so the view must record neither the creation nor the spend"
        );
        Ok(())
    }

    type UtxoError = bitcoin_rs_utxo::UtxoError;

    fn seed(utxo: &UtxoSet, outpoint: bitcoin::OutPoint, value: u64) -> Result<(), UtxoError> {
        let mut batch = UndoBatch::default();
        batch.restore(UtxoAdd::new(
            internal_outpoint(&outpoint),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: op_true(),
            },
            false,
            1,
        ));
        utxo.undo_block(&batch)
    }

    fn op_true() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn txid_of(byte: u8) -> bitcoin::Txid {
        bitcoin::Txid::from_byte_array([byte; 32])
    }

    fn outpoint_of(txid: bitcoin::Txid, vout: u32) -> bitcoin::OutPoint {
        bitcoin::OutPoint { txid, vout }
    }

    fn coinbase() -> Transaction {
        Transaction {
            version: Version::ONE,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x00, 0x01]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true(),
            }],
        }
    }

    /// A coinbase paying one output, so `advance` sees a creation.
    fn paying_tx(script_pubkey: ScriptBuf, value: u64) -> Transaction {
        let mut tx = coinbase();
        tx.output = vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey,
        }];
        tx
    }

    fn spending_tx(previous_output: bitcoin::OutPoint) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: op_true(),
            }],
        }
    }

    fn block_of(txdata: Vec<Transaction>) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::from_byte_array([0; 32]),
                merkle_root: bitcoin::TxMerkleNode::from_byte_array([0; 32]),
                time: 0,
                bits: bitcoin::CompactTarget::from_consensus(0x2100_ffff),
                nonce: 0,
            },
            txdata,
        }
    }
}
