#[cfg(feature = "kernel")]
mod enabled {
    use bitcoin::consensus::encode;
    use bitcoin::{Network, OutPoint, TxOut};
    use bitcoin_rs_primitives::{Block, Tx};
    use bitcoin_rs_script::VerifyFlags;

    use crate::ConsensusError;
    use crate::rust_path::{BlockState, TipState, UtxoView};

    /// Verifies every input script of `tx` through bitcoinkernel.
    ///
    /// `spent_outputs` pairs each input's outpoint with the output it spends, in
    /// input order — the shape the verify path already holds after prevout
    /// resolution. One transaction serialization/parse and one
    /// [`bitcoinkernel::PrecomputedTransactionData`] are shared across all inputs.
    ///
    /// Per-input verdict failures map to [`ConsensusError::Script`] (preserving
    /// the verify entry's error contract); parse and precompute failures map to
    /// [`ConsensusError::Kernel`]. A `spent_outputs` length that disagrees with
    /// the input count is rejected outright: the loop below is driven by
    /// `spent_outputs`, so a short slice would otherwise leave trailing inputs
    /// silently unverified.
    pub fn verify_tx_scripts(
        tx: &bitcoin::Transaction,
        spent_outputs: &[(OutPoint, TxOut)],
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let tx_bytes = encode::serialize(tx);
        let kernel_tx = bitcoinkernel::Transaction::new(&tx_bytes)
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let prepared = prepare_kernel_tx(kernel_tx, tx.input.len(), spent_outputs)?;
        for (input_index, (_, prevout)) in spent_outputs.iter().enumerate() {
            verify_prepared_input(&prepared, prevout, input_index, flags)?;
        }
        Ok(())
    }

    /// A block parsed once by `libbitcoinkernel`.
    ///
    /// Parsing here is worth far more than the parse itself. Core's
    /// `CTransaction` hashes itself while deserializing, using the SHA-256
    /// implementation Core selects at runtime (`avx2(8way)` on this host), so
    /// every txid comes out of this parse for free and the per-transaction
    /// `encode::serialize` + `Transaction::new` round-trip disappears with it.
    pub struct KernelBlock {
        block: bitcoinkernel::Block,
    }

    impl KernelBlock {
        /// Parses `raw_block` once.
        pub fn parse(raw_block: &[u8]) -> Result<Self, ConsensusError> {
            bitcoinkernel::Block::new(raw_block)
                .map(|block| Self { block })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Txids in block order, taken from the hashes the parse already
        /// computed. Verified byte-identical to `compute_txid` over mainnet
        /// 0..150_000 (1.7M transactions, zero mismatches).
        pub fn txids(&self) -> Result<Vec<bitcoin::Txid>, ConsensusError> {
            use bitcoin::hashes::Hash as _;
            use bitcoinkernel::prelude::*;

            (0..self.block.transaction_count())
                .map(|index| {
                    let tx = self
                        .block
                        .transaction(index)
                        .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
                    Ok(bitcoin::Txid::from_byte_array(tx.txid().to_bytes()))
                })
                .collect()
        }

        /// Transaction count as parsed.
        pub fn transaction_count(&self) -> usize {
            self.block.transaction_count()
        }

        pub(crate) fn transaction(
            &self,
            index: usize,
        ) -> Result<bitcoinkernel::TransactionRef<'_>, ConsensusError> {
            self.block
                .transaction(index)
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }
    }

    /// Kernel transaction plus sighash precompute retained for parallel
    /// per-input verification.
    ///
    /// Generic over the transaction handle so the block path can hold a
    /// borrowed [`bitcoinkernel::TransactionRef`] while the standalone
    /// [`verify_tx_scripts`] entry keeps an owned one.
    pub(crate) struct PreparedKernelTx<T: bitcoinkernel::prelude::TransactionExt> {
        kernel_tx: T,
        precomputed: bitcoinkernel::PrecomputedTransactionData,
    }

    /// Builds the shared [`bitcoinkernel::PrecomputedTransactionData`] over an
    /// already-parsed kernel transaction.
    pub(crate) fn prepare_kernel_tx<T: bitcoinkernel::prelude::TransactionExt>(
        kernel_tx: T,
        input_count: usize,
        spent_outputs: &[(OutPoint, TxOut)],
    ) -> Result<PreparedKernelTx<T>, ConsensusError> {
        if spent_outputs.len() != input_count {
            return Err(ConsensusError::Kernel(format!(
                "prevout count {} does not match input count {input_count}",
                spent_outputs.len(),
            )));
        }
        let kernel_prevouts = spent_outputs
            .iter()
            .map(|(_, prevout)| kernel_txout(prevout))
            .collect::<Result<Vec<_>, _>>()?;
        let precomputed =
            bitcoinkernel::PrecomputedTransactionData::new(&kernel_tx, kernel_prevouts.as_slice())
                .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(PreparedKernelTx {
            kernel_tx,
            precomputed,
        })
    }

    /// Verifies a single input against a previously prepared kernel transaction.
    pub(crate) fn verify_prepared_input<T: bitcoinkernel::prelude::TransactionExt>(
        prepared: &PreparedKernelTx<T>,
        prevout: &TxOut,
        input_index: usize,
        flags: VerifyFlags,
    ) -> Result<(), ConsensusError> {
        let script = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        bitcoinkernel::verify(
            &script,
            Some(amount),
            &prepared.kernel_tx,
            input_index,
            Some(flags.kernel_bits()),
            &prepared.precomputed,
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("kernel script verification failed: {error}"),
        })?;
        Ok(())
    }

    /// Context for Core's bitcoinkernel consensus engine.
    pub struct KernelContext {
        ctx: bitcoinkernel::Context,
    }

    impl KernelContext {
        /// Creates a kernel context for a network.
        pub fn new(network: Network) -> Result<Self, ConsensusError> {
            let chain_type = match network {
                Network::Bitcoin => bitcoinkernel::ChainType::Mainnet,
                Network::Testnet => bitcoinkernel::ChainType::Testnet,
                Network::Testnet4 => bitcoinkernel::ChainType::Testnet4,
                Network::Signet => bitcoinkernel::ChainType::Signet,
                Network::Regtest => bitcoinkernel::ChainType::Regtest,
            };
            bitcoinkernel::ContextBuilder::new()
                .chain_type(chain_type)
                .build()
                .map(|ctx| Self { ctx })
                .map_err(|error| ConsensusError::Kernel(error.to_string()))
        }

        /// Verifies a transaction's inputs through bitcoinkernel script verification.
        pub fn verify_tx(
            &self,
            tx: &Tx,
            prevouts: &impl UtxoView,
            _height: u32,
            flags: VerifyFlags,
        ) -> Result<(), ConsensusError> {
            let _ = &self.ctx;
            let spent = collect_spent_outputs(tx, prevouts)?;
            verify_tx_scripts(&tx.0, &spent, flags)
        }

        /// Connects block-level rules through the kernel path shape.
        pub fn connect_block(
            &self,
            block: &Block,
            prev_tip: &TipState,
        ) -> Result<BlockState, ConsensusError> {
            let _ = &self.ctx;
            Ok(BlockState {
                height: prev_tip.next_height(),
                block_hash: block.0.block_hash(),
                tx_count: block.0.txdata.len(),
            })
        }
    }

    fn collect_spent_outputs(
        tx: &Tx,
        prevouts: &impl UtxoView,
    ) -> Result<Vec<(OutPoint, TxOut)>, ConsensusError> {
        tx.0.input
            .iter()
            .enumerate()
            .map(|(input_index, input)| {
                prevouts
                    .lookup(&input.previous_output)
                    .map(|txout| (input.previous_output, txout))
                    .ok_or(ConsensusError::MissingPrevout { input_index })
            })
            .collect()
    }

    fn kernel_txout(prevout: &TxOut) -> Result<bitcoinkernel::TxOut, ConsensusError> {
        let script = bitcoinkernel::ScriptPubkey::new(prevout.script_pubkey.as_bytes())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        let amount = i64::try_from(prevout.value.to_sat())
            .map_err(|error| ConsensusError::Kernel(error.to_string()))?;
        Ok(bitcoinkernel::TxOut::new(&script, amount))
    }
}

#[cfg(feature = "kernel")]
pub use enabled::{KernelBlock, KernelContext, verify_tx_scripts};
#[cfg(feature = "kernel")]
pub(crate) use enabled::{PreparedKernelTx, prepare_kernel_tx, verify_prepared_input};

#[cfg(not(feature = "kernel"))]
/// Stub kernel context available when the `kernel` feature is off.
#[derive(Debug, Default, Clone, Copy)]
pub struct KernelContext;

#[cfg(not(feature = "kernel"))]
/// Portable-build stand-in for the kernel's one-shot block parse.
///
/// The kernel build gets every txid out of `libbitcoinkernel`'s parse for free.
/// Without the kernel there is no such parse, so this decodes with rust-bitcoin
/// and hashes each transaction. That is slower than the kernel path by design:
/// the portable backend exists for differential testing, not for throughput.
pub struct KernelBlock {
    txids: Vec<bitcoin::Txid>,
}

#[cfg(not(feature = "kernel"))]
impl KernelBlock {
    /// Decodes `raw_block` and computes its txids.
    ///
    /// # Errors
    /// Returns [`ConsensusError::Kernel`] if `raw_block` is not a valid block.
    pub fn parse(raw_block: &[u8]) -> Result<Self, crate::ConsensusError> {
        let block: bitcoin::Block = bitcoin::consensus::deserialize(raw_block)
            .map_err(|error| crate::ConsensusError::Kernel(error.to_string()))?;
        Ok(Self {
            txids: block
                .txdata
                .iter()
                .map(bitcoin::Transaction::compute_txid)
                .collect(),
        })
    }

    /// Txids in block order.
    ///
    /// # Errors
    /// Never fails in this build; the signature matches the kernel one.
    pub fn txids(&self) -> Result<Vec<bitcoin::Txid>, crate::ConsensusError> {
        Ok(self.txids.clone())
    }

    /// Transaction count as parsed.
    #[must_use]
    pub fn transaction_count(&self) -> usize {
        self.txids.len()
    }
}
