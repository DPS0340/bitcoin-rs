use std::collections::BTreeSet;
use std::sync::LazyLock;

#[cfg(feature = "bitcoinconsensus")]
use bitcoin::{Script, consensus::encode};
use bitcoin_rs_primitives::Tx;
#[cfg(not(feature = "kernel"))]
use bitcoin_rs_script::Interpreter;
use bitcoin_rs_script::VerifyFlags;
use rayon::prelude::*;

use crate::rust_path::UtxoView;
use crate::{ConsensusError, MAX_BLOCK_SIGOPS_COST, MAX_MONEY};

const LOCKTIME_THRESHOLD: u32 = 500_000_000;
const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const MIN_COINBASE_SCRIPT_SIG_SIZE: usize = 2;
const MAX_COINBASE_SCRIPT_SIG_SIZE: usize = 100;

// SMT siblings make secp256k1 verification slower past this width on large hosts.
const MAX_SCRIPT_VERIFY_THREADS: usize = 16;
const MIN_PARALLEL_SCRIPT_CHECKS: usize = 16;
static SCRIPT_VERIFY_POOL: LazyLock<rayon::ThreadPool> = LazyLock::new(|| {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    rayon::ThreadPoolBuilder::new()
        .num_threads(available.min(MAX_SCRIPT_VERIFY_THREADS))
        .thread_name(|index| format!("script-verify-{index}"))
        .build()
        .unwrap_or_else(|error| panic!("failed to build script verification pool: {error}"))
});

/// Returns `true` iff the transaction is locktime-final at `block_height` and the timestamp cutoff.
///
/// Implements Bitcoin Core's `IsFinalTx`:
///   - locktime == 0: always final.
///   - locktime < `LOCKTIME_THRESHOLD`: height-based; final iff locktime < `block_height`.
///   - locktime >= `LOCKTIME_THRESHOLD`: timestamp-based; final iff locktime < `locktime_cutoff`.
///   - all inputs have sequence == `SEQUENCE_FINAL`: final regardless of locktime.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
pub fn is_final_tx(tx: &bitcoin::Transaction, block_height: u32, locktime_cutoff: u32) -> bool {
    is_final_tx_with_locktime_cutoff(tx, block_height, locktime_cutoff)
}

/// Verifies that a coinbase transaction's scriptSig length is within consensus bounds.
pub fn verify_coinbase_script_sig_size(tx: &bitcoin::Transaction) -> Result<(), ConsensusError> {
    if let Some(input) = tx.input.first().filter(|_| tx.is_coinbase()) {
        let len = input.script_sig.len();
        if !(MIN_COINBASE_SCRIPT_SIG_SIZE..=MAX_COINBASE_SCRIPT_SIG_SIZE).contains(&len) {
            return Err(ConsensusError::CoinbaseScriptSigSize { len });
        }
    }
    Ok(())
}

/// Returns `true` iff the transaction is locktime-final at `block_height` and `locktime_cutoff`.
///
/// Callers choose the timestamp cutoff: block header time before BIP113, previous-tip MTP after.
#[must_use]
fn is_final_tx_with_locktime_cutoff(
    tx: &bitcoin::Transaction,
    block_height: u32,
    locktime_cutoff: u32,
) -> bool {
    let lock_time = tx.lock_time.to_consensus_u32();
    if lock_time == 0 {
        return true;
    }

    let threshold = if lock_time < LOCKTIME_THRESHOLD {
        block_height
    } else {
        locktime_cutoff
    };
    if lock_time < threshold {
        return true;
    }

    let sequence_final = bitcoin::Sequence::from_consensus(SEQUENCE_FINAL);
    tx.input
        .iter()
        .all(|input| input.sequence == sequence_final)
}

/// Verifies non-contextual and input-script transaction rules without contextual MTP checks.
pub fn verify_transaction(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_with_mtp(tx, prevouts, height, 0, flags)
}

/// Verifies non-contextual and input-script transaction rules with a caller-selected timestamp cutoff.
///
/// The historical `_with_mtp` suffix is retained for source compatibility. Callers pass block
/// header time before BIP113 activation and previous-tip MTP after activation.
pub fn verify_transaction_with_mtp(
    tx: &Tx,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_mtp(&tx.0, prevouts, height, locktime_cutoff, flags)
}

/// Verifies non-contextual and input-script transaction rules for a borrowed transaction without contextual MTP checks.
pub fn verify_transaction_borrowed(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_mtp(tx, prevouts, height, 0, flags)
}

/// Verifies non-contextual and input-script transaction rules for a borrowed transaction.
///
/// The historical `_with_mtp` suffix is retained for source compatibility. Callers pass block
/// header time before BIP113 activation and previous-tip MTP after activation.
pub fn verify_transaction_borrowed_with_mtp(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        flags,
        false,
    )
}

/// Verifies non-script transaction rules for a borrowed transaction with a caller-selected
/// timestamp cutoff.
///
/// Checks finality, empty inputs/outputs, coinbase scriptSig size, duplicate inputs, null
/// prevouts, missing prevouts, input/output value balance, and sigop limits. Skips interpreter
/// and `bitcoinconsensus` script execution.
pub fn verify_transaction_borrowed_non_script_with_mtp(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
) -> Result<(), ConsensusError> {
    verify_transaction_borrowed_with_locktime_cutoff(
        tx,
        prevouts,
        height,
        locktime_cutoff,
        VerifyFlags::NONE,
        true,
    )
}

fn verify_transaction_borrowed_with_locktime_cutoff(
    tx: &bitcoin::Transaction,
    prevouts: &impl UtxoView,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
    skip_scripts: bool,
) -> Result<(), ConsensusError> {
    let Some(prep) = prepare_tx_checks(tx, height, locktime_cutoff, |_, outpoint| {
        prevouts.lookup(outpoint)
    })?
    else {
        // Coinbase: fully checked by the pre-phase; no inputs to verify.
        return Ok(());
    };

    if !skip_scripts {
        // KTD5: under the kernel feature every script class routes through Core's
        // engine — one transaction parse plus one sighash precompute shared across
        // inputs. The portable arm keeps the interpreter/bitcoinconsensus dispatch.
        #[cfg(feature = "kernel")]
        crate::kernel::verify_tx_scripts(tx, &prep.prevouts, flags)?;
        #[cfg(not(feature = "kernel"))]
        {
            #[cfg(feature = "bitcoinconsensus")]
            let serialized_tx = Some(encode::serialize(tx));
            #[cfg(not(feature = "bitcoinconsensus"))]
            let serialized_tx: Option<Vec<u8>> = None;
            for (input_index, (_, prevout)) in prep.prevouts.iter().enumerate() {
                verify_input_script_portable(
                    input_index,
                    prevout,
                    tx,
                    flags,
                    serialized_tx.as_deref(),
                )?;
            }
        }
    }

    finalize_tx_value_and_sigops(tx, &prep)
}

/// Resolved per-transaction state carried from the pre-phase into the script and
/// post phases.
struct TxPrep {
    prevouts: Vec<(bitcoin::OutPoint, bitcoin::TxOut)>,
    input_value: u64,
    output_value: u64,
}

/// Runs a transaction's non-script pre-checks: finality, empty in/out, total
/// output value, coinbase scriptSig size, duplicate/null inputs, and ordered
/// prevout resolution with input-value overflow. `lookup(input_index, outpoint)`
/// resolves each input's prevout. Returns `Ok(None)` for an accepted coinbase
/// (no inputs to verify) and `Ok(Some(prep))` for a clean non-coinbase tx.
fn prepare_tx_checks(
    tx: &bitcoin::Transaction,
    height: u32,
    locktime_cutoff: u32,
    mut lookup: impl FnMut(usize, &bitcoin::OutPoint) -> Option<bitcoin::TxOut>,
) -> Result<Option<TxPrep>, ConsensusError> {
    if !is_final_tx_with_locktime_cutoff(tx, height, locktime_cutoff) {
        return Err(ConsensusError::Bip {
            bip: "BIP113",
            reason: format!(
                "non-final transaction at height {height} locktime cutoff \
                 {locktime_cutoff}: locktime {}",
                tx.lock_time.to_consensus_u32()
            ),
        });
    }

    if tx.input.is_empty() {
        return Err(ConsensusError::EmptyInputs);
    }
    if tx.output.is_empty() {
        return Err(ConsensusError::EmptyOutputs);
    }

    let output_value = total_output_value_borrowed(tx)?;
    if tx.is_coinbase() {
        verify_coinbase_script_sig_size(tx)?;
        return Ok(None);
    }

    let mut seen = BTreeSet::new();
    for (input_index, input) in tx.input.iter().enumerate() {
        if input.previous_output.is_null() {
            return Err(ConsensusError::NullPrevout { input_index });
        }
        if !seen.insert(input.previous_output) {
            return Err(ConsensusError::DuplicateInput { input_index });
        }
    }

    let mut input_value = 0u64;
    let mut prevouts = Vec::with_capacity(tx.input.len());
    for (input_index, input) in tx.input.iter().enumerate() {
        let prevout = lookup(input_index, &input.previous_output)
            .ok_or(ConsensusError::MissingPrevout { input_index })?;
        input_value = input_value
            .checked_add(prevout.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        prevouts.push((input.previous_output, prevout));
    }

    Ok(Some(TxPrep {
        prevouts,
        input_value,
        output_value,
    }))
}

/// Runs a transaction's deferred post-checks: input/output value balance and the
/// sigop-cost limit, reusing the resolved prevouts.
fn finalize_tx_value_and_sigops(
    tx: &bitcoin::Transaction,
    prep: &TxPrep,
) -> Result<(), ConsensusError> {
    if prep.input_value < prep.output_value {
        return Err(ConsensusError::InputsLessThanOutputs {
            input_value: prep.input_value,
            output_value: prep.output_value,
        });
    }

    let mut sigop_lookup_cursor = 0usize;
    let sigop_cost = u32::try_from(tx.total_sigop_cost(|outpoint| {
        cached_prevout_lookup(&prep.prevouts, &mut sigop_lookup_cursor, outpoint)
    }))
    .unwrap_or(u32::MAX);
    if sigop_cost > MAX_BLOCK_SIGOPS_COST {
        return Err(ConsensusError::SigopsLimit {
            cost: sigop_cost,
            max: MAX_BLOCK_SIGOPS_COST,
        });
    }
    Ok(())
}

/// Portable per-input script verdict: bitcoinconsensus for non-taproot, else the
/// Rust interpreter. `serialized_tx` borrows one serialization shared by every
/// input of the transaction.
#[cfg(not(feature = "kernel"))]
fn verify_input_script_portable(
    input_index: usize,
    prevout: &bitcoin::TxOut,
    tx: &bitcoin::Transaction,
    flags: VerifyFlags,
    serialized_tx: Option<&[u8]>,
) -> Result<(), ConsensusError> {
    #[cfg(feature = "bitcoinconsensus")]
    if let Some(serialized_tx) = serialized_tx
        && verify_non_taproot_with_bitcoinconsensus(input_index, prevout, serialized_tx, flags)?
    {
        return Ok(());
    }
    #[cfg(not(feature = "bitcoinconsensus"))]
    let _ = serialized_tx;

    let input = &tx.input[input_index];
    let witness = input.witness.to_vec();
    Interpreter
        .execute(
            prevout.script_pubkey.as_bytes(),
            input.script_sig.as_bytes(),
            &witness,
            flags,
            prevout,
            tx,
            input_index,
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: error.to_string(),
        })?;
    Ok(())
}

/// Per-transaction state retained across the flat block verify phases.
struct PreparedTx {
    tx_index: usize,
    prevouts: Vec<(bitcoin::OutPoint, bitcoin::TxOut)>,
    pre_error: Option<ConsensusError>,
    post_error: Option<ConsensusError>,
    checks_start: usize,
    checks_len: usize,
    #[cfg(feature = "kernel")]
    kernel_state: Option<crate::kernel::PreparedKernelTx>,
    #[cfg(all(not(feature = "kernel"), feature = "bitcoinconsensus"))]
    serialized: Option<Vec<u8>>,
}

/// One deferred per-input script check, indexing back into the prepared txs.
struct InputCheck {
    prepared_index: usize,
    input_index: usize,
}

/// Verifies every input script across a block in one flat, block-ordered pass.
///
/// `resolved[i]` holds transaction `i`'s prevouts in input order (empty for the
/// coinbase). The node resolves them serially in block order so same-block
/// spends and overlay semantics stay authoritative. Prevout resolution is order
/// sensitive; script verification is not, so the per-input checks run
/// concurrently, yet the first failure is returned in block order (tx ascending,
/// phase `pre < script < post`, input ascending) — byte-identical to applying
/// the single-tx path tx by tx in block order.
pub fn verify_block_input_scripts(
    txs: &[bitcoin::Transaction],
    mut resolved: Vec<Vec<Option<bitcoin::TxOut>>>,
    height: u32,
    locktime_cutoff: u32,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    if txs.len() != resolved.len() {
        return Err(ConsensusError::PrevoutMatrixSize {
            expected: txs.len(),
            actual: resolved.len(),
        });
    }

    let (prepared, checks) =
        prepare_block_input_checks(txs, resolved.as_mut_slice(), height, locktime_cutoff);
    let results: Vec<Result<(), ConsensusError>> = if checks.len() < MIN_PARALLEL_SCRIPT_CHECKS {
        checks
            .iter()
            .map(|check| check_input(txs, &prepared, check, flags))
            .collect()
    } else {
        SCRIPT_VERIFY_POOL.install(|| {
            checks
                .par_iter()
                .map(|check| check_input(txs, &prepared, check, flags))
                .collect()
        })
    };

    for prep in &prepared {
        if let Some(error) = &prep.pre_error {
            return Err(error.clone());
        }
        for result in &results[prep.checks_start..prep.checks_start + prep.checks_len] {
            if let Err(error) = result {
                return Err(error.clone());
            }
        }
        if let Some(error) = &prep.post_error {
            return Err(error.clone());
        }
    }
    Ok(())
}

/// Resolves order-sensitive transaction state before script checks fan out.
///
/// Preparation stops at the first pre-script failure so no later transaction
/// can outrank it during the final ordered error scan.
fn prepare_block_input_checks(
    txs: &[bitcoin::Transaction],
    resolved: &mut [Vec<Option<bitcoin::TxOut>>],
    height: u32,
    locktime_cutoff: u32,
) -> (Vec<PreparedTx>, Vec<InputCheck>) {
    let mut prepared = Vec::with_capacity(txs.len());
    let mut checks = Vec::new();
    for (tx_index, tx) in txs.iter().enumerate() {
        let resolved_inputs = &mut resolved[tx_index];
        let prep = match prepare_tx_checks(tx, height, locktime_cutoff, |input_index, _| {
            resolved_inputs.get_mut(input_index).and_then(Option::take)
        }) {
            Ok(Some(prep)) => prep,
            Ok(None) => {
                prepared.push(PreparedTx {
                    tx_index,
                    prevouts: Vec::new(),
                    pre_error: None,
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    #[cfg(feature = "kernel")]
                    kernel_state: None,
                    #[cfg(all(not(feature = "kernel"), feature = "bitcoinconsensus"))]
                    serialized: None,
                });
                continue;
            }
            Err(pre_error) => {
                prepared.push(PreparedTx {
                    tx_index,
                    prevouts: Vec::new(),
                    pre_error: Some(pre_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    #[cfg(feature = "kernel")]
                    kernel_state: None,
                    #[cfg(all(not(feature = "kernel"), feature = "bitcoinconsensus"))]
                    serialized: None,
                });
                break;
            }
        };

        // Build retained kernel state before checks so setup failure cannot
        // leave an InputCheck without its PreparedKernelTx.
        #[cfg(feature = "kernel")]
        let kernel_state = match crate::kernel::prepare_kernel_tx(tx, &prep.prevouts) {
            Ok(state) => state,
            Err(setup_error) => {
                prepared.push(PreparedTx {
                    tx_index,
                    prevouts: prep.prevouts,
                    pre_error: Some(setup_error),
                    post_error: None,
                    checks_start: checks.len(),
                    checks_len: 0,
                    kernel_state: None,
                });
                break;
            }
        };

        let prepared_index = prepared.len();
        let checks_start = checks.len();
        for input_index in 0..tx.input.len() {
            checks.push(InputCheck {
                prepared_index,
                input_index,
            });
        }
        let checks_len = tx.input.len();
        #[cfg(all(not(feature = "kernel"), feature = "bitcoinconsensus"))]
        let serialized = Some(encode::serialize(tx));
        let post_error = finalize_tx_value_and_sigops(tx, &prep).err();
        let stop_after_tx = post_error.is_some();
        prepared.push(PreparedTx {
            tx_index,
            prevouts: prep.prevouts,
            pre_error: None,
            post_error,
            checks_start,
            checks_len,
            #[cfg(feature = "kernel")]
            kernel_state: Some(kernel_state),
            #[cfg(all(not(feature = "kernel"), feature = "bitcoinconsensus"))]
            serialized,
        });
        // This tx's scripts still outrank its post error; that post error makes
        // every later transaction irrelevant to the ordered verdict.
        if stop_after_tx {
            break;
        }
    }
    (prepared, checks)
}

/// Runs one deferred input's script verdict against its retained state. Forks on
/// `cfg(kernel)` between the kernel and portable engines, sharing `&prepared` and
/// `&txs` by shared reference only.
fn check_input(
    txs: &[bitcoin::Transaction],
    prepared: &[PreparedTx],
    check: &InputCheck,
    flags: VerifyFlags,
) -> Result<(), ConsensusError> {
    let prep = &prepared[check.prepared_index];
    let tx = &txs[prep.tx_index];
    let (_, prevout) = &prep.prevouts[check.input_index];
    #[cfg(feature = "kernel")]
    {
        let _ = tx;
        let kernel_state = prep.kernel_state.as_ref().ok_or_else(|| {
            ConsensusError::Kernel("clean non-coinbase tx lost prepared kernel state".to_owned())
        })?;
        crate::kernel::verify_prepared_input(kernel_state, prevout, check.input_index, flags)
    }
    #[cfg(not(feature = "kernel"))]
    {
        #[cfg(feature = "bitcoinconsensus")]
        let serialized_tx = prep.serialized.as_deref();
        #[cfg(not(feature = "bitcoinconsensus"))]
        let serialized_tx = None;
        verify_input_script_portable(check.input_index, prevout, tx, flags, serialized_tx)
    }
}

fn cached_prevout_lookup(
    prevouts: &[(bitcoin::OutPoint, bitcoin::TxOut)],
    cursor: &mut usize,
    outpoint: &bitcoin::OutPoint,
) -> Option<bitcoin::TxOut> {
    if prevouts.is_empty() {
        return None;
    }
    if *cursor >= prevouts.len() {
        *cursor = 0;
    }
    if let Some((cached_outpoint, txout)) = prevouts.get(*cursor)
        && cached_outpoint == outpoint
    {
        *cursor = (*cursor).saturating_add(1);
        return Some(txout.clone());
    }
    let (index, txout) =
        prevouts
            .iter()
            .enumerate()
            .find_map(|(index, (cached_outpoint, txout))| {
                (cached_outpoint == outpoint).then_some((index, txout))
            })?;
    *cursor = index.saturating_add(1);
    Some(txout.clone())
}

#[cfg(feature = "bitcoinconsensus")]
fn verify_non_taproot_with_bitcoinconsensus(
    input_index: usize,
    prevout: &bitcoin::TxOut,
    serialized_tx: &[u8],
    flags: VerifyFlags,
) -> Result<bool, ConsensusError> {
    let script = Script::from_bytes(prevout.script_pubkey.as_bytes());
    if script.is_p2tr() && flags.contains(VerifyFlags::TAPROOT) {
        return Ok(false);
    }

    script
        .verify_with_flags(
            input_index,
            prevout.value,
            serialized_tx,
            flags.consensus_bits(),
        )
        .map_err(|error| ConsensusError::Script {
            input_index,
            reason: format!("script verification failed: {error}"),
        })?;
    Ok(true)
}

fn total_output_value_borrowed(tx: &bitcoin::Transaction) -> Result<u64, ConsensusError> {
    tx.output.iter().try_fold(0u64, |sum, output| {
        let next = sum
            .checked_add(output.value.to_sat())
            .ok_or(ConsensusError::OutputValueOverflow)?;
        if next > MAX_MONEY {
            Err(ConsensusError::OutputValueOverflow)
        } else {
            Ok(next)
        }
    })
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, collections::BTreeMap};

    use bitcoin::hashes::Hash as _;
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    use bitcoin::opcodes::all::OP_EQUAL;
    use bitcoin::script::Builder;
    use bitcoin::{
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
        transaction,
    };
    use bitcoin_rs_primitives::Tx;
    use bitcoin_rs_script::VerifyFlags;

    use super::{
        is_final_tx_with_locktime_cutoff, verify_coinbase_script_sig_size, verify_transaction,
        verify_transaction_borrowed, verify_transaction_borrowed_with_mtp,
        verify_transaction_with_mtp,
    };
    use crate::{ConsensusError, rust_path::UtxoView};

    #[test]
    fn coinbase_transaction_skips_prevout_lookup() {
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1, 1]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let utxos = BTreeMap::new();
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn coinbase_script_sig_size_rejects_invalid_lengths() {
        for len in [0, 1, 101] {
            let tx = coinbase_transaction_with_script_sig_len(len);
            let utxos = BTreeMap::new();
            let expected = Err(ConsensusError::CoinbaseScriptSigSize { len });

            assert_eq!(verify_coinbase_script_sig_size(&tx.0), expected);
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
                expected
            );
        }
    }

    #[test]
    fn coinbase_script_sig_size_accepts_valid_boundaries() {
        let utxos = BTreeMap::new();
        for len in [2, 100] {
            let tx = coinbase_transaction_with_script_sig_len(len);

            assert_eq!(verify_coinbase_script_sig_size(&tx.0), Ok(()));
            assert_eq!(
                verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
                Ok(())
            );
        }
    }

    #[test]
    fn duplicate_non_coinbase_input_is_rejected() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![spending_input(outpoint), spending_input(outpoint)],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::NONE),
            Err(ConsensusError::DuplicateInput { input_index: 1 })
        );
    }

    #[test]
    fn verify_transaction_accepts_multi_input_true_scripts() {
        let first = OutPoint {
            txid: Txid::from_byte_array([1; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([2; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    fn verify_transaction_reuses_prevouts_for_sigop_counting() {
        let first = OutPoint {
            txid: Txid::from_byte_array([11; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([12; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(75),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );
        let view = CountingUtxoView::new(utxos);

        assert_eq!(
            verify_transaction(&tx, &view, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
        assert_eq!(view.lookup_count(), tx.0.input.len());
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_accepts_non_taproot_spend_with_script_sig_data() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([3; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(7).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_rejects_non_taproot_spend_with_script_sig_mismatch() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([4; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason
            }) if reason.starts_with("script verification failed:")
        ));
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn verify_transaction_routes_taproot_spends_to_interpreter() {
        let first = OutPoint {
            txid: Txid::from_byte_array([5; 32]),
            vout: 0,
        };
        let second = OutPoint {
            txid: Txid::from_byte_array([6; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![true_spending_input(first), true_spending_input(second)],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            first,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: p2tr_script_pubkey(),
            },
        );
        utxos.insert(
            second,
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Builder::new().push_int(1).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert_eq!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason:
                    "taproot key-path verification requires all prevouts for multi-input transactions"
                        .to_owned(),
            })
        );
    }

    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_accepts_non_taproot_spend_with_script_sig_data() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(7).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );
    }

    /// R2 pin: in the kernel build the script verdict carries the kernel
    /// dispatch marker, proving the Rust interpreter (whose call site is
    /// `cfg(not(feature = "kernel"))`) did not produce it.
    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_rejects_script_sig_mismatch_with_kernel_verdict() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([8; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        let result = verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Script {
                input_index: 0,
                reason
            }) if reason.starts_with("kernel script verification failed:")
        ));
    }

    /// Assume-valid semantics: the non-script entry must accept a transaction
    /// whose script the kernel would reject — no kernel invocation when
    /// scripts are skipped.
    #[test]
    #[cfg(feature = "kernel")]
    fn kernel_skip_scripts_entry_accepts_invalid_script() {
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([9; 32]),
            vout: 0,
        };
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: Builder::new().push_int(7).push_int(8).into_script(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let mut utxos = BTreeMap::new();
        utxos.insert(
            outpoint,
            TxOut {
                value: Amount::from_sat(100),
                script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
            },
        );

        assert_eq!(
            super::verify_transaction_borrowed_non_script_with_mtp(&tx.0, &utxos, 0, 0),
            Ok(())
        );
        assert!(matches!(
            verify_transaction(&tx, &utxos, 0, VerifyFlags::MANDATORY),
            Err(ConsensusError::Script { input_index: 0, .. })
        ));
    }

    #[test]
    fn verify_transaction_rejects_non_final_height_lock() {
        let tx = Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::from_consensus(200),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        });
        let utxos = BTreeMap::new();

        let result = verify_transaction_with_mtp(&tx, &utxos, 100, 0, VerifyFlags::MANDATORY);

        assert!(matches!(
            result,
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    #[test]
    fn timestamp_locktime_uses_caller_supplied_cutoff() {
        let tx = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::from_consensus(500_000_100),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(!is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_100));
        assert!(is_final_tx_with_locktime_cutoff(&tx, 1, 500_000_101));
    }

    #[test]
    fn borrowed_transaction_paths_share_locktime_and_coinbase_rules() {
        let coinbase = coinbase_transaction_with_script_sig_len(2);
        let utxos = BTreeMap::new();

        assert_eq!(
            verify_transaction_borrowed(&coinbase.0, &utxos, 0, VerifyFlags::MANDATORY),
            Ok(())
        );

        let non_final = Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::from_consensus(500_000_100),
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(0),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        assert!(matches!(
            verify_transaction_borrowed_with_mtp(
                &non_final,
                &utxos,
                1,
                500_000_100,
                VerifyFlags::MANDATORY
            ),
            Err(ConsensusError::Bip { bip: "BIP113", .. })
        ));
    }

    fn spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Builder::new().push_int(1).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    fn true_spending_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    struct CountingUtxoView {
        utxos: BTreeMap<OutPoint, TxOut>,
        lookups: Cell<usize>,
    }

    impl CountingUtxoView {
        fn new(utxos: BTreeMap<OutPoint, TxOut>) -> Self {
            Self {
                utxos,
                lookups: Cell::new(0),
            }
        }

        fn lookup_count(&self) -> usize {
            self.lookups.get()
        }
    }

    impl UtxoView for CountingUtxoView {
        fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
            self.lookups.set(self.lookups.get().saturating_add(1));
            self.utxos.get(outpoint).cloned()
        }
    }

    #[cfg(feature = "bitcoinconsensus")]
    fn p2tr_script_pubkey() -> ScriptBuf {
        let mut bytes = Vec::with_capacity(34);
        bytes.push(0x51);
        bytes.push(0x20);
        bytes.extend_from_slice(&[7; 32]);
        ScriptBuf::from_bytes(bytes)
    }

    fn coinbase_transaction_with_script_sig_len(len: usize) -> Tx {
        Tx(Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![1; len]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: ScriptBuf::new(),
            }],
        })
    }

    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn op1_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }
    }

    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn op_equal_txout(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Builder::new().push_opcode(OP_EQUAL).into_script(),
        }
    }

    /// Input spending an `OP_EQUAL` prevout with a mismatched `7 8` scriptSig:
    /// rejected by both bitcoinconsensus and the kernel.
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn mismatch_input(outpoint: OutPoint) -> TxIn {
        TxIn {
            previous_output: outpoint,
            script_sig: Builder::new().push_int(7).push_int(8).into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }

    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn spend_tx(inputs: Vec<TxIn>, output_value: u64) -> Transaction {
        Transaction {
            version: transaction::Version(1),
            lock_time: absolute::LockTime::ZERO,
            input: inputs,
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: Builder::new().push_int(1).into_script(),
            }],
        }
    }

    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn outpoint(seed: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([seed; 32]),
            vout: 0,
        }
    }

    #[test]
    fn block_input_scripts_rejects_mismatched_prevout_matrix() {
        let txs = vec![coinbase_transaction_with_script_sig_len(2).0];
        assert_eq!(
            super::verify_block_input_scripts(&txs, Vec::new(), 0, 0, VerifyFlags::MANDATORY),
            Err(ConsensusError::PrevoutMatrixSize {
                expected: 1,
                actual: 0,
            })
        );
    }

    /// The assignment's required case: an earlier transaction's script failure
    /// must outrank a later transaction's missing prevout, because prep emits the
    /// earlier tx's input checks before it breaks on the missing-prevout pre-error.
    #[test]
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn earlier_tx_script_error_beats_later_tx_missing_prevout() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2).0,
            spend_tx(vec![mismatch_input(outpoint(1))], 50),
            spend_tx(vec![true_spending_input(outpoint(2))], 50),
        ];
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))], vec![None]];
        let result =
            super::verify_block_input_scripts(&txs, resolved, 0, 0, VerifyFlags::MANDATORY);
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected tx1 Script error, got {result:?}"
        );
    }

    /// The deferred post-error (value balance) must not outrank the same tx's
    /// script failure: script is phase 1, post is phase 2 in the intra-tx order.
    #[test]
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn intra_tx_script_error_beats_value_and_sigop() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2).0,
            spend_tx(vec![mismatch_input(outpoint(1))], 100),
        ];
        let resolved = vec![Vec::new(), vec![Some(op_equal_txout(50))]];
        let result =
            super::verify_block_input_scripts(&txs, resolved, 0, 0, VerifyFlags::MANDATORY);
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected Script error over InputsLessThanOutputs, got {result:?}"
        );
    }

    /// A later transaction's pre-error must not outrank an earlier transaction's
    /// deferred post-error: the scan walks in block order and returns tx1 first.
    #[test]
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn later_pre_error_does_not_outrank_earlier_post_error() {
        let txs = vec![
            coinbase_transaction_with_script_sig_len(2).0,
            spend_tx(vec![true_spending_input(outpoint(1))], 100),
            spend_tx(
                vec![
                    true_spending_input(outpoint(2)),
                    true_spending_input(outpoint(2)),
                ],
                50,
            ),
        ];
        let resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(50))],
            vec![Some(op1_txout(50)), Some(op1_txout(50))],
        ];
        let result =
            super::verify_block_input_scripts(&txs, resolved, 0, 0, VerifyFlags::MANDATORY);
        assert_eq!(
            result,
            Err(ConsensusError::InputsLessThanOutputs {
                input_value: 50,
                output_value: 100,
            })
        );
    }

    /// Parallel script checks still report the earliest block-ordered failure.
    #[test]
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn parallel_script_checks_report_first_error() {
        let mut txs = vec![
            coinbase_transaction_with_script_sig_len(2).0,
            spend_tx(vec![mismatch_input(outpoint(1))], 50),
        ];
        let mut resolved = vec![Vec::new(), vec![Some(op_equal_txout(100))]];
        for seed in 2..=u8::try_from(super::MIN_PARALLEL_SCRIPT_CHECKS).unwrap_or(u8::MAX) {
            txs.push(spend_tx(vec![mismatch_input(outpoint(seed))], 50));
            resolved.push(vec![Some(op_equal_txout(100))]);
        }

        let result =
            super::verify_block_input_scripts(&txs, resolved, 0, 0, VerifyFlags::MANDATORY);
        assert!(
            matches!(result, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected first Script error, got {result:?}"
        );
    }

    /// A same-block spend (tx2 consuming tx1's output) verifies when the node
    /// resolves it into `resolved`; a bad script in the producing tx surfaces that
    /// earlier transaction's Script error.
    #[test]
    #[cfg(any(feature = "bitcoinconsensus", feature = "kernel"))]
    fn same_block_spend_resolves_and_verifies() {
        let tx1 = spend_tx(vec![true_spending_input(outpoint(1))], 100);
        let tx1_out = OutPoint {
            txid: tx1.compute_txid(),
            vout: 0,
        };
        let tx2 = spend_tx(vec![true_spending_input(tx1_out)], 90);
        let tx1_output = tx1.output[0].clone();
        let txs = vec![coinbase_transaction_with_script_sig_len(2).0, tx1, tx2];
        let resolved = vec![
            Vec::new(),
            vec![Some(op1_txout(100))],
            vec![Some(tx1_output)],
        ];
        assert_eq!(
            super::verify_block_input_scripts(&txs, resolved, 0, 0, VerifyFlags::MANDATORY),
            Ok(())
        );

        let bad_tx1 = spend_tx(vec![mismatch_input(outpoint(1))], 100);
        let bad_out = OutPoint {
            txid: bad_tx1.compute_txid(),
            vout: 0,
        };
        let bad_tx2 = spend_tx(vec![true_spending_input(bad_out)], 90);
        let bad_tx1_output = bad_tx1.output[0].clone();
        let bad_txs = vec![
            coinbase_transaction_with_script_sig_len(2).0,
            bad_tx1,
            bad_tx2,
        ];
        let bad_resolved = vec![
            Vec::new(),
            vec![Some(op_equal_txout(100))],
            vec![Some(bad_tx1_output)],
        ];
        let bad =
            super::verify_block_input_scripts(&bad_txs, bad_resolved, 0, 0, VerifyFlags::MANDATORY);
        assert!(
            matches!(bad, Err(ConsensusError::Script { input_index: 0, .. })),
            "expected producing tx Script error, got {bad:?}"
        );
    }
}
