//! Deletion of historical block bodies and undo records, once the active
//! chain no longer needs them.
//!
//! This lives in `storage` rather than in a crate of its own (issue #164)
//! because it is a retention policy over the rows this crate already owns.
//! Its former crate declared `bitcoin-rs-utxo`, `bitcoin-rs-chain` and
//! `bitcoin` as dependencies and referenced none of them: the only things it
//! ever touched were this crate and `Hash256`.
//!
//! [`stage_block_and_undo_prune`] is the main entry point. It stages
//! block-body and undo-row deletion together with prune-height metadata into
//! one caller-owned atomic batch, so node wiring commits them in a single
//! backend commit. Both kinds of data are pruned against the durable tip
//! rather than the in-memory tip: a crash restores to the last durable
//! checkpoint, and bodies between that base and the crash-recovery sidecar tip
//! are evidence needed for local replay while undo records are needed to
//! disconnect back through the restored chain. After the index rows commit,
//! [`reclaim_staged_flat_block_files`] deletes the staged flat block files,
//! and [`PruneOutcome`] reports the bytes and row counts freed.
//!
//! Rows pinned by a live [`RetentionLease`] are never staged: the policy
//! line folds with the registry's retention floor before any deletion is
//! selected, so a reader holding a lease keeps exactly its required history.
//!
//! [`PrunePolicy`] carries no behaviour of its own: the node builds one from
//! configuration and hands it in, which is the policy/mechanism split this
//! module keeps.
//!
//! Note that [`block_body_key`] and [`BLOCK_DATA_CF`] are not only pruning
//! concerns -- they are the block-body key schema, and the node reads bodies
//! through them on the ordinary path. That is the sharper reason this is a
//! storage module: the schema was living in the crate that deletes rows.

/// Block-body pruning over persisted block rows.
pub mod block_pruner;
/// Retention leases that keep required history against pruning.
pub mod lease;
/// Pruning policy shapes matching Bitcoin Core semantics.
pub mod policy;
/// Undo-data pruning over persisted undo rows.
pub mod undo_pruner;

pub use block_pruner::{BLOCK_DATA_CF, BlockPruner, block_body_key};
pub use lease::{RetentionError, RetentionLease, RetentionRegistry};
pub use policy::PrunePolicy;
pub use undo_pruner::{UndoPruner, block_undo_key};

use crate::{StorageError, WriteBatch as _};
use alloc::vec::Vec;
use thiserror::Error;

/// What one pruning pass staged for its caller's atomic batch.
///
/// [`stage_block_and_undo_prune`] fills this; the caller commits the batch,
/// reclaims the flat files, and then records [`StagedPrune::pruned_below`]
/// through [`RetentionRegistry::record_pruned_below`] so later lease
/// requests learn what is actually gone.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct StagedPrune {
    /// Block-body rows the batch deletes.
    pub blocks: PruneOutcome,
    /// Undo rows the batch deletes.
    pub undo: PruneOutcome,
    /// Flat block files to reclaim after the batch commits.
    pub file_numbers: Vec<u32>,
    /// Heights strictly below this line were staged for deletion.
    pub pruned_below: u32,
}

/// Stages block-body and undo-row pruning into a caller-owned atomic batch.
///
/// This is intentionally narrow: node wiring uses it to combine manual-prune
/// row deletion with prune-height metadata in one backend commit.
///
/// `durable_tip_height` is the height the node would restore to after a
/// crash. Both block bodies and undo records are pruned against it rather
/// than against `current_tip_height`, because the in-memory applied tip can
/// run far ahead of the last durable checkpoint. Bodies above this base may
/// be named by the crash-recovery sidecar and must remain available for
/// local replay; undo records below the base would prevent a restored chain
/// from disconnecting its own tip.
///
/// The pass never deletes rows pinned by a live [`RetentionLease`]: the
/// policy line is folded with [`RetentionRegistry::retention_floor`], and
/// the resulting line comes back as [`StagedPrune::pruned_below`].
pub fn stage_block_and_undo_prune<S: crate::KvStore>(
    store: &S,
    batch: &mut S::WriteBatch,
    block_files: &crate::FlatFileBlockStore,
    current_tip_height: u32,
    durable_tip_height: u32,
    policy: PrunePolicy,
    retention: &RetentionRegistry,
) -> Result<StagedPrune, PruneError> {
    if policy.is_full_node() {
        return Ok(StagedPrune::default());
    }

    let durable_tip = current_tip_height.min(durable_tip_height);
    let policy_line = durable_tip.saturating_sub(policy.retention_depth());
    // The retention floor binds before the byte target does: a lease holder
    // proved it needs rows at or above its floor, so the line stops there
    // even when the pass could free more below it.
    let pruned_below = policy_line.min(retention.retention_floor().unwrap_or(u32::MAX));
    let (blocks, file_numbers) =
        block_pruner::stage_flat_block_file_prune(store, batch, block_files, pruned_below, policy)?;
    let undo = block_pruner::prune_prefixed_rows_into_batch(
        store,
        batch,
        undo_pruner::BLOCK_UNDO_CF,
        undo_pruner::BLOCK_UNDO_PREFIX_BYTES,
        // The lease-clamped line, not a fresh derivation: the whole pass
        // must delete through one line, or a lease would hold block bodies
        // while their undo records delete around them (or the reverse).
        pruned_below,
        policy,
    )?;

    Ok(StagedPrune {
        blocks,
        undo,
        file_numbers,
        pruned_below,
    })
}

/// Deletes staged flat block files after their block-index rows are committed.
#[doc(hidden)]
pub fn reclaim_staged_flat_block_files<S: crate::KvStore>(
    store: &S,
    block_files: &crate::FlatFileBlockStore,
    file_numbers: &[u32],
) -> Result<(), PruneError> {
    let mut batch = store.new_batch();
    let mut removed_metadata = false;
    for &file_no in file_numbers {
        if file_no == block_files.current_file_number() {
            continue;
        }
        let _ = block_files.delete_file_if_not_current(file_no)?;
        batch.delete(
            block_pruner::BLOCK_DATA_CF,
            &crate::block_file_max_height_key(file_no),
        );
        removed_metadata = true;
    }
    if removed_metadata {
        store.write(batch)?;
    }
    Ok(())
}

/// Result of one pruning pass.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PruneOutcome {
    /// Number of payload bytes deleted from storage.
    pub bytes_freed: u64,
    /// Number of block or undo rows deleted from storage.
    pub blocks_removed: u64,
}

impl PruneOutcome {
    /// Adds one deleted row to the outcome.
    pub(crate) const fn record_removed(&mut self, bytes: u64) {
        self.bytes_freed = self.bytes_freed.saturating_add(bytes);
        self.blocks_removed = self.blocks_removed.saturating_add(1);
    }

    /// Returns true when no rows were deleted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.blocks_removed == 0
    }
}

/// Errors returned while pruning persisted block or undo rows.
#[derive(Debug, Error)]
pub enum PruneError {
    /// A storage backend operation failed.
    #[error(transparent)]
    Storage(#[from] StorageError),
    /// A storage row length could not fit in the pruning byte counter.
    #[error("storage row length {size} does not fit in u64")]
    RowSizeOverflow {
        /// Row length returned by the storage backend.
        size: usize,
    },
}

pub(crate) fn row_len_u64(value: &[u8]) -> Result<u64, PruneError> {
    u64::try_from(value.len()).map_err(|_| PruneError::RowSizeOverflow { size: value.len() })
}
