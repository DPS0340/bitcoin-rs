//! Mutation records for the mempool's mutation API.
//!
//! Every mutating [`Mempool`](crate::Mempool) method returns a
//! [`MutationResult`] describing exactly what it committed, in commit order.
//! The pool advances its [`Mempool::sequence_number`] counter exactly once
//! per emitted change while the write lock is held, so each change in a
//! batch carries a distinct, contiguous sequence value that observers can
//! publish verbatim.

use alloc::vec::Vec;

use bitcoin_rs_primitives::{Hash256, Txid};

/// Why an entry left the pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RemovalReason {
    /// The entry confirmed in a connected block.
    BlockInclusion,
    /// A connected block's transaction took the entry's inputs.
    Conflict,
    /// A BIP125 replacement evicted the entry.
    Replaced,
    /// The entry descended from an evicted or confirmed entry.
    Descendant,
    /// Size or fee-rate policy evicted the entry.
    PolicyEviction,
    /// The entry outlived its expiry.
    Expiry,
    /// An explicit removal addressed the entry by id or txid.
    Explicit,
    /// A wholesale clear emptied the pool.
    Clear,
    /// A reorg disconnected the entry's containing state.
    Reorg,
}

/// What happened to one transaction in a committed mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationOutcome {
    /// The transaction was admitted to the pool.
    Accepted,
    /// The transaction left the pool for the recorded reason.
    Removed(RemovalReason),
}

/// One transaction's committed outcome, in commit order within a
/// [`MutationResult`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationChange {
    /// Transaction id in native consensus byte order.
    pub txid: Hash256,
    /// What happened to the transaction.
    pub outcome: MutationOutcome,
}

/// Builds a change for `txid`, converting the pool's internal `Txid` once at
/// this seam.
pub(crate) fn change(txid: &Txid, outcome: MutationOutcome) -> MutationChange {
    MutationChange {
        txid: Hash256::from(*txid),
        outcome,
    }
}

/// The ordered record of one committed mempool mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    /// Committed changes in commit order.
    pub changes: Vec<MutationChange>,
    /// Mempool sequence assigned to `changes[0]`; each later change took the
    /// next value. `0` when `changes` is empty.
    ///
    /// The pool advances its sequence exactly once per emitted change under
    /// the write lock, so a batch's sequences are contiguous.
    pub sequence_base: u64,
}

impl MutationResult {
    /// An empty result: nothing was committed and no sequence moved.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            changes: Vec::new(),
            sequence_base: 0,
        }
    }

    /// Number of committed changes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.changes.len()
    }

    /// Returns `true` when nothing was committed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// The sequence assigned to `changes[index]`, when in bounds.
    #[must_use]
    pub fn sequence_of(&self, index: usize) -> Option<u64> {
        if self.changes.is_empty() {
            return None;
        }
        let offset = u64::try_from(index).ok()?;
        self.sequence_base.checked_add(offset)
    }
}
