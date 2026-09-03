use alloc::collections::{BTreeMap, BTreeSet};

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by signed modified fee rate, modified ancestor fee
/// rate, then age.
///
/// Ordering lives in [`ParetoKey`]'s [`Ord`], and the set is kept in that order
/// rather than re-sorted. Insertion and removal are both `O(log n)`.
///
/// Insertion and removal stay logarithmic so peer-driven mempool growth does
/// not re-sort the complete priority set.
#[derive(Clone, Debug, Default)]
pub struct ParetoFront {
    /// Keys in priority order.
    order: BTreeSet<ParetoKey>,
    /// The key currently indexed for each entry.
    ///
    /// A removal is given an id, and the ordered set is keyed by priority, so
    /// without this a removal would have to search the set to find what to
    /// remove — which is the linear scan this type exists to avoid.
    keys: BTreeMap<EntryId, ParetoKey>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct ParetoKey {
    id: EntryId,
    modified_fee_rate: i128,
    modified_ancestor_fee_rate: i128,
    time: u64,
}

impl Ord for ParetoKey {
    /// Highest modified fee rate first, then highest modified ancestor fee
    /// rate, then oldest.
    ///
    /// The rates are the actual fee rate plus the signed mining-only overlay
    /// ([`MempoolEntry::modified_fee_rate`]), so `prioritisetransaction`
    /// moves entries without touching their actual fees. The rates are signed
    /// because a negative overlay can push a modified fee below zero.
    ///
    /// The final tiebreak on `id` is what makes this a *total* order, and that
    /// is load-bearing rather than cosmetic: the ordered set stores keys, so two
    /// entries whose keys compared `Equal` would collapse into one and an entry
    /// would silently vanish from the mempool's priority index. Entry ids are
    /// unique, so no two distinct entries can compare equal.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other
            .modified_fee_rate
            .cmp(&self.modified_fee_rate)
            .then_with(|| {
                other
                    .modified_ancestor_fee_rate
                    .cmp(&self.modified_ancestor_fee_rate)
            })
            .then_with(|| self.time.cmp(&other.time))
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl PartialOrd for ParetoKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ParetoKey {
    fn new(id: EntryId, entry: &MempoolEntry) -> Self {
        Self {
            id,
            modified_fee_rate: entry.modified_fee_rate(),
            modified_ancestor_fee_rate: entry.modified_ancestor_fee_rate(),
            time: entry.time,
        }
    }
}

impl ParetoFront {
    /// Creates an empty priority index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            order: BTreeSet::new(),
            keys: BTreeMap::new(),
        }
    }

    /// Inserts or replaces an entry in priority order.
    ///
    /// Replacement is not a special case for the caller but is one here: an
    /// entry whose ancestor fee rate changed has a different key, so the stale
    /// key must leave the ordered set or the entry would be indexed twice.
    pub fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
        let key = ParetoKey::new(id, entry);
        if let Some(previous) = self.keys.insert(id, key) {
            let _ = self.order.remove(&previous);
        }
        let _ = self.order.insert(key);
    }

    /// Removes an entry from the priority index.
    pub fn remove(&mut self, id: EntryId) -> bool {
        let Some(key) = self.keys.remove(&id) else {
            return false;
        };
        self.order.remove(&key)
    }

    /// Returns the highest-priority `n` entry identifiers.
    pub fn top_n(&self, n: usize) -> impl Iterator<Item = EntryId> + '_ {
        self.order.iter().take(n).map(|key| key.id)
    }

    /// Returns `true` if the front is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    /// Returns the number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.order.len()
    }
}
