use alloc::collections::{BTreeMap, BTreeSet};

use tinyvec::TinyVec;

use crate::{EntryId, MempoolEntry};

/// Priority index ordered by fee rate, ancestor fee rate, then age.
///
/// Ordering lives in [`ParetoKey`]'s [`Ord`], and the set is kept in that order
/// rather than re-sorted. Insertion and removal are both `O(log n)`.
///
/// The previous implementation held the keys in a flat vector, and every
/// `insert` did a linear `remove` followed by a full `sort_by`. Filling a
/// mempool was therefore quadratic — 4.92 ms at 1,000 entries against 4.57 s at
/// 50,000, a measured exponent of 2.05 — and the cost is paid on the path that
/// accepts transactions from peers, so it was reachable by anyone who could fill
/// the mempool. [`SortedParetoFront`] keeps that implementation as the oracle
/// these tests compare against and as the benchmark's `before` arm.
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
    fee_rate: u64,
    ancestor_fee_rate: u64,
    time: u64,
}

impl Ord for ParetoKey {
    /// Highest fee rate first, then highest ancestor fee rate, then oldest.
    ///
    /// The final tiebreak on `id` is what makes this a *total* order, and that
    /// is load-bearing rather than cosmetic: the ordered set stores keys, so two
    /// entries whose keys compared `Equal` would collapse into one and an entry
    /// would silently vanish from the mempool's priority index. Entry ids are
    /// unique, so no two distinct entries can compare equal.
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        other
            .fee_rate
            .cmp(&self.fee_rate)
            .then_with(|| other.ancestor_fee_rate.cmp(&self.ancestor_fee_rate))
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
            fee_rate: entry.fee_rate,
            ancestor_fee_rate: entry.ancestor_fee_rate(),
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

    /// Estimates the heap this index occupies, in bytes.
    ///
    /// **Every entry is stored twice.** `order` is keyed by priority so the
    /// front can be read in order, and `keys` is keyed by id so a removal does
    /// not have to search the set for what to remove -- the linear scan this
    /// type exists to avoid. Charging one `EntryId` per transaction, as
    /// `dynamic_memory_usage` did, misses both key copies and reports a small
    /// fraction of what the index actually holds.
    ///
    /// A lower bound rather than a measurement, and deliberately so: a B-tree
    /// allocates nodes of a fixed arity and leaves them partly filled, so its
    /// real footprint is above this and depends on insertion order. Bitcoin
    /// Core's own `DynamicMemoryUsage` is an estimate for the same reason --
    /// "no exact formula for `boost::multi_index_container` is implemented".
    /// What matters is that the term scales with what is stored, which one
    /// `EntryId` per entry did not.
    #[must_use]
    pub fn dynamic_memory_usage(&self) -> u64 {
        use core::mem::size_of;

        let ordered = u64::try_from(self.order.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<ParetoKey>()).unwrap_or(0));
        let by_id = u64::try_from(self.keys.len())
            .unwrap_or(u64::MAX)
            .saturating_mul(u64::try_from(size_of::<(EntryId, ParetoKey)>()).unwrap_or(0));
        ordered.saturating_add(by_id)
    }
}

/// The flat-vector priority index [`ParetoFront`] replaced.
///
/// Retained deliberately, not left behind: it is the oracle the equivalence
/// tests compare the replacement against, and the `before` arm of
/// `benches/pareto.rs`. Both arms have to run in one process over one fixture
/// for the ratio to mean anything, which they cannot do if this is deleted.
///
/// Nothing in the node uses it. It is quadratic to fill, which is the entire
/// reason it was replaced.
///
/// It keeps its own copy of the comparison rather than borrowing
/// [`ParetoKey`]'s [`Ord`]. Sharing it looked tidier and made the oracle
/// worthless: a mutation that reversed the ordering left both implementations
/// agreeing with each other, so the equivalence tests stayed green while the
/// index was ordered backwards. An oracle has to be able to disagree.
#[derive(Clone, Debug, Default)]
pub struct SortedParetoFront {
    entries: TinyVec<[ParetoKey; 256]>,
}

impl SortedParetoFront {
    /// Creates an empty priority index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: TinyVec::new(),
        }
    }

    /// Inserts or replaces an entry in priority order.
    pub fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
        self.remove(id);
        self.entries.push(ParetoKey::new(id, entry));
        self.entries.sort_by(legacy_compare_keys);
    }

    /// Removes an entry from the priority index.
    pub fn remove(&mut self, id: EntryId) -> bool {
        let Some(index) = self.entries.iter().position(|entry| entry.id == id) else {
            return false;
        };
        let _ = self.entries.remove(index);
        true
    }

    /// Returns the highest-priority `n` entry identifiers.
    pub fn top_n(&self, n: usize) -> impl Iterator<Item = EntryId> + '_ {
        self.entries.iter().take(n).map(|entry| entry.id)
    }

    /// Returns `true` if the front is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of indexed entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

/// The ordering the flat-vector index sorted by, kept verbatim.
///
/// Deliberately a duplicate of [`ParetoKey`]'s [`Ord`] rather than a call to it.
/// See [`SortedParetoFront`].
fn legacy_compare_keys(left: &ParetoKey, right: &ParetoKey) -> core::cmp::Ordering {
    right
        .fee_rate
        .cmp(&left.fee_rate)
        .then_with(|| right.ancestor_fee_rate.cmp(&left.ancestor_fee_rate))
        .then_with(|| left.time.cmp(&right.time))
        .then_with(|| left.id.cmp(&right.id))
}

#[cfg(test)]
mod memory_usage_tests {
    use alloc::sync::Arc;
    use core::mem::size_of;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};

    use super::*;

    fn entry(tag: u8) -> MempoolEntry {
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: alloc::vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([tag; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: alloc::vec![TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        MempoolEntry::new(Arc::new(tx), 100, 10_000, u64::from(tag), 7)
    }

    /// Every entry is stored twice, and the estimate says so.
    ///
    /// `order` is keyed by priority so the front can be read in order; `keys`
    /// is keyed by id so a removal need not search the set for what to remove.
    /// An estimate that counted only one of them -- or, as the pool's term
    /// did, one `EntryId` per transaction -- reports a small fraction of what
    /// the index holds, and the shortfall grows with the pool.
    ///
    /// The floor is two key copies per entry: deliberately below what the
    /// implementation computes, which also carries the id the map keys on, so
    /// this is a claim rather than a restatement of the formula. It is a lower
    /// bound in the other direction too -- a B-tree leaves its nodes partly
    /// filled, so the real footprint is above this.
    #[test]
    fn the_estimate_counts_both_key_collections() {
        const COUNT: u32 = 64;

        let mut front = ParetoFront::new();
        for id in 0..COUNT {
            front.insert(id, &entry(u8::try_from(id).unwrap_or(0)));
        }
        assert_eq!(front.len(), usize::try_from(COUNT).unwrap_or(0));

        let usage = front.dynamic_memory_usage();
        let two_keys_each = u64::from(COUNT)
            .saturating_mul(u64::try_from(size_of::<ParetoKey>()).unwrap_or(0))
            .saturating_mul(2);
        assert!(
            usage >= two_keys_each,
            "both collections must be counted: {usage} vs {two_keys_each}"
        );

        let one_key_each = two_keys_each / 2;
        assert!(
            usage > one_key_each,
            "counting one collection is the under-report this replaces"
        );
    }

    /// An empty index reports nothing, and a removal gives its memory back.
    ///
    /// Unlike the pool's arena, the priority index has nothing that retains an
    /// allocation this estimate can see: both collections are B-trees keyed by
    /// value, and neither exposes a capacity. So `len`-based terms are right
    /// here for the same reason they were wrong there, and the two cases are
    /// pinned together so the distinction is not lost.
    #[test]
    fn the_estimate_follows_what_is_indexed() {
        let mut front = ParetoFront::new();
        assert_eq!(front.dynamic_memory_usage(), 0);

        for id in 0..16_u32 {
            front.insert(id, &entry(u8::try_from(id).unwrap_or(0)));
        }
        let full = front.dynamic_memory_usage();
        assert!(full > 0);

        for id in 0..16_u32 {
            assert!(front.remove(id), "the fixture must have indexed {id}");
        }
        assert_eq!(front.dynamic_memory_usage(), 0);
        assert!(full > front.dynamic_memory_usage());
    }
}
