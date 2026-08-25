use std::collections::{BTreeMap, BinaryHeap, HashSet};

use bitcoin_rs_mempool::{EntryId as MempoolEntryId, Mempool};

/// Weight Bitcoin Core holds back for the coinbase transaction.
///
/// `DEFAULT_BLOCK_RESERVED_WEIGHT` in `policy/policy.h`. Selection runs against
/// `max_weight - reserved`, while the template still advertises the full
/// `weightlimit`: the miner is told what a block may weigh, and the space its
/// own coinbase will need is kept out of what we hand it. Filling the whole
/// four million and then adding a coinbase produces an oversize block.
pub const DEFAULT_BLOCK_RESERVED_WEIGHT: u32 = 8_000;

/// Sigop cost Bitcoin Core holds back for the coinbase transaction.
///
/// `DEFAULT_COINBASE_OUTPUT_MAX_ADDITIONAL_SIGOPS` in `policy/policy.h`, which
/// its assembler seeds `nBlockSigOpsCost` with before selecting anything. The
/// counterpart to [`DEFAULT_BLOCK_RESERVED_WEIGHT`], and needed for the same
/// reason: a miner's payout script may contain `CHECKSIG`, and a selection that
/// spent the whole consensus budget would push the finished block over it.
pub const DEFAULT_COINBASE_RESERVED_SIGOPS: u32 = 400;

/// Transaction selection policy for candidate block assembly.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MiningPolicy;

/// A candidate and the package score it was last ranked by.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Ranked {
    /// Package fee, in satoshis, of the ancestors still needed plus itself.
    fee: u64,
    /// Package vsize, in virtual bytes, of the same set.
    vsize: u64,
    /// The candidate's own fee rate, for the first tie-break.
    own_fee_rate: u64,
    /// Acceptance time, for the second.
    time: u64,
    /// Entry id, so the order is total.
    id: MempoolEntryId,
}

impl Ranked {
    /// Orders by package fee rate without dividing.
    ///
    /// `a.fee / a.vsize` against `b.fee / b.vsize` as `a.fee * b.vsize` against
    /// `b.fee * a.vsize`: integer division would collapse packages that differ
    /// by less than one satoshi per vbyte into ties, and the tie-break would
    /// then decide by age what the fee should have decided.
    fn cmp_by_package_fee_rate(&self, other: &Self) -> core::cmp::Ordering {
        let left = u128::from(self.fee).saturating_mul(u128::from(other.vsize.max(1)));
        let right = u128::from(other.fee).saturating_mul(u128::from(self.vsize.max(1)));
        left.cmp(&right)
            .then_with(|| self.own_fee_rate.cmp(&other.own_fee_rate))
            .then_with(|| other.time.cmp(&self.time))
            .then_with(|| other.id.cmp(&self.id))
    }
}

impl Ord for Ranked {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.cmp_by_package_fee_rate(other)
    }
}

impl PartialOrd for Ranked {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl MiningPolicy {
    /// Selects mempool transactions for a candidate block.
    ///
    /// Ancestor-package selection, as in Bitcoin Core's `addPackageTxs`:
    /// candidates are considered in descending **ancestor** fee-rate order,
    /// and a candidate is taken together with every unconfirmed ancestor it
    /// still needs. Two properties follow, and neither held before:
    ///
    /// - **The result is topologically ordered.** A parent always precedes its
    ///   child, so a miner can serialize the list as-is.
    /// - **No child is taken without its parents.** A package that does not
    ///   fit is skipped whole rather than truncated mid-way.
    ///
    /// Fee-rate order alone gave neither: a high-fee child sorted ahead of the
    /// low-fee parent it depends on, and the weight cut-off could land between
    /// them. Both produce a template that cannot be mined.
    ///
    /// Ordering by ancestor fee rate is also what makes child-pays-for-parent
    /// work — a child's fee lifts its parent into the block instead of being
    /// discarded with it.
    ///
    /// **Candidates are re-ranked as ancestors are taken.** Once a shared
    /// parent is in the block, a sibling that depended on it is no longer
    /// paying for that parent, so its package is smaller and its fee rate
    /// higher than the order it was first given. Ranking once and never again
    /// leaves fee on the table: at a tight boundary a cheap shared parent with
    /// two children loses to an independent transaction worth less than either
    /// of them. Core keeps the same accounting in `mapModifiedTx` and updates
    /// it in `UpdatePackagesForAdded`.
    ///
    /// Re-ranking is pushed, not pulled. Taking a package can only ever raise
    /// what its descendants are worth, and a score that rises is invisible to a
    /// queue that only re-checks whatever already reached the front. So each
    /// accepted package re-scores exactly its descendants and pushes them back
    /// in; the entries they supersede are recognised on the way out and
    /// dropped.
    ///
    /// `max_weight` is the selection budget, which the caller is expected to
    /// have already reduced by [`DEFAULT_BLOCK_RESERVED_WEIGHT`]. `max_sigops`
    /// is likewise expected to be reduced by
    /// [`DEFAULT_COINBASE_RESERVED_SIGOPS`].
    #[must_use]
    pub fn select_transactions(
        &self,
        mempool: &Mempool,
        max_weight: u32,
        max_sigops: u32,
    ) -> Vec<MempoolEntryId> {
        let (mut queue, mut current) = initial_ranking(mempool);
        let mut selected = Vec::with_capacity(queue.len());
        let mut included = HashSet::with_capacity(queue.len());
        let mut weight = 0_u64;
        let mut sigops = 0_u64;
        let weight_budget = u64::from(max_weight);
        let sigop_budget = u64::from(max_sigops);

        while let Some(ranked) = queue.pop() {
            if included.contains(&ranked.id) {
                continue;
            }
            // A superseded copy of a candidate that has since been re-scored.
            // Taking it twice is already impossible -- `included` above sees to
            // that -- so this only saves re-attempting a package at a price
            // that has been replaced. A mutation audit could not distinguish
            // dropping it, which is recorded rather than hidden: the guard is
            // there to keep the queue honest, not to hold a property up.
            if current.get(&ranked.id) != Some(&ranked) {
                continue;
            }
            let Some(package) = ancestor_package(mempool, ranked.id, &included) else {
                continue;
            };
            let Some((package_weight, package_sigops)) = package_cost(mempool, &package) else {
                continue;
            };
            let next_weight = weight.saturating_add(package_weight);
            let next_sigops = sigops.saturating_add(package_sigops);
            if next_weight > weight_budget || next_sigops > sigop_budget {
                // Skip rather than stop: a later, smaller package can still
                // fit in what is left. Core's assembler does the same.
                continue;
            }
            weight = next_weight;
            sigops = next_sigops;
            for member in &package {
                included.insert(*member);
                selected.push(*member);
                let _dropped = current.remove(member);
            }
            // Everything downstream of what was just taken now owes less.
            for id in descendants_of(mempool, &package, &included) {
                let Some(rescored) = ancestor_package(mempool, id, &included)
                    .and_then(|package| rank_package(mempool, id, &package))
                else {
                    continue;
                };
                if current.insert(id, rescored) != Some(rescored) {
                    queue.push(rescored);
                }
            }
        }

        selected
    }
}

/// Every entry, ranked by its full ancestor package to begin with.
///
/// The map carries the score each candidate is currently ranked by, so a copy
/// popped from the queue after a re-score can be told apart from the live one.
fn initial_ranking(mempool: &Mempool) -> (BinaryHeap<Ranked>, BTreeMap<MempoolEntryId, Ranked>) {
    let ranked = mempool
        .entries
        .iter()
        .filter_map(|(index, entry)| {
            let id = MempoolEntryId::try_from(index).ok()?;
            Some(Ranked {
                fee: entry.ancestor_fee,
                vsize: entry.ancestor_size,
                own_fee_rate: entry.fee_rate,
                time: entry.time,
                id,
            })
        })
        .collect::<Vec<_>>();
    let current = ranked.iter().map(|entry| (entry.id, *entry)).collect();
    (ranked.into_iter().collect(), current)
}

/// Every not-yet-included entry downstream of `roots`, transitively.
///
/// Bitcoin Core's `CalculateDescendants`, reached from `UpdatePackagesForAdded`.
/// The walk is over the spend index -- a transaction is a child of `roots` when
/// it spends one of their outputs -- and the depth is bounded by the mempool's
/// descendant limit.
fn descendants_of(
    mempool: &Mempool,
    roots: &[MempoolEntryId],
    included: &HashSet<MempoolEntryId>,
) -> Vec<MempoolEntryId> {
    let mut found = HashSet::new();
    let mut ordered = Vec::new();
    let mut frontier: Vec<MempoolEntryId> = roots.to_vec();

    while let Some(id) = frontier.pop() {
        let Some(entry) = mempool.entry(id) else {
            continue;
        };
        let low = (bitcoin::OutPoint::new(entry.txid, 0), MempoolEntryId::MIN);
        let high = (
            bitcoin::OutPoint::new(entry.txid, u32::MAX),
            MempoolEntryId::MAX,
        );
        for (_outpoint, child) in mempool.spending.range(low..=high) {
            if included.contains(child) || !found.insert(*child) {
                continue;
            }
            ordered.push(*child);
            frontier.push(*child);
        }
    }
    ordered
}

/// Scores `id` by the package it still needs, not the one it started with.
fn rank_package(
    mempool: &Mempool,
    id: MempoolEntryId,
    package: &[MempoolEntryId],
) -> Option<Ranked> {
    let mut fee = 0_u64;
    let mut vsize = 0_u64;
    for member in package {
        let entry = mempool.entry(*member)?;
        fee = fee.saturating_add(entry.fee);
        vsize = vsize.saturating_add(u64::from(entry.vsize));
    }
    let entry = mempool.entry(id)?;
    Some(Ranked {
        fee,
        vsize,
        own_fee_rate: entry.fee_rate,
        time: entry.time,
        id,
    })
}

/// `id` and every unconfirmed ancestor not already included, parents first.
///
/// Returns `None` if any member has vanished from the pool, which drops the
/// whole package rather than emitting a partial one.
fn ancestor_package(
    mempool: &Mempool,
    id: MempoolEntryId,
    included: &HashSet<MempoolEntryId>,
) -> Option<Vec<MempoolEntryId>> {
    let mut ordered = Vec::new();
    let mut visited = HashSet::new();
    visit_ancestors(mempool, id, included, &mut visited, &mut ordered)?;
    Some(ordered)
}

/// Post-order depth-first walk over the parents, which is a topological sort.
///
/// Depth is bounded by the mempool's ancestor limit (25 by default), so this
/// cannot run away. Entry ids are deliberately not used as a stand-in for
/// dependency order: the pool's arena reuses freed slots, so a parent accepted
/// after a slab slot was released can hold a **higher** id than its own child.
fn visit_ancestors(
    mempool: &Mempool,
    id: MempoolEntryId,
    included: &HashSet<MempoolEntryId>,
    visited: &mut HashSet<MempoolEntryId>,
    ordered: &mut Vec<MempoolEntryId>,
) -> Option<()> {
    if included.contains(&id) || !visited.insert(id) {
        return Some(());
    }
    let entry = mempool.entry(id)?;
    for input in &entry.tx.input {
        if let Some(parent) = mempool.by_txid.get(&input.previous_output.txid) {
            visit_ancestors(mempool, *parent, included, visited, ordered)?;
        }
    }
    ordered.push(id);
    Some(())
}

/// Total weight and sigop cost of a package.
fn package_cost(mempool: &Mempool, package: &[MempoolEntryId]) -> Option<(u64, u64)> {
    let mut weight = 0_u64;
    let mut sigops = 0_u64;
    for id in package {
        let entry = mempool.entry(*id)?;
        weight = weight.saturating_add(entry.tx.weight().to_wu());
        sigops = sigops.saturating_add(u64::from(entry.sigop_cost));
    }
    Some((weight, sigops))
}
