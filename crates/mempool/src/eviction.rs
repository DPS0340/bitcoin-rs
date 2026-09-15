use alloc::vec::Vec;

use crate::Mempool;
use crate::mutation::{MutationChange, RemovalReason};

pub(crate) struct EvictionInputs {
    stamp: crate::pool::fee_policy::PolicyStamp,
    data: Option<(crate::MempoolMiningSnapshot, Vec<crate::EntryId>)>,
    size: u64,
    target: u64,
}

impl EvictionInputs {
    pub(crate) fn verify(self) -> Result<crate::rbf::PreparedPoolChange, crate::MempoolError> {
        let mut removals = Vec::new();
        if let Some((snapshot, ids)) = self.data {
            let chunks = snapshot.fee_chunks()?;
            let mut size = self.size;
            let mut selected = vec![false; snapshot.entries.len()];
            for chunk in chunks.iter().rev() {
                if size <= self.target {
                    break;
                }
                for &index in &chunk.indices {
                    selected[index] = true;
                    size = size
                        .checked_sub(u64::from(snapshot.entries[index].vsize))
                        .ok_or(crate::FeeDiagramError::Arithmetic)?;
                }
            }
            if size > self.target {
                return Err(crate::FeeDiagramError::Dependencies.into());
            }
            removals.extend(
                chunks
                    .iter()
                    .flat_map(|chunk| chunk.indices.iter().copied())
                    .filter(|&index| selected[index])
                    .map(|index| (ids[index], RemovalReason::PolicyEviction)),
            );
        }
        Ok(crate::rbf::PreparedPoolChange {
            stamp: self.stamp,
            evicted: Vec::new(),
            removals,
            entry: None,
        })
    }
}

impl Mempool {
    pub(crate) fn capture_eviction(
        &self,
        target: u64,
    ) -> Result<EvictionInputs, crate::MempoolError> {
        let size = self.total_vsize();
        let data = if size <= target {
            None
        } else {
            let snapshot = self.mining_snapshot();
            let ids = snapshot
                .entries
                .iter()
                .map(|entry| {
                    self.entry_id_by_txid(&entry.txid)
                        .ok_or(crate::MempoolError::FeeDiagram(
                            crate::FeeDiagramError::Dependencies,
                        ))
                })
                .collect::<Result<Vec<_>, _>>()?;
            Some((snapshot, ids))
        };
        Ok(EvictionInputs {
            stamp: self.policy_stamp(),
            data,
            size,
            target,
        })
    }
}

/// Evicts the lowest-fee dependency chunks until the pool fits.
/// The complete selection is validated before any mutation occurs.
pub fn evict_lowest_fee_packages(
    pool: &mut Mempool,
    target_size_bytes: u64,
) -> Result<Vec<MutationChange>, crate::MempoolError> {
    let plan = pool.capture_eviction(target_size_bytes)?.verify()?;
    pool.commit_pool_change(plan)
        .map(|result| result.changes)
        .map_err(crate::RbfError::into_pool_error)
}

/// Dynamic mempool minimum fee under size pressure, matching Core's
/// `mempoolminfee` heuristic used by `getmempoolinfo`.
///
/// When the pool occupies at least half of `max_total_bytes`, new admissions
/// must pay more than the cheapest currently-evictable entry by
/// `incremental_relay_fee_sat_per_kvb`. Below that pressure threshold the
/// configured min-relay fee is returned unchanged.
#[must_use]
pub fn mempool_min_fee_sat_per_kvb(pool: &Mempool, incremental_relay_fee_sat_per_kvb: u64) -> u64 {
    let maxmempool = pool.limits.max_total_bytes;
    let live_min_relay = pool.min_relay_fee_sat_per_kvb();
    if maxmempool > 0
        && pool.total_vsize().saturating_mul(2) >= maxmempool
        && let Some(lowest) = pool.lowest_fee_rate()
    {
        return live_min_relay.max(lowest.saturating_add(incremental_relay_fee_sat_per_kvb));
    }
    live_min_relay
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use alloc::sync::Arc;
    use bitcoin_rs_primitives::{
        Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use super::{evict_lowest_fee_packages, mempool_min_fee_sat_per_kvb};
    use crate::mutation::{MutationChange, MutationOutcome, RemovalReason};
    use crate::{Mempool, MempoolEntry, MempoolLimits};

    #[test]
    fn mempool_min_fee_equals_min_relay_below_half_full() {
        let pool = Mempool::new(MempoolLimits {
            max_total_bytes: 1_000,
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 1_000);
    }

    #[test]
    fn mempool_min_fee_rises_above_cheapest_when_at_least_half_full() {
        let mut pool = Mempool::new(MempoolLimits {
            max_total_bytes: 400,
            min_relay_fee_sat_per_kvb: 1_000,
            ..MempoolLimits::default()
        });
        // 200 vbytes is exactly half of 400 — pressure threshold.
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1))
            .expect("insert");
        // fee_rate = 400 * 1000 / 200 = 2_000 sat/kvB
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 3_000);
    }

    #[test]
    fn eviction_removes_lowest_descendant_package_first() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 10_000,
            ..MempoolLimits::default()
        });
        let high = MempoolEntry::new(Arc::new(tx(2)), 100, 10_000, 1, 1);
        let low = MempoolEntry::new(Arc::new(tx(3)), 100, 1_000, 2, 1);
        pool.insert_entry(high).expect("high");
        pool.insert_entry(low).expect("low");

        let evicted = evict_lowest_fee_packages(&mut pool, 100).expect("eviction policy");
        assert_eq!(
            evicted,
            vec![MutationChange {
                txid: Hash256::from_le_bytes(tx(3).txid().as_bytes()),
                outcome: MutationOutcome::Removed(RemovalReason::PolicyEviction),
            }],
            "the lowest-fee package leaves first, tagged PolicyEviction"
        );
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn eviction_raises_lowest_fee_rate_and_mempool_min_fee() {
        let mut pool = Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        });
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1))
            .expect("low");
        pool.insert_entry(MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1))
            .expect("high");
        assert_eq!(pool.lowest_fee_rate(), Some(2_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 3_000);

        let evicted = evict_lowest_fee_packages(&mut pool, 200).expect("eviction policy");
        assert_eq!(evicted.len(), 1);
        assert_eq!(pool.lowest_fee_rate(), Some(4_000));
        assert_eq!(mempool_min_fee_sat_per_kvb(&pool, 1_000), 5_000);
    }

    fn tx(label: u8) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: vec![0x51, label].into(),
            }],
        }
    }
}
