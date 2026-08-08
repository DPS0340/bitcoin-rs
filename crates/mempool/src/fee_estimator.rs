//! History-based fee-rate estimator modelled on Bitcoin Core's
//! `CBlockPolicyEstimator` but simplified.
//!
//! Maintains exponentially-spaced fee-rate buckets and records, per bucket,
//! how many blocks transactions waited before confirmation.
//! [`FeeEstimator::estimate`] returns the lowest fee rate whose historical
//! confirmation success rate clears a threshold, or [`None`] when there is
//! insufficient data.

use alloc::vec::Vec;

use bitcoin::Txid;
use hashbrown::HashMap;

/// Bucket fee-rate growth numerator: each bucket's lower bound is 5% above
/// the previous (`lower * 105 / 100`).
const BUCKET_GROWTH_NUM: u64 = 105;
/// Bucket fee-rate growth denominator.
const BUCKET_GROWTH_DEN: u64 = 100;
/// Minimum tracked fee rate: 1 sat/vB = 1 000 sat/kvB.
const MIN_FEE_RATE_SAT_PER_KVB: u64 = 1_000;
/// Maximum tracked fee rate: 1 000 sat/vB = 1 000 000 sat/kvB.
const MAX_FEE_RATE_SAT_PER_KVB: u64 = 1_000_000;
/// Maximum confirmation-target horizon in blocks.
const MAX_CONF_TARGET: usize = 25;
/// A bucket is suggested when >= 85% of historical transactions at or above
/// its fee rate confirmed within the target.
const SUCCESS_THRESHOLD: f64 = 0.85;
/// Per-block decay factor applied to all bucket counts.
const DECAY_FACTOR: f64 = 0.998;
/// Minimum decayed observation count required before producing an estimate.
const MIN_OBSERVATIONS: f64 = 1.0;
/// Maximum number of pending (unconfirmed) transaction entries tracked.
const MAX_PENDING_ENTRIES: usize = 10_000;

/// Fee rate in satoshis per kilo-virtual-byte (sat/kvB).
///
/// One sat/vB equals 1 000 sat/kvB. This unit matches
/// [`MempoolEntry`](crate::MempoolEntry).
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FeeRate(u64);

impl FeeRate {
    /// Returns the fee rate in sat/kvB.
    #[must_use]
    pub const fn as_sat_per_kvb(self) -> u64 {
        self.0
    }

    /// Returns the fee rate in sat/vB (truncated toward zero).
    #[must_use]
    pub const fn as_sat_per_vb(self) -> u64 {
        self.0 / 1_000
    }
}

/// Per-bucket confirmation statistics.
struct Bucket {
    /// Lower-bound fee rate for this bucket (sat/kvB).
    fee_rate_sat_per_kvb: u64,
    /// Decayed count of transactions confirmed within N blocks
    /// (index 0 = 1 block, index 24 = 25 blocks).
    confirmed_within: [f64; MAX_CONF_TARGET],
    /// Decayed count of all transactions observed in this bucket.
    total: f64,
}

impl Bucket {
    /// Creates a zeroed bucket at the given fee-rate lower bound.
    const fn new(fee_rate_sat_per_kvb: u64) -> Self {
        Self {
            fee_rate_sat_per_kvb,
            confirmed_within: [0.0; MAX_CONF_TARGET],
            total: 0.0,
        }
    }
}

/// Metadata for a pending (unconfirmed) transaction.
struct PendingEntry {
    /// Index into `buckets`.
    bucket_index: usize,
    /// Block height at which the transaction entered the mempool.
    entry_height: u32,
}

/// History-based fee estimator with exponential buckets and per-block decay.
///
/// Call [`FeeEstimator::tx_entered`] when a transaction enters the mempool
/// and [`FeeEstimator::block_connected`] for each connected block. Then use
/// [`FeeEstimator::estimate`] to obtain a fee-rate estimate for a given
/// confirmation target.
pub struct FeeEstimator {
    buckets: Vec<Bucket>,
    pending: HashMap<Txid, PendingEntry>,
}

impl FeeEstimator {
    /// Creates a new estimator with precomputed fee-rate buckets and no data.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: build_buckets(),
            pending: HashMap::new(),
        }
    }

    /// Records that a transaction entered the mempool.
    ///
    /// Call this when a transaction is accepted into the mempool.
    /// `fee_rate_sat_per_kvb` is the effective fee rate
    /// (fee / vsize * 1 000). `height` is the current block height.
    pub fn tx_entered(&mut self, txid: Txid, fee_rate_sat_per_kvb: u64, height: u32) {
        if self.pending.len() >= MAX_PENDING_ENTRIES {
            return;
        }
        let bucket_index = self.bucket_index_for_rate(fee_rate_sat_per_kvb);
        self.buckets[bucket_index].total += 1.0;
        self.pending.insert(
            txid,
            PendingEntry {
                bucket_index,
                entry_height: height,
            },
        );
    }

    /// Records confirmations from a connected block and applies decay.
    ///
    /// Call this for each connected block. `confirmed_txids` are the txids of
    /// transactions confirmed in that block. `block_height` is the height of
    /// the connected block. Transactions not tracked by the estimator are
    /// silently ignored.
    pub fn block_connected(&mut self, confirmed_txids: &[Txid], block_height: u32) {
        for txid in confirmed_txids {
            if let Some(entry) = self.pending.remove(txid) {
                let blocks_waited = block_height.saturating_sub(entry.entry_height).max(1);
                self.record_confirmation(entry.bucket_index, blocks_waited);
            }
        }
        self.apply_decay();
    }

    /// Estimates the minimum fee rate for confirmation within
    /// `conf_target_blocks`.
    ///
    /// Returns the lowest fee-rate bucket whose historical success rate at
    /// the given confirmation target clears the threshold (0.85), or [`None`]
    /// when there is insufficient data. A [`None`] result is an honest
    /// refusal — a fabricated estimate is worse than no estimate.
    #[must_use]
    pub fn estimate(&self, conf_target_blocks: u32) -> Option<FeeRate> {
        let target = usize::try_from(conf_target_blocks)
            .unwrap_or(0)
            .min(MAX_CONF_TARGET);
        if target == 0 {
            return None;
        }
        let target_idx = target - 1;
        let mut cumulative_confirmed = 0.0_f64;
        let mut cumulative_total = 0.0_f64;
        let mut result = None;
        for bucket in self.buckets.iter().rev() {
            cumulative_confirmed += bucket.confirmed_within[target_idx];
            cumulative_total += bucket.total;
            if cumulative_total >= MIN_OBSERVATIONS {
                let success_rate = cumulative_confirmed / cumulative_total;
                if success_rate >= SUCCESS_THRESHOLD {
                    result = Some(FeeRate(bucket.fee_rate_sat_per_kvb));
                }
            }
        }
        result
    }

    /// Returns the bucket index for a fee rate: the highest bucket whose
    /// lower bound is <= the given rate. Rates below the first bucket clamp
    /// to index 0.
    fn bucket_index_for_rate(&self, fee_rate_sat_per_kvb: u64) -> usize {
        let idx = self
            .buckets
            .partition_point(|b| b.fee_rate_sat_per_kvb <= fee_rate_sat_per_kvb);
        idx.saturating_sub(1)
    }

    /// Records a confirmation, incrementing all targets >= `blocks_waited`.
    fn record_confirmation(&mut self, bucket_index: usize, blocks_waited: u32) {
        let waited = usize::try_from(blocks_waited).unwrap_or(0);
        if waited == 0 || waited > MAX_CONF_TARGET {
            return;
        }
        let bucket = &mut self.buckets[bucket_index];
        for target in waited..=MAX_CONF_TARGET {
            bucket.confirmed_within[target - 1] += 1.0;
        }
    }

    /// Applies the per-block decay factor to all bucket counts.
    fn apply_decay(&mut self) {
        for bucket in &mut self.buckets {
            for count in &mut bucket.confirmed_within {
                *count *= DECAY_FACTOR;
            }
            bucket.total *= DECAY_FACTOR;
        }
    }
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self::new()
    }
}

/// Builds the exponentially-spaced fee-rate buckets.
fn build_buckets() -> Vec<Bucket> {
    let mut buckets = Vec::new();
    let mut lower = MIN_FEE_RATE_SAT_PER_KVB;
    while lower <= MAX_FEE_RATE_SAT_PER_KVB {
        buckets.push(Bucket::new(lower));
        let next = lower.saturating_mul(BUCKET_GROWTH_NUM) / BUCKET_GROWTH_DEN;
        if next <= lower {
            break;
        }
        lower = next;
    }
    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    fn test_txid(n: u8) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn no_data_yields_none() {
        let est = FeeEstimator::new();
        assert!(est.estimate(1).is_none());
        assert!(est.estimate(6).is_none());
        assert!(est.estimate(25).is_none());
    }

    #[test]
    fn low_fee_confirms_quickly_yields_low_estimate() {
        let mut est = FeeEstimator::new();
        for i in 0..10 {
            est.tx_entered(test_txid(i), 2_000, 100);
        }
        for i in 10..20 {
            est.tx_entered(test_txid(i), 100_000, 100);
        }
        let confirmed: Vec<Txid> = (0..20).map(test_txid).collect();
        est.block_connected(&confirmed, 101);
        let result = est.estimate(1).expect("should have an estimate");
        assert!(
            result.as_sat_per_kvb() <= 3_000,
            "estimate should be low, got {} sat/kvB",
            result.as_sat_per_kvb()
        );
    }

    #[test]
    fn never_confirms_yields_none() {
        let mut est = FeeEstimator::new();
        for i in 0..10 {
            est.tx_entered(test_txid(i), 5_000, 100);
        }
        assert!(est.estimate(1).is_none());
    }

    #[test]
    fn decay_reduces_influence_of_old_data() {
        let mut est = FeeEstimator::new();
        for i in 0..10 {
            est.tx_entered(test_txid(i), 5_000, 100);
        }
        let confirmed: Vec<Txid> = (0..10).map(test_txid).collect();
        est.block_connected(&confirmed, 101);
        assert!(
            est.estimate(1).is_some(),
            "should have estimate before decay"
        );
        for height in 102..6_102 {
            est.block_connected(&[], height);
        }
        assert!(
            est.estimate(1).is_none(),
            "estimate should be None after heavy decay"
        );
    }
}
