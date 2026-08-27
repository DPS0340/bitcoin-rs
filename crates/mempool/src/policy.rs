use thiserror::Error;

/// Mempool ancestor, descendant, and replacement limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MempoolLimits {
    /// Maximum number of transactions in an ancestor package, including the transaction itself.
    pub max_ancestors: u32,
    /// Maximum ancestor package virtual size in vbytes.
    pub max_ancestor_size: u64,
    /// Maximum number of transactions in a descendant package, including the transaction itself.
    pub max_descendants: u32,
    /// Maximum number of transactions a single BIP125 replacement may evict.
    pub max_replacement_evictions: u32,
    /// Maximum total mempool size in vbytes. Default 300 MB (Bitcoin Core default).
    /// Set to 0 to disable size-bound eviction.
    pub max_total_bytes: u64,
    /// Minimum relay fee rate in sat/kvB. Transactions with lower `fee_rate` are
    /// not relayed. Default 1000 sat/kvB = 1 sat/vB (Bitcoin Core default).
    pub min_relay_fee_sat_per_kvb: u64,
    /// Maximum number of transactions in one cluster, including the candidate.
    ///
    /// A cluster is the set of mempool transactions directly or indirectly
    /// connected to a transaction through spends -- a connected component of
    /// the spend graph, not an ancestor package. Two children of one parent
    /// share a cluster although neither is an ancestor of the other.
    ///
    /// Core's `-limitclustercount`, `DEFAULT_CLUSTER_LIMIT` (`policy.h`).
    pub cluster_count: u32,
    /// Maximum virtual size of one cluster in vbytes, including the candidate.
    ///
    /// Core's `-limitclustersize`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB * 1000`
    /// (`policy.h`, `kernel/mempool_limits.h`).
    pub cluster_size_vbytes: u64,
}

impl Default for MempoolLimits {
    fn default() -> Self {
        Self {
            max_ancestors: 25,
            max_ancestor_size: 101_000,
            max_descendants: 25,
            max_replacement_evictions: 100,
            max_total_bytes: 300_000_000,
            min_relay_fee_sat_per_kvb: 1_000,
            cluster_count: 64,
            // 101 kvB, the same number `max_ancestor_size` carries. The
            // coincidence is why ancestor limits look like a stand-in for
            // cluster limits and are not one: Core 31 deprecated
            // `-limitancestorcount`/`-limitdescendantcount` and replaced them
            // with these, keeping the old ones only for wallet coin selection.
            cluster_size_vbytes: 101_000,
        }
    }
}

/// Policy rejection reason for non-consensus mempool limits.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PolicyError {
    /// The transaction would exceed the configured ancestor count limit.
    #[error("too many unconfirmed ancestors")]
    TooManyAncestors,
    /// Transaction's `fee_rate` is below the configured min-relay-fee floor.
    #[error("fee rate {tx_rate} sat/kvB below min-relay-fee {min_rate} sat/kvB")]
    BelowMinRelayFee {
        /// The transaction's effective `fee_rate` in sat/kvB.
        tx_rate: u64,
        /// The configured min-relay-fee floor.
        min_rate: u64,
    },
    /// The transaction would exceed the configured ancestor package size limit.
    #[error("ancestor package is too large")]
    AncestorSizeLimit,
    /// The transaction would exceed a configured descendant count limit.
    #[error("too many unconfirmed descendants")]
    TooManyDescendants,
    /// The transaction would join a cluster holding too many transactions.
    #[error("too many transactions in cluster")]
    ClusterCountLimit,
    /// The transaction would join a cluster exceeding the virtual size limit.
    #[error("cluster is too large")]
    ClusterSizeLimit,
}
