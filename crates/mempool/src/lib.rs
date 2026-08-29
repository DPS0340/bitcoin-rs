#![doc = include_str!("../README.md")]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

/// Mempool entry metadata.
pub mod entry;
/// Package eviction policy.
pub mod eviction;
/// Fee-rate history-based fee-rate estimator.
pub mod fee_estimator;
/// Single mutation gateway and observer seam in front of the pool.
pub mod gateway;
/// Mutation records returned by every mutating pool method.
pub mod mutation;
/// Orphan transaction pool for transactions with missing parents.
pub mod orphan;
/// Pareto-front transaction priority ordering.
pub mod pareto;
/// Mempool policy limits.
pub mod policy;
/// Mempool indexes and mutation API.
pub mod pool;
/// BIP125 replacement-by-fee checks.
pub mod rbf;
/// Transaction relay standardness policy.
pub mod standardness;

pub use entry::{EntryId, MempoolEntry};
pub use eviction::evict_lowest_fee_packages;
pub use fee_estimator::{FeeEstimator, FeeRate};
pub use gateway::{MempoolGateway, MempoolObserver};
pub use mutation::{MutationChange, MutationOutcome, MutationResult, RemovalReason};
pub use pareto::{ParetoFront, SortedParetoFront};
pub use policy::{MempoolLimits, MempoolPolicySnapshot, PolicyError};
pub use pool::{
    Mempool, MempoolError, MempoolMiningSnapshot, MempoolStats, PrioritiseError, ScriptHash,
    SnapshotEntry,
};
pub use rbf::{RbfError, ReplacementCandidate, ReplacementPlan};
