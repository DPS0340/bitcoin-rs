//! RPC re-exports for the index-owned capability status contract.

pub use bitcoin_rs_index::{
    CapabilitySnapshot, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    TXINDEX_CAPABILITY, derived_index_status, disabled_txindex, txindex_snapshot,
};
