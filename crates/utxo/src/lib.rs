//! In-memory UTXO set for bitcoin-rs.
//!
//! The set is split into 256 first-byte shards. Each shard stores compact,
//! transaction-level `UtxoRecord` owners inline in a `hashbrown::HashTable`;
//! every record owns one boxed encoded payload and mutations are guarded by a
//! cache-padded `parking_lot::RwLock`.

#![forbid(unsafe_op_in_unsafe_fn)]

/// UTXO hash-table key.
pub mod key;
/// Owned UTXO records.
pub mod record;
/// UTXO-set mutations and lookup.
pub mod set;
/// Shard internals.
pub mod shard;
/// Native bitcoin-rs UTXO snapshot format.
pub mod snapshot;

pub use key::{UtxoBuildHasher, UtxoKey};
pub use record::{OneUtxoOut, UtxoRecord};
pub use set::{
    BlockChanges, ScannedUtxo, UndoBatch, UtxoAdd, UtxoChangeListener, UtxoError, UtxoInserted,
    UtxoRemoved, UtxoScan, UtxoSet, UtxoSetView,
};
pub use shard::{LiveOutput, LiveOutputMeta};
pub use snapshot::{
    SnapshotCoin, SnapshotCoinObserver, SnapshotLoad, aggregate_hash, hash_serialized_3,
    read_snapshot, read_snapshot_strict_v4_observed, write_snapshot, write_snapshot_observed,
};
