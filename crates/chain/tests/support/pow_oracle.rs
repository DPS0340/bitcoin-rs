//! Differential proof-of-work oracle shared by the chain integration tests.
//!
//! The oracle deliberately rides on the `bitcoin` crate's own compact-target
//! decode and comparison, not on `bitcoin_rs_chain::compact_is_met_by`: it is
//! differential against the code under test, so independence from the
//! implementation is its purpose.

use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{BlockHash, CompactTarget};

/// Checks that the header hash satisfies the compact target, using bitcoin's
/// compact-target decode and comparison.
pub(crate) fn pow_is_met(bits: CompactTarget, hash: &BlockHash) -> bool {
    let target = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(
        bits.to_consensus(),
    ));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}
