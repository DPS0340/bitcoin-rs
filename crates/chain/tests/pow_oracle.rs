//! Differential proof-of-work oracle shared by the chain integration tests.
//!
//! The oracle deliberately rides on the `bitcoin` crate's own compact-target
//! decode and comparison, not on `bitcoin_rs_chain::compact_is_met_by`: it is
//! differential against the code under test, so independence from the
//! implementation is its purpose.

use bitcoin::hashes::Hash as _;
use bitcoin_rs_primitives::{BlockHash, CompactTarget, Network};

/// Checks that the header hash satisfies the compact target, using bitcoin's
/// compact-target decode and comparison.
pub(crate) fn pow_is_met(bits: CompactTarget, hash: &BlockHash) -> bool {
    let target = bitcoin::pow::Target::from_compact(bitcoin::pow::CompactTarget::from_consensus(
        bits.to_consensus(),
    ));
    target.is_met_by(bitcoin::BlockHash::from_byte_array(*hash.as_bytes()))
}

#[test]
fn oracle_accepts_genesis_and_rejects_a_far_hash() {
    let genesis = Network::Regtest.genesis_block();
    assert!(
        pow_is_met(genesis.header.bits, &genesis.block_hash()),
        "the regtest genesis must meet its own compact target"
    );
    let far_hash = BlockHash(bitcoin_rs_primitives::Hash256::from_le_bytes(
        &[0xff_u8; 32],
    ));
    assert!(
        !pow_is_met(genesis.header.bits, &far_hash),
        "an all-ones hash must exceed the regtest target"
    );
    // Byte order is the oracle's load-bearing detail: a hash encoding 2^255
    // in little-endian bytes exceeds the regtest target, while the same
    // bytes read big-endian are 128 — far below it.
    let mut le_bytes = [0_u8; 32];
    le_bytes[31] = 0x80;
    let le_2_pow_255 = BlockHash(bitcoin_rs_primitives::Hash256::from_le_bytes(&le_bytes));
    assert!(
        !pow_is_met(genesis.header.bits, &le_2_pow_255),
        "a hash encoding 2^255 little-endian must exceed the regtest target"
    );
}
