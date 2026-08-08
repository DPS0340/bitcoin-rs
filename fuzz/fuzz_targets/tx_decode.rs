#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz transaction deserialization.
///
/// Uses `bitcoin::consensus::encode::deserialize::<Transaction>`, the same
/// function the P2P wire codec calls for `tx` command payloads (see
/// `crates/p2p/src/wire.rs` `decode_payload`).
fuzz_target!(|data: &[u8]| {
    let _ = bitcoin::consensus::encode::deserialize::<bitcoin::Transaction>(data);
});
