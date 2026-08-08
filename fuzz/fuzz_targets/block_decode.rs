#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz block deserialization.
///
/// Uses `bitcoin::consensus::encode::deserialize::<Block>`, the same function
/// the P2P wire codec calls for `block` command payloads (see
/// `crates/p2p/src/wire.rs` `decode_payload`).  This is the entry point the
/// node uses to turn inbound block bytes into a `bitcoin::Block`.
fuzz_target!(|data: &[u8]| {
    let _ = bitcoin::consensus::encode::deserialize::<bitcoin::Block>(data);
});
