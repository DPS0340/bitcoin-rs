#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

/// Fuzz the Bitcoin P2P wire message decoder.
///
/// Feeds arbitrary bytes as a complete v1 network message stream and exercises
/// `read_message`, the same entry point the node's inbound listener uses.
/// The `Result` is consumed without `unwrap` so panics in the decoder surface
/// as fuzzer findings rather than harness crashes.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let magic = bitcoin::p2p::Magic::REGTEST;
    let _ = bitcoin_rs_p2p::wire::read_message(&mut cursor, magic);
});
