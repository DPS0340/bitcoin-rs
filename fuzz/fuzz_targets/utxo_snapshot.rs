#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

/// Fuzz the UTXO snapshot deserializer.
///
/// Feeds arbitrary bytes as a native bitcoin-rs UTXO snapshot via
/// `read_snapshot` in `crates/utxo/src/snapshot.rs`.  This is the deserializer
/// that runs against on-disk state after a crash.  The function does not
/// pre-allocate from untrusted count fields, so arbitrary input is safe.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::snapshot::read_snapshot(&mut cursor);
});
