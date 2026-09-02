#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

/// Fuzz the complete version-4 snapshot contract used by checkpoint loading.
/// Both entry points reject unsupported versions, malformed records, missing
/// trailers, and trailing bytes.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut cursor);

    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut cursor, ());
});
