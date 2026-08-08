#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;

/// Fuzz the UTXO snapshot readers the checkpoint path actually uses.
///
/// `crates/node/src/checkpoint.rs` loads through `read_snapshot_strict_v4` and
/// `read_snapshot_strict_v4_observed`. This target used to call the legacy
/// `read_snapshot`, whose policy accepts v2 and v3, tolerates a missing
/// trailer, skips the strict record-count check, and permits trailing bytes —
/// so every rule that only the production policy enforces, and the observer
/// dispatch that runs after a restart, got no coverage at all while the target
/// claimed to exercise on-disk crash state.
///
/// Both entry points run on the same input: they share a decoder but differ in
/// the trailer path, and the observer variant is what the checkpoint uses when
/// it needs the coin accumulator.
fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::snapshot::read_snapshot_strict_v4(&mut cursor);

    let mut cursor = Cursor::new(data);
    let _ = bitcoin_rs_utxo::read_snapshot_strict_v4_observed(&mut cursor, ());
});
