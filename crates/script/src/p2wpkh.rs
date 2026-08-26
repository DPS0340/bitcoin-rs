//! SegWit v0 key-hash template helpers.
//!
//! The module shape follows `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0d83feb8f3b036937` (MIT OR Apache-2.0). BIP143
//! execution remains in the local evaluator and will consume this seam.

use bitcoin::Script;

/// Returns the HASH160 program for a version-0 P2WPKH output.
#[must_use]
pub(crate) fn program(script: &Script) -> Option<[u8; 20]> {
    let bytes = script.as_bytes();
    if bytes.len() != 22 || bytes[0] != 0x00 || bytes[1] != 0x14 {
        return None;
    }
    bytes[2..].try_into().ok()
}
