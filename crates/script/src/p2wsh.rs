//! SegWit v0 script-hash template helpers.
//!
//! The boundary is adapted from `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937` (MIT OR Apache-2.0). The local
//! evaluator owns witness-script execution and uses this only for dispatch.

use bitcoin::Script;

/// Returns the SHA256 program for a version-0 P2WSH output.
#[must_use]
pub(crate) fn program(script: &Script) -> Option<[u8; 32]> {
    let bytes = script.as_bytes();
    if bytes.len() != 34 || bytes[0] != 0x00 || bytes[1] != 0x20 {
        return None;
    }
    bytes[2..].try_into().ok()
}
