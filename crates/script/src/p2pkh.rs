//! P2PKH template recognition and hash extraction.
//!
//! Shape adapted from `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0d83feb8f3b036937` (MIT OR Apache-2.0), with the
//! local API kept independent of that project.

use bitcoin::Script;

/// Returns the HASH160 payload of a canonical P2PKH script.
#[must_use]
pub(crate) fn pubkey_hash(script: &Script) -> Option<[u8; 20]> {
    let bytes = script.as_bytes();
    if bytes.len() != 25
        || bytes[0] != 0x76
        || bytes[1] != 0xa9
        || bytes[2] != 0x14
        || bytes[23] != 0x88
        || bytes[24] != 0xac
    {
        return None;
    }
    bytes[3..23].try_into().ok()
}
