//! Nested-script helpers for P2SH and witness dispatch.
//!
//! The module boundary follows `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0d83feb8f3b036937` (MIT OR Apache-2.0). The helpers
//! operate on local rust-bitcoin values and carry no storage or query layer.

use bitcoin::{Script, ScriptBuf};

/// Returns whether every instruction in `script` is a data push.
#[must_use]
pub(crate) fn is_push_only(script: &Script) -> bool {
    script.is_push_only()
}

/// Decodes the last stack item as a redeem script.
#[must_use]
#[allow(dead_code)]
pub(crate) fn redeem_script(stack: &[Vec<u8>]) -> Option<ScriptBuf> {
    stack.last().cloned().map(ScriptBuf::from_bytes)
}

#[cfg(test)]
mod tests {
    use bitcoin::{Script, ScriptBuf};

    use super::{is_push_only, redeem_script};

    #[test]
    fn nested_helpers_keep_push_only_and_redeem_boundaries() {
        assert!(is_push_only(Script::from_bytes(&[1, 1])));
        assert!(!is_push_only(Script::from_bytes(&[0x93])));
        assert_eq!(
            redeem_script(&[vec![0x51]]),
            Some(ScriptBuf::from_bytes(vec![0x51]))
        );
        assert_eq!(redeem_script(&[]), None);
    }
}
