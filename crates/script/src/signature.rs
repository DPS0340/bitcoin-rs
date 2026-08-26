//! Signature and public-key encoding seams for the local evaluator.
//!
//! The module boundary follows `reardencode/rbitcoin` commit
//! `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937` (MIT OR Apache-2.0). These
//! helpers deliberately expose bytes; policy and consensus encoding rules are
//! applied by the execution context rather than hidden in a parser.

/// Splits a serialized ECDSA signature into DER bytes and its hash-type byte.
#[must_use]
#[allow(dead_code)]
pub(crate) fn ecdsa_signature_parts(signature: &[u8]) -> Option<(&[u8], u8)> {
    let (&sighash_type, der) = signature.split_last()?;
    (!der.is_empty()).then_some((der, sighash_type))
}

/// Returns whether a public key uses one of Bitcoin's compressed encodings.
#[must_use]
#[allow(dead_code)]
pub(crate) fn is_compressed_public_key(public_key: &[u8]) -> bool {
    matches!(public_key, [0x02 | 0x03, ..] if public_key.len() == 33)
}

#[cfg(test)]
mod tests {
    use super::{ecdsa_signature_parts, is_compressed_public_key};

    #[test]
    fn signature_helpers_keep_hash_type_and_key_shape_visible() {
        assert_eq!(ecdsa_signature_parts(&[1, 2, 3]), Some((&[1, 2][..], 3)));
        assert_eq!(ecdsa_signature_parts(&[]), None);
        assert!(is_compressed_public_key(&[0x02; 33]));
        assert!(!is_compressed_public_key(&[0x04; 65]));
    }
}
