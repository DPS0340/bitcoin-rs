use crate::ConsensusError;

/// Checks BIP66 strict DER signature encoding, including a trailing sighash byte.
pub fn check_bip66(signature_with_sighash: &[u8]) -> Result<(), ConsensusError> {
    if is_strict_der_signature(signature_with_sighash) {
        return Ok(());
    }
    Err(ConsensusError::Bip {
        bip: "BIP66",
        reason: "signature is not strict DER encoding".to_owned(),
    })
}

/// BIP66 `IsValidSignatureEncoding`: a strict DER ECDSA signature plus the
/// trailing sighash-type byte. Checks the sequence/integer tags, both integer
/// lengths against the total length, the mandatory minimal negative encoding
/// (no high bit set on the first byte), and the absence of non-minimal
/// leading zero padding — the same rules Core enforces under the `DERSIG` flag.
fn is_strict_der_signature(signature: &[u8]) -> bool {
    // Format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s] [sighash].
    // The minimum is a 1-byte r, a 1-byte s, and the sighash byte: 9 bytes.
    // The maximum is a 33-byte r and s (padded) plus the sighash byte: 73 bytes.
    if !(9..=73).contains(&signature.len())
        || signature[0] != 0x30
        || usize::from(signature[1]) != signature.len() - 3
        || signature[2] != 0x02
    {
        return false;
    }

    let len_r = usize::from(signature[3]);
    if len_r == 0 || 5 + len_r >= signature.len() {
        return false;
    }
    let s_tag = 4 + len_r;
    let len_s = usize::from(signature[s_tag + 1]);
    if signature[s_tag] != 0x02 || len_s == 0 || len_r + len_s + 7 != signature.len() {
        return false;
    }

    let r = &signature[4..4 + len_r];
    let s = &signature[s_tag + 2..s_tag + 2 + len_s];
    r[0] & 0x80 == 0
        && !(r.len() > 1 && r[0] == 0 && r[1] & 0x80 == 0)
        && s[0] & 0x80 == 0
        && !(s.len() > 1 && s[0] == 0 && s[1] & 0x80 == 0)
}

#[cfg(test)]
mod tests {
    use super::check_bip66;

    #[test]
    fn strict_der_signature_passes() {
        let sig = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01];
        assert_eq!(check_bip66(&sig), Ok(()));
    }

    #[test]
    fn malformed_der_signature_fails() {
        assert!(check_bip66(&[1, 2, 3, 1]).is_err());
    }

    #[test]
    fn high_bit_and_excess_padding_integers_fail() {
        // Negative integer: the first magnitude byte carries the sign bit.
        assert!(check_bip66(&[0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01, 0x01]).is_err());
        // Non-minimal padding: a leading zero whose successor lacks the high bit.
        assert!(
            check_bip66(&[0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01]).is_err()
        );
    }
}
