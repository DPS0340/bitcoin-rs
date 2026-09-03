use rayon::prelude::*;
use secp256k1::{Message, XOnlyPublicKey, schnorr::Signature};

/// Verifies Schnorr signatures in parallel.
///
/// secp256k1 exposes per-signature Schnorr verification but no public batch
/// verification. This v1 batch path preserves the public shape while using
/// Rayon to verify independent items concurrently.
#[must_use]
pub fn verify_schnorr_batch(items: &[(Signature, Message, XOnlyPublicKey)]) -> bool {
    items.par_iter().all(|(signature, message, public_key)| {
        secp256k1::SECP256K1
            .verify_schnorr(signature, message, public_key)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

    use super::verify_schnorr_batch;

    #[test]
    fn batch_verify_is_conjunction_of_individual_verification() {
        let secp = Secp256k1::new();
        let secret = match SecretKey::from_slice(&[3u8; 32]) {
            Ok(secret) => secret,
            Err(error) => panic!("fixed secret key should be valid: {error}"),
        };
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);
        let items: Vec<_> = (0u8..20)
            .map(|byte| {
                let message = Message::from_digest([byte; 32]);
                let signature = secp.sign_schnorr(&message, &keypair);
                (signature, message, public_key)
            })
            .collect();

        assert!(verify_schnorr_batch(&items));
    }
}
