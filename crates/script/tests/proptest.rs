//! Property tests for delegated script execution over signed synthetic spends.

#[cfg(feature = "bitcoinconsensus")]
use bitcoin::PublicKey;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
#[cfg(feature = "bitcoinconsensus")]
use bitcoin::sighash::EcdsaSighashType;
use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    transaction,
};
use bitcoin_rs_primitives::Tx;
use bitcoin_rs_script::{Interpreter, ScriptError, VerifyFlags};
use proptest::prelude::*;

proptest! {
    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_valid_p2pkh_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2pkh(byte) else {
            return Ok(());
        };
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &[],
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_valid_p2wpkh_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2wpkh(byte) else {
            return Ok(());
        };
        let witness = fixture.tx.0.input[0].witness.to_vec();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    fn random_valid_p2tr_keypath_spends_execute(byte in 1u8..=127) {
        let Some(fixture) = signed_p2tr(byte) else {
            return Ok(());
        };
        let witness = fixture.tx.0.input[0].witness.to_vec();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert_eq!(ok, Ok(true));
    }

    #[test]
    fn random_p2tr_keypath_spends_with_extra_witness_items_fail(
        byte in 1u8..=127,
        extra in prop::collection::vec(any::<u8>(), 0..=80),
    ) {
        let Some(fixture) = signed_p2tr(byte) else {
            return Ok(());
        };
        let mut witness = fixture.tx.0.input[0].witness.to_vec();
        witness.push(extra);
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert!(
            matches!(
                ok,
                Err(ScriptError::TaprootUnsupportedWitness { elements: 2 })
            ),
            "expected TaprootUnsupportedWitness with elements=2"
        );
    }

    #[test]
    #[cfg(feature = "bitcoinconsensus")]
    fn random_invalid_empty_witness_fails_for_p2wpkh(byte in 1u8..=127) {
        let Some(mut fixture) = signed_p2wpkh(byte) else {
            return Ok(());
        };
        fixture.tx.0.input[0].witness = Witness::new();
        let interpreter = Interpreter;
        let ok = interpreter.execute(
            fixture.prevout.script_pubkey.as_bytes(),
            fixture.tx.0.input[0].script_sig.as_bytes(),
            &[],
            VerifyFlags::MANDATORY,
            &fixture.prevout,
            &fixture.tx.0,
            0,
        );
        prop_assert!(matches!(ok, Err(bitcoin_rs_script::ScriptError::Verification(_))));
    }
}

/// Valid multi-input taproot key-path spend must verify once all prevouts are supplied.
///
/// Before the prevout-threading fix this fails with `TaprootPrevoutsUnavailable` because
/// `Interpreter::execute` only receives the single input's prevout.
#[test]
fn valid_multi_input_taproot_keypath_spend_executes() {
    let Some((tx, prevouts)) = signed_multi_input_p2tr([1, 2]) else {
        return;
    };
    let interpreter = Interpreter;
    let prevout_refs: Vec<&TxOut> = prevouts.iter().collect();
    for (input_idx, prevout) in prevouts.iter().enumerate() {
        let witness = tx.input[input_idx].witness.to_vec();
        let ok = interpreter.execute_with_prevouts(
            prevout.script_pubkey.as_bytes(),
            tx.input[input_idx].script_sig.as_bytes(),
            &witness,
            VerifyFlags::MANDATORY,
            &prevout_refs,
            &tx,
            input_idx,
        );
        assert_eq!(ok, Ok(true), "input {input_idx}");
    }
}

struct SpendFixture {
    prevout: TxOut,
    tx: Tx,
}

#[cfg(feature = "bitcoinconsensus")]
fn signed_p2pkh(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let public_key = PublicKey::new(secp_public);
    let script_pubkey = ScriptBuf::new_p2pkh(&public_key.pubkey_hash());
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey,
    };
    let mut tx = unsigned_spend(byte);
    let cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.legacy_signature_hash(
        0,
        prevout.script_pubkey.as_script(),
        EcdsaSighashType::All.to_u32(),
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &secret));
    tx.input[0].script_sig = Builder::new()
        .push_slice(push_bytes(signature.to_vec())?)
        .push_key(&public_key)
        .into_script();
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
}

#[cfg(feature = "bitcoinconsensus")]
fn signed_p2wpkh(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let secp_public = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let public_key = PublicKey::new(secp_public);
    let Ok(wpubkey_hash) = public_key.wpubkey_hash() else {
        return None;
    };
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2wpkh(&wpubkey_hash),
    };
    let mut tx = unsigned_spend(byte);
    let mut cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.p2wpkh_signature_hash(
        0,
        prevout.script_pubkey.as_script(),
        prevout.value,
        EcdsaSighashType::All,
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = bitcoin::ecdsa::Signature::sighash_all(secp.sign_ecdsa(&message, &secret));
    tx.input[0].witness = Witness::from_slice(&[signature.to_vec(), public_key.to_bytes()]);
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
}

fn signed_p2tr(byte: u8) -> Option<SpendFixture> {
    let secp = Secp256k1::new();
    let secret = secret_key(byte)?;
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
    let (output_key, _) = tweaked.public_parts();
    let prevout = TxOut {
        value: Amount::from_sat(50_000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
    };
    let mut tx = unsigned_spend(byte);
    let prevouts = [prevout.clone()];
    let mut cache = SighashCache::new(&tx);
    let Ok(sighash) = cache.taproot_key_spend_signature_hash(
        0,
        &Prevouts::All(&prevouts),
        TapSighashType::Default,
    ) else {
        return None;
    };
    let message = Message::from_digest(*sighash.as_byte_array());
    let signature = secp.sign_schnorr(&message, tweaked.as_keypair());
    tx.input[0].witness = Witness::from_slice(&[signature.serialize().to_vec()]);
    Some(SpendFixture {
        prevout,
        tx: Tx(tx),
    })
}

/// Builds a two-input taproot key-path transaction signed with BIP341 `Prevouts::All`.
///
/// Signatures are produced with rust-bitcoin sighash/schnorr APIs independently of the
/// interpreter under test.
fn signed_multi_input_p2tr(seeds: [u8; 2]) -> Option<(Transaction, Vec<TxOut>)> {
    let secp = Secp256k1::new();
    let mut keypairs = Vec::with_capacity(seeds.len());
    let mut prevouts = Vec::with_capacity(seeds.len());
    for seed in seeds {
        let secret = secret_key(seed)?;
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let tweaked = bitcoin::key::TapTweak::tap_tweak(keypair, &secp, None);
        let (output_key, _) = tweaked.public_parts();
        prevouts.push(TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
        });
        keypairs.push(tweaked);
    }

    let mut tx = Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: seeds
            .iter()
            .enumerate()
            .map(|(index, seed)| TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([*seed; 32]),
                    vout: u32::try_from(index).expect("input index fits u32"),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: vec![TxOut {
            value: Amount::from_sat(99_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    };

    for input_idx in 0..tx.input.len() {
        let mut cache = SighashCache::new(&tx);
        let Ok(sighash) = cache.taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        ) else {
            return None;
        };
        let message = Message::from_digest(*sighash.as_byte_array());
        let signature = secp.sign_schnorr(&message, keypairs[input_idx].as_keypair());
        tx.input[input_idx].witness = Witness::from_slice(&[signature.serialize().to_vec()]);
    }

    Some((tx, prevouts))
}

fn unsigned_spend(byte: u8) -> Transaction {
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([byte; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(49_000),
            script_pubkey: Builder::new().push_int(1).into_script(),
        }],
    }
}

fn secret_key(byte: u8) -> Option<SecretKey> {
    SecretKey::from_slice(&[byte; 32]).ok()
}

#[cfg(feature = "bitcoinconsensus")]
fn push_bytes(bytes: Vec<u8>) -> Option<PushBytesBuf> {
    PushBytesBuf::try_from(bytes).ok()
}
