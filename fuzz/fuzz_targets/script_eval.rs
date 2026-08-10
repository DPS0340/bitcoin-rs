#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz the taproot key-path verifier.
///
/// The previous shape evaluated nothing. With `VerifyFlags::NONE`,
/// `Interpreter::execute` routes to `verify_non_taproot_portable`, which is a
/// stub accepting only a bare `OP_TRUE` spend with an empty scriptSig and
/// witness; and the equal input split made even that unreachable, because a
/// one-byte scriptPubKey forces a nonempty scriptSig. No input reached an
/// opcode.
///
/// The taproot key path is the substantive verifier available here: it parses
/// a Schnorr signature, derives the sighash over the transaction, and runs
/// secp256k1 verification. Reaching it needs a P2TR scriptPubKey, the
/// `TAPROOT` flag, and a witness, so the harness builds all three and spends
/// the remaining fuzz bytes on the signature — the part with parsing to break.
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    // 32 bytes of x-only key, then whatever is left as the witness element.
    let Some((program, signature)) = data.split_at_checked(32) else {
        return;
    };

    // `OP_1 PUSH32 <program>` is exactly what `Script::is_p2tr` matches.
    let mut script_pubkey = Vec::with_capacity(34);
    script_pubkey.push(0x51);
    script_pubkey.push(0x20);
    script_pubkey.extend_from_slice(program);

    let prevout = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(10_000),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(script_pubkey.clone()),
    };
    let witness = vec![signature.to_vec()];

    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::from_slice(&[signature]),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(9_000),
            script_pubkey: bitcoin::ScriptBuf::new(),
        }],
    };

    let interpreter = bitcoin_rs_script::Interpreter::default();
    let _ = interpreter.execute(
        &script_pubkey,
        &[],
        &witness,
        bitcoin_rs_script::VerifyFlags::TAPROOT,
        &prevout,
        &tx,
        0,
    );
});
