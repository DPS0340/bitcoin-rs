#![no_main]

use libfuzzer_sys::fuzz_target;

/// Fuzz the portable script interpreter.
///
/// Splits the fuzz input into a `script_pubkey` / `script_sig` pair and runs
/// `Interpreter::execute`, the public entry point in
/// `crates/script/src/interpreter.rs`.  Input is bounded to 4 KiB so the
/// fuzzer does not time out on huge scripts.  `VerifyFlags::NONE` exercises
/// the non-taproot portable path without triggering Schnorr verification.
fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }

    let split = data.len() / 2;
    let script_pubkey = &data[..split];
    let script_sig = &data[split..];

    let prevout = bitcoin::TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: bitcoin::ScriptBuf::new(),
    };

    let tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version::ONE,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::default(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::default(),
        }],
        output: vec![],
    };

    let interpreter = bitcoin_rs_script::Interpreter::default();
    let _ = interpreter.execute(
        script_pubkey,
        script_sig,
        &[],
        bitcoin_rs_script::VerifyFlags::NONE,
        &prevout,
        &tx,
        0,
    );
});
