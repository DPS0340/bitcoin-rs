//! Kernel smoke tests; ignored locally and executed by the kernel CI job.
//!
//! These are **smoke** tests — they prove the kernel loads, initializes, and
//! can verify a single known-valid transaction. The real parity differential
//! lives in `kernel_block_parity.rs` (script-verdict differential over 6
//! mainnet fixtures) and `kernel_vector_parity.rs` (Core vector oracle over
//! 121 tx_valid + 84 tx_invalid rows). These smoke tests are the minimum
//! proof that the kernel FFI is alive; they are not a parity differential.

#[cfg(feature = "kernel")]
#[test]
#[ignore = "kernel parity requires libboost-dev and the kernel CI job"]
fn kernel_context_builds_for_mainnet() {
    bitcoin_rs_consensus::kernel::KernelContext::new(bitcoin_rs_primitives::Network::Mainnet)
        .unwrap_or_else(|error| panic!("kernel context should build: {error}"));
}

/// Proves the kernel can verify a real transaction, not just construct a
/// context. Loads the first `tx_valid.json` row, builds the prevout set,
/// and asserts the kernel accepts it. This replaces the previous vacuous
/// "file exists and has >1 row" check with a real kernel verdict assertion.
#[cfg(feature = "kernel")]
#[test]
#[ignore = "kernel parity requires libboost-dev and the kernel CI job"]
fn kernel_accepts_first_tx_valid_vector() {
    use bitcoin_rs_primitives::{OutPoint, Tx, TxOut, Txid, deserialize};
    use bitcoin_rs_script::VerifyFlags;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value};
    use std::str::FromStr;

    let text = std::fs::read_to_string("tests/vectors/tx_valid.json")
        .expect("tx_valid.json should be readable");
    let root: Vec<Value> =
        sonic_rs::from_str(&text).expect("tx_valid.json should parse as JSON array");

    // Find the first runnable row: [[prevouts...], tx_hex, flags].
    let mut found = false;
    for row in &root {
        let Some(arr) = row.as_array() else { continue };
        if arr.len() < 3 || !arr[0].is_array() || arr[1].as_str().is_none() {
            continue;
        }
        let flags_str = arr[2].as_str().unwrap_or("NONE");
        if flags_str.contains("BADTX") {
            continue;
        }
        // Skip rows with policy flags — the kernel only enforces mandatory
        // consensus rules, and some policy-flag vectors carry pre-BIP66
        // signatures the kernel correctly rejects.
        if flags_str != "NONE" && !flags_str.chars().all(|c| c.is_whitespace()) {
            let parsed = VerifyFlags::from_core_names(flags_str).expect("flags should parse");
            if parsed.bits() & !VerifyFlags::MANDATORY.bits() != 0 {
                continue;
            }
        }

        let tx_hex = arr[1].as_str().expect("tx hex should be string");
        let tx_bytes = decode_hex(tx_hex);
        let tx: Tx = deserialize(&tx_bytes).expect("tx should deserialize");

        let flags = VerifyFlags::from_core_names(flags_str).expect("flags should parse");

        let prevout_specs = arr[0].as_array().expect("prevout specs should be array");
        let mut prevouts = Vec::with_capacity(prevout_specs.len());
        for spec in prevout_specs {
            let spec = spec.as_array().expect("prevout spec should be array");
            let hash_hex = spec[0].as_str().expect("prevout hash should be string");
            let vout = u32::try_from(spec[1].as_i64().expect("prevout vout should be number"))
                .expect("prevout vout should fit in u32");
            let script_asm = spec[2].as_str().expect("prevout script should be string");
            let amount = spec.get(3).and_then(|v| v.as_u64()).unwrap_or(0);

            let script_pubkey = parse_core_asm(script_asm);
            let txid = Txid::from_str(hash_hex).expect("prevout txid should parse");
            prevouts.push((
                OutPoint::new(txid, vout),
                TxOut {
                    value: amount,
                    script_pubkey,
                },
            ));
        }

        let result = bitcoin_rs_consensus::kernel::verify_tx_scripts(&tx, &prevouts, flags);
        assert!(
            result.is_ok(),
            "kernel should accept first tx_valid vector: {:?}",
            result.err()
        );
        found = true;
        break;
    }

    assert!(
        found,
        "should have found at least one runnable tx_valid vector"
    );
}

/// Minimal Core ASM parser for the smoke test. The full parser lives in
/// `kernel_vector_parity.rs`; this copy is intentionally minimal — it only
/// needs to handle the first tx_valid row's scriptPubKey.
fn parse_core_asm(asm: &str) -> Vec<u8> {
    use bitcoin_rs_script::push_int;
    let mut script = Vec::new();
    for token in asm.split_whitespace() {
        if let Some(hex) = token.strip_prefix("0x") {
            script.extend_from_slice(&decode_hex(hex));
        } else if let Ok(n) = token.parse::<i64>() {
            script.extend_from_slice(&push_int(n));
        } else {
            // For the smoke test, resolve common opcodes.
            if let Some(byte) = resolve_opcode(token) {
                script.push(byte);
            }
        }
    }
    script
}

fn resolve_opcode(name: &str) -> Option<u8> {
    use bitcoin_rs_script::opcode::*;
    let bare = name.strip_prefix("OP_").unwrap_or(name);
    Some(match bare {
        "0" | "EMPTY" => OP_0,
        "1NEGATE" => OP_1NEGATE,
        "1" => OP_PUSHNUM_1,
        "2" => 0x52,
        "3" => 0x53,
        "4" => 0x54,
        "5" => 0x55,
        "6" => 0x56,
        "7" => 0x57,
        "8" => 0x58,
        "9" => 0x59,
        "10" => 0x5a,
        "11" => 0x5b,
        "12" => 0x5c,
        "13" => 0x5d,
        "14" => 0x5e,
        "15" => 0x5f,
        "16" => OP_PUSHNUM_16,
        "DUP" => OP_DUP,
        "HASH160" => OP_HASH160,
        "EQUAL" => OP_EQUAL,
        "EQUALVERIFY" => OP_EQUALVERIFY,
        "CHECKSIG" => OP_CHECKSIG,
        "CHECKSIGVERIFY" => OP_CHECKSIGVERIFY,
        "CHECKMULTISIG" => OP_CHECKMULTISIG,
        "CHECKMULTISIGVERIFY" => OP_CHECKMULTISIGVERIFY,
        "VERIFY" => 0x69,
        "RETURN" => OP_RETURN,
        "DROP" => 0x75,
        "IF" => 0x63,
        "NOTIF" => 0x64,
        "ELSE" => 0x67,
        "ENDIF" => 0x68,
        "CHECKLOCKTIMEVERIFY" => 0xb1,
        "CHECKSEQUENCEVERIFY" => 0xb2,
        "CODESEPARATOR" => 0xab,
        "ADD" => 0x93,
        "SUB" => 0x94,
        "1ADD" => 0x8b,
        "1SUB" => 0x8c,
        "NOT" => 0x91,
        _ => return None,
    })
}

fn decode_hex(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[cfg(not(feature = "kernel"))]
#[test]
#[ignore = "kernel feature is off in portable verification"]
const fn kernel_parity_skipped_without_kernel_feature() {}
