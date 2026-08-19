//! CHECKSIG census bare-secp per-attempt timing harness.
//!
//! Reads BRSREC1 records produced by the capture/census phase, converts them
//! to `btck_bare_input` structs, and calls the native `btck_bare_verify_bench`
//! mode 0 (`CPubKey::Verify` from libbitcoinkernel-sys 0.3.0 via bitcoinkernel
//! 0.2.1, embedding Bitcoin Core 31.99.0 development sources: parse pubkey +
//! lax DER + normalize + verify). Also runs Rust secp256k1 0.31.1 verify-only
//! and parse+verify as diagnostics.
//!
//! CLI: `--records PATH --warmup N --rounds N [--output PATH]`
//! Emits JSON to `--output` or stdout.

#![allow(clippy::print_stdout)]

use std::ffi::OsString;
use std::io::{BufReader, Read as _};
use std::path::PathBuf;

use anyhow::{Context as _, Result, bail};
use serde_json::json;

// ── Constants ──────────────────────────────────────────────────────────────

const RECORD_MAGIC: &[u8; 8] = b"BRSREC1\0";
const SUMMARY_SCHEMA: u32 = 1;

/// Record size must match the native CensusRecord (224 bytes).
const RECORD_SIZE: usize = 224;
/// Counter names in the exact order defined by the census contract.
const COUNTER_NAMES: [&str; 24] = [
    "verify_script_calls",
    "ffi_verify_entries",
    "ffi_verify_true",
    "eval_script_entries",
    "op_checksig",
    "op_checksigverify",
    "op_checkmultisig",
    "op_checkmultisigverify",
    "op_checksigadd",
    "checkecdsa_entries",
    "checkecdsa_reject_pubkey",
    "checkecdsa_reject_empty_sig",
    "checkecdsa_reject_missing_data",
    "ecdsa_verify_calls",
    "ecdsa_verify_ok",
    "ecdsa_verify_fail",
    "ecdsa_from_checksig",
    "ecdsa_from_checkmultisig",
    "sighash_computed",
    "sighash_midstate_hit",
    "checkschnorr_entries",
    "schnorr_verify_calls",
    "schnorr_verify_ok",
    "schnorr_verify_fail",
];

// ── Entry point ────────────────────────────────────────────────────────────

fn record_to_bare_input(
    rec: &ParsedRecord,
) -> Result<Option<libbitcoinkernel_sys::btck_bare_input>> {
    // Outcome-2 records are pre-verification rejects and carry no sighash.
    // They must be skipped before any capacity-indexed public-key slice.
    if rec.outcome == 2 {
        return Ok(None);
    }
    // parse_record already enforces these bounds for non-exempt records,
    // but the helper keeps the slice contract self-contained.
    if rec.der_len > 72 {
        bail!("record: der_len {} exceeds 72", rec.der_len);
    }
    if rec.pubkey_len > 65 {
        bail!("record: pubkey_len {} exceeds 65", rec.pubkey_len);
    }

    let mut input = libbitcoinkernel_sys::btck_bare_input {
        sighash: [0u8; 32],
        der_sig: [0u8; 72],
        pubkey: [0u8; 65],
        der_len: rec.der_len,
        pubkey_len: rec.pubkey_len,
        expected: rec.outcome, // 1=true, 0=false
        pad: [0u8; 4],
    };
    input.sighash.copy_from_slice(&rec.sighash);
    input.der_sig[..rec.der_len as usize].copy_from_slice(&rec.der_sig[..rec.der_len as usize]);
    input.pubkey[..rec.pubkey_len as usize].copy_from_slice(&rec.pubkey[..rec.pubkey_len as usize]);
    Ok(Some(input))
}

fn main() -> Result<()> {
    let args = Args::parse(std::env::args_os().skip(1))?;

    let records = load_records(&args.records)?;

    if records.is_empty() {
        bail!("no records in file");
    }

    // Convert records to btck_bare_input array.
    // Only records with outcome != 2 (pre-verification reject) have a verification sighash.
    let mut inputs: Vec<libbitcoinkernel_sys::btck_bare_input> = Vec::with_capacity(records.len());
    let mut rejected: u64 = 0;
    for rec in &records {
        match record_to_bare_input(rec)? {
            None => rejected += 1,
            Some(input) => inputs.push(input),
        }
    }
    let expected_true_count: u64 = inputs.iter().filter(|inp| inp.expected == 1).count() as u64;

    let count = inputs.len() as u64;
    let warmup = args.warmup;
    let rounds = args.rounds;

    // ── Native Core mode 0 (authoritative Y) ───────────────────────────────
    let mut native_result = libbitcoinkernel_sys::btck_bare_result {
        attempts: 0,
        rounds: 0,
        mismatches: 0,
        first_mismatch: u64::MAX,
        ok_count: 0,
        round_ns: [0u64; 64],
    };

    // Reset counters before timing; require zero after.
    unsafe {
        libbitcoinkernel_sys::btck_census_reset();
    }

    let native_rc = unsafe {
        libbitcoinkernel_sys::btck_bare_verify_bench(
            inputs.as_ptr(),
            count,
            warmup,
            rounds,
            0, // mode 0
            &mut native_result,
        )
    };

    if native_rc != 0 {
        bail!("btck_bare_verify_bench returned {native_rc}");
    }

    // Verify counters stayed zero.
    let mut counters = [0u64; 24];
    unsafe {
        libbitcoinkernel_sys::btck_census_snapshot(counters.as_mut_ptr(), 24);
    }
    let counters_nonzero: u64 = counters.iter().map(|&v| v.min(1)).sum();
    if counters_nonzero != 0 {
        bail!("counters nonzero after bare timing: {counters:?}");
    }

    // ── Rust secp256k1 diagnostic: verify-only ─────────────────────────────
    let secp = secp256k1::Secp256k1::verification_only();
    let mut rust_verify_ok: u64 = 0;
    let mut rust_verify_fail: u64 = 0;
    let mut rust_preparse_failures: u64 = 0;
    let mut rust_preparse_failures_on_expected_true: u64 = 0;
    let mut rust_preparse_pubkey_failures_on_expected_true: u64 = 0;
    let mut rust_preparse_der_failures_on_expected_true: u64 = 0;

    for inp in &inputs {
        let pubkey = if inp.pubkey_len == 0 {
            None
        } else {
            secp256k1::PublicKey::from_slice(&inp.pubkey[..inp.pubkey_len as usize]).ok()
        };
        let sig = if inp.der_len == 0 {
            None
        } else {
            secp256k1::ecdsa::Signature::from_der(&inp.der_sig[..inp.der_len as usize]).ok()
        };

        let pubkey_parse_failed = pubkey.is_none();
        let der_parse_failed = sig.is_none();
        let preparse_failed = pubkey_parse_failed || der_parse_failed;

        if preparse_failed {
            rust_preparse_failures += 1;
            if inp.expected == 1 {
                rust_preparse_failures_on_expected_true += 1;
                if pubkey_parse_failed {
                    rust_preparse_pubkey_failures_on_expected_true += 1;
                }
                if der_parse_failed {
                    rust_preparse_der_failures_on_expected_true += 1;
                }
            }
        }

        let ok = match (pubkey, sig) {
            (Some(pk), Some(sg)) => {
                let msg = secp256k1::Message::from_digest(inp.sighash);
                secp.verify_ecdsa(msg, &sg, &pk).is_ok()
            }
            _ => false,
        };
        if ok {
            rust_verify_ok += 1;
        } else {
            rust_verify_fail += 1;
        }
    }

    // ── Compute per-attempt timing from raw round cost ─────────────────────
    // The authoritative per-attempt cost for round i is round_ns[i] / inputs_per_round.
    let inputs_per_round: u64 = count;
    let attempts_total: u64 = inputs_per_round * (rounds as u64);
    let round_ns_vec: Vec<u64> = native_result.round_ns[..rounds as usize].to_vec();

    let mut per_attempt_round_ns: Vec<f64> = round_ns_vec
        .iter()
        .map(|&ns| ns as f64 / inputs_per_round as f64)
        .collect();
    per_attempt_round_ns.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));

    let min_ns_per_attempt = *per_attempt_round_ns.first().unwrap_or(&0.0);
    let max_ns_per_attempt = *per_attempt_round_ns.last().unwrap_or(&0.0);
    let median_ns_per_attempt = if per_attempt_round_ns.is_empty() {
        0.0
    } else {
        let n = per_attempt_round_ns.len();
        if n % 2 == 1 {
            per_attempt_round_ns[n / 2]
        } else {
            (per_attempt_round_ns[n / 2 - 1] + per_attempt_round_ns[n / 2]) / 2.0
        }
    };

    // Native attempts_total is expected to equal inputs_per_round * rounds, but
    // the timing contract does not depend on the native bookkeeping value.
    let _ = native_result.attempts;

    // ── INV-8: native correctness only ─────────────────────────────────────
    let inv8_mismatches = native_result.mismatches;
    let inv8_ok_match = native_result.ok_count == expected_true_count;
    let inv8_passed = inv8_mismatches == 0 && inv8_ok_match;

    // ── INV-15: counters zero after timing ─────────────────────────────────
    let mut counters_map = serde_json::Map::new();
    for (i, name) in COUNTER_NAMES.iter().enumerate() {
        counters_map.insert((*name).to_string(), json!(counters[i]));
    }
    let inv15_all_zero = counters_nonzero == 0;

    let summary = json!({
        "schema": SUMMARY_SCHEMA,
        "records_total": records.len(),
        "records_rejected_pre_secp": rejected,
        "inputs_timed": count,
        "warmup_rounds": warmup,
        "timed_rounds": rounds,
        "native_mode0": {
            "inputs_per_round": inputs_per_round,
            "rounds": rounds,
            "attempts_total": attempts_total,
            "round_ns": round_ns_vec,
            "median_ns_per_attempt": median_ns_per_attempt,
            "min_ns_per_attempt": min_ns_per_attempt,
            "max_ns_per_attempt": max_ns_per_attempt,
            "mismatches": native_result.mismatches,
            "first_mismatch": if native_result.first_mismatch == u64::MAX {
                serde_json::Value::Null
            } else {
                json!(native_result.first_mismatch)
            },
            "ok_count": native_result.ok_count,
        },
        "rust_secp_diagnostic": {
            "verify_ok": rust_verify_ok,
            "verify_fail": rust_verify_fail,
            "preparse_failures": rust_preparse_failures,
            "preparse_failures_on_expected_true": rust_preparse_failures_on_expected_true,
            "preparse_pubkey_failures_on_expected_true": rust_preparse_pubkey_failures_on_expected_true,
            "preparse_der_failures_on_expected_true": rust_preparse_der_failures_on_expected_true,
        },
        "counters_zero_after_timing": inv15_all_zero,
        "inv_8": {
            "mismatches": inv8_mismatches,
            "ok_count": native_result.ok_count,
            "expected_true_count": expected_true_count,
            "ok_equals_count_outcome_1": inv8_ok_match,
            "passed": inv8_passed,
        },
        "inv_15": {
            "counters": counters_map,
            "all_counters_zero": inv15_all_zero,
            "passed": inv15_all_zero,
        },
    });

    let rendered = serde_json::to_string_pretty(&summary).context("render summary JSON")?;

    match &args.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            std::fs::write(path, rendered + "\n")
                .with_context(|| format!("write {}", path.display()))?;
        }
        None => {
            println!("{rendered}");
        }
    }

    Ok(())
}

// ── CLI ────────────────────────────────────────────────────────────────────

#[derive(Debug)]
struct Args {
    records: PathBuf,
    warmup: u32,
    rounds: u32,
    output: Option<PathBuf>,
}

impl Args {
    fn parse(mut args: impl Iterator<Item = OsString>) -> Result<Self> {
        let mut records: Option<PathBuf> = None;
        let mut warmup: u32 = 1;
        let mut rounds: u32 = 5;
        let mut output: Option<PathBuf> = None;

        while let Some(arg) = args.next() {
            let arg = arg.to_string_lossy();
            match arg.as_ref() {
                "--records" => records = Some(PathBuf::from(next_arg(&mut args, "--records")?)),
                "--warmup" => {
                    warmup = next_arg(&mut args, "--warmup")?.parse().context("warmup")?
                }
                "--rounds" => {
                    rounds = next_arg(&mut args, "--rounds")?.parse().context("rounds")?
                }
                "--output" => output = Some(PathBuf::from(next_arg(&mut args, "--output")?)),
                other => bail!("unknown argument: {other}"),
            }
        }

        Ok(Args {
            records: records.context("--records is required")?,
            warmup,
            rounds,
            output,
        })
    }
}

fn next_arg(args: &mut impl Iterator<Item = OsString>, name: &str) -> Result<String> {
    args.next()
        .map(|s| s.to_string_lossy().into_owned())
        .with_context(|| format!("missing value for {name}"))
}

// ── Record loader ──────────────────────────────────────────────────────────

/// Parsed BRSREC1 record (224 bytes).
struct ParsedRecord {
    sighash: [u8; 32],
    der_sig: [u8; 72],
    pubkey: [u8; 65],
    der_len: u8,
    pubkey_len: u8,
    outcome: u8,
}

/// Exact over-capacity ECDSA reject shape accepted by the bare-secp reader.
/// Native reason-1 records may preserve the original (>=66) pubkey_len only
/// for outcome 2 with a null payload and unchanged padding.
fn is_exempt_over_capacity_ecdsa_reject(buf: &[u8; RECORD_SIZE]) -> bool {
    if !(1..=4).contains(&buf[40]) {
        return false;
    } // op_kind
    if !(0..=1).contains(&buf[41]) {
        return false;
    } // sig_version
    if buf[42] != 2 {
        return false;
    } // outcome
    if buf[43] != 0 {
        return false;
    } // der_len
    if buf[45] != 0 {
        return false;
    } // sighash_type
    if buf[46] != 1 {
        return false;
    } // reject_reason
    if buf[47] != 0 {
        return false;
    } // _pad0
    if buf[48..80] != [0; 32] {
        return false;
    } // sighash
    if buf[80..152] != [0; 72] {
        return false;
    } // der_sig
    if buf[152..217] != [0; 65] {
        return false;
    } // pubkey
    if buf[217..224] != [0; 7] {
        return false;
    } // _pad1
    true
}

fn parse_record(buf: &[u8; RECORD_SIZE], index: u64) -> Result<ParsedRecord> {
    let outcome = buf[42];
    let der_len = buf[43];
    let pubkey_len = buf[44];

    if pubkey_len > 65 && !is_exempt_over_capacity_ecdsa_reject(buf) {
        bail!("record {index}: pubkey_len {pubkey_len} exceeds 65");
    }
    if der_len > 72 {
        bail!("record {index}: der_len {der_len} exceeds 72");
    }
    if outcome > 2 {
        bail!("record {index}: outcome {outcome} exceeds 2");
    }

    let mut sighash = [0u8; 32];
    sighash.copy_from_slice(&buf[48..80]);

    let mut der_sig = [0u8; 72];
    der_sig.copy_from_slice(&buf[80..152]);

    let mut pubkey = [0u8; 65];
    pubkey.copy_from_slice(&buf[152..217]);

    Ok(ParsedRecord {
        sighash,
        der_sig,
        pubkey,
        der_len,
        pubkey_len,
        outcome,
    })
}

fn load_records(path: &std::path::Path) -> Result<Vec<ParsedRecord>> {
    let file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut magic = [0u8; 8];
    reader.read_exact(&mut magic).context("read magic")?;
    if &magic != RECORD_MAGIC {
        bail!("bad magic: expected BRSREC1, got {:?}", &magic);
    }

    let mut count_buf = [0u8; 8];
    reader.read_exact(&mut count_buf).context("read count")?;
    let count = u64::from_le_bytes(count_buf);

    let mut records = Vec::with_capacity(count.min(10_000_000) as usize);

    for i in 0..count {
        let mut buf = [0u8; RECORD_SIZE];
        reader
            .read_exact(&mut buf)
            .with_context(|| format!("read record {i}"))?;
        records.push(parse_record(&buf, i)?);
    }

    // Reject trailing bytes
    let mut trailing = [0u8; 1];
    if reader.read(&mut trailing).unwrap_or(0) > 0 {
        bail!("trailing bytes after {count} records");
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_buf() -> [u8; RECORD_SIZE] {
        let mut buf = [0u8; RECORD_SIZE];
        buf[42] = 1;
        buf[43] = 72;
        buf[44] = 65;
        for (i, byte) in buf[48..80].iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in buf[80..152].iter_mut().enumerate() {
            *byte = i as u8;
        }
        for (i, byte) in buf[152..217].iter_mut().enumerate() {
            *byte = i as u8;
        }
        buf
    }

    #[test]
    fn parse_valid_boundary() {
        let mut buf = valid_buf();
        // exact boundary: der_len=72, pubkey_len=65, outcome=2
        buf[42] = 2;
        let rec = parse_record(&buf, 0).unwrap();
        assert_eq!(rec.outcome, 2);
        assert_eq!(rec.der_len, 72);
        assert_eq!(rec.pubkey_len, 65);
        assert_eq!(&rec.sighash, &buf[48..80]);
        assert_eq!(&rec.der_sig[..], &buf[80..152]);
        assert_eq!(&rec.pubkey[..], &buf[152..217]);
    }

    #[test]
    fn parse_rejects_der_len_too_large() {
        let mut buf = valid_buf();
        buf[43] = 73;
        assert!(parse_record(&buf, 0).is_err());
    }

    #[test]
    fn parse_rejects_pubkey_len_too_large() {
        let mut buf = valid_buf();
        buf[44] = 66;
        assert!(parse_record(&buf, 0).is_err());
    }

    #[test]
    fn parse_rejects_outcome_too_large() {
        let mut buf = valid_buf();
        buf[42] = 3;
        assert!(parse_record(&buf, 0).is_err());
    }

    #[test]
    fn ffi_rejects_invalid_der_len() {
        let input = libbitcoinkernel_sys::btck_bare_input {
            sighash: [0u8; 32],
            der_sig: [0u8; 72],
            pubkey: [0u8; 65],
            der_len: 73,
            pubkey_len: 65,
            expected: 1,
            pad: [0u8; 4],
        };
        let mut result = libbitcoinkernel_sys::btck_bare_result {
            attempts: 0,
            rounds: 0,
            mismatches: 0,
            first_mismatch: u64::MAX,
            ok_count: 0,
            round_ns: [0u64; 64],
        };
        let rc = unsafe {
            libbitcoinkernel_sys::btck_bare_verify_bench(&input, 1, 0, 1, 0, &mut result)
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_rejects_invalid_pubkey_len() {
        let input = libbitcoinkernel_sys::btck_bare_input {
            sighash: [0u8; 32],
            der_sig: [0u8; 72],
            pubkey: [0u8; 65],
            der_len: 72,
            pubkey_len: 66,
            expected: 1,
            pad: [0u8; 4],
        };
        let mut result = libbitcoinkernel_sys::btck_bare_result {
            attempts: 0,
            rounds: 0,
            mismatches: 0,
            first_mismatch: u64::MAX,
            ok_count: 0,
            round_ns: [0u64; 64],
        };
        let rc = unsafe {
            libbitcoinkernel_sys::btck_bare_verify_bench(&input, 1, 0, 1, 0, &mut result)
        };
        assert_eq!(rc, -1);
    }

    #[test]
    fn ffi_rejects_expected_greater_than_one() {
        let input = libbitcoinkernel_sys::btck_bare_input {
            sighash: [0u8; 32],
            der_sig: [0u8; 72],
            pubkey: [0u8; 65],
            der_len: 72,
            pubkey_len: 65,
            expected: 2,
            pad: [0u8; 4],
        };
        let mut result = libbitcoinkernel_sys::btck_bare_result {
            attempts: 0,
            rounds: 0,
            mismatches: 0,
            first_mismatch: u64::MAX,
            ok_count: 0,
            round_ns: [0u64; 64],
        };
        let rc = unsafe {
            libbitcoinkernel_sys::btck_bare_verify_bench(&input, 1, 0, 1, 0, &mut result)
        };
        assert_eq!(rc, -1);
    }

    fn preserved_over_capacity_row() -> [u8; RECORD_SIZE] {
        let mut buf = [0u8; RECORD_SIZE];
        let prefix: [u8; 48] = [
            0xcf, 0x42, 0xbd, 0x87, 0xb9, 0x98, 0x25, 0x95, 0xbf, 0x2d, 0x35, 0x4c, 0x5f, 0x75,
            0x8c, 0x14, 0x4d, 0x66, 0x33, 0x01, 0xce, 0xfc, 0x3b, 0x31, 0xad, 0x31, 0x32, 0xf8,
            0x7f, 0x49, 0x18, 0xd1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00,
            0x02, 0x00, 0x42, 0x00, 0x01, 0x00,
        ];
        buf[..48].copy_from_slice(&prefix);
        buf
    }

    #[test]
    fn parse_accepts_preserved_over_capacity_ecdsa_reject() {
        let buf = preserved_over_capacity_row();
        let rec = parse_record(&buf, 0).unwrap();
        assert_eq!(rec.outcome, 2);
        assert_eq!(rec.der_len, 0);
        assert_eq!(rec.pubkey_len, 66);
        assert_eq!(rec.sighash, [0; 32]);
        assert_eq!(rec.der_sig, [0; 72]);
        assert_eq!(rec.pubkey, [0; 65]);
    }

    #[test]
    fn parse_rejects_over_capacity_near_misses() {
        let base = preserved_over_capacity_row();
        let mutations: [(usize, u8, &str); 19] = [
            (40, 0, "op_kind=0"),
            (40, 5, "op_kind=5"),
            (41, 2, "sig_version=2"),
            (41, 3, "sig_version=3"),
            (42, 0, "outcome=0"),
            (42, 1, "outcome=1"),
            (43, 1, "der_len=1"),
            (43, 73, "der_len=73"),
            (45, 1, "sighash_type=1"),
            (46, 0, "reject_reason=0"),
            (46, 2, "reject_reason=2"),
            (46, 3, "reject_reason=3"),
            (46, 4, "reject_reason=4"),
            (46, 5, "reject_reason=5"),
            (46, 6, "reject_reason=6"),
            (46, 7, "reject_reason=7"),
            (46, 8, "reject_reason=8"),
            (47, 1, "nonzero _pad0"),
            (80, 1, "nonzero der_sig byte"),
        ];
        for (offset, value, label) in mutations {
            let mut buf = base;
            buf[offset] = value;
            let err = match parse_record(&buf, 0) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{label} should have failed"),
            };
            assert!(
                err.contains("pubkey_len 66 exceeds 65"),
                "{label} should fail with length error, got: {err}"
            );
        }

        for offset in [48, 79, 80, 151, 152, 216, 217, 223] {
            let mut buf = base;
            buf[offset] = 1;
            let err = match parse_record(&buf, 0) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("byte {offset} should have failed"),
            };
            assert!(
                err.contains("pubkey_len 66 exceeds 65"),
                "byte {offset} should fail with length error, got: {err}"
            );
        }
    }

    #[test]
    fn load_records_accepts_preserved_over_capacity_reject() {
        // Build a minimal BRSREC1 fixture with the exact over-capacity row.
        let path = std::env::temp_dir().join(format!(
            "checksig_bare_secp_preserved_row_{}.bin",
            std::process::id()
        ));
        let mut file = std::fs::File::create(&path).unwrap();
        std::io::Write::write_all(&mut file, RECORD_MAGIC).unwrap();
        std::io::Write::write_all(&mut file, &1u64.to_le_bytes()).unwrap();
        std::io::Write::write_all(&mut file, &preserved_over_capacity_row()).unwrap();
        drop(file);

        let records = load_records(&path).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].outcome, 2);
        assert_eq!(records[0].pubkey_len, 66);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn record_to_bare_input_skips_over_capacity_outcome_two() {
        // The exact over-capacity reason-1 record is outcome 2, so the
        // production helper must return None before any capacity-indexed
        // public-key slice. Removing the outcome-2 guard would make this
        // test panic because pubkey_len (66) exceeds the fixed 65-byte array.
        let rec = parse_record(&preserved_over_capacity_row(), 0).unwrap();
        assert_eq!(rec.outcome, 2);
        assert!(rec.pubkey_len > 65);
        let input = record_to_bare_input(&rec).unwrap();
        assert!(
            input.is_none(),
            "outcome-2 record must be skipped before copy"
        );
    }

    #[test]
    fn record_to_bare_input_accepts_ordinary_record() {
        // Ordinary outcome-1 records are converted to a real FFI input.
        let buf = valid_buf();
        let rec = parse_record(&buf, 0).unwrap();
        assert_eq!(rec.outcome, 1);
        let input = record_to_bare_input(&rec).unwrap().unwrap();
        assert_eq!(input.expected, 1);
        assert_eq!(input.der_len, 72);
        assert_eq!(input.pubkey_len, 65);
    }
}
