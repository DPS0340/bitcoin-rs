#!/usr/bin/env python3
"""CHECKSIG census analyzer.

Three subcommands:
  validate-capture  — validate Run B capture artifacts (INV-1..INV-11, INV-13)
  validate-census   — validate Run A census + cross-check with Run B (INV-12, EXP-1..4)
  verdict           — compute OPEN/CLOSED/INVALID from timing and census data

Stdlib-only, Python 3.12+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import statistics
import struct
import sys
from pathlib import Path
from typing import Any

# ── Constants ───────────────────────────────────────────────────────────────

RECORD_MAGIC = b"BRSREC1\x00"
JOURNAL_MAGIC = b"BRSJRN1\x00"
RECORD_SIZE = 224
JOURNAL_SIZE = 56
HEADER_SIZE = 16

EXPECTED_FFI_VERIFY_ENTRIES_FULL = 2_868_199
EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1 = 159_259

COUNTER_NAMES: list[str] = [
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
]

HEADER_STRUCT = struct.Struct("<8sQ")
RECORD_STRUCT = struct.Struct("<32sIIBBBBBBBB32s72s65s7s")
JOURNAL_STRUCT = struct.Struct("<32sIIIIIB3s")

assert HEADER_STRUCT.size == HEADER_SIZE
assert RECORD_STRUCT.size == RECORD_SIZE
assert JOURNAL_STRUCT.size == JOURNAL_SIZE


# ── Exceptions ──────────────────────────────────────────────────────────────


class AnalyzerError(Exception):
    """Fatal: malformed input or unparseable file."""


# ── Data classes ────────────────────────────────────────────────────────────


class Counters:
    """Parsed counters JSON."""

    verify_script_calls: int
    ffi_verify_entries: int
    ffi_verify_true: int
    eval_script_entries: int
    op_checksig: int
    op_checksigverify: int
    op_checkmultisig: int
    op_checkmultisigverify: int
    op_checksigadd: int
    checkecdsa_entries: int
    checkecdsa_reject_pubkey: int
    checkecdsa_reject_empty_sig: int
    checkecdsa_reject_missing_data: int
    ecdsa_verify_calls: int
    ecdsa_verify_ok: int
    ecdsa_verify_fail: int
    ecdsa_from_checksig: int
    ecdsa_from_checkmultisig: int
    sighash_computed: int
    sighash_midstate_hit: int
    checkschnorr_entries: int
    schnorr_verify_calls: int

    def __init__(self, raw: dict[str, Any]) -> None:
        self._raw = raw
        self.schema: int = int(raw.get("schema", 0))
        self.label: str = str(raw.get("label", ""))
        for name in COUNTER_NAMES:
            setattr(self, name, int(raw.get(name, 0)))
        self.record_count: int = int(raw.get("record_count", 0))
        self.journal_count: int = int(raw.get("journal_count", 0))


class Record:
    """Parsed 224-byte record."""

    __slots__ = (
        "spend_txid", "input_index", "op_seq",
        "op_kind", "sig_version", "outcome",
        "der_len", "pubkey_len", "sighash_type",
        "reject_reason", "sighash", "der_sig", "pubkey",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = RECORD_STRUCT.unpack(raw)
        (
            self.spend_txid, self.input_index, self.op_seq,
            self.op_kind, self.sig_version, self.outcome,
            self.der_len, self.pubkey_len, self.sighash_type,
            self.reject_reason, _pad0,
            self.sighash, self.der_sig, self.pubkey, _pad1,
        ) = unpacked

    @property
    def sort_key(self) -> tuple[bytes, int, int]:
        return (self.spend_txid, self.input_index, self.op_seq)


class JournalEntry:
    """Parsed 56-byte journal entry."""

    __slots__ = (
        "spend_txid", "input_index",
        "checksig_ops", "checkmultisig_ops",
        "ecdsa_verify_calls", "ecdsa_verify_ok",
        "verdict",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = JOURNAL_STRUCT.unpack(raw)
        (
            self.spend_txid, self.input_index,
            self.checksig_ops, self.checkmultisig_ops,
            self.ecdsa_verify_calls, self.ecdsa_verify_ok,
            self.verdict, _pad,
        ) = unpacked

    @property
    def key(self) -> tuple[bytes, int]:
        return (self.spend_txid, self.input_index)


# ── Binary parsing ──────────────────────────────────────────────────────────


def read_raw_entries(path: Path, magic: bytes, entry_size: int, name: str) -> list[bytes]:
    """Read a binary file with magic + u64 count header, return raw entry bytes."""
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise AnalyzerError(f"{path}: file too short ({len(data)} bytes < {HEADER_SIZE} header)")
    file_magic, count = HEADER_STRUCT.unpack_from(data, 0)
    if file_magic != magic:
        raise AnalyzerError(f"{path}: bad magic {file_magic!r}, expected {magic!r}")
    expected = HEADER_SIZE + count * entry_size
    if len(data) != expected:
        raise AnalyzerError(
            f"{path}: size mismatch (got {len(data)}, expected {expected} "
            f"= {HEADER_SIZE} + {count} × {entry_size} {name})"
        )
    return [
        data[HEADER_SIZE + i * entry_size : HEADER_SIZE + (i + 1) * entry_size]
        for i in range(count)
    ]


def parse_records(path: Path) -> list[Record]:
    raws = read_raw_entries(path, RECORD_MAGIC, RECORD_SIZE, "records")
    return [Record(r) for r in raws]


def parse_journal(path: Path) -> list[JournalEntry]:
    raws = read_raw_entries(path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries")
    return [JournalEntry(r) for r in raws]


def parse_counters(path: Path) -> Counters:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise AnalyzerError(f"{path}: JSON root is not an object")
    if raw.get("schema") != 1:
        raise AnalyzerError(f"{path}: schema is {raw.get('schema')}, expected 1")
    return Counters(raw)


# ── Sorting and hashing ─────────────────────────────────────────────────────


def sort_records_raw(raw_entries: list[bytes]) -> bytes:
    """Sort raw record bytes by (spend_txid, input_index, op_seq), concatenate."""

    def key(raw: bytes) -> tuple[bytes, int, int]:
        txid = raw[0:32]
        input_index = struct.unpack_from("<I", raw, 32)[0]
        op_seq = struct.unpack_from("<I", raw, 36)[0]
        return (txid, input_index, op_seq)

    return b"".join(sorted(raw_entries, key=key))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── Invariant checks ────────────────────────────────────────────────────────


def check_counter_arithmetic(c: Counters) -> list[dict[str, Any]]:
    """INV-1 through INV-7."""
    results: list[dict[str, Any]] = []

    def inv(inv_id: str, passed: bool, statement: str, **extra: Any) -> None:
        entry: dict[str, Any] = {"id": inv_id, "passed": passed, "statement": statement}
        entry.update(extra)
        results.append(entry)

    inv(
        "INV-1",
        c.verify_script_calls == c.ffi_verify_entries,
        "C_VERIFY_SCRIPT_CALLS == C_FFI_VERIFY_ENTRIES",
        expected=c.ffi_verify_entries,
        actual=c.verify_script_calls,
    )
    inv(
        "INV-2",
        c.ffi_verify_true == c.ffi_verify_entries,
        "C_FFI_VERIFY_TRUE == C_FFI_VERIFY_ENTRIES",
        expected=c.ffi_verify_entries,
        actual=c.ffi_verify_true,
    )
    inv(
        "INV-3",
        c.checkecdsa_entries == c.ecdsa_from_checksig + c.ecdsa_from_checkmultisig,
        "C_CHECKECDSA_ENTRIES == C_ECDSA_FROM_CHECKSIG + C_ECDSA_FROM_CHECKMULTISIG",
        expected=c.ecdsa_from_checksig + c.ecdsa_from_checkmultisig,
        actual=c.checkecdsa_entries,
    )
    rejects = (
        c.checkecdsa_reject_pubkey
        + c.checkecdsa_reject_empty_sig
        + c.checkecdsa_reject_missing_data
    )
    inv(
        "INV-4",
        c.checkecdsa_entries == c.ecdsa_verify_calls + rejects,
        "C_CHECKECDSA_ENTRIES == C_ECDSA_VERIFY_CALLS + rejects",
        expected=c.ecdsa_verify_calls + rejects,
        actual=c.checkecdsa_entries,
    )
    inv(
        "INV-5",
        c.ecdsa_verify_calls == c.ecdsa_verify_ok + c.ecdsa_verify_fail
        and c.ecdsa_verify_calls == c.sighash_computed,
        "C_ECDSA_VERIFY_CALLS == C_ECDSA_VERIFY_OK + C_ECDSA_VERIFY_FAIL and == C_SIGHASH_COMPUTED",
        ok_plus_fail=c.ecdsa_verify_ok + c.ecdsa_verify_fail,
        sighash_computed=c.sighash_computed,
        ecdsa_verify_calls=c.ecdsa_verify_calls,
    )
    inv(
        "INV-6",
        c.ecdsa_from_checksig <= c.op_checksig + c.op_checksigverify
        and c.ecdsa_from_checkmultisig <= 20 * (c.op_checkmultisig + c.op_checkmultisigverify),
        "C_ECDSA_FROM_CHECKSIG <= C_OP_CHECKSIG + C_OP_CHECKSIGVERIFY; "
        "C_ECDSA_FROM_CHECKMULTISIG <= 20 * (C_OP_CHECKMULTISIG + C_OP_CHECKMULTISIGVERIFY)",
        from_checksig=c.ecdsa_from_checksig,
        checksig_plus_verify=c.op_checksig + c.op_checksigverify,
        from_checkmultisig=c.ecdsa_from_checkmultisig,
        twenty_multisig=20 * (c.op_checkmultisig + c.op_checkmultisigverify),
    )
    inv(
        "INV-7",
        c.op_checksigadd == 0 and c.checkschnorr_entries == 0 and c.schnorr_verify_calls == 0,
        "C_OP_CHECKSIGADD == 0 and C_CHECKSCHNORR_ENTRIES == 0 and C_SCHNORR_VERIFY_CALLS == 0",
        op_checksigadd=c.op_checksigadd,
        checkschnorr_entries=c.checkschnorr_entries,
        schnorr_verify_calls=c.schnorr_verify_calls,
    )
    return results


def check_record_counts(records: list[Record], c: Counters) -> dict[str, Any]:
    """INV-9: record count reconciliation."""
    outcome_01 = sum(1 for r in records if r.outcome in (0, 1))
    total = len(records)
    return {
        "id": "INV-9",
        "passed": outcome_01 == c.ecdsa_verify_calls and total == c.checkecdsa_entries,
        "statement": "count(outcome in {0,1}) == C_ECDSA_VERIFY_CALLS and count(all) == C_CHECKECDSA_ENTRIES",
        "outcome_01_count": outcome_01,
        "total_records": total,
        "ecdsa_verify_calls": c.ecdsa_verify_calls,
        "checkecdsa_entries": c.checkecdsa_entries,
    }


def check_journal_sums(journal: list[JournalEntry], c: Counters) -> dict[str, Any]:
    """INV-10: journal sums reconcile with counters."""
    s_checksig = sum(e.checksig_ops for e in journal)
    s_checkmultisig = sum(e.checkmultisig_ops for e in journal)
    s_ecdsa_calls = sum(e.ecdsa_verify_calls for e in journal)
    s_ecdsa_ok = sum(e.ecdsa_verify_ok for e in journal)
    return {
        "id": "INV-10",
        "passed": (
            s_ecdsa_calls == c.ecdsa_verify_calls
            and s_checksig == c.op_checksig + c.op_checksigverify
            and s_checkmultisig == c.op_checkmultisig + c.op_checkmultisigverify
            and s_ecdsa_ok == c.ecdsa_verify_ok
        ),
        "statement": "sum(journal fields) == counter values",
        "journal_sum_checksig_ops": s_checksig,
        "journal_sum_checkmultisig_ops": s_checkmultisig,
        "journal_sum_ecdsa_verify_calls": s_ecdsa_calls,
        "journal_sum_ecdsa_verify_ok": s_ecdsa_ok,
        "counter_op_checksig_plus_verify": c.op_checksig + c.op_checksigverify,
        "counter_op_checkmultisig_plus_verify": c.op_checkmultisig + c.op_checkmultisigverify,
        "counter_ecdsa_verify_calls": c.ecdsa_verify_calls,
        "counter_ecdsa_verify_ok": c.ecdsa_verify_ok,
    }


def check_duplicate_keys(records: list[Record]) -> dict[str, Any]:
    """INV-11: no duplicate (spend_txid, input_index, op_seq) after sorting."""
    seen: set[tuple[bytes, int, int]] = set()
    duplicates = 0
    for r in records:
        key = r.sort_key
        if key in seen:
            duplicates += 1
        seen.add(key)
    return {
        "id": "INV-11",
        "passed": duplicates == 0,
        "statement": "No duplicate (spend_txid, input_index, op_seq) after sorting",
        "duplicate_count": duplicates,
    }


def check_all_verdicts_true(journal: list[JournalEntry]) -> dict[str, Any]:
    """INV-2 for census: all journal verdicts are true (1)."""
    false_count = sum(1 for e in journal if e.verdict != 1)
    return {
        "id": "INV-2",
        "passed": false_count == 0,
        "statement": "All journal verdicts are true (valid chain)",
        "total_entries": len(journal),
        "false_verdicts": false_count,
    }


def check_count_repeat(
    c1: Counters, c2: Counters, sha1: str, sha2: str
) -> dict[str, Any]:
    """INV-13: two Run-B executions produce identical counters and sorted records SHA256."""
    counters_identical = all(
        getattr(c1, name) == getattr(c2, name) for name in COUNTER_NAMES
    ) and c1.record_count == c2.record_count and c1.journal_count == c2.journal_count
    sha_match = sha1 == sha2
    return {
        "id": "INV-13",
        "passed": counters_identical and sha_match,
        "statement": "Two Run-B executions produce byte-identical counters and identical sha256(records.sorted.bin)",
        "counters_identical": counters_identical,
        "sorted_records_sha256_match": sha_match,
        "sha256_run1": sha1,
        "sha256_run2": sha2,
    }


def check_census_capture_agreement(
    census_journal: list[JournalEntry],
    capture_journal: list[JournalEntry],
) -> dict[str, Any]:
    """INV-12: census ∩ capture journal agreement (anti-triple-count)."""
    census_map: dict[tuple[bytes, int], JournalEntry] = {}
    for e in census_journal:
        if e.key in census_map:
            raise AnalyzerError(
                f"INV-12: duplicate key in census journal (input_index={e.input_index})"
            )
        census_map[e.key] = e

    capture_map: dict[tuple[bytes, int], JournalEntry] = {}
    for e in capture_journal:
        if e.key in capture_map:
            raise AnalyzerError(
                f"INV-12: duplicate key in capture journal (input_index={e.input_index})"
            )
        capture_map[e.key] = e

    intersection = set(census_map.keys()) & set(capture_map.keys())
    discrepancies: list[dict[str, Any]] = []
    max_ratio = 1.0

    for key in sorted(intersection):
        c = census_map[key]
        b = capture_map[key]
        for field_name in ("checksig_ops", "checkmultisig_ops", "ecdsa_verify_calls", "ecdsa_verify_ok"):
            cv = int(getattr(c, field_name))
            bv = int(getattr(b, field_name))
            if cv != bv:
                discrepancies.append(
                    {
                        "input_index": key[1],
                        "field": field_name,
                        "census_value": cv,
                        "capture_value": bv,
                    }
                )
                if field_name == "ecdsa_verify_calls" and bv > 0:
                    ratio = cv / bv
                    if ratio > max_ratio:
                        max_ratio = ratio

    width_multiplier: int | None = None
    if max_ratio > 2.5 and max_ratio < 3.5:
        width_multiplier = 3
    elif max_ratio > 1.5:
        width_multiplier = round(max_ratio)

    return {
        "id": "INV-12",
        "passed": len(discrepancies) == 0,
        "statement": "Census ∩ capture journals agree exactly on every field",
        "intersection_size": len(intersection),
        "census_size": len(census_map),
        "capture_size": len(capture_map),
        "discrepancy_count": len(discrepancies),
        "discrepancies": discrepancies[:50],
        "width_multiplier": width_multiplier,
    }


# ── Bare JSON extraction ────────────────────────────────────────────────────


def extract_bare_mode0(bare: dict[str, Any]) -> dict[str, Any]:
    """Extract mode-0 results from bare-secp JSON per the binding contract.

    Requires top-level ``native_mode0`` with all exact fields:
    inputs_per_round, rounds, attempts_total, round_ns,
    median_ns_per_attempt, min_ns_per_attempt, max_ns_per_attempt,
    mismatches, first_mismatch, ok_count.

    Per-attempt round cost is ``round_ns[i] / inputs_per_round``, never
    divided by ``attempts_total`` across all rounds.  The median of those
    per-round costs is the authoritative Y.  Reported median/min/max must
    agree with the independently recomputed values within floating tolerance.
    """
    _REQUIRED_FIELDS = (
        "inputs_per_round",
        "rounds",
        "attempts_total",
        "round_ns",
        "median_ns_per_attempt",
        "min_ns_per_attempt",
        "max_ns_per_attempt",
        "mismatches",
        "first_mismatch",
        "ok_count",
    )

    mode0 = bare.get("native_mode0")
    if not isinstance(mode0, dict):
        raise AnalyzerError(
            "bare JSON: missing top-level native_mode0 object "
            "(old schema without inputs_per_round/rounds/attempts_total)"
        )

    missing = [f for f in _REQUIRED_FIELDS if f not in mode0]
    if missing:
        raise AnalyzerError(
            "bare JSON: native_mode0 missing required fields: "
            + ", ".join(missing)
        )

    inputs_per_round = int(mode0["inputs_per_round"])
    rounds = int(mode0["rounds"])
    attempts_total = int(mode0["attempts_total"])
    mismatches = int(mode0["mismatches"])
    ok_count = int(mode0["ok_count"])
    first_mismatch = mode0["first_mismatch"]

    # Validate positive / non-negative values
    if inputs_per_round <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.inputs_per_round = {inputs_per_round} "
            "(must be positive)"
        )
    if rounds <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.rounds = {rounds} (must be positive)"
        )
    if attempts_total <= 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.attempts_total = {attempts_total} "
            "(must be positive)"
        )
    if ok_count < 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.ok_count = {ok_count} "
            "(must be non-negative)"
        )
    if mismatches < 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.mismatches = {mismatches} "
            "(must be non-negative)"
        )

    # Require attempts_total == inputs_per_round * rounds
    if attempts_total != inputs_per_round * rounds:
        raise AnalyzerError(
            f"bare JSON: attempts_total ({attempts_total}) != "
            f"inputs_per_round ({inputs_per_round}) * rounds ({rounds})"
        )

    # round_ns must be a list of positive ints with length == rounds
    round_ns_raw = mode0["round_ns"]
    if not isinstance(round_ns_raw, list):
        raise AnalyzerError("bare JSON: native_mode0.round_ns is not a list")
    if len(round_ns_raw) != rounds:
        raise AnalyzerError(
            f"bare JSON: round_ns length ({len(round_ns_raw)}) != "
            f"rounds ({rounds})"
        )

    round_ns: list[int] = []
    for i, ns in enumerate(round_ns_raw):
        val = int(ns)
        if val <= 0:
            raise AnalyzerError(
                f"bare JSON: round_ns[{i}] = {val} (must be positive)"
            )
        round_ns.append(val)

    # Independently recompute per-round ns/attempt as round_ns / inputs_per_round.
    # Never divide by attempts_total for a single round.
    per_attempt: list[float] = [
        float(ns) / float(inputs_per_round) for ns in round_ns
    ]

    # Median is the authoritative Y (not mean).
    recomputed_median = statistics.median(per_attempt)
    recomputed_min = min(per_attempt)
    recomputed_max = max(per_attempt)

    reported_median = float(mode0["median_ns_per_attempt"])
    reported_min = float(mode0["min_ns_per_attempt"])
    reported_max = float(mode0["max_ns_per_attempt"])

    # Require reported median/min/max agree within floating tolerance.
    _REL_TOL = 1e-6

    def _approx(a: float, b: float) -> bool:
        if a == b:
            return True
        return abs(a - b) <= _REL_TOL * max(abs(a), abs(b), 1.0)

    if not _approx(reported_median, recomputed_median):
        raise AnalyzerError(
            f"bare JSON: median_ns_per_attempt ({reported_median}) != "
            f"recomputed round-median ({recomputed_median})"
        )
    if not _approx(reported_min, recomputed_min):
        raise AnalyzerError(
            f"bare JSON: min_ns_per_attempt ({reported_min}) != "
            f"recomputed round-min ({recomputed_min})"
        )
    if not _approx(reported_max, recomputed_max):
        raise AnalyzerError(
            f"bare JSON: max_ns_per_attempt ({reported_max}) != "
            f"recomputed round-max ({recomputed_max})"
        )

    spread_ns = recomputed_max - recomputed_min

    return {
        "median_ns_per_attempt": recomputed_median,
        "min_ns_per_attempt": recomputed_min,
        "max_ns_per_attempt": recomputed_max,
        "spread_ns": spread_ns,
        "inputs_per_round": inputs_per_round,
        "rounds": rounds,
        "attempts_total": attempts_total,
        "mismatches": mismatches,
        "first_mismatch": first_mismatch,
        "ok_count": ok_count,
        "per_attempt_ns": per_attempt,
    }


def extract_spike_width1(spike: dict[str, Any]) -> float:
    """Extract width-1 us_per_input from a spike run JSON."""
    if "runs" in spike and isinstance(spike["runs"], list):
        for run in spike["runs"]:
            if isinstance(run, dict) and run.get("threads") == 1:
                return float(run["us_per_input"])
        raise AnalyzerError("spike JSON: no run with threads == 1")
    if "us_per_input" in spike:
        return float(spike["us_per_input"])
    raise AnalyzerError("spike JSON: no us_per_input found")


# ── Subcommand: validate-capture ────────────────────────────────────────────


def cmd_validate_capture(args: argparse.Namespace) -> int:
    counters = parse_counters(Path(args.counters))
    records = parse_records(Path(args.records))
    journal = parse_journal(Path(args.journal))

    repeat_counters = parse_counters(Path(args.repeat_counters))
    parse_records(Path(args.repeat_records))
    parse_journal(Path(args.repeat_journal))

    # Sort records and compute SHA256 for both runs
    raw1 = read_raw_entries(Path(args.records), RECORD_MAGIC, RECORD_SIZE, "records")
    raw2 = read_raw_entries(Path(args.repeat_records), RECORD_MAGIC, RECORD_SIZE, "records")
    sorted1 = sort_records_raw(raw1)
    sorted2 = sort_records_raw(raw2)
    sha1 = sha256_hex(sorted1)
    sha2 = sha256_hex(sorted2)

    if args.sorted_records_output:
        out = Path(args.sorted_records_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(sorted1)

    inv_results: list[dict[str, Any]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(check_record_counts(records, counters))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_duplicate_keys(records))
    inv_results.append(check_count_repeat(counters, repeat_counters, sha1, sha2))

    all_passed = all(r["passed"] for r in inv_results)

    report = {
        "schema": "validate-capture-v1",
        "counters_label": counters.label,
        "record_count": len(records),
        "journal_count": len(journal),
        "sorted_records_sha256": sha1,
        "repeat_sorted_records_sha256": sha2,
        "invariants": inv_results,
        "all_passed": all_passed,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    failed = [r["id"] for r in inv_results if not r["passed"]]
    if failed:
        print(f"validate-capture: FAILED — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"validate-capture: PASSED — {len(records)} records, sha256={sha1[:16]}…")
    return 0


# ── Subcommand: validate-census ─────────────────────────────────────────────


def cmd_validate_census(args: argparse.Namespace) -> int:
    counters = parse_counters(Path(args.counters))
    journal = parse_journal(Path(args.journal))
    capture_journal = parse_journal(Path(args.capture_journal))

    inv_results: list[dict[str, Any]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(check_all_verdicts_true(journal))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_census_capture_agreement(journal, capture_journal))

    # EXP-1: expected input count
    exp1_passed = counters.ffi_verify_entries == EXPECTED_FFI_VERIFY_ENTRIES_FULL
    exp1: dict[str, Any] = {
        "id": "EXP-1",
        "passed": exp1_passed,
        "statement": f"C_FFI_VERIFY_ENTRIES == {EXPECTED_FFI_VERIFY_ENTRIES_FULL}",
        "expected": EXPECTED_FFI_VERIFY_ENTRIES_FULL,
        "actual": counters.ffi_verify_entries,
    }
    if not exp1_passed:
        exp1["warning"] = "Value differs from published anchor — window, corpus, or published figure may have moved."

    # EXP-4: attempts-per-check comparison (census vs capture)
    census_a = counters.ecdsa_verify_calls / counters.ffi_verify_entries if counters.ffi_verify_entries else 0.0
    capture_ecdsa_sum = sum(e.ecdsa_verify_calls for e in capture_journal)
    capture_count = len(capture_journal)
    capture_a = capture_ecdsa_sum / capture_count if capture_count else 0.0
    if census_a > 0 and capture_a > 0:
        ratio = census_a / capture_a
        exp4_passed = abs(ratio - 1.0) <= 0.10
    else:
        ratio = 0.0
        exp4_passed = False
    exp4: dict[str, Any] = {
        "id": "EXP-4",
        "passed": exp4_passed,
        "statement": "attempts-per-check on KSPIKE1 vs 0..150k differ by <= 10%",
        "census_attempts_per_check": census_a,
        "capture_attempts_per_check": capture_a,
        "ratio": ratio,
    }
    if not exp4_passed and ratio > 0:
        exp4["warning"] = "Corpus over-represents multisig; report both ratios and extrapolate with the whole-window ratio."

    all_passed = all(r["passed"] for r in inv_results) and exp1["passed"] and exp4["passed"]

    report = {
        "schema": "validate-census-v1",
        "counters_label": counters.label,
        "journal_count": len(journal),
        "invariants": inv_results,
        "expected_anchors": [exp1, exp4],
        "all_passed": all_passed,
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    failed = [r["id"] for r in inv_results if not r["passed"]]
    if not exp1["passed"]:
        failed.append("EXP-1")
    if not exp4["passed"]:
        failed.append("EXP-4")
    if failed:
        print(f"validate-census: FAILED — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"validate-census: PASSED — {len(journal)} journal entries")
    return 0


# ── Subcommand: verdict ─────────────────────────────────────────────────────


def cmd_verdict(args: argparse.Namespace) -> int:
    if len(args.bare_runs) != 3:
        raise AnalyzerError(f"verdict requires exactly three bare-runs, got {len(args.bare_runs)}")
    if len(args.spike_runs) != 3:
        raise AnalyzerError(f"verdict requires exactly three spike-runs, got {len(args.spike_runs)}")
    capture_counters = parse_counters(Path(args.capture_counters))
    k_entries = capture_counters.ffi_verify_entries
    if k_entries == 0:
        raise AnalyzerError("capture counters: ffi_verify_entries == 0")

    # Extract spike width-1 values across runs
    spike_values: list[float] = []
    for spike_path in args.spike_runs:
        spike_raw = json.loads(Path(spike_path).read_text())
        if not isinstance(spike_raw, dict):
            raise AnalyzerError(f"{spike_path}: JSON root is not an object")
        spike_values.append(extract_spike_width1(spike_raw))

    if not spike_values:
        raise AnalyzerError("no spike run files provided")

    x_us = statistics.median(spike_values)
    spike_spread_us = (max(spike_values) - min(spike_values)) if len(spike_values) > 1 else 0.0

    # Extract and validate every bare timing run.
    run_records: list[dict[str, Any]] = []
    run_medians: list[float] = []
    all_per_attempt_ns: list[float] = []
    for bare_path in args.bare_runs:
        bare_raw = json.loads(Path(bare_path).read_text())
        if not isinstance(bare_raw, dict):
            raise AnalyzerError(f"{bare_path}: JSON root is not an object")

        mode0 = extract_bare_mode0(bare_raw)
        run_medians.append(mode0["median_ns_per_attempt"])
        all_per_attempt_ns.extend(mode0["per_attempt_ns"])

        # INV-8: native correctness, recomputed rather than trusting emitted passed.
        inv8_raw = bare_raw.get("inv_8")
        if not isinstance(inv8_raw, dict):
            raise AnalyzerError(f"{bare_path}: missing inv_8")
        for field in (
            "passed",
            "mismatches",
            "ok_count",
            "expected_true_count",
            "ok_equals_count_outcome_1",
        ):
            if field not in inv8_raw:
                raise AnalyzerError(f"{bare_path}: inv_8 missing {field}")
        inv8_mismatches = int(inv8_raw["mismatches"])
        inv8_ok_count = int(inv8_raw["ok_count"])
        inv8_expected = int(inv8_raw["expected_true_count"])
        inv8_ok_eq = inv8_raw["ok_equals_count_outcome_1"]
        if not isinstance(inv8_ok_eq, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_8 ok_equals_count_outcome_1 is not a boolean"
            )
        inv8_emitted_passed = inv8_raw["passed"]
        if not isinstance(inv8_emitted_passed, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_8 passed is not a boolean"
            )
        inv8_run_passed = (
            inv8_mismatches == 0
            and inv8_ok_count == inv8_expected
            and inv8_expected == k_entries
            and inv8_ok_eq
            and inv8_emitted_passed
        )

        # INV-15: every run must contain exactly the 22 COUNTER_NAMES with
        # integer zero values, plus explicit true all_counters_zero and passed.
        inv15_raw = bare_raw.get("inv_15")
        if not isinstance(inv15_raw, dict):
            raise AnalyzerError(f"{bare_path}: missing inv_15")
        for field in ("counters", "all_counters_zero", "passed"):
            if field not in inv15_raw:
                raise AnalyzerError(f"{bare_path}: inv_15 missing {field}")
        inv15_all_zero = inv15_raw["all_counters_zero"]
        inv15_passed_emitted = inv15_raw["passed"]
        if not isinstance(inv15_all_zero, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_15 all_counters_zero is not a boolean"
            )
        if not isinstance(inv15_passed_emitted, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_15 passed is not a boolean"
            )
        inv15_counters = inv15_raw["counters"]
        if not isinstance(inv15_counters, dict):
            raise AnalyzerError(f"{bare_path}: inv_15 counters is not a dict")
        inv15_counter_keys = set(inv15_counters.keys())
        expected_counter_keys = set(COUNTER_NAMES)
        if inv15_counter_keys != expected_counter_keys:
            missing = sorted(expected_counter_keys - inv15_counter_keys)
            extra = sorted(inv15_counter_keys - expected_counter_keys)
            raise AnalyzerError(
                f"{bare_path}: inv_15 counters keys mismatch "
                f"(missing={missing}, extra={extra})"
            )
        computed_all_zero = True
        for name in COUNTER_NAMES:
            value = inv15_counters[name]
            if not isinstance(value, int) or isinstance(value, bool):
                raise AnalyzerError(
                    f"{bare_path}: inv_15 counter {name} is not an integer: {value!r}"
                )
            if value != 0:
                computed_all_zero = False
        # Recompute rather than trust the emitted summaries.
        inv15_run_passed = (
            computed_all_zero
            and inv15_all_zero is True
            and inv15_passed_emitted is True
        )

        run_records.append(
            {
                "path": str(bare_path),
                "native_mode0": {
                    "inputs_per_round": mode0["inputs_per_round"],
                    "rounds": mode0["rounds"],
                    "attempts_total": mode0["attempts_total"],
                    "round_ns": bare_raw["native_mode0"]["round_ns"],
                    "mismatches": mode0["mismatches"],
                    "first_mismatch": mode0["first_mismatch"],
                    "ok_count": mode0["ok_count"],
                    "median_ns_per_attempt": mode0["median_ns_per_attempt"],
                    "min_ns_per_attempt": mode0["min_ns_per_attempt"],
                    "max_ns_per_attempt": mode0["max_ns_per_attempt"],
                    "per_attempt_ns": mode0["per_attempt_ns"],
                },
                "inv_8": {
                    "passed": inv8_run_passed,
                    "mismatches": inv8_mismatches,
                    "ok_count": inv8_ok_count,
                    "expected_true_count": inv8_expected,
                    "ok_equals_count_outcome_1": inv8_ok_eq,
                    "emitted_passed": inv8_emitted_passed,
                },
                "inv_15": {
                    "passed": inv15_run_passed,
                    "all_counters_zero": inv15_all_zero,
                    "passed_emitted": inv15_passed_emitted,
                    "computed_all_zero": computed_all_zero,
                    "counters": {name: int(inv15_counters[name]) for name in COUNTER_NAMES},
                },
                "rust_secp_diagnostic": bare_raw.get("rust_secp_diagnostic"),
            }
        )

    if not run_medians:
        raise AnalyzerError("no bare run files provided")

    # Authoritative Y is the median of each run's validated per-round median.
    y_ns = statistics.median(run_medians)
    y_us = y_ns / 1000.0

    if not all_per_attempt_ns:
        raise AnalyzerError("no bare per-round timing values")
    bare_spread_ns = max(all_per_attempt_ns) - min(all_per_attempt_ns)
    bare_spread_us = bare_spread_ns / 1000.0

    inv8_passed = all(r["inv_8"]["passed"] for r in run_records)
    inv15_passed = all(r["inv_15"]["passed"] for r in run_records)

    # Rust secp diagnostic is a per-run non-gating observation; report first present.
    rust_secp_diagnostic = next(
        (r["rust_secp_diagnostic"] for r in run_records if r["rust_secp_diagnostic"] is not None),
        None,
    )

    # INV-14: reproducible source-identity proof from integrity JSON.
    # Object-byte identity is deliberately not required because RelWithDebInfo
    # embeds absolute source paths; the build has no LTO/IPO.
    integrity_raw = json.loads(Path(args.integrity).read_text())
    if not isinstance(integrity_raw, dict):
        raise AnalyzerError(f"{args.integrity}: JSON root is not an object")
    for field in (
        "pristine_source_hash",
        "patched_source_hash",
        "pristine_secp_tree_hash",
        "patched_secp_tree_hash",
    ):
        if field not in integrity_raw:
            raise AnalyzerError(f"{args.integrity}: missing {field}")
        value = integrity_raw[field]
        if not isinstance(value, str) or len(value) != 64 or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise AnalyzerError(
                f"{args.integrity}: {field} is not a 64-character lowercase hex string"
            )
    pristine_pubkey = integrity_raw["pristine_source_hash"]
    patched_pubkey = integrity_raw["patched_source_hash"]
    pristine_secp = integrity_raw["pristine_secp_tree_hash"]
    patched_secp = integrity_raw["patched_secp_tree_hash"]
    recompute_pubkey_identical = pristine_pubkey == patched_pubkey
    recompute_secp_identical = pristine_secp == patched_secp
    inv14_pubkey_identical = integrity_raw.get("pubkey_source_identical")
    inv14_secp_identical = integrity_raw.get("secp_tree_identical")
    if not isinstance(inv14_pubkey_identical, bool):
        raise AnalyzerError(
            "integrity JSON: missing or non-boolean pubkey_source_identical"
        )
    if not isinstance(inv14_secp_identical, bool):
        raise AnalyzerError(
            "integrity JSON: missing or non-boolean secp_tree_identical"
        )
    # Gate on recomputed equality and require the emitted booleans to agree.
    inv14_passed = (
        recompute_pubkey_identical
        and recompute_secp_identical
        and inv14_pubkey_identical is recompute_pubkey_identical
        and inv14_secp_identical is recompute_secp_identical
    )

    # Census data
    a_calls = capture_counters.ecdsa_verify_calls
    a_ratio = a_calls / k_entries

    # Floor and residual (all in µs)
    f_us = a_ratio * y_us
    r_us = x_us - f_us
    r_frac = r_us / x_us if x_us != 0 else 0.0

    # Threshold: 5% of total wall, expressed as fraction of script wall
    current_wall = float(args.current_wall_seconds)
    current_script_wall = float(args.current_script_wall_seconds)
    if current_script_wall == 0:
        raise AnalyzerError("current_script_wall_seconds == 0")
    threshold = 0.05 * current_wall / current_script_wall

    # Noise estimate
    noise_us = spike_spread_us + abs(a_ratio * bare_spread_us)

    # EXP-3: a in (0, 2]
    exp3_passed = 0.0 < a_ratio <= 2.0

    # Determine verdict
    if not inv8_passed or not inv14_passed or not inv15_passed:
        verdict = "INVALID"
        rationale = "Bare arm integrity check failed (INV-8/14/15)"
    elif r_us < -noise_us:
        verdict = "INVALID"
        rationale = (
            f"R = {r_us:.4f} µs < -noise = {-noise_us:.4f} µs; "
            "capture or comparator is wrong"
        )
    elif r_frac >= threshold:
        verdict = "OPEN"
        rationale = f"r = {r_frac:.4f} >= threshold = {threshold:.4f}"
    else:
        verdict = "CLOSED"
        rationale = f"r = {r_frac:.4f} < threshold = {threshold:.4f}"

    report = {
        "schema": "verdict-v1",
        "verdict": verdict,
        "rationale": rationale,
        "X_us_per_check": x_us,
        "Y_ns_per_attempt": y_ns,
        "Y_us_per_attempt": y_us,
        "A_ecdsa_verify_calls": a_calls,
        "K_ffi_verify_entries": k_entries,
        "a_attempts_per_check": a_ratio,
        "F_us_per_check": f_us,
        "R_us_per_check": r_us,
        "r_residual_fraction": r_frac,
        "threshold": threshold,
        "current_wall_seconds": current_wall,
        "current_script_wall_seconds": current_script_wall,
        "spike_run_values": spike_values,
        "spike_spread_us": spike_spread_us,
        "bare_spread_ns": bare_spread_ns,
        "bare_spread_us": bare_spread_us,
        "noise_us": noise_us,
        "bare_runs": run_records,
        "run_medians_ns_per_attempt": run_medians,
        "inv_8": {"passed": inv8_passed},
        "rust_secp_diagnostic": rust_secp_diagnostic,
        "inv_14": {
            "passed": inv14_passed,
            "pubkey_source_identical": inv14_pubkey_identical,
            "secp_tree_identical": inv14_secp_identical,
            "pubkey_source_identical_recomputed": recompute_pubkey_identical,
            "secp_tree_identical_recomputed": recompute_secp_identical,
            "pristine_source_hash": pristine_pubkey,
            "patched_source_hash": patched_pubkey,
            "pristine_secp_tree_hash": pristine_secp,
            "patched_secp_tree_hash": patched_secp,
            "note": integrity_raw.get("note"),
        },
        "inv_15": {"passed": inv15_passed},
        "EXP-3": {
            "passed": exp3_passed,
            "a_attempts_per_check": a_ratio,
            "statement": "a in (0, 2]",
        },
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    print(f"verdict: {verdict} — {rationale}")
    return 0 if verdict != "INVALID" else 2

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="analyze.py",
        description="CHECKSIG census analyzer",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    vc = sub.add_parser("validate-capture", help="validate Run B capture artifacts")
    vc.add_argument("--counters", required=True, help="Run B counters JSON (first run)")
    vc.add_argument("--records", required=True, help="Run B records binary (first run)")
    vc.add_argument("--journal", required=True, help="Run B journal binary (first run)")
    vc.add_argument("--repeat-counters", required=True, help="Run B counters JSON (second run)")
    vc.add_argument("--repeat-records", required=True, help="Run B records binary (second run)")
    vc.add_argument("--repeat-journal", required=True, help="Run B journal binary (second run)")
    vc.add_argument("--output", required=True, help="output validation report JSON")
    vc.add_argument(
        "--sorted-records-output",
        default=None,
        help="optional: write sorted records binary here",
    )
    vc.set_defaults(func=cmd_validate_capture)

    vs = sub.add_parser("validate-census", help="validate Run A census + cross-check with Run B")
    vs.add_argument("--counters", required=True, help="Run A census counters JSON")
    vs.add_argument("--journal", required=True, help="Run A census journal binary")
    vs.add_argument("--capture-journal", required=True, help="Run B capture journal binary")
    vs.add_argument("--output", required=True, help="output validation report JSON")
    vs.set_defaults(func=cmd_validate_census)

    vd = sub.add_parser("verdict", help="compute OPEN/CLOSED/INVALID verdict")
    vd.add_argument("--capture-counters", required=True, help="Run B capture counters JSON")
    vd.add_argument(
        "--bare-runs",
        required=True,
        nargs="+",
        help="exactly three bare-secp timing JSON files (Run C)",
    )
    vd.add_argument(
        "--spike-runs",
        required=True,
        nargs="+",
        help="exactly three spike run JSON files (Run D)",
    )
    vd.add_argument(
        "--current-wall-seconds",
        required=True,
        type=float,
        help="current total replay wall time in seconds",
    )
    vd.add_argument(
        "--current-script-wall-seconds",
        required=True,
        type=float,
        help="current script verification wall time in seconds",
    )
    vd.add_argument("--output", required=True, help="output verdict JSON")
    vd.add_argument(
        "--integrity",
        required=True,
        help="integrity JSON (INV-14 source-identity proof: pubkey.cpp and secp256k1 tree hashes)",
    )
    vd.set_defaults(func=cmd_verdict)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except AnalyzerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except (KeyError, ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
