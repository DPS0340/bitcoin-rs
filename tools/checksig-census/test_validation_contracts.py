#!/usr/bin/env python3
"""Regression guards for analyze.py validation contracts.

Tests the observable behavior of:
- Counters parsing rejects malformed untrusted analyzer input (INV-gate)
- ffi_verify_entries gate makes all_passed false on wrong corpus (Finding 2)
- sorted-records output prepends BRSREC1 header + u64 count (Finding 1)
- extract_spike_width1 rejects non-integer or non-1 threads (Finding 5)
- cmd_verdict cross-checks native_mode0 vs inv_8 (Finding 4)

Stdlib-only, Python 3.12+. Run: python3 test_validation_contracts.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

# Make analyze importable
sys.path.insert(0, str(Path(__file__).parent))
from analyze import (
    COUNTER_NAMES,
    EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1,
    HEADER_STRUCT,
    JOURNAL_MAGIC,
    JOURNAL_STRUCT,
    RECORD_MAGIC,
    RECORD_STRUCT,
    AnalyzerError,
    Counters,
    extract_bare_mode0,
    extract_spike_width1,
    parse_records,
    sort_records_raw,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _valid_counters_dict(**overrides: object) -> dict[str, object]:
    """Return a counters dict with all 22 fields set to valid values."""
    d: dict[str, object] = {name: 0 for name in COUNTER_NAMES}
    d["schema"] = 1
    d["label"] = "test"
    d["record_count"] = 0
    d["journal_count"] = 0
    d.update(overrides)
    return d


def _make_record_bytes(txid: bytes, input_index: int) -> bytes:
    """Build a minimal valid 224-byte record."""
    fields = (
        txid,  # 32s spend_txid
        input_index,  # I input_index
        0,  # I op_seq
        0,  # B op_kind
        0,  # B sig_version
        1,  # B outcome (true)
        0,  # B der_len
        0,  # B pubkey_len
        0,  # B sighash_type
        0,  # B reject_reason
        0,  # B _pad0
        b"\x00" * 32,  # 32s sighash
        b"\x00" * 72,  # 72s der_sig
        b"\x00" * 65,  # 65s pubkey
        b"\x00" * 7,  # 7s _pad1
    )
    return RECORD_STRUCT.pack(*fields)


def _make_journal_bytes(
    txid: bytes,
    input_index: int,
    *,
    checksig_ops: int = 0,
    checkmultisig_ops: int = 0,
    ecdsa_verify_calls: int = 0,
    ecdsa_verify_ok: int = 0,
    verdict: int = 0,
) -> bytes:
    """Build a minimal valid 56-byte journal entry."""
    fields = (
        txid,  # 32s spend_txid
        input_index,  # I input_index
        checksig_ops,  # I checksig_ops
        checkmultisig_ops,  # I checkmultisig_ops
        ecdsa_verify_calls,  # I ecdsa_verify_calls
        ecdsa_verify_ok,  # I ecdsa_verify_ok
        verdict,  # B verdict
        b"\x00" * 3,  # 3s pad
    )
    return JOURNAL_STRUCT.pack(*fields)


def _write_records_file(path: Path, records: list[bytes]) -> None:
    """Write a records file with magic header + count + raw records."""
    data = HEADER_STRUCT.pack(RECORD_MAGIC, len(records)) + b"".join(records)
    path.write_bytes(data)


def _write_journal_file(path: Path, entries: list[bytes]) -> None:
    """Write a journal file with magic header + count + raw entries."""
    data = HEADER_STRUCT.pack(JOURNAL_MAGIC, len(entries)) + b"".join(entries)
    path.write_bytes(data)


# ── Tests: Counters validation (Finding 3) ───────────────────────────────────


def test_counters_rejects_missing_field() -> None:
    """A counters dict missing a required COUNTER_NAMES field must raise."""
    d = _valid_counters_dict()
    del d["ffi_verify_entries"]
    try:
        Counters(d)
    except AnalyzerError as e:
        assert "ffi_verify_entries" in str(e)
        return
    raise AssertionError("expected AnalyzerError for missing field")


def test_counters_rejects_non_int_value() -> None:
    """A counters dict with a string value must raise."""
    d = _valid_counters_dict()
    d["op_checksig"] = "not_an_int"
    try:
        Counters(d)
    except AnalyzerError as e:
        assert "op_checksig" in str(e)
        return
    raise AssertionError("expected AnalyzerError for non-int value")


def test_counters_rejects_bool_value() -> None:
    """Python bools are ints but must be rejected for counter fields."""
    d = _valid_counters_dict()
    d["ecdsa_verify_ok"] = True
    try:
        Counters(d)
    except AnalyzerError as e:
        assert "ecdsa_verify_ok" in str(e)
        return
    raise AssertionError("expected AnalyzerError for bool value")


def test_counters_rejects_negative_value() -> None:
    """A counters dict with a negative value must raise."""
    d = _valid_counters_dict()
    d["sighash_computed"] = -1
    try:
        Counters(d)
    except AnalyzerError as e:
        assert "sighash_computed" in str(e)
        return
    raise AssertionError("expected AnalyzerError for negative value")


def test_counters_accepts_valid_dict() -> None:
    """A well-formed counters dict must parse without error."""
    d = _valid_counters_dict(ffi_verify_entries=42, op_checksig=42)
    c = Counters(d)
    assert c.ffi_verify_entries == 42
    assert c.op_checksig == 42


# ── Tests: ffi_verify_entries gate (Finding 2) ───────────────────────────────


def test_validate_capture_rejects_wrong_ffi_verify_entries() -> None:
    """Wrong ffi_verify_entries must fail *only* EXP-KSPIKE1, not any INV.

    Every invariant INV-1 through INV-13 must pass with a self-consistent
    1-entry corpus; the sole failure is ffi_verify_entries != the expected
    KSPIKE1 anchor, so the failed-id list is exactly ['EXP-KSPIKE1'].
    """
    import argparse
    import contextlib
    import io

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        txid = b"\x01" * 32
        recs = [_make_record_bytes(txid, 0)]
        _write_records_file(tmp / "records.bin", recs)
        _write_records_file(tmp / "repeat.bin", recs)
        jnl = [
            _make_journal_bytes(
                txid,
                0,
                checksig_ops=1,
                ecdsa_verify_calls=1,
                ecdsa_verify_ok=1,
                verdict=1,
            )
        ]
        _write_journal_file(tmp / "journal.bin", jnl)
        _write_journal_file(tmp / "repeat_journal.bin", jnl)

        # Self-consistent counters with ffi_verify_entries=1 (not 159259).
        # INV-1: verify_script_calls == ffi_verify_entries            → 1==1 ✓
        # INV-2: ffi_verify_true == ffi_verify_entries                → 1==1 ✓
        # INV-3: checkecdsa_entries == from_checksig + from_checkmultisig → 1==1+0 ✓
        # INV-4: checkecdsa_entries == ecdsa_verify_calls + rejects   → 1==1+0 ✓
        # INV-5: ecdsa_verify_calls == ok+fail and == sighash_computed → 1==1+0 and 1==1 ✓
        # INV-6: ecdsa_from_checksig <= op_checksig + op_checksigverify → 1<=1+0 ✓
        # INV-7: op_checksigadd==0, checkschnorr==0, schnorr_verify==0 → all 0 ✓
        # INV-9: 1 record (outcome=1) == ecdsa_verify_calls; 1 total == checkecdsa_entries ✓
        # INV-10: journal sums match counters                         → 1==1, 1==1, 0==0, 1==1 ✓
        # INV-11: no duplicate keys                                   → 1 record ✓
        # INV-13: both runs identical                                 → same data ✓
        c = _valid_counters_dict(
            ffi_verify_entries=1,
            verify_script_calls=1,
            ffi_verify_true=1,
            checkecdsa_entries=1,
            ecdsa_from_checksig=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
            sighash_computed=1,
            op_checksig=1,
            record_count=1,
            journal_count=1,
        )
        (tmp / "counters.json").write_text(json.dumps(c))
        (tmp / "repeat_counters.json").write_text(json.dumps(c))

        out = tmp / "report.json"
        sorted_out = tmp / "sorted.bin"
        args = argparse.Namespace(
            subcommand="validate-capture",
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=out,
            sorted_records_output=sorted_out,
        )
        stderr_buf = io.StringIO()
        with contextlib.redirect_stderr(stderr_buf):
            rc = analyze.cmd_validate_capture(args)
        assert rc == 1, "expected return code 1 for wrong ffi_verify_entries"
        report = json.loads(out.read_text())
        assert report["all_passed"] is False
        # Every invariant must pass — the only failure is the EXP-KSPIKE1 gate.
        inv_failed = [r["id"] for r in report["invariants"] if not r["passed"]]
        assert inv_failed == [], f"invariants should all pass, but {inv_failed} failed"
        # The stderr message lists the exact failed IDs.
        stderr_msg = stderr_buf.getvalue().strip()
        assert "EXP-KSPIKE1" in stderr_msg, (
            f"stderr should mention EXP-KSPIKE1, got: {stderr_msg!r}"
        )
        # No INV- should appear in the failed list.
        for inv_id in (
            "INV-1",
            "INV-2",
            "INV-3",
            "INV-4",
            "INV-5",
            "INV-6",
            "INV-7",
            "INV-9",
            "INV-10",
            "INV-11",
            "INV-13",
        ):
            assert inv_id not in stderr_msg, (
                f"{inv_id} should not be in failed list, stderr: {stderr_msg!r}"
            )


def test_validate_capture_sorted_output_has_header() -> None:
    """The sorted-records output file must start with BRSREC1 magic + u64 count."""
    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        recs = [
            _make_record_bytes(b"\x02" * 32, 1),
            _make_record_bytes(b"\x01" * 32, 0),
        ]
        _write_records_file(tmp / "records.bin", recs)
        _write_records_file(tmp / "repeat.bin", recs)
        _write_journal_file(tmp / "journal.bin", [])
        _write_journal_file(tmp / "repeat_journal.bin", [])

        c = _valid_counters_dict(
            ffi_verify_entries=EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1,
            ffi_verify_true=2,
            record_count=2,
            journal_count=0,
        )
        (tmp / "counters.json").write_text(json.dumps(c))
        (tmp / "repeat_counters.json").write_text(json.dumps(c))

        out = tmp / "report.json"
        sorted_out = tmp / "sorted.bin"

        import argparse

        args = argparse.Namespace(
            subcommand="validate-capture",
            counters=tmp / "counters.json",
            records=tmp / "records.bin",
            journal=tmp / "journal.bin",
            repeat_counters=tmp / "repeat_counters.json",
            repeat_records=tmp / "repeat.bin",
            repeat_journal=tmp / "repeat_journal.bin",
            output=out,
            sorted_records_output=sorted_out,
        )
        # Will fail because counters don't match records, but sorted output is still written
        analyze.cmd_validate_capture(args)

        data = sorted_out.read_bytes()
        magic, count = HEADER_STRUCT.unpack_from(data, 0)
        assert magic == RECORD_MAGIC, f"bad magic {magic!r}"
        assert count == 2, f"expected count 2, got {count}"
        # Verify the payload is sorted
        payload = data[HEADER_STRUCT.size :]
        sorted_recs = sort_records_raw(recs)
        assert payload == sorted_recs, (
            "sorted payload must match sort_records_raw output"
        )


def test_records_reject_invalid_encoded_fields() -> None:
    """BRSREC1 readers must reject impossible length and outcome metadata."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = Path(tmpdir) / "records.bin"
        for offset, bad, field in (
            (42, 3, "outcome"),
            (43, 73, "der_len"),
            (44, 66, "pubkey_len"),
        ):
            record = bytearray(_make_record_bytes(b"\x01" * 32, 0))
            record[offset] = bad
            _write_records_file(path, [bytes(record)])
            try:
                parse_records(path)
            except AnalyzerError:
                continue
            raise AssertionError(f"expected AnalyzerError for {field}={bad}")


# ── Tests: extract_spike_width1 validation (Finding 5) ───────────────────────


def test_spike_rejects_non_integer_threads() -> None:
    """Top-level us_per_input with non-integer threads must raise."""
    try:
        extract_spike_width1({"us_per_input": 50.0, "threads": "1"})
    except AnalyzerError:
        return
    raise AssertionError("expected AnalyzerError for string threads")


def test_spike_rejects_bool_threads() -> None:
    """Top-level us_per_input with bool threads must raise."""
    try:
        extract_spike_width1({"us_per_input": 50.0, "threads": True})
    except AnalyzerError:
        return
    raise AssertionError("expected AnalyzerError for bool threads")


def test_spike_rejects_threads_not_1() -> None:
    """Top-level us_per_input with threads != 1 must raise."""
    try:
        extract_spike_width1({"us_per_input": 50.0, "threads": 2})
    except AnalyzerError:
        return
    raise AssertionError("expected AnalyzerError for threads == 2")


def test_spike_accepts_threads_1() -> None:
    """Top-level us_per_input with threads == 1 must succeed."""
    val = extract_spike_width1({"us_per_input": 50.0, "threads": 1})
    assert val == 50.0


def test_spike_accepts_runs_list_with_threads_1() -> None:
    """A runs list containing a run with threads == 1 must succeed."""
    val = extract_spike_width1(
        {
            "runs": [
                {"threads": 4, "us_per_input": 25.0},
                {"threads": 1, "us_per_input": 50.0},
            ]
        }
    )
    assert val == 50.0


def test_spike_rejects_runs_list_without_threads_1() -> None:
    """A runs list with no threads == 1 run must raise."""
    try:
        extract_spike_width1({"runs": [{"threads": 4, "us_per_input": 25.0}]})
    except AnalyzerError:
        return
    raise AssertionError("expected AnalyzerError for no threads==1 run")


def test_spike_rejects_runs_list_bool_threads() -> None:
    """A runs list with boolean threads must not be accepted as threads == 1."""
    try:
        extract_spike_width1({"runs": [{"threads": True, "us_per_input": 50.0}]})
    except AnalyzerError:
        return
    raise AssertionError("expected AnalyzerError for bool threads in runs list")


def test_spike_rejects_nonfinite_us_per_input() -> None:
    """Spike us_per_input must be a finite positive number in both forms."""
    bad_values = [float("nan"), float("inf"), 0.0, -1.0]
    for bad in bad_values:
        try:
            extract_spike_width1({"us_per_input": bad, "threads": 1})
        except AnalyzerError:
            continue
        raise AssertionError(
            f"expected AnalyzerError for top-level us_per_input={bad!r}"
        )
    for bad in bad_values:
        try:
            extract_spike_width1({"runs": [{"threads": 1, "us_per_input": bad}]})
        except AnalyzerError:
            continue
        raise AssertionError(f"expected AnalyzerError for list us_per_input={bad!r}")


def test_bare_rejects_nonfinite_reported_values() -> None:
    """Reported bare median/min/max must be finite positive numbers."""
    for field in ("median_ns_per_attempt", "min_ns_per_attempt", "max_ns_per_attempt"):
        for bad in (float("nan"), float("inf"), -1.0):
            bare = _make_bare_run_json()
            bare["native_mode0"][field] = bad
            try:
                extract_bare_mode0(bare)
            except AnalyzerError:
                continue
            raise AssertionError(f"expected AnalyzerError for {field}={bad!r}")


def test_bare_rejects_invalid_round_ns_types() -> None:
    """round_ns must contain integers and must not accept booleans."""
    for bad, reported in ((100.5, 100.5), ("100", 100.0), (True, 1.0)):
        bare = _make_bare_run_json()
        bare["native_mode0"]["round_ns"] = [bad]
        for field in (
            "median_ns_per_attempt",
            "min_ns_per_attempt",
            "max_ns_per_attempt",
        ):
            bare["native_mode0"][field] = reported
        try:
            extract_bare_mode0(bare)
        except AnalyzerError:
            continue
        raise AssertionError(f"expected AnalyzerError for round_ns={bad!r}")


def test_bare_rejects_nonpositive_round_ns() -> None:
    """round_ns must contain positive values."""
    for bad in (-50, 0):
        bare = _make_bare_run_json()
        bare["native_mode0"]["round_ns"] = [bad]
        try:
            extract_bare_mode0(bare)
        except AnalyzerError:
            continue
        raise AssertionError(f"expected AnalyzerError for round_ns={bad!r}")


def test_bare_rejects_non_integer_summary_fields() -> None:
    """Native timing summaries must not coerce booleans or floats to integers."""
    for field in (
        "inputs_per_round",
        "rounds",
        "attempts_total",
        "mismatches",
        "ok_count",
    ):
        for bad in (True, 1.5):
            bare = _make_bare_run_json()
            bare["native_mode0"][field] = bad
            try:
                extract_bare_mode0(bare)
            except AnalyzerError:
                continue
            raise AssertionError(f"expected AnalyzerError for {field}={bad!r}")


def test_verdict_rejects_invalid_numeric_fields() -> None:
    """Verdict inputs must preserve strict integer and positive-finite contracts."""
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        cap = _valid_counters_dict(
            ffi_verify_entries=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
        )
        cap_path = tmp / "capture.json"
        cap_path.write_text(json.dumps(cap))

        integrity = _make_integrity_json()
        integrity_path = tmp / "integrity.json"
        integrity_path.write_text(json.dumps(integrity))

        spike = {"us_per_input": 50.0, "threads": 1}
        spike_paths = []
        for i in range(3):
            p = tmp / f"spike{i}.json"
            p.write_text(json.dumps(spike))
            spike_paths.append(p)

        bare = _make_bare_run_json()
        bare_paths = []
        for i in range(3):
            p = tmp / f"bare{i}.json"
            p.write_text(json.dumps(bare))
            bare_paths.append(p)

        out = tmp / "verdict.json"

        for current_wall, current_script in (
            (-1.0, 50.0),
            (100.0, -1.0),
            (float("nan"), 50.0),
            (100.0, float("inf")),
        ):
            args = argparse.Namespace(
                capture_counters=cap_path,
                bare_runs=bare_paths,
                spike_runs=spike_paths,
                current_wall_seconds=current_wall,
                current_script_wall_seconds=current_script,
                output=out,
                integrity=integrity_path,
            )
            try:
                analyze.cmd_verdict(args)
            except AnalyzerError:
                continue
            raise AssertionError(
                f"expected AnalyzerError for wall={current_wall!r}, script={current_script!r}"
            )

        for field in ("mismatches", "ok_count", "expected_true_count"):
            for bad in (True, 1.5):
                malformed = _make_bare_run_json()
                malformed["inv_8"][field] = bad
                for path in bare_paths:
                    path.write_text(json.dumps(malformed))
                args = argparse.Namespace(
                    capture_counters=cap_path,
                    bare_runs=bare_paths,
                    spike_runs=spike_paths,
                    current_wall_seconds=100.0,
                    current_script_wall_seconds=50.0,
                    output=out,
                    integrity=integrity_path,
                )
                try:
                    analyze.cmd_verdict(args)
                except AnalyzerError:
                    continue
                raise AssertionError(
                    f"expected AnalyzerError for inv_8 {field}={bad!r}"
                )


# ── Tests: cmd_verdict native_mode0 cross-check (Finding 4) ──────────────────


def _make_bare_run_json(
    *,
    mode0_mismatches: int = 0,
    mode0_ok_count: int = 1,
    inv8_mismatches: int = 0,
    inv8_ok_count: int = 1,
    inv8_expected_true_count: int = 1,
) -> dict[str, object]:
    """Build a minimal bare-secp run JSON that passes all verdict checks.

    The native_mode0 mismatches/ok_count can be set independently from
    inv_8 to create a contradiction (Finding 4).
    """
    ns = 50000
    return {
        "native_mode0": {
            "inputs_per_round": 1,
            "rounds": 1,
            "attempts_total": 1,
            "round_ns": [ns],
            "median_ns_per_attempt": float(ns),
            "min_ns_per_attempt": float(ns),
            "max_ns_per_attempt": float(ns),
            "mismatches": mode0_mismatches,
            "first_mismatch": None,
            "ok_count": mode0_ok_count,
        },
        "inv_8": {
            "passed": True,
            "mismatches": inv8_mismatches,
            "ok_count": inv8_ok_count,
            "expected_true_count": inv8_expected_true_count,
            "ok_equals_count_outcome_1": True,
        },
        "inv_15": {
            "counters": {name: 0 for name in COUNTER_NAMES},
            "all_counters_zero": True,
            "passed": True,
        },
    }


def _make_integrity_json() -> dict[str, object]:
    """Build a valid integrity JSON where source/secp hashes match."""
    h = "0" * 64
    return {
        "pristine_source_hash": h,
        "patched_source_hash": h,
        "pristine_secp_tree_hash": h,
        "patched_secp_tree_hash": h,
        "pubkey_source_identical": True,
        "secp_tree_identical": True,
    }


def test_verdict_native_mode0_contradiction_fails() -> None:
    """Contradictory native_mode0 vs inv_8 must make verdict INVALID.

    An agreeing artifact passes (verdict is OPEN or CLOSED, return code 0),
    while a contradictory artifact (mode0.mismatches != inv_8.mismatches)
    must yield INVALID with return code 2.
    """
    import argparse

    import analyze

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # Capture counters: ffi_verify_entries=1, ecdsa_verify_calls=1 → a=1.0
        cap = _valid_counters_dict(
            ffi_verify_entries=1,
            ecdsa_verify_calls=1,
            ecdsa_verify_ok=1,
        )
        cap_path = tmp / "capture.json"
        cap_path.write_text(json.dumps(cap))

        integrity = _make_integrity_json()
        integrity_path = tmp / "integrity.json"
        integrity_path.write_text(json.dumps(integrity))

        spike = {"us_per_input": 50.0, "threads": 1}
        spike_paths = []
        for i in range(3):
            p = tmp / f"spike{i}.json"
            p.write_text(json.dumps(spike))
            spike_paths.append(p)

        out_ok = tmp / "verdict_ok.json"
        out_bad = tmp / "verdict_bad.json"

        # --- Agreeing artifact: mode0 matches inv_8 ---
        agreeing = _make_bare_run_json(
            mode0_mismatches=0,
            mode0_ok_count=1,
            inv8_mismatches=0,
            inv8_ok_count=1,
            inv8_expected_true_count=1,
        )
        agreeing_paths = []
        for i in range(3):
            p = tmp / f"agree{i}.json"
            p.write_text(json.dumps(agreeing))
            agreeing_paths.append(p)

        args_ok = argparse.Namespace(
            subcommand="verdict",
            capture_counters=cap_path,
            bare_runs=agreeing_paths,
            spike_runs=spike_paths,
            current_wall_seconds=100.0,
            current_script_wall_seconds=50.0,
            output=out_ok,
            integrity=integrity_path,
        )
        rc_ok = analyze.cmd_verdict(args_ok)
        assert rc_ok == 0, f"agreeing artifact should not be INVALID, got rc={rc_ok}"
        report_ok = json.loads(out_ok.read_text())
        assert report_ok["verdict"] != "INVALID", (
            f"agreeing artifact verdict should not be INVALID, got {report_ok['verdict']!r}"
        )
        assert report_ok["inv_8"]["passed"] is True

        # --- Contradictory artifact: mode0.mismatches != inv_8.mismatches ---
        contradictory = _make_bare_run_json(
            mode0_mismatches=1,
            mode0_ok_count=1,
            inv8_mismatches=0,
            inv8_ok_count=1,
            inv8_expected_true_count=1,
        )
        contra_paths = []
        for i in range(3):
            p = tmp / f"contra{i}.json"
            p.write_text(json.dumps(contradictory))
            contra_paths.append(p)

        args_bad = argparse.Namespace(
            subcommand="verdict",
            capture_counters=cap_path,
            bare_runs=contra_paths,
            spike_runs=spike_paths,
            current_wall_seconds=100.0,
            current_script_wall_seconds=50.0,
            output=out_bad,
            integrity=integrity_path,
        )
        rc_bad = analyze.cmd_verdict(args_bad)
        assert rc_bad == 2, (
            f"contradictory artifact should be INVALID (rc=2), got rc={rc_bad}"
        )
        report_bad = json.loads(out_bad.read_text())
        assert report_bad["verdict"] == "INVALID", (
            f"contradictory artifact should be INVALID, got {report_bad['verdict']!r}"
        )
        assert report_bad["inv_8"]["passed"] is False, (
            "INV-8 must fail when native_mode0 contradicts inv_8"
        )


# ── Runner ───────────────────────────────────────────────────────────────────


def main() -> int:
    tests = [
        test_counters_rejects_missing_field,
        test_counters_rejects_non_int_value,
        test_counters_rejects_bool_value,
        test_counters_rejects_negative_value,
        test_counters_accepts_valid_dict,
        test_validate_capture_rejects_wrong_ffi_verify_entries,
        test_validate_capture_sorted_output_has_header,
        test_records_reject_invalid_encoded_fields,
        test_spike_rejects_non_integer_threads,
        test_spike_rejects_bool_threads,
        test_spike_rejects_threads_not_1,
        test_spike_accepts_threads_1,
        test_spike_accepts_runs_list_with_threads_1,
        test_spike_rejects_runs_list_without_threads_1,
        test_spike_rejects_runs_list_bool_threads,
        test_spike_rejects_nonfinite_us_per_input,
        test_bare_rejects_nonfinite_reported_values,
        test_bare_rejects_invalid_round_ns_types,
        test_bare_rejects_nonpositive_round_ns,
        test_bare_rejects_non_integer_summary_fields,
        test_verdict_rejects_invalid_numeric_fields,
        test_verdict_native_mode0_contradiction_fails,
    ]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS  {test.__name__}")
            passed += 1
        # Run every guard so one failure does not hide the remaining broken contracts.
        except Exception as e:  # noqa: BLE001
            print(f"  FAIL  {test.__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(tests)} total")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
