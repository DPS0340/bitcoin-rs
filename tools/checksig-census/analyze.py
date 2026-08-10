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
import math
import re
import sqlite3
import statistics
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterator

from context import (
    ClassifiedInput,
    ContextError,
    ContextInput,
    InputIdentity,
    SpendContext,
    classify_input,
    iter_context_inputs,
)

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
    "schnorr_verify_ok",
    "schnorr_verify_fail",
]


CONTEXT_INPUT_SCHEMA = "census-context-input-v1"

CONTEXT_COUNTER_NAMES: list[str] = [
    "p2sh_redeem_spends",
    "native_witness_v0_spends",
    "p2sh_wrapped_witness_v0_spends",
    "bare_multisig_checks",
    "p2sh_multisig_checks",
    "native_witness_v0_multisig_checks",
    "p2sh_wrapped_witness_v0_multisig_checks",
    "taproot_key_path_spends",
    "tapscript_spends",
    "tapscript_schnorr_checks",
    "tapscript_checksigadd_checks",
]

CONTEXT_COUNTER_DEFINITIONS: dict[str, str] = {
    "p2sh_redeem_spends": "non-coinbase inputs whose prevout is P2SH and whose redeem script is not a witness-v0 program",
    "native_witness_v0_spends": "non-coinbase inputs whose prevout is a native witness-v0 program (P2WPKH or P2WSH)",
    "p2sh_wrapped_witness_v0_spends": "non-coinbase inputs whose prevout is P2SH and whose redeem script is a witness-v0 program",
    "bare_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a bare legacy input",
    "p2sh_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a P2SH input",
    "native_witness_v0_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a native witness-v0 input",
    "p2sh_wrapped_witness_v0_multisig_checks": "BRSREC1 executed-operation records with op_kind CHECKMULTISIG or CHECKMULTISIGVERIFY joined to a P2SH-wrapped witness-v0 input",
    "taproot_key_path_spends": "P2TR inputs with one witness element after optional annex removal",
    "tapscript_spends": "P2TR inputs with at least two witness elements after optional annex removal",
    "tapscript_schnorr_checks": "BRSREC1 executed-operation records with sig_version TAPSCRIPT and op_kind CHECKSIG, CHECKSIGVERIFY, or CHECKSIGADD",
    "tapscript_checksigadd_checks": "BRSREC1 executed-operation records with sig_version TAPSCRIPT and op_kind CHECKSIGADD",
}

MULTISIG_ELIGIBLE_CONTEXTS: frozenset[SpendContext] = frozenset((
    SpendContext.BARE,
    SpendContext.P2SH,
    SpendContext.NATIVE_WITNESS_V0,
    SpendContext.P2SH_WRAPPED_WITNESS_V0,
))

HEADER_STRUCT = struct.Struct("<8sQ")
RECORD_STRUCT = struct.Struct("<32sIIBBBBBBBB32s72s65s7s")
JOURNAL_STRUCT = struct.Struct("<32sIIIIIB3s")

assert HEADER_STRUCT.size == HEADER_SIZE
assert RECORD_STRUCT.size == RECORD_SIZE
assert JOURNAL_STRUCT.size == JOURNAL_SIZE

# ── Canonical mainnet constants ─────────────────────────────────────────────

MAINNET_MAGIC = "f9beb4d9"
MAINNET_GENESIS_HASH = (
    "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
)
C150_STOP_HEIGHT = 150_000
C150_STOP_HASH = (
    "0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b"
)


# ── Exceptions ──────────────────────────────────────────────────────────────


class AnalyzerError(Exception):
    """Fatal: malformed input or unparseable file."""


def _require_positive_finite_float(value: object, field: str) -> float:
    """Return value as float, or raise AnalyzerError if it is not a finite,
    non-boolean, positive int/float.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise AnalyzerError(
            f"{field} must be a non-boolean int or float, got {type(value).__name__}"
        )
    f = float(value)
    if math.isnan(f) or math.isinf(f):
        raise AnalyzerError(f"{field} must be finite, got {value!r}")
    if f <= 0.0:
        raise AnalyzerError(f"{field} must be > 0, got {value!r}")
    return f


def _require_non_bool_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalyzerError(
            f"{field} must be a non-boolean integer, got {type(value).__name__}"
        )
    return value


def _require_exact_keys(
    d: dict[str, object], expected: set[str], label: str
) -> None:
    """Reject unknown or missing keys in *d* against *expected*."""
    actual = set(d.keys())
    unknown = actual - expected
    if unknown:
        raise AnalyzerError(
            f"CTX-CUSTODY: {label} has unknown key(s): {sorted(unknown)}"
        )
    missing = expected - actual
    if missing:
        raise AnalyzerError(
            f"CTX-CUSTODY: {label} missing required key(s): {sorted(missing)}"
        )


def _require_u32(value: object, field: str) -> int:
    """Validate a u32 (0 ..= 2**32-1)."""
    v = _require_non_bool_int(value, field)
    if v < 0 or v > 0xFFFFFFFF:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be u32 (0..{0xFFFFFFFF}), got {v}"
        )
    return v


def _require_u64(value: object, field: str) -> int:
    """Validate a u64 (0 ..= 2**64-1)."""
    v = _require_non_bool_int(value, field)
    if v < 0 or v > 0xFFFFFFFFFFFFFFFF:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be u64, got {v}"
        )
    return v


def _require_custody_ref(value: object, label: str, *, with_schema: bool = False) -> dict[str, object]:
    """Validate a custody reference object (path/bytes/sha256, optionally schema/version)."""
    if not isinstance(value, dict):
        raise AnalyzerError(f"CTX-CUSTODY: {label} must be an object")
    expected = {"path", "bytes", "sha256"}
    if with_schema:
        expected |= {"schema", "version"}
    _require_exact_keys(value, expected, label)
    path = value["path"]
    if not isinstance(path, str) or len(path) == 0:
        raise AnalyzerError(f"CTX-CUSTODY: {label}.path must be a nonempty string")
    bytes_val = _require_non_bool_int(value["bytes"], f"{label}.bytes")
    if bytes_val < 0:
        raise AnalyzerError(f"CTX-CUSTODY: {label}.bytes must be >= 0, got {bytes_val}")
    sha = _require_hex_str(value["sha256"], f"{label}.sha256", 64)
    result: dict[str, object] = {"path": path, "bytes": bytes_val, "sha256": sha}
    if with_schema:
        schema = value["schema"]
        if schema != "bitcoin-rs-corpus-manifest":
            raise AnalyzerError(
                f"CTX-CUSTODY: {label}.schema is {schema!r}, "
                f"expected 'bitcoin-rs-corpus-manifest'"
            )
        version = _require_int_field(value["version"], f"{label}.version")
        if version != 1:
            raise AnalyzerError(f"CTX-CUSTODY: {label}.version must be 1, got {version}")
        result["schema"] = schema
        result["version"] = version
    return result


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
    schnorr_verify_ok: int
    schnorr_verify_fail: int
    context_count: int

    def __init__(self, raw: dict[str, object]) -> None:
        self._raw = raw
        self.schema: int = int(raw.get("schema", 0))
        self.label: str = str(raw.get("label", ""))
        for name in COUNTER_NAMES:
            if name not in raw:
                raise AnalyzerError(f"counters JSON: missing required field {name!r}")
            value = raw[name]
            if isinstance(value, bool) or not isinstance(value, int):
                raise AnalyzerError(
                    f"counters JSON: field {name!r} must be int, got {type(value).__name__}"
                )
            if value < 0:
                raise AnalyzerError(
                    f"counters JSON: field {name!r} must be >= 0, got {value}"
                )
            setattr(self, name, value)
        # ── Reconciliation count fields: required, strict non-bool nonnegative int ──
        for _rc_field in ("record_count", "journal_count", "context_count"):
            if _rc_field not in raw:
                raise AnalyzerError(
                    f"counters JSON: missing required field {_rc_field!r}"
                )
            _rc_val = raw[_rc_field]
            if isinstance(_rc_val, bool) or not isinstance(_rc_val, int):
                raise AnalyzerError(
                    f"counters JSON: field {_rc_field!r} must be int, "
                    f"got {type(_rc_val).__name__}"
                )
            if _rc_val < 0:
                raise AnalyzerError(
                    f"counters JSON: field {_rc_field!r} must be >= 0, got {_rc_val}"
                )
        self.record_count: int = raw["record_count"]
        self.journal_count: int = raw["journal_count"]
        self.context_count: int = raw["context_count"]

class Record:
    """Parsed 224-byte record."""

    __slots__ = (
        "spend_txid",
        "input_index",
        "op_seq",
        "op_kind",
        "sig_version",
        "outcome",
        "der_len",
        "pubkey_len",
        "sighash_type",
        "reject_reason",
        "sighash",
        "der_sig",
        "pubkey",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = RECORD_STRUCT.unpack(raw)
        (
            self.spend_txid,
            self.input_index,
            self.op_seq,
            self.op_kind,
            self.sig_version,
            self.outcome,
            self.der_len,
            self.pubkey_len,
            self.sighash_type,
            self.reject_reason,
            _pad0,
            self.sighash,
            self.der_sig,
            self.pubkey,
            _pad1,
        ) = unpacked
        # ── Canonical field-range validation ──
        if self.op_kind > 5:
            raise AnalyzerError(f"CTX-OPERATIONS: record op_kind {self.op_kind} exceeds 5")
        if self.sig_version > 3:
            raise AnalyzerError(f"CTX-OPERATIONS: record sig_version {self.sig_version} exceeds 3")
        if self.outcome > 2:
            raise AnalyzerError(f"CTX-OPERATIONS: record outcome {self.outcome} exceeds 2")
        if self.reject_reason > 8:
            raise AnalyzerError(f"CTX-OPERATIONS: record reject_reason {self.reject_reason} exceeds 8")
        # Canonical outcome/reject combinations:
        # outcome 0/1 (post-verification) must not carry a reject reason.
        # outcome 2 (pre-verification reject) must have a valid reason and no sighash.
        if self.outcome in (0, 1) and self.reject_reason != 0:
            raise AnalyzerError(
                f"CTX-OPERATIONS: outcome {self.outcome} must have reject_reason 0, "
                f"got {self.reject_reason}"
            )
        if self.outcome == 2:
            if self.reject_reason == 0:
                raise AnalyzerError(
                    "CTX-OPERATIONS: outcome 2 (pre-verification reject) must have a non-zero reject_reason"
                )
            if self.sighash != b"\x00" * 32:
                raise AnalyzerError(
                    "CTX-OPERATIONS: pre-verification reject must have an all-zero sighash"
                )
            # ── Reject-family compatibility: exact native emission ──
            _is_ecdsa_rec = self.sig_version in (0, 1) and self.op_kind in (1, 2, 3, 4)
            _is_schnorr_rec = (
                (self.sig_version == 2 and self.op_kind in (1, 2, 5))
                or (self.sig_version == 3 and self.op_kind == 0)
            )
            _is_tapscript_skip = (
                self.sig_version == 2 and self.op_kind in (1, 2, 5)
                and self.der_len == 0
            )
            if self.reject_reason in (1, 2, 3):
                if not _is_ecdsa_rec:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason {self.reject_reason} "
                        f"requires ECDSA record (sig_version 0/1, op_kind 1..4), "
                        f"got sig_version {self.sig_version}, op_kind {self.op_kind}"
                    )
            elif self.reject_reason in (4, 5, 6, 7):
                if not _is_schnorr_rec:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason {self.reject_reason} "
                        f"requires Schnorr record (sig_version 2 op 1/2/5, "
                        f"or sig_version 3 op 0), got sig_version "
                        f"{self.sig_version}, op_kind {self.op_kind}"
                    )
            elif self.reject_reason == 8:
                if not _is_tapscript_skip:
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: reject_reason 8 requires Tapscript "
                        f"skipped call (sig_version 2, op_kind 1/2/5, "
                        f"empty signature), got sig_version "
                        f"{self.sig_version}, op_kind {self.op_kind}, "
                        f"der_len {self.der_len}"
                    )
        if self.der_len > 72:
            # The native instrumented kernel stores the original vchSig length in
            # der_len but only copies up to 72 bytes into the fixed-size der_sig
            # field.  Lengths > 72 therefore mean the signature was truncated; the
            # record still contains at most 72 meaningful bytes, so we clamp the
            # padding check to the field size.
            effective_der_len = 72
        else:
            effective_der_len = self.der_len
        if self.pubkey_len > 65:
            raise AnalyzerError(f"CTX-OPERATIONS: record pubkey_len {self.pubkey_len} exceeds 65")
        # ── Padding must be all-zero ──
        if _pad0 != 0:
            raise AnalyzerError("CTX-OPERATIONS: record _pad0 is not all-zero")
        if _pad1 != b"\x00" * 7:
            raise AnalyzerError("CTX-OPERATIONS: record _pad1 is not all-zero")
        # ── Trailing bytes in der_sig / pubkey beyond their lengths must be zero ──
        if self.der_sig[effective_der_len:] != b"\x00" * (72 - effective_der_len):
            raise AnalyzerError(
                f"CTX-OPERATIONS: record der_sig has non-zero padding beyond der_len={self.der_len}"
            )
        if self.pubkey[self.pubkey_len:] != b"\x00" * (65 - self.pubkey_len):
            raise AnalyzerError(
                f"CTX-OPERATIONS: record pubkey has non-zero padding beyond pubkey_len={self.pubkey_len}"
            )

    @property
    def sort_key(self) -> tuple[bytes, int, int]:
        return (self.spend_txid, self.input_index, self.op_seq)


class JournalEntry:
    """Parsed 56-byte journal entry."""

    __slots__ = (
        "spend_txid",
        "input_index",
        "checksig_ops",
        "checkmultisig_ops",
        "ecdsa_verify_calls",
        "ecdsa_verify_ok",
        "verdict",
    )

    def __init__(self, raw: bytes) -> None:
        unpacked = JOURNAL_STRUCT.unpack(raw)
        (
            self.spend_txid,
            self.input_index,
            self.checksig_ops,
            self.checkmultisig_ops,
            self.ecdsa_verify_calls,
            self.ecdsa_verify_ok,
            self.verdict,
            _pad,
        ) = unpacked
        # ── Canonical field-range validation ──
        if self.verdict not in (0, 1):
            raise AnalyzerError(
                f"CTX-OPERATIONS: journal verdict {self.verdict} must be 0 or 1"
            )
        if _pad != b"\x00" * 3:
            raise AnalyzerError("CTX-OPERATIONS: journal padding is not all-zero")
        if self.ecdsa_verify_ok > self.ecdsa_verify_calls:
            raise AnalyzerError(
                f"CTX-OPERATIONS: ecdsa_verify_ok {self.ecdsa_verify_ok} > "
                f"ecdsa_verify_calls {self.ecdsa_verify_calls}"
            )

    @property
    def key(self) -> tuple[bytes, int]:
        return (self.spend_txid, self.input_index)


# ── Binary parsing ──────────────────────────────────────────────────────────


def read_raw_entries(
    path: Path, magic: bytes, entry_size: int, name: str
) -> list[bytes]:
    """Read a binary file with magic + u64 count header, return raw entry bytes."""
    data = path.read_bytes()
    if len(data) < HEADER_SIZE:
        raise AnalyzerError(
            f"{path}: file too short ({len(data)} bytes < {HEADER_SIZE} header)"
        )
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


def _iter_binary_entries(
    path: Path, magic: bytes, entry_size: int, name: str
) -> Iterator[tuple[int, bytes]]:
    """Stream fixed-size entries from a magic+u64-count binary file.

    Yields ``(index, raw_bytes)`` pairs without loading the whole file.
    Raises ``AnalyzerError`` on short reads, bad magic, or size mismatch.
    """
    file_size = path.stat().st_size
    if file_size < HEADER_SIZE:
        raise AnalyzerError(
            f"{name}: file too short ({file_size} bytes < {HEADER_SIZE} header)"
        )
    with path.open("rb") as stream:
        header = _read_exact_bytes(stream, HEADER_SIZE, f"{name} header")
        file_magic, count = HEADER_STRUCT.unpack(header)
        if file_magic != magic:
            raise AnalyzerError(
                f"{name}: bad magic {file_magic!r}, expected {magic!r}"
            )
        expected_payload = count * entry_size
        available = file_size - HEADER_SIZE
        if available < expected_payload:
            raise AnalyzerError(
                f"{name}: declared {count} entries need {expected_payload} bytes "
                f"but only {available} remain after header"
            )
        for index in range(count):
            raw = _read_exact_bytes(stream, entry_size, f"{name} entry {index}")
            yield index, raw
        trailing = stream.read(1)
        if trailing:
            raise AnalyzerError(
                f"{name}: {len(trailing)} trailing byte(s) after declared entries"
            )


def _read_exact_bytes(stream: BinaryIO, length: int, field: str, scope: str = "") -> bytes:
    """Read exactly *length* bytes from *stream* or raise AnalyzerError."""
    data = stream.read(length)
    if data is None or len(data) < length:
        prefix = f"{scope}: " if scope else ""
        raise AnalyzerError(f"{prefix}{field}: short read (expected {length} bytes)")
    return data


def iter_records(path: Path) -> Iterator[Record]:
    """Stream BRSREC1 records one at a time without materializing the file."""
    for _index, raw in _iter_binary_entries(
        path, RECORD_MAGIC, RECORD_SIZE, "records"
    ):
        yield Record(raw)


def _iter_binary_entries_with_custody(
    path: Path, magic: bytes, entry_size: int, name: str
) -> tuple[Iterator[tuple[int, bytes]], dict[str, int]]:
    """Stream fixed-size entries and compute custody (size + sha256) on the
    exact single open used for parsing.  Returns ``(iterator, custody)``
    where *custody* is populated once the iterator is fully consumed.
    """
    file_size = path.stat().st_size
    if file_size < HEADER_SIZE:
        raise AnalyzerError(
            f"{name}: file too short ({file_size} bytes < {HEADER_SIZE} header)"
        )
    custody: dict[str, int] = {"bytes": 0, "sha256": 0}
    stream = path.open("rb")
    running_hash = hashlib.sha256()
    try:
        header = _read_exact_bytes(stream, HEADER_SIZE, f"{name} header")
        running_hash.update(header)
        file_magic, count = HEADER_STRUCT.unpack(header)
        if file_magic != magic:
            raise AnalyzerError(
                f"{name}: bad magic {file_magic!r}, expected {magic!r}"
            )
        expected_payload = count * entry_size
        available = file_size - HEADER_SIZE
        if available < expected_payload:
            raise AnalyzerError(
                f"{name}: declared {count} entries need {expected_payload} bytes "
                f"but only {available} remain after header"
            )

        def _gen() -> Iterator[tuple[int, bytes]]:
            try:
                for index in range(count):
                    raw = _read_exact_bytes(stream, entry_size, f"{name} entry {index}")
                    running_hash.update(raw)
                    yield index, raw
                trailing = stream.read(1)
                if trailing:
                    raise AnalyzerError(
                        f"{name}: {len(trailing)} trailing byte(s) after declared entries"
                    )
                custody["bytes"] = file_size
                custody["sha256"] = int(running_hash.hexdigest(), 16)
            finally:
                stream.close()

        return _gen(), custody
    except BaseException:
        stream.close()
        raise


def iter_records_with_custody(
    path: Path
) -> tuple[Iterator[Record], dict[str, int]]:
    """Stream BRSREC1 records and compute custody on the single open."""
    gen, custody = _iter_binary_entries_with_custody(
        path, RECORD_MAGIC, RECORD_SIZE, "records"
    )
    return ((Record(raw) for _idx, raw in gen), custody)


def iter_journal_with_custody(
    path: Path
) -> tuple[Iterator[JournalEntry], dict[str, int]]:
    """Stream BRSJRN1 journal entries and compute custody on the single open."""
    gen, custody = _iter_binary_entries_with_custody(
        path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries"
    )
    return ((JournalEntry(raw) for _idx, raw in gen), custody)

def iter_journal(path: Path) -> Iterator[JournalEntry]:
    """Stream BRSJRN1 journal entries one at a time without materializing the file."""
    for _index, raw in _iter_binary_entries(
        path, JOURNAL_MAGIC, JOURNAL_SIZE, "journal entries"
    ):
        yield JournalEntry(raw)
def parse_counters(path: Path) -> tuple[Counters, dict[str, int]]:
    """Parse counters JSON and return (Counters, custody) from the single read."""
    counters_bytes = path.read_bytes()
    raw = json.loads(counters_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError(f"{path}: JSON root is not an object")
    if raw.get("schema") != 1:
        raise AnalyzerError(f"{path}: schema is {raw.get('schema')}, expected 1")
    custody = {
        "bytes": len(counters_bytes),
        "sha256": int(hashlib.sha256(counters_bytes).hexdigest(), 16),
    }
    return Counters(raw), custody


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


def _sha256_file(path: Path) -> tuple[int, str]:
    """Return (size in bytes, lowercase hex sha256) for a file."""
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            h.update(chunk)
            size += len(chunk)
    return size, h.hexdigest()


# ── Invariant checks ────────────────────────────────────────────────────────


def check_counter_arithmetic(c: Counters) -> list[dict[str, object]]:
    """INV-1 through INV-7."""
    results: list[dict[str, object]] = []

    def inv(inv_id: str, passed: bool, statement: str, **extra: object) -> None:
        entry: dict[str, object] = {"id": inv_id, "passed": passed, "statement": statement}
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
        and c.ecdsa_from_checkmultisig
        <= 20 * (c.op_checkmultisig + c.op_checkmultisigverify),
        "C_ECDSA_FROM_CHECKSIG <= C_OP_CHECKSIG + C_OP_CHECKSIGVERIFY; "
        "C_ECDSA_FROM_CHECKMULTISIG <= 20 * (C_OP_CHECKMULTISIG + C_OP_CHECKMULTISIGVERIFY)",
        from_checksig=c.ecdsa_from_checksig,
        checksig_plus_verify=c.op_checksig + c.op_checksigverify,
        from_checkmultisig=c.ecdsa_from_checkmultisig,
        twenty_multisig=20 * (c.op_checkmultisig + c.op_checkmultisigverify),
    )
    inv(
        "INV-7",
        c.op_checksigadd == 0
        and c.checkschnorr_entries == 0
        and c.schnorr_verify_calls == 0,
        "C_OP_CHECKSIGADD == 0 and C_CHECKSCHNORR_ENTRIES == 0 and C_SCHNORR_VERIFY_CALLS == 0",
        op_checksigadd=c.op_checksigadd,
        checkschnorr_entries=c.checkschnorr_entries,
        schnorr_verify_calls=c.schnorr_verify_calls,
    )
    return results


def check_record_counts(records: list[Record], c: Counters) -> dict[str, object]:
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


def check_journal_sums(journal: list[JournalEntry], c: Counters) -> dict[str, object]:
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
        "counter_op_checkmultisig_plus_verify": c.op_checkmultisig
        + c.op_checkmultisigverify,
        "counter_ecdsa_verify_calls": c.ecdsa_verify_calls,
        "counter_ecdsa_verify_ok": c.ecdsa_verify_ok,
    }


def check_duplicate_keys(records: list[Record]) -> dict[str, object]:
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


def check_all_verdicts_true(journal: list[JournalEntry]) -> dict[str, object]:
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
) -> dict[str, object]:
    """INV-13: two Run-B executions produce identical counters and sorted records SHA256."""
    counters_identical = (
        all(getattr(c1, name) == getattr(c2, name) for name in COUNTER_NAMES)
        and c1.record_count == c2.record_count
        and c1.journal_count == c2.journal_count
    )
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
) -> dict[str, object]:
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
    discrepancies: list[dict[str, object]] = []
    max_ratio = 1.0

    for key in sorted(intersection):
        c = census_map[key]
        b = capture_map[key]
        for field_name in (
            "checksig_ops",
            "checkmultisig_ops",
            "ecdsa_verify_calls",
            "ecdsa_verify_ok",
        ):
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


def extract_bare_mode0(bare: dict[str, object]) -> dict[str, object]:
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
            "bare JSON: native_mode0 missing required fields: " + ", ".join(missing)
        )

    inputs_per_round = _require_non_bool_int(
        mode0["inputs_per_round"], "bare JSON: native_mode0.inputs_per_round"
    )
    rounds = _require_non_bool_int(mode0["rounds"], "bare JSON: native_mode0.rounds")
    attempts_total = _require_non_bool_int(
        mode0["attempts_total"], "bare JSON: native_mode0.attempts_total"
    )
    mismatches = _require_non_bool_int(
        mode0["mismatches"], "bare JSON: native_mode0.mismatches"
    )
    ok_count = _require_non_bool_int(
        mode0["ok_count"], "bare JSON: native_mode0.ok_count"
    )
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
            f"bare JSON: native_mode0.ok_count = {ok_count} (must be non-negative)"
        )
    if mismatches < 0:
        raise AnalyzerError(
            f"bare JSON: native_mode0.mismatches = {mismatches} (must be non-negative)"
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
            f"bare JSON: round_ns length ({len(round_ns_raw)}) != rounds ({rounds})"
        )

    round_ns: list[int] = []
    for i, ns in enumerate(round_ns_raw):
        if isinstance(ns, bool) or not isinstance(ns, int):
            raise AnalyzerError(
                f"bare JSON: round_ns[{i}] = {ns!r} (must be a positive non-boolean integer)"
            )
        if ns <= 0:
            raise AnalyzerError(f"bare JSON: round_ns[{i}] = {ns} (must be positive)")
        round_ns.append(ns)

    # Independently recompute per-round ns/attempt as round_ns / inputs_per_round.
    # Never divide by attempts_total for a single round.
    per_attempt: list[float] = [float(ns) / float(inputs_per_round) for ns in round_ns]

    # Median is the authoritative Y (not mean).
    recomputed_median = statistics.median(per_attempt)
    recomputed_min = min(per_attempt)
    recomputed_max = max(per_attempt)

    reported_median = _require_positive_finite_float(
        mode0["median_ns_per_attempt"], "bare JSON: median_ns_per_attempt"
    )
    reported_min = _require_positive_finite_float(
        mode0["min_ns_per_attempt"], "bare JSON: min_ns_per_attempt"
    )
    reported_max = _require_positive_finite_float(
        mode0["max_ns_per_attempt"], "bare JSON: max_ns_per_attempt"
    )

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


def extract_spike_width1(spike: dict[str, object]) -> float:
    """Extract width-1 us_per_input from a spike run JSON."""
    if "runs" in spike and isinstance(spike["runs"], list):
        for run in spike["runs"]:
            if not isinstance(run, dict):
                raise AnalyzerError("spike JSON: runs entry is not an object")
            threads = run.get("threads")
            if isinstance(threads, bool) or not isinstance(threads, int):
                raise AnalyzerError(
                    "spike JSON: run.threads must be a non-boolean integer"
                )
            if threads != 1:
                continue
            us = run.get("us_per_input")
            if us is None:
                raise AnalyzerError(
                    "spike JSON: run with threads == 1 missing us_per_input"
                )
            return _require_positive_finite_float(us, "spike JSON: run.us_per_input")
        raise AnalyzerError("spike JSON: no run with threads == 1")
    if "us_per_input" in spike:
        threads = spike.get("threads")
        if isinstance(threads, bool) or not isinstance(threads, int):
            raise AnalyzerError(
                "spike JSON: top-level us_per_input requires threads to be a non-boolean integer"
            )
        if threads != 1:
            raise AnalyzerError(
                "spike JSON: top-level us_per_input requires threads == 1"
            )
        return _require_positive_finite_float(
            spike["us_per_input"], "spike JSON: top-level us_per_input"
            )
    raise AnalyzerError("spike JSON: no us_per_input found")


# ── Subcommand: validate-capture ────────────────────────────────────────────


def cmd_validate_capture(args: argparse.Namespace) -> int:
    counters, _ = parse_counters(Path(args.counters))
    records = parse_records(Path(args.records))
    journal = parse_journal(Path(args.journal))

    repeat_counters, _ = parse_counters(Path(args.repeat_counters))
    parse_records(Path(args.repeat_records))
    parse_journal(Path(args.repeat_journal))

    # Sort records and compute SHA256 for both runs
    raw1 = read_raw_entries(Path(args.records), RECORD_MAGIC, RECORD_SIZE, "records")
    raw2 = read_raw_entries(
        Path(args.repeat_records), RECORD_MAGIC, RECORD_SIZE, "records"
    )
    sorted1 = sort_records_raw(raw1)
    sorted2 = sort_records_raw(raw2)
    sha1 = sha256_hex(sorted1)
    sha2 = sha256_hex(sorted2)

    if args.sorted_records_output:
        out = Path(args.sorted_records_output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(HEADER_STRUCT.pack(RECORD_MAGIC, len(raw1)) + sorted1)

    inv_results: list[dict[str, object]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(check_record_counts(records, counters))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_duplicate_keys(records))
    inv_results.append(check_count_repeat(counters, repeat_counters, sha1, sha2))

    all_passed = (
        all(r["passed"] for r in inv_results)
        and counters.ffi_verify_entries == EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1
    )

    report: dict[str, object] = {
        "schema": "census-capture-v2",
        "counters_label": counters.label,
        "record_count": len(records),
        "journal_count": len(journal),
        "sorted_records_sha256": sha1,
        "repeat_sorted_records_sha256": sha2,
        "invariants": inv_results,
        "all_passed": all_passed,
    }

    context_inputs = getattr(args, "context_inputs", None)
    if context_inputs:
        corpus_size, corpus_sha256 = _sha256_file(Path(context_inputs))
        report["corpus_size"] = corpus_size
        report["corpus_sha256"] = corpus_sha256

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    failed = [r["id"] for r in inv_results if not r["passed"]]
    if counters.ffi_verify_entries != EXPECTED_FFI_VERIFY_ENTRIES_KSPIKE1:
        failed.append("EXP-KSPIKE1")
    if failed:
        print(f"validate-capture: FAILED — {', '.join(failed)}", file=sys.stderr)
        return 1
    print(f"validate-capture: PASSED — {len(records)} records, sha256={sha1[:16]}…")
    return 0


# ── Subcommand: validate-census ─────────────────────────────────────────────


def cmd_validate_census(args: argparse.Namespace) -> int:
    counters, _ = parse_counters(Path(args.counters))
    journal = parse_journal(Path(args.journal))
    capture_journal = parse_journal(Path(args.capture_journal))

    inv_results: list[dict[str, object]] = []
    inv_results.extend(check_counter_arithmetic(counters))
    inv_results.append(check_all_verdicts_true(journal))
    inv_results.append(check_journal_sums(journal, counters))
    inv_results.append(check_census_capture_agreement(journal, capture_journal))

    # EXP-1: expected input count
    exp1_passed = counters.ffi_verify_entries == EXPECTED_FFI_VERIFY_ENTRIES_FULL
    exp1: dict[str, object] = {
        "id": "EXP-1",
        "passed": exp1_passed,
        "statement": f"C_FFI_VERIFY_ENTRIES == {EXPECTED_FFI_VERIFY_ENTRIES_FULL}",
        "expected": EXPECTED_FFI_VERIFY_ENTRIES_FULL,
        "actual": counters.ffi_verify_entries,
    }
    if not exp1_passed:
        exp1["warning"] = (
            "Value differs from published anchor — window, corpus, or published figure may have moved."
        )

    # EXP-4: attempts-per-check comparison (census vs capture)
    census_a = (
        counters.ecdsa_verify_calls / counters.ffi_verify_entries
        if counters.ffi_verify_entries
        else 0.0
    )
    capture_ecdsa_sum = sum(e.ecdsa_verify_calls for e in capture_journal)
    capture_count = len(capture_journal)
    capture_a = capture_ecdsa_sum / capture_count if capture_count else 0.0
    if census_a > 0 and capture_a > 0:
        ratio = census_a / capture_a
        exp4_passed = abs(ratio - 1.0) <= 0.10
    else:
        ratio = 0.0
        exp4_passed = False
    exp4: dict[str, object] = {
        "id": "EXP-4",
        "passed": exp4_passed,
        "statement": "attempts-per-check on KSPIKE1 vs 0..150k differ by <= 10%",
        "census_attempts_per_check": census_a,
        "capture_attempts_per_check": capture_a,
        "ratio": ratio,
    }
    if not exp4_passed and ratio > 0:
        exp4["warning"] = (
            "Corpus over-represents multisig; report both ratios and extrapolate with the whole-window ratio."
        )

    all_passed = (
        all(r["passed"] for r in inv_results) and exp1["passed"] and exp4["passed"]
    )

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
        raise AnalyzerError(
            f"verdict requires exactly three bare-runs, got {len(args.bare_runs)}"
        )
    if len(args.spike_runs) != 3:
        raise AnalyzerError(
            f"verdict requires exactly three spike-runs, got {len(args.spike_runs)}"
        )
    capture_counters, _ = parse_counters(Path(args.capture_counters))
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
    spike_spread_us = (
        (max(spike_values) - min(spike_values)) if len(spike_values) > 1 else 0.0
    )

    # Extract and validate every bare timing run.
    run_records: list[dict[str, object]] = []
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
        inv8_mismatches = _require_non_bool_int(
            inv8_raw["mismatches"], f"{bare_path}: inv_8 mismatches"
        )
        inv8_ok_count = _require_non_bool_int(
            inv8_raw["ok_count"], f"{bare_path}: inv_8 ok_count"
        )
        inv8_expected = _require_non_bool_int(
            inv8_raw["expected_true_count"],
            f"{bare_path}: inv_8 expected_true_count",
        )
        inv8_ok_eq = inv8_raw["ok_equals_count_outcome_1"]
        if not isinstance(inv8_ok_eq, bool):
            raise AnalyzerError(
                f"{bare_path}: inv_8 ok_equals_count_outcome_1 is not a boolean"
            )
        inv8_emitted_passed = inv8_raw["passed"]
        if not isinstance(inv8_emitted_passed, bool):
            raise AnalyzerError(f"{bare_path}: inv_8 passed is not a boolean")
        inv8_run_passed = (
            inv8_mismatches == 0
            and inv8_ok_count == inv8_expected
            and inv8_expected == k_entries
            and inv8_ok_eq
            and inv8_emitted_passed
            and mode0["mismatches"] == inv8_mismatches
            and mode0["ok_count"] == inv8_ok_count
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
            raise AnalyzerError(f"{bare_path}: inv_15 passed is not a boolean")
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
                    "counters": {
                        name: int(inv15_counters[name]) for name in COUNTER_NAMES
                    },
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
        (
            r["rust_secp_diagnostic"]
            for r in run_records
            if r["rust_secp_diagnostic"] is not None
        ),
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
        if (
            not isinstance(value, str)
            or len(value) != 64
            or not re.fullmatch(r"[0-9a-f]{64}", value)
        ):
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
    current_wall = _require_positive_finite_float(
        args.current_wall_seconds, "current_wall_seconds"
    )
    current_script_wall = _require_positive_finite_float(
        args.current_script_wall_seconds, "current_script_wall_seconds"
    )
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



# ── Subcommand: classify-corpus ──────────────────────────────────────────────


def _op_kind_name(op_kind: int) -> str:
    return {
        1: "CHECKSIG",
        2: "CHECKSIGVERIFY",
        3: "CHECKMULTISIG",
        4: "CHECKMULTISIGVERIFY",
        5: "CHECKSIGADD",
    }.get(op_kind, f"UNKNOWN({op_kind})")


def _sig_version_name(sig_version: int) -> str:
    return {
        0: "BASE",
        1: "WITNESS_V0",
        2: "TAPSCRIPT",
        3: "TAPROOT",
    }.get(sig_version, f"UNKNOWN({sig_version})")


def _require_hex_str(value: object, field: str, length: int) -> str:
    """Validate that *value* is a lowercase hex string of exactly *length* chars."""
    if not isinstance(value, str) or len(value) != length:
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be a {length}-character hex string"
        )
    if not re.fullmatch(r"[0-9a-f]{" + str(length) + r"}", value):
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be lowercase hex, got {value!r}"
        )
    return value


def _require_int_field(value: object, field: str) -> int:
    """Validate that *value* is a non-bool int."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise AnalyzerError(
            f"CTX-CUSTODY: {field} must be an integer, got {type(value).__name__}"
        )
    return value


def _validate_replay_artifact(path: Path) -> dict[str, object]:
    """Validate a mainnet-prefix-replay-v2 JSON artifact and return flat fields.

    Required root keys (exactly): schema, network, network_magic, genesis_hash,
    start_height, start_hash, stop_height, stop_hash, block_count, window,
    assume_valid_height, window_verify_success_total, corpus_manifest, archive.
    Raises ``AnalyzerError`` with CTX-CUSTODY or CTX-WINDOW prefix on any
    schema, field, or invariant violation.
    """
    replay_bytes = path.read_bytes()
    raw = json.loads(replay_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError("CTX-CUSTODY: replay artifact root is not an object")

    _REPLAY_KEYS = {
        "schema", "network", "network_magic", "genesis_hash",
        "start_height", "start_hash", "stop_height", "stop_hash",
        "block_count", "window", "assume_valid_height",
        "window_verify_success_total", "corpus_manifest", "archive",
        "block_bytes", "block_source", "blockfilterindex",
        "blocks_per_second", "checkpoint_generation", "data_dir",
        "decode_seconds", "elapsed_seconds", "fetch_seconds",
        "git_head", "measurement_target", "rss_high_water_bytes",
        "stage_seconds", "storage_backend", "tx_count", "txindex",
    }
    _require_exact_keys(raw, _REPLAY_KEYS, "replay artifact root")

    if raw["schema"] != "mainnet-prefix-replay-v2":
        raise AnalyzerError(
            f"CTX-CUSTODY: replay schema is {raw['schema']!r}, "
            f"expected 'mainnet-prefix-replay-v2'"
        )

    network = raw["network"]
    if network != "mainnet":
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.network must be 'mainnet', got {network!r}"
        )

    network_magic = _require_hex_str(raw["network_magic"], "replay.network_magic", 8)
    if network_magic != MAINNET_MAGIC:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.network_magic must be {MAINNET_MAGIC!r}, "
            f"got {network_magic!r}"
        )

    genesis_hash = _require_hex_str(raw["genesis_hash"], "replay.genesis_hash", 64)
    if genesis_hash != MAINNET_GENESIS_HASH:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.genesis_hash must be the canonical mainnet "
            f"genesis {MAINNET_GENESIS_HASH!r}, got {genesis_hash!r}"
        )

    start_height = _require_int_field(raw["start_height"], "replay.start_height")
    if start_height != 0:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.start_height must be 0, got {start_height}"
        )
    start_hash = _require_hex_str(raw["start_hash"], "replay.start_hash", 64)
    if start_hash != genesis_hash:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.start_hash must equal genesis_hash, "
            f"got {start_hash!r}"
        )

    stop_height = _require_int_field(raw["stop_height"], "replay.stop_height")
    stop_hash = _require_hex_str(raw["stop_hash"], "replay.stop_hash", 64)
    block_count = _require_int_field(raw["block_count"], "replay.block_count")
    if block_count != stop_height + 1:
        raise AnalyzerError(
            f"CTX-CUSTODY: replay.block_count must equal stop_height+1 "
            f"({stop_height + 1}), got {block_count}"
        )

    window = _require_int_field(raw["window"], "replay.window")
    if window <= 1:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.window must be > 1, got {window}"
        )

    assume_valid_height = _require_int_field(
        raw["assume_valid_height"], "replay.assume_valid_height"
    )
    if assume_valid_height != 0:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.assume_valid_height must be 0, "
            f"got {assume_valid_height}"
        )

    window_verify_success_total = _require_int_field(
        raw["window_verify_success_total"], "replay.window_verify_success_total"
    )
    if window_verify_success_total < 1:
        raise AnalyzerError(
            f"CTX-WINDOW: replay.window_verify_success_total must be >= 1, "
            f"got {window_verify_success_total}"
        )

    corpus_manifest = _require_custody_ref(
        raw["corpus_manifest"], "replay.corpus_manifest", with_schema=True
    )
    archive = _require_custody_ref(
        raw["archive"], "replay.archive", with_schema=False
    )

    # ── Optional timing/metadata fields emitted by the Rust replay binary.
    # These are not load-bearing for the contract, but the schema is frozen,
    # so we validate type and canonical range for each.
    def _require_float(value: object, field: str, *, ge: float | None = None) -> float:
        if isinstance(value, bool) or not isinstance(value, float):
            raise AnalyzerError(f"CTX-CUSTODY: {field} must be a float")
        if ge is not None and value < ge:
            raise AnalyzerError(f"CTX-CUSTODY: {field} must be >= {ge}, got {value}")
        return value

    block_bytes = _require_non_bool_int(raw["block_bytes"], "replay.block_bytes")
    if block_bytes < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.block_bytes must be >= 0, got {block_bytes}")

    block_source = raw["block_source"]
    if not isinstance(block_source, str) or block_source not in ("file", "rest"):
        raise AnalyzerError(f"CTX-CUSTODY: replay.block_source must be 'file' or 'rest', got {block_source!r}")

    if not isinstance(raw["blockfilterindex"], bool):
        raise AnalyzerError("CTX-CUSTODY: replay.blockfilterindex must be a boolean")
    if not isinstance(raw["txindex"], bool):
        raise AnalyzerError("CTX-CUSTODY: replay.txindex must be a boolean")

    blocks_per_second = _require_float(raw["blocks_per_second"], "replay.blocks_per_second", ge=0.0)
    checkpoint_generation = _require_non_bool_int(
        raw["checkpoint_generation"], "replay.checkpoint_generation"
    )
    if checkpoint_generation < 1:
        raise AnalyzerError(f"CTX-CUSTODY: replay.checkpoint_generation must be >= 1, got {checkpoint_generation}")

    data_dir = raw["data_dir"]
    if not isinstance(data_dir, str) or len(data_dir) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.data_dir must be a nonempty string")

    decode_seconds = _require_float(raw["decode_seconds"], "replay.decode_seconds", ge=0.0)
    elapsed_seconds = _require_float(raw["elapsed_seconds"], "replay.elapsed_seconds", ge=0.0)
    fetch_seconds = _require_float(raw["fetch_seconds"], "replay.fetch_seconds", ge=0.0)

    git_head = raw["git_head"]
    if not isinstance(git_head, str) or len(git_head) != 40:
        raise AnalyzerError("CTX-CUSTODY: replay.git_head must be a 40-character hex string")

    measurement_target = raw["measurement_target"]
    if not isinstance(measurement_target, str) or len(measurement_target) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.measurement_target must be a nonempty string")

    rss_high_water_bytes = _require_non_bool_int(
        raw["rss_high_water_bytes"], "replay.rss_high_water_bytes"
    )
    if rss_high_water_bytes < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.rss_high_water_bytes must be >= 0, got {rss_high_water_bytes}")

    stage_seconds = raw["stage_seconds"]
    if not isinstance(stage_seconds, list) or not all(
        isinstance(v, dict) and "count" in v and "stage" in v and "sum_seconds" in v
        and isinstance(v["count"], int) and isinstance(v["stage"], str) and isinstance(v["sum_seconds"], float)
        and v["count"] >= 0 and v["sum_seconds"] >= 0 for v in stage_seconds
    ):
        raise AnalyzerError("CTX-CUSTODY: replay.stage_seconds must be a list of objects with count, stage, and sum_seconds")

    storage_backend = raw["storage_backend"]
    if not isinstance(storage_backend, str) or len(storage_backend) == 0:
        raise AnalyzerError("CTX-CUSTODY: replay.storage_backend must be a nonempty string")

    tx_count = _require_non_bool_int(raw["tx_count"], "replay.tx_count")
    if tx_count < 0:
        raise AnalyzerError(f"CTX-CUSTODY: replay.tx_count must be >= 0, got {tx_count}")

    return {
        "schema": "mainnet-prefix-replay-v2",
        "network": network,
        "network_magic": network_magic,
        "genesis_hash": genesis_hash,
        "start_height": start_height,
        "start_hash": start_hash,
        "stop_height": stop_height,
        "stop_hash": stop_hash,
        "block_count": block_count,
        "window": window,
        "assume_valid_height": assume_valid_height,
        "window_verify_success_total": window_verify_success_total,
        "corpus_manifest": corpus_manifest,
        "archive": archive,
        "block_bytes": block_bytes,
        "block_source": block_source,
        "blockfilterindex": raw["blockfilterindex"],
        "blocks_per_second": blocks_per_second,
        "checkpoint_generation": checkpoint_generation,
        "data_dir": data_dir,
        "decode_seconds": decode_seconds,
        "elapsed_seconds": elapsed_seconds,
        "fetch_seconds": fetch_seconds,
        "git_head": git_head,
        "measurement_target": measurement_target,
        "rss_high_water_bytes": rss_high_water_bytes,
        "stage_seconds": stage_seconds,
        "storage_backend": storage_backend,
        "tx_count": tx_count,
        "txindex": raw["txindex"],
        "custody": {
            "bytes": len(replay_bytes),
            "sha256": hashlib.sha256(replay_bytes).hexdigest(),
        },
    }


def _validate_corpus_manifest(
    manifest_path: Path, archive_path: Path, replay: dict[str, object]
) -> dict[str, object]:
    """Validate corpus manifest JSON, cross-check against replay, and
    stream-validate every Core-frame in the archive in a single open pass.

    The archive is opened exactly once.  A running SHA-256 is updated
    incrementally with every byte read (magic + length + payload), replacing
    the separate ``_sha256_file`` call.  The computed hash and byte count
    must match the manifest's declared archive size and sha256.

    Returns the manifest summary **without** ``entries``.  Raises
    ``AnalyzerError`` with CTX-CUSTODY prefix on any mismatch.
    """
    # ── Load and validate manifest JSON ──
    manifest_bytes = manifest_path.read_bytes()
    raw = json.loads(manifest_bytes)
    if not isinstance(raw, dict):
        raise AnalyzerError("CTX-CUSTODY: corpus manifest root is not an object")

    _MANIFEST_KEYS = {
        "schema", "version", "network", "network_magic", "genesis_hash",
        "range", "archive", "entries",
    }
    _require_exact_keys(raw, _MANIFEST_KEYS, "corpus manifest root")

    if raw["schema"] != "bitcoin-rs-corpus-manifest":
        raise AnalyzerError(
            f"CTX-CUSTODY: corpus manifest schema is {raw['schema']!r}, "
            f"expected 'bitcoin-rs-corpus-manifest'"
        )
    version = _require_int_field(raw["version"], "manifest.version")
    if version != 1:
        raise AnalyzerError(
            f"CTX-CUSTODY: corpus manifest version must be 1, got {version}"
        )

    network = raw["network"]
    if network != "mainnet":
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.network must be 'mainnet', got {network!r}"
        )
    network_magic = _require_hex_str(raw["network_magic"], "manifest.network_magic", 8)
    if network_magic != MAINNET_MAGIC:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.network_magic must be {MAINNET_MAGIC!r}, "
            f"got {network_magic!r}"
        )
    genesis_hash = _require_hex_str(raw["genesis_hash"], "manifest.genesis_hash", 64)
    if genesis_hash != MAINNET_GENESIS_HASH:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.genesis_hash must be the canonical mainnet "
            f"genesis {MAINNET_GENESIS_HASH!r}, got {genesis_hash!r}"
        )

    # ── range ──
    range_obj = raw["range"]
    if not isinstance(range_obj, dict):
        raise AnalyzerError("CTX-CUSTODY: manifest.range must be an object")
    _require_exact_keys(range_obj, {"start_height", "stop_height"}, "manifest.range")
    range_start = _require_u32(range_obj["start_height"], "manifest.range.start_height")
    range_stop = _require_u32(range_obj["stop_height"], "manifest.range.stop_height")
    if range_start != 0:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest.range.start_height must be 0, got {range_start}"
        )

    # ── archive ──
    archive_obj = raw["archive"]
    if not isinstance(archive_obj, dict):
        raise AnalyzerError("CTX-CUSTODY: manifest.archive must be an object")
    _require_exact_keys(archive_obj, {"size", "sha256"}, "manifest.archive")
    archive_size = _require_u64(archive_obj["size"], "manifest.archive.size")
    archive_sha256 = _require_hex_str(
        archive_obj["sha256"], "manifest.archive.sha256", 64
    )

    # ── entries ──
    entries = raw["entries"]
    if not isinstance(entries, list) or len(entries) == 0:
        raise AnalyzerError(
            "CTX-CUSTODY: manifest.entries must be a non-empty array"
        )

    # ── Cross-check manifest file bytes/SHA-256 against replay ──
    replay_cm = replay["corpus_manifest"]
    replay_cm_bytes = replay_cm["bytes"]
    replay_cm_sha256 = replay_cm["sha256"]
    actual_cm_size = len(manifest_bytes)
    actual_cm_sha = hashlib.sha256(manifest_bytes).hexdigest()
    if actual_cm_size != replay_cm_bytes:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest file size mismatch: replay={replay_cm_bytes}, "
            f"actual={actual_cm_size}"
        )
    if actual_cm_sha != replay_cm_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest file sha256 mismatch: replay={replay_cm_sha256}, "
            f"actual={actual_cm_sha}"
        )

    # ── Cross-check manifest fields against replay ──
    replay_network = replay["network"]
    replay_magic = replay["network_magic"]
    replay_genesis = replay["genesis_hash"]
    replay_start = replay["start_height"]
    replay_stop = replay["stop_height"]
    replay_stop_hash = replay["stop_hash"]
    replay_arch_bytes = replay["archive"]["bytes"]
    replay_arch_sha256 = replay["archive"]["sha256"]

    if network != replay_network:
        raise AnalyzerError(
            f"CTX-CUSTODY: network mismatch: manifest={network!r}, "
            f"replay={replay_network!r}"
        )
    if network_magic != replay_magic:
        raise AnalyzerError(
            f"CTX-CUSTODY: network_magic mismatch: manifest={network_magic!r}, "
            f"replay={replay_magic!r}"
        )
    if genesis_hash != replay_genesis:
        raise AnalyzerError(
            f"CTX-CUSTODY: genesis_hash mismatch: manifest={genesis_hash!r}, "
            f"replay={replay_genesis!r}"
        )
    if range_start != replay_start:
        raise AnalyzerError(
            f"CTX-CUSTODY: start_height mismatch: manifest={range_start}, "
            f"replay={replay_start}"
        )
    if range_stop != replay_stop:
        raise AnalyzerError(
            f"CTX-CUSTODY: stop_height mismatch: manifest={range_stop}, "
            f"replay={replay_stop}"
        )
    if archive_size != replay_arch_bytes:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive size mismatch: manifest={archive_size}, "
            f"replay={replay_arch_bytes}"
        )
    if archive_sha256 != replay_arch_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive sha256 mismatch: manifest={archive_sha256}, "
            f"replay={replay_arch_sha256!r}"
        )

    # ── Validate manifest entries: exact keys, types, duplicates, contiguity ──
    expected_entry_count = range_stop + 1
    if len(entries) != expected_entry_count:
        raise AnalyzerError(
            f"CTX-CUSTODY: manifest entries count {len(entries)} != "
            f"stop_height+1 ({expected_entry_count})"
        )

    _ENTRY_KEYS = {"height", "hash", "offset", "payload_length"}
    seen_heights: set[int] = set()
    seen_hashes: set[str] = set()
    expected_offset = 0
    last_index = len(entries) - 1
    magic_bytes = bytes.fromhex(network_magic)

    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}] is not an object"
            )
        _require_exact_keys(entry, _ENTRY_KEYS, f"manifest.entries[{index}]")
        entry_height = _require_u32(
            entry["height"], f"manifest.entries[{index}].height"
        )
        entry_hash = _require_hex_str(
            entry["hash"], f"manifest.entries[{index}].hash", 64
        )
        entry_offset = _require_u64(
            entry["offset"], f"manifest.entries[{index}].offset"
        )
        entry_payload_length = _require_u32(
            entry["payload_length"], f"manifest.entries[{index}].payload_length"
        )
        if entry_payload_length < 80 or entry_payload_length > 4_000_000:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].payload_length "
                f"{entry_payload_length} out of range [80, 4000000]"
            )

        if entry_height in seen_heights:
            raise AnalyzerError(
                f"CTX-CUSTODY: duplicate height {entry_height} in manifest entries"
            )
        if entry_hash in seen_hashes:
            raise AnalyzerError(
                f"CTX-CUSTODY: duplicate hash {entry_hash} in manifest entries"
            )
        seen_heights.add(entry_height)
        seen_hashes.add(entry_hash)

        if entry_height != range_start + index:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].height {entry_height} "
                f"!= expected {range_start + index} (gapped heights)"
            )
        if entry_offset != expected_offset:
            raise AnalyzerError(
                f"CTX-CUSTODY: manifest.entries[{index}].offset {entry_offset} "
                f"!= expected {expected_offset} (inconsistent offset)"
            )
        expected_offset = entry_offset + 8 + entry_payload_length
        if index == last_index and expected_offset != archive_size:
            raise AnalyzerError(
                f"CTX-CUSTODY: final frame end {expected_offset} != "
                f"archive.size {archive_size}"
            )

    # ── Single-open archive pass: stream frames, hash incrementally ──
    prev_block_hash_raw: bytes | None = None
    running_hash = hashlib.sha256()
    bytes_consumed = 0

    with archive_path.open("rb") as stream:
        for index, entry in enumerate(entries):
            assert isinstance(entry, dict)
            entry_payload_length = int(entry["payload_length"])
            entry_hash = str(entry["hash"])

            # Read frame header: 4-byte magic + 4-byte LE u32 length.
            frame_header = _read_exact_bytes(
                stream, 8, f"archive frame {index} header", scope="CTX-CUSTODY"
            )
            running_hash.update(frame_header)
            bytes_consumed += 8
            frame_magic = frame_header[0:4]
            frame_length = struct.unpack_from("<I", frame_header, 4)[0]

            if frame_magic != magic_bytes:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} magic "
                    f"{frame_magic.hex()} != manifest network_magic "
                    f"{magic_bytes.hex()} (frame magic mismatch)"
                )
            if frame_length != entry_payload_length:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} length {frame_length} "
                    f"!= manifest payload_length {entry_payload_length} "
                    f"(payload_length mismatch)"
                )

            # Read the 80-byte block header first.
            header_bytes = _read_exact_bytes(
                stream, 80, f"archive frame {index} block header", scope="CTX-CUSTODY"
            )
            running_hash.update(header_bytes)
            bytes_consumed += 80

            # Double-SHA256 of the 80-byte header → internal LE hash.
            hash_raw = hashlib.sha256(
                hashlib.sha256(header_bytes).digest()
            ).digest()
            hash_display = hash_raw[::-1].hex()

            if hash_display != entry_hash:
                raise AnalyzerError(
                    f"CTX-CUSTODY: archive frame {index} header double-SHA256 "
                    f"{hash_display} != manifest hash {entry_hash} "
                    f"(header hash mismatch)"
                )

            # prev_blockhash is bytes 4..36 of the header (internal LE order).
            prev_blockhash = header_bytes[4:36]

            if index == 0:
                if entry_hash != genesis_hash:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: first block hash {entry_hash} != "
                        f"manifest genesis_hash {genesis_hash}"
                    )
                if prev_blockhash != b"\x00" * 32:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: genesis block prev_blockhash is not "
                        f"all-zero (genesis prev_blockhash nonzero: "
                        f"got {prev_blockhash[::-1].hex()})"
                    )
            else:
                if prev_block_hash_raw is None:
                    raise AnalyzerError(
                        "CTX-CUSTODY: internal error: prev_block_hash_raw is None"
                    )
                if prev_blockhash != prev_block_hash_raw:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: block {index} prev_blockhash "
                        f"{prev_blockhash[::-1].hex()} != previous block hash "
                        f"{prev_block_hash_raw[::-1].hex()} (chain break)"
                    )

            # Last block hash must equal replay stop_hash.
            if index == last_index:
                if entry_hash != replay_stop_hash:
                    raise AnalyzerError(
                        f"CTX-CUSTODY: last block hash {entry_hash} != "
                        f"replay stop_hash {replay_stop_hash}"
                    )

            prev_block_hash_raw = hash_raw

            # Consume the remainder of the payload in 64 KiB chunks.
            remaining = entry_payload_length - 80
            chunk_size = 65536
            while remaining > 0:
                to_read = min(remaining, chunk_size)
                chunk = _read_exact_bytes(
                    stream, to_read, f"archive frame {index} payload chunk", scope="CTX-CUSTODY"
                )
                running_hash.update(chunk)
                bytes_consumed += to_read
                remaining -= to_read

        # Archive must be exhausted exactly at archive.size.
        trailing = stream.read(1)
        if trailing:
            raise AnalyzerError(
                f"CTX-CUSTODY: archive has {len(trailing)} trailing byte(s) "
                f"after final frame (trailing bytes)"
            )

    if bytes_consumed != archive_size:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive bytes consumed {bytes_consumed} != "
            f"archive.size {archive_size}"
        )
    computed_sha256 = running_hash.hexdigest()
    if computed_sha256 != archive_sha256:
        raise AnalyzerError(
            f"CTX-CUSTODY: archive streaming sha256 {computed_sha256} != "
            f"manifest archive sha256 {archive_sha256}"
        )

    return {
        "schema": "bitcoin-rs-corpus-manifest",
        "version": version,
        "network": network,
        "network_magic": network_magic,
        "genesis_hash": genesis_hash,
        "range": {"start_height": range_start, "stop_height": range_stop},
        "archive": {"size": archive_size, "sha256": archive_sha256},
        "custody": {
            "bytes": len(manifest_bytes),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        },
    }


def _count_context_records_disk(
    contexts_path: Path,
    records_path: Path,
    journal_path: Path,
    counters: Counters,
) -> tuple[dict[str, int], int, dict[str, dict[str, int]]]:
    """Disk-backed streaming computation of context counters.

    Uses a temporary on-disk sqlite3 database to join BRSCTX1 contexts,
    BRSJRN1 journal entries, and BRSREC1 records without materializing
    any of the binary files in memory.

    Returns ``(counts, context_count, custody)`` where *custody* maps
    ``"contexts"``, ``"records"``, ``"journal"`` to ``{bytes, sha256}``
    computed on the single open used for parsing.
    """
    counts: dict[str, int] = {name: 0 for name in CONTEXT_COUNTER_NAMES}

    with tempfile.TemporaryDirectory(prefix="classify-corpus-") as tmpdir:
        db_path = Path(tmpdir) / "contexts.db"
        conn = sqlite3.connect(str(db_path))
        try:
            conn.execute(
                "CREATE TABLE contexts ("
                "txid_le BLOB, input_index INTEGER, spend_context TEXT, "
                "prevout BLOB, script_sig BLOB, witness_count INTEGER, "
                "PRIMARY KEY(txid_le, input_index))"
            )
            conn.execute(
                "CREATE TABLE journal ("
                "txid_le BLOB, input_index INTEGER, verdict INTEGER, "
                "checksig_ops INTEGER, checkmultisig_ops INTEGER, "
                "ecdsa_verify_calls INTEGER, ecdsa_verify_ok INTEGER, "
                "PRIMARY KEY(txid_le, input_index))"
            )
            conn.execute(
                "CREATE TABLE record_keys ("
                "txid_le BLOB, input_index INTEGER, op_seq INTEGER, "
                "PRIMARY KEY(txid_le, input_index, op_seq))"
            )
            conn.execute(
                "CREATE TABLE record_seq ("
                "txid_le BLOB, input_index INTEGER, last_op_seq INTEGER, "
                "PRIMARY KEY(txid_le, input_index))"
            )
            conn.execute(
                "CREATE TABLE record_ecdsa ("
                "txid_le BLOB, input_index INTEGER, calls INTEGER, ok INTEGER, "
                "PRIMARY KEY(txid_le, input_index))"
            )

            # ── Stream BRSCTX1 → classify → INSERT ──
            context_count = 0
            context_iter = iter_context_inputs(contexts_path, dedup=False)
            try:
                for evidence in context_iter:
                    classified = classify_input(evidence)
                    ctx = classified.spend_context
                    conn.execute(
                        "INSERT INTO contexts VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            evidence.identity.txid_le,
                            evidence.identity.input_index,
                            ctx.value,
                            evidence.prevout_script_pubkey,
                            evidence.script_sig,
                            len(evidence.witness),
                        ),
                    )
                    context_count += 1
                contexts_custody = context_iter.custody()
            except ContextError as exc:
                raise AnalyzerError(
                    f"CTX-RAW: BRSCTX1 stream failed: {exc}"
                ) from exc
            except sqlite3.IntegrityError as exc:
                raise AnalyzerError(
                    f"CTX-EXECUTION: duplicate context execution identity in BRSCTX1: {exc}"
                ) from exc
            # ── Stream BRSJRN1 → INSERT, verify all verdicts == 1 ──
            journal_count = 0
            journal_iter, journal_custody = iter_journal_with_custody(journal_path)
            try:
                for entry in journal_iter:
                    if entry.verdict != 1:
                        display_txid = entry.spend_txid[::-1].hex()
                        raise AnalyzerError(
                            f"CTX-EXECUTION: journal verdict {entry.verdict} != 1 "
                            f"for txid={display_txid}, input_index={entry.input_index}"
                        )
                    conn.execute(
                        "INSERT INTO journal VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            entry.spend_txid,
                            entry.input_index,
                            entry.verdict,
                            entry.checksig_ops,
                            entry.checkmultisig_ops,
                            entry.ecdsa_verify_calls,
                            entry.ecdsa_verify_ok,
                        ),
                    )
                    journal_count += 1
            except sqlite3.IntegrityError as exc:
                raise AnalyzerError(
                    f"CTX-EXECUTION: duplicate journal key in BRSJRN1: {exc}"
                ) from exc

            # ── Count reconciliation: contexts == journal == ffi_verify_entries ──
            if context_count != journal_count:
                raise AnalyzerError(
                    f"CTX-EXECUTION: context count {context_count} != "
                    f"journal count {journal_count}"
                )
            if context_count != counters.ffi_verify_entries:
                raise AnalyzerError(
                    f"CTX-EXECUTION: context count {context_count} != "
                    f"counters.ffi_verify_entries {counters.ffi_verify_entries}"
                )
            if journal_count != counters.ffi_verify_entries:
                raise AnalyzerError(
                    f"CTX-EXECUTION: journal count {journal_count} != "
                    f"counters.ffi_verify_entries {counters.ffi_verify_entries}"
                )
            if context_count != counters.context_count:
                raise AnalyzerError(
                    f"CTX-EXECUTION: context count {context_count} != "
                    f"counters.context_count {counters.context_count}"
                )
            if journal_count != counters.journal_count:
                raise AnalyzerError(
                    f"CTX-EXECUTION: journal count {journal_count} != "
                    f"counters.journal_count {counters.journal_count}"
                )

            # ── Key equality: contexts ↔ journal via EXCEPT both directions ──
            except_ctx_not_in_journal = conn.execute(
                "SELECT COUNT(*) FROM ("
                "  SELECT txid_le, input_index FROM contexts "
                "  EXCEPT "
                "  SELECT txid_le, input_index FROM journal"
                ")"
            ).fetchone()[0]
            if except_ctx_not_in_journal:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: {except_ctx_not_in_journal} context key(s) "
                    f"not present in journal"
                )
            except_jrn_not_in_ctx = conn.execute(
                "SELECT COUNT(*) FROM ("
                "  SELECT txid_le, input_index FROM journal "
                "  EXCEPT "
                "  SELECT txid_le, input_index FROM contexts"
                ")"
            ).fetchone()[0]
            if except_jrn_not_in_ctx:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: {except_jrn_not_in_ctx} journal key(s) "
                    f"not present in contexts"
                )

            # ── Tally spend-context counts from the contexts table ──
            ctx_rows = conn.execute(
                "SELECT spend_context, COUNT(*) FROM contexts GROUP BY spend_context"
            ).fetchall()
            for ctx_name, cnt in ctx_rows:
                ctx_enum = SpendContext(ctx_name)
                if ctx_enum == SpendContext.P2SH:
                    counts["p2sh_redeem_spends"] += cnt
                elif ctx_enum == SpendContext.NATIVE_WITNESS_V0:
                    counts["native_witness_v0_spends"] += cnt
                elif ctx_enum == SpendContext.P2SH_WRAPPED_WITNESS_V0:
                    counts["p2sh_wrapped_witness_v0_spends"] += cnt
                elif ctx_enum == SpendContext.TAPROOT_KEY_PATH:
                    counts["taproot_key_path_spends"] += cnt
                elif ctx_enum == SpendContext.TAPSCRIPT:
                    counts["tapscript_spends"] += cnt

            # ── Global aggregate counters for reconciliation (running ints) ──
            agg_ecdsa_calls = 0
            agg_ecdsa_ok = 0
            agg_ecdsa_fail = 0
            agg_schnorr_calls = 0
            agg_schnorr_ok = 0
            agg_schnorr_fail = 0
            agg_checkecdsa_entries = 0
            agg_checkschnorr_entries = 0
            # Eight reject counters (reject_reason 0..7; 8 = unknown/distinct)
            agg_rejects = [0] * 9


            # ── Stream BRSREC1 → insert key, look up context, tally op counts ──
            record_streamed_count = 0
            record_iter, record_custody = iter_records_with_custody(records_path)
            try:
                for record in record_iter:
                    conn.execute(
                        "INSERT INTO record_keys VALUES (?, ?, ?)",
                        (record.spend_txid, record.input_index, record.op_seq),
                    )
                    row = conn.execute(
                        "SELECT spend_context FROM contexts "
                        "WHERE txid_le = ? AND input_index = ?",
                        (record.spend_txid, record.input_index),
                    ).fetchone()
                    if row is None:
                        display_txid = record.spend_txid[::-1].hex()
                        raise AnalyzerError(
                            f"CTX-OPERATIONS: BRSREC1 record has no matching "
                            f"context identity: txid={display_txid}, "
                            f"input_index={record.input_index}"
                        )
                    ctx = SpendContext(row[0])
                    op = record.op_kind
                    sig = record.sig_version
                    display_txid = record.spend_txid[::-1].hex()
                    identity_str = f"txid={display_txid}, input_index={record.input_index}"
                    # ── Per-key contiguous op_seq via SQLite record_seq ──
                    conn.execute(
                        "INSERT INTO record_seq (txid_le, input_index, last_op_seq) "
                        "VALUES (?, ?, ?) "
                        "ON CONFLICT(txid_le, input_index) DO UPDATE SET "
                        "last_op_seq = excluded.last_op_seq "
                        "WHERE record_seq.last_op_seq + 1 = excluded.last_op_seq",
                        (record.spend_txid, record.input_index, record.op_seq),
                    )
                    seq_row = conn.execute(
                        "SELECT last_op_seq FROM record_seq "
                        "WHERE txid_le = ? AND input_index = ?",
                        (record.spend_txid, record.input_index),
                    ).fetchone()
                    if seq_row is None or seq_row[0] != record.op_seq:
                        expected = (seq_row[0] + 1) if seq_row else 0
                        raise AnalyzerError(
                            f"CTX-OPERATIONS: op_seq contiguity violation for "
                            f"txid={display_txid}, input_index={record.input_index}: "
                            f"expected {expected}, got {record.op_seq}"
                        )
                    if op in (3, 4):
                        if sig not in (0, 1):
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: multisig record must have "
                                f"sig_version BASE or WITNESS_V0, "
                                f"got {_sig_version_name(sig)} for {identity_str}"
                            )
                        if ctx == SpendContext.BARE:
                            if sig != 0:
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: bare multisig record has "
                                    f"sig_version {_sig_version_name(sig)}, "
                                    f"expected BASE for {identity_str}"
                                )
                            counts["bare_multisig_checks"] += 1
                        elif ctx == SpendContext.P2SH:
                            if sig != 0:
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: P2SH multisig record has "
                                    f"sig_version {_sig_version_name(sig)}, "
                                    f"expected BASE for {identity_str}"
                                )
                            counts["p2sh_multisig_checks"] += 1
                        elif ctx == SpendContext.NATIVE_WITNESS_V0:
                            if sig != 1:
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: native witness-v0 multisig "
                                    f"record has sig_version "
                                    f"{_sig_version_name(sig)}, "
                                    f"expected WITNESS_V0 for {identity_str}"
                                )
                            counts["native_witness_v0_multisig_checks"] += 1
                        elif ctx == SpendContext.P2SH_WRAPPED_WITNESS_V0:
                            if sig != 1:
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: P2SH-wrapped witness-v0 "
                                    f"multisig record has sig_version "
                                    f"{_sig_version_name(sig)}, "
                                    f"expected WITNESS_V0 for {identity_str}"
                                )
                            counts["p2sh_wrapped_witness_v0_multisig_checks"] += 1
                        elif ctx in (SpendContext.TAPROOT_KEY_PATH, SpendContext.TAPSCRIPT):
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: multisig record joined to a "
                                f"Taproot input {identity_str}"
                            )
                        else:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: unknown spend context {ctx!r}"
                            )
                    elif op == 5:
                        if sig != 2:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: CHECKSIGADD record must have "
                                f"sig_version TAPSCRIPT, got "
                                f"{_sig_version_name(sig)} for {identity_str}"
                            )
                        if ctx != SpendContext.TAPSCRIPT:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: CHECKSIGADD record joined to a "
                                f"non-Tapscript input {identity_str}"
                            )
                        counts["tapscript_schnorr_checks"] += 1
                        counts["tapscript_checksigadd_checks"] += 1
                    elif op == 0:
                        if sig != 3:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: key-path record must have "
                                f"sig_version TAPROOT, got {_sig_version_name(sig)} "
                                f"for {identity_str}"
                            )
                        if ctx != SpendContext.TAPROOT_KEY_PATH:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: key-path record joined to a "
                                f"non-key-path input {identity_str}"
                            )
                    elif op in (1, 2):
                        if sig == 2:
                            if ctx != SpendContext.TAPSCRIPT:
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: Tapscript CHECKSIG record "
                                    f"joined to a non-Tapscript input {identity_str}"
                                )
                            counts["tapscript_schnorr_checks"] += 1
                        elif sig == 1:
                            if ctx not in (
                                SpendContext.NATIVE_WITNESS_V0,
                                SpendContext.P2SH_WRAPPED_WITNESS_V0,
                            ):
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: WITNESS_V0 CHECKSIG record "
                                    f"joined to a non-witness-v0 input {identity_str}"
                                )
                        elif sig == 0:
                            if ctx not in (SpendContext.BARE, SpendContext.P2SH):
                                raise AnalyzerError(
                                    f"CTX-OPERATIONS: BASE CHECKSIG record joined "
                                    f"to a non-legacy input {identity_str}"
                                )
                        else:
                            raise AnalyzerError(
                                f"CTX-OPERATIONS: CHECKSIG record has unknown "
                                f"sig_version {sig} for {identity_str}"
                            )
                    else:
                        raise AnalyzerError(
                            f"CTX-OPERATIONS: unknown op_kind {op} for {identity_str}"
                        )
                    record_streamed_count += 1
                    # ── Global aggregate reconciliation ──
                    outcome = record.outcome
                    reject = record.reject_reason
                    # ECDSA: op in (1,2,3,4) with sig in (0,1) → ECDSA verify
                    is_ecdsa = op in (1, 2, 3, 4) and sig in (0, 1)
                    is_schnorr = (op in (1, 2, 5) and sig == 2) or (op == 0 and sig == 3)
                    # Native emission (instrumentation.diff): CheckECDSASignature
                    # increments C_CHECKECDSA_ENTRIES on every entry; the bad-pubkey
                    # (reject_reason 1), empty-sig (2), and missing-data (3) guards
                    # return before C_ECDSA_VERIFY_CALLS. Only outcome 0/1 are
                    # verify calls, with C_ECDSA_VERIFY_FAIL on outcome 0 (crypto
                    # false) and C_ECDSA_VERIFY_OK on outcome 1.
                    if is_ecdsa:
                        agg_checkecdsa_entries += 1
                        if outcome != 2:
                            agg_ecdsa_calls += 1
                            if outcome == 1:
                                agg_ecdsa_ok += 1
                            else:  # outcome == 0: verifier returned false
                                agg_ecdsa_fail += 1
                            # Per-key ECDSA verify-call tracking (verify calls
                            # only; pre-verification rejects never reach the
                            # verifier so they emit no record_ecdsa row).
                            conn.execute(
                                "INSERT INTO record_ecdsa (txid_le, input_index, calls, ok) "
                                "VALUES (?, ?, 1, ?) "
                                "ON CONFLICT(txid_le, input_index) DO UPDATE SET "
                                "calls = calls + 1, ok = ok + excluded.ok",
                                (record.spend_txid, record.input_index,
                                 1 if outcome == 1 else 0),
                            )
                    # Native emission: CheckSchnorrSignature increments
                    # C_CHECKSCHNORR_ENTRIES on entry (reject_reason 4..7 are rejects
                    # inside it), but reject_reason 8 is a Tapscript empty-sig skip
                    # emitted in EvalChecksigTapscript before the function is called,
                    # so it is neither an entry nor a verify call. Verify calls are
                    # outcome 0/1 with fail on outcome 0.
                    if is_schnorr:
                        if reject != 8:
                            agg_checkschnorr_entries += 1
                        if outcome != 2:
                            agg_schnorr_calls += 1
                            if outcome == 1:
                                agg_schnorr_ok += 1
                            else:  # outcome == 0
                                agg_schnorr_fail += 1
                    if outcome == 2 and reject <= 8:
                        agg_rejects[reject] += 1

            except sqlite3.IntegrityError as exc:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: duplicate record key in BRSREC1: {exc}"
                ) from exc

            if record_streamed_count != counters.record_count:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: BRSREC1 record count "
                    f"{record_streamed_count} != counters.record_count "
                    f"{counters.record_count}"
                )
            # ── Per-key op_seq contiguity proof via SQL ──
            # For every (txid, input_index), count of record_keys must equal
            # max(op_seq)+1 and min(op_seq) must be 0.
            gap_count = conn.execute(
                "SELECT COUNT(*) FROM ("
                "  SELECT txid_le, input_index "
                "  FROM record_keys "
                "  GROUP BY txid_le, input_index "
                "  HAVING COUNT(*) != MAX(op_seq) + 1 OR MIN(op_seq) != 0"
                ")"
            ).fetchone()[0]
            if gap_count:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: op_seq contiguity proof failed: "
                    f"{gap_count} key(s) with non-contiguous op_seq"
                )
            # Keys in record_ecdsa with mismatched journal values
            ecdsa_mismatch = conn.execute(
                "SELECT r.txid_le, r.input_index, r.calls, r.ok, "
                "j.ecdsa_verify_calls, j.ecdsa_verify_ok "
                "FROM record_ecdsa r "
                "JOIN journal j "
                "ON r.txid_le = j.txid_le AND r.input_index = j.input_index "
                "WHERE r.calls != j.ecdsa_verify_calls "
                "OR r.ok != j.ecdsa_verify_ok "
                "LIMIT 1"
            ).fetchone()
            if ecdsa_mismatch is not None:
                r_txid, r_idx, r_calls, r_ok, j_calls, j_ok = ecdsa_mismatch
                display_txid = r_txid[::-1].hex()
                raise AnalyzerError(
                    f"CTX-OPERATIONS: ECDSA mismatch for "
                    f"txid={display_txid}, input_index={r_idx}: "
                    f"records calls={r_calls} ok={r_ok}, "
                    f"journal calls={j_calls} ok={j_ok}"
                )
            # Keys in journal with ecdsa but missing from record_ecdsa
            jrn_only_ecdsa = conn.execute(
                "SELECT j.txid_le, j.input_index, j.ecdsa_verify_calls, "
                "j.ecdsa_verify_ok "
                "FROM journal j "
                "WHERE (j.ecdsa_verify_calls > 0 OR j.ecdsa_verify_ok > 0) "
                "AND NOT EXISTS ("
                "  SELECT 1 FROM record_ecdsa r "
                "  WHERE r.txid_le = j.txid_le AND r.input_index = j.input_index) "
                "LIMIT 1"
            ).fetchone()
            if jrn_only_ecdsa is not None:
                j_txid, j_idx, j_calls, j_ok = jrn_only_ecdsa
                display_txid = j_txid[::-1].hex()
                raise AnalyzerError(
                    f"CTX-OPERATIONS: journal has ECDSA calls for "
                    f"txid={display_txid}, input_index={j_idx} "
                    f"but no ECDSA records found"
                )

            # ── Journal-sum reconciliation: SUM(checksig_ops) and SUM(checkmultisig_ops) ──
            sum_checksig = conn.execute(
                "SELECT COALESCE(SUM(checksig_ops), 0) FROM journal"
            ).fetchone()[0]
            if sum_checksig != counters.op_checksig + counters.op_checksigverify:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: SUM(checksig_ops) {sum_checksig} != "
                    f"op_checksig + op_checksigverify "
                    f"{counters.op_checksig + counters.op_checksigverify}"
                )
            sum_checkmultisig = conn.execute(
                "SELECT COALESCE(SUM(checkmultisig_ops), 0) FROM journal"
            ).fetchone()[0]
            if sum_checkmultisig != counters.op_checkmultisig + counters.op_checkmultisigverify:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: SUM(checkmultisig_ops) {sum_checkmultisig} != "
                    f"op_checkmultisig + op_checkmultisigverify "
                    f"{counters.op_checkmultisig + counters.op_checkmultisigverify}"
                )
            # ── Global ECDSA/Schnorr/reject aggregate reconciliation ──
            if agg_ecdsa_calls != counters.ecdsa_verify_calls:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: ecdsa_verify_calls mismatch: "
                    f"records={agg_ecdsa_calls}, counters={counters.ecdsa_verify_calls}"
                )
            if agg_ecdsa_ok != counters.ecdsa_verify_ok:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: ecdsa_verify_ok mismatch: "
                    f"records={agg_ecdsa_ok}, counters={counters.ecdsa_verify_ok}"
                )
            if agg_ecdsa_fail != counters.ecdsa_verify_fail:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: ecdsa_verify_fail mismatch: "
                    f"records={agg_ecdsa_fail}, counters={counters.ecdsa_verify_fail}"
                )
            if agg_schnorr_calls != counters.schnorr_verify_calls:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: schnorr_verify_calls mismatch: "
                    f"records={agg_schnorr_calls}, counters={counters.schnorr_verify_calls}"
                )
            if agg_schnorr_ok != counters.schnorr_verify_ok:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: schnorr_verify_ok mismatch: "
                    f"records={agg_schnorr_ok}, counters={counters.schnorr_verify_ok}"
                )
            if agg_schnorr_fail != counters.schnorr_verify_fail:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: schnorr_verify_fail mismatch: "
                    f"records={agg_schnorr_fail}, counters={counters.schnorr_verify_fail}"
                )
            if agg_checkecdsa_entries != counters.checkecdsa_entries:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: checkecdsa_entries mismatch: "
                    f"records={agg_checkecdsa_entries}, counters={counters.checkecdsa_entries}"
                )
            if agg_checkschnorr_entries != counters.checkschnorr_entries:
                raise AnalyzerError(
                    f"CTX-OPERATIONS: checkschnorr_entries mismatch: "
                    f"records={agg_checkschnorr_entries}, counters={counters.checkschnorr_entries}"
                )
            # Eight reject counters reconciliation
            _reject_names = [
                "checkecdsa_reject_pubkey",
                "checkecdsa_reject_empty_sig",
                "checkecdsa_reject_missing_data",
            ]
            # reject_reason 1..3 (1=bad pubkey, 2=empty sig, 3=missing data per
            # instrumentation.diff) map to the three named ECDSA reject counters.
            for i, name in enumerate(_reject_names):
                if agg_rejects[i + 1] != getattr(counters, name):
                    raise AnalyzerError(
                        f"CTX-OPERATIONS: {name} mismatch: "
                        f"records={agg_rejects[i + 1]}, counters={getattr(counters, name)}"
                    )

            conn.commit()
        finally:
            conn.close()

    # Contexts custody comes from the same single-open parse stream.
    custody_meta: dict[str, dict[str, int]] = {
        "contexts": contexts_custody,
        "records": record_custody,
        "journal": journal_custody,
    }
    return counts, context_count, custody_meta
def _c150_passed(counts: dict[str, int], counters: Counters) -> bool:
    """Exact C150 product predicate.

    All 11 CONTEXT_COUNTER_NAMES are zero; the equality-chain counters all
    equal EXPECTED_FFI_VERIFY_ENTRIES_FULL (2_868_199); all complementary
    counters are zero.
    """
    # All 11 context counters must be zero
    if any(counts[name] != 0 for name in CONTEXT_COUNTER_NAMES):
        return False
    # Equality chain: all must equal 2_868_199
    expected = EXPECTED_FFI_VERIFY_ENTRIES_FULL
    equality_chain = (
        counters.ffi_verify_entries,
        counters.op_checksig,
        counters.ecdsa_from_checksig,
        counters.checkecdsa_entries,
        counters.ecdsa_verify_calls,
        counters.ecdsa_verify_ok,
    )
    if any(v != expected for v in equality_chain):
        return False
    # Complementary counters must be zero
    complementary_zero = (
        counters.op_checksigverify,
        counters.op_checkmultisig,
        counters.op_checkmultisigverify,
        counters.op_checksigadd,
        counters.ecdsa_from_checkmultisig,
        counters.checkecdsa_reject_pubkey,
        counters.checkecdsa_reject_empty_sig,
        counters.checkecdsa_reject_missing_data,
        counters.ecdsa_verify_fail,
        counters.checkschnorr_entries,
        counters.schnorr_verify_calls,
        counters.schnorr_verify_ok,
        counters.schnorr_verify_fail,
    )
    if any(v != 0 for v in complementary_zero):
        return False
    return True


def cmd_classify_corpus(args: argparse.Namespace) -> int:
    counters_path = Path(args.counters)
    contexts_path = Path(args.contexts)
    records_path = Path(args.records)
    journal_path = Path(args.journal)
    replay_path = Path(args.replay)
    manifest_path = Path(args.corpus_manifest)
    archive_path = Path(args.archive)
    output_path = Path(args.output)

    # ── Parse counters (single read, custody from same buffer) ──
    counters, counters_custody = parse_counters(counters_path)

    # ── Validate replay artifact and corpus manifest/archive ──
    # Each parser computes custody (size + sha256) from the exact buffer it
    # parses, eliminating TOCTOU from a separate prehash pass.
    replay = _validate_replay_artifact(replay_path)
    manifest = _validate_corpus_manifest(manifest_path, archive_path, replay)

    # ── Run disk-backed counter computation (returns custody for ctx/rec/jrn) ──
    counts, context_count, bin_custody = _count_context_records_disk(
        contexts_path, records_path, journal_path, counters
    )

    # ── Assemble custody from parser-returned metadata ──
    custody: dict[str, dict[str, object]] = {
        "counters": {
            "path": str(counters_path),
            "bytes": counters_custody["bytes"],
            "sha256": format(counters_custody["sha256"], "064x"),
        },
        "contexts": {
            "path": str(contexts_path),
            "bytes": bin_custody["contexts"]["bytes"],
            "sha256": format(bin_custody["contexts"]["sha256"], "064x"),
        },
        "records": {
            "path": str(records_path),
            "bytes": bin_custody["records"]["bytes"],
            "sha256": format(bin_custody["records"]["sha256"], "064x"),
        },
        "journal": {
            "path": str(journal_path),
            "bytes": bin_custody["journal"]["bytes"],
            "sha256": format(bin_custody["journal"]["sha256"], "064x"),
        },
        "replay": {
            "path": str(replay_path),
            "bytes": replay["custody"]["bytes"],
            "sha256": replay["custody"]["sha256"],
        },
        "corpus_manifest": {
            "path": str(manifest_path),
            "bytes": manifest["custody"]["bytes"],
            "sha256": manifest["custody"]["sha256"],
        },
        "archive": {
            "path": str(archive_path),
            "bytes": manifest["archive"]["size"],
            "sha256": manifest["archive"]["sha256"],
        },
    }

    # ── Counter arithmetic invariants (INV-1 through INV-7) ──
    inv_results = check_counter_arithmetic(counters)
    inv_all_passed = all(r["passed"] for r in inv_results)

    # ── Zero-input evidence precedence: validate counts > 0 before contract logic ──
    if counters.context_count == 0 or counters.journal_count == 0 or counters.record_count == 0:
        raise AnalyzerError(
            "CTX-EXECUTION: zero-input evidence rejected: "
            f"context_count={counters.context_count}, "
            f"journal_count={counters.journal_count}, "
            f"record_count={counters.record_count}"
        )

    # ── Apply c150 / cmodern contract logic ──
    if args.contract == "cmodern":
        # cmodern is not frozen until the exact tip is empirically recorded.
        cmodern_frozen = False
        all_passed = False
        report_error = (
            "CTX-CUSTODY: cmodern contract is not frozen until the exact "
            "tip is empirically recorded"
        )
    elif args.contract == "c150":
        # c150 pin: stop_height must be exactly 150000 and stop_hash must match.
        if replay["stop_height"] != C150_STOP_HEIGHT:
            raise AnalyzerError(
                f"CTX-CUSTODY: c150 requires stop_height {C150_STOP_HEIGHT}, "
                f"got {replay['stop_height']}"
            )
        if replay["stop_hash"] != C150_STOP_HASH:
            raise AnalyzerError(
                f"CTX-CUSTODY: c150 requires stop_hash {C150_STOP_HASH!r}, "
                f"got {replay['stop_hash']!r}"
            )
        c150_passed = _c150_passed(counts, counters) and inv_all_passed
        all_passed = c150_passed
    else:
        raise AnalyzerError(
            f"contract must be 'c150' or 'cmodern', got {args.contract!r}"
        )

    # ── Build report ──
    report: dict[str, object] = {
        "schema": "classify-corpus-v2",
        "contract": args.contract,
        "input_count": context_count,
        "context_counts": counts,
        "definitions": CONTEXT_COUNTER_DEFINITIONS,
        "all_passed": all_passed,
        "custody": custody,
        "replay": replay,
        "corpus_manifest": manifest,
        "counter_arithmetic": inv_results,
    }
    if args.contract == "cmodern":
        report["cmodern_frozen"] = cmodern_frozen
        report["error"] = report_error
    else:
        report["c150_passed"] = c150_passed

    # Optional cross-check: --input-count if provided.
    input_count_opt = getattr(args, "input_count", None)
    if input_count_opt is not None:
        if input_count_opt != context_count:
            raise AnalyzerError(
                f"CTX-SOURCE: --input-count {input_count_opt} != "
                f"BRSCTX1 context count {context_count}"
            )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2) + "\n")

    if all_passed:
        print(f"classify-corpus: PASSED — {args.contract}")
        return 0
    print(f"classify-corpus: FAILED — {args.contract}", file=sys.stderr)
    return 1


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
    vc.add_argument(
        "--repeat-counters", required=True, help="Run B counters JSON (second run)"
    )
    vc.add_argument(
        "--repeat-records", required=True, help="Run B records binary (second run)"
    )
    vc.add_argument(
        "--repeat-journal", required=True, help="Run B journal binary (second run)"
    )
    vc.add_argument("--output", required=True, help="output validation report JSON")
    vc.add_argument(
        "--sorted-records-output",
        default=None,
        help="optional: write sorted records binary here",
    )
    vc.add_argument(
        "--context-inputs",
        default=None,
        help="optional: census-context-input-v1 JSONL to bind corpus_size and corpus_sha256",
    )
    vc.set_defaults(func=cmd_validate_capture)

    vs = sub.add_parser(
        "validate-census", help="validate Run A census + cross-check with Run B"
    )
    vs.add_argument("--counters", required=True, help="Run A census counters JSON")
    vs.add_argument("--journal", required=True, help="Run A census journal binary")
    vs.add_argument(
        "--capture-journal", required=True, help="Run B capture journal binary"
    )
    vs.add_argument("--output", required=True, help="output validation report JSON")
    vs.set_defaults(func=cmd_validate_census)

    vd = sub.add_parser("verdict", help="compute OPEN/CLOSED/INVALID verdict")
    vd.add_argument(
        "--capture-counters", required=True, help="Run B capture counters JSON"
    )
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

    cc = sub.add_parser(
        "classify-corpus",
        help="classify verified inputs by spend context and join BRSREC1 records (v2)",
    )
    cc.add_argument(
        "--counters",
        required=True,
        help="counters JSON (schema 1) with ffi_verify_entries and record_count",
    )
    cc.add_argument(
        "--contexts",
        required=True,
        help="BRSCTX1 binary context evidence file (one row per verified non-coinbase input)",
    )
    cc.add_argument(
        "--records",
        required=True,
        help="BRSREC1 executed-operation records binary",
    )
    cc.add_argument(
        "--journal",
        required=True,
        help="BRSJRN1 journal binary",
    )
    cc.add_argument(
        "--replay",
        required=True,
        help="mainnet-prefix-replay-v2 JSON artifact",
    )
    cc.add_argument(
        "--corpus-manifest",
        required=True,
        help="bitcoin-rs-corpus-manifest v1 JSON",
    )
    cc.add_argument(
        "--archive",
        required=True,
        help="Core-framed corpus archive binary",
    )
    cc.add_argument(
        "--output",
        required=True,
        help="output classification report JSON",
    )
    cc.add_argument(
        "--contract",
        required=True,
        choices=("c150", "cmodern"),
        help="classification contract: c150 (C150 bare-multisig only) or cmodern (all context counters nonzero)",
    )
    cc.add_argument(
        "--input-count",
        default=None,
        type=int,
        help="optional cross-check: expected BRSCTX1 row count (BRSCTX1 file is authoritative)",
    )
    cc.set_defaults(func=cmd_classify_corpus)

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
