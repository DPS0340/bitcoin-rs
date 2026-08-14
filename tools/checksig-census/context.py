#!/usr/bin/env python3
"""Strict parsing and spend-container classification for census context evidence."""

from __future__ import annotations

import hashlib
import json
import os
import struct
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO

CONTEXT_MAGIC = b"BRSCTX1\x00"
CONTEXT_HEADER = struct.Struct("<8sQ")
CONTEXT_ROW_LENGTH = struct.Struct("<I")
CONTEXT_FIXED = struct.Struct("<32sIIIII")
CONTEXT_MIN_ROW_SIZE = CONTEXT_FIXED.size
# Consensus-maximum serialized block payload. No single BRSCTX1 row may
# legitimately exceed a block's worth of script/witness data.
CONTEXT_MAX_ROW_BYTES = 1 << 24

# Deprecated/diagnostic schema name retained for sampled tooling only.
CONTEXT_INPUT_SCHEMA = "census-context-input-v1"
_CONTEXT_FIELDS = {
    "schema",
    "height",
    "block_hash",
    "tx_index",
    "input_index",
    "txid",
    "prevout_script_pubkey_hex",
    "script_sig_hex",
    "witness_hex",
}


# Incoming kernel script verify flag bits emitted by Core 31.99.
# P2SH=1<<0, WITNESS=1<<11, TAPROOT=1<<17.
VERIFY_P2SH = 0x1
VERIFY_WITNESS = 1 << 11
VERIFY_TAPROOT = 1 << 17


class ContextError(ValueError):
    """The context evidence is malformed, ambiguous, or incomplete."""


class SpendContext(str, Enum):
    BARE = "bare"
    P2SH = "p2sh"
    NATIVE_WITNESS_V0 = "native_witness_v0"
    P2SH_WRAPPED_WITNESS_V0 = "p2sh_wrapped_witness_v0"
    TAPROOT_KEY_PATH = "taproot_key_path"
    TAPSCRIPT = "tapscript"


@dataclass(frozen=True)
class InputIdentity:
    txid_le: bytes
    input_index: int

    def __post_init__(self) -> None:
        if len(self.txid_le) != 32:
            raise ContextError("CTX-RAW: execution txid must contain exactly 32 bytes")
        if not 0 <= self.input_index <= 0xFFFF_FFFF:
            raise ContextError("CTX-RAW: input index is outside u32 range")

    @property
    def execution_key(self) -> tuple[bytes, int]:
        return (self.txid_le, self.input_index)

    @property
    def display_txid(self) -> str:
        return self.txid_le[::-1].hex()


@dataclass(frozen=True)
class ContextInput:
    identity: InputIdentity
    verify_flags: int
    prevout_script_pubkey: bytes
    script_sig: bytes
    witness: tuple[bytes, ...]


@dataclass(frozen=True)
class ClassifiedInput:
    evidence: ContextInput
    spend_context: SpendContext


@dataclass(frozen=True)
class ScriptElement:
    opcode: int
    pushed: bytes | None


def _read_exact(stream: BinaryIO, length: int, field: str, row_number: int | None = None) -> bytes:
    data = stream.read(length)
    if len(data) != length:
        location = "header" if row_number is None else f"row {row_number}"
        raise ContextError(f"CTX-RAW: short {field} in {location}: expected {length} bytes, got {len(data)}")
    return data


def _consume_blob(
    stream: BinaryIO, length: int, remaining: int, field: str, row_number: int
) -> tuple[bytes, int]:
    if length > remaining:
        raise ContextError(
            f"CTX-RAW: row {row_number} {field} length {length} exceeds "
            f"{remaining} bytes remaining in row"
        )
    return _read_exact(stream, length, field, row_number), remaining - length


def decode_context_row(
    stream: BinaryIO,
    row_number: int,
    available: int,
    *,
    boundary: str = "end of file",
) -> ContextInput:
    """Decode one canonically framed BRSCTX1 row from ``stream``.

    ``available`` is the exact number of bytes remaining in the caller's
    trusted boundary. Strict full-file and live committed-prefix parsing both
    use this function so framing and field legality cannot drift.
    """
    row_length = CONTEXT_ROW_LENGTH.unpack(
        _read_exact(stream, CONTEXT_ROW_LENGTH.size, "row length", row_number)
    )[0]
    if row_length < CONTEXT_MIN_ROW_SIZE:
        raise ContextError(
            f"CTX-RAW: row {row_number} length {row_length} is shorter than "
            f"the {CONTEXT_MIN_ROW_SIZE}-byte fixed body"
        )
    if row_length > CONTEXT_MAX_ROW_BYTES:
        raise ContextError(
            f"CTX-RAW: row {row_number} length {row_length} exceeds "
            f"the {CONTEXT_MAX_ROW_BYTES}-byte maximum"
        )
    payload_available = available - CONTEXT_ROW_LENGTH.size
    if row_length > payload_available:
        raise ContextError(
            f"CTX-RAW: row {row_number} length {row_length} extends "
            f"{payload_available} bytes past {boundary}"
        )

    (
        txid_le,
        input_index,
        verify_flags,
        prevout_length,
        script_sig_length,
        witness_count,
    ) = CONTEXT_FIXED.unpack(
        _read_exact(stream, CONTEXT_FIXED.size, "fixed fields", row_number)
    )

    if prevout_length > 0xFFFF_FFFF:
        raise ContextError(f"CTX-RAW: row {row_number} prevout length overflows u32")
    if script_sig_length > 0xFFFF_FFFF:
        raise ContextError(f"CTX-RAW: row {row_number} scriptSig length overflows u32")
    if witness_count > 0xFFFF_FFFF:
        raise ContextError(f"CTX-RAW: row {row_number} witness count overflows u32")

    remaining = row_length - CONTEXT_FIXED.size
    if witness_count > remaining // 4:
        raise ContextError(
            f"CTX-RAW: row {row_number} witness count {witness_count} cannot fit "
            f"in the {remaining} bytes remaining in its row"
        )

    prevout, remaining = _consume_blob(
        stream, prevout_length, remaining, "prevout script", row_number
    )
    script_sig, remaining = _consume_blob(
        stream, script_sig_length, remaining, "scriptSig", row_number
    )

    witness: list[bytes] = []
    for item_index in range(witness_count):
        if remaining < 4:
            raise ContextError(
                f"CTX-RAW: row {row_number} is short before witness item {item_index}"
            )
        item_length = struct.unpack(
            "<I", _read_exact(stream, 4, "witness item length", row_number)
        )[0]
        remaining -= 4
        item, remaining = _consume_blob(
            stream,
            item_length,
            remaining,
            f"witness item {item_index}",
            row_number,
        )
        witness.append(item)

    if remaining != 0:
        raise ContextError(
            f"CTX-RAW: row {row_number} length mismatch: {remaining} unconsumed bytes"
        )

    return ContextInput(
        identity=InputIdentity(txid_le=txid_le, input_index=input_index),
        verify_flags=verify_flags,
        prevout_script_pubkey=prevout,
        script_sig=script_sig,
        witness=tuple(witness),
    )


class _PreadBoundedReader:
    """Sequential view over one immutable committed prefix using ``pread``."""

    def __init__(
        self,
        fd: int,
        start: int,
        end: int,
        observe_bytes: Callable[[bytes], None] | None = None,
    ) -> None:
        self._fd = fd
        self._cursor = start
        self._end = end
        self._observe_bytes = observe_bytes

    @property
    def cursor(self) -> int:
        return self._cursor

    @property
    def remaining(self) -> int:
        return self._end - self._cursor

    def read(self, length: int) -> bytes:
        length = min(length, self.remaining)
        if length <= 0:
            return b""
        data = os.pread(self._fd, length, self._cursor)
        self._cursor += len(data)
        if data and self._observe_bytes is not None:
            self._observe_bytes(data)
        return data


def read_bounded_context_rows(
    fd: int,
    *,
    start_offset: int,
    end_offset: int,
    start_row: int,
    committed_rows: int,
    observe_bytes: Callable[[bytes], None] | None = None,
) -> list[ContextInput]:
    """Read only newly committed BRSCTX1 rows from an already-open fd.

    The producer may still have the placeholder header count zero. A patched
    terminal count is accepted only when it covers the requested committed
    prefix. Bytes beyond ``end_offset`` are never observed. ``observe_bytes``
    receives each committed payload byte exactly once.
    """
    if start_row < 0 or committed_rows < start_row:
        raise ContextError(
            f"CTX-RAW: invalid committed row range {start_row}..{committed_rows}"
        )
    if start_offset < CONTEXT_HEADER.size or end_offset < start_offset:
        raise ContextError(
            f"CTX-RAW: invalid committed byte range {start_offset}..{end_offset}"
        )
    file_size = os.fstat(fd).st_size
    if end_offset > file_size:
        raise ContextError(
            f"CTX-RAW: committed endpoint {end_offset} exceeds current file size {file_size}"
        )
    header = os.pread(fd, CONTEXT_HEADER.size, 0)
    if len(header) != CONTEXT_HEADER.size:
        raise ContextError(
            f"CTX-RAW: short header: expected {CONTEXT_HEADER.size} bytes, got {len(header)}"
        )
    magic, declared_count = CONTEXT_HEADER.unpack(header)
    if magic != CONTEXT_MAGIC:
        raise ContextError(f"CTX-RAW: wrong magic {magic!r}, expected {CONTEXT_MAGIC!r}")
    if declared_count != 0 and declared_count < committed_rows:
        raise ContextError(
            f"CTX-RAW: terminal row count {declared_count} is below committed prefix count {committed_rows}"
        )

    reader = _PreadBoundedReader(fd, start_offset, end_offset, observe_bytes)
    rows = [
        decode_context_row(
            reader,
            row_number,
            reader.remaining,
            boundary="committed endpoint",
        )
        for row_number in range(start_row + 1, committed_rows + 1)
    ]
    if reader.cursor != end_offset:
        raise ContextError(
            f"CTX-RAW: {end_offset - reader.cursor} trailing byte(s) within committed prefix"
        )
    return rows


def _parse_legacy_row(value: object, line_number: int) -> ContextInput:
    """Parse one diagnostic census-context-input-v1 JSONL row."""
    if not isinstance(value, dict):
        raise ContextError(f"CTX-DIAG line {line_number}: JSON value must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ContextError(f"CTX-DIAG line {line_number}: object keys must be strings")
    row = {str(key): item for key, item in value.items()}
    actual = set(row)
    if actual != _CONTEXT_FIELDS:
        missing = sorted(_CONTEXT_FIELDS - actual)
        extra = sorted(actual - _CONTEXT_FIELDS)
        raise ContextError(
            f"CTX-DIAG line {line_number}: fields differ from {CONTEXT_INPUT_SCHEMA}; "
            f"missing={missing}, extra={extra}"
        )
    if row["schema"] != CONTEXT_INPUT_SCHEMA:
        raise ContextError(f"CTX-DIAG line {line_number}: schema must be {CONTEXT_INPUT_SCHEMA!r}")

    block_hash_bytes = _require_hex(row["block_hash"], "block_hash", line_number, 32)
    txid_bytes = _require_hex(row["txid"], "txid", line_number, 32)
    witness_value = row["witness_hex"]
    if not isinstance(witness_value, list):
        raise ContextError(f"CTX-DIAG line {line_number}: witness_hex must be an array")
    witness = tuple(
        _require_hex(item, f"witness_hex[{index}]", line_number)
        for index, item in enumerate(witness_value)
    )

    return ContextInput(
        identity=InputIdentity(txid_le=txid_bytes[::-1], input_index=_require_uint(row["input_index"], "input_index", line_number)),
        verify_flags=0,
        prevout_script_pubkey=_require_hex(row["prevout_script_pubkey_hex"], "prevout_script_pubkey_hex", line_number),
        script_sig=_require_hex(row["script_sig_hex"], "script_sig_hex", line_number),
        witness=witness,
    )


def _require_uint(value: object, field: str, line_number: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContextError(f"CTX-DIAG line {line_number}: {field} must be a non-negative integer")
    return value


def _require_hex(value: object, field: str, line_number: int, size: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise ContextError(f"CTX-DIAG line {line_number}: {field} must be a string")
    if value != value.lower() or len(value) % 2 != 0:
        raise ContextError(
            f"CTX-DIAG line {line_number}: {field} must be even-length lowercase hex"
        )
    try:
        decoded = bytes.fromhex(value)
    except ValueError:
        raise ContextError(f"CTX-DIAG line {line_number}: {field} must be lowercase hex")
    if size is not None and len(decoded) != size:
        raise ContextError(f"CTX-DIAG line {line_number}: {field} must encode exactly {size} bytes")
    return decoded


class _HashingReader:
    """BinaryIO wrapper that hashes every byte read and counts total bytes."""

    def __init__(self, stream: BinaryIO, hasher: hashlib._Hash) -> None:
        self._stream = stream
        self._hasher = hasher
        self._bytes_read = 0

    def read(self, length: int) -> bytes:
        data = self._stream.read(length)
        if data:
            self._hasher.update(data)
            self._bytes_read += len(data)
        return data

    def close(self) -> None:
        self._stream.close()


class ContextIterator(Iterator[ContextInput]):
    """Single-open streaming BRSCTX1 parser that returns custody from the same stream.

    The file is opened once, every byte read is fed into a SHA-256 hasher, and
    the row count is tracked. After the iterator is exhausted, ``custody()``
    returns ``{'bytes': total_bytes, 'sha256': hex_digest, 'count': row_count}``
    from that exact parse stream.
    """

    def __init__(self, path: Path, dedup: bool = True) -> None:
        self._path = path
        self._dedup = dedup
        self._hasher = hashlib.sha256()
        self._stream: _HashingReader | None = None
        self._count = 0
        self._closed = False
        self._gen = self._run()

    def _open(self) -> _HashingReader:
        if self._stream is None:
            self._stream = _HashingReader(self._path.open("rb"), self._hasher)
        return self._stream

    def _run(self) -> Iterator[ContextInput]:
        stream = self._open()
        try:
            file_size = self._path.stat().st_size
            if file_size < CONTEXT_HEADER.size:
                raise ContextError(f"CTX-RAW: short header: expected {CONTEXT_HEADER.size} bytes, got {file_size}")

            magic, declared_count = CONTEXT_HEADER.unpack(
                _read_exact(stream, CONTEXT_HEADER.size, "header")
            )
            if magic != CONTEXT_MAGIC:
                raise ContextError(f"CTX-RAW: wrong magic {magic!r}, expected {CONTEXT_MAGIC!r}")
            if declared_count > 0xFFFF_FFFF_FFFF_FFFF:
                raise ContextError(f"CTX-RAW: declared row count exceeds representable u64 range")

            available = file_size - CONTEXT_HEADER.size
            minimum_framed_row = CONTEXT_ROW_LENGTH.size + CONTEXT_MIN_ROW_SIZE
            if declared_count > available // minimum_framed_row:
                raise ContextError(
                    f"CTX-RAW: declared row count {declared_count} cannot fit "
                    f"in the {available} payload bytes"
                )

            identities: set[tuple[bytes, int]] | None = set() if self._dedup else None

            for row_number in range(1, declared_count + 1):
                evidence = decode_context_row(
                    stream, row_number, file_size - stream._bytes_read
                )
                identity = evidence.identity
                if identities is not None:
                    if identity.execution_key in identities:
                        raise ContextError(
                            f"CTX-EXECUTION: duplicate context execution identity "
                            f"{identity.display_txid}:{identity.input_index}"
                        )
                    identities.add(identity.execution_key)
                self._count += 1
                yield evidence

            trailing = stream.read(1)
            if trailing:
                raise ContextError("CTX-RAW: trailing bytes after declared BRSCTX1 rows")
        finally:
            if not self._closed:
                self.close()
                self._closed = True

    def __iter__(self) -> ContextIterator:
        return self

    def __next__(self) -> ContextInput:
        return next(self._gen)

    def close(self) -> None:
        if self._stream is not None:
            self._stream.close()
            self._closed = True

    def custody(self) -> dict[str, object]:
        """Return custody metadata from the exact parse stream.

        Must be called after the iterator is exhausted. The reported SHA-256
        and byte count come from the same already-open byte stream used to
        parse and validate rows.
        """
        return {
            "bytes": self._stream._bytes_read if self._stream else 0,
            "sha256": int(self._hasher.hexdigest(), 16),
            "count": self._count,
        }


def iter_context_inputs(path: Path, dedup: bool = True) -> ContextIterator:
    """Yield strict BRSCTX1 rows from a single open hashing stream."""
    return ContextIterator(path, dedup=dedup)


def read_context_inputs(path: Path) -> list[ContextInput]:
    return list(iter_context_inputs(path))


def iter_legacy_context_inputs(path: Path, expected_input_count: int) -> Iterator[ContextInput]:
    """Diagnostic-only JSONL iterator; no census certification path uses this."""
    if isinstance(expected_input_count, bool) or not isinstance(expected_input_count, int) or expected_input_count < 0:
        raise ContextError("CTX-DIAG: expected_input_count must be a non-negative integer")
    seen = 0
    identities: set[tuple[bytes, int]] = set()
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            raise ContextError(f"CTX-DIAG line {line_number}: blank lines are not permitted")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ContextError(f"CTX-DIAG line {line_number}: invalid JSON: {error}")
        row = _parse_legacy_row(value, line_number)
        if row.identity.execution_key in identities:
            raise ContextError(
                f"CTX-DIAG line {line_number}: duplicate execution identity "
                f"{row.identity.display_txid}:{row.identity.input_index}"
            )
        identities.add(row.identity.execution_key)
        seen += 1
        if seen > expected_input_count:
            raise ContextError(
                f"CTX-DIAG: context input count mismatch: expected {expected_input_count}, got more"
            )
        yield row
    if seen != expected_input_count:
        raise ContextError(
            f"CTX-DIAG: context input count mismatch: expected {expected_input_count}, got {seen}"
        )


def parse_script(script: bytes) -> tuple[ScriptElement, ...]:
    """Parse every script byte into data pushes or opcodes, rejecting truncation."""
    elements: list[ScriptElement] = []
    offset = 0
    while offset < len(script):
        opcode = script[offset]
        offset += 1
        pushed: bytes | None = None
        if opcode == 0:
            pushed = b""
        elif 1 <= opcode <= 75:
            if offset + opcode > len(script):
                raise ContextError(f"script push opcode {opcode} truncated at byte {offset}")
            pushed = script[offset : offset + opcode]
            offset += opcode
        elif opcode == 76:
            if offset + 1 > len(script):
                raise ContextError("script OP_PUSHDATA1 length byte missing")
            length = script[offset]
            offset += 1
            if offset + length > len(script):
                raise ContextError("script OP_PUSHDATA1 payload truncated")
            pushed = script[offset : offset + length]
            offset += length
        elif opcode == 77:
            if offset + 2 > len(script):
                raise ContextError("script OP_PUSHDATA2 length bytes missing")
            length = struct.unpack_from("<H", script, offset)[0]
            offset += 2
            if offset + length > len(script):
                raise ContextError("script OP_PUSHDATA2 payload truncated")
            pushed = script[offset : offset + length]
            offset += length
        elif opcode == 78:
            if offset + 4 > len(script):
                raise ContextError("script OP_PUSHDATA4 length bytes missing")
            length = struct.unpack_from("<I", script, offset)[0]
            offset += 4
            if offset + length > len(script):
                raise ContextError("script OP_PUSHDATA4 payload truncated")
            pushed = script[offset : offset + length]
            offset += length
        elif opcode == 79:
            pushed = b"\x81"
        elif 81 <= opcode <= 96:
            pushed = bytes([opcode - 80])
        elements.append(ScriptElement(opcode=opcode, pushed=pushed))
    return tuple(elements)


def _push_only_stack(script_sig: bytes) -> tuple[bytes, ...]:
    """Return the stack produced by a push-only script, or fail closed."""
    stack: list[bytes] = []
    for element in parse_script(script_sig):
        if element.pushed is None:
            raise ContextError("scriptSig is not push-only")
        stack.append(element.pushed)
    return tuple(stack)


def _witness_v0_program(script: bytes) -> bool:
    return len(script) in (22, 34) and script[0] == 0 and script[1] in (20, 32)


def _is_p2sh(script: bytes) -> bool:
    return len(script) == 23 and script[:2] == b"\xa9\x14" and script[-1:] == b"\x87"


def _is_p2tr(script: bytes) -> bool:
    return len(script) == 34 and script[:2] == b"\x51\x20"


def _require_witness_v0(evidence: ContextInput) -> None:
    if not evidence.witness:
        raise ContextError("witness-v0 input has an empty witness stack")


def _classify_bare(evidence: ContextInput) -> SpendContext:
    return SpendContext.BARE


def _classify_witness_v0(evidence: ContextInput) -> SpendContext:
    if evidence.script_sig:
        raise ContextError(
            "native witness-v0 input has a non-empty scriptSig after successful validation"
        )
    _require_witness_v0(evidence)
    return SpendContext.NATIVE_WITNESS_V0


def _classify_p2sh(evidence: ContextInput) -> SpendContext:
    stack = _push_only_stack(evidence.script_sig)
    if stack:
        redeem = stack[-1]
        if _witness_v0_program(redeem) and (evidence.verify_flags & VERIFY_WITNESS):
            return SpendContext.P2SH_WRAPPED_WITNESS_V0
    return SpendContext.P2SH


def _classify_taproot(evidence: ContextInput) -> SpendContext:
    if evidence.script_sig:
        raise ContextError("taproot input has a non-empty scriptSig")
    witness = list(evidence.witness)
    if witness and witness[-1] and witness[-1][0] == 0x50:
        witness.pop()
    if not witness:
        raise ContextError("taproot input has no witness elements")
    if len(witness) == 1:
        if len(witness[0]) not in (64, 65):
            raise ContextError("taproot key-path signature has wrong length")
        return SpendContext.TAPROOT_KEY_PATH
    control_block = witness[-1]
    if len(control_block) < 33 or (len(control_block) - 1) % 32 != 0 or len(control_block) > 4129:
        raise ContextError("tapscript control block has wrong length")
    return SpendContext.TAPSCRIPT


def classify_input(evidence: ContextInput) -> ClassifiedInput:
    prevout = evidence.prevout_script_pubkey
    if _is_p2tr(prevout):
        if not (evidence.verify_flags & VERIFY_WITNESS):
            context = _classify_bare(evidence)
        elif not (evidence.verify_flags & VERIFY_TAPROOT):
            context = _classify_bare(evidence)
        else:
            context = _classify_taproot(evidence)
    elif _is_p2sh(prevout):
        if not (evidence.verify_flags & VERIFY_P2SH):
            context = _classify_bare(evidence)
        else:
            context = _classify_p2sh(evidence)
    elif _witness_v0_program(prevout):
        if evidence.verify_flags & VERIFY_WITNESS:
            context = _classify_witness_v0(evidence)
        else:
            context = _classify_bare(evidence)
    else:
        context = _classify_bare(evidence)
    return ClassifiedInput(evidence=evidence, spend_context=context)


def classify_context_inputs(rows: list[ContextInput]) -> list[ClassifiedInput]:
    return [classify_input(row) for row in rows]
