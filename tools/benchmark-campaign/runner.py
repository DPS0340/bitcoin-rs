#!/usr/bin/env python3
# pyright: strict
"""Strict exact-seven-pair benchmark campaign runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import re
import signal
import stat
import statistics
import string
import subprocess
import sys
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, NoReturn, TypeIs

from native_offline import (
    ADAPTER_PLACEHOLDERS,
    PROOF_SCOPE,
    AdapterKind,
    CandidateExpectation,
    CellProof,
    CertifiedState,
    ContractError,
    NativeArmResult,
    ProofExpectation,
    arm_result_from_json,
    arm_result_json,
    core_expectation,
    parse_candidate_file,
    parse_cell_proof,
    parse_core_file,
    state_from_json,
    state_json,
)

CONFIG_SCHEMA = "benchmark-campaign-config-v2"
RESULT_SCHEMA = "benchmark-campaign-result-v2"
PAIR_COUNT = 7
ARM_COUNT = PAIR_COUNT * 2
PERFORMANCE_GATE = 2.0
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_FD_PATH_RE = re.compile(r"/proc/self/fd/([0-9]+)\Z")
_FIXED_CHILD_ENV: dict[str, str] = {
    "LC_ALL": "C",
    "TZ": "UTC",
}


class Domain(str, Enum):
    OFFLINE = "offline"
    P2P = "p2p"
    RPC = "rpc"


class Corpus(str, Enum):
    C150 = "c150"
    CMODERN = "cmodern"


class Architecture(str, Enum):
    X86_64 = "x86_64"
    AARCH64 = "aarch64"


_HOST_ARCH_ALIASES: dict[str, Architecture] = {
    "x86_64": Architecture.X86_64,
    "amd64": Architecture.X86_64,
    "aarch64": Architecture.AARCH64,
    "arm64": Architecture.AARCH64,
}


class Backend(str, Enum):
    FJALL = "fjall"
    ROCKSDB = "rocksdb"
    REDB = "redb"


class Role(str, Enum):
    CANDIDATE = "candidate"
    CORE = "core"


class Verdict(str, Enum):
    PASS = "pass"
    FAIL_PERF = "fail_perf"
    FAIL_CORRECTNESS = "fail_correctness"
    FAIL_RUN = "fail_run"
    INVALID_ENV = "invalid_env"
    BLOCKED = "blocked"


@dataclass(frozen=True, order=True)
class CellId:
    domain: Domain
    corpus: Corpus
    architecture: Architecture
    backend: Backend

    @property
    def key(self) -> str:
        return (
            f"{self.domain.value}/{self.corpus.value}/"
            f"{self.architecture.value}/{self.backend.value}"
        )


@dataclass(frozen=True)
class ProgramIdentity:
    adapter: AdapterKind
    binary_path: str
    binary_sha256: str
    commit: str
    build: str
    features: tuple[str, ...]
    mimalloc: bool
    command: tuple[str, ...]


@dataclass(frozen=True)
class PreparedProgram:
    identity: ProgramIdentity
    path: Path
    fingerprint: tuple[int, int, int, int, int, int]
    descriptor: int


@dataclass(frozen=True)
class FailedProgram:
    identity: ProgramIdentity
    path: Path
    error: str


type ProgramCustody = PreparedProgram | FailedProgram


@dataclass(frozen=True)
class PreparedPrograms:
    candidate: ProgramCustody
    core: ProgramCustody


@dataclass(frozen=True)
class FileCustody:
    path: Path
    fingerprint: tuple[int, int, int, int, int, int]
    descriptor: int


@dataclass(frozen=True)
class InputCustody:
    corpus: FileCustody
    manifest: FileCustody
    proof: FileCustody


@dataclass(frozen=True)
class CellConfig:
    cell: CellId
    blocked_reason: str | None
    candidate: ProgramIdentity
    core: ProgramIdentity
    corpus_path: str
    corpus_sha256: str
    manifest_path: str
    manifest_sha256: str
    proof_path: str | None
    proof_sha256: str | None
    affinity: tuple[int, ...]

    @property
    def ready(self) -> bool:
        return self.blocked_reason is None


@dataclass(frozen=True)
class CampaignConfig:
    schedule_seed: int
    output_root: str
    cells: tuple[CellConfig, ...]
    canonical_sha256: str


@dataclass(frozen=True)
class ArmObservation:
    role: Role
    pair_index: int
    order_index: int
    command: tuple[str, ...]
    arm_dir: str
    data_dir: str
    result_path: str
    stdout_path: str
    stderr_path: str
    pid: int | None
    pid_starttime: int | None
    wall_ns: int | None
    cpu_user_ns: int | None
    cpu_system_ns: int | None
    peak_rss_bytes: int | None
    exit_code: int | None
    arm_result: NativeArmResult | None
    error: str | None

    @property
    def run_valid(self) -> bool:
        return (
            self.error is None and self.exit_code == 0 and self.arm_result is not None
        )


@dataclass(frozen=True)
class PairResult:
    pair_index: int
    order: tuple[Role, Role]
    candidate: ArmObservation
    core: ArmObservation
    valid: bool
    correctness_match: bool | None


@dataclass(frozen=True)
class CellResult:
    config_sha256: str
    cell_config: CellConfig
    proof_sha256: str
    proof_scope: str
    certified_state: CertifiedState
    schedule_seed: int
    pairs: tuple[PairResult, ...]
    scheduled_pairs: int
    valid_pairs: int
    candidate_median_wall_ns: int | None
    core_median_wall_ns: int | None
    wall_ratio: float | None
    verdict: Verdict


ALL_CELLS = tuple(
    CellId(domain, corpus, architecture, backend)
    for domain in Domain
    for corpus in Corpus
    for architecture in Architecture
    for backend in Backend
)
if len(ALL_CELLS) != 36 or len(set(ALL_CELLS)) != 36:
    raise RuntimeError("campaign universe must contain exactly 36 unique cells")


def _is_json_object(value: object) -> TypeIs[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)  # pyright: ignore[reportUnknownVariableType]


def _is_json_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _object(value: object, field: str, keys: frozenset[str]) -> dict[str, object]:
    if not _is_json_object(value):
        raise ContractError(f"{field} must be a JSON object")
    actual = frozenset(value)
    if actual != keys:
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        raise ContractError(
            f"{field} has wrong keys; missing={missing}, unknown={unknown}"
        )
    return value


def _array(value: object, field: str) -> list[object]:
    if not _is_json_array(value):
        raise ContractError(f"{field} must be an array")
    return value


def _text(value: object, field: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        qualifier = "nonempty " if nonempty else ""
        raise ContractError(f"{field} must be a {qualifier}string")
    return value


def _boolean(value: object, field: str) -> bool:
    if not isinstance(value, bool):
        raise ContractError(f"{field} must be a boolean")
    return value


def _uint(value: object, field: str, *, positive: bool = False) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or value < (1 if positive else 0)
    ):
        qualifier = "positive " if positive else "nonnegative "
        raise ContractError(f"{field} must be a {qualifier}integer")
    return value


def _optional_uint(value: object, field: str) -> int | None:
    return None if value is None else _uint(value, field)


def _optional_text(value: object, field: str) -> str | None:
    return None if value is None else _text(value, field)


def _finite_number(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number")
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise ContractError(f"{field} must be finite and nonnegative")
    return result


def _hash(value: object, field: str) -> str:
    text = _text(value, field)
    if _HASH_RE.fullmatch(text) is None:
        raise ContractError(
            f"{field} must be exactly 64 lowercase hexadecimal characters"
        )
    return text


def _canonical_absolute_path(value: str, field: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or value != str(path):
        raise ContractError(f"{field} must be an absolute normalized path")
    resolved = path.resolve(strict=False)
    if resolved != path:
        raise ContractError(f"{field} must not use a filesystem alias")
    return resolved


def _enum(enum_type: type[Enum], value: object, field: str) -> Enum:
    text = _text(value, field)
    try:
        return enum_type(text)
    except ValueError as error:
        raise ContractError(f"{field} has unsupported value {text!r}") from error


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _sha256_json(value: object) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _fingerprint(status: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _snapshot_file(path_text: str, expected_sha256: str, field: str) -> FileCustody:
    path = Path(path_text)
    if not path.is_absolute():
        raise ContractError(f"{field} must be absolute")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    except OSError as error:
        raise ContractError(f"cannot open {field} {path}: {error}") from error
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ContractError(f"{field} must be a regular file")
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            observed_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(descriptor)
        if _fingerprint(before) != _fingerprint(after):
            raise ContractError(f"{field} changed while it was hashed")
        if observed_sha256 != expected_sha256:
            raise ContractError(
                f"{field} hash mismatch for {path}: "
                f"expected {expected_sha256}, got {observed_sha256}"
            )
        return FileCustody(path, _fingerprint(after), descriptor)
    except (OSError, ContractError):
        os.close(descriptor)
        raise


def _snapshot_inputs(config: CellConfig) -> InputCustody:
    if config.proof_path is None or config.proof_sha256 is None:
        raise ContractError("ready cell requires a cell proof")
    opened: list[FileCustody] = []
    try:
        corpus = _snapshot_file(config.corpus_path, config.corpus_sha256, "corpus_path")
        opened.append(corpus)
        manifest = _snapshot_file(
            config.manifest_path, config.manifest_sha256, "manifest_path"
        )
        opened.append(manifest)
        proof = _snapshot_file(config.proof_path, config.proof_sha256, "proof_path")
        return InputCustody(corpus=corpus, manifest=manifest, proof=proof)
    except (OSError, ContractError):
        for custody in reversed(opened):
            os.close(custody.descriptor)
        raise


def _verify_file_unchanged(custody: FileCustody, field: str) -> None:
    try:
        current_path = custody.path.stat()
        current_descriptor = os.fstat(custody.descriptor)
    except OSError as error:
        raise ContractError(f"cannot verify {field} {custody.path}: {error}") from error
    if (
        not stat.S_ISREG(current_path.st_mode)
        or _fingerprint(current_path) != custody.fingerprint
        or _fingerprint(current_descriptor) != custody.fingerprint
    ):
        raise ContractError(f"{field} changed during campaign execution")


def _close_inputs(custody: InputCustody) -> None:
    for item in (custody.corpus, custody.manifest, custody.proof):
        os.close(item.descriptor)


def _verify_inputs_unchanged(custody: InputCustody) -> None:
    _verify_file_unchanged(custody.corpus, "corpus_path")
    _verify_file_unchanged(custody.manifest, "manifest_path")
    _verify_file_unchanged(custody.proof, "proof_path")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    with path.open("rb") as stream:
        os.fsync(stream.fileno())


def _mkdir_durable(path: Path) -> None:
    missing: list[Path] = []
    cursor = path
    while not cursor.exists():
        missing.append(cursor)
        parent = cursor.parent
        if parent == cursor:
            raise ContractError(f"cannot find existing parent for {path}")
        cursor = parent
    if not cursor.is_dir():
        raise ContractError(f"{cursor} is not a directory")
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            if not directory.is_dir():
                raise ContractError(f"{directory} is not a directory") from None
        _fsync_directory(directory.parent)


def _persist_arm_evidence(arm_dir: Path, files: tuple[Path, ...]) -> None:
    for path in files:
        if path.is_file():
            _fsync_file(path)
    _fsync_directory(arm_dir)


def _custody_program_path(run_dir: Path, role: Role, program: ProgramIdentity) -> Path:
    basename = Path(program.binary_path).name or "program"
    return run_dir / "programs" / role.value / basename


def _write_all(stream: BinaryIO, chunk: bytes) -> int:
    view = memoryview(chunk)
    written = 0
    while view:
        count = stream.write(view)
        if count <= 0:
            raise OSError("short write while preparing program custody")
        written += count
        view = view[count:]
    return written


def _prepare_program(
    program: ProgramIdentity, role: Role, run_dir: Path
) -> ProgramCustody:
    destination = _custody_program_path(run_dir, role, program)
    _mkdir_durable(destination.parent)
    source_path = Path(program.binary_path)
    descriptor: int | None = None
    if not source_path.is_absolute():
        return FailedProgram(
            program, destination, "program binary_path must be absolute"
        )
    try:
        digest = hashlib.sha256()
        bytes_written = 0
        with source_path.open("rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ContractError("program binary_path must be a regular file")
            with destination.open("xb") as copied:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    bytes_written += _write_all(copied, chunk)
                after = os.fstat(source.fileno())
                if _fingerprint(before) != _fingerprint(after):
                    raise ContractError("program binary changed while it was copied")
                if bytes_written != before.st_size:
                    raise ContractError("program custody copy has the wrong size")
                observed_sha256 = digest.hexdigest()
                if observed_sha256 != program.binary_sha256:
                    raise ContractError(
                        f"program binary hash mismatch for {source_path}: "
                        f"expected {program.binary_sha256}, got {observed_sha256}"
                    )
                copied.flush()
                os.fchmod(copied.fileno(), stat.S_IMODE(before.st_mode))
                os.fsync(copied.fileno())
                copied_status = os.fstat(copied.fileno())
                if copied_status.st_size != bytes_written:
                    raise ContractError("program custody copy has the wrong size")
                descriptor = os.open(
                    f"/proc/self/fd/{copied.fileno()}", os.O_RDONLY | os.O_CLOEXEC
                )
        _fsync_directory(destination.parent)
        return PreparedProgram(
            program, destination, _fingerprint(copied_status), descriptor
        )
    except (OSError, ContractError) as error:
        if descriptor is not None:
            os.close(descriptor)
        cleanup_errors: list[str] = []
        try:
            destination.unlink()
        except FileNotFoundError as cleanup_error:
            cleanup_errors.append(f"partial copy was already absent: {cleanup_error}")
        except OSError as cleanup_error:
            cleanup_errors.append(f"cannot remove partial copy: {cleanup_error}")
        try:
            _fsync_directory(destination.parent)
        except OSError as cleanup_error:
            cleanup_errors.append(
                f"cannot persist partial-copy cleanup: {cleanup_error}"
            )
        suffix = "" if not cleanup_errors else f"; {'; '.join(cleanup_errors)}"
        return FailedProgram(program, destination, f"{error}{suffix}")


def _prepare_programs(config: CellConfig, run_dir: Path) -> PreparedPrograms:
    candidate = _prepare_program(config.candidate, Role.CANDIDATE, run_dir)
    try:
        core = _prepare_program(config.core, Role.CORE, run_dir)
    except BaseException:
        if isinstance(candidate, PreparedProgram):
            os.close(candidate.descriptor)
        raise
    return PreparedPrograms(candidate=candidate, core=core)


def _verify_program_custody(custody: ProgramCustody) -> PreparedProgram:
    if isinstance(custody, FailedProgram):
        raise ContractError(custody.error)
    try:
        current_path = custody.path.stat()
        current_descriptor = os.fstat(custody.descriptor)
    except OSError as error:
        raise ContractError(
            f"cannot verify program custody {custody.path}: {error}"
        ) from error
    if (
        not stat.S_ISREG(current_path.st_mode)
        or _fingerprint(current_path) != custody.fingerprint
        or _fingerprint(current_descriptor) != custody.fingerprint
    ):
        raise ContractError("program custody changed during execution")
    return custody


def _close_programs(programs: PreparedPrograms) -> None:
    for custody in (programs.candidate, programs.core):
        if isinstance(custody, PreparedProgram):
            os.close(custody.descriptor)


def _load_json(path: Path, field: str) -> object:
    try:
        with path.open("r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ContractError(f"cannot read strict JSON for {field}: {error}") from error


def _cell_id_from_json(value: object, field: str) -> CellId:
    item = _object(
        value, field, frozenset({"domain", "corpus", "architecture", "backend"})
    )
    return CellId(
        Domain(_enum(Domain, item["domain"], f"{field}.domain").value),
        Corpus(_enum(Corpus, item["corpus"], f"{field}.corpus").value),
        Architecture(
            _enum(Architecture, item["architecture"], f"{field}.architecture").value
        ),
        Backend(_enum(Backend, item["backend"], f"{field}.backend").value),
    )


def _cell_id_json(cell: CellId) -> dict[str, str]:
    return {
        "domain": cell.domain.value,
        "corpus": cell.corpus.value,
        "architecture": cell.architecture.value,
        "backend": cell.backend.value,
    }


def _validate_command(
    command: object, field: str, adapter: AdapterKind
) -> tuple[str, ...]:
    values = _array(command, field)
    if not values:
        raise ContractError(f"{field} must contain at least one argv element")
    result = tuple(
        _text(value, f"{field}[{index}]") for index, value in enumerate(values)
    )
    allowed = ADAPTER_PLACEHOLDERS[adapter]
    seen: set[str] = set()
    formatter = string.Formatter()
    for index, argument in enumerate(result):
        try:
            pieces = tuple(formatter.parse(argument))
        except ValueError as error:
            raise ContractError(
                f"{field}[{index}] has malformed placeholders"
            ) from error
        for _literal, name, format_spec, conversion in pieces:
            if name is None:
                continue
            if name not in allowed or format_spec or conversion:
                raise ContractError(
                    f"{field}[{index}] contains unsafe placeholder {name!r}"
                )
            seen.add(name)
    if seen != set(allowed):
        raise ContractError(
            f"{field} must use exactly the {adapter.value} placeholders; "
            f"missing={sorted(allowed - seen)}"
        )
    return result


def expand_command(
    command: tuple[str, ...], paths: dict[str, str], adapter: AdapterKind
) -> tuple[str, ...]:
    allowed = ADAPTER_PLACEHOLDERS[adapter]
    if frozenset(paths) != allowed:
        raise ContractError(
            f"placeholder expansion for {adapter.value} requires {sorted(allowed)}"
        )
    validated = _validate_command(list(command), "command", adapter)
    return tuple(argument.format_map(paths) for argument in validated)


def _descriptor_path(descriptor: int) -> str:
    return f"/proc/self/fd/{descriptor}"


def _execution_command(
    program: ProgramIdentity,
    paths: dict[str, str],
    executable_path: str,
) -> tuple[str, ...]:
    expanded = expand_command(program.command, paths, program.adapter)
    if expanded[0] != program.binary_path:
        raise ContractError("program command must execute its bound binary_path")
    return (executable_path, *expanded[1:])


def _program_from_json(value: object, field: str) -> ProgramIdentity:
    item = _object(
        value,
        field,
        frozenset(
            {
                "adapter",
                "binary_path",
                "binary_sha256",
                "commit",
                "build",
                "features",
                "mimalloc",
                "command",
            }
        ),
    )
    adapter = AdapterKind(_enum(AdapterKind, item["adapter"], f"{field}.adapter").value)
    features_raw = _array(item["features"], f"{field}.features")
    features = tuple(
        _text(value, f"{field}.features[{index}]")
        for index, value in enumerate(features_raw)
    )
    if len(set(features)) != len(features):
        raise ContractError(f"{field}.features must be unique")
    return ProgramIdentity(
        adapter=adapter,
        binary_path=_text(item["binary_path"], f"{field}.binary_path"),
        binary_sha256=_hash(item["binary_sha256"], f"{field}.binary_sha256"),
        commit=_text(item["commit"], f"{field}.commit"),
        build=_text(item["build"], f"{field}.build"),
        features=features,
        mimalloc=_boolean(item["mimalloc"], f"{field}.mimalloc"),
        command=_validate_command(item["command"], f"{field}.command", adapter),
    )


def _program_json(program: ProgramIdentity) -> dict[str, object]:
    return {
        "adapter": program.adapter.value,
        "binary_path": program.binary_path,
        "binary_sha256": program.binary_sha256,
        "commit": program.commit,
        "build": program.build,
        "features": list(program.features),
        "mimalloc": program.mimalloc,
        "command": list(program.command),
    }


def _program_identity_sha256(program: ProgramIdentity) -> str:
    return _sha256_json(_program_json(program))


def _cell_config_from_json(value: object, field: str) -> CellConfig:
    item = _object(
        value,
        field,
        frozenset(
            {
                "cell",
                "blocked_reason",
                "candidate",
                "core",
                "corpus_path",
                "corpus_sha256",
                "manifest_path",
                "manifest_sha256",
                "proof_path",
                "proof_sha256",
                "affinity",
            }
        ),
    )
    reason = _optional_text(item["blocked_reason"], f"{field}.blocked_reason")
    affinity_raw = _array(item["affinity"], f"{field}.affinity")
    affinity = tuple(
        _uint(cpu, f"{field}.affinity[{index}]")
        for index, cpu in enumerate(affinity_raw)
    )
    if not affinity or len(set(affinity)) != len(affinity):
        raise ContractError(f"{field}.affinity must be nonempty and unique")
    cell = _cell_id_from_json(item["cell"], f"{field}.cell")
    candidate = _program_from_json(item["candidate"], f"{field}.candidate")
    core = _program_from_json(item["core"], f"{field}.core")
    if candidate.adapter is not AdapterKind.BITCOIN_RS_REPLAY:
        raise ContractError(f"{field}.candidate must use the bitcoin-rs replay adapter")
    if core.adapter is not AdapterKind.BITCOIN_CORE_LOADBLOCK:
        raise ContractError(f"{field}.core must use the Bitcoin Core adapter")
    corpus_path = str(
        _canonical_absolute_path(
            _text(item["corpus_path"], f"{field}.corpus_path"),
            f"{field}.corpus_path",
        )
    )
    manifest_path = str(
        _canonical_absolute_path(
            _text(item["manifest_path"], f"{field}.manifest_path"),
            f"{field}.manifest_path",
        )
    )
    proof_path_raw = _optional_text(item["proof_path"], f"{field}.proof_path")
    proof_sha256_raw = item["proof_sha256"]
    proof_path = (
        None
        if proof_path_raw is None
        else str(_canonical_absolute_path(proof_path_raw, f"{field}.proof_path"))
    )
    proof_sha256 = (
        None
        if proof_sha256_raw is None
        else _hash(proof_sha256_raw, f"{field}.proof_sha256")
    )
    if (proof_path is None) != (proof_sha256 is None):
        raise ContractError(
            f"{field} proof_path and proof_sha256 must be both set or null"
        )
    if reason is None and cell.domain is not Domain.OFFLINE:
        raise ContractError(
            f"{field} native adapters currently support only offline cells"
        )
    if reason is None and proof_path is None:
        raise ContractError(f"{field} ready offline cell requires a proof")
    return CellConfig(
        cell=cell,
        blocked_reason=reason,
        candidate=candidate,
        core=core,
        corpus_path=corpus_path,
        corpus_sha256=_hash(item["corpus_sha256"], f"{field}.corpus_sha256"),
        manifest_path=manifest_path,
        manifest_sha256=_hash(item["manifest_sha256"], f"{field}.manifest_sha256"),
        proof_path=proof_path,
        proof_sha256=proof_sha256,
        affinity=affinity,
    )


def _cell_config_json(config: CellConfig) -> dict[str, object]:
    return {
        "cell": _cell_id_json(config.cell),
        "blocked_reason": config.blocked_reason,
        "candidate": _program_json(config.candidate),
        "core": _program_json(config.core),
        "corpus_path": config.corpus_path,
        "corpus_sha256": config.corpus_sha256,
        "manifest_path": config.manifest_path,
        "manifest_sha256": config.manifest_sha256,
        "proof_path": config.proof_path,
        "proof_sha256": config.proof_sha256,
        "affinity": list(config.affinity),
    }


def parse_config(value: object) -> CampaignConfig:
    item = _object(
        value, "config", frozenset({"schema", "schedule_seed", "output_root", "cells"})
    )
    if _text(item["schema"], "config.schema") != CONFIG_SCHEMA:
        raise ContractError(f"config.schema must be {CONFIG_SCHEMA!r}")
    cells = tuple(
        _cell_config_from_json(cell, f"config.cells[{index}]")
        for index, cell in enumerate(_array(item["cells"], "config.cells"))
    )
    ids = tuple(cell.cell for cell in cells)
    if (
        len(cells) != 36
        or len(set(ids)) != 36
        or frozenset(ids) != frozenset(ALL_CELLS)
    ):
        raise ContractError(
            "config.cells must contain the exact 36-cell universe once each"
        )
    schedule_seed = _uint(item["schedule_seed"], "config.schedule_seed")
    output_root = str(
        _canonical_absolute_path(
            _text(item["output_root"], "config.output_root"),
            "config.output_root",
        )
    )
    canonical: dict[str, object] = {
        "schema": CONFIG_SCHEMA,
        "schedule_seed": schedule_seed,
        "output_root": output_root,
        "cells": [_cell_config_json(cell) for cell in cells],
    }
    return CampaignConfig(
        schedule_seed=schedule_seed,
        output_root=output_root,
        cells=cells,
        canonical_sha256=_sha256_json(canonical),
    )


def load_config(path: Path) -> CampaignConfig:
    return parse_config(_load_json(path, "config"))


def schedule_for(cell: CellId, seed: int) -> tuple[tuple[Role, Role], ...]:
    _uint(seed, "schedule_seed")
    parity = hashlib.sha256(f"{seed}:{cell.key}".encode("ascii")).digest()[0] & 1
    return tuple(
        (Role.CANDIDATE, Role.CORE)
        if (parity + index) % 2 == 0
        else (Role.CORE, Role.CANDIDATE)
        for index in range(PAIR_COUNT)
    )


def classify_wall_performance(
    candidate_walls: Sequence[int], core_walls: Sequence[int]
) -> tuple[int, int, float, Verdict]:
    if len(candidate_walls) != PAIR_COUNT or len(core_walls) != PAIR_COUNT:
        raise ContractError("wall performance requires exactly seven pairs")
    candidate_values = tuple(
        _uint(value, f"candidate_walls[{index}]", positive=True)
        for index, value in enumerate(candidate_walls)
    )
    core_values = tuple(
        _uint(value, f"core_walls[{index}]", positive=True)
        for index, value in enumerate(core_walls)
    )
    candidate_median = int(statistics.median(candidate_values))
    core_median = int(statistics.median(core_values))
    ratio = core_median / candidate_median
    verdict = Verdict.PASS if ratio >= PERFORMANCE_GATE else Verdict.FAIL_PERF
    return candidate_median, core_median, ratio, verdict


def _load_cell_proof(config: CellConfig, inputs: InputCustody) -> CellProof:
    if config.proof_path is None or config.proof_sha256 is None:
        raise ContractError("ready cell requires a cell proof")
    proof = parse_cell_proof(
        Path(_descriptor_path(inputs.proof.descriptor)),
        config.proof_sha256,
        ProofExpectation(
            cell_key=config.cell.key,
            corpus_sha256=config.corpus_sha256,
            corpus_bytes=inputs.corpus.fingerprint[3],
            manifest_sha256=config.manifest_sha256,
            manifest_bytes=inputs.manifest.fingerprint[3],
            affinity=config.affinity,
            candidate_program_sha256=_program_identity_sha256(config.candidate),
            core_program_sha256=_program_identity_sha256(config.core),
        ),
    )
    _verify_inputs_unchanged(inputs)
    return proof


def _verify_command_semantics(
    config: CellConfig,
    proof: CellProof,
    role: Role,
    command: tuple[str, ...],
    paths: dict[str, str],
) -> None:
    arguments = command[1:]
    if role is Role.CORE:
        options = dict(core_expectation(proof.state, arguments).expected_args)
        required = {
            "assumevalid": "0",
            "blocksxor": "0",
            "connect": "0",
            "datadir": paths["data_dir"],
            "debuglogfile": paths["result_path"],
            "disablewallet": "1",
            "dnsseed": "0",
            "fixedseeds": "0",
            "listen": "0",
            "loadblock": paths["corpus_path"],
            "server": "1",
            "stopatheight": str(proof.state.height),
        }
        if options != required:
            raise ContractError(
                "Core command must exactly match the offline proof contract"
            )
        return
    if len(arguments) % 2 != 0:
        raise ContractError("candidate command options must be flag/value pairs")
    options = dict(zip(arguments[::2], arguments[1::2], strict=True))
    if len(options) != len(arguments) // 2:
        raise ContractError("candidate command options must not repeat")
    required = {
        "--stop-height": str(proof.state.height),
        "--blocks-file": paths["corpus_path"],
        "--corpus-manifest": paths["manifest_path"],
        "--assume-valid-height": "0",
        "--storage-backend": config.cell.backend.value,
        "--data-dir": paths["data_dir"],
        "--output": paths["result_path"],
    }
    if options != required:
        raise ContractError(
            "candidate timed command must not include, omit, or alter offline proof options"
        )


def _parse_native_result(
    config: CellConfig,
    proof: CellProof,
    role: Role,
    command: tuple[str, ...],
    data_dir: Path,
    result_path: Path,
    inputs: InputCustody,
    paths: dict[str, str],
) -> NativeArmResult:
    program = config.candidate if role is Role.CANDIDATE else config.core
    if role is Role.CANDIDATE:
        if program.adapter is not AdapterKind.BITCOIN_RS_REPLAY:
            raise ContractError("candidate uses the wrong native adapter")
        return parse_candidate_file(
            result_path,
            CandidateExpectation(
                state=proof.state,
                data_dir=str(data_dir),
                corpus_path=paths["corpus_path"],
                corpus_sha256=config.corpus_sha256,
                corpus_bytes=inputs.corpus.fingerprint[3],
                manifest_path=paths["manifest_path"],
                manifest_sha256=config.manifest_sha256,
                manifest_bytes=inputs.manifest.fingerprint[3],
                backend=config.cell.backend.value,
                commit=program.commit,
            ),
        )
    if program.adapter is not AdapterKind.BITCOIN_CORE_LOADBLOCK:
        raise ContractError("Core uses the wrong native adapter")
    return parse_core_file(result_path, core_expectation(proof.state, command[1:]))


def _read_starttime(pid: int) -> int:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError) as error:
        raise ContractError(
            f"cannot bind child PID {pid} starttime: {error}"
        ) from error
    close = raw.rfind(")")
    if close < 0:
        raise ContractError(f"malformed /proc/{pid}/stat")
    fields = raw[close + 2 :].split()
    if len(fields) <= 19:
        raise ContractError(f"truncated /proc/{pid}/stat")
    return _uint(int(fields[19]), f"/proc/{pid}/stat starttime")


def _sample_rss(pid: int, starttime: int) -> int | None:
    if _read_starttime(pid) != starttime:
        raise ContractError(f"PID {pid} starttime changed during observation")
    try:
        lines = Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as error:
        raise ContractError(f"cannot sample child PID {pid} RSS: {error}") from error
    state: str | None = None
    for line in lines:
        if line.startswith("State:"):
            fields = line.split()
            if len(fields) < 2:
                raise ContractError(f"/proc/{pid}/status has malformed State")
            state = fields[1]
        elif line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) != 3 or fields[2] != "kB":
                raise ContractError(f"/proc/{pid}/status has malformed VmRSS")
            return _uint(int(fields[1]), f"/proc/{pid}/status VmRSS") * 1024
    if state is None:
        raise ContractError(f"/proc/{pid}/status has no valid State")
    # Linux can remove VmRSS before wait4 exposes the exit, even while State is R.
    return None


def _wait_and_measure(
    process: subprocess.Popen[bytes],
) -> tuple[int, int, int, int, int, int]:
    reaped = False
    try:
        starttime = _read_starttime(process.pid)
        peak_rss = 0
        while True:
            waited_pid, status, usage = os.wait4(process.pid, os.WNOHANG)
            if waited_pid == process.pid:
                reaped = True
                ended_ns = time.monotonic_ns()
                exit_code = os.waitstatus_to_exitcode(status)
                process.returncode = exit_code
                if peak_rss == 0:
                    raise ContractError(
                        f"child PID {process.pid} exited before RSS could be sampled"
                    )
                return (
                    starttime,
                    exit_code,
                    int(usage.ru_utime * 1_000_000_000),
                    int(usage.ru_stime * 1_000_000_000),
                    peak_rss,
                    ended_ns,
                )
            rss = _sample_rss(process.pid, starttime)
            if rss is None:
                continue
            peak_rss = max(peak_rss, rss)
            time.sleep(0.01)
    except BaseException as error:
        if not reaped:
            try:
                os.kill(process.pid, signal.SIGKILL)
            except ProcessLookupError as cleanup_error:
                error.add_note(f"child cleanup kill raced with exit: {cleanup_error}")
            try:
                _waited_pid, status, _usage = os.wait4(process.pid, 0)
                process.returncode = os.waitstatus_to_exitcode(status)
            except ChildProcessError as cleanup_error:
                error.add_note(
                    f"child cleanup found no waitable process: {cleanup_error}"
                )
        raise


def _run_arm(
    config: CellConfig,
    proof: CellProof,
    role: Role,
    pair_index: int,
    order_index: int,
    run_dir: Path,
    inputs: InputCustody,
    program_custody: ProgramCustody,
) -> ArmObservation:
    program = program_custody.identity
    arm_dir = run_dir / f"pair-{pair_index}-{order_index}-{role.value}"
    arm_dir.mkdir(mode=0o700)
    data_dir = arm_dir / "data"
    result_path = arm_dir / (
        "replay.json"
        if program.adapter is AdapterKind.BITCOIN_RS_REPLAY
        else "debug.log"
    )
    stdout_path = arm_dir / "stdout.log"
    stderr_path = arm_dir / "stderr.log"
    if data_dir.exists() or result_path.exists():
        raise ContractError("fresh arm paths unexpectedly already exist")
    data_dir.mkdir(mode=0o700)
    paths = {
        "data_dir": str(data_dir),
        "corpus_path": _descriptor_path(inputs.corpus.descriptor),
        "result_path": str(result_path),
    }
    inherited_descriptors = [inputs.corpus.descriptor]
    if program.adapter is AdapterKind.BITCOIN_RS_REPLAY:
        paths["manifest_path"] = _descriptor_path(inputs.manifest.descriptor)
        inherited_descriptors.append(inputs.manifest.descriptor)
    if isinstance(program_custody, PreparedProgram):
        executable_path = _descriptor_path(program_custody.descriptor)
        inherited_descriptors.append(program_custody.descriptor)
    else:
        executable_path = str(program_custody.path)
    command = _execution_command(program, paths, executable_path)
    _verify_command_semantics(config, proof, role, command, paths)
    pid: int | None = None
    pid_starttime: int | None = None
    wall_ns: int | None = None
    cpu_user_ns: int | None = None
    cpu_system_ns: int | None = None
    peak_rss_bytes: int | None = None
    exit_code: int | None = None
    arm_result: NativeArmResult | None = None
    error_text: str | None = None
    started: int | None = None
    try:
        _verify_inputs_unchanged(inputs)
        _verify_program_custody(program_custody)
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            previous_affinity = os.sched_getaffinity(0)
            os.sched_setaffinity(0, config.affinity)
            process: subprocess.Popen[bytes] | None = None
            try:
                effective_affinity = os.sched_getaffinity(0)
                if effective_affinity != set(config.affinity):
                    raise ContractError(
                        "CPU affinity not applied: "
                        f"configured {sorted(config.affinity)}, "
                        f"effective {sorted(effective_affinity)}"
                    )
                started = time.monotonic_ns()
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=stdout,
                    stderr=stderr,
                    shell=False,
                    close_fds=True,
                    pass_fds=tuple(inherited_descriptors),
                    env=_FIXED_CHILD_ENV,
                )
            finally:
                try:
                    os.sched_setaffinity(0, previous_affinity)
                except OSError as restore_error:
                    if process is not None:
                        process.kill()
                        process.wait()
                    raise ContractError(
                        "cannot restore runner CPU affinity"
                    ) from restore_error
            if process is None:
                raise AssertionError("native process did not start")
            pid = process.pid
            (
                pid_starttime,
                exit_code,
                cpu_user_ns,
                cpu_system_ns,
                peak_rss_bytes,
                ended_ns,
            ) = _wait_and_measure(process)
            wall_ns = ended_ns - started
            _verify_program_custody(program_custody)
            _verify_inputs_unchanged(inputs)
            stdout.flush()
            os.fsync(stdout.fileno())
            stderr.flush()
            os.fsync(stderr.fileno())
        if exit_code != 0:
            error_text = f"native process exited with status {exit_code}"
        elif not result_path.is_file():
            error_text = "native process did not create its evidence file"
        else:
            _fsync_file(result_path)
            arm_result = _parse_native_result(
                config, proof, role, command, data_dir, result_path, inputs, paths
            )
    except (OSError, ContractError, subprocess.SubprocessError) as error:
        if started is not None and wall_ns is None:
            wall_ns = time.monotonic_ns() - started
        error_text = str(error)
    try:
        _persist_arm_evidence(arm_dir, (stdout_path, stderr_path, result_path))
    except OSError as evidence_error:
        message = f"cannot persist arm evidence: {evidence_error}"
        error_text = message if error_text is None else f"{error_text}; {message}"
    return ArmObservation(
        role=role,
        pair_index=pair_index,
        order_index=order_index,
        command=command,
        arm_dir=str(arm_dir),
        data_dir=str(data_dir),
        result_path=str(result_path),
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        pid=pid,
        pid_starttime=pid_starttime,
        wall_ns=wall_ns,
        cpu_user_ns=cpu_user_ns,
        cpu_system_ns=cpu_system_ns,
        peak_rss_bytes=peak_rss_bytes,
        exit_code=exit_code,
        arm_result=arm_result,
        error=error_text,
    )


def _derive(
    config_sha256: str,
    config: CellConfig,
    proof: CellProof,
    seed: int,
    pairs: tuple[PairResult, ...],
) -> CellResult:
    scheduled = len(pairs)
    valid_pairs = sum(pair.valid for pair in pairs)
    candidate_median: int | None = None
    core_median: int | None = None
    ratio: float | None = None
    performance_verdict: Verdict | None = None
    environment_invalid = any(
        arm.arm_result is not None and not arm.arm_result.environment_valid
        for pair in pairs
        for arm in (pair.candidate, pair.core)
    )
    run_failed = any(
        not arm.run_valid for pair in pairs for arm in (pair.candidate, pair.core)
    )
    correctness_failed = any(pair.correctness_match is False for pair in pairs)
    timed = scheduled == PAIR_COUNT and valid_pairs == PAIR_COUNT
    if timed:
        candidate_walls = [pair.candidate.wall_ns for pair in pairs]
        core_walls = [pair.core.wall_ns for pair in pairs]
        if any(value is None or value <= 0 for value in candidate_walls + core_walls):
            raise ContractError("timed pairs require positive wall measurements")
        candidate_median, core_median, ratio, performance_verdict = (
            classify_wall_performance(
                [value for value in candidate_walls if value is not None],
                [value for value in core_walls if value is not None],
            )
        )
    if correctness_failed:
        verdict = Verdict.FAIL_CORRECTNESS
    elif environment_invalid:
        verdict = Verdict.INVALID_ENV
    elif run_failed or scheduled != PAIR_COUNT:
        verdict = Verdict.FAIL_RUN
    elif performance_verdict is not None:
        verdict = performance_verdict
    else:
        verdict = Verdict.FAIL_RUN
    return CellResult(
        config_sha256=config_sha256,
        cell_config=config,
        proof_sha256=proof.sha256,
        proof_scope=proof.scope,
        certified_state=proof.state,
        schedule_seed=seed,
        pairs=pairs,
        scheduled_pairs=scheduled,
        valid_pairs=valid_pairs,
        candidate_median_wall_ns=candidate_median,
        core_median_wall_ns=core_median,
        wall_ratio=ratio,
        verdict=verdict,
    )


def _make_pair(
    pair_index: int,
    order: tuple[Role, Role],
    observations: tuple[ArmObservation, ArmObservation],
) -> PairResult:
    by_role = {observation.role: observation for observation in observations}
    if frozenset(by_role) != frozenset(Role) or len(by_role) != 2:
        raise ContractError(
            f"pair {pair_index} must contain one candidate and one Core arm"
        )
    candidate = by_role[Role.CANDIDATE]
    core = by_role[Role.CORE]
    valid = candidate.run_valid and core.run_valid
    correctness: bool | None = None
    if valid:
        candidate_result = candidate.arm_result
        core_result = core.arm_result
        if candidate_result is None or core_result is None:
            raise AssertionError("valid pair must contain both native arm results")
        correctness = (
            candidate_result.correctness_ok
            and core_result.correctness_ok
            and candidate_result.height == core_result.height
            and candidate_result.bestblock == core_result.bestblock
        )
    return PairResult(pair_index, order, candidate, core, valid, correctness)


def _host_architecture() -> Architecture:
    machine = platform.machine().casefold()
    try:
        return _HOST_ARCH_ALIASES[machine]
    except KeyError:
        raise ContractError(
            f"host architecture {machine!r} is not supported by the campaign runner"
        ) from None


def run_cell(campaign: CampaignConfig, cell: CellId) -> tuple[CellResult, Path]:
    matches = tuple(config for config in campaign.cells if config.cell == cell)
    if len(matches) != 1:
        raise ContractError(f"cell {cell.key} is not configured exactly once")
    config = matches[0]
    if not config.ready:
        raise ContractError(f"cell {cell.key} is blocked: {config.blocked_reason}")
    host_arch = _host_architecture()
    if host_arch is not cell.architecture:
        raise ContractError(
            f"cell {cell.key} requires {cell.architecture.value} "
            f"but host is {host_arch.value}"
        )
    inputs = _snapshot_inputs(config)
    programs: PreparedPrograms | None = None
    try:
        proof = _load_cell_proof(config, inputs)
        root = Path(campaign.output_root)
        _mkdir_durable(root)
        run_dir = Path(
            tempfile.mkdtemp(prefix=f"{cell.key.replace('/', '-')}-", dir=root)
        )
        _fsync_directory(root)
        programs = _prepare_programs(config, run_dir)
        schedule = schedule_for(cell, campaign.schedule_seed)
        pairs: list[PairResult] = []
        seen_paths: set[str] = set()
        for pair_index, order in enumerate(schedule):
            observations: tuple[ArmObservation, ArmObservation] = (
                _run_arm(
                    config,
                    proof,
                    order[0],
                    pair_index,
                    0,
                    run_dir,
                    inputs,
                    programs.candidate if order[0] is Role.CANDIDATE else programs.core,
                ),
                _run_arm(
                    config,
                    proof,
                    order[1],
                    pair_index,
                    1,
                    run_dir,
                    inputs,
                    programs.candidate if order[1] is Role.CANDIDATE else programs.core,
                ),
            )
            for observation in observations:
                paths = {
                    observation.arm_dir,
                    observation.data_dir,
                    observation.result_path,
                    observation.stdout_path,
                    observation.stderr_path,
                }
                if seen_paths & paths or len(paths) != 5:
                    raise ContractError("arm paths must be unique and never reused")
                seen_paths.update(paths)
            pairs.append(_make_pair(pair_index, order, observations))
        result = _derive(
            campaign.canonical_sha256,
            config,
            proof,
            campaign.schedule_seed,
            tuple(pairs),
        )
        result_path = run_dir / "custody-result.json"
        _atomic_write_json(result_path, _result_json(result))
        return result, result_path
    finally:
        if programs is not None:
            _close_programs(programs)
        _close_inputs(inputs)


def _arm_json(arm: ArmObservation) -> dict[str, object]:
    return {
        "role": arm.role.value,
        "pair_index": arm.pair_index,
        "order_index": arm.order_index,
        "command": list(arm.command),
        "arm_dir": arm.arm_dir,
        "data_dir": arm.data_dir,
        "result_path": arm.result_path,
        "stdout_path": arm.stdout_path,
        "stderr_path": arm.stderr_path,
        "pid": arm.pid,
        "pid_starttime": arm.pid_starttime,
        "wall_ns": arm.wall_ns,
        "cpu_user_ns": arm.cpu_user_ns,
        "cpu_system_ns": arm.cpu_system_ns,
        "peak_rss_bytes": arm.peak_rss_bytes,
        "exit_code": arm.exit_code,
        "arm_result": (
            None if arm.arm_result is None else arm_result_json(arm.arm_result)
        ),
        "error": arm.error,
    }


def _pair_json(pair: PairResult) -> dict[str, object]:
    return {
        "pair_index": pair.pair_index,
        "order": [role.value for role in pair.order],
        "candidate": _arm_json(pair.candidate),
        "core": _arm_json(pair.core),
        "valid": pair.valid,
        "correctness_match": pair.correctness_match,
    }


def _result_json(result: CellResult) -> dict[str, object]:
    return {
        "schema": RESULT_SCHEMA,
        "config_sha256": result.config_sha256,
        "cell_config": _cell_config_json(result.cell_config),
        "proof_sha256": result.proof_sha256,
        "proof_scope": result.proof_scope,
        "certified_state": state_json(result.certified_state),
        "schedule_seed": result.schedule_seed,
        "pairs": [_pair_json(pair) for pair in result.pairs],
        "scheduled_pairs": result.scheduled_pairs,
        "valid_pairs": result.valid_pairs,
        "candidate_median_wall_ns": result.candidate_median_wall_ns,
        "core_median_wall_ns": result.core_median_wall_ns,
        "wall_ratio": result.wall_ratio,
        "verdict": result.verdict.value,
    }


def _arm_from_json(value: object, field: str) -> ArmObservation:
    item = _object(
        value,
        field,
        frozenset(
            {
                "role",
                "pair_index",
                "order_index",
                "command",
                "arm_dir",
                "data_dir",
                "result_path",
                "stdout_path",
                "stderr_path",
                "pid",
                "pid_starttime",
                "wall_ns",
                "cpu_user_ns",
                "cpu_system_ns",
                "peak_rss_bytes",
                "exit_code",
                "arm_result",
                "error",
            }
        ),
    )
    command = tuple(
        _text(arg, f"{field}.command[{index}]")
        for index, arg in enumerate(_array(item["command"], f"{field}.command"))
    )
    if not command:
        raise ContractError(f"{field}.command must be nonempty")
    exit_code_value = item["exit_code"]
    exit_code = None
    if exit_code_value is not None:
        if isinstance(exit_code_value, bool) or not isinstance(exit_code_value, int):
            raise ContractError(f"{field}.exit_code must be an integer or null")
        exit_code = exit_code_value
    return ArmObservation(
        role=Role(_enum(Role, item["role"], f"{field}.role").value),
        pair_index=_uint(item["pair_index"], f"{field}.pair_index"),
        order_index=_uint(item["order_index"], f"{field}.order_index"),
        command=command,
        arm_dir=_text(item["arm_dir"], f"{field}.arm_dir"),
        data_dir=_text(item["data_dir"], f"{field}.data_dir"),
        result_path=_text(item["result_path"], f"{field}.result_path"),
        stdout_path=_text(item["stdout_path"], f"{field}.stdout_path"),
        stderr_path=_text(item["stderr_path"], f"{field}.stderr_path"),
        pid=_optional_uint(item["pid"], f"{field}.pid"),
        pid_starttime=_optional_uint(item["pid_starttime"], f"{field}.pid_starttime"),
        wall_ns=_optional_uint(item["wall_ns"], f"{field}.wall_ns"),
        cpu_user_ns=_optional_uint(item["cpu_user_ns"], f"{field}.cpu_user_ns"),
        cpu_system_ns=_optional_uint(item["cpu_system_ns"], f"{field}.cpu_system_ns"),
        peak_rss_bytes=_optional_uint(
            item["peak_rss_bytes"], f"{field}.peak_rss_bytes"
        ),
        exit_code=exit_code,
        arm_result=(
            None
            if item["arm_result"] is None
            else arm_result_from_json(item["arm_result"], f"{field}.arm_result")
        ),
        error=_optional_text(item["error"], f"{field}.error"),
    )


def _verify_recorded_evidence(
    observation: ArmObservation,
    config: CellConfig,
    proof: CellProof,
    inputs: InputCustody,
    paths: dict[str, str],
) -> None:
    if observation.arm_result is None:
        return
    for descriptor in (
        inputs.corpus.descriptor,
        inputs.manifest.descriptor,
        inputs.proof.descriptor,
    ):
        os.fstat(descriptor)
    observed = _parse_native_result(
        config,
        proof,
        observation.role,
        observation.command,
        Path(observation.data_dir),
        Path(observation.result_path),
        inputs,
        paths,
    )
    if observed != observation.arm_result:
        raise ContractError("recorded arm result does not match native evidence bytes")


def _canonical_recorded_path(value: str, field: str) -> Path:
    return _canonical_absolute_path(value, field)


def _recorded_descriptor_path(value: object, field: str) -> str:
    path = _text(value, field)
    match = _FD_PATH_RE.fullmatch(path)
    if match is None or int(match.group(1)) < 3:
        raise ContractError(f"{field} must be a historical inherited descriptor path")
    return path


def _recorded_command_paths(
    observation: ArmObservation, program: ProgramIdentity, proof: CellProof
) -> dict[str, str]:
    arguments = observation.command[1:]
    paths = {
        "data_dir": observation.data_dir,
        "result_path": observation.result_path,
    }
    if program.adapter is AdapterKind.BITCOIN_RS_REPLAY:
        if len(arguments) % 2 != 0:
            raise ContractError("recorded candidate command has incomplete options")
        options = dict(zip(arguments[::2], arguments[1::2], strict=True))
        paths["corpus_path"] = _recorded_descriptor_path(
            options.get("--blocks-file"), "recorded candidate corpus path"
        )
        paths["manifest_path"] = _recorded_descriptor_path(
            options.get("--corpus-manifest"), "recorded candidate manifest path"
        )
    else:
        options = dict(core_expectation(proof.state, arguments).expected_args)
        paths["corpus_path"] = _recorded_descriptor_path(
            options.get("loadblock"), "recorded Core corpus path"
        )
    descriptor_paths = [paths["corpus_path"]]
    if "manifest_path" in paths:
        descriptor_paths.append(paths["manifest_path"])
    if len(set(descriptor_paths)) != len(descriptor_paths):
        raise ContractError("recorded input descriptors must be distinct")
    return paths


def parse_result(value: object) -> CellResult:
    item = _object(
        value,
        "result",
        frozenset(
            {
                "schema",
                "config_sha256",
                "cell_config",
                "proof_sha256",
                "proof_scope",
                "certified_state",
                "schedule_seed",
                "pairs",
                "scheduled_pairs",
                "valid_pairs",
                "candidate_median_wall_ns",
                "core_median_wall_ns",
                "wall_ratio",
                "verdict",
            }
        ),
    )
    if _text(item["schema"], "result.schema") != RESULT_SCHEMA:
        raise ContractError(f"result.schema must be {RESULT_SCHEMA!r}")
    config = _cell_config_from_json(item["cell_config"], "result.cell_config")
    inputs = _snapshot_inputs(config)
    try:
        return _parse_result_with_inputs(item, config, inputs)
    finally:
        _close_inputs(inputs)


def _parse_result_with_inputs(
    item: dict[str, object], config: CellConfig, inputs: InputCustody
) -> CellResult:
    proof = _load_cell_proof(config, inputs)
    if _hash(item["proof_sha256"], "result.proof_sha256") != proof.sha256:
        raise ContractError("result proof hash was tampered")
    if _text(item["proof_scope"], "result.proof_scope") != PROOF_SCOPE:
        raise ContractError("result proof scope was tampered")
    if (
        state_from_json(item["certified_state"], "result.certified_state")
        != proof.state
    ):
        raise ContractError("result certified state was tampered")
    seed = _uint(item["schedule_seed"], "result.schedule_seed")
    pair_values = _array(item["pairs"], "result.pairs")
    if len(pair_values) != PAIR_COUNT:
        raise ContractError("result.pairs must contain exactly seven scheduled pairs")
    expected_schedule = schedule_for(config.cell, seed)
    parsed_pairs: list[PairResult] = []
    all_paths: set[Path] = set()
    run_dir: Path | None = None
    role_executable_descriptors: dict[Role, str] = {}
    for index, value_pair in enumerate(pair_values):
        pair = _object(
            value_pair,
            f"result.pairs[{index}]",
            frozenset(
                {
                    "pair_index",
                    "order",
                    "candidate",
                    "core",
                    "valid",
                    "correctness_match",
                }
            ),
        )
        if _uint(pair["pair_index"], f"result.pairs[{index}].pair_index") != index:
            raise ContractError("pair indexes must be contiguous and ordered")
        order_values = _array(pair["order"], f"result.pairs[{index}].order")
        if len(order_values) != 2:
            raise ContractError("pair order must contain exactly two roles")
        order = (
            Role(_enum(Role, order_values[0], f"result.pairs[{index}].order[0]").value),
            Role(_enum(Role, order_values[1], f"result.pairs[{index}].order[1]").value),
        )
        if order != expected_schedule[index]:
            raise ContractError(
                f"result.pairs[{index}].order does not match deterministic schedule"
            )
        candidate = _arm_from_json(
            pair["candidate"], f"result.pairs[{index}].candidate"
        )
        core = _arm_from_json(pair["core"], f"result.pairs[{index}].core")
        observations = (candidate, core)
        for observation in observations:
            expected_order = order.index(observation.role)
            if (
                observation.pair_index != index
                or observation.order_index != expected_order
            ):
                raise ContractError(
                    f"result.pairs[{index}] arm indexes do not match schedule"
                )
            field = f"result.pairs[{index}].{observation.role.value}"
            arm_dir = _canonical_recorded_path(observation.arm_dir, f"{field}.arm_dir")
            if run_dir is None:
                run_dir = arm_dir.parent
            expected_arm_dir = run_dir / (
                f"pair-{index}-{expected_order}-{observation.role.value}"
            )
            if arm_dir != expected_arm_dir:
                raise ContractError(f"{field}.arm_dir is outside the campaign run")
            paths = {
                arm_dir,
                _canonical_recorded_path(observation.data_dir, f"{field}.data_dir"),
                _canonical_recorded_path(
                    observation.result_path, f"{field}.result_path"
                ),
                _canonical_recorded_path(
                    observation.stdout_path, f"{field}.stdout_path"
                ),
                _canonical_recorded_path(
                    observation.stderr_path, f"{field}.stderr_path"
                ),
            }
            expected_program = (
                config.candidate if observation.role is Role.CANDIDATE else config.core
            )
            expected_result_name = (
                "replay.json"
                if expected_program.adapter is AdapterKind.BITCOIN_RS_REPLAY
                else "debug.log"
            )
            expected_paths = {
                arm_dir,
                arm_dir / "data",
                arm_dir / expected_result_name,
                arm_dir / "stdout.log",
                arm_dir / "stderr.log",
            }
            if paths != expected_paths:
                raise ContractError(f"{field} artifacts are outside arm_dir")
            if all_paths & paths:
                raise ContractError("result reuses an arm path")
            all_paths.update(paths)
            executable_path = _custody_program_path(
                run_dir, observation.role, expected_program
            )
            command_paths = _recorded_command_paths(
                observation, expected_program, proof
            )
            program_preparation_failed = (
                observation.error is not None
                and observation.pid is None
                and observation.pid_starttime is None
                and observation.wall_ns is None
                and observation.cpu_user_ns is None
                and observation.cpu_system_ns is None
                and observation.peak_rss_bytes is None
                and observation.exit_code is None
                and observation.arm_result is None
                and observation.command[0] == str(executable_path)
            )
            if observation.command[0] == str(executable_path):
                if not program_preparation_failed:
                    raise ContractError(
                        f"{field}.command[0] uses unpinned program custody"
                    )
                recorded_executable = str(executable_path)
            else:
                recorded_executable = _recorded_descriptor_path(
                    observation.command[0], f"{field}.command[0]"
                )
                prior_descriptor = role_executable_descriptors.setdefault(
                    observation.role, recorded_executable
                )
                if prior_descriptor != recorded_executable:
                    raise ContractError(
                        f"recorded {observation.role.value} executable descriptor changed"
                    )
                if any(
                    role is not observation.role and descriptor == recorded_executable
                    for role, descriptor in role_executable_descriptors.items()
                ):
                    raise ContractError(
                        "candidate and Core executable descriptors must be distinct"
                    )
            if recorded_executable in {
                command_paths["corpus_path"],
                command_paths.get("manifest_path"),
            }:
                raise ContractError(
                    f"{field}.command reuses its executable descriptor as input"
                )
            expanded = _execution_command(
                expected_program, command_paths, recorded_executable
            )
            if observation.command != expanded:
                raise ContractError(
                    "recorded command does not match bound identity and paths"
                )
            _verify_command_semantics(
                config, proof, observation.role, expanded, command_paths
            )
            _verify_recorded_evidence(observation, config, proof, inputs, command_paths)
        derived_pair = _make_pair(index, order, observations)
        if (
            _boolean(pair["valid"], f"result.pairs[{index}].valid")
            != derived_pair.valid
        ):
            raise ContractError(f"result.pairs[{index}].valid was tampered")
        recorded_correctness = pair["correctness_match"]
        if recorded_correctness is not None:
            recorded_correctness = _boolean(
                recorded_correctness, f"result.pairs[{index}].correctness_match"
            )
        if recorded_correctness != derived_pair.correctness_match:
            raise ContractError(f"result.pairs[{index}].correctness_match was tampered")
        parsed_pairs.append(derived_pair)
    if run_dir is None:
        raise ContractError("result has no campaign run directory")
    for role, program in (
        (Role.CANDIDATE, config.candidate),
        (Role.CORE, config.core),
    ):
        executable_path = _custody_program_path(run_dir, role, program)
        role_arms = [
            pair.candidate if role is Role.CANDIDATE else pair.core
            for pair in parsed_pairs
        ]
        if executable_path.is_file():
            custody = _snapshot_file(
                str(executable_path),
                program.binary_sha256,
                f"result program custody {role.value}",
            )
            os.close(custody.descriptor)
            continue
        preparation_failed = all(
            arm.error is not None
            and arm.pid is None
            and arm.pid_starttime is None
            and arm.wall_ns is None
            and arm.cpu_user_ns is None
            and arm.cpu_system_ns is None
            and arm.peak_rss_bytes is None
            and arm.exit_code is None
            and arm.arm_result is None
            for arm in role_arms
        )
        if not preparation_failed:
            raise ContractError(f"result program custody {role.value} is missing")
    derived = _derive(
        _hash(item["config_sha256"], "result.config_sha256"),
        config,
        proof,
        seed,
        tuple(parsed_pairs),
    )
    if (
        _uint(item["scheduled_pairs"], "result.scheduled_pairs")
        != derived.scheduled_pairs
    ):
        raise ContractError("result.scheduled_pairs was tampered")
    if _uint(item["valid_pairs"], "result.valid_pairs") != derived.valid_pairs:
        raise ContractError("result.valid_pairs was tampered")
    if (
        _optional_uint(
            item["candidate_median_wall_ns"], "result.candidate_median_wall_ns"
        )
        != derived.candidate_median_wall_ns
    ):
        raise ContractError("result.candidate_median_wall_ns was tampered")
    if (
        _optional_uint(item["core_median_wall_ns"], "result.core_median_wall_ns")
        != derived.core_median_wall_ns
    ):
        raise ContractError("result.core_median_wall_ns was tampered")
    recorded_ratio = (
        None
        if item["wall_ratio"] is None
        else _finite_number(item["wall_ratio"], "result.wall_ratio")
    )
    if recorded_ratio != derived.wall_ratio:
        raise ContractError("result.wall_ratio was tampered")
    if (
        Verdict(_enum(Verdict, item["verdict"], "result.verdict").value)
        is not derived.verdict
    ):
        raise ContractError("result.verdict was tampered")
    return derived


def validate_result(path: Path, config_path: Path) -> CellResult:
    campaign = load_config(config_path)
    result_path = _canonical_absolute_path(str(path), "result path")
    output_root = Path(campaign.output_root)
    if (
        result_path.name != "custody-result.json"
        or result_path.parent.parent != output_root
    ):
        raise ContractError("result path must be output_root/<run>/custody-result.json")
    result = parse_result(_load_json(result_path, "result"))
    if campaign.canonical_sha256 != result.config_sha256:
        raise ContractError("result config hash does not match supplied config")
    if campaign.schedule_seed != result.schedule_seed:
        raise ContractError("result schedule seed does not match supplied config")
    matches = [cell for cell in campaign.cells if cell.cell == result.cell_config.cell]
    if len(matches) != 1 or matches[0] != result.cell_config:
        raise ContractError("result cell identity does not match supplied config")
    recorded_run_dir = Path(result.pairs[0].candidate.arm_dir).parent
    if result_path.parent != recorded_run_dir:
        raise ContractError("result path does not match its recorded campaign run")
    return result


def _atomic_write_json(path: Path, value: object) -> None:
    _mkdir_durable(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_json_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _parse_cell_key(value: str) -> CellId:
    parts = value.split("/")
    if len(parts) != 4:
        raise ContractError("cell must be domain/corpus/architecture/backend")
    return CellId(
        Domain(parts[0]), Corpus(parts[1]), Architecture(parts[2]), Backend(parts[3])
    )


def _plan(config: CampaignConfig) -> dict[str, object]:
    by_id = {cell.cell: cell for cell in config.cells}
    return {
        "schema": "benchmark-campaign-plan-v1",
        "config_sha256": config.canonical_sha256,
        "cells": [
            {
                "cell": _cell_id_json(cell),
                "ready": by_id[cell].ready,
                "blocked_reason": by_id[cell].blocked_reason,
            }
            for cell in ALL_CELLS
        ],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    plan = subparsers.add_parser(
        "plan", help="emit readiness for all 36 configured cells"
    )
    plan.add_argument(
        "--config", type=Path, required=True, help="strict campaign config JSON"
    )
    run = subparsers.add_parser("run", help="run one ready cell as exactly seven pairs")
    run.add_argument(
        "--config", type=Path, required=True, help="strict campaign config JSON"
    )
    run.add_argument("--cell", required=True, help="domain/corpus/architecture/backend")
    validate = subparsers.add_parser(
        "validate", help="strictly reparse and recompute a custody result"
    )
    validate.add_argument(
        "--result", type=Path, required=True, help="custody result JSON"
    )
    validate.add_argument(
        "--config",
        type=Path,
        required=True,
        help="original config for identity binding",
    )
    return parser


def _die(message: str) -> NoReturn:
    print(f"error: {message}", file=sys.stderr)
    raise SystemExit(2)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.operation == "plan":
            print(json.dumps(_plan(load_config(arguments.config)), sort_keys=True))
            return 0
        if arguments.operation == "run":
            result, path = run_cell(
                load_config(arguments.config), _parse_cell_key(arguments.cell)
            )
            print(
                json.dumps(
                    {"result": str(path), "verdict": result.verdict.value},
                    sort_keys=True,
                )
            )
            return 0
        result = validate_result(arguments.result, arguments.config)
        print(
            json.dumps(
                {"cell": result.cell_config.cell.key, "verdict": result.verdict.value},
                sort_keys=True,
            )
        )
        return 0
    except (ContractError, ValueError) as error:
        _die(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
