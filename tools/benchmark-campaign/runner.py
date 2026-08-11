#!/usr/bin/env python3
# pyright: strict
"""Strict, generic exact-seven-pair benchmark campaign runner."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
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

CONFIG_SCHEMA = "benchmark-campaign-config-v1"
RESULT_SCHEMA = "benchmark-campaign-result-v1"
CHILD_SCHEMA = "benchmark-campaign-child-v1"
PAIR_COUNT = 7
ARM_COUNT = PAIR_COUNT * 2
PERFORMANCE_GATE = 2.0
_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_ALLOWED_PLACEHOLDERS = frozenset({"arm_dir", "data_dir", "result_path"})


class ContractError(ValueError):
    """Untrusted campaign data violates the executable contract."""


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
    binary_path: str
    binary_sha256: str
    commit: str
    build: str
    features: tuple[str, ...]
    mimalloc: bool
    command: tuple[str, ...]
    exposes_full_validation_witness: bool
    consensus_proof_hash: str


@dataclass(frozen=True)
class PreparedProgram:
    identity: ProgramIdentity
    path: Path
    fingerprint: tuple[int, int, int, int, int, int]


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


@dataclass(frozen=True)
class InputCustody:
    corpus: FileCustody
    manifest: FileCustody


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
class ChildResult:
    role: Role
    height: int
    bestblock: str
    txouts: int
    total_amount_sat: int
    muhash: str
    full_validation_witness: int
    consensus_proof_hash: str
    durability_ok: bool | None
    source_capacity_ok: bool | None
    environment_valid: bool
    environment_reason: str | None


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
    child_result: ChildResult | None
    child_result_raw: object | None
    error: str | None

    @property
    def run_valid(self) -> bool:
        return (
            self.error is None and self.exit_code == 0 and self.child_result is not None
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


def _optional_bool(value: object, field: str) -> bool | None:
    return None if value is None else _boolean(value, field)


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
        with path.open("rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ContractError(f"{field} must be a regular file")
            observed_sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
            after = os.fstat(stream.fileno())
    except OSError as error:
        raise ContractError(f"cannot hash {field} {path}: {error}") from error
    if _fingerprint(before) != _fingerprint(after):
        raise ContractError(f"{field} changed while it was hashed")
    if observed_sha256 != expected_sha256:
        raise ContractError(
            f"{field} hash mismatch for {path}: "
            f"expected {expected_sha256}, got {observed_sha256}"
        )
    return FileCustody(path, _fingerprint(after))


def _snapshot_inputs(config: CellConfig) -> InputCustody:
    return InputCustody(
        corpus=_snapshot_file(config.corpus_path, config.corpus_sha256, "corpus_path"),
        manifest=_snapshot_file(
            config.manifest_path, config.manifest_sha256, "manifest_path"
        ),
    )


def _verify_file_unchanged(custody: FileCustody, field: str) -> None:
    try:
        current = custody.path.stat()
    except OSError as error:
        raise ContractError(f"cannot stat {field} {custody.path}: {error}") from error
    if (
        not stat.S_ISREG(current.st_mode)
        or _fingerprint(current) != custody.fingerprint
    ):
        raise ContractError(f"{field} changed during campaign execution")


def _verify_inputs_unchanged(custody: InputCustody) -> None:
    _verify_file_unchanged(custody.corpus, "corpus_path")
    _verify_file_unchanged(custody.manifest, "manifest_path")


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
        _fsync_directory(destination.parent)
        return PreparedProgram(program, destination, _fingerprint(copied_status))
    except (OSError, ContractError) as error:
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
    return PreparedPrograms(
        candidate=_prepare_program(config.candidate, Role.CANDIDATE, run_dir),
        core=_prepare_program(config.core, Role.CORE, run_dir),
    )


def _verify_program_custody(custody: ProgramCustody) -> PreparedProgram:
    if isinstance(custody, FailedProgram):
        raise ContractError(custody.error)
    try:
        current = custody.path.stat()
    except OSError as error:
        raise ContractError(
            f"cannot stat program custody {custody.path}: {error}"
        ) from error
    if (
        not stat.S_ISREG(current.st_mode)
        or _fingerprint(current) != custody.fingerprint
    ):
        raise ContractError("program custody changed during execution")
    return custody


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


def _validate_command(command: object, field: str) -> tuple[str, ...]:
    values = _array(command, field)
    if not values:
        raise ContractError(f"{field} must contain at least one argv element")
    result = tuple(
        _text(value, f"{field}[{index}]") for index, value in enumerate(values)
    )
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
            if name not in _ALLOWED_PLACEHOLDERS or format_spec or conversion:
                raise ContractError(
                    f"{field}[{index}] contains unsafe placeholder {name!r}"
                )
    return result


def expand_command(command: tuple[str, ...], paths: dict[str, str]) -> tuple[str, ...]:
    if frozenset(paths) != _ALLOWED_PLACEHOLDERS:
        raise ContractError(
            "placeholder expansion requires exactly arm_dir, data_dir, and result_path"
        )
    validated = _validate_command(list(command), "command")
    return tuple(argument.format_map(paths) for argument in validated)


def _execution_command(
    program: ProgramIdentity,
    affinity: tuple[int, ...],
    paths: dict[str, str],
    executable_path: Path,
) -> tuple[str, ...]:
    expanded = expand_command(program.command, paths)
    if expanded[0] != program.binary_path:
        raise ContractError("program command must execute its bound binary_path")
    taskset = shutil.which("taskset")
    if taskset is None:
        raise ContractError("taskset is required to bind child CPU affinity")
    return (
        taskset,
        "--cpu-list",
        ",".join(str(cpu) for cpu in affinity),
        str(executable_path),
        *expanded[1:],
    )


def _program_from_json(value: object, field: str) -> ProgramIdentity:
    item = _object(
        value,
        field,
        frozenset(
            {
                "binary_path",
                "binary_sha256",
                "commit",
                "build",
                "features",
                "mimalloc",
                "command",
                "exposes_full_validation_witness",
                "consensus_proof_hash",
            }
        ),
    )
    features_raw = _array(item["features"], f"{field}.features")
    features = tuple(
        _text(value, f"{field}.features[{index}]")
        for index, value in enumerate(features_raw)
    )
    if len(set(features)) != len(features):
        raise ContractError(f"{field}.features must be unique")
    return ProgramIdentity(
        binary_path=_text(item["binary_path"], f"{field}.binary_path"),
        binary_sha256=_hash(item["binary_sha256"], f"{field}.binary_sha256"),
        commit=_text(item["commit"], f"{field}.commit"),
        build=_text(item["build"], f"{field}.build"),
        features=features,
        mimalloc=_boolean(item["mimalloc"], f"{field}.mimalloc"),
        command=_validate_command(item["command"], f"{field}.command"),
        exposes_full_validation_witness=_boolean(
            item["exposes_full_validation_witness"],
            f"{field}.exposes_full_validation_witness",
        ),
        consensus_proof_hash=_hash(
            item["consensus_proof_hash"], f"{field}.consensus_proof_hash"
        ),
    )


def _program_json(program: ProgramIdentity) -> dict[str, object]:
    return {
        "binary_path": program.binary_path,
        "binary_sha256": program.binary_sha256,
        "commit": program.commit,
        "build": program.build,
        "features": list(program.features),
        "mimalloc": program.mimalloc,
        "command": list(program.command),
        "exposes_full_validation_witness": program.exposes_full_validation_witness,
        "consensus_proof_hash": program.consensus_proof_hash,
    }


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
    corpus_path = _text(item["corpus_path"], f"{field}.corpus_path")
    manifest_path = _text(item["manifest_path"], f"{field}.manifest_path")
    if not Path(corpus_path).is_absolute() or not Path(manifest_path).is_absolute():
        raise ContractError(f"{field} corpus and manifest paths must be absolute")
    return CellConfig(
        cell=_cell_id_from_json(item["cell"], f"{field}.cell"),
        blocked_reason=reason,
        candidate=_program_from_json(item["candidate"], f"{field}.candidate"),
        core=_program_from_json(item["core"], f"{field}.core"),
        corpus_path=corpus_path,
        corpus_sha256=_hash(item["corpus_sha256"], f"{field}.corpus_sha256"),
        manifest_path=manifest_path,
        manifest_sha256=_hash(item["manifest_sha256"], f"{field}.manifest_sha256"),
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


def _child_from_json(
    value: object, field: str, role: Role, program: ProgramIdentity, domain: Domain
) -> ChildResult:
    item = _object(
        value,
        field,
        frozenset(
            {
                "schema",
                "role",
                "height",
                "bestblock",
                "txouts",
                "total_amount_sat",
                "muhash",
                "full_validation_witness",
                "consensus_proof_hash",
                "durability_ok",
                "source_capacity_ok",
                "environment_valid",
                "environment_reason",
            }
        ),
    )
    if _text(item["schema"], f"{field}.schema") != CHILD_SCHEMA:
        raise ContractError(f"{field}.schema must be {CHILD_SCHEMA!r}")
    parsed_role = Role(_enum(Role, item["role"], f"{field}.role").value)
    if parsed_role is not role:
        raise ContractError(f"{field}.role does not match scheduled role")
    witness = _uint(item["full_validation_witness"], f"{field}.full_validation_witness")
    if program.exposes_full_validation_witness and witness == 0:
        raise ContractError(
            f"{field}.full_validation_witness must be nonzero for this build"
        )
    proof = _hash(item["consensus_proof_hash"], f"{field}.consensus_proof_hash")
    if proof != program.consensus_proof_hash:
        raise ContractError(
            f"{field}.consensus_proof_hash does not match configured build"
        )
    durability = _optional_bool(item["durability_ok"], f"{field}.durability_ok")
    capacity = _optional_bool(item["source_capacity_ok"], f"{field}.source_capacity_ok")
    if domain in (Domain.OFFLINE, Domain.RPC) and durability is None:
        raise ContractError(f"{field}.durability_ok is required for {domain.value}")
    if domain in (Domain.P2P, Domain.RPC) and capacity is None:
        raise ContractError(
            f"{field}.source_capacity_ok is required for {domain.value}"
        )
    environment_valid = _boolean(
        item["environment_valid"], f"{field}.environment_valid"
    )
    environment_reason = _optional_text(
        item["environment_reason"], f"{field}.environment_reason"
    )
    if environment_valid == (environment_reason is not None):
        raise ContractError(
            f"{field}.environment_reason must be nonempty exactly when environment is invalid"
        )
    return ChildResult(
        role=parsed_role,
        height=_uint(item["height"], f"{field}.height"),
        bestblock=_hash(item["bestblock"], f"{field}.bestblock"),
        txouts=_uint(item["txouts"], f"{field}.txouts"),
        total_amount_sat=_uint(item["total_amount_sat"], f"{field}.total_amount_sat"),
        muhash=_hash(item["muhash"], f"{field}.muhash"),
        full_validation_witness=witness,
        consensus_proof_hash=proof,
        durability_ok=durability,
        source_capacity_ok=capacity,
        environment_valid=environment_valid,
        environment_reason=environment_reason,
    )


def _child_json(child: ChildResult) -> dict[str, object]:
    return {
        "schema": CHILD_SCHEMA,
        "role": child.role.value,
        "height": child.height,
        "bestblock": child.bestblock,
        "txouts": child.txouts,
        "total_amount_sat": child.total_amount_sat,
        "muhash": child.muhash,
        "full_validation_witness": child.full_validation_witness,
        "consensus_proof_hash": child.consensus_proof_hash,
        "durability_ok": child.durability_ok,
        "source_capacity_ok": child.source_capacity_ok,
        "environment_valid": child.environment_valid,
        "environment_reason": child.environment_reason,
    }


def _state_equal(left: ChildResult, right: ChildResult) -> bool:
    return (
        left.height,
        left.bestblock,
        left.txouts,
        left.total_amount_sat,
        left.muhash,
    ) == (
        right.height,
        right.bestblock,
        right.txouts,
        right.total_amount_sat,
        right.muhash,
    )


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
    result_path = arm_dir / "child-result.json"
    stdout_path = arm_dir / "stdout.log"
    stderr_path = arm_dir / "stderr.log"
    if data_dir.exists() or result_path.exists():
        raise ContractError("fresh arm paths unexpectedly already exist")
    data_dir.mkdir(mode=0o700)
    command = _execution_command(
        program,
        config.affinity,
        {
            "arm_dir": str(arm_dir),
            "data_dir": str(data_dir),
            "result_path": str(result_path),
        },
        program_custody.path,
    )
    child_environment = os.environ.copy()
    child_environment.update(
        {
            "ROLE": role.value,
            "PAIR_INDEX": str(pair_index),
            "ORDER_INDEX": str(order_index),
        }
    )
    pid: int | None = None
    pid_starttime: int | None = None
    wall_ns: int | None = None
    cpu_user_ns: int | None = None
    cpu_system_ns: int | None = None
    peak_rss_bytes: int | None = None
    exit_code: int | None = None
    raw: object | None = None
    child: ChildResult | None = None
    error_text: str | None = None
    started: int | None = None
    try:
        _verify_inputs_unchanged(inputs)
        _verify_program_custody(program_custody)
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            started = time.monotonic_ns()
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                shell=False,
                close_fds=True,
                env=child_environment,
            )
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
            error_text = f"child exited with status {exit_code}"
        elif not result_path.is_file():
            error_text = "child did not create its result JSON"
        else:
            raw = _load_json(
                result_path, f"pair {pair_index} {role.value} child result"
            )
            child = _child_from_json(
                raw, "child_result", role, program, config.cell.domain
            )
    except (OSError, ContractError, subprocess.SubprocessError) as error:
        if started is not None and wall_ns is None:
            wall_ns = time.monotonic_ns() - started
        error_text = str(error)
        if result_path.is_file():
            try:
                raw = _load_json(result_path, "failed child result")
            except ContractError:
                raw = result_path.read_text(encoding="utf-8", errors="replace")
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
        child_result=child,
        child_result_raw=raw,
        error=error_text,
    )


def _derive(
    config_sha256: str, config: CellConfig, seed: int, pairs: tuple[PairResult, ...]
) -> CellResult:
    scheduled = len(pairs)
    valid_pairs = sum(pair.valid for pair in pairs)
    candidate_median: int | None = None
    core_median: int | None = None
    ratio: float | None = None
    performance_verdict: Verdict | None = None
    source_invalid = any(
        config.cell.domain in (Domain.P2P, Domain.RPC)
        and arm.child_result is not None
        and arm.child_result.source_capacity_ok is False
        for pair in pairs
        for arm in (pair.candidate, pair.core)
    )
    environment_invalid = source_invalid or any(
        arm.child_result is not None and not arm.child_result.environment_valid
        for pair in pairs
        for arm in (pair.candidate, pair.core)
    )
    run_failed = any(
        not arm.run_valid for pair in pairs for arm in (pair.candidate, pair.core)
    )
    durability_failed = any(
        config.cell.domain in (Domain.OFFLINE, Domain.RPC)
        and arm.child_result is not None
        and arm.child_result.durability_ok is False
        for pair in pairs
        for arm in (pair.candidate, pair.core)
    )
    correctness_failed = durability_failed or any(
        pair.correctness_match is False for pair in pairs
    )
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
        candidate_result = candidate.child_result
        core_result = core.child_result
        if candidate_result is None or core_result is None:
            raise AssertionError("valid pair must contain both child results")
        correctness = _state_equal(candidate_result, core_result)
    return PairResult(pair_index, order, candidate, core, valid, correctness)


def run_cell(campaign: CampaignConfig, cell: CellId) -> tuple[CellResult, Path]:
    matches = tuple(config for config in campaign.cells if config.cell == cell)
    if len(matches) != 1:
        raise ContractError(f"cell {cell.key} is not configured exactly once")
    config = matches[0]
    if not config.ready:
        raise ContractError(f"cell {cell.key} is blocked: {config.blocked_reason}")
    inputs = _snapshot_inputs(config)
    root = Path(campaign.output_root)
    _mkdir_durable(root)
    run_dir = Path(tempfile.mkdtemp(prefix=f"{cell.key.replace('/', '-')}-", dir=root))
    _fsync_directory(root)
    programs = _prepare_programs(config, run_dir)
    schedule = schedule_for(cell, campaign.schedule_seed)
    pairs: list[PairResult] = []
    seen_paths: set[str] = set()
    for pair_index, order in enumerate(schedule):
        observations: tuple[ArmObservation, ArmObservation] = (
            _run_arm(
                config,
                order[0],
                pair_index,
                0,
                run_dir,
                inputs,
                programs.candidate if order[0] is Role.CANDIDATE else programs.core,
            ),
            _run_arm(
                config,
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
        campaign.canonical_sha256, config, campaign.schedule_seed, tuple(pairs)
    )
    result_path = run_dir / "custody-result.json"
    _atomic_write_json(result_path, _result_json(result))
    return result, result_path


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
        "child_result": None
        if arm.child_result is None
        else _child_json(arm.child_result),
        "child_result_raw": arm.child_result_raw,
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
        "schedule_seed": result.schedule_seed,
        "pairs": [_pair_json(pair) for pair in result.pairs],
        "scheduled_pairs": result.scheduled_pairs,
        "valid_pairs": result.valid_pairs,
        "candidate_median_wall_ns": result.candidate_median_wall_ns,
        "core_median_wall_ns": result.core_median_wall_ns,
        "wall_ratio": result.wall_ratio,
        "verdict": result.verdict.value,
    }


def _arm_from_json(value: object, field: str, config: CellConfig) -> ArmObservation:
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
                "child_result",
                "child_result_raw",
                "error",
            }
        ),
    )
    role = Role(_enum(Role, item["role"], f"{field}.role").value)
    program = config.candidate if role is Role.CANDIDATE else config.core
    child = (
        None
        if item["child_result"] is None
        else _child_from_json(
            item["child_result"],
            f"{field}.child_result",
            role,
            program,
            config.cell.domain,
        )
    )
    raw_child = item["child_result_raw"]
    if child is not None and raw_child != _child_json(child):
        raise ContractError(f"{field}.child_result_raw does not match child_result")
    command = tuple(
        _text(arg, f"{field}.command[{index}]")
        for index, arg in enumerate(_array(item["command"], f"{field}.command"))
    )
    if not command:
        raise ContractError(f"{field}.command must be nonempty")
    error = _optional_text(item["error"], f"{field}.error")
    exit_code_value = item["exit_code"]
    exit_code = None
    if exit_code_value is not None:
        if isinstance(exit_code_value, bool) or not isinstance(exit_code_value, int):
            raise ContractError(f"{field}.exit_code must be an integer or null")
        exit_code = exit_code_value
    return ArmObservation(
        role=role,
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
        child_result=child,
        child_result_raw=raw_child,
        error=error,
    )


def _canonical_recorded_path(value: str, field: str) -> Path:
    return _canonical_absolute_path(value, field)


def parse_result(value: object) -> CellResult:
    item = _object(
        value,
        "result",
        frozenset(
            {
                "schema",
                "config_sha256",
                "cell_config",
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
    seed = _uint(item["schedule_seed"], "result.schedule_seed")
    pair_values = _array(item["pairs"], "result.pairs")
    if len(pair_values) != PAIR_COUNT:
        raise ContractError("result.pairs must contain exactly seven scheduled pairs")
    expected_schedule = schedule_for(config.cell, seed)
    parsed_pairs: list[PairResult] = []
    all_paths: set[Path] = set()
    run_dir: Path | None = None
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
            pair["candidate"], f"result.pairs[{index}].candidate", config
        )
        core = _arm_from_json(pair["core"], f"result.pairs[{index}].core", config)
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
            expected_paths = {
                arm_dir,
                arm_dir / "data",
                arm_dir / "child-result.json",
                arm_dir / "stdout.log",
                arm_dir / "stderr.log",
            }
            if paths != expected_paths:
                raise ContractError(f"{field} artifacts are outside arm_dir")
            if all_paths & paths:
                raise ContractError("result reuses an arm path")
            all_paths.update(paths)
            expected_program = (
                config.candidate if observation.role is Role.CANDIDATE else config.core
            )
            executable_path = _custody_program_path(
                run_dir, observation.role, expected_program
            )
            expanded = _execution_command(
                expected_program,
                config.affinity,
                {
                    "arm_dir": observation.arm_dir,
                    "data_dir": observation.data_dir,
                    "result_path": observation.result_path,
                },
                executable_path,
            )
            if observation.command != expanded:
                raise ContractError(
                    "recorded command does not match bound identity and paths"
                )
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
            _snapshot_file(
                str(executable_path),
                program.binary_sha256,
                f"result program custody {role.value}",
            )
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
            and arm.child_result is None
            for arm in role_arms
        )
        if not preparation_failed:
            raise ContractError(f"result program custody {role.value} is missing")
    derived = _derive(
        _hash(item["config_sha256"], "result.config_sha256"),
        config,
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
    result = parse_result(_load_json(path, "result"))
    campaign = load_config(config_path)
    if campaign.canonical_sha256 != result.config_sha256:
        raise ContractError("result config hash does not match supplied config")
    matches = [cell for cell in campaign.cells if cell.cell == result.cell_config.cell]
    if len(matches) != 1 or matches[0] != result.cell_config:
        raise ContractError("result cell identity does not match supplied config")
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
