#!/usr/bin/env python3
# pyright: strict
"""Strict contract and end-to-end tests for the generic campaign runner."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import TypedDict, TypeIs
from unittest import mock

import runner
from runner import (
    ALL_CELLS,
    Architecture,
    Backend,
    CellId,
    ContractError,
    Corpus,
    Domain,
    Role,
    classify_wall_performance,
    expand_command,
    load_config,
    parse_config,
    parse_result,
    run_cell,
    schedule_for,
    validate_result,
)

_WORKSPACES: list[tempfile.TemporaryDirectory[str]] = []


class _ProgramJson(TypedDict):
    binary_path: str
    binary_sha256: str
    commit: str
    build: str
    features: list[str]
    mimalloc: bool
    command: list[str]
    exposes_full_validation_witness: bool
    consensus_proof_hash: str


class _CellIdJson(TypedDict):
    domain: str
    corpus: str
    architecture: str
    backend: str


class _CellConfigJson(TypedDict):
    cell: _CellIdJson
    blocked_reason: str | None
    candidate: _ProgramJson
    core: _ProgramJson
    corpus_path: str
    corpus_sha256: str
    manifest_path: str
    manifest_sha256: str
    affinity: list[int]


class _CampaignConfigJson(TypedDict):
    schema: str
    schedule_seed: int
    output_root: str
    cells: list[_CellConfigJson]


class _ArmJson(TypedDict):
    command: list[str]
    child_result: dict[str, object] | None
    child_result_raw: object
    error: str | None
    pid: int | None
    wall_ns: int | None
    arm_dir: str
    data_dir: str
    result_path: str
    stdout_path: str
    stderr_path: str


class _PairJson(TypedDict):
    pair_index: int
    candidate: _ArmJson
    core: _ArmJson
    valid: bool
    correctness_match: bool | None


class _ResultJson(TypedDict):
    pairs: list[_PairJson]
    scheduled_pairs: int
    valid_pairs: int
    verdict: str
    _run_path: str
    _config_path: str


def _is_json_object(value: object) -> TypeIs[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in value)  # pyright: ignore[reportUnknownVariableType]


def _is_json_array(value: object) -> TypeIs[list[object]]:
    return isinstance(value, list)


def _is_integer(value: object) -> TypeIs[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_optional_int(value: object) -> bool:
    return value is None or _is_integer(value)


def _is_arm_json(value: object) -> TypeIs[_ArmJson]:
    if not _is_json_object(value):
        return False
    required = {
        "command",
        "child_result",
        "child_result_raw",
        "error",
        "pid",
        "wall_ns",
        "arm_dir",
        "data_dir",
        "result_path",
        "stdout_path",
        "stderr_path",
    }
    if not required.issubset(value):
        return False
    child = value["child_result"]
    error = value["error"]
    command = value["command"]
    return (
        _is_json_array(command)
        and bool(command)
        and all(isinstance(argument, str) for argument in command)
        and (child is None or _is_json_object(child))
        and (error is None or isinstance(error, str))
        and _is_optional_int(value["pid"])
        and _is_optional_int(value["wall_ns"])
        and all(
            isinstance(value[key], str)
            for key in (
                "arm_dir",
                "data_dir",
                "result_path",
                "stdout_path",
                "stderr_path",
            )
        )
    )


def _is_pair_json(value: object) -> TypeIs[_PairJson]:
    if not _is_json_object(value):
        return False
    required = {
        "pair_index",
        "candidate",
        "core",
        "valid",
        "correctness_match",
    }
    if not required.issubset(value):
        return False
    return (
        _is_integer(value["pair_index"])
        and _is_arm_json(value["candidate"])
        and _is_arm_json(value["core"])
        and isinstance(value["valid"], bool)
        and (
            value["correctness_match"] is None
            or isinstance(value["correctness_match"], bool)
        )
    )


def _is_result_json(value: object) -> TypeIs[_ResultJson]:
    if not _is_json_object(value):
        return False
    pairs = value.get("pairs")
    return (
        _is_json_array(pairs)
        and all(_is_pair_json(pair) for pair in pairs)
        and _is_integer(value.get("scheduled_pairs"))
        and _is_integer(value.get("valid_pairs"))
        and isinstance(value.get("verdict"), str)
        and isinstance(value.get("_run_path"), str)
        and isinstance(value.get("_config_path"), str)
    )


def _object(value: object) -> dict[str, object]:
    if not _is_json_object(value):
        raise TypeError("expected JSON object")
    return value


def _load_json_object(text: str) -> dict[str, object]:
    value: object = json.loads(text)
    return _object(value)


def _integer(value: object) -> int:
    if not _is_integer(value):
        raise TypeError("expected JSON integer")
    return value


def _required_text(value: object) -> str:
    if not isinstance(value, str):
        raise TypeError("expected JSON string")
    return value


def _cleanup_workspaces() -> None:
    while _WORKSPACES:
        _WORKSPACES.pop().cleanup()


def tearDownModule() -> None:
    _cleanup_workspaces()


class _WorkspaceTestCase(unittest.TestCase):
    def tearDown(self) -> None:
        _cleanup_workspaces()


class UniverseTests(unittest.TestCase):
    def test_exactly_thirty_six_unique_cells(self) -> None:
        self.assertEqual(len(ALL_CELLS), 36)
        self.assertEqual(len(set(ALL_CELLS)), 36)

    def test_cartesian_closure(self) -> None:
        expected = {
            (domain, corpus, arch, backend)
            for domain in Domain
            for corpus in Corpus
            for arch in Architecture
            for backend in Backend
        }
        actual = {
            (cell.domain, cell.corpus, cell.architecture, cell.backend)
            for cell in ALL_CELLS
        }
        self.assertEqual(expected, actual)


class ScheduleTests(unittest.TestCase):
    def test_seven_pairs_every_cell(self) -> None:
        for cell in ALL_CELLS:
            schedule = schedule_for(cell, 0)
            self.assertEqual(len(schedule), 7)
            for order in schedule:
                self.assertEqual(frozenset(order), frozenset(Role))

    def test_fixed_schedule_vectors(self) -> None:
        core_first = (
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
        )
        candidate_first = (
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
            (Role.CORE, Role.CANDIDATE),
            (Role.CANDIDATE, Role.CORE),
        )
        self.assertEqual(schedule_for(ALL_CELLS[0], 0), core_first)
        self.assertEqual(schedule_for(ALL_CELLS[0], 1), candidate_first)
        self.assertEqual(schedule_for(ALL_CELLS[2], 0), candidate_first)

    def test_alternating_balance(self) -> None:
        for cell in ALL_CELLS:
            schedule = schedule_for(cell, 0)
            first_candidate = sum(1 for order in schedule if order[0] is Role.CANDIDATE)
            first_core = 7 - first_candidate
            self.assertIn(first_candidate, (3, 4))
            self.assertIn(first_core, (3, 4))


class PlaceholderTests(unittest.TestCase):
    def test_exact_placeholders_only(self) -> None:
        paths = {"arm_dir": "/a", "data_dir": "/a/d", "result_path": "/a/d/r.json"}
        self.assertEqual(
            expand_command(
                ("{arm_dir}/bin", "--data", "{data_dir}", "--out", "{result_path}"),
                paths,
            ),
            ("/a/bin", "--data", "/a/d", "--out", "/a/d/r.json"),
        )

    def test_rejects_unknown_placeholder(self) -> None:
        paths = {"arm_dir": "/a", "data_dir": "/a/d", "result_path": "/a/d/r.json"}
        with self.assertRaises(ContractError):
            expand_command(("{home}",), paths)

    def test_rejects_attribute_access(self) -> None:
        paths = {"arm_dir": "/a", "data_dir": "/a/d", "result_path": "/a/d/r.json"}
        with self.assertRaises(ContractError):
            expand_command(("{arm_dir.__class__}",), paths)

    def test_rejects_format_spec(self) -> None:
        paths = {"arm_dir": "/a", "data_dir": "/a/d", "result_path": "/a/d/r.json"}
        with self.assertRaises(ContractError):
            expand_command(("{arm_dir!r}",), paths)


class JsonStrictnessTests(_WorkspaceTestCase):
    def test_unknown_keys_rejected_in_config(self) -> None:
        base = _minimal_config()
        malformed: dict[str, object] = dict(base)
        malformed["extra_field"] = "bad"
        with self.assertRaises(ContractError):
            parse_config(malformed)

    def test_relative_output_root_rejected(self) -> None:
        base = _minimal_config()
        base["output_root"] = "."
        with self.assertRaisesRegex(ContractError, "absolute normalized path"):
            parse_config(base)

    def test_output_root_alias_rejected(self) -> None:
        base = _minimal_config()
        with tempfile.TemporaryDirectory() as workspace:
            real = Path(workspace) / "real"
            alias = Path(workspace) / "alias"
            real.mkdir()
            alias.symlink_to(real, target_is_directory=True)
            base["output_root"] = str(alias / "out")
            with self.assertRaisesRegex(ContractError, "filesystem alias"):
                parse_config(base)

    def test_bool_as_int_rejected(self) -> None:
        base = _minimal_config()
        base["schedule_seed"] = True
        with self.assertRaises(ContractError):
            parse_config(base)

    def test_hash_width_rejected(self) -> None:
        base = _minimal_config()
        base["cells"][0]["candidate"]["binary_sha256"] = "0" * 63
        with self.assertRaises(ContractError):
            parse_config(base)

    def test_mixed_case_hash_rejected(self) -> None:
        base = _minimal_config()
        base["cells"][0]["candidate"]["binary_sha256"] = "A" * 64
        with self.assertRaises(ContractError):
            parse_config(base)

    def test_nonempty_argv(self) -> None:
        base = _minimal_config()
        base["cells"][0]["candidate"]["command"] = []
        with self.assertRaises(ContractError):
            parse_config(base)

    def test_malformed_child_result_rejected(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        child = result["pairs"][0]["candidate"]["child_result"]
        if child is None:
            self.fail("successful fake arm has no child result")
        child["height"] = "not an int"
        with self.assertRaises(ContractError):
            parse_result(_schema_result(result))

    def test_unknown_keys_in_child_result_rejected(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        child = result["pairs"][0]["candidate"]["child_result"]
        if child is None:
            self.fail("successful fake arm has no child result")
        child["extra"] = 1
        with self.assertRaises(ContractError):
            parse_result(_schema_result(result))

    def test_raw_child_evidence_must_match_parsed_child(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5)
        raw = _object(result["pairs"][0]["candidate"]["child_result_raw"])
        raw["height"] = _integer(raw.get("height")) + 1
        with self.assertRaisesRegex(ContractError, "child_result_raw"):
            parse_result(_schema_result(result))

    def test_arm_guard_rejects_missing_optional_value_keys(self) -> None:
        arm: dict[str, object] = {
            "child_result_raw": None,
            "error": None,
            "pid": None,
            "wall_ns": None,
            "arm_dir": "/arm",
            "data_dir": "/arm/data",
            "result_path": "/arm/result",
            "stdout_path": "/arm/stdout",
            "stderr_path": "/arm/stderr",
        }
        self.assertFalse(_is_arm_json(arm))

    def test_pair_guard_requires_correctness_key(self) -> None:
        pair: dict[str, object] = {
            "pair_index": 0,
            "candidate": {},
            "core": {},
            "valid": False,
        }
        self.assertFalse(_is_pair_json(pair))


class ExecutionTests(_WorkspaceTestCase):
    def test_complete_seven_pair_run(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        self.assertEqual(len(result["pairs"]), 7)
        self.assertEqual(result["scheduled_pairs"], 7)
        self.assertEqual(result["valid_pairs"], 7)

    def test_process_failure_invalidates_pair(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(
            base, speed_ms=5, fail_pair_index=2, fail_role=Role.CANDIDATE
        )
        pair = result["pairs"][2]
        self.assertFalse(pair["valid"])
        self.assertEqual(result["valid_pairs"], 6)
        self.assertEqual(result["verdict"], "fail_run")

    def test_invalid_environment_pair(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(
            base, speed_ms=5, invalid_env_pair_index=1, invalid_env_role=Role.CORE
        )
        self.assertEqual(result["verdict"], "invalid_env")

    def test_false_source_capacity_invalidates_p2p_environment(self) -> None:
        p2p_cell = next(
            cell
            for cell in ALL_CELLS
            if cell.domain is Domain.P2P
            and cell.corpus is Corpus.C150
            and cell.architecture is Architecture.X86_64
            and cell.backend is Backend.FJALL
        )
        result = _run_with_fake(
            _minimal_config(),
            cell=p2p_cell,
            speed_ms=5,
            source_capacity_ok=False,
        )
        self.assertEqual(result["verdict"], "invalid_env")

    def test_false_offline_durability_fails_correctness(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5, durability_ok=False)
        self.assertEqual(result["verdict"], "fail_correctness")

    def test_rpc_durability_failure_dominates_invalid_environment(self) -> None:
        rpc_cell = next(
            cell
            for cell in ALL_CELLS
            if cell.domain is Domain.RPC
            and cell.corpus is Corpus.C150
            and cell.architecture is Architecture.X86_64
            and cell.backend is Backend.FJALL
        )
        result = _run_with_fake(
            _minimal_config(),
            cell=rpc_cell,
            speed_ms=5,
            durability_ok=False,
            source_capacity_ok=False,
        )
        self.assertEqual(result["verdict"], "fail_correctness")

    def test_binary_hash_mismatch_fails_run(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5, binary_sha256="f" * 64)
        self.assertEqual(result["verdict"], "fail_run")
        self.assertIn(
            "program binary hash mismatch",
            _required_text(result["pairs"][0]["candidate"]["error"]),
        )
        validated = validate_result(
            Path(result["_run_path"]), Path(result["_config_path"])
        )
        self.assertEqual(validated.verdict.value, "fail_run")

    def test_relative_binary_path_fails_run(self) -> None:
        result = _run_with_fake(
            _minimal_config(), speed_ms=5, binary_path="fake-child.py"
        )
        self.assertEqual(result["verdict"], "fail_run")
        self.assertIn(
            "binary_path must be absolute",
            _required_text(result["pairs"][0]["candidate"]["error"]),
        )

    def test_command_must_execute_bound_binary(self) -> None:
        with self.assertRaisesRegex(ContractError, "bound binary_path"):
            _run_with_fake(
                _minimal_config(),
                speed_ms=5,
                command_binary_path="/different/program",
            )

    def test_post_exit_binary_mutation_fails_run(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5, mutate_binary=True)
        self.assertEqual(result["verdict"], "fail_run")
        errors: list[str] = []
        for pair in result["pairs"]:
            for arm in (pair["candidate"], pair["core"]):
                error = arm["error"]
                if error is not None:
                    errors.append(error)
        self.assertTrue(
            any("program custody changed during execution" in error for error in errors)
        )

    def test_private_custody_copy_is_the_executed_program(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5)
        run_dir = Path(result["_run_path"]).parent
        candidate_command = result["pairs"][0]["candidate"]["command"]
        self.assertEqual(
            Path(candidate_command[3]),
            run_dir / "programs" / "candidate" / "fake-child.py",
        )

    def test_source_mutation_cannot_change_custodied_run(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5, mutate_source=True)
        self.assertEqual(result["valid_pairs"], 7)
        validated = validate_result(
            Path(result["_run_path"]), Path(result["_config_path"])
        )
        self.assertEqual(validated.valid_pairs, 7)

    def test_configured_corpus_hash_must_match(self) -> None:
        with self.assertRaisesRegex(ContractError, "corpus_path hash mismatch"):
            _run_with_fake(_minimal_config(), speed_ms=5, corpus_sha256="f" * 64)

    def test_input_mutation_fails_run(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5, mutate_input=True)
        self.assertEqual(result["verdict"], "fail_run")
        errors = [
            _required_text(arm["error"])
            for pair in result["pairs"]
            for arm in (pair["candidate"], pair["core"])
            if arm["error"] is not None
        ]
        self.assertTrue(
            any("corpus_path changed during campaign" in error for error in errors)
        )

    def test_log_durability_work_is_outside_wall_measurement(self) -> None:
        clock_calls = 0
        fsync_calls = 0
        fsyncs_at_start = 0
        real_sleep = time.sleep

        def monotonic_ns() -> int:
            nonlocal clock_calls, fsyncs_at_start
            arm_index, boundary = divmod(clock_calls, 2)
            clock_calls += 1
            if boundary == 0:
                fsyncs_at_start = fsync_calls
                return arm_index * 2_000_000
            self.assertEqual(fsync_calls, fsyncs_at_start)
            return arm_index * 2_000_000 + 1_000_000

        def delayed_fsync(_descriptor: int) -> None:
            nonlocal fsync_calls
            fsync_calls += 1
            real_sleep(0.001)

        with (
            mock.patch.object(runner.time, "monotonic_ns", monotonic_ns),
            mock.patch.object(runner.os, "fsync", delayed_fsync),
        ):
            result = _run_with_fake(_minimal_config(), speed_ms=5)

        walls = [
            arm["wall_ns"]
            for pair in result["pairs"]
            for arm in (pair["candidate"], pair["core"])
        ]
        self.assertEqual(walls, [1_000_000] * 14)
        self.assertEqual(clock_calls, 28)
        self.assertGreaterEqual(fsync_calls, 28)

    def test_new_result_directory_hierarchy_is_fsynced(self) -> None:
        synced: list[Path] = []
        fsync_directory = runner._fsync_directory  # pyright: ignore[reportPrivateUsage]

        def record_fsync(path: Path) -> None:
            synced.append(path)
            fsync_directory(path)

        with mock.patch.object(runner, "_fsync_directory", record_fsync):
            result = _run_with_fake(_minimal_config(), speed_ms=5)

        run_dir = Path(result["_run_path"]).parent
        output_root = run_dir.parent
        self.assertIn(output_root.parent, synced)
        self.assertIn(output_root, synced)
        self.assertIn(run_dir, synced)

    def test_observation_failure_kills_and_reaps_child(self) -> None:
        with mock.patch.object(
            runner,
            "_read_starttime",
            side_effect=ContractError("synthetic observation failure"),
        ):
            result = _run_with_fake(_minimal_config(), speed_ms=100)

        for pair in result["pairs"]:
            for arm in (pair["candidate"], pair["core"]):
                self.assertIn(
                    "synthetic observation failure", _required_text(arm["error"])
                )
                pid = arm["pid"]
                if pid is None:
                    self.fail("launched arm has no PID")
                with self.assertRaises(ChildProcessError):
                    os.waitpid(pid, os.WNOHANG)

    def test_zombie_rss_race_retries_until_wait4_reaps(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
        )
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
            starttime = runner._read_starttime(  # pyright: ignore[reportPrivateUsage]
                process.pid
            )
            self.assertIsNone(
                runner._sample_rss(  # pyright: ignore[reportPrivateUsage]
                    process.pid, starttime
                )
            )
        finally:
            process.wait()

    def test_invalid_pair_not_replaced(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(
            base, speed_ms=5, fail_pair_index=0, fail_role=Role.CORE
        )
        self.assertEqual(len(result["pairs"]), 7)
        self.assertEqual(result["scheduled_pairs"], 7)
        self.assertEqual(result["valid_pairs"], 6)

    def test_state_mismatch_fails_correctness(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5, mismatch_pair_index=3)
        pair = result["pairs"][3]
        self.assertTrue(pair["valid"])
        self.assertFalse(pair["correctness_match"])
        self.assertEqual(result["verdict"], "fail_correctness")

    def test_blocked_cell_refused(self) -> None:
        base = _minimal_config()
        base["cells"][0]["blocked_reason"] = "cmodern aarch64 unsupported"
        config = _write_config(base)
        with self.assertRaises(ContractError):
            run_cell(load_config(config), ALL_CELLS[0])

    def test_ratio_boundary_at_two_zero(self) -> None:
        candidate, core, ratio, verdict = classify_wall_performance(
            [100] * 7, [200] * 7
        )
        self.assertEqual((candidate, core, ratio), (100, 200, 2.0))
        self.assertEqual(verdict.value, "pass")

    def test_ratio_fails_perf(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, candidate_ms=200, core_ms=100)
        self.assertEqual(result["verdict"], "fail_perf")

    def test_output_tamper_detected(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        result["valid_pairs"] = 0
        with self.assertRaises(ContractError):
            parse_result(_schema_result(result))

    def test_path_freshness(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        paths: set[str] = set()
        for pair in result["pairs"]:
            for arm_name in ("candidate", "core"):
                arm = pair[arm_name]
                for key in (
                    "arm_dir",
                    "data_dir",
                    "result_path",
                    "stdout_path",
                    "stderr_path",
                ):
                    path = arm[key]
                    self.assertNotIn(path, paths)
                    paths.add(path)
                    self.assertTrue(Path(path).exists())

    def test_path_alias_tamper_detected(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5)
        arm = result["pairs"][0]["candidate"]
        arm["stdout_path"] = arm["stdout_path"].replace("/stdout.log", "/./stdout.log")
        with self.assertRaisesRegex(ContractError, "normalized path"):
            parse_result(_schema_result(result))

    def test_arm_artifacts_must_remain_contained(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5)
        arm = result["pairs"][0]["candidate"]
        arm["stdout_path"] = str(Path(arm["arm_dir"]).parent / "outside.log")
        with self.assertRaisesRegex(ContractError, "outside arm_dir"):
            parse_result(_schema_result(result))

    def test_cli_subprocess_run_and_validate(self) -> None:
        base = _minimal_config()
        prepared = _run_with_fake(base, speed_ms=5)
        config_path = prepared["_config_path"]
        runner = Path(__file__).with_name("runner.py")
        run_proc = subprocess.run(
            [
                sys.executable,
                str(runner),
                "run",
                "--config",
                config_path,
                "--cell",
                ALL_CELLS[0].key,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        run_obj = _load_json_object(run_proc.stdout)
        result_path = _required_text(run_obj.get("result"))
        val_proc = subprocess.run(
            [
                sys.executable,
                str(runner),
                "validate",
                "--result",
                result_path,
                "--config",
                config_path,
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        val_obj = _load_json_object(val_proc.stdout)
        self.assertEqual(_required_text(val_obj.get("cell")), ALL_CELLS[0].key)

        missing_config = subprocess.run(
            [
                sys.executable,
                str(runner),
                "validate",
                "--result",
                result_path,
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(missing_config.returncode, 2)
        self.assertIn("--config", missing_config.stderr)

    def test_cli_plan_and_help(self) -> None:
        base = _minimal_config()
        with tempfile.TemporaryDirectory() as workspace:
            config_path = Path(workspace) / "config.json"
            config_path.write_text(json.dumps(base))
            runner = Path(__file__).with_name("runner.py")
            plan_proc = subprocess.run(
                [sys.executable, str(runner), "plan", "--config", str(config_path)],
                check=True,
                capture_output=True,
                text=True,
            )
            plan = _load_json_object(plan_proc.stdout)
            cells = plan.get("cells")
            if not _is_json_array(cells):
                self.fail("plan cells must be a JSON array")
            self.assertEqual(len(cells), 36)
            for op in ("plan", "run", "validate"):
                proc = subprocess.run(
                    [sys.executable, str(runner), op, "--help"],
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertIn("usage:", proc.stdout.lower())


class IdentityBindingTests(_WorkspaceTestCase):
    def test_identity_hash_bound_to_result(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        config = _write_config(base)
        validated = validate_result(Path(result["_run_path"]), config)
        self.assertEqual(validated.cell_config.cell, ALL_CELLS[0])

    def test_changed_config_rejected(self) -> None:
        base = _minimal_config()
        result = _run_with_fake(base, speed_ms=5)
        base["schedule_seed"] = base["schedule_seed"] + 1
        config = _write_config(base)
        with self.assertRaises(ContractError):
            validate_result(Path(result["_run_path"]), config)

    def test_tampered_program_custody_rejected(self) -> None:
        result = _run_with_fake(_minimal_config(), speed_ms=5)
        command = result["pairs"][0]["candidate"]["command"]
        with Path(command[3]).open("ab") as executable:
            executable.write(b"tampered")
        with self.assertRaisesRegex(ContractError, "program custody candidate"):
            validate_result(Path(result["_run_path"]), Path(result["_config_path"]))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _minimal_config() -> _CampaignConfigJson:
    cells: list[_CellConfigJson] = []
    for cell in ALL_CELLS:
        cells.append(
            {
                "cell": {
                    "domain": cell.domain.value,
                    "corpus": cell.corpus.value,
                    "architecture": cell.architecture.value,
                    "backend": cell.backend.value,
                },
                "blocked_reason": None,
                "candidate": _program_identity("candidate"),
                "core": _program_identity("core"),
                "corpus_path": "/fake/corpus",
                "corpus_sha256": "0" * 64,
                "manifest_path": "/fake/manifest",
                "manifest_sha256": "0" * 64,
                "affinity": [0, 1, 2, 3],
            }
        )
    return {
        "schema": "benchmark-campaign-config-v1",
        "schedule_seed": 42,
        "output_root": str(
            Path(tempfile.gettempdir()).resolve() / "benchmark-campaign-unused-output"
        ),
        "cells": cells,
    }


def _program_identity(role: str) -> _ProgramJson:
    return {
        "binary_path": f"/fake/{role}",
        "binary_sha256": "0" * 64,
        "commit": "abc123",
        "build": f"{role}-build",
        "features": ["kernel"],
        "mimalloc": False,
        "command": ["{arm_dir}/bin", "--data", "{data_dir}", "--out", "{result_path}"],
        "exposes_full_validation_witness": True,
        "consensus_proof_hash": "0" * 64,
    }


def _write_config(base: _CampaignConfigJson) -> Path:
    handle, path = tempfile.mkstemp(suffix=".json")
    os.close(handle)
    Path(path).write_text(json.dumps(base))
    return Path(path)


def _fake_child_script(
    workspace: Path,
    *,
    candidate_ms: int,
    core_ms: int,
    fail_pair_index: int | None,
    fail_role: Role | None,
    mismatch_pair_index: int | None,
    invalid_env_pair_index: int | None,
    invalid_env_role: Role | None,
    durability_ok: bool,
    source_capacity_ok: bool,
    mutate_binary: bool,
    mutate_input: bool,
    mutate_source: bool,
    speed_ms: int | None,
) -> Path:
    script = workspace / "fake-child.py"
    pairs = [
        {
            "height": 150000,
            "bestblock": "0" * 64,
            "txouts": 1127181,
            "total_amount_sat": 749989998999999,
            "muhash": "383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116",
            "full_validation_witness": 1,
            "durability_ok": durability_ok,
            "source_capacity_ok": source_capacity_ok,
            "environment_valid": True,
            "environment_reason": None,
        }
        for _ in range(7)
    ]

    code = (
        "#!/usr/bin/env python3\n"
        "import json, os, sys, time\n"
        "role = os.environ['ROLE']\n"
        f"pairs = {pairs!r}\n"
        f"candidate_ms = {candidate_ms}\n"
        f"core_ms = {core_ms}\n"
        f"fail_pair_index = {fail_pair_index}\n"
        f"fail_role = {fail_role.value if fail_role else None!r}\n"
        f"mismatch_pair_index = {mismatch_pair_index}\n"
        f"invalid_env_pair_index = {invalid_env_pair_index}\n"
        f"invalid_env_role = {invalid_env_role.value if invalid_env_role else None!r}\n"
        f"mutate_binary = {mutate_binary!r}\n"
        f"mutate_input = {mutate_input!r}\n"
        f"mutate_source = {mutate_source!r}\n"
        f"speed_ms = {speed_ms}\n"
        "pair = int(os.environ['PAIR_INDEX'])\n"
        "result_path = sys.argv[sys.argv.index('--out') + 1]\n"
        "if fail_pair_index == pair and fail_role == role:\n"
        "    sys.exit(1)\n"
        "if mutate_binary:\n"
        "    with open(__file__, 'a') as executable:\n"
        "        executable.write('\\n# mutated during execution\\n')\n"
        "if mutate_input:\n"
        "    input_path = sys.argv[sys.argv.index('--corpus') + 1]\n"
        "    with open(input_path, 'ab') as corpus:\n"
        "        corpus.write(b'mutated')\n"
        "if mutate_source:\n"
        "    source_path = sys.argv[sys.argv.index('--source-binary') + 1]\n"
        "    with open(source_path, 'ab') as source:\n"
        "        source.write(b'mutated source')\n"
        "ms = candidate_ms if role == 'candidate' else core_ms\n"
        "if speed_ms is not None:\n"
        "    ms = speed_ms\n"
        "time.sleep(max(ms, 50) / 1000.0)\n"
        "record = dict(pairs[pair])\n"
        "if mismatch_pair_index == pair and role == 'candidate':\n"
        "    record['height'] = 150001\n"
        "if invalid_env_pair_index == pair and invalid_env_role == role:\n"
        "    record['environment_valid'] = False\n"
        "    record['environment_reason'] = 'synthetic invalid env'\n"
        "record['schema'] = 'benchmark-campaign-child-v1'\n"
        "record['role'] = role\n"
        "record['consensus_proof_hash'] = '0' * 64\n"
        "with open(result_path, 'w') as f:\n"
        "    json.dump(record, f)\n"
    )
    script.write_text(code)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return script


def _run_with_fake(
    base: _CampaignConfigJson,
    *,
    cell: CellId = ALL_CELLS[0],
    speed_ms: int | None = None,
    candidate_ms: int = 10,
    core_ms: int = 10,
    fail_pair_index: int | None = None,
    fail_role: Role | None = None,
    mismatch_pair_index: int | None = None,
    invalid_env_pair_index: int | None = None,
    invalid_env_role: Role | None = None,
    durability_ok: bool = True,
    source_capacity_ok: bool = True,
    binary_sha256: str | None = None,
    binary_path: str | None = None,
    command_binary_path: str | None = None,
    mutate_binary: bool = False,
    mutate_input: bool = False,
    mutate_source: bool = False,
    corpus_sha256: str | None = None,
) -> _ResultJson:
    workspace_context = tempfile.TemporaryDirectory()
    _WORKSPACES.append(workspace_context)
    workspace = Path(workspace_context.name)
    corpus_path = workspace / "corpus.dat"
    manifest_path = workspace / "manifest.json"
    corpus_path.write_bytes(b"hash-bound corpus")
    manifest_path.write_bytes(b"hash-bound manifest")
    script = _fake_child_script(
        workspace,
        candidate_ms=candidate_ms,
        core_ms=core_ms,
        fail_pair_index=fail_pair_index,
        fail_role=fail_role,
        mismatch_pair_index=mismatch_pair_index,
        invalid_env_pair_index=invalid_env_pair_index,
        invalid_env_role=invalid_env_role,
        durability_ok=durability_ok,
        source_capacity_ok=source_capacity_ok,
        mutate_binary=mutate_binary,
        mutate_input=mutate_input,
        mutate_source=mutate_source,
        speed_ms=speed_ms,
    )
    observed_sha256 = hashlib.sha256(script.read_bytes()).hexdigest()
    observed_corpus_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
    observed_manifest_sha256 = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    configured_binary = str(script) if binary_path is None else binary_path
    configured_command = (
        configured_binary if command_binary_path is None else command_binary_path
    )
    for configured_cell in base["cells"]:
        configured_cell["corpus_path"] = str(corpus_path)
        configured_cell["corpus_sha256"] = (
            observed_corpus_sha256 if corpus_sha256 is None else corpus_sha256
        )
        configured_cell["manifest_path"] = str(manifest_path)
        configured_cell["manifest_sha256"] = observed_manifest_sha256
        for program in (configured_cell["candidate"], configured_cell["core"]):
            program["binary_path"] = configured_binary
            program["binary_sha256"] = (
                observed_sha256 if binary_sha256 is None else binary_sha256
            )
            program["command"] = [
                configured_command,
                "--source-binary",
                str(script),
                "--corpus",
                str(corpus_path),
                "--data",
                "{data_dir}",
                "--out",
                "{result_path}",
            ]
    output_root = workspace / "out"
    base["output_root"] = str(output_root)
    config_path = workspace / "config.json"
    config_path.write_text(json.dumps(base))
    _result, result_path = run_cell(load_config(config_path), cell)
    obj = _load_json_object(result_path.read_text(encoding="utf-8"))
    obj["_run_path"] = str(result_path)
    obj["_config_path"] = str(config_path)
    if not _is_result_json(obj):
        raise TypeError("runner emitted an invalid test result")
    return obj


def _schema_result(result: _ResultJson) -> dict[str, object]:
    value: dict[str, object] = dict(result)
    value.pop("_run_path")
    value.pop("_config_path")
    return value


if __name__ == "__main__":
    raise SystemExit(unittest.main())
