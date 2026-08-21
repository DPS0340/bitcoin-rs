#!/usr/bin/env bash
set -euo pipefail

usage() {
  printf '%s\n' \
    'usage: run-g14-guarded.sh --fixture PATH --max-fixture-bytes N --reserve-bytes N --max-rss-bytes N --interval-seconds S --stdout PATH --stderr PATH --unit-name NAME -- COMMAND...'
}

if [[ $# -eq 0 || ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  [[ $# -gt 0 ]] && exit 0
  exit 2
fi

exec python3 - "$@" <<'PY'
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import tempfile
import sys
import time

SCHEMA = "bitcoin-rs-disk-guard-v2"
BREACH_EXIT = 75
SENSITIVE_OPTIONS = frozenset(("--rpc-password",))
INTERNAL_ERROR_EXIT = 70
UNIT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}")


def die(message: str, status: int = 2) -> None:
    print(f"run-g14-guarded.sh: {message}", file=sys.stderr)
    raise SystemExit(status)


def parse_nonnegative_integer(value: str, name: str, *, positive: bool = False) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        die(f"{name} must be a base-10 integer")
    parsed = int(value)
    if positive and parsed == 0:
        die(f"{name} must be greater than zero")
    return parsed


def parse_positive_seconds(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError:
        die("--interval-seconds must be a finite number greater than zero")
    if not 0.0 < parsed < float("inf"):
        die("--interval-seconds must be a finite number greater than zero")
    return parsed

def resolved_target(value: str, label: str) -> Path:
    path = Path(value)
    try:
        parent = path.parent.resolve(strict=True)
    except (FileNotFoundError, OSError) as error:
        die(f"{label} parent cannot be resolved: {error}")
    if not parent.is_dir():
        die(f"{label} parent must exist and be a directory")
    return parent / path.name


def run_systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", "--no-pager", *arguments],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def unit_properties(unit: str) -> dict[str, str]:
    result = run_systemctl(
        "show",
        unit,
        "--property=LoadState",
        "--property=ActiveState",
        "--property=SubState",
        "--property=Result",
        "--property=ExecMainCode",
        "--property=ExecMainStatus",
        "--property=ControlGroup",
    )
    properties: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            properties[key] = value
    return properties


def fixture_bytes(path: Path) -> int:
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return 0
    if not path.is_dir() or path.is_symlink():
        return stat.st_size

    total = 0
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            entries = list(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    total += entry.stat(follow_symlinks=False).st_size
            except FileNotFoundError:
                continue
    return total


def cgroup_pids(path: Path) -> set[int]:
    if not path.is_dir():
        return set()
    pids: set[int] = set()
    pending = [path]
    while pending:
        directory = pending.pop()
        try:
            with (directory / "cgroup.procs").open("r", encoding="ascii") as handle:
                for line in handle:
                    try:
                        pids.add(int(line))
                    except ValueError:
                        continue
            pending.extend(entry for entry in directory.iterdir() if entry.is_dir())
        except (FileNotFoundError, PermissionError):
            continue
    return pids


def aggregate_rss_bytes(path: Path) -> int:
    total_kib = 0
    for pid in cgroup_pids(path):
        try:
            with Path(f"/proc/{pid}/status").open("r", encoding="ascii") as handle:
                for line in handle:
                    if line.startswith("VmRSS:"):
                        fields = line.split()
                        if len(fields) >= 2:
                            total_kib += int(fields[1])
                        break
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            continue
    return total_kib * 1024


def reserve_file(path: Path) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
    finally:
        os.close(descriptor)


def remove_files(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except FileNotFoundError:
            pass


def remove_fixture(path: Path) -> None:
    try:
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink(missing_ok=True)
    except FileNotFoundError:
        pass


def wait_for_empty_cgroup(path: Path, timeout_seconds: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not cgroup_pids(path):
            return True
        time.sleep(0.05)
    return not cgroup_pids(path)


def child_exit_status(properties: dict[str, str]) -> int:
    try:
        status = int(properties.get("ExecMainStatus", "1"))
    except ValueError:
        return 1
    if properties.get("ExecMainCode") in ("1", "exited") and 0 <= status <= 255:
        return status
    return 128 + status if 0 < status < 128 else 1


def redact_command(arguments: list[str]) -> list[str]:
    redacted: list[str] = []
    redact_next = False
    for argument in arguments:
        if redact_next:
            redacted.append("<redacted>")
            redact_next = False
            continue
        option, separator, _value = argument.partition("=")
        if option not in SENSITIVE_OPTIONS:
            redacted.append(argument)
        elif separator:
            redacted.append(f"{option}=<redacted>")
        else:
            redacted.append(option)
            redact_next = True
    return redacted


separator = sys.argv.index("--") if "--" in sys.argv else -1
if separator < 0 or separator == len(sys.argv) - 1:
    die("a non-empty command must follow --")
option_args = sys.argv[1:separator]
command = sys.argv[separator + 1 :]
command_digest = hashlib.sha256()
for argument in redact_command(command):
    command_digest.update(os.fsencode(argument))
    command_digest.update(b"\0")
command_sha256 = command_digest.hexdigest()

parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
parser.add_argument("--fixture", required=True)
parser.add_argument("--max-fixture-bytes", required=True)
parser.add_argument("--reserve-bytes", required=True)
parser.add_argument("--max-rss-bytes", required=True)
parser.add_argument("--interval-seconds", required=True)
parser.add_argument("--stdout", required=True)
parser.add_argument("--stderr", required=True)
parser.add_argument("--unit-name", required=True)
args = parser.parse_args(option_args)

max_fixture_bytes = parse_nonnegative_integer(
    args.max_fixture_bytes, "--max-fixture-bytes", positive=True
)
reserve_bytes = parse_nonnegative_integer(args.reserve_bytes, "--reserve-bytes")
max_rss_bytes = parse_nonnegative_integer(args.max_rss_bytes, "--max-rss-bytes", positive=True)
interval_seconds = parse_positive_seconds(args.interval_seconds)
if not UNIT_NAME.fullmatch(args.unit_name):
    die("--unit-name must match [A-Za-z0-9][A-Za-z0-9_-]{0,62}")

fixture = resolved_target(args.fixture, "--fixture")
fixture_parent = fixture.parent
stdout_path = resolved_target(args.stdout, "--stdout")
stderr_path = resolved_target(args.stderr, "--stderr")
verdict_path = stdout_path.with_name(f"{stdout_path.name}.guard.json")
custody_paths = (fixture, stdout_path, stderr_path, verdict_path)
if len(set(custody_paths)) != len(custody_paths):
    die("fixture, stdout, stderr, and verdict paths must be distinct")
if fixture.exists() or fixture.is_symlink():
    die("--fixture must not exist before launch")
for label, path in (
    ("--stdout", stdout_path),
    ("--stderr", stderr_path),
    ("verdict", verdict_path),
):
    if path.exists() or path.is_symlink():
        die(f"{label} path already exists: {path}")

try:
    manager = run_systemctl("show", "--property=Version", "--value")
except (FileNotFoundError, subprocess.CalledProcessError) as error:
    die(f"systemd user manager is required: {error}")
if not manager.stdout.strip():
    die("systemd user manager is required")

unit = f"{args.unit_name}.service"
existing = unit_properties(unit)
if existing.get("LoadState") != "not-found":
    die(f"unit already exists: {unit}")

start_free_bytes = shutil.disk_usage(fixture_parent).free
required_free_bytes = max_fixture_bytes + reserve_bytes
if start_free_bytes < required_free_bytes:
    die(
        f"insufficient free space: {start_free_bytes} bytes available, "
        f"{required_free_bytes} bytes required"
    )

reserved_artifacts = [stdout_path, stderr_path, verdict_path]
reserved: list[Path] = []
try:
    for artifact in reserved_artifacts:
        reserve_file(artifact)
        reserved.append(artifact)
except OSError as error:
    remove_files(reserved)
    die(f"cannot reserve custody artifact: {error}")

started_at = time.monotonic()
max_aggregate_rss_bytes = 0
peak_fixture_bytes = 0
min_free_bytes = start_free_bytes
cgroup_path: Path | None = None
started = False
stopped = False


def terminate_unit() -> None:
    global stopped
    if stopped or not started:
        return
    path = cgroup_path
    if path is None:
        properties = unit_properties(unit)
        control_group = properties.get("ControlGroup", "")
        if control_group:
            path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
    run_systemctl(
        "kill", "--kill-whom=all", "--signal=SIGKILL", unit, check=False
    )
    run_systemctl("stop", unit, check=False)
    if path is not None and not wait_for_empty_cgroup(path):
        raise RuntimeError(f"unit cgroup is not empty after stop: {path}")
    run_systemctl("reset-failed", unit, check=False)
    stopped = True


def write_verdict(exit_code: int, breach_reason: str | None) -> None:
    verdict = {
        "aggregate_max_rss_bytes": max_aggregate_rss_bytes,
        "breach_reason": breach_reason,
        "command_sha256": command_sha256,
        "elapsed_seconds": round(time.monotonic() - started_at, 6),
        "exit_code": exit_code,
        "interval_seconds": interval_seconds,
        "max_fixture_bytes": max_fixture_bytes,
        "max_rss_bytes": max_rss_bytes,
        "min_free_bytes": min_free_bytes,
        "peak_fixture_bytes": peak_fixture_bytes,
        "reserve_bytes": reserve_bytes,
        "schema": SCHEMA,
        "start_free_bytes": start_free_bytes,
        "unit_name": args.unit_name,
    }
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=verdict_path.parent,
            prefix=f".{verdict_path.name}.",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            os.fchmod(temporary.fileno(), 0o600)
            json.dump(verdict, temporary, sort_keys=True, separators=(",", ":"))
            temporary.write("\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        temporary_path.replace(verdict_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def handle_signal(signum: int, _frame: object) -> None:
    exit_code = 128 + signum
    try:
        terminate_unit()
    finally:
        remove_fixture(fixture)
    if started:
        write_verdict(exit_code, "signal")
    else:
        remove_files(reserved_artifacts)
    raise SystemExit(exit_code)


terminating_signals = (signal.SIGHUP, signal.SIGINT, signal.SIGQUIT, signal.SIGTERM)
for terminating_signal in terminating_signals:
    signal.signal(terminating_signal, handle_signal)

# This is resource containment for trusted same-user benchmark commands, not a sandbox.
try:
    launch = [
        "systemd-run",
        "--user",
        f"--unit={args.unit_name}",
        "--no-block",
        "--quiet",
        "--service-type=exec",
        "--remain-after-exit",
        f"--working-directory={os.getcwd()}",
        "--property=KillMode=control-group",
        "--property=TimeoutStopSec=5s",
        "--property=UMask=0077",
        f"--property=StandardOutput=file:{stdout_path}",
        f"--property=StandardError=file:{stderr_path}",
        "--",
        *command,
    ]
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, terminating_signals)
    try:
        subprocess.run(
            launch,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        started = True
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)

    deadline = time.monotonic() + 10.0
    properties: dict[str, str]
    while True:
        properties = unit_properties(unit)
        control_group = properties.get("ControlGroup", "")
        if control_group:
            cgroup_path = Path("/sys/fs/cgroup") / control_group.lstrip("/")
            break
        if properties.get("LoadState") == "not-found" or time.monotonic() >= deadline:
            raise RuntimeError("transient unit did not expose its control group")
        time.sleep(0.02)
    assert cgroup_path is not None

    next_sample = time.monotonic()
    breach_reason: str | None = None
    while True:
        now = time.monotonic()
        if now >= next_sample:
            aggregate_rss = aggregate_rss_bytes(cgroup_path)
            size = fixture_bytes(fixture)
            free = shutil.disk_usage(fixture_parent).free
            max_aggregate_rss_bytes = max(max_aggregate_rss_bytes, aggregate_rss)
            peak_fixture_bytes = max(peak_fixture_bytes, size)
            min_free_bytes = min(min_free_bytes, free)
            if aggregate_rss >= max_rss_bytes:
                breach_reason = "aggregate-rss"
            elif size > max_fixture_bytes:
                breach_reason = "fixture-size"
            elif free <= reserve_bytes:
                breach_reason = "free-space"
            if breach_reason is not None:
                terminate_unit()
                remove_fixture(fixture)
                write_verdict(BREACH_EXIT, breach_reason)
                raise SystemExit(BREACH_EXIT)
            next_sample = now + interval_seconds

        properties = unit_properties(unit)
        if properties.get("SubState") not in ("start", "start-pre", "running"):
            break
        time.sleep(min(0.05, max(0.001, next_sample - time.monotonic())))

    aggregate_rss = aggregate_rss_bytes(cgroup_path)
    size = fixture_bytes(fixture)
    free = shutil.disk_usage(fixture_parent).free
    max_aggregate_rss_bytes = max(max_aggregate_rss_bytes, aggregate_rss)
    peak_fixture_bytes = max(peak_fixture_bytes, size)
    min_free_bytes = min(min_free_bytes, free)
    if aggregate_rss >= max_rss_bytes:
        breach_reason = "aggregate-rss"
    elif size > max_fixture_bytes:
        breach_reason = "fixture-size"
    elif free <= reserve_bytes:
        breach_reason = "free-space"
    if breach_reason is not None:
        terminate_unit()
        remove_fixture(fixture)
        write_verdict(BREACH_EXIT, breach_reason)
        raise SystemExit(BREACH_EXIT)

    exit_code = child_exit_status(properties)
    terminate_unit()
    if exit_code != 0:
        remove_fixture(fixture)
    write_verdict(exit_code, None)
    raise SystemExit(exit_code)
except SystemExit:
    raise
except (FileNotFoundError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
    try:
        terminate_unit()
    finally:
        remove_fixture(fixture)
    print(f"run-g14-guarded.sh: {error}", file=sys.stderr)
    if started:
        write_verdict(INTERNAL_ERROR_EXIT, "guard-error")
    else:
        remove_files(reserved_artifacts)
    raise SystemExit(INTERNAL_ERROR_EXIT)
PY
