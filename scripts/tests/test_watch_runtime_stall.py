"""Offline monitoring/capture regressions; synthetic debugger is not a live-node proof."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import watch_runtime_stall as watchdog


class RuntimeStallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.log = self.root / "node.log"
        self.log.write_bytes(b"old sync progress\n")

    def test_old_partial_and_unrelated_log_lines_do_not_refresh_cadence(self) -> None:
        cursor, fresh = watchdog.read_progress(self.log, None)
        self.assertFalse(fresh)
        with self.log.open("ab") as stream:
            stream.write(b"other work\nsync pro")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        with self.log.open("ab") as stream:
            stream.write(b"gress height=42\n")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertTrue(fresh)
        _, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)

    def test_rotation_truncation_and_large_backlog_are_bounded(self) -> None:
        cursor, _ = watchdog.read_progress(self.log, None)
        self.log.rename(self.root / "old.log")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        self.log.write_bytes(b"sync progress\n")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertTrue(fresh)
        self.log.write_bytes(b"x" * (2 * watchdog.READ_LIMIT) + b"\nsync progress\n")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertTrue(fresh)
        self.assertIsNotNone(cursor)
        self.log.write_bytes(b"sync progress\n")
        _, fresh = watchdog.read_progress(self.log, cursor)
        self.assertTrue(fresh)

    def test_copy_truncate_regrowth_rescans_instead_of_resuming(self) -> None:
        cursor, _ = watchdog.read_progress(self.log, None)
        with self.log.open("ab") as stream:
            stream.write(b"sync pro")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        self.assertNotEqual(cursor.suffix, b"")
        # Steady state: unchanged bytes under the carried suffix keep the
        # cursor in place instead of resetting it to a full rescan.
        steady, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        self.assertEqual(steady.offset, cursor.offset)
        self.assertEqual(steady.suffix, cursor.suffix)
        # A plain append past the carried suffix resumes instead of
        # rescanning; a rescan would re-read the old complete progress line
        # and report it as fresh.
        with self.log.open("ab") as stream:
            stream.write(b"other work\n")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        self.assertGreater(cursor.offset, steady.offset)
        # Re-arm a partial tail so the truncation poll has a suffix to
        # verify.
        with self.log.open("ab") as stream:
            stream.write(b"sync pro")
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertFalse(fresh)
        self.assertNotEqual(cursor.suffix, b"")
        # Copy-truncate refills the same inode up to the previous offset and
        # drops the partial tail; resuming at the stale offset would read
        # nothing and miss the fresh progress line.
        with self.log.open("r+b") as stream:
            stream.truncate(0)
            stream.write(b"sync progress\n" + b"x" * (cursor.offset - len(b"sync progress\n")))
        self.assertGreaterEqual(self.log.stat().st_size, cursor.offset)
        cursor, fresh = watchdog.read_progress(self.log, cursor)
        self.assertTrue(fresh)

    def test_missing_cadence_expires_without_rpc_or_node_locks(self) -> None:
        identity = watchdog.Process(99, "100")
        with patch.object(watchdog, "process", return_value=identity), \
             patch.object(watchdog.time, "monotonic", side_effect=[0.0, 0.0, 179.0, 180.0]), \
             patch.object(watchdog.time, "sleep"):
            self.assertTrue(watchdog.wait_for_stall(identity, self.log, 180))

    def test_exit_and_pid_reuse_do_not_attach_to_a_replacement(self) -> None:
        identity = watchdog.Process(99, "100")
        for current in (None, watchdog.Process(99, "101")):
            with self.subTest(current=current), patch.object(watchdog, "process", return_value=current):
                self.assertFalse(watchdog.wait_for_stall(identity, self.log, 180))
                with self.assertRaises(ProcessLookupError):
                    watchdog.capture(identity, self.log, self.root, "/not-a-debugger")
        self.assertFalse(list(self.root.glob("stall-*")))

    def test_new_progress_restarts_the_deadline(self) -> None:
        identity = watchdog.Process(99, "100")
        cursor, _ = watchdog.read_progress(self.log, None)
        with patch.object(watchdog, "process", side_effect=[identity, identity, None]), \
             patch.object(watchdog, "read_progress", side_effect=[(cursor, False), (cursor, False), (cursor, True)]), \
             patch.object(watchdog.time, "monotonic", side_effect=[0.0, 179.0, 180.0]), \
             patch.object(watchdog.time, "sleep"):
            self.assertFalse(watchdog.wait_for_stall(identity, self.log, 180))

    def test_capture_preserves_failure_and_only_accepts_complete_debugger_output(self) -> None:
        identity = watchdog.process(os.getpid())
        assert identity is not None
        executable = self.root / "fake-gdb"
        for rc, text, complete in (
            (0, "Thread 1 (LWP 1):\n#0  main () at src/main.rs:12\nSTALL_CAPTURE_COMPLETE", True),
            (1, "permission denied", False),
            (0, "partial", False),
            (0, "ptrace: Operation not permitted.\nNo threads.\nSTALL_CAPTURE_COMPLETE", False),
            (0, "Thread 1 (LWP 1):\n#0  main () at src/main.rs:12\n"
                "Thread 2 (LWP 2):\nerror reading frames\nSTALL_CAPTURE_COMPLETE", False),
            (0, "Thread 1 (LWP 1):\n#0  0x00007f9b4000 in ?? ()\nSTALL_CAPTURE_COMPLETE", False),
            (0, "Thread 1 (LWP 1):\nThread " + "x" * (2 * watchdog.READ_LIMIT) + "\n"
                "Thread 2 (LWP 2):\n#0  main () at src/main.rs:12\nSTALL_CAPTURE_COMPLETE", False),
        ):
            with self.subTest(rc=rc, text=text):
                executable.write_text(f"#!{sys.executable}\nprint({text!r})\nraise SystemExit({rc})\n")
                executable.chmod(0o755)
                if complete:
                    directory = watchdog.capture(identity, self.log, self.root, str(executable))
                    self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
                    result = json.loads((directory / "result.json").read_text())
                    self.assertTrue(result["complete"])
                    self.assertIn("thread apply all -c bt 32", (directory / "capture.gdb").read_text())
                else:
                    with self.assertRaises(RuntimeError):
                        watchdog.capture(identity, self.log, self.root, str(executable))
        results = [json.loads(path.read_text()) for path in self.root.glob("stall-*/result.json")]
        self.assertEqual(len(results), 7)
        self.assertEqual(sum(result["complete"] for result in results), 1)

    def test_pre_attach_exit_writes_an_incomplete_result(self) -> None:
        identity = watchdog.process(os.getpid())
        assert identity is not None
        with patch.object(watchdog, "process", side_effect=[identity, None]):
            with self.assertRaises(ProcessLookupError):
                watchdog.capture(identity, self.log, self.root, "/not-a-debugger")
        result = json.loads(next(self.root.glob("stall-*/result.json")).read_text())
        self.assertFalse(result["complete"])
        self.assertEqual(result["pid"], identity.pid)
        self.assertEqual(result["start_ticks"], identity.start_ticks)
        self.assertIn("exited", result["reason"])

    def test_exit_before_kernel_snapshot_writes_an_incomplete_result(self) -> None:
        identity = watchdog.process(os.getpid())
        assert identity is not None
        with patch.object(watchdog, "process", return_value=identity), \
             patch.object(Path, "iterdir", side_effect=FileNotFoundError):
            with self.assertRaises(ProcessLookupError) as raised:
                watchdog.capture(identity, self.log, self.root, "/not-a-debugger")
        directory = next(self.root.glob("stall-*"))
        self.assertIn(str(directory), str(raised.exception))
        result = json.loads((directory / "result.json").read_text())
        self.assertFalse(result["complete"])
        self.assertEqual(result["pid"], identity.pid)
        self.assertEqual(result["start_ticks"], identity.start_ticks)
        self.assertIn("kernel snapshot", result["reason"])

    def test_identity_change_after_attach_forces_an_incomplete_result(self) -> None:
        identity = watchdog.process(os.getpid())
        assert identity is not None
        executable = self.root / "fake-gdb"
        text = "Thread 1 (LWP 1):\n#0  main () at src/main.rs:12\nSTALL_CAPTURE_COMPLETE"
        executable.write_text(f"#!{sys.executable}\nprint({text!r})\nraise SystemExit(0)\n")
        executable.chmod(0o755)
        replacement = watchdog.Process(identity.pid, "1")
        with patch.object(watchdog, "process", side_effect=[identity, identity, replacement]):
            with self.assertRaises(RuntimeError):
                watchdog.capture(identity, self.log, self.root, str(executable))
        result = json.loads(next(self.root.glob("stall-*/result.json")).read_text())
        self.assertFalse(result["complete"])
        self.assertTrue(result["identity_changed_after_attach"])

    def test_attach_preflight_fails_fast_when_ptrace_is_denied(self) -> None:
        identity = watchdog.Process(99, "100")
        executable = self.root / "fake-gdb"
        executable.write_text(
            f"#!{sys.executable}\nprint('ptrace: Operation not permitted.')\nraise SystemExit(0)\n")
        executable.chmod(0o755)
        with self.assertRaises(RuntimeError):
            watchdog.preflight_attach(identity, str(executable))
        executable.write_text(f"#!{sys.executable}\nraise SystemExit(0)\n")
        executable.chmod(0o755)
        watchdog.preflight_attach(identity, str(executable))


if __name__ == "__main__":
    unittest.main()
