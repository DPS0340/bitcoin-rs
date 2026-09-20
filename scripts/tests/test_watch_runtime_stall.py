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
            (0, "Thread 1\n#0 blocking_call ()\nSTALL_CAPTURE_COMPLETE", True),
            (1, "permission denied", False),
            (0, "partial", False),
            (0, "ptrace: Operation not permitted.\nNo threads.\nSTALL_CAPTURE_COMPLETE", False),
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
        self.assertEqual(len(results), 4)
        self.assertEqual(sum(result["complete"] for result in results), 1)


if __name__ == "__main__":
    unittest.main()
