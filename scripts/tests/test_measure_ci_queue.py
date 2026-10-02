"""Offline tests of the CI queue measurement's runner-assignment criterion."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "measure-ci-queue.py"
SPEC = importlib.util.spec_from_file_location("measure_ci_queue", SCRIPT)
measure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(measure)


def job(name, status, runner_id, created, started, completed=None):
    return {
        "name": name,
        "status": status,
        "runner_id": runner_id,
        "created_at": f"2026-10-01T00:{created}Z",
        "started_at": f"2026-10-01T00:{started}Z",
        "completed_at": f"2026-10-01T00:{completed}Z" if completed else None,
    }


class RunnerAssignmentTests(unittest.TestCase):
    def test_queued_job_with_runner_zero_is_waiting_not_a_zero_second_sample(self) -> None:
        rows, waiting = measure.job_rows([job("clippy", "queued", 0, "00:00", "00:00")])
        self.assertEqual(rows, [])
        self.assertEqual(waiting, 1)

    def test_in_progress_job_without_runner_is_waiting(self) -> None:
        rows, waiting = measure.job_rows([job("fmt", "in_progress", None, "00:00", "00:00")])
        self.assertEqual(rows, [])
        self.assertEqual(waiting, 1)

    def test_assigned_job_samples_creation_to_start_latency(self) -> None:
        rows, waiting = measure.job_rows([job("fmt", "completed", 7, "00:00", "00:30", "01:30")])
        self.assertEqual(waiting, 0)
        [(name, queue, execution, _, _)] = rows
        self.assertEqual((name, queue, execution), ("fmt", 30.0, 60.0))

    def test_skipped_job_without_runner_is_neither_sampled_nor_waiting(self) -> None:
        rows, waiting = measure.job_rows([job("test-binary", "completed", 0, "00:00", "00:00", "00:00")])
        self.assertEqual((rows, waiting), ([], 0))

    def test_busy_runners_counts_assigned_jobs_executing_at_the_instant(self) -> None:
        rows, _ = measure.job_rows(
            [
                job("covers", "completed", 1, "00:00", "00:10", "01:00"),
                job("starts-later", "completed", 2, "00:00", "00:40", "01:00"),
                job("ended-before", "completed", 3, "00:00", "00:05", "00:20"),
                job("running", "in_progress", 4, "00:00", "00:20"),
                job("queued", "queued", 0, "00:00", "00:00"),
            ]
        )
        self.assertEqual(measure.busy_runners_at(measure.dt("2026-10-01T00:00:30Z"), rows), 2)


class PaginationTests(unittest.TestCase):
    def test_paginate_reads_until_a_short_page(self) -> None:
        pages = {1: [{"id": index} for index in range(measure.PER_PAGE)], 2: [{"id": -1}]}
        calls = []

        def fake_api(path):
            calls.append(path)
            return {"jobs": pages[int(path.rsplit("page=", 1)[1])]}

        with patch.object(measure, "api", fake_api):
            items = measure.paginate("/repos/x/actions/runs/1/jobs", "jobs")
        self.assertEqual(len(items), measure.PER_PAGE + 1)
        self.assertEqual(len(calls), 2)

    def test_runs_stop_at_the_page_that_crosses_the_window_start(self) -> None:
        inside = [{"id": index, "created_at": "2026-10-01T12:00:00Z"} for index in range(measure.PER_PAGE)]
        crossing = inside[:10] + [{"id": -1, "created_at": "2026-09-30T00:00:00Z"}] * (measure.PER_PAGE - 10)
        pages = {1: inside, 2: crossing}
        calls = []

        def fake_api(path):
            calls.append(path)
            return {"workflow_runs": pages[int(path.rsplit("page=", 1)[1])]}

        with patch.object(measure, "api", fake_api), patch.object(measure, "SINCE", "2026-10-01T00:00:00Z"):
            found = measure.runs()
        self.assertEqual(len(found), measure.PER_PAGE + 10)
        self.assertEqual(len(calls), 2)


if __name__ == "__main__":
    unittest.main()
