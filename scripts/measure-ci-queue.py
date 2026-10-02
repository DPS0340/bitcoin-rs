"""Measure CI runner-queue pressure per workflow (issues #1349, #1351).

Reports per-job queue latency (creation -> runner assignment), execution
duration, and how many jobs held a runner at each job start, so queue delay
is never attributed to CI command cost.

A job counts as runner-assigned only once GitHub reports it: status
`in_progress` or `completed` with a nonzero `runner_id`. A job can still be
`queued` with `runner_id` 0 while `started_at == created_at`; such jobs are
reported as waiting, never sampled as a zero-second assignment.

Runner occupancy counts jobs from every workflow in the window that held an
assigned runner at the sampled instant, not workflow runs: a queued run holds
no runner.

Usage: gh auth + `python3 scripts/measure-ci-queue.py` (override repo via
GITHUB_REPOSITORY)."""
import datetime
import json
import os
import statistics
import subprocess

REPO = os.environ.get("GITHUB_REPOSITORY", "gosuda/bitcoin-rs")
# Window start for every filter below. Defaults to a rolling 48 h so the
# script still measures after the "before" data ages out; override for a
# fixed window, e.g. CI_SINCE=2026-09-29T00:00:00Z (the before-measurement
# window used in PR #1350).
SINCE = os.environ.get(
    "CI_SINCE",
    (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"),
)
PER_PAGE = 100


def api(path):
    out = subprocess.run(["gh", "api", path], capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr[:300])
    return json.loads(out.stdout)


def paginate(path, key):
    """Every item under `key` across all pages of a list endpoint."""
    sep = "&" if "?" in path else "?"
    items, page = [], 1
    while True:
        batch = api(f"{path}{sep}per_page={PER_PAGE}&page={page}")[key]
        items.extend(batch)
        if len(batch) < PER_PAGE:
            return items
        page += 1


def runs():
    """Every workflow run created since SINCE.

    Runs arrive newest first, so the page that reaches past the window start
    is the last one needed."""
    found, page = [], 1
    while True:
        batch = api(f"/repos/{REPO}/actions/runs?per_page={PER_PAGE}&page={page}")["workflow_runs"]
        found.extend(run for run in batch if run["created_at"] >= SINCE)
        if len(batch) < PER_PAGE or batch[-1]["created_at"] < SINCE:
            return found
        page += 1


def dt(x):
    return datetime.datetime.fromisoformat(x.replace("Z", "+00:00"))


def runner_assigned(job):
    """Whether GitHub reports `job` as handed to a runner."""
    return job.get("status") in ("in_progress", "completed") and bool(job.get("runner_id"))


def job_rows(jobs):
    """(name, queue s, exec s or None, start, end or None) for each
    runner-assigned job, and how many jobs are still waiting for a runner.

    A completed job that never had a runner, such as a skipped one, is
    neither sampled nor waiting."""
    rows, waiting = [], 0
    for j in jobs:
        if runner_assigned(j):
            c, s = dt(j["created_at"]), dt(j["started_at"])
            e = dt(j["completed_at"]) if j.get("completed_at") else None
            rows.append((j["name"], (s - c).total_seconds(), (e - s).total_seconds() if e else None, s, e))
        elif j.get("status") != "completed":
            waiting += 1
    return rows, waiting


def busy_runners_at(t, rows):
    """Runner-assigned jobs executing at `t`, i.e. `start <= t < end`."""
    return sum(1 for _, _, _, s, e in rows if s <= t and (e is None or t < e))


def workflow_runs(window, workflow, event=None):
    return [
        run for run in window
        if run["path"].endswith(f"/{workflow}") and (event is None or run["event"] == event)
    ]


def summarize(label, selected, rows_by_run, all_rows):
    qs, exs, loads, details, waiting = [], [], [], [], 0
    for run in selected:
        rows, run_waiting = rows_by_run[run["id"]]
        waiting += run_waiting
        for name, q, ex, s, _ in rows:
            busy = busy_runners_at(s, all_rows)
            qs.append(q)
            loads.append(busy)
            if ex is not None:
                exs.append(ex)
            details.append((run["id"], run["event"], name, round(q), round(ex) if ex is not None else None, busy))
    if not qs:
        print(label, "no runner-assigned jobs; still waiting:", waiting)
        return
    qs.sort()
    print(f"\n== {label} (n={len(qs)} runner-assigned jobs, {waiting} still waiting) ==")
    print(f" queue s: median={statistics.median(qs):.0f} p90={qs[min(len(qs) - 1, int(len(qs) * 0.9))]:.0f} max={max(qs):.0f}")
    if exs:
        print(f" exec  s: median={statistics.median(exs):.0f} max={max(exs):.0f}")
    print(f" jobs holding a runner at job start: median={statistics.median(loads):.0f} max={max(loads)}")
    for d in details[:10]:
        print("  run%s %s %-22s queue=%ss exec=%s busy=%s" % d)


def main():
    window = runs()
    rows_by_run = {
        run["id"]: job_rows(paginate(f"/repos/{REPO}/actions/runs/{run['id']}/jobs", "jobs"))
        for run in window
    }
    all_rows = [row for rows, _ in rows_by_run.values() for row in rows]

    summarize("PR ci.yml (pull_request fast lanes)", workflow_runs(window, "ci.yml", "pull_request"), rows_by_run, all_rows)
    summarize("main push ci.yml (fast lanes)", workflow_runs(window, "ci.yml", "push"), rows_by_run, all_rows)
    summarize("ci-main (main.yml deep lanes)", workflow_runs(window, "main.yml"), rows_by_run, all_rows)
    print("\n== raw: slowest-queued PR jobs ==")
    pr = [
        (q, run["id"], name, round(ex) if ex is not None else 0)
        for run in workflow_runs(window, "ci.yml", "pull_request")
        for name, q, ex, _, _ in rows_by_run[run["id"]][0]
    ]
    for q, rid, name, ex in sorted(pr, reverse=True)[:8]:
        print(f"  queue={q:7.0f}s run={rid} {name} exec={ex}s")


if __name__ == "__main__":
    main()
