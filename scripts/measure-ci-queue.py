import os
import subprocess, json, datetime, statistics
"""Measure CI runner-queue pressure per workflow (issue #1349).

Reports per-job queue latency (creation -> runner assignment), execution
duration, and how many workflow runs were concurrently active at each
job start, so queue delay is never attributed to CI command cost.

Usage: gh auth + `python3 scripts/measure-ci-queue.py` (override repo via
GITHUB_REPOSITORY)."""
REPO = os.environ.get("GITHUB_REPOSITORY", "gosuda/bitcoin-rs")
# Window start for every filter below. Defaults to a rolling 48 h so the
# script still measures after the "before" data ages out; override for a
# fixed window, e.g. CI_SINCE=2026-09-29T00:00:00Z (the before-measurement
# window used in PR #1350).
SINCE = os.environ.get(
    "CI_SINCE",
    (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=48)).strftime("%Y-%m-%dT%H:%M:%SZ"),
)
def api(path):
    out=subprocess.run(["gh","api",path],capture_output=True,text=True,timeout=120)
    if out.returncode!=0: raise RuntimeError(out.stderr[:300])
    return json.loads(out.stdout)

def runs(wf,n=25):
    d=api(f"/repos/{REPO}/actions/workflows/{wf}/runs?per_page={n}")
    return [r for r in d["workflow_runs"] if r["created_at"]>=SINCE]

# concurrent load: all runs updated in the window
def dt(x): return datetime.datetime.fromisoformat(x.replace("Z","+00:00"))
def load_at(t, all_runs):
    c=0
    for r in all_runs:
        st=dt(r.get("run_started_at") or r["created_at"])
        en=dt(r["updated_at"])
        if st<=t<en: c+=1
    return c

ci=runs("ci.yml"); main=runs("main.yml")
allr=api(f"/repos/{REPO}/actions/runs?per_page=100")["workflow_runs"]
allr=[r for r in allr if r["created_at"]>=SINCE]

def job_rows(run):
    jobs=api(f"/repos/{REPO}/actions/runs/{run['id']}/jobs?per_page=50")["jobs"]
    rows=[]
    for j in jobs:
        s=j.get("started_at")
        if not s or s.startswith("1970"): continue  # still queued: no runner yet
        c=datetime.datetime.fromisoformat(j["created_at"].replace("Z","+00:00"))
        s=datetime.datetime.fromisoformat(s.replace("Z","+00:00"))
        e=j.get("completed_at")
        e=datetime.datetime.fromisoformat(e.replace("Z","+00:00")) if e else None
        rows.append((j["name"],(s-c).total_seconds(),((e-s).total_seconds() if e else None),s))
    return rows

def summarize(label, wf, event_filter=None):
    qs,exs,loads=[],[],[]
    details=[]
    for r in runs(wf)[:12]:
        if event_filter and r["event"]!=event_filter: continue
        for name,q,ex,s in job_rows(r):
            qs.append(q); loads.append(load_at(s,allr))
            if ex: exs.append(ex)
            details.append((r["id"],r["event"],name,round(q),round(ex) if ex else None,load_at(s,allr)))
    if not qs: print(label,"no data"); return
    qs.sort(); 
    print(f"\n== {label} (n={len(qs)} jobs) ==")
    print(f" queue s: median={statistics.median(qs):.0f} p90={qs[int(len(qs)*0.9)]:.0f} max={max(qs):.0f}")
    if exs: print(f" exec  s: median={statistics.median(exs):.0f} max={max(exs):.0f}")
    print(f" concurrent runs at job start: median={statistics.median(loads):.0f} max={max(loads)}")
    for d in details[:10]: print("  run%s %s %-22s queue=%ss exec=%s load=%s"%d)

summarize("PR ci.yml (pull_request fast lanes)","ci.yml","pull_request")
summarize("main push ci.yml (fast lanes)","ci.yml","push")
summarize("ci-main (main.yml deep lanes)","main.yml")
print("\n== raw: slowest-queued PR jobs ==")
pr=[]
for r in runs("ci.yml")[:15]:
    if r["event"]!="pull_request": continue
    for name,q,ex,s in job_rows(r): pr.append((q,r["id"],name,round(ex) if ex else 0))
for q,rid,name,ex in sorted(pr,reverse=True)[:8]:
    print(f"  queue={q:7.0f}s run={rid} {name} exec={ex}s")
