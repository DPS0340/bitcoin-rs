#!/usr/bin/env bash
# Run the wire_latency harness RUNS times and aggregate per-scenario
# min/avg/max/stdev of the per-run medians (p50) and means (avg).
#
# Usage: scripts/run-pr2-wire-bench.sh [RUNS]
set -euo pipefail

RUNS="${1:-10}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/target/release/examples/wire_latency"

cargo build --release -p bitcoin-rs-p2p --example wire_latency

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

for i in $(seq 1 "$RUNS"); do
    echo "run $i/$RUNS ..." >&2
    "$BIN" | tail -n +2 >>"$OUT"
done

python3 - "$OUT" <<'EOF'
import statistics
import sys

rows = {}
with open(sys.argv[1]) as fh:
    for line in fh:
        scenario, link, _iters, min_us, avg_us, p50, p95, max_us = line.split(",")
        rows.setdefault((scenario, link), []).append(
            {k: float(v) for k, v in
             [("min", min_us), ("avg", avg_us), ("p50", p50), ("p95", p95), ("max", max_us)]}
        )

def stats(values):
    return (min(values), statistics.fmean(values), max(values),
            statistics.stdev(values) if len(values) > 1 else 0.0)

print("| scenario | link | runs | p50 min | p50 avg | p50 max | p50 stdev | avg-of-avg | p95 avg |")
print("|---|---|---|---|---|---|---|---|---|")
for (scenario, link), runs in sorted(rows.items()):
    p50_min, p50_avg, p50_max, p50_sd = stats([r["p50"] for r in runs])
    _, avg_avg, _, _ = stats([r["avg"] for r in runs])
    _, p95_avg, _, _ = stats([r["p95"] for r in runs])
    print(f"| {scenario} | {link} | {len(runs)} | {p50_min:,.1f} | {p50_avg:,.1f} | "
          f"{p50_max:,.1f} | {p50_sd:,.1f} | {avg_avg:,.1f} | {p95_avg:,.1f} |")
EOF
