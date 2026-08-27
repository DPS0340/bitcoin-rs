# Task: PR2 wire-bench evidence (main vs PR)

## Goals

- Benchmark matrix compares `main` behavior (5x `write_all`, Nagle on) against
  the PR behavior (`write_vectored`, `TCP_NODELAY`), plus the two intermediate
  combinations so each effect is attributed separately.
- Throughput path: criterion bench `crates/p2p/benches/write_message.rs`
  (4 configs x {ping, block}).
- Latency path: `crates/p2p/examples/wire_latency.rs` measures ping/pong
  round-trip latency for the 4 configs over loopback and over an emulated
  20 ms one-way WAN link (userspace store-and-forward delay proxy).
- `scripts/run-pr2-wire-bench.sh` runs the latency harness 10 times and
  aggregates min/avg/max/stdev per scenario.
- Results and rationale written to `PR2.md`.

## Verification

- `cargo bench -p bitcoin-rs-p2p --bench write_message` runs the matrix.
- `scripts/run-pr2-wire-bench.sh` prints a markdown table with 10-run stats.
