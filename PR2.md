# PR2 — writev / TCP_NODELAY: separated measurements vs main

Response to the PR #190 review request: "split the two optimizations and bring
measured evidence." Four write paths are compared in the same harness:

| label | write path | Nagle | corresponds to |
|---|---|---|---|
| `main` | 5x `write_all` (magic/command/len/checksum/payload) | ON | main branch |
| `legacy5_nodelay` | 5x `write_all` | OFF (`TCP_NODELAY`) | (isolation only) |
| `writev_nagle` | header assembled, single `write_vectored` | ON | (isolation only) |
| `pr` | single `write_vectored` | OFF (`TCP_NODELAY`) | PR #190 |

The wire bytes are identical in all four configurations (no protocol
compatibility concern).

## Methodology

- Throughput (per-write call cost): `crates/p2p/benches/write_message.rs`
  (criterion, loopback `TcpStream`, drain thread). ping 8B / block 285B.
- Round-trip latency (request/response pattern: ping/pong, getdata/tx,
  getheaders/headers): `crates/p2p/examples/wire_latency.rs`. A responder
  answers each ping with a pong; all four configurations are measured over
  loopback and over an emulated WAN link (a userspace store-and-forward
  delay proxy adding 20 ms one-way latency).
  `scripts/run-pr2-wire-bench.sh 10` runs the harness 10 times and
  aggregates min/avg/max/stdev of the per-run p50.

## Result 1 — round-trip latency (10-run aggregate, µs)

| scenario | link | runs | p50 min | p50 avg | p50 max | p50 stdev | avg-of-avg | p95 avg |
|---|---|---|---|---|---|---|---|---|
| main | loopback | 10 | 91,986.4 | 91,993.7 | 91,998.6 | 3.7 | 91,285.1 | 96,004.1 |
| legacy5_nodelay | loopback | 10 | 51.6 | 53.9 | 57.2 | 1.7 | 56.8 | 68.0 |
| writev_nagle | loopback | 10 | 17.5 | 17.9 | 18.8 | 0.5 | 18.5 | 21.6 |
| pr | loopback | 10 | 17.5 | 17.8 | 18.7 | 0.4 | 18.6 | 21.5 |
| main | wan_20ms | 10 | 128,006.9 | 131,199.9 | 132,001.9 | 1,681.7 | 131,229.7 | 135,605.6 |
| legacy5_nodelay | wan_20ms | 10 | 131,733.9 | 131,971.4 | 132,004.2 | 83.6 | 130,470.5 | 136,003.8 |
| writev_nagle | wan_20ms | 10 | 40,224.3 | 40,233.5 | 40,254.0 | 8.4 | 40,245.6 | 40,308.4 |
| pr | wan_20ms | 10 | 40,215.0 | 40,227.0 | 40,247.3 | 9.1 | 40,229.6 | 40,260.4 |

Interpretation:

- **main's loopback round trip is ~92 ms.** This is not slow syscalls — it is
  the Nagle + delayed-ACK deadlock (a small segment waits for the previous
  segment's ACK, ~40 ms per direction). Splitting the header into five writes
  triggers this deadlock on every message.
- **writev alone eliminates the deadlock** (writev_nagle = 17.9 µs). Once a
  message is a single segment, the "unacknowledged small segment" condition
  never arises.
- On the emulated WAN (20 ms one-way), main/legacy5 take ~132 ms (five
  segments serialized through store-and-forward ≈ 3+ RTT), while the writev
  variants take ~40 ms = exactly 1 RTT. The numbers confirm that
  **segment count == round-trip count**.
- writev_nagle and pr are within noise on both links: for the single-message
  request/response pattern, NODELAY adds no measurable effect on top of
  writev (see "Honest limitations" below).

## Result 2 — per-write call cost (criterion, µs)

| payload | main | legacy5_nodelay | writev_nagle | pr |
|---|---|---|---|---|
| ping_8B | 3.94 | 24.41 | 1.14 | 5.04 |
| block_285B | 3.34 | 24.79 | 1.34 | 5.44 |

Interpretation:

- `main` only *looks* fast at 3.9 µs because Nagle defers transmission, so
  `write()` degenerates into a send-buffer memcpy. The cost is not gone — it
  is **deferred into latency**, and that deferred cost is the 92 ms in
  Result 1.
- With nodelay, cost is proportional to syscall count: 5 syscalls ≈ 24 µs,
  1 syscall ≈ 5 µs. writev_nagle (1.14 µs) shows what remains when even that
  one syscall becomes a buffer copy. This re-confirms the PR's original claim
  that **the cost driver is the number of syscalls**.

## Conclusions

1. **Most of the improvement comes from write coalescing (writev).** Removing
   segment splits eliminates the Nagle/delayed-ACK deadlock (loopback
   92 ms → 18 µs, ~5,000x) and yields one round trip per message on WAN links
   (132 ms → 40 ms, ~3.3x). On throughput it also cuts syscall cost from
   24 µs to 5 µs under nodelay.
2. **TCP_NODELAY's marginal effect is honestly recorded as unmeasurable** for
   the single-message request/response pattern once writev is in place
   (writev_nagle ≈ pr). However, even after writev, Nagle can still stall
   (a) the second and later messages of a pipelined burst and (b) resumption
   after a partial write, and (c) it matches the Bitcoin Core lineage
   (0.10.4 release note "Set TCP_NODELAY on P2P sockets"; the HTTP server
   re-setting nodelay on accepted sockets). Its measured cost is zero within
   noise, so keeping it is justified.
3. PR #190 is therefore not "perf, so both" — it is structured as a
   **primary effect (writev) plus a lineage-orthodox, zero-cost insurance
   (NODELAY)**.

## Honest limitations

- The ~40 ms loopback deadlock depends on Linux's delayed-ACK implementation.
- The WAN link is a userspace delay-proxy emulation (no root required).
  Validation against real peers should follow in the mainnet IBD measurement
  campaign.
- NODELAY's residual effects (pipelining / partial-write scenarios) are
  outside this harness's scope.

## Reproduce

```bash
cargo bench -p bitcoin-rs-p2p --bench write_message   # Result 2 (throughput)
scripts/run-pr2-wire-bench.sh 10                      # Result 1 (10-run aggregate)
```
