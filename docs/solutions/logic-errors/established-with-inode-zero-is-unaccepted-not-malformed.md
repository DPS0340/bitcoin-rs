---
title: ESTABLISHED with inode 0 means unaccepted, not malformed
date: 2026-08-08
category: docs/solutions/logic-errors
module: scripts/measure-g14-electrum-rss.sh (accepted-connection ownership proof)
problem_type: logic_error
component: benchmarking
severity: medium
applies_when:
  - "Code proves a PID owns a TCP connection by reading /proc/<pid>/net/tcp"
  - "A socket check passes locally and fails only on a loaded CI runner"
  - "A test failure names a malformed inode"
related_components:
  - benchmark_harness
  - electrum
tags:
  - proc-net-tcp
  - listen-backlog
  - race-condition
  - ci-only-failure
  - false-negative
---

# ESTABLISHED with inode 0 means unaccepted, not malformed

## Symptom

`electrum_rss_measurement_rejects_empty_history_for_real_corpus` failed on
GitHub runners and passed on every local run:

```
error: /proc/23832/net/tcp ESTABLISHED entry matching 127.0.0.1:37695
       <- 127.0.0.1:56908 has malformed inode
```

The failure was on `main` before any of this branch's work, so it looked like
environment flakiness that no code change could reach.

## Cause

The kernel completes the TCP three-way handshake by itself. A connection is
ESTABLISHED as soon as the handshake finishes and waits in the listen backlog
until the server calls `accept()`. Only `accept()` allocates the `struct file`
that gives the socket an inode. Between those two moments the row in
`/proc/<pid>/net/tcp` is ESTABLISHED with **inode 0**.

`established_socket_inodes_for_connection` read inode 0 and called `die`. The
enclosing `require_pid_owns_accepted_connection` already polled with a deadline,
so the transient state was survivable, but the parser aborted the whole script
before the loop could retry.

Local runs never saw it because the fixture accepts within microseconds. A
loaded CI runner delays the server enough for the reader to win the race.

## Fix

Count inode-0 rows and `continue`, letting the existing poll loop retry.

```python
if inode <= 0:
    unaccepted += 1
    continue
inodes.add(inode)
```

This cannot weaken the ownership proof, and that is the load-bearing argument:
the check returns only inodes in `match_inodes & process_socket_inodes(pid)`.
An inode of 0 appears in no process fd table, so it could never survive that
intersection and could never have proved ownership. Dying on it was a pure
false-negative generator.

The timeout message now distinguishes "never accepted" from "never present",
so a genuine hang still reports accurately.

## Reproducing it deterministically

Listen without accepting:

```python
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)  # no accept()
cli = socket.socket(); cli.connect(srv.getsockname())
# /proc/self/net/tcp now shows the server-side row ESTABLISHED with inode 0
```

The regression test applies the same idea by delaying `accept()` 1.5s in the
fake node. Reverting the fix makes it fail with the exact CI message, so the
test is mutation-verified rather than merely present.

## Guidance

1. **A CI-only failure is a race until proven otherwise.** "Works locally"
   means the local timing wins, not that the code is correct. Find the ordering
   that CI exposes and reproduce it deliberately.
2. **Never gate a check on `CI` or swap it for a weaker probe to get green.**
   That converts a correctness question into a permanent blind spot. Establish
   whether the check is right first; here it was right and only its failure
   handling was wrong.
3. **Before deleting or loosening a validation, ask what it could ever have
   admitted.** If the rejected input could not have passed the downstream test
   anyway, the rejection was dead weight and removing it costs no safety.
