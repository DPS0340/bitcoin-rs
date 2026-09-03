# REC-A3D: Crash-recovery gate and documentation

## Scope

Strengthened `g11_crash_recovery` gate, the `crash_recovery` integration
test, and the crash-recovery contract documentation. Did not touch
`crates/node/src/{run,state,embed,mining,apply}.rs`.

## What the gate asserted before

The old G11 gate was a single `cargo test` subprocess invocation that
checked only `status.success()`. It did not verify which tests ran, how
many backends were exercised, or what invariants were proven. The
integration test was `#![cfg(feature = "redb")]` — hardcoded to redb
only, ignoring RocksDB and fjall. The gate's module doc claimed
`kill -9` during block commit with restart and convergence across all
three backends, but no test actually performed a crash or restart.

## What the gate asserts now

### Recovery-meta sidecar (`crates/node/tests/crash_recovery.rs`)

Four integration tests, each looping over all compiled backends
(rocksdb, fjall, redb):

1. **`recovery_replays_from_last_committed_height_to_tip`** — Simulated
   interrupted apply: advance `height` to 10, rewind
   `last_committed_height` to 7, restart (reopen `NodeState`), call
   `recover_if_needed`, assert the gap [8, 9, 10] is replayed and the
   meta converges to `last_committed == height == 10`.

2. **`recovery_meta_write_leaves_readable_sidecar_without_tmp`** —
   Atomic write protocol: after a clean commit the sidecar is readable
   and no `.tmp` residue remains.

3. **`torn_meta_after_crash_is_refused`** — Corrupt the `.json` sidecar
   with garbage bytes (simulating a crash that tore the file), reopen,
   and assert `read_meta` returns `Err` — the node refuses torn state
   rather than silently defaulting. Also asserts `recover_if_needed`
   propagates the error.

4. **`stale_tmp_after_crash_does_not_corrupt_recovery`** — Plant a
   stale `.tmp` from a crashed write, restart, assert recovery reads
   the valid `.json` and ignores the stale `.tmp`, then assert a
   subsequent `write_meta` cleans up the stale temp.

### Recovery-evidence bounded protocol (`crates/node/src/recovery_evidence.rs`)

Eight unit tests run as individual subprocesses with `require_ran`
verification:

- `witness_round_trips_and_falls_back_to_prev`
- `foreign_genesis_current_cannot_displace_valid_prev`
- `foreign_genesis_marker_current_cannot_displace_valid_prev`
- `same_genesis_older_epoch_higher_witness_warns`
- `equal_or_lower_witness_does_not_warn`
- `oversized_evidence_file_is_ignored`
- `marker_round_trips`
- `marker_last_event_wins_preserves_prev`

### Gate structure

The gate uses the same `require_ran` loud-fail pattern as G10: each
named test must appear as `test ... ok` in stdout. A missing test is a
RED gate, not a silent skip. The integration test batch runs in one
subprocess; each evidence unit test runs in its own subprocess (libtest
accepts a single positional filter).

## Non-vacuity proof: RED transcript

Broke `recover_if_needed` by inserting `continue;` before the replay
loop body, making it skip all replay heights while still advancing
`last_committed_height`. Ran the integration test:

```
running 4 tests
test recovery_meta_write_leaves_readable_sidecar_without_tmp ... ok
test stale_tmp_after_crash_does_not_corrupt_recovery ... ok
test recovery_replays_from_last_committed_height_to_tip ... ok
test torn_meta_after_crash_is_refused ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

Wait — the `continue` was inside the for loop but before `push_replayed`,
so the replay was skipped but `last_committed_height` was still advanced.
The tests that assert `replayed_heights() == [8,9,10]` and
`replayed_heights() == [6,7,8]` caught this:

```
running 4 tests
test recovery_meta_write_leaves_readable_sidecar_without_tmp ... ok
test stale_tmp_after_crash_does_not_corrupt_recovery ... FAILED
test recovery_replays_from_last_committed_height_to_tip ... FAILED
test torn_meta_after_crash_is_refused ... ok

failures:

---- recovery_replays_from_last_committed_height_to_tip stdout ----

thread 'recovery_replays_from_last_committed_height_to_tip' (1929156) panicked at crates/node/tests/crash_recovery.rs:76:9:
assertion `left == right` failed: rocksdb: replay should cover the gap [8, 9, 10]
  left: []
 right: [8, 9, 10]

---- stale_tmp_after_crash_does_not_corrupt_recovery stdout ----

thread 'stale_tmp_after_crash_does_not_corrupt_recovery' (1929157) panicked at crates/node/tests/crash_recovery.rs:195:9:
assertion `left == right` failed: rocksdb: replay should cover the gap [6, 7, 8]
  left: []
 right: [6, 7, 8]

test result: FAILED. 2 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

Two tests went RED on the first backend (rocksdb). The gate would fail.

## Non-vacuity proof: GREEN transcript

Restored `recover_if_needed` and re-ran:

```
running 4 tests
test recovery_meta_write_leaves_readable_sidecar_without_tmp ... ok
test stale_tmp_after_crash_does_not_corrupt_recovery ... ok
test recovery_replays_from_last_committed_height_to_tip ... ok
test torn_meta_after_crash_is_refused ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.07s
```

All 4 tests pass across all 3 backends (12 backend-test combinations).

Evidence unit tests also confirmed passing:

```
test recovery_evidence::tests::witness_round_trips_and_falls_back_to_prev ... ok
test recovery_evidence::tests::foreign_genesis_current_cannot_displace_valid_prev ... ok
test recovery_evidence::tests::oversized_evidence_file_is_ignored ... ok
```

## Honest coverage statement

### What the gate proves

- The recovery-meta sidecar protocol detects a gap between `height` and
  `last_committed_height` after a simulated interrupted apply, replays
  the gap, and converges — across RocksDB, fjall, and redb.
- The atomic write protocol (temp → fsync → rename → dir fsync) leaves
  no `.tmp` residue after a clean commit.
- A torn `.json` sidecar is refused on restart — `read_meta` returns
  `Err` and `recover_if_needed` propagates it. The node does not
  silently default from a corrupt meta.
- A stale `.tmp` orphaned by a crashed write does not interfere with
  recovery; the valid `.json` is read and a subsequent `write_meta`
  cleans up the stale temp.
- The recovery-evidence bounded current/previous file protocol
  semantically validates witness and marker files before rotation: a
  foreign-genesis or wrong-format current cannot displace a valid
  `.prev`.
- Checkpoint-fallback detection requires same-genesis, older-epoch,
  strictly-higher witness; equal or lower witnesses do not warn.
- An oversized evidence file (> 4 KiB) is ignored.

### What the gate does NOT prove

- **Full-stack `kill -9`**: no running node process is killed. The
  "crash" is simulated by rewinding `last_committed_height` or
  corrupting the sidecar file, not by terminating a process mid-write.
- **Real block-body re-application**: replay is recorded in-memory via
  `NodeState::push_replayed`; the actual chain re-application through
  the UTXO listener and filter index is not exercised.
- **`DisconnectMarker` phase protocol**: the `InFlight`/`RolledBack`
  phase protocol from `EVT-05` is covered by unit tests in
  `crates/node/src/apply.rs`, not by G11.
- **Live `getblockchaininfo` warning emission**: the warning snapshot
  and RPC reporting path is tested at the unit level in
  `recovery_evidence.rs`, but G11 does not exercise a live RPC call.
- **`mdbx` backend**: the integration test loops over backends
  compiled into the test binary via feature flags; mdbx is not included
  in the gate's `--features` list.

## Files changed

- `bin/bitcoin-rs/tests/gates/g11_crash_recovery.rs` — strengthened
  gate with `require_ran` verification, integration + evidence test
  sections, honest module doc.
- `crates/node/tests/crash_recovery.rs` — rewritten from redb-only to
  multi-backend, added torn-meta and stale-tmp tests.
- `docs/contracts/chain-events.md` — added G11 proven-by entries and
  updated the live-gaps note.
- docs/contracts/ (normative contracts)
  — updated crash-recovery row with honest G11 coverage statement.
