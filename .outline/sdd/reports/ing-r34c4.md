# ING-R34c4 Repair Report

## Context
Repair commit-level contract violations found by fresh review of R3 (0763ec1)
on branch overhaul/one-session. Review report: .outline/sdd/reports/r34-r3-review.md.

## Findings repaired

### F1 — G5 contract violation: error paths must leave generation odd

**Root cause:** 0763ec1 called `proof.finish()` unconditionally on
`apply_window`'s error-capable loop (apply.rs ~1434-1438) and on
`switch_to_branch`'s replan/early-return paths (reorg.rs ~284, 288),
restoring the generation to even so retries could proceed. Brief G5
requires any post-begin error to leave the generation odd (fail-closed).

**Fix — apply.rs:** Reverted to a direct loop that calls `proof.finish()`
only on the success path. An error after `begin_chain_change` drops the
proof (and thus the guard) without finishing, leaving the generation odd
by design.

**Fix — reorg.rs:** Moved the `begin_chain_change` guard start to AFTER
the replan check, consistent with the brief's "Start the guard after
fallible read-only planning/proof work and before the first UTXO, undo,
tip, cache, mempool, or publication mutation." The replan path
(`plan != authoritative`) and the plan-None early return now drop the
transition without beginning a generation, so the gateway stays even and
the loop retries normally. The guard is started only when the plan is
authoritative and execution is about to begin. An error during execution
(`outcome?`) leaves the generation odd by design.

**G5-recovery interpretation:** The brief states "Any error after begin
remains odd by design" and "Odd means a chain change is active or a
failed chain change has closed admission." The brief does not specify a
recovery path for an odd generation left by a failed `apply_window` — no
reset method exists on `MempoolGateway`, and the dropped guard cannot be
re-finished. The narrowest reading consistent with G5 is fail-closed:
the system stops accepting new chain changes after a mid-batch failure
until an external recovery path (e.g. a restart) resets the generation.
The migrated `batch_drain` test asserts this behavior: after the
mid-batch failure, the generation is odd, and a retry tick cannot
advance the height.

For the reorg replan path, the recovery is implicit: because the guard
is started after the replan check, a replan never leaves the generation
odd. The `branch_switch_replans` test passes unchanged — the reorg
absorbs the competing connect and reaches the target as before.

### F2 — frozen-row mutation: preview policy_contract row changed in R3

**Root cause:** 0763ec1 flipped
`acceptance_preview_gap_ancestor_limits_surface_only_at_admission` from
expecting preview acceptance (documented gap) to expecting `PackageLimit`
rejection, and added `check_package_limits` to `evaluate_one` (the shared
preview path). The brief freezes expected rows/strings and assigns
evaluator consolidation to R4.

**Fix — policy_contract.rs:** Restored the frozen row byte-identical to
its pre-R3 form (verified with `diff` against
`0763ec1^:crates/mempool/tests/policy_contract.rs`). The test again
pins the documented preview gap: preview reports allowed, admission
rejects with `TooManyAncestors`.

**Fix — standardness.rs:** Stripped `check_package_limits` from
`evaluate_one`. The `Ok(plan)` branch of `check_replacement` now
returns `None` (allowed) without checking package limits. Package-limit
enforcement lives only in the admission path (R4). The
`PackageLimit` enum variant is retained for R4 wiring. The
`package_limits_use_shared_evaluator` test (which tested the removed
behavior) was deleted. The `is_coinbase` detection and
`coinbase_requires_null_prevout` test are retained (R3 additions not
contested by the review).

### F3 — M1-M5 mutation transcripts

Re-executed each mutation against the repaired tree on the staged export.
See the M1-M5 transcripts section below.

## Lane results (isolated export /tmp/r34c4tree, committed version + only these repairs)

- `-p bitcoin-rs-mempool --lib`: 151 passed, 0 failed
- `-p bitcoin-rs-mempool --test policy_contract`: 17 passed, 0 failed
- `-p bitcoin-rs-node --lib`: 640 passed, 0 failed, 1 ignored
- `cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings`: clean
- `rustfmt --check` on all changed files: clean

## Files changed
- `crates/node/src/apply.rs` — revert error-path `proof.finish()` in `apply_window`
- `crates/node/src/reorg.rs` — move guard start after replan check, remove error-path finishes
- `crates/node/src/sync.rs` — migrate `batch_drain` test to G5 odd-on-error contract
- `crates/mempool/src/standardness.rs` — strip `check_package_limits` from `evaluate_one`, remove `package_limits_use_shared_evaluator` test
- `crates/mempool/tests/policy_contract.rs` — restore frozen row to pre-R3 form

## M1-M5 mutation transcripts

All mutations executed on the export tree at /tmp/r34c4tree with
`env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR TMPDIR=/tmp/r34c4tree/target/tmp`.

### M1: lock-free CAS in begin_chain_change
**Mutation:** Replaced `let pool_guard = self.pool.write();` with a comment
(no lock), removed `drop(pool_guard);` in `begin_chain_change`
(gateway.rs:274).

**Focused test:**
`gateway::tests::begin_chain_change_serializes_with_inflight_admission`

**Result (red):**
```
assertion `left == right` failed: begin must not store odd while an admission holds the write lock
  left: None
 right: Some(0)
test result: FAILED. 0 passed; 1 failed
```

**Restore:** Reverted gateway.rs to pre-mutation. **Green:**
```
test gateway::tests::begin_chain_change_serializes_with_inflight_admission ... ok
test result: ok. 1 passed; 0 failed
```

### M2: auto-finish in Drop for ChainChangeGuard
**Mutation:** Added `impl Drop for ChainChangeGuard` that compare-exchanges
odd to even on drop (gateway.rs after line 535).

**Focused test:**
`gateway::tests::dropping_chain_change_stays_unstable`

**Result (red):**
```
assertion `left == right` failed: dropping the guard without finish leaves the generation odd
  left: Some(2)
 right: None
test result: FAILED. 0 passed; 1 failed
```

**Restore:** Reverted gateway.rs to pre-mutation. **Green:**
```
test gateway::tests::dropping_chain_change_stays_unstable ... ok
test result: ok. 1 passed; 0 failed
```

### M3: wrapping_add instead of checked_add in begin_chain_change
**Mutation:** Replaced `checked_add(1).ok_or(ChainChangeError::Overflow)?`
with `wrapping_add(1)` for both odd and even reservation (gateway.rs:279-280).

**Focused test:**
`gateway::tests::chain_generation_overflow_fails_closed`

**Result (red):**
```
overflow must fail before any store: ChainChangeGuard { gateway: MempoolGateway { ... } }
test result: FAILED. 0 passed; 1 failed
```

**Restore:** Reverted gateway.rs to pre-mutation. **Green:**
```
test gateway::tests::chain_generation_overflow_fails_closed ... ok
test result: ok. 1 passed; 0 failed
```

### M4: error-path proof.finish() in apply_window (G5 violation)
**Mutation:** Wrapped the apply_window loop in a closure and added
unconditional `proof.finish()` after it, restoring the R3 error-path
finish (apply.rs ~1423-1435).

**Focused test:**
`sync::tests::batch_drain_restores_unapplied_tail_after_mid_batch_failure`

**Result (red):**
```
generation must be odd after mid-batch failure (G5 fail-closed)
test result: FAILED. 0 passed; 1 failed
```

**Restore:** Reverted apply.rs to pre-mutation. **Green:**
```
test sync::tests::batch_drain_restores_unapplied_tail_after_mid_batch_failure ... ok
test result: ok. 1 passed; 0 failed
```

### M5: retag Conflict as BlockInclusion in remove_for_block
**Mutation:** Changed `RemovalReason::Conflict` to
`RemovalReason::BlockInclusion` for conflict/descendant removal in
`remove_for_block` (pool.rs:911).

**Focused test:**
`gateway::tests::remove_for_block_distinguishes_mined_from_conflicts`

**Result (red):**
```
assertion `left == right` failed: mined is BlockInclusion, conflict and descendant are Conflict, in deterministic order
  left: [..., Removed(BlockInclusion)), (..., Removed(BlockInclusion))]
 right: [..., Removed(BlockInclusion)), (..., Removed(Conflict))]
test result: FAILED. 0 passed; 1 failed
```

**Restore:** Reverted pool.rs to pre-mutation. **Green:**
```
test gateway::tests::remove_for_block_distinguishes_mined_from_conflicts ... ok
test result: ok. 1 passed; 0 failed
```

## Out of scope
- R4 admission wiring (evaluator consolidation, package-limit enforcement at admission) — held by IngR34c3
- Recovery path for an odd generation left by a failed apply_window (no reset mechanism specified in the brief)
