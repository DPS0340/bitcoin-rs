# ING-R34c5 Repair Report

## Context
Close the single FAIL finding from the R4 audit: r4c3_reuse_context_across_retry.
The mutation gate requires each named mutation to fail a named test. The r4c3
mutation (hoisting admission context construction out of the retry loop in
`sendrawtransaction`) was uncaught by any test. Reviewer ruled a fix test is
REQUIRED; ledger amendment not available because the mutation is reachable.

## Finding repaired

### r4c3 — reuse context across retry

**Root cause:** `sendrawtransaction` (tx.rs ~448-498) rebuilds
`mempool_prevouts` and `context` inside the retry loop on every attempt. The
r4c3 mutation hoists both captures to BEFORE the loop so the context is reused
across retries. With the mutation, a retried admission operates on stale
mempool facts captured before the transient error — the exact invariant the
retry loop exists to prevent.

**Fix — test seam (gateway.rs):** Added a `#[cfg(any(test, feature =
"test-seam"))]` park point at the start of `admit_transaction` (before the
write lock) mirroring the existing `ordering_gate` pattern at
`acquire_publish_lock`. Exposed `arm_admission_park` / `reset_admission_park`
as public functions gated on the same cfg, re-exported from the crate root.
Added a `test-seam` Cargo feature to the mempool crate so the seam is
available to dependent-crate tests (Rust's `#[cfg(test)]` does not propagate
to dependency crates).

**Fix — regression test (tx.rs):**
`sendrawtransaction_rebuilds_admission_context_after_transient_rejection`

The test is deterministic — no sleeps, no races:

1. Set up: `parent` spends a confirmed UTXO; `child` spends the parent's
   output. The parent output is NOT in the UTXO set, so the child's prevout
   is only available while the parent is in the mempool.
2. Arm the admission park gate on the context's gateway.
3. Spawn a thread calling `sendrawtransaction(child)`.
4. The first attempt captures `generation=0`, `sequence=0`, and context with
   `missing_inputs=true` (parent absent). It calls `admit_transaction` and
   parks at the seam before the write lock.
5. The test thread waits for the "parked" signal, then:
   - Changes the chain generation (`begin_chain_change` + `finish`: 0→2).
   - Admits the parent to the mempool (sequence 0→1, parent output now
     available).
6. The test thread releases the park.
7. The first attempt proceeds: `admit_transaction` sees `generation=0 !=
   2` → `GenerationChanged` → retry. (Policy eval is never reached on the
   first attempt, so `missing_inputs` does not cause an early Policy error.)
8. The retried attempt captures `generation=2`, `sequence=1`, and FRESH
   context (parent in mempool → `missing_inputs=false`) → admission
   succeeds.

With the r4c3 mutation: the context is hoisted before the loop (parent
absent → `missing_inputs=true`). The retried attempt uses the STALE context
→ policy eval rejects with `missing-inputs` → the test's success assertion
fails.

## Mutation transcript

### r4c3: hoist context construction out of the retry loop

**Mutation:** Moved `mempool_prevouts` capture and `resolve_full_context`
call to before the `for` loop in `sendrawtransaction` (tx.rs ~448-470),
keeping `generation` and `sequence` fresh inside the loop. The `context`
field in `AdmissionRequest` is `Copy` (`MempoolPackageTxContext`), so the
hoisted value is reused on each retry without a move error.

**Focused test:**
`handlers::tx::tests::sendrawtransaction_rebuilds_admission_context_after_transient_rejection`

**Result (red):**
```
thread 'handlers::tx::tests::sendrawtransaction_rebuilds_admission_context_after_transient_rejection' (4014493) panicked at crates/rpc/src/handlers/tx.rs:2267:22:
child admitted on retry: "sendrawtransaction failed: internal error: missing-inputs"
test handlers::tx::tests::sendrawtransaction_rebuilds_admission_context_after_transient_rejection ... FAILED

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 326 filtered out
```

**Restore:** Reverted tx.rs to pre-mutation. **Green:**
```
test handlers::tx::tests::sendrawtransaction_rebuilds_admission_context_after_transient_rejection ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 326 filtered out
```

## Lane results

- `-p bitcoin-rs-rpc --lib`: 327 passed, 0 failed
- `-p bitcoin-rs-mempool --lib concurrent_mutators_publish_in_commit_order`: 1 passed (existing seam test unaffected)

## Files changed
- `crates/mempool/Cargo.toml` — add `test-seam` feature
- `crates/mempool/src/gateway.rs` — add park point at start of `admit_transaction`, expose `arm_admission_park`/`reset_admission_park`
- `crates/mempool/src/lib.rs` — re-export test seam functions
- `crates/rpc/Cargo.toml` — add `bitcoin-rs-mempool` dev-dependency with `test-seam` feature
- `crates/rpc/src/handlers/tx.rs` — add `sendrawtransaction_rebuilds_admission_context_after_transient_rejection` regression test + helpers
