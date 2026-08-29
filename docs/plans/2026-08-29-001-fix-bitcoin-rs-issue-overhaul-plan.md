---
title: Bitcoin-rs issue overhaul - Plan
type: fix
date: 2026-08-29
topic: bitcoin-rs-issue-overhaul
source: brainstorm
execution: code
---

# Bitcoin-rs issue overhaul - Plan

## Goal Capsule

Ship one reviewed atomic pull request that resolves every resolvable issue in the fixed target set, makes adverse sync and reorganization behavior fail closed, and changes the validation default only when measured evidence supports it.

The target issue set is #51, #74, #77, #78, #79, #113, #114, #115, #116, #118, #145, #166, #171, #172, #173, #174, #179, and Wayfinder issues #210 through #214. These issues, the repository contracts, and the compatibility policies define product authority.

Native validation must beat the locked kernel baseline before it can become the default. External interoperability gaps keep compatibility tracking issue #116 open until direct evidence closes them.

---

## ODIN spec outline

### Summary

Complete the issue overhaul as one coherent change. The result must reject invalid consensus data without retry loops, preserve chain and mempool state across failed reorganizations and restarts, and publish issue closures that point to direct proof.

### Problem frame

The existing sync and reorganization coverage emphasizes successful progression. Several failure paths cross chainstate, block-tree, mempool, index, and restart state without one explicit adverse-path contract. Sync and reorganization must handle adverse paths directly: permanently invalid frontier blocks must not stall, partial reorganizations must not lose disconnected transactions, and transient index dependencies must not cause permanent failure.

The native validation path has not passed the locked kernel gate. Microbenchmark improvements cannot replace the canonical measurement or justify changing the production default.

### Key decisions

- Fail closed on permanent consensus errors and keep operational failures retryable.
- Preserve one authoritative mutation path for mempool admission, removal, publication, and mining wake-up.
- Judge the native default with the canonical same-tree benchmark and unchanged consensus behavior.
- Publish one pull request with atomic commits rather than staged delivery or compatibility layers.
- Keep compatibility tracking issue #116 open while named external interoperability proof remains absent.

### Requirements

**Adverse sync and chainstate**

- R1. A permanently invalid frontier block must leave the applied tip unchanged, invalidate the block and its descendants, stop unbounded re-request, and attribute the bad delivery to its peer where the peer contract permits it.
- R2. An operational apply failure must preserve retry state without marking valid consensus data invalid.
- R3. Every fallible block-tree and accounting decision must complete before irreversible UTXO mutation, so a rejected or pre-commit failure cannot expose torn chainstate.
- R4. A failed reorganization must report the exact disconnected and connected prefix, restore a coherent active chain, and reconsider eligible transactions from the successful disconnect prefix after the final connected prefix is known.

**Mempool and indexes**

- R5. Reorganization readmission must use the same typed policy path as ordinary admission, reject conflicts instead of invoking replacement policy, and count legacy, P2SH, and witness signature operations with consensus-correct context.
- R6. Block application, reorganization, RPC admission, embedding, event publication, and mining invalidation must share one node-owned mempool mutation path.
- R7. Index catch-up must retry transient dependency results, fail on terminal unavailability or storage errors, and converge to the active tip after reorganization and restart.
- R8. Hash-addressed historical filter rows remain queryable after reorganization; active readiness must still describe the reconciled active snapshot.

**Validation and performance**

- R9. The differential kernel oracle must compare independent native and kernel verdicts for every eligible block without feeding kernel state into native validation.
- R10. Kernel verification remains runtime opt-in, adds no oracle work when disabled, and excludes only the documented assume-valid range.
- R11. Native validation becomes the production default only if the canonical same-tree measurement satisfies `native median * 1.05 <= kernel median` with equivalent behavior. Microbenchmark improvements alone do not qualify.

**Delivery and evidence**

- R12. The embedding interface must own one service graph, one idempotent teardown path, bounded joins, and the same node state used by the daemon.
- R13. Every resolved issue must link to its owning atomic commit and the narrow command or live scenario that proves the acceptance condition.
- R14. Compatibility tracking issue #116 must receive a current evidence ledger and remain open while external Core, miner, transaction-relay, or other named integration proof is missing.
- R15. The final branch must pass repository formatting, lint, workspace tests, required feature lanes, adverse-path gates, fuzz smoke, and a fresh whole-branch review.

### Key flows

- F1. Invalid forward block
  - **Trigger:** A peer supplies a block body whose header is accepted but whose transactions violate consensus.
  - **Steps:** Validate before mutation; classify the apply error; invalidate the permanent-failure subtree; purge retry state; apply peer consequences.
  - **Outcome:** The node remains healthy and does not request the same invalid frontier forever.
  - **Covered by:** R1, R2, R3
- F2. Partial reorganization failure
  - **Trigger:** One or more old-branch blocks disconnect, then a replacement-branch connection fails.
  - **Steps:** Record exact progress; restore the final active branch; reconsider only eligible transactions against that branch through the common admission path.
  - **Outcome:** Chainstate and mempool match the final active tip with deterministic publication order.
  - **Covered by:** R4, R5, R6
- F3. Restarted index reconciliation
  - **Trigger:** The process restarts while an index cursor is behind or on a stale branch.
  - **Steps:** Compare the persisted cursor with a fresh chain snapshot; retry transient dependencies; roll back and replay or rebuild as required.
  - **Outcome:** Readiness becomes healthy only after the index cursor reaches the active snapshot.
  - **Covered by:** R7, R8
- F4. Validation-default decision
  - **Trigger:** Native correctness and performance work is complete.
  - **Steps:** Run independent differential validation; measure kernel and native paths on the same tree and fixture; compare against the locked threshold.
  - **Outcome:** The default changes only on a passing result; otherwise the kernel default remains.
  - **Covered by:** R9, R10, R11

### Acceptance examples

- AE1. **Covers R1-R3.** Given an invalid transaction at the sync frontier, when repeated sync ticks run, then the applied tip and UTXO set stay unchanged and the block does not cycle through unbounded requests.
- AE2. **Covers R2.** Given a retryable storage or availability failure, when apply aborts, then the candidate remains retryable and is not marked consensus-invalid.
- AE3. **Covers R4-R6.** Given a reorganization that disconnects a prefix and fails partway through connection, when recovery completes, then eligible disconnected transactions are reconsidered once against the final active branch without conflict eviction or publication gaps.
- AE4. **Covers R5.** Given reorganization candidates with P2SH or witness inputs, when admission computes policy cost, then the result matches ordinary admission and rejects over-limit transactions.
- AE5. **Covers R7-R8.** Given a stale index cursor across restart, when its dependency first returns retry and later becomes available, then the worker remains live, converges, and keeps historical hash queries valid.
- AE6. **Covers R9-R11.** Given oracle mode disabled, when blocks apply, then no kernel-oracle work occurs. Given oracle mode enabled, native and kernel verdicts are independent and mismatches follow the configured policy.
- AE7. **Covers R13-R15.** Given the final pull request, each closure has direct commit and verifier evidence, compatibility tracking issue #116 lists remaining external gaps, and the full required gate set is green.

### Scope boundaries

- No compatibility aliases, dual production dispatch paths, staged rollout, or deferred in-scope implementation. The independent kernel oracle required by R9-R10 is a verification path, not a second production dispatch path.
- No native-default switch from a benchmark that does not represent the canonical local-file workload.
- No closure of compatibility tracking issue #116 from internal tests alone when it requires external interoperability evidence.
- No removal of hash-addressed historical index rows merely because they are outside the active branch.

### Success criteria

- Permanent invalidity terminates; operational failure retries; neither corrupts visible state.
- Reorganization, restart, mempool, index, and embedding paths converge on one active chain snapshot.
- The validation default matches the measured gate result.
- Every resolvable issue closes from direct evidence in one atomic, reviewable pull request.

### Sources and research

- `docs/contracts/indexing.md` defines the chain-event and index reconciliation contract.
- `docs/contracts/mempool-policy.md` defines transaction admission and replacement behavior.
- `docs/plans/2026-06-05-performance-campaign-ledger.md` records prior performance evidence and rejected candidates.
- `CONCEPTS.md` defines the shared chain, mempool, index, and compatibility vocabulary.
