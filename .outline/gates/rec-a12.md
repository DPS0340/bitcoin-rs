# REC-A12 gates

Branch: `overhaul/one-session`.

Leaf plan: `.outline/sdd/leaves/rec-a12-plan.md`.

Implementer brief: `.outline/sdd/briefs/rec-a12.md`.

Task goals: `.agent-tasks/rec-a12/GOALS.md`.

A checked box requires evidence. Pending evidence stays unchecked.

## Materialization

- [x] The leaf plan, brief, gate ledger, and goals file all exist.
- [x] The plan starts with `# REC-A12 leaf plan (batch S2-B2)` and contains `## Task 1: REC-A12`.
- [x] The brief contains every binding correction.

## A1: Worker-owned open behind one complete lifecycle snapshot

### R1: Stable query adapters and one-snapshot loads

- [ ] Stable query adapters exist before backend open and before RPC context construction.
- [ ] Each request loads exactly one immutable lifecycle snapshot and retains it.
- [ ] The installed payload is the complete existing query engine. No raw reader query path exists.
- [ ] Existing tip/revision/watermark/budget proofs are preserved inside the captured engine.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib publication_boundaries_never_expose_half_installed_state`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib query_is_unavailable_while_txindex_is_opening`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib complete_query_engine_survives_atomic_handoff`

Evidence:

- lifecycle_tests::publication_boundaries_never_expose_half_installed_state: green
- lifecycle_tests::query_adapter_returns_unavailable_for_opening: green
- lifecycle_tests::query_adapter_returns_unavailable_for_failed: green
- lifecycle_tests::query_adapter_returns_unavailable_for_shutdown_abandoned: green
- TxIndexQueryAdapter constructed in NodeState::open before spawn_with_open and before RPC context
- TxIndexQueryEngine constructed on worker thread in open_and_run, never a raw reader

### R2: Worker-contained open and panic containment

- [ ] Backend open, schema, writer, complete engine construction, publication, and initial handoff run on the worker behind one complete `catch_unwind`.
- [ ] Synchronous spawn failure publishes `Failed` before boot continues.
- [ ] An independent 30-second heartbeat starts before blocking open and stops on every exit.
- [ ] Ordinary open errors and panics publish `Failed`; `NodeState::open` never propagates optional-index failure.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib worker_open_panic_publishes_failed -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib spawn_failure_publishes_failed_synchronously -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib heartbeat_starts_before_blocking_open_and_stops_on_exit -- --test-threads=1`

Evidence:

- spawn_with_open wraps run_worker_with_open in catch_unwind(AssertUnwindSafe(...))
- Heartbeat::start called before open_tx_index_on_worker in run_worker_with_open
- lifecycle_tests::heartbeat_starts_and_stops: green
- lifecycle_tests::stale_generation_rcu_is_a_noop: green (publish_failed_if_current respects revocation)
- spawn_with_open returns Err on thread::Builder::spawn failure; caller context("spawn txindex worker") propagates as NodeState::open error
- panic payload downcast to &str or String, bounded diagnostic published via publish_failed

### R3: Namespace ownership and bounded shutdown

- [x] The namespace map key is canonical data root plus validated fixed child without child canonicalization.
- [x] The map has `Active(owner)` and permanent `Poisoned`. Poison applies only to abandoned opens.
- [x] `Active(owner)` releases only after normal store drop. Poisoned never clears in-process.
- [x] Bounded shutdown uses the shared deadline. Revocation, `ShutdownAbandoned`, poison, and detach occur on expiry.
- [x] A late opener cannot publish after revocation and does not reconcile.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib blocked_open_drop_detaches_within_deadline -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib fresh_namespace_opens_and_normal_reopen_succeeds -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib poisoned_namespace_never_reopens_in_process -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib late_open_cannot_publish_after_revocation -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12c2 cargo test -p bitcoin-rs-node --lib blocked_open_abandonment_detaches_and_poisons -- --test-threads=1`

Evidence:

- lifecycle_tests::namespace_registry_claims_and_releases: green
- lifecycle_tests::namespace_registry_poisons_on_abandon: green
- lifecycle_tests::namespace_registry_poison_only_for_matching_owner: green
- lifecycle_tests::namespace_registry_validates_child: green
- lifecycle_tests::generation_revoke_makes_publication_noop: green
- lifecycle_tests::generation_clone_shares_revocation: green
- bounded_index_shutdown in state.rs uses DRAIN_DEADLINE, revokes generation, publishes ShutdownAbandoned
- NamespaceRegistry::validate_child rejects empty, separator, ., .., absolute paths
- open_and_run checks shutdown and generation.is_revoked() after backend open
- blocked_open_abandonment_detaches_and_poisons: green (RecA12c2, 2026-09-01)
- TxIndexWorker::detach() sets join_handle=None so Drop does not join
- TxIndexWorker::poison_namespace() calls NAMESPACE_REGISTRY.poison(key, owner)
- bounded_index_shutdown abandonment branch calls poison_namespace() + detach()
- RED evidence: drop without detach hangs (timeout 15s killed process) — mutation-proof.txt #13

### R4: Backend matrix and boot independence

- [ ] All four compiled backends keep their constructor, cache path, and batch limits.
- [ ] RPC binds and reports `Opening` while a test-only keyed gate blocks backend open.
- [ ] Disabled boot touches no namespace. Re-enabled boot reconciles from the durable cursor.

Check:

- fjall lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --no-default-features --features fjall async_index_open_preserves_backend -- --test-threads=1`
- redb lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --no-default-features --features redb async_index_open_preserves_backend -- --test-threads=1`
- rocksdb lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --no-default-features --features rocksdb async_index_open_preserves_backend -- --test-threads=1`
- mdbx lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --no-default-features --features mdbx async_index_open_preserves_backend -- --test-threads=1`
- Disabled lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --test extensions disabled_index_boot_then_reenable_reconciles -- --test-threads=1`
- RPC lane: `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --test extensions rpc_binds_while_txindex_open_is_blocked -- --test-threads=1`

Evidence:

- open_tx_index_on_worker preserves all four backend constructors (rocksdb, fjall, redb, mdbx) with cache_bytes and batch_limits
- build_tx_index_open_spec selects batch_limits per backend matching the original open_tx_index
- TxIndexOpenSpec carries storage_backend string; worker dispatches to the correct constructor
- Disabled path: build_tx_index_open_spec returns Ok(None) when capabilities are empty; no namespace, worker, adapter, or map entry created
- Existing extensions tests (4/4) green including filter_extension_restarts_reconcile_from_persisted_pointer
- Backend matrix lanes not run (blocked by concurrent sibling WIP in apply.rs/reorg.rs preventing lib test binary compilation); verified via cargo check -p bitcoin-rs-node (clean)

### R5: A1 mutations

- [ ] Every named A1 mutation fails its intended red test and is reverted.
Evidence:

- Mutation-proof file at .agent-tasks/rec-a12/tests/mutation-proof.txt with 12 A1 mutations
- Each mutation describes the production change and the expected test failure
- Mutations verified by code inspection: generation revocation, namespace owner matching, child validation, heartbeat stop, adapter one-snapshot load

### R6: A1 atomic commit

- [ ] A1 lands as one atomic commit: `Bring index stores up on their workers behind one atomic capability snapshot`, footers `Refs #208`.
- [ ] No A2 file or type appears in the A1 commit.
- [ ] No forbidden path appears in the A1 commit.

Evidence:

- (pending)

## A2: Durable rollback evidence and one warning snapshot

### R7: Sidecar codec and bounded recovery

- [x] Witness and marker files use bounded versioned `deny_unknown_fields` JSON with trailing newline.
- [x] Temp-fsync, validated rotation, publish rename, and dir-fsync recovery is implemented for both file families.
- [x] Invalid current falls back to valid `.prev`. Valid `.prev` is never overwritten by invalid current.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib recovery_evidence::tests`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib witness_stage_failure_preserves_bounded_current_prev -- --test-threads=1`

Evidence:

- (pending)

- recovery_evidence::tests: 14/14 green (RecA12c2, 2026-09-01)
- AppliedTipWitness + ChainRollbackEvent use deny_unknown_fields, format="1", trailing newline
- write_bounded: temp create_new → write+newline → sync_all → validate+rotate → rename → dir sync
- read_bounded: current first, .prev fallback only when current missing/invalid/oversized
- write_bounded validates current content before rotation (never overwrites valid .prev with invalid current)
### R8: Witness publication boundary

- [ ] The only witness writer is `NodeState::write_clean_checkpoint`.
- [ ] Witness publication occurs only after `CheckpointWrite::Published` from durable `CURRENT` rename plus root fsync.
- [ ] A witness failure returns a typed error through the existing deferred path. `SkippedNoAppliedTip` writes no witness.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib witness_is_published_only_after_current_root_sync -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib checkpoint -- --test-threads=1`

Evidence:

- (pending)

### R9: Detection and durable markers

- [x] Only same-genesis, older-epoch, strictly higher witness evidence warns.
- [x] The warning states durable evidence. It does not claim recoverable live state newer than a clean checkpoint.
- [ ] Checkpoint marker failure aborts `NodeState::open`. Worker marker failure fails only the index capability.
- [ ] Every distinct index-ahead fact warns and publishes durable evidence before reconciliation continues.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib same_genesis_older_epoch_higher_witness_warns_and_marks -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib equal_or_lower_witness_does_not_warn -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib marker_write_failure_fails_only_the_reporting_index -- --test-threads=1`

Evidence:

- (pending)

- same_genesis_older_epoch_higher_witness_warns: green (RecA12c2, 2026-09-01)
- equal_or_lower_witness_does_not_warn: green
- foreign_genesis_or_future_epoch_witness_is_ignored: green
- detect_checkpoint_fallback: checks format, genesis, epoch < current, height > restored
- checkpoint_fallback_warning: "Durable applied-tip witness at height X is ahead of the restored tip at height Y. Chainstate was restored from a clean checkpoint, not rejected."
- reporter_report_checkpoint_fallback_writes_marker_and_warns: green
- reporter_report_index_ahead_writes_marker_and_warns: green
- NodeState::open integration and worker marker failure: pending (requires state.rs wiring)
### R10: One atomic warning snapshot

- [x] One in-memory snapshot retains checkpoint and index warning classes together.
- [x] Exact repeats deduplicate. Rendering is deterministic: checkpoint first, then sorted index warnings.
- [ ] Index reporting never erases checkpoint fallback. `getblockchaininfo` loads one snapshot per request.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib checkpoint_and_index_warnings_coexist -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib repeated_index_ahead_report_is_deduplicated -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-rpc --lib getblockchaininfo_reports_atomic_rollback_warnings`

Evidence:

- (pending)

- checkpoint_and_index_warnings_coexist: green (RecA12c2, 2026-09-01)
- repeated_index_ahead_report_is_deduplicated: green
- index_update_preserves_checkpoint_warning: green
- getblockchaininfo_reports_atomic_rollback_warnings: green (module-level test)
- WarningStore uses ArcSwap<WarningSnapshot> with RCU updates
- getblockchaininfo RPC wiring: pending (requires NodeState integration)
### R11: End-to-end convergence and A2 mutations

- [ ] `checkpoint_fallback_with_index_far_ahead_converges_and_warns` passes through the landed REC-C cutover.
- [ ] Every named A2 mutation fails its intended red test and is reverted.

Check:

- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --lib checkpoint_fallback_with_index_far_ahead_converges_and_warns -- --test-threads=1`
- `CARGO_TARGET_DIR=/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12 cargo test -p bitcoin-rs-node --test state_storage -- --test-threads=1`

Evidence:

- (pending)

### R12: A2 atomic commit

- [ ] A2 lands as one atomic commit: `Detect chainstate rollback from durable evidence only, loudly`, footers `Closes #208`.
- [ ] No forbidden path appears in the A2 commit.

Evidence:

- (pending)

## Final review

### R13: Fresh reviewer acceptance

- [ ] A fresh reviewer verifies all fourteen reviewer conditions in the leaf plan and checks this box only after full pass.

Evidence:

- (pending)