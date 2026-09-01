# REC-A12 goals

## End state

- Land two serial atomic commits on committed base `634bd1afb93a111a1ce4302fc5137a51e8078894`:
  1. `Bring index stores up on their workers behind one atomic capability snapshot` (A1, footer `Refs #208`).
  2. `Detect chainstate rollback from durable evidence only, loudly` (A2, footer `Closes #208`).
- Preserve authoritative boot when optional index open and recovery run on workers.
- Preserve the complete existing query-consistency proof without publishing a raw reader.
- Detect rollback only from durable evidence. Report checkpoint fallback and index-ahead facts together.

## A1 status: IMPLEMENTED, PENDING VERIFICATION

- [x] Lifecycle snapshot (`TxIndexLifecycle`) behind `ArcSwap` with `Opening`/`CatchingUp`/`Ready`/`Failed`/`ShutdownAbandoned` variants
- [x] Stable query adapter (`TxIndexQueryAdapter`) — one snapshot load per request, typed Unavailable for non-payload states
- [x] Worker-owned open (`spawn_with_open`) — store open on worker thread behind `catch_unwind`
- [x] Namespace registry — process-global `LazyLock<NamespaceRegistry>` with `Active`/`Poisoned`, owner-matched claim/release/poison
- [x] Heartbeat — 30s observability helper, started before blocking open, stopped on all exits
- [x] Bounded shutdown — shared `DRAIN_DEADLINE`, request both, detach on expiry, revoke + `ShutdownAbandoned` + poison
- [x] Generation token — revocation makes late publication a no-op via `rcu`
- [x] `HealthStatus::Opening` and `HealthStatus::ShutdownAbandoned` added to ext-api
- [x] 12 lifecycle unit tests written (green status unverified by continuation worker)
- [ ] 12 lifecycle unit tests verified green by continuation worker
- [ ] Existing extension tests preserved (4/4 green) — verified by continuation worker
- [ ] ext-api round-trip test green — verified by continuation worker
- [x] Mutation-proof file created at `.agent-tasks/rec-a12/tests/mutation-proof.txt`
- [ ] Real mutation cycles run with transcripts (predecessor documented only)
- [ ] 9 named integration tests written and green
- [ ] Backend matrix (fjall/redb/rocksdb/mdbx) verified
- [ ] A1 atomic commit landed

## A2 status: NOT STARTED

- [ ] `recovery_evidence.rs` — witness and event marker file protocol with bounded current/prev
- [ ] Witness publication boundary — only after `CheckpointWrite::Published`
- [ ] Detection and warning state — one `ArcSwap` snapshot, checkpoint + index warnings
- [ ] `getblockchaininfo.warnings` populated from one immutable load
- [ ] Recovery evidence tests green
- [ ] RPC handler test green
- [ ] A2 red-green mutation cycles run with transcripts
- [ ] A2 atomic commit landed

## A1: Worker-owned open

- Keep synchronous boot work limited to authoritative chain open, validation, open-spec construction, runtime/capability/adapter creation, and thread spawn.
- Build one immutable lifecycle snapshot per enabled index behind `ArcSwap`. Only `CatchingUp` and `Ready` carry a payload. Publish every transition with one generation-checked `ArcSwap::rcu`.
- Install stable query adapters before backend open and before RPC context construction. Each request loads exactly one snapshot.
- The installed payload is the full existing query engine, never a raw reader. Preserve `TxIndexQueryEngine::with_snapshot` proofs (tip, revision, watermark, budget) and the full filter engine proof.
- Run directory creation, backend match, backend open, schema inspection, writer construction, complete query-engine construction, publication, and initial reconciliation handoff on the worker.
- Cover the complete worker body with one `catch_unwind(AssertUnwindSafe(...))`. Publish `Failed` with a bounded diagnostic on error or panic when the token is current. Publish nothing when revoked.
- Publish `Failed` synchronously when `thread::Builder::spawn` fails.
- Start an independent 30-second heartbeat before blocking backend open. Stop and join it on every normal, error, and panic exit. Treat it as observability only.
- Preserve all four backend constructors, cache paths, and batch limits. Keep redb txindex as a distinct concrete store. Call the landed generation-aware `IndexWriter::open`.
- Derive namespace keys from canonical data root plus one validated fixed child. Never canonicalize the child. A missing child directory must not block first-time startup.
- Use a process-global map with `Active(owner)` and permanent `Poisoned`. Claim before any namespace touch. Release `Active` only after a normal exit drops the complete store. Poison only abandoned opens. Never poison ordinary errors or spawn failure. Never clear `Poisoned` in-process.
- Bound shutdown by the one shared absolute deadline from `run.rs::DRAIN_DEADLINE`. Request both shutdowns before waiting for either. On expiry: revoke, publish `ShutdownAbandoned`, poison, log, and detach. Never call unbounded `join`.
- A late opener checks shutdown and generation after open. It drops store values and exits without publication or reconciliation.

## A2: Durable rollback evidence

- Add root-level sidecars beside `process-epoch`: `applied-tip-witness.json`, `.prev`, `.tmp`; `chain-rollback-event.json`, `.prev`, `.tmp`.
- Bound every file read and write to 4 KiB. Use versioned `deny_unknown_fields` JSON with a trailing newline.
- Publish the applied-tip witness only after durable checkpoint `CURRENT` publication and root fsync return `CheckpointWrite::Published`. Keep `NodeState::write_clean_checkpoint` as the only witness writer.
- Use bounded current/prev recovery: stale temp removal, create-new no-symlink temp write, temp fsync, validate-then-rotate, publish rename, dir fsync, and error-path temp cleanup. Use `.prev` only when current is missing or invalid. Never overwrite a valid `.prev` with invalid current. Never select by greatest height.
- Ignore malformed, oversized, wrong-format, foreign-genesis, and current/future-epoch evidence at DEBUG.
- Warn only for same-genesis, older-epoch, strictly higher witness evidence against the restored applied tip. No hash comparison requirement. Include equal-height-different-hash as non-warning.
- Never diagnose fjall internals. Never claim recoverable state newer than a clean checkpoint. "Checkpoint fallback" means durable witness ahead of restored checkpoint/cold/headers-only tip.
- Route checkpoint-fallback and every distinct index-ahead fact through one private reporter. WARN first, then in-memory snapshot update, then durable marker. Checkpoint marker failure aborts `NodeState::open`. Worker marker failure fails only the index capability.
- Keep one `ArcSwap` warning snapshot with both classes. Update it in one RCU transaction. Deduplicate exact repeats. Render checkpoint fallback first, then index warnings sorted by capability id and stable evidence fields.
- Expose the existing `getblockchaininfo.warnings` field from one immutable load per request. No disk I/O in the RPC read path. No new public warning-provider trait. No automatic clearing policy in A2.

## Proof

- Run each named red test before its production change, observe green after it, apply the named mutation, observe the test fail again, and restore.
- Run the four-backend matrix lanes. Every command uses the single worktree-isolated target `/home/alpha/blockchain/bitcoin-rs/.outline/tmp/target-rec-a12`, never shared with another worktree.
- Preserve existing restart, reconciliation, query-budget, prune/dependency, shutdown, and checkpoint tests. Run full modules, not only expected-to-flip tests.
- Record mutation evidence in `.agent-tasks/rec-a12/tests/mutation-proof.txt`.
- Record final gate outputs and the fresh-review verdict in `.outline/gates/rec-a12.md`.

## Boundaries

- Do not edit `crates/node/src/apply.rs` (ING-R34 owns it).
- Do not edit `crates/rpc/src/handlers/tx.rs` (ING-R34 owns it).
- Do not edit `crates/index/src/index.rs` (REC-C/RES-160 territory; read-only for REC-A12).
- Do not edit `crates/node/src/reconcile.rs`; its behavior must remain byte-for-byte unchanged.
- Do not edit `crates/node/src/config.rs`, `crates/node/src/crash_recovery.rs`, storage backends, checkpoint bytes, or `CURRENT` barriers.
- Do not add store-open timeouts, thread kills, retry loops, public query traits, public warning-provider traits, or raw-reader query paths.
- Do not change `getcapabilities` response shape or `getblockchaininfo` field shape beyond filling the existing warnings field.
- Do not run formatters, linters, project-wide builds, or project-wide test suites. The batch integrator owns those.
- Delete this task directory only after the REC-A12 leaf is integrated.