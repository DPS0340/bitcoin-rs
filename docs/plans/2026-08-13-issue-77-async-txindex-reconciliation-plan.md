# Issue #77: asynchronous TxIndex reconciliation

Status: IMPLEMENTED (correctness implementation and tests; dedicated IBD
performance capture remains to be recorded), 2026-08-13.

Scope: `crates/node`, `crates/index`, and the TxIndex-dependent RPC/Electrum
read paths. This plan changes only TxIndex; it does not redesign `BlockSync`,
UTXO application, checkpoints, pruning, or the filter index.

Implementation record:

* `crates/index` stores a versioned `(height, hash)` watermark and commits
  bounded contiguous forward-row batches or one strict rollback together with
  the terminal watermark.
* `crates/node` owns the capacity-one wake, startup reconciliation, captured-tip
  ancestry walk, retained-body loading, worker health, and clean join.
* Authoritative connect/disconnect and `BlockSync` contain no TxIndex row
  mutation or batching.
* RPC and Electrum complete reads use the shared read/write gate and reject lag,
  failure, or an applied-tip race as unavailable.
* The watermark-based index is the initial unreleased `txindex` format; no
  legacy migration or parallel versioned directory is required.
* The sync-pipeline benchmark no longer has a synchronous TxIndex mode and now
  includes paired `sync_pipeline_apply_only_proxy{,_txindex_detached}` cases
  that exclude store-open setup from apply-path timing.
  A dedicated long IBD/replay capture of worker catch-up remains an operational
  measurement task, not an unresolved correctness dependency.

## 1. Outcome

Define the minimum boundary that lets backfillable derived state be built and
recovered independently of authoritative block application, and prove that
boundary with TxIndex as the first concrete consumer.

The concrete result is that TxIndex work no longer runs in block connect or
disconnect. A dedicated worker owns a durable `(height, block_hash)` watermark,
pulls exact retained block bodies, and converges the index to a captured
authoritative applied tip. Core publishes only a coalesced wake after an
applied-tip transition. A TxIndex failure makes complete TxIndex queries
unavailable; it does not fail block application or stop chain sync.

This plan documents reusable invariants, not a generic consumer framework.

```text
BlockSync / apply / reorg
          |
          +-- authoritative applied_tip
          +-- ancestry anchored at a captured tip
          +-- block bodies addressed by (height, hash)
                          |
                          | pull
                          v
                    TxIndex worker
                bootstrap -> reconcile
                          |
                          v
              rows + durable watermark
```

## 2. Replaced seam

Before this implementation, `ApplyHandles::tx_index` coupled TxIndex to
authoritative mutation:

* `apply_block` writes TxIndex rows synchronously after body persistence.
* `disconnect_block` rolls TxIndex rows back before UTXO undo and the
  `applied_tip` rollback.
* `BlockSync` opens and closes TxIndex batches around apply runs.
* RPC and Electrum readers can interpret an incomplete lookup as a complete
  negative because no independent TxIndex progress exists.

Issue #77 removes only those TxIndex connections. The existing chain sync,
validation, UTXO, checkpoint, block-body persistence, and `switch_to_branch`
algorithms remain authoritative and otherwise unchanged.

## 3. Invariants

The implementation is complete only if all of these statements are true.

1. The authoritative applied chain is the only source of truth. TxIndex is a
   deterministic materialized view of that chain.
2. TxIndex owns its durable progress as an exact `(height, block_hash)`
   watermark. Header-row count is not progress and must not be used to infer it.
3. Every durable TxIndex transition atomically commits all row additions or
   deletions together with the terminal watermark in the same TxIndex DB batch.
4. A durable TxIndex watermark may be ahead of the core tip restored from a
   checkpoint. This is valid for TxIndex because each backward transition is
   reconstructed from an identity-checked retained block body.
5. Every body used for connect or rollback must match the expected height and
   full block hash. Its decoded header and Merkle identity must be validated
   before its transactions determine row mutations.
6. A captured tip is the stable target of one reconciliation attempt, not a
   pinned chain snapshot. Issue #77 adds no header/body retention solely for
   the worker.
7. A complete-negative TxIndex query is permitted only against an observed
   healthy worker whose watermark equals the applied tip for the entire query
   validation boundary.
8. TxIndex storage, body-read, and worker failures never fail authoritative
   block application, reorg, or chain sync.

## 4. Concrete design

### 4.1 TxIndex-owned state

The TxIndex store contains:

```text
electrs-shaped TxIndex rows
watermark codec version
watermark height
watermark block hash
```

The process owns only ephemeral observations:

```text
worker health / last error
cached committed watermark
capacity-1 wake channel
query/mutation synchronization gate
shutdown state
```

There is no durable lifecycle (`Building`, `CaughtUp`, or `Failed`), event
cursor, event epoch, sequence, or event journal. On restart, the durable
watermark and the current applied tip determine the work.

The cursor codec is TxIndex-private. Do not add a shared index metadata schema
or a new generic column family for it. Store the watermark-based schema
directly at `data_dir/txindex`. This format has not been released, so there is
no legacy migration, detection, parallel versioned directory, or progress
inference. A newly created store starts empty and follows the normal bootstrap
path. General rebuild and pruning policy remain outside #77. As a temporary
safety boundary, configuration rejects TxIndex with a nonzero prune target
until pruning can retain every body required after the TxIndex watermark.

### 4.2 Exact source access

`NodeBlockSource::block_at_height` resolves the current active hash and is not
suitable for a captured reconciliation target. Add a TxIndex-specific source
boundary that performs these operations:

```text
capture_applied_tip() -> TipSnapshot
node_at_height_from(captured_tip.tip_id, height) -> (height, hash)
block_body(height, expected_hash) -> validated body
```

Do not introduce an `AppliedChainView` wrapper unless implementation evidence
shows it is needed. The load-bearing rule is that ancestry reads within one
attempt remain anchored to the captured `tip_id`; the worker must not mix
height lookups from different live tips.

### 4.3 Empty-watermark bootstrap

An empty TxIndex takes a forward-only fast path:

1. Capture the current applied tip as the attempt target.
2. Walk its ancestry in increasing height order.
3. Read each body by the exact `(height, hash)` obtained from that target.
4. Commit bounded contiguous batches of rows plus their terminal watermark.
5. At the captured target, enter normal reconciliation against a fresh tip.

The inner loop does not track live reorgs per block. Core may advance or reorg
while the worker scans. The captured target is not a retention promise:

* If forward ancestry or a forward body becomes unavailable and a fresh
  `applied_tip` differs from the captured target, abandon the attempt and retry
  against the fresh target after a short bounded exponential backoff. Repeated
  stale targets remain retries rather than source failures; the backoff prevents
  a moving tip from turning unavailable bodies into a hot spin.
* If the same authoritative target remains published but its ancestry or body
  cannot be resolved, report a source/invariant failure and stop the worker.

Batch limits must include both row count and bytes. A crash may lose the whole
last batch, but it must never leave its rows without its watermark or vice
versa.

### 4.4 Reconciliation

Bootstrap, restart, live catch-up, and reorg recovery all end in the same
reconciliation primitive:

```rust,ignore
loop {
    let target = capture_applied_tip();

    rollback_until_watermark_matches_target_ancestry(target)?;
    connect_until(target)?;

    if watermark() == capture_applied_tip() {
        return Ok(());
    }
}
```

The stored watermark branch need not be active or addressable by a live
`NodeId`. To roll it back:

1. While the watermark is higher than the target, roll it back unconditionally.
2. Once the watermark is no higher than the target, compare it with the hash at
   the same height in the target ancestry. Continue rolling back while the
   hashes differ.
3. Read the exact body addressed by the watermark `(height, hash)` for each
   rollback step.
4. Verify its identity before deriving delete keys.
5. Atomically delete that block's rows and move the watermark to
   `(height - 1, header.prev_blockhash)`.
6. Stop at the common prefix and connect the captured target suffix in forward
   order.

The common-prefix loop is explicitly height-aware so consumer-ahead recovery
does not attempt to query a target height that does not exist:

```rust,ignore
while watermark.height > target.height
    || hash_at(target, watermark.height) != Some(watermark.hash)
{
    if watermark.height == 0 {
        return Err(ReconcileError::NoCommonAncestor);
    }
    rollback_watermark_block()?;
}
```

The first condition must short-circuit the ancestry lookup. If genesis differs,
fail without decrementing below height zero.

A missing body for the durable watermark is not a stale-attempt retry: changing
the forward target cannot remove already-durable stale rows. Stop the worker as
source-unavailable and leave core running.

TxIndex's existing header-row identity guard remains mandatory, but the worker
uses a stricter cursor-aware interpretation than the current synchronous
best-effort rollback. If the durable watermark identifies the block being
disconnected but that block's expected header identity row is absent, the
TxIndex state is inconsistent: fail the worker and change neither rows nor the
watermark. It is not safe to treat that case as an already-completed rollback
and retreat only the watermark. When the identity is present, it prevents a
repeat rollback of one block from deleting colliding electrs-shaped rows that
now belong to a replacement block at the same height.

### 4.5 Independent durability and consumer-ahead recovery

Do not fence TxIndex commits at the core checkpoint tip. The following restart
state is permitted:

```text
restored authoritative core tip = 100
durable TxIndex watermark       = 105
```

The worker rolls 105 back to the chain matching the restored authoritative tip
and then follows its current branch. This policy is proven only for TxIndex;
future stateful consumers may require undo data or durability coordination and
must choose separately.

The atomic write API must accept pending row mutations and a terminal watermark
in one backend batch. Do not implement the watermark as a second `put` after
`Indexer::end_batch`.

### 4.6 Coalesced wake, not events

After every successful runtime `applied_tip` transition, core performs:

```rust,ignore
applied_tip.store(new_tip);
let _ = txindex_wake.try_send(());
```

Use a capacity-1 channel. A full queue coalesces duplicate work; it does not
carry block identity, order, or recovery truth. Startup always reconciles once
before waiting.

```rust,ignore
reconcile();
while wake_rx.recv().is_ok() {
    reconcile();
}
```

Reconciliation compares its watermark with a fresh applied tip before it
sleeps. If core changes after that comparison, the required store-then-send
order leaves a wake queued. No periodic correctness poll is required.

Route every successful runtime applied-tip publication (connect and
disconnect) through one small helper or otherwise test all publication sites.
Checkpoint restoration happens before worker startup and is covered by the
mandatory startup reconciliation.

### 4.7 Failure isolation

Classify worker outcomes rather than treating every missing lookup alike:

| Condition | Outcome |
|---|---|
| Captured forward target disappeared and fresh tip differs | abandon attempt; retry fresh tip |
| Published target still cannot resolve ancestry/body | worker failed/source unavailable |
| Durable watermark body is missing or identity-invalid | worker failed/source unavailable |
| TxIndex DB read/write or cursor decode fails | worker failed |
| Wake channel closes during shutdown | normal worker exit |

A failed worker retains its last durable watermark and exposes an unavailable
status to complete queries. It does not request node shutdown and does not
change the authoritative applied tip.

### 4.8 Minimal query completeness gate

Moving TxIndex off apply makes normal states such as `core=100, txindex=97`
possible. A query must not translate that lag into “transaction/history does
not exist.” This is part of #77 correctness, distinct from richer Electrum
readiness policy.

For every query whose negative result assumes complete confirmed history:

1. Enter a TxIndex read gate that excludes worker row mutation/commit but still
   permits concurrent readers.
2. Capture the applied tip.
3. Require a healthy worker and a committed watermark equal to that tip.
4. Execute the complete logical query while holding the read gate.
5. Re-read the applied tip before returning and require the same publication
   identity, not merely an equal `(height, hash)` value. Every publication uses
   a fresh `Arc`, making pointer identity a unique process-local publication
   token while the query retains its starting `Arc`.
6. If the identity changed, discard the result and return `TxIndex unavailable/catching
   up` (or perform a small bounded retry); do not return a negative result.

The worker takes the write side of this gate only while publishing a TxIndex DB
transition and its cached watermark. Body loading, identity validation, row
construction, sorting, and deduplication remain outside it through prepared
connect/rollback transitions; commit rechecks the starting watermark under the
gate before writing. This closes query/index mutation races without blocking
core apply. Publication-identity validation closes an `A -> B -> A` tip ABA;
the read gate independently prevents the worker from mutating TxIndex during
the query.

Apply the gate to RPC transaction/prevout reads and Electrum confirmed history,
transaction, and unspent reads. Change read interfaces that currently collapse
storage/unavailable errors into empty vectors or `None`; unavailable must be
distinguishable from an authoritative empty result. `getindexinfo` should use
the TxIndex watermark and worker health rather than core header/applied heights.
Electrum history and unspent scans are bounded while holding the gate, lossy
spending-prefix candidates are exact-resolved against block inputs, and a
broadcast resolves all prevouts inside one completeness boundary.

Electrum-specific waiting policy, partial-history service, protocol messaging,
and service startup policy remain outside #77.

## 5. Implementation sequence

### Phase A: durable transition primitive

* Add the versioned TxIndex watermark codec and exact `(height, hash)` type in
  `crates/index`.
* Add forward and rollback row-construction paths that append both row
  mutations and the terminal watermark to one caller-owned write batch.
* Preserve the header identity guard and reject body/hash mismatches before
  mutation.
* Use the watermark-based schema as the initial `txindex` storage format.

Gate: backend tests prove atomic rows+watermark behavior for every enabled
storage backend before worker integration.

### Phase B: anchored source and worker

* Add captured-tip ancestry and exact body access in `crates/node`.
* Implement empty-watermark bootstrap and reconciliation as TxIndex-specific
  code, not a generic registry or trait framework.
* Add worker health, committed-watermark observation, bounded wake, and clean
  shutdown/join handling.
* Start the worker only after checkpoint restoration and block-body storage are
  available.

Gate: deterministic worker tests cover forward catch-up, stale-target retry,
fork rollback, restart, and source failure without touching production apply.

### Phase C: detach authoritative mutation

* Remove TxIndex ingest from `apply_block`.
* Remove TxIndex rollback from `disconnect_block` and its durable disconnect
  marker participation.
* Remove `BlockSync` TxIndex `begin_batch`/`end_batch` calls.
* Publish one coalesced wake after every successful applied-tip connect or
  disconnect transition.
* Keep block-body persistence independent of whether TxIndex is enabled; the
  worker consumes the existing exact body store.

Gate: apply, IBD, and reorg tests pass with a slow and a failing TxIndex worker,
and no authoritative path waits for or propagates that failure.

### Phase D: query correctness and status

* Wire the TxIndex-specific completeness/read gate into RPC and Electrum
  confirmed-data readers.
* Preserve “not found” only when the query ran against a healthy, complete
  watermark; expose lag/failure as unavailable.
* Report the real watermark and synced status from `getindexinfo`.

Gate: race tests prove lag, concurrent advance, reorg, and worker failure never
produce a false authoritative negative.

### Phase E: integration and performance proof

* Run the full workspace test lanes required by repository policy.
* Add an IBD/replay comparison with TxIndex enabled, recording apply-stage time,
  total wall/CPU, worker catch-up time, and final watermark/hash equality.
* Verify the final TxIndex rows against an uninterrupted synchronous-reference
  fixture across normal sync and a reorg.

This phase validates the issue's performance goal; correctness gates in earlier
phases do not depend on a benchmark win.

## 6. Required tests

### Storage and crash

* Rows and watermark commit together on connect.
* Rows and watermark commit together on rollback.
* Injected write failure exposes neither half of a transition.
* Core checkpoint at 100 plus durable TxIndex watermark at 105 restarts,
  rewinds 105 to 100, and converges to the current branch.
* Cursor corruption and unknown codec fail the worker without affecting core.
* An empty store has no watermark and bootstraps from genesis.

### Bootstrap and reconciliation

* Empty index bootstraps one captured branch in height order.
* Core advances during bootstrap; the worker finishes its attempt and catches
  the fresh suffix.
* Core reorgs during bootstrap while the captured branch remains resolvable;
  stale rows are rolled back and the replacement suffix is connected.
* Captured ancestry disappears; a changed fresh tip causes a clean retry.
* The same published target with missing ancestry/body fails the worker.
* Missing durable-watermark body fails rather than skipping stale rows.
* A watermark above the target rolls back before any same-height ancestry
  comparison, including the `index=105, core=100` restart case.
* Same-height fork hashes roll back until their common prefix.
* A genesis mismatch fails without height underflow or mutation.
* A watermark whose expected header identity row is absent refuses rollback
  and leaves both rows and watermark unchanged.
* Repeated rollback cannot delete same-height replacement rows.
* All connect and rollback inputs reject wrong height/hash/header/Merkle data.

### Wake and lifecycle

* Many tip transitions coalesce into one wake and still converge.
* A tip transition during reconciliation queues or observes subsequent work.
* Startup reconciliation catches changes that occurred before worker start.
* Worker failure and shutdown do not block or stop block application.

### Queries

* Lagging TxIndex returns unavailable, never a complete negative.
* A healthy equal watermark permits not-found, history, and unspent results.
* Applied tip movement during a query discards the result or retries.
* Reorg during a query cannot expose a partially mutated TxIndex view.
* Worker failure remains distinguishable from not found.
* `getindexinfo` reports the TxIndex watermark, caught-up state, and failure
  state accurately.

## 7. Explicit non-goals

Issue #77 does not implement:

* a general `BlockSync` or IBD redesign;
* a generic optional-index consumer trait, registry, lifecycle, rollback, undo,
  or durability policy;
* migration of filter index, Utreexo, enforcer state, or every optional index;
* a durable event log/WAL, ordered event record, event cursor, epoch, sequence,
  replay, schema, version, or retention policy;
* periodic correctness polling;
* core-checkpoint/TxIndex-commit coordination;
* pruning retention, pruned-node TxIndex build, or general rebuild procedure;
* filter-index backfill;
* rich Electrum readiness, partial-history, or wait behavior.

## 8. Completion criteria

Issue #77 is complete when:

1. no TxIndex row mutation or flush remains on authoritative block connect,
   disconnect, or `BlockSync` batching paths;
2. the worker deterministically converges an empty, behind, ahead, or stale-fork
   TxIndex from its durable watermark whenever required bodies are available;
3. every row transition and watermark is atomic and identity-checked;
4. stale captured targets retry without branch pinning, while real source or DB
   failures stop only the worker;
5. complete TxIndex queries cannot turn lag or concurrent mutation into a false
   negative;
6. capacity-1 wakes plus startup/final comparisons converge without sequence,
   WAL, replay, or periodic polling; and
7. integration tests prove final watermark/hash and row equivalence while core
   remains live under slow or failed TxIndex work.

The frozen one-sentence model is:

> TxIndex independently stores where it is, wakes when the authoritative
> applied chain changes, and reconciles itself to one captured attempt target;
> complete queries are served only from a healthy watermark proven equal to
> the applied tip.
