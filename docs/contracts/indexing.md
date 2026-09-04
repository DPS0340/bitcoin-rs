# Indexing contract

The normative contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and selective
rebuilds.

Owners:
- `TxIndexRuntime`, `TxIndexQueryEngine`, `Worker` in `crates/node/src/txindex_worker.rs`
- `IndexWriter`, `IndexReader`, `IndexCapabilities`, `IndexCapability`, `IndexWatermarks`, `IndexWatermark` in `crates/index/src/index.rs` and `crates/index/src/types.rs`
- Capability status provider in `crates/node/src/capabilities.rs` and
  `crates/rpc/src/context.rs`

## Clauses

### `IDX-01`: Capability configuration and internal enablement

- CLI `--txindex` (env `BITCOIN_RS_TXINDEX`, configuration `txindex=1`) enables
  the `TxLookup` capability in the transaction index store. This builds
  Core-compatible transaction identifier lookup rows (`TxidRow`) and outpoint
  value positions.
- CLI `--scriptindex` / `--script-index` (env `BITCOIN_RS_SCRIPTINDEX`,
  configuration `scriptindex=1`) enables the `ScriptHistory` capability. This
  builds generic scripthash funding rows (`ScriptHashRow`), spending rows
  (`SpendingPrefixRow`), and outpoint spender records.
- Enabling either `--txindex` or `--scriptindex` spawns exactly one node-owned
  `TxIndexRuntime` worker thread. Enabling both permits both capability row
  families to share a single block-body parse and atomic forward commit batch
  when their watermarks are aligned.

### `IDX-02`: Capability advertisement and Core compatibility

- Only explicit `--txindex` advertises the Core `txindex` capability in RPC
  `getindexinfo` and enables historical `getrawtransaction` verbose and raw
  lookups across all confirmed blocks.
- `--scriptindex` provides generic script history, unspent output, and spender
  queries for Esplora and RPC routes without advertising Core `txindex` unless
  `--txindex` is also set.
- `getindexinfo` reports `synced: true` if and only if the advertised
  capability watermark matches the height and block hash of the active chain tip.

### `IDX-03`: Query gating and snapshot consistency

- **Ready invariant**: `ready ⇔ cursor == applied_tip on active chain`.
- `TxIndexQueryEngine::with_snapshot` and `index_info_internal` gate every read:
  1. The worker runtime must be healthy (neither `failed` nor `shutdown`).
  2. The applied tip loaded before snapshot creation must match the durable
     capability watermark (`IndexWatermark { height, hash }`) for every consumed
     capability.
  3. The runtime revision (`TxIndexRuntime::revision`) and the applied tip
     identity must remain identical before and after snapshot acquisition.
- If an index capability lags behind the tip, is rebuilding, is rolling back
  across a reorg, or experiences a concurrent tip advance during read assembly,
  the query engine refuses the request with `TxQueryError::Retry` or
  `TxQueryError::Unavailable`. Stale, unconfirmed, or torn rows are never
  returned to callers.

### `IDX-04`: Selective reset preserves sibling readiness

- When one capability watermark experiences corruption, a missing block body
  during reorg rollback, or a schema/version mismatch, the worker resets only
  the degraded capability watermark to `None` and backfills it from the active
  chain.
- Surviving sibling capabilities remain ready: resetting and rebuilding
  `ScriptHistory` leaves `TxLookup` online and serving queries as long as its
  own watermark matches the applied tip, and vice versa.

### `IDX-05`: Restart reconciliation and schema version refusal

- The `data_dir/txindex` namespace maintains
  durable format versions and capability watermarks (`IndexWatermarks`,
  `ConsumerCursor`).
- A stored schema or format version foreign to this build refuses start for that
  namespace per `docs/policies/db-migration.md` (never an in-place migration).
- On node startup, index workers read their persisted watermarks and reconcile
  against `NodeState::active_chain_snapshot()`:
  - If the watermark is an ancestor of the restored tip, the worker connects
    forward.
  - If the watermark is on an abandoned branch, the worker rolls back to the
    common ancestor and connects forward to the active tip.
- Startup crash recovery (`crates/node/src/crash_recovery.rs`) runs and completes
  replaying the gap up to the sidecar tip before `NodeState::start_index_workers()`
  spawns worker threads (`crates/node/src/run.rs`), ensuring index workers reconcile
  against a fully restored active chainstate.

### `IDX-06`: Reorganization rollback and forward reconciliation

- Reorganizations reconcile asynchronously across the chain-event seam
  (`docs/contracts/chain-events.md`). `ApplyHandles` invokes
  `TxIndexRuntime::wake()` after each committed `applied_tip.store`.
- **Disconnect walk**:
  - Height-keyed rows (transaction position rows) are removed using per-block
    watermark identity records to delete exactly the rows contributed by each
    disconnected block from the tip down to the common ancestor.
  - When the rollback depth (watermark height minus common ancestor height)
    exceeds `txindex_worker::DEFAULT_ROLLBACK_REBUILD_CUTOVER` (100 000 blocks),
    the worker routes to `reset_capabilities` and backfills forward instead of
    executing a long block-by-block rollback
    (`docs/benchmarks/index-rollback-rebuild-cutover.md`).
- **Connect walk**:
  - The worker loads bodies from `PruneBodyStore`, constructs bounded forward
    batches (`PreparedBatchLimits`), and commits row mutations and updated
    watermarks in a single atomic store batch per block or block chunk.
- If a rival reorg or tip extension occurs while a forward batch is being
  prepared, the atomic commit detects the watermark divergence, discards the
  stale prepared batch, and re-plans from the new active tip on the next pass.

### `IDX-07`: Error isolation and supervised rebuild

- If a required block body is missing during a rollback (e.g. an abandoned
  branch block pruned before rollback completed), the worker resets the
  affected capability watermark and initiates a fresh rebuild from the active
  chain.
- Index workers execute in supervised threads under `catch_unwind`. A fatal
  storage failure or panic marks the worker as failed (`publish_failed`) and
  stops the worker. Block validation, UTXO commits, and chainstate progress
  continue unimpeded: the apply path never depends on index writes.

## Live gaps

- **Asynchronous recovery decoupling**: Index stores now open on their
  worker threads (`TxIndexWorker::spawn_with_open`), not synchronously
  during `NodeState::open`. Durable recovery-evidence detection
  (`crates/node/src/recovery_evidence.rs`) validates the applied-tip
  witness semantically before rotating the current record and detects
  checkpoint fallback from durable evidence. Full decoupling of index
  recovery from authoritative chain listener readiness is tracked under
  #208 and #209 (open on GitHub; #208 addressed on this branch by
  `b67bd87`).
- **Deep reorg memory bounding**: Disconnect planning preloads branch block bodies into memory; streaming bounded-memory disconnect is tracked under #206 (open).
## Proven by

- `crates/node/src/txindex_worker_reconcile_tests.rs`:
  - `forward_commit_overlapping_tip_extension_repairs_on_next_pass`
  - `forward_commit_overlapping_rival_reorg_repairs_on_next_pass`
  - `rollback_of_recanonicalized_watermark_repairs_on_next_pass`
  - `absent_tip_rolls_index_back_to_none`
  - `missing_disconnected_body_resets_and_rebuilds_selected_capabilities`
  - `stale_script_index_reset_preserves_ready_tx_lookup_then_rebuilds`
  - `missing_rollback_identity_resets_and_rebuilds_selected_capabilities`
  - `overflow_block_is_reprepared_and_committed_on_next_pass`
  - `reconciliation_plan_walks_the_tree`
  - `snapshot_identity_changes_reconcile_from_the_cursor_position`
  - `consumer_cursor_round_trips_bytes`
  - `interrupted_consumer_converges_to_the_uninterrupted_index_state`
- `crates/node/src/txindex_worker_query_tests.rs`: query gating, snapshot
  consistency, and revision ABA detection tests.
- `crates/node/src/txindex_worker_catchup_tests.rs`: multi-branch catchup,
  parallel batching, and watermark alignment tests.
- `bin/bitcoin-rs/tests/gates/g10_reorg_deep.rs`: reorganization planning,
  execution, disconnect restoration, and index reconciliation gate.
