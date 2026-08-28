# Chain events contract

The seam between the block-apply commit path and index consumers that mirror
the applied chain. Owners: `ChainSnapshot`, `ChainEventHint`,
`ChainEventPublisher`, `NodeState::active_chain_snapshot` in
`crates/node/src/state.rs`; `ConsumerCursor` and the reconciliation plan in
`crates/node/src/reconcile.rs`.

## Snapshot

- `ChainSnapshot { epoch, sequence, tip_hash, tip_height }` is a coherent,
  non-torn view of the applied tip. The single writer replaces the whole cell
  under one `RwLock`; a reader never sees a torn mix of two commit points.
- `epoch` is a persisted, strictly monotonic counter per data dir. It changes
  only across process restarts.
- `sequence` advances once per committed connect and once per committed
  disconnect. It starts at `1` on the first `record` of a run; `0` means no
  committed event yet this run.
- The snapshot is a live value. It is never persisted per-event.
- Readers use `NodeState::active_chain_snapshot()`.

## Hints

- One `ChainEventHint { kind, height, hash, epoch, sequence }` per committed
  event. `kind` is `Connected` or `Disconnected`.
- `ChainEventPublisher::record` runs in this order: advance the sequence,
  replace the snapshot cell, emit the hint. A consumer woken by a hint
  therefore reads a snapshot at least as fresh as the hint.
- Hints travel over a bounded channel (`CHAIN_HINT_CHANNEL_LIMIT`, sized from
  `INBOUND_BLOCK_CHANNEL_LIMIT`). The send is non-blocking: a full channel
  drops the hint and never blocks the commit path.
- A dropped hint is not a bug. Hints are wake-ups, not a replay log. They
  carry no payload to apply. Recovery is always positional: read a fresh
  snapshot, re-plan from the consumer's persisted cursor over the chain
  itself. Ancestry comes from `BlockTree::active_node_at_height` and
  `BlockTree::find_common_ancestor` (`crates/chain`); bodies come from
  `PruneBodyStore::load_block_body`.

## Consumer cursor

- `ConsumerCursor { epoch, sequence, height, hash }` names the chain state a
  consumer's rows already mirror. Durable form is `CURSOR_BYTE_LEN` = 52
  bytes: epoch (8 LE) + sequence (8 LE) + height (4 LE) + hash (32 LE).
- A cursor from an older epoch keeps its rows but loses its advisory
  identity: the consumer re-plans from its row position before trusting it.
- Row mutations and the cursor commit in one consumer-owned atomic batch.
  The txindex worker (`crates/node/src/txindex_worker.rs`) is the reference
  consumer; later index consumers copy this shape.

## Proven by

- `crates/node/src/state.rs`: `record_publishes_snapshot_and_hints_in_commit_order`,
  `record_drops_hints_when_channel_full`,
  `active_chain_snapshot_starts_at_genesis_on_fresh_node`,
  `active_chain_snapshot_anchors_at_restored_tip_after_restart`.
- `crates/node/src/txindex_worker_reconcile_tests.rs`:
  `forward_commit_overlapping_tip_extension_repairs_on_next_pass`,
  `forward_commit_overlapping_rival_reorg_repairs_on_next_pass`,
  `snapshot_identity_changes_reconcile_from_the_cursor_position`,
  `missing_disconnected_body_resets_and_rebuilds_selected_capabilities`,
  `stale_script_index_reset_preserves_ready_tx_lookup_then_rebuilds`,
  `consumer_cursor_round_trips_bytes`.
