# Mempool mutations contract

The single mutation gateway in front of the mempool, the records it emits,
and the ZMQ `sequence` mapping built on them. Owners: `MempoolGateway` in
`crates/mempool/src/gateway.rs`; `MutationResult`/`MutationOutcome`/
`RemovalReason` in `crates/mempool/src/mutation.rs`; the node-side observer
in `crates/node/src/mempool_observer.rs`; payload encoding in
`crates/node/src/zmq_publisher.rs`.

## Gateway invariant

- Every production mempool mutation routes through `MempoolGateway`. No
  production code outside the gateway takes the mempool write lock; lookups
  go through `MempoolGateway::read`.
- Every mutating method flows through one path, `commit`, in this exact
  order:
  1. take the pool write lock,
  2. mutate and assign per-change `mempool_sequence` values,
  3. acquire the publish mutex while still holding the write lock,
  4. drop the write lock,
  5. call the observer under the publish mutex,
  6. release the publish mutex.
- Taking the publish mutex before the write lock is released (step 3 before
  step 4) serializes publish acquisitions in commit order. An observer never
  sees a later-committed batch before, or interleaved with, an earlier one.
- The write lock is never held across an observer call. A slow or blocked
  observer delays later publications; it can never roll anything back or
  reorder the stream. Sequences were assigned in step 2, so a lagging
  observer still sees a gap-free, ordered stream.
- Observers are best-effort mirrors. Observer errors and panics never affect
  the committed mutation. An observer must never route mutations back
  through the gateway or otherwise take the mempool write lock: re-entrancy
  deadlocks.

## Mutation records

- Every mutating `Mempool` method returns `MutationResult`: an ordered
  `Vec<MutationChange>`, one change per affected transaction, in commit
  order. Each change carries the txid and a `MutationOutcome`:
  `Accepted`, or `Removed(RemovalReason)`.
- `RemovalReason` is one of `BlockInclusion`, `Conflict`, `Replaced`,
  `Descendant`, `PolicyEviction`, `Expiry`, `Explicit`, `Clear`, `Reorg`.
- `Mempool::sequence_number` advances exactly once per emitted change while
  the write lock is held. A failed insert, a no-op removal, and a clear of
  an empty pool assign nothing.

## ZMQ `sequence` mapping

- `SequenceEvent::Added(Txid, seq)` publishes label `A` (`0x41`);
  `SequenceEvent::Removed(Txid, seq)` publishes label `R` (`0x52`).
- Body frame for `A`/`R`: reversed txid (32 bytes) + label byte (1) +
  mempool sequence as little-endian u64 (8) = 41 bytes. The transport's own
  4-byte counter stays in its separate trailing frame.
- `BlockInclusion` emits no `R`: the block `C` event covers it. Every other
  removal reason emits `R`. Accepted changes emit `A`. One event per change,
  in commit order.

## Proven by

- `crates/mempool/src/gateway.rs` (inline tests):
  `accepted_and_removed_events_arrive_in_commit_order`,
  `remove_for_block_reports_block_inclusion_not_explicit`,
  `failed_insert_and_noop_remove_publish_nothing`,
  `replacement_tags_direct_conflicts_and_descendants`,
  `observer_panic_does_not_roll_back_the_mutation`,
  `insert_reports_accepted_then_policy_evictions`,
  `sequence_base_matches_per_change_assignment`.
- `crates/node/src/mempool_observer.rs`:
  `admission_publishes_one_a_frame_with_core_payload_bytes`,
  `explicit_removal_publishes_r_frames_in_commit_order`,
  `block_inclusion_suppresses_r_frames`,
  `policy_eviction_publishes_r_frames_with_contiguous_sequences`.
- `crates/node/src/zmq_publisher.rs`:
  `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence`,
  `sequence_event_payload_uses_core_hash_orientation_and_label`.
