# Synchronization regression domains (#1190)

This is the sync-convergence slice of [#1190](https://github.com/gosuda/bitcoin-rs/issues/1190).
It maps Bitcoin Core synchronization functional/regression tests to bitcoin-rs
observable invariants, grouped by externally meaningful failure domain instead
of by our internal sync/state-machine structure. The reorg/chainstate/mempool
slice is owned by [#1280](https://github.com/gosuda/bitcoin-rs/issues/1280) and
documented in [REORG-COVERAGE.md](REORG-COVERAGE.md); domain 5 below only
cross-references it.

What this document is **not**: a plan to behave internally like Core. Exact
peer-selection order, internal queues, Core-specific RPCs, and
implementation-specific state are not compatibility requirements unless they
are operationally required for Bitcoin interoperability. bitcoin-rs
intentionally omits optional Core behavior that is not required for consensus
or normal full-node participation. Every row below compares observable
postconditions only:

- the node eventually reaches the highest-work valid chain
- a stalled or disconnected peer cannot permanently stop progress
- missing ancestry can be recovered from another capable peer
- header tip and applied tip eventually converge
- an interrupted or restarted node reconstructs a consistent chainstate
- an invalid branch does not poison future valid synchronization

Core references pin
[`v31.1`](https://github.com/bitcoin/bitcoin/tree/v31.1/test/functional), the
version the compatibility gates track. Coverage levels in the tables:

- **process** — a real `bitcoin-rs` binary process, judged over its public
  RPC/P2P/REST surfaces (sometimes against a pinned Core process)
- **wire** — a real socket to a real node, driven by a scripted peer; the node
  itself runs in-process
- **internal** — sync state-machine or recovery unit test with no live socket;
  it proves the internal invariant only

A domain is not "covered" because an internal test exists. Status lines state
which levels hold.

## Complementary verification layers

`qa-assets` and `bitcoinfuzz` are complementary layers, not substitutes for the
stateful sync regression coverage mapped here. `qa-assets` is an external fuzz
corpus source: malformed and pathological serialized inputs, parser/decoder
edge cases, script/transaction/block corpora. `bitcoinfuzz` is
cross-implementation differential testing at component level: serialization,
script evaluation, transaction/block checks, P2P message parsing,
protocol primitives. Neither models long-lived node behavior — headers-first
sync, peer failover, stalled block download, competing branches, reorg
progression, restart/persistence during partial sync. The verification stack
therefore owns distinct surfaces: **qa-assets** (fuzz corpora/pathological
inputs), **bitcoinfuzz** (component differential), **this mapping**
(stateful sync/reorg/IBD behavior), and **bitcoin-rs internal tests**
(implementation-specific invariants).

## 1. Initial headers sync

Bitcoin Core:

- [`p2p_initial_headers_sync.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_initial_headers_sync.py)
  — initial headers sync from one peer until nearly caught up; one `getheaders`
  per block announcement; peer timeout during initial headers sync, including
  normal disconnect vs `noban`
- [`p2p_headers_sync_with_minchainwork.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_headers_sync_with_minchainwork.py),
  [`feature_minchainwork.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_minchainwork.py)
  — `nMinimumChainWork` gates header/block acceptance and IBD exit
- [`p2p_unrequested_blocks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_unrequested_blocks.py)
  — low-work unrequested blocks are not processed
- [`p2p_sendheaders.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_sendheaders.py)
  — headers-announcement route to the tip

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| A node pointed at a Core peer reaches the same tip as that peer | `e2e/tests/p2p_sync.rs`: `node_syncs_core_chain_to_tip` | process |
| An announced tip is admitted as headers first, fetched with witness bodies, and applied to the announced tip | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: `announced_tip_fetches_witness_block_and_applies_segwit_chain` | wire |
| Repeated near-tip announcements keep advancing the applied tip without a stall | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: `announced_live_head_applies_and_continues` | wire |
| Header chains below the assumed-work floor never reach the block tree | `crates/p2p/src/sync/tests/headers_presync.rs`: `low_work_headers_do_not_reach_block_tree` | internal |
| A chain crossing the work floor is re-verified against salted commitments before admission | `headers_presync.rs`: `sufficient_work_chain_syncs_presync_then_redownload` | internal |
| A header batch with a mid-batch continuity break is rejected whole | `headers_presync.rs`: `a_midbatch_continuity_break_spends_the_sync` (pinned to Core `CheckHeadersAreContinuous`) | internal |
| A header page that ends below the work floor caps that peer's horizon instead of reselecting it forever | `headers_presync.rs`: `a_terminal_low_work_page_demotes_the_source` | internal |
| A headers batch with a missing parent requests ancestry instead of stalling | `crates/p2p/src/sync/tests/head_sync.rs`: `headers_batch_missing_parent_requests_ancestry` | internal |
| `getheaders` serves the active chain with stop-hash and 2000-header limits matching Core | `crates/p2p/tests/core_compat.rs`: `getheaders_serves_active_chain_with_stop_hash_and_limit`, `headers_responses_truncate_at_the_core_2000_limit` | internal (wire frames) |
| Oversized `getheaders` locators and >2000-header batches are rejected at the boundary | `core_compat.rs`: `oversized_getheaders_locator_disconnects_before_state_mutation`; `crates/p2p/tests/wire_codec.rs`: `rejects_getheaders_message_with_more_than_max_locator_hashes`, `rejects_headers_message_with_more_than_2000_headers` | internal (wire frames) |
| Valid header batches across pages are accepted and bad `nbits` rejected | `crates/chain/tests/header_sync_roundtrip.rs`: `accepts_valid_headers_across_batches_and_rejects_bad_bits` | internal |

Status: wire and internal levels hold; the process level holds for the
Core-peer sync path (`spawn_synced_pair`).

Missing:

- The one-peer-at-a-time initial `getheaders` selection and the announcement
  fan-out rule of `p2p_initial_headers_sync.py` are Core-internal scheduling
  policy; per the constraint above they are **not** compatibility
  requirements. The externally observable half — peer timeout during initial
  headers sync and its disconnect-vs-noban outcome — has no bitcoin-rs test at
  any level. `crates/p2p/src/sync/tests/chain_sync.rs` probes and retires
  lagging connections (`behind_tip_connection_is_probed_then_retired`,
  `a_claimed_height_without_headers_is_probed_then_retired`) but nothing names
  the `noban`-vs-ban distinction.
- The `nMinimumChainWork` header-side fixture exists
  (`headers_presync.rs` presync floor), but no test asserts that a peer whose
  best chain is below `minimum_chain_work` is refused for block download as
  `feature_minchainwork.py` does.
- No test covers the headers-announcement (`sendheaders`) route specifically;
  the inv → `getheaders` probe route is what `live_head_carried_e2e.rs`
  exercises.

## 2. Block download / inflight management

Bitcoin Core:

- [`p2p_block_sync.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_block_sync.py)
  — IBD completes from inbound peers
- [`p2p_getdata.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_getdata.py),
  [`p2p_unrequested_blocks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_unrequested_blocks.py)
  — request/response discipline, unrequested bodies
- [`p2p_node_network_limited.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_node_network_limited.py)
  — pruned peers serve only the retained window
- [`p2p_compactblocks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_compactblocks.py),
  [`p2p_mutated_blocks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_mutated_blocks.py)
  — BIP152 relay and mutated-block resistance
- [`p2p_ibd_txrelay.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_ibd_txrelay.py)
  — transaction relay gating during IBD

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| Block requests start at the next unapplied height and already-pending blocks are not re-requested | `crates/p2p/src/sync/tests/behavior_2.rs`: `tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch`, `second_tick_does_not_re_request_already_pending_blocks` | internal |
| Inflight volume per peer and per request budget is bounded | `behavior_2.rs`: `tick_respects_pending_byte_budget`, `tick_limits_inflight_per_peer`, `tick_fans_out_getdata_across_eligible_peers` (`behavior_6.rs`) | internal |
| Expired pending requests are retried before new heights are requested | `crates/p2p/src/sync/tests/behavior_4.rs`: `tick_retries_expired_pending_before_new_heights`, `tick_fills_mixed_retry_and_new_height_batch` | internal |
| Contiguous blocks apply before more are requested; an oversized body releases its budget for retry | `behavior_4.rs`: `tick_applies_contiguous_blocks_before_requesting_more`, `oversized_received_block_releases_pending_budget_for_retry` | internal |
| Pruned/limited peers are not asked for bodies during IBD or outside their retained window | `crates/p2p/src/sync/tests/limited_peers.rs`: `predicate_excludes_limited_peer_during_initial_block_download`, `tick_asks_no_bodies_from_limited_peer_during_initial_block_download`, `tick_asks_no_bodies_from_limited_peer_beyond_retained_window` | internal |
| Compact blocks are served by depth: `cmpctblock`, `blocktxn`, and an empty `getblocktxn` delta list | `bin/bitcoin-rs/tests/compact_blocks_e2e.rs`: `serves_compact_by_depth_on_the_wire`, `serves_blocktxn_by_depth_on_the_wire`, `empty_getblocktxn_disconnects_on_the_wire` | wire |
| A compact block whose prefilled body does not match its header falls back to the full body from the same peer before applying | `compact_blocks_e2e.rs`: `wrong_root_compact_block_falls_back_to_same_peer` (pinned to Core 31.1 `blockencodings.cpp`/`net_processing.cpp` behavior) | wire |
| A node in IBD ignores transaction announcements until out of IBD, then requests them | `bin/bitcoin-rs/tests/tx_ibd_gate_e2e.rs`: `ibd_node_ignores_then_requests_relay_transactions` | wire |
| `getdata`/`inv`/`notfound` bounds match Core's 50k inventory limit | `crates/p2p/tests/core_compat.rs`: `getdata_bound_of_50k_vectors_matches_core_max_inv`, `inv_getdata_relay_round_trip_serves_blocks_and_notfounds_misses` | internal (wire frames) |
| A node dials a Core peer and follows extended history as it is mined | `e2e/tests/p2p_sync.rs`: `node_follows_extended_core_chain` | process |
| Blocks are requested as witness bodies; the reorg/switch path matches Core's applied ancestry for retained lookups | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: `announced_tip_fetches_witness_block_and_applies_segwit_chain`; `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: `retained_transaction_confirmations_match_core_after_reorg` | wire / process |

Status: internal level is strong (request budgets, fanout, retry ordering);
wire level holds for compact-block serving, the witness fetch path, and the
IBD transaction gate.

Missing:

- No `p2p_block_sync.py`-shaped scenario: IBD completed with **only inbound
  peers and no outbound peer**. The scripted-peer process tests do drive the
  node over inbound connections, but none asserts the "no outbound exists"
  variant explicitly.
- Unrequested/low-work body floods at the wire level are untested; the refusal
  exists internally (`crates/p2p/src/sync/tests/head_sync.rs`:
  `unrequested_body_at_the_count_budget_is_refused`,
  `validation_1.rs`: `received_only_state_uses_scan_path_without_duplicate_request`).
- `p2p_mutated_blocks.py`'s specific claim — an attacker cannot clear honest
  peers' in-flight `blocktxn` requests with unsolicited mutated blocks — has
  no direct equivalent. The nearest internal tests are
  `crates/p2p/src/sync/tests/witness_staging_gate.rs`
  (`malformed_body_dropped_then_correct_body_staged`,
  `malformed_pending_owner_is_disconnected_and_other_peer_gets_same_hash`)
  and `behavior_6.rs`: `mutated_forward_body_preserves_descendant_for_retry`.
- High-bandwidth compact-block negotiation
  (`p2p_compactblocks_hb.py`) has no equivalent; BIP152 relay with a live Core
  peer is covered by `crates/p2p/tests/core_interop_live.rs`:
  `live_bitcoin_core_p2p_interop_matches_contract` (evidence-gated, see §9).

## 3. Stalled peer recovery and failover

Bitcoin Core:

- [`p2p_ibd_stalling.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_ibd_stalling.py)
  — stalling logic during IBD
- [`p2p_timeouts.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_timeouts.py)
  — request timeouts
- Historical sync regressions: Core's stall-detection and
  peer-rotation fixes (`net_processing.cpp` stalling work)

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| A stalled window front wedges into request backpressure; the staller is not churned away | `crates/p2p/src/sync/tests/behavior_3.rs`: `stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn` | internal |
| A cold-start stall hedges the front without reassigning the owning request | `behavior_3.rs`: `cold_start_stall_hedges_front_without_reassigning_owner` | internal |
| When the eligible peer pool recovers, fanout replaces the preferred peer | `behavior_3.rs`: `fanout_replaces_preferred_peer_when_eligible_pool_recovers` | internal |
| Apply-side backpressure is never blamed on the front peer | `behavior_3.rs`: `apply_side_backpressure_never_blamed_on_front_peer`, `staged_frontier_stuck_past_bound_escalates_without_blame` | internal |
| A wedged window expires the stalled front, re-requests through the count clamp, and a byte-wedged window recovers by disconnecting the staller | `crates/p2p/src/sync/tests/transitions_4.rs`: `wedged_window_expires_stalled_front_and_rerequests_through_count_clamp`, `byte_wedged_window_recovers_via_staller_disconnect_before_received_timeout` | internal |
| A same-address reconnect neither inherits its predecessor's stalled inflight nor loses its own work | `transitions_4.rs`: `same_address_reconnect_does_not_inherit_stalled_inflight`; `frontier_model.rs`: `convicted_connection_cannot_pass_its_stall_to_a_replacement` (#1129) | internal |
| Stall eviction never disconnects the replacement connection | `transitions_4.rs`: `stall_eviction_does_not_disconnect_replacement_connection` | internal |
| Slow-but-served download is never misread as a stall: a trickling front peer is observed but not disconnected, and uniform slow fanout completes without disconnects | `crates/p2p/src/sync/tests/transitions_5.rs`: `slow_trickle_front_peer_observable_but_never_disconnected`, `uniform_slow_saturated_fanout_disconnects_no_peer_and_completes`, `single_peer_can_fill_default_pending_window` | internal |
| A mid-window peer disconnect requeues its blocks to remaining peers; a sole staller is disconnected and usable again as last resort | `crates/p2p/src/sync/tests/transitions_6.rs`: `peer_disconnect_mid_window_requeues_blocks_to_remaining_peers`, `sole_peer_staller_disconnected_and_usable_again_as_last_resort`, `reconnecting_staller_held_out_of_window_front_by_cooldown` | internal |
| A frontier whose owner dies recovers as unowned and schedules recovery on a capable peer; probes rotate past dead owners and evict them | `crates/p2p/src/sync/tests/frontier_model.rs`: `unowned_frontier_schedules_recovery_when_a_capable_peer_exists`, `in_flight_frontier_on_a_dead_connection_recovers_as_unowned`, `probe_rotates_past_the_dead_pending_owner`; `frontier_recovery.rs`: `failed_probe_send_falls_back_to_best_peer_in_the_same_tick`, `dead_probe_peer_is_evicted_and_not_repicked_on_the_next_tick` | internal |
| After serving peers time out one after another, replacements carry the frontier and the apply frontier advances | `crates/p2p/src/sync/tests/issue_1153.rs`: `replacements_carry_frontier_after_serving_peer_timeouts` (#1153) | internal |
| Expired pending requests demote the owning peer and retry on an alternate peer | `behavior_1.rs`: `tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer` | internal |
| A stale-tip node is allowed to dial extra outbound peers past its slot cap | `crates/p2p/src/sync/tests/stale_tip.rs`: `the_stale_tip_allowance_dials_past_the_slot_cap` (pinned to Core `ThreadOpenConnections`) | internal |
| Two-peer failover at the wire: one peer serves every body but the tip and then disconnects mid-download; a second peer's untracked body delivery still converges the chain to the tip with no request-cursor rewind | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: `untracked_delivery_of_tree_known_block_converges` | wire |
| A body arriving with an unknown parent is recovered via `getheaders` and applied in place once ancestry lands | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: `missing_parent_delivery_recovers_via_getheaders` | wire |
| A stalled P2P connection hits its deadline and the peer slot is released | `bin/bitcoin-rs/tests/overhaul_process_p2p.rs`: `p2p_timeout_releases_the_connected_peer_and_process`, `p2p_connect_to_an_absent_listener_has_a_fixed_deadline` | process |

Status: internal level covers the stall/failover state machine in depth; wire
level covers one two-peer mid-download failover (`head_sync_e2e.rs` T4) and
one missing-ancestry recovery; process level covers only deadline-driven peer
release. The headline `p2p_ibd_stalling.py` invariant — *a stalled peer during
IBD cannot permanently stop sync progress* — is **not asserted end-to-end at
process level**.

Missing:

- No process-level test where a live peer serves headers then stalls block
  delivery mid-IBD while a second live peer carries the node to the tip. The
  T4 wire case covers the disconnection half of this, but not a peer that
  stays connected while stalling, and not through the public RPC surfaces.
- `p2p_timeouts.py`-style ping/pong latency measurement is intentionally
  deviating (`e2e/tests/p2p_sync.rs`: `ping_answers_immediately` documents the
  deviation); only connect/request deadlines are pinned.

## 4. Competing branches and chain selection

Bitcoin Core:

- [`feature_block.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_block.py)
  — competing and invalid chains (see [REORG-COVERAGE.md](REORG-COVERAGE.md)
  for the reorg execution half)
- [`feature_chain_tiebreaks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_chain_tiebreaks.py)
  — earliest-received tip wins an equal-work tie
- [`rpc_getchaintips.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_getchaintips.py)
  — branch visibility
- [`rpc_invalidateblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_invalidateblock.py)
  — manual branch switching

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| An equal-work rival does not displace the applied chain; a strictly higher-work branch does, and committed coins converge with a clean sync | `e2e/tests/reorg_state.rs`: `equal_work_then_one_block_reorg_matches_clean_sync` | process |
| A deeper competing branch mined on Core re-points the node tip; the old branch is gone from the active height map | `e2e/tests/reorg.rs`: `core_reorg_repoints_node_tip` | process |
| A duplicate equal-work competing child keeps its original id and does not reorg (first-received tiebreak) | `crates/chain/tests/header_sync_roundtrip.rs`: `duplicate_equal_work_competing_child_returns_original_id_and_does_not_reorg` | internal |
| A staged higher-work winner stays staged across the pending switch instead of drain/fail/re-request cycles | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: `pending_reorg_keeps_staged_winner_then_switches` | wire |
| Fork download starts at the common-ancestor child; buffered applies wait for the pending reorg | `crates/p2p/src/sync/tests/behavior_1.rs`: `fork_getdata_starts_at_common_ancestor_child`, `pending_reorg_frontier_is_first_connect_node`, `apply_buffered_blocks_waits_for_pending_reorg` | internal |
| Retargeting drops losing-branch hashes from pending requests and staged bodies; an outweighed branch target accepts a shorter higher-work branch | `crates/p2p/src/sync/tests/transitions_2.rs`: `retargeting_pending_requests_drops_losing_branch_hashes`, `retarget_purges_staged_off_branch_bodies`, `outweighed_branch_target_accepts_shorter_higher_work_branch` | internal |
| A deeper reorg plans to the common fork | `crates/chain/tests/reorg_deep.rs`: `plans_deep_reorg_to_common_fork` | internal |
| A branch switch whose plan races a competing connect replans on the moved tip and still lands | `crates/node/tests/unit/sync/tests/transitions_2.rs`: `branch_switch_replans_after_a_competing_connect_before_transition` | internal |
| Peer-visible chain identity follows the reorg | `crates/p2p/tests/core_compat.rs`: `reorg_switches_which_chain_a_peer_sees` | internal (wire frames) |
| `getchaintips` reports the active tip and, after a rewind, the dead branch remains visible with a valid status | `e2e/tests/chain_queries.rs`: `chain_tips_and_tx_stats`; `e2e/tests/reorg.rs`: `invalidateblock_rewinds_tip` | process |
| `invalidateblock` rewinds the tip and mining continues on a provably different branch | `e2e/tests/reorg.rs`: `invalidateblock_rewinds_tip` | process |

Status: process and internal levels hold; wire level holds for the
staged-winner case. Natural (non-`invalidateblock`) higher-work switching is
covered at process level via Core-mined competitors.

Missing:

- `feature_chain_tiebreaks.py` also covers timestamp/first-seen tiebreaks
  beyond the duplicate-child case; only the first-received equal-work
  invariant is mapped.
- [`rpc_preciousblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_preciousblock.py)
  has no equivalent surface: `preciousblock` is
  [`Unimplemented`](../crates/rpc/src/registry.rs) ("No manual
  block-preference surface"), and per the constraint it is not a
  compatibility requirement. [`rpc_invalidateblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_invalidateblock.py)
  is covered above; `reconsiderblock` is likewise `Unimplemented`.

## 5. Reorg execution and recovery

Owned by [#1280](https://github.com/gosuda/bitcoin-rs/issues/1280); the full
mapping lives in [REORG-COVERAGE.md](REORG-COVERAGE.md). Snapshot of what that
slice proves, for domain completeness:

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| Multi-block disconnect/forward-connect mempool reconciliation equals a clean sync | `e2e/tests/reorg_state.rs`: `deep_reorg_mempool_matches_clean_sync` | process |
| A consensus-invalid higher-work branch cannot change committed coins and cannot poison later valid sync | `e2e/tests/reorg_state.rs`: `invalid_higher_work_body_cannot_change_active_chain` | process |
| ZMQ `sequence` reports exact disconnect-then-connect order | `crates/rpc/tests/reorg_notifications.rs`: `sequence_reports_exact_disconnect_connect_order` | process |
| SIGKILL/restart around a branch switch preserves the settled chainstate | `e2e/tests/reorg_state.rs`, `crates/rpc/tests/reorg_notifications.rs` per [REORG-COVERAGE.md](REORG-COVERAGE.md) `RCV-08` row | process |
| A permanent reorg failure invalidates descendants; a mutated connect body through a switch preserves the subtree | `crates/node/tests/unit/sync/tests/transitions_3.rs`: `permanent_reorg_failure_invalidates_descendants`; `crates/node/tests/unit/sync/tests/transitions_7.rs`: `mutated_connect_body_through_switch_to_branch_preserves_subtree` | internal |
| A deep reorg streams bounded prefixes to an independently replayed reference | `crates/node/tests/unit/state/tests/recovery.rs`: `deep_reorg_streams_bounded_prefixes_to_the_exact_reference` | internal |
| Pruning keeps the Core reorg floor and a shallow reorg still succeeds | `crates/storage/tests/prune_then_reorg.rs`: `pruning_keeps_core_reorg_floor_and_shallow_reorg_succeeds` | internal |
| Readiness returns to ready on the forked tip after a reorg | `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: `reorg_returns_readiness_to_ready_on_the_forked_tip` | process |

Core references in this domain are enumerated in
[REORG-COVERAGE.md](REORG-COVERAGE.md) (`feature_block.py`,
`mempool_reorg.py`, `interface_zmq.py`, Core `ReplayBlocks` recovery). Gaps
recorded there — e.g. `savemempool`/mempool reload is `Unimplemented`
(`crates/rpc/src/registry.rs`) — stay gaps here too.

## 6. Header-tip vs applied-tip convergence

Bitcoin Core:

- [`p2p_initial_headers_sync.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_initial_headers_sync.py),
  [`rpc_blockchain.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_blockchain.py)
  — `getblockchaininfo`'s `headers`/`blocks` split and IBD progress
- [`feature_maxtipage.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_maxtipage.py)
  — IBD exit semantics by tip age

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| While headers run ahead of bodies, the node keeps fetching and applying until the two tips converge | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: `announced_live_head_applies_and_continues` (observed heights are monotonic once an earlier tip applied) | wire |
| An applied-tip rewind with unchanged headers refetches the missing prefix | `crates/p2p/src/sync/tests/frontier_recovery.rs`: `applied_rewind_with_unchanged_headers_refetches_the_missing_prefix` | internal |
| Header sync requests stop when the header tip matches the peer's height | `crates/p2p/src/sync/tests/transitions_3.rs`: `tick_skips_getheaders_when_header_tip_matches_peer_height` | internal |
| The frontier reports `at_tip` only when applied reaches header tip; unresolvable diverged tips are reported as such | `crates/p2p/src/sync/tests/frontier_model.rs`: `at_tip_reports_at_tip`, `diverged_tips_with_unresolvable_frontier_report_frontier_unresolvable` | internal |
| `getblockchaininfo` reports `headers` and `blocks` from one coherent published pair, even mid-transition | `crates/rpc/src/handlers/chain.rs` (`headers: i64::from(progress.headers)`); `crates/rpc/tests/core_parity.rs`: `getblockchaininfo_returns_during_chain_transition` | internal |
| The node exits IBD only with enough work and a recent tip, against Core's default 24h window | `crates/chain/src/ibd.rs` inline tests: `a_recent_tip_with_enough_work_exits_initial_block_download`, `a_stale_tip_with_enough_work_is_still_initial_block_download`, `a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download`, `the_tip_age_boundary_is_twenty_four_hours` | internal |

Status: convergence is asserted at wire level by the live-head tests and at
internal level by the frontier model; the `headers` vs `blocks` publication
pair is asserted at the RPC boundary.

Missing:

- No process-level test that pins `getblockchaininfo.headers` ahead of
  `blocks` during a partially synced catch-up and then equal at convergence.
- `feature_maxtipage.py`'s process-level claim (a node whose tip is older than
  the window stays in IBD) has no process-level equivalent; `-maxtipage` is not
  an option yet (`crates/chain/src/ibd.rs`: "this node has no such option yet,
  so the default stands").

## 7. Restart / persistence during partial sync

Bitcoin Core:

- [`feature_dbcrash.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_dbcrash.py)
  — repeated crash-restart during sync with varying dbcache
- [`mempool_persist.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/mempool_persist.py)
  — pool persistence across restart
- [`feature_reindex.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_reindex.py),
  [`feature_reindex_init.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_reindex_init.py),
  [`feature_reindex_readonly.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_reindex_readonly.py),
  [`feature_loadblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_loadblock.py)
  — rebuild-from-blocks paths
- Core `ReplayBlocks` recovery behavior (see [REORG-COVERAGE.md](REORG-COVERAGE.md))

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| A node restarted mid-chain keeps its tip and catches up on new blocks without a fresh full sync | `e2e/tests/reorg.rs`: `restart_mid_chain_resumes_sync` | process |
| A mined tip survives a clean restart over the same datadir | `e2e/tests/lifecycle.rs`: `restart_preserves_chain_tip` | process |
| Clean restart restores readiness at the pinned tip with indexes intact; a destroyed index rebuilds from canonical data | `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: `clean_restart_restores_ready_readiness_at_the_pinned_tip`, `destroyed_index_rebuilds_from_canonical_data_and_restores_history` | process |
| A restarted node answers peers identically | `crates/p2p/tests/core_compat.rs`: `restart_rebuild_serves_identical_answers_to_peers` | internal (wire frames) |
| SIGKILL leaves a valid journal frontier; torn disconnects replay to the parent tip, cold replay to the head, and a checkpoint above head rewinds to head | `crates/node/tests/crash_recovery.rs`: `sigkill_restarts_at_valid_journal_frontier`, `torn_disconnect_replays_parent_tip`, `torn_disconnect_cold_replays_head`, `torn_disconnect_checkpoint_above_head_rewinds_to_head` | internal |
| A checkpoint far below the durable head replays the whole authenticated gap and lands on the head | `crash_recovery.rs`: `checkpoint_fallback_replays_wide_gap_to_durable_head`; `crates/chainstate/tests/unit/durable_replay_tests.rs`: `wide_authenticated_gap_replays_to_durable_head`, `committed_gap_replays_to_head_without_recommitting_it`, `cold_chainstate_replays_head_chain_from_genesis` | internal |
| Restart replays the durable journal suffix above the checkpoint; a disconnect rewrites the durable head before restart | `crates/node/tests/chainstate_journal.rs`: `restart_replays_durable_journal_suffix_above_checkpoint`, `disconnect_rewrites_durable_head_before_restart` | internal |
| The durable head precedes publication and survives restart; corrupt head rows fail startup closed | `crates/node/tests/overhaul_durable_head.rs`: `durable_head_precedes_publication_and_survives_restart`, `corrupt_head_rows_fail_startup_fail_closed` | internal |
| A restarted chainstate reconstructs a consistent tip: the active-chain snapshot anchors at the restored tip, missing checkpoints replay the durable head chain, and uncommitted tails are discarded | `crates/node/tests/unit/state/tests/events.rs`: `active_chain_snapshot_anchors_at_restored_tip_after_restart`; `crates/node/tests/unit/state/tests/recovery.rs`: `missing_checkpoint_replays_durable_head_chain_at_startup`, `checkpoint_resume_discards_only_incomplete_uncommitted_tail`, `full_revalidation_marker_resumes_on_durable_head` | internal |
| Prune frontier survives SIGKILL and refuses deleted history | `crates/node/tests/crash_recovery.rs`: `pruned_frontier_survives_sigkill_and_refuses_deleted_history`; `crates/storage/tests/prune_then_reorg.rs`: `executed_frontier_survives_restart_and_refuses_deleted_heights` | internal |

Status: restart-persistence is the strongest domain — one process-level
partial-sync restart, three process-level clean-restart/rebuild tests, and a
deep deterministic crash matrix internally.

Missing:

- `feature_dbcrash.py`'s randomized repeated-crash campaign (crash ratios,
  varying dbcache, long sync loops) has no equivalent; crash coverage is the
  deterministic boundary matrix above.
- [`mempool_persist.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/mempool_persist.py)
  has no equivalent: `savemempool`/`importmempool` are `Unimplemented`
  (`crates/rpc/src/registry.rs`, "Mempool dump/reload persistence not
  implemented"). Restart assertions cover durable chainstate, not pool
  persistence (same note as [REORG-COVERAGE.md](REORG-COVERAGE.md)).
- `feature_reindex.py` / `feature_reindex_init.py` /
  `feature_reindex_readonly.py` / `feature_loadblock.py` have no equivalents:
  there is no `-reindex`/`-reindex-chainstate` or `bootstrap.dat` load path.
  Recorded as gaps, not as compatibility requirements; revisit if a block
  rebuild-from-blocks path is added.

## 8. Invalid peer attribution and recovery

Bitcoin Core:

- [`p2p_invalid_block.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_invalid_block.py)
  — invalid blocks are rejected and re-request behavior differs by failure
- [`p2p_invalid_messages.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_invalid_messages.py),
  [`p2p_invalid_locator.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_invalid_locator.py)
  — malformed protocol input is attributed and disconnects only the offender
- [`p2p_mutated_blocks.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_mutated_blocks.py)
  — mutated bodies do not degrade honest relay
- [`p2p_disconnect_ban.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_disconnect_ban.py),
  [`rpc_setban.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_setban.py)
  — ban semantics

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| Invalid `nbits` headers disconnect the source and rotate `getheaders`; unattributed invalid headers disconnect nobody | `crates/p2p/src/sync/tests/transitions_4.rs`: `invalid_nbits_headers_disconnect_source_and_rotate_getheaders`, `unattributed_invalid_headers_do_not_disconnect_any_peer` | internal |
| A substituted header in the redownload pass disconnects the connection that served it and admits nothing | `crates/p2p/src/sync/tests/headers_presync.rs`: `a_substituted_redownload_header_disconnects_the_connection` | internal |
| Body-carried low-work bad PoW/nbits headers are discarded and fault the delivering peer | `headers_presync.rs`: `body_carried_low_work_bad_pow_is_discarded_and_faults_peer`, `body_carried_low_work_bad_nbits_is_discarded_and_faults_peer` | internal |
| Rejected matching peer headers release the `getheaders` gate and retry immediately; orphan headers keep the source connected | `crates/p2p/src/sync/tests/behavior_1.rs`: `rejected_matching_peer_headers_release_gate_and_retry_immediately`, `orphan_headers_keep_source_peer_connected` | internal |
| A malformed pending body's owner is disconnected and another peer can serve the same hash; a later correct body still stages | `crates/p2p/src/sync/tests/witness_staging_gate.rs`: `malformed_pending_owner_is_disconnected_and_other_peer_gets_same_hash`, `malformed_body_dropped_then_correct_body_staged`, `altered_non_witness_body_dropped_then_correct_body_staged` | internal |
| An inadmissible staged body is evicted; a stale source cannot settle its gate; rejected bodies restore peer credit | `crates/p2p/src/sync/tests/head_sync.rs`: `staged_body_with_permanently_inadmissible_header_is_discarded`, `staged_body_whose_resolved_header_is_inadmissible_is_evicted`, `stale_owned_fetch_source_does_not_settle_the_gate`; `witness_staging_gate.rs`: `idle_frontier_relearns_stale_peer_credit_after_rejected_body` | internal |
| A compact block whose prefilled body does not match its header never applies; the node refetches the real body | `bin/bitcoin-rs/tests/compact_blocks_e2e.rs`: `wrong_root_compact_block_falls_back_to_same_peer` | wire |
| A consensus-invalid higher-work branch cannot change committed coins and the valid branch keeps advancing | `e2e/tests/reorg_state.rs`: `invalid_higher_work_body_cannot_change_active_chain` | process |
| Malformed P2P frames fail the protocol without becoming behavior evidence; messages before handshake disconnect like Core | `bin/bitcoin-rs/tests/overhaul_process_p2p.rs`: `malformed_p2p_frames_are_protocol_failures_not_behavior_evidence`; `crates/p2p/tests/core_compat.rs`: `messages_before_handshake_disconnect_like_core`, `foreign_network_frames_are_rejected_before_payload_decode` | process / internal (wire frames) |
| Ban list round-trips over RPC | `e2e/tests/p2p_sync.rs`: `ban_list_round_trip`; `crates/p2p/tests/listener_ban.rs`: `outbound_ban_short_circuits_before_connect_with_typed_error`, `inbound_ban_drops_connection_pre_handshake` | process / internal |

Status: attribution rules are covered in depth internally and at wire level for
the compact-block case; the process level covers the invalid-branch invariant
and protocol-failure classification.

Missing:

- `p2p_invalid_block.py`'s re-request classification (duplicated-tx block is
  re-requested vs bad-coinbase block is not; future-timestamp blocks are
  accepted once valid) has no equivalent. The duplicate vs permanent-failure
  distinction exists internally (`witness_staging_gate.rs`, `behavior_6.rs`:
  `stale_invalid_headers_cannot_evict_or_clear_replacement`) but is not
  asserted per `p2p_invalid_block.py`'s scenario list.
- `p2p_invalid_locator.py` has no dedicated scenario; oversized locator
  rejection is covered at the codec level only
  (`crates/p2p/tests/wire_codec.rs`, `core_compat.rs`).
- Ban **expiry** over time has `crates/rpc/tests/setban_expiry.rs`; the
  `p2p_disconnect_ban.py` disconnect-vs-ban menu (e.g. `noban` disconnects)
  is unmapped, same as §1.

## 9. Tip-transition semantics and concurrency

Tracked as a dedicated section per
[#1190 comment](https://github.com/gosuda/bitcoin-rs/issues/1190#issuecomment-5864002451)
(PR #1275 exposed the failure class: a caller observes its commit outcome
correctly, then a post-release tip re-read mistakes a legitimate later
transition for a publication failure). The comparison target is Core's
**observable transition invariants**, not its locking structure — final best
block after convergence is not sufficient evidence.

Bitcoin Core:

- [`rpc_blockchain.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_blockchain.py),
  [`interface_rpc.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/interface_rpc.py)
  — chainstate reads answer coherently while blocks arrive
- [`feature_dbcrash.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_dbcrash.py),
  [`feature_reindex_init.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_reindex_init.py)
  — recovery after interrupted commits

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| A status read during a chain transition answers from the last complete published pair (`getblockchaininfo`, `getchaintxstats`), pinned to Core's typed wire shapes | `crates/rpc/tests/core_parity.rs`: `getblockchaininfo_returns_during_chain_transition`, `getchaintxstats_returns_during_chain_transition` (driven through the `replay_during_chain_transition` helper, which holds the node's real transition barrier from `crates/rpc/tests/support/harness.rs`) | internal |
| Concurrent reads during reorg/activation return coherent applied views | `crates/rpc/tests/core_parity.rs` barrier cases above; `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: `reorg_returns_readiness_to_ready_on_the_forked_tip` | internal / process |
| Disconnect debt is settled by branch switches and `invalidateblock`, and a completed switch releases its pruning retention authority exactly once | `crates/node/tests/unit/state/tests/recovery.rs`: `invalidate_block_settles_disconnect_debt`, `switch_to_branch_settles_disconnect_debt`, `switch_to_branch_releases_retention_authority_once` | internal |
| Restart after a committed transition reconstructs the exact pre-restart tip and `commit_id` | `crates/node/tests/unit/state/tests/recovery.rs` checkpoint-resume cases; `crates/node/tests/crash_recovery.rs` matrix (§7) | internal |
| Multi-block disconnect/reconnect sequences and natural higher-work reorgs land on the correct settled state | `e2e/tests/reorg_state.rs`, `crates/node/tests/unit/sync/tests/transitions_3.rs` (§4, §5) | process / internal |

Status: concurrent-read coherence at the RPC boundary is pinned; settlement
semantics and post-commit recovery are covered internally.

Missing:

- No deterministic barrier-controlled sequence reproducing exactly
  `A commit -> release transition -> B commit -> resume A's caller` with the
  assertion that A's caller does not treat tip B as evidence that A failed.
  The regression class was fixed in PR #1275 ("Preserve commit state in node
  mutation results"), but no permanent test pins the interleaving. This is the
  top gap in this section.
- No process-level concurrent connect interleaving (two blocks committing in a
  race through live RPC/P2P surfaces) and no process-level
  committed-but-settlement-failed restart case.

## 10. Out-of-scope Core behavior

Recorded so absence of coverage is not mistaken for a gap. These are Core
surfaces bitcoin-rs intentionally omits — optional behavior not required for
consensus or normal full-node participation — and are
[`Unimplemented`](../crates/rpc/src/registry.rs) by declaration:

- `preciousblock`, `reconsiderblock` (manual block preference) — see §4
- `savemempool`, `importmempool` (mempool dump/reload) — see §7
- `loadtxoutset` / `dumptxoutset` (`assumeutxo` snapshots),
  [`feature_assumeutxo.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_assumeutxo.py)
- `getblockfrompeer`, `waitforblock`/`waitforblockheight`/`waitfornewblock`,
  `scanblocks`, `getmempoolcluster`, `getaddrmaninfo`
- wallet-facing reorg tests
  ([`wallet_reorgsrestore.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/wallet_reorgsrestore.py),
  [`wallet_listsinceblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/wallet_listsinceblock.py)):
  no wallet
- `-reindex`/`-reindex-chainstate`/`loadblock` startup paths — currently a
  gap (§7), revisit if implemented

Adding any of these surfaces means adding its observable-invariant test here
first.

## Evidence and CI

The process-level suites (`e2e/`, `bin/bitcoin-rs/tests/`, the pinned-Core
pair tests) run in `scripts/ci-pr.sh test-workspace` after the pinned Core
binary is provisioned; the ZMQ process test has an explicit profile in that
lane. `crates/p2p/tests/core_interop_live.rs`
(`live_bitcoin_core_p2p_interop_matches_contract`) is `#[ignore]`d in ordinary
runs and judges evidence produced by `scripts/run-p2p-core-interop.sh` against
a live pinned `bitcoind` (handshake identity, chain identity, BIP152 relay).
Raw launch, RPC, and P2P evidence is retained under
`target/process-harness/e2e/` by the CI artifact upload.

When adding a sync test, give it a row in its domain with its observable
invariant and its level; do not record an internal state-machine test as a
process-level equivalent, and record missing coverage as a gap in the domain's
`Missing` list instead of inferring it.
