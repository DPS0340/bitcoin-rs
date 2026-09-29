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
version the compatibility gates track. All bitcoin-rs source links pin the
unchanged source tree at
[`73f9ee62115de60e6b89f1a05a97a71cd2032674`](https://github.com/gosuda/bitcoin-rs/tree/73f9ee62115de60e6b89f1a05a97a71cd2032674);
references to implementation files rather than tests are labeled **source
only**. Coverage levels in the tables:

- **process** — a real `bitcoin-rs` binary process, judged over its public
  RPC/P2P/REST surfaces (sometimes against a pinned Core process or driven by
  a scripted peer)
- **internal** — in-process component or recovery tests, sometimes using real
  loopback sockets; they do not launch the daemon and prove only the asserted
  component-level invariant
- **synthetic boundary** — a codec, dispatcher, harness, or query double. It
  proves that boundary's behavior, not daemon lifecycle, persistence, chain
  activation, or peer-visible node behavior

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
| A node pointed at a Core peer reaches the same tip as that peer | `e2e/tests/p2p_sync.rs`: [`node_syncs_core_chain_to_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/p2p_sync.rs#L15) | process |
| An announced tip is admitted as headers first, fetched with witness bodies, and applied to the announced tip | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: [`announced_tip_fetches_witness_block_and_applies_segwit_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/head_sync_e2e.rs#L187) | process |
| Repeated near-tip announcements keep advancing the applied tip without a stall | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: [`announced_live_head_applies_and_continues`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/live_head_carried_e2e.rs#L226) | process |
| Header chains below the assumed-work floor never reach the block tree | `crates/p2p/src/sync/tests/headers_presync.rs`: [`low_work_headers_do_not_reach_block_tree`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L158) | internal |
| A chain crossing the work floor is re-verified against salted commitments before admission | `headers_presync.rs`: [`sufficient_work_chain_syncs_presync_then_redownload`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L225) | internal |
| A header batch with a mid-batch continuity break is rejected whole | `headers_presync.rs`: [`a_midbatch_continuity_break_spends_the_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L508) (pinned to Core `CheckHeadersAreContinuous`) | internal |
| A header page that ends below the work floor caps that peer's horizon instead of reselecting it forever | `headers_presync.rs`: [`a_terminal_low_work_page_demotes_the_source`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L781) | internal |
| A headers batch with a missing parent requests ancestry instead of stalling | `crates/p2p/src/sync/tests/head_sync.rs`: [`headers_batch_missing_parent_requests_ancestry`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/head_sync.rs#L129) | internal |
| The production active-chain query honors an active stop hash and ignores stale-fork locators/stops | `crates/p2p/src/chain_query.rs`: [`getheaders_after_locator_stops_at_stop_hash`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/chain_query.rs#L540), [`getheaders_ignores_stale_fork_locator_and_stop`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/chain_query.rs#L554) | internal |
| Dispatch truncates a deliberately overlong query response at 2000 headers | `crates/p2p/src/dispatch.rs`: [`getheaders_truncates_chain_response_above_protocol_cap`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/dispatch.rs#L694) | synthetic boundary |
| Oversized `getheaders` locators and >2000-header batches are rejected at the codec/dispatcher boundary | `crates/p2p/tests/core_compat.rs`: [`oversized_getheaders_locator_disconnects_before_state_mutation`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L788); `crates/p2p/tests/wire_codec.rs`: [`rejects_getheaders_message_with_more_than_max_locator_hashes`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L203), [`rejects_headers_message_with_more_than_2000_headers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L263) | synthetic boundary |
| Valid header batches across pages are accepted and bad `nbits` rejected | `crates/chain/tests/header_sync_roundtrip.rs`: [`accepts_valid_headers_across_batches_and_rejects_bad_bits`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/tests/header_sync_roundtrip.rs#L13) | internal |

Status: process coverage holds for the Core-peer and scripted-peer sync paths;
internal coverage holds for header admission and production active-chain
query behavior. Codec/dispatcher limits remain synthetic-boundary evidence.

Missing:

- The one-peer-at-a-time initial `getheaders` selection and the announcement
  fan-out rule of `p2p_initial_headers_sync.py` are Core-internal scheduling
  policy; per the constraint above they are **not** compatibility
  requirements. The externally observable half — peer timeout during initial
  headers sync and its disconnect-vs-noban outcome — has no bitcoin-rs test at
  any level. `crates/p2p/src/sync/tests/chain_sync.rs` probes and retires
  lagging connections ([`behind_tip_connection_is_probed_then_retired`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/chain_sync.rs#L101),
  [`a_claimed_height_without_headers_is_probed_then_retired`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/chain_sync.rs#L58)) but nothing names
  the `noban`-vs-ban distinction.
- The `nMinimumChainWork` header-side fixture exists
  ([`low_work_headers_do_not_reach_block_tree`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L158)),
  but no test asserts that a peer whose
  best chain is below `minimum_chain_work` is refused for block download as
  `feature_minchainwork.py` does.
- No test covers the headers-announcement (`sendheaders`) route specifically;
  the inv → `getheaders` probe route is what
  [`announced_live_head_applies_and_continues`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/live_head_carried_e2e.rs#L226)
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
| Block requests start at the next unapplied height and already-pending blocks are not re-requested | `crates/p2p/src/sync/tests/behavior_2.rs`: [`tick_sends_getdata_from_next_applied_height_when_gap_exceeds_batch`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_2.rs#L8), [`second_tick_does_not_re_request_already_pending_blocks`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_2.rs#L67) | internal |
| Inflight volume per peer and per request budget is bounded | `behavior_2.rs`: [`tick_respects_pending_byte_budget`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_2.rs#L180), [`tick_limits_inflight_per_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_2.rs#L204), [`tick_fans_out_getdata_across_eligible_peers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_6.rs#L28) (`behavior_6.rs`) | internal |
| Expired pending requests are retried before new heights are requested | `crates/p2p/src/sync/tests/behavior_4.rs`: [`tick_retries_expired_pending_before_new_heights`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_4.rs#L4), [`tick_fills_mixed_retry_and_new_height_batch`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_4.rs#L37) | internal |
| A tick bootstraps genesis before requesting its child; an oversized received body releases its budget for retry | `behavior_4.rs`: [`tick_applies_contiguous_blocks_before_requesting_more`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_4.rs#L76), [`oversized_received_block_releases_pending_budget_for_retry`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_4.rs#L109) | internal |
| Pruned/limited peers are not asked for bodies during IBD or outside their retained window | `crates/p2p/src/sync/tests/limited_peers.rs`: [`predicate_excludes_limited_peer_during_initial_block_download`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/limited_peers.rs#L55), [`tick_asks_no_bodies_from_limited_peer_during_initial_block_download`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/limited_peers.rs#L140), [`tick_asks_no_bodies_from_limited_peer_beyond_retained_window`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/limited_peers.rs#L193) | internal |
| Compact blocks and `blocktxn` are served according to retained depth | `bin/bitcoin-rs/tests/compact_blocks_e2e.rs`: [`serves_compact_by_depth_on_the_wire`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/compact_blocks_e2e.rs#L507), [`serves_blocktxn_by_depth_on_the_wire`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/compact_blocks_e2e.rs#L579) | process |
| An empty `getblocktxn` index list is rejected by disconnecting the peer | `bin/bitcoin-rs/tests/compact_blocks_e2e.rs`: [`empty_getblocktxn_disconnects_on_the_wire`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/compact_blocks_e2e.rs#L638) | process |
| A compact block whose prefilled body does not match its header falls back to the full body from the same peer before applying | `compact_blocks_e2e.rs`: [`wrong_root_compact_block_falls_back_to_same_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/compact_blocks_e2e.rs#L686) (pinned to Core 31.1 `blockencodings.cpp`/`net_processing.cpp` behavior) | process |
| A node in IBD ignores transaction announcements until out of IBD, then requests them | `bin/bitcoin-rs/tests/tx_ibd_gate_e2e.rs`: [`ibd_node_ignores_then_requests_relay_transactions`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/tx_ibd_gate_e2e.rs#L548) | process |
| The codec accepts exactly 50k and rejects more than 50k `inv`, `getdata`, and `notfound` entries | `crates/p2p/tests/wire_codec.rs`: [`accepts_inv_message_with_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L113), [`rejects_inv_message_with_more_than_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L62), [`accepts_getdata_message_with_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L124), [`rejects_getdata_message_with_more_than_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L79), [`accepts_notfound_message_with_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L135), [`rejects_notfound_message_with_more_than_max_vectors`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L96) | synthetic boundary |
| Dispatcher doubles exercise a one-item transaction announcement and one-item `notfound` response; they do not establish the 50k limits | `crates/p2p/tests/core_compat.rs`: [`inv_getdata_relay_round_trip_serves_blocks_and_notfounds_misses`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L817) | synthetic boundary |
| A node dials a Core peer and follows extended history as it is mined | `e2e/tests/p2p_sync.rs`: [`node_follows_extended_core_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/p2p_sync.rs#L208) | process |
| Blocks are requested as witness bodies; the reorg/switch path matches Core's applied ancestry for retained lookups | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: [`announced_tip_fetches_witness_block_and_applies_segwit_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/head_sync_e2e.rs#L187); `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: [`retained_transaction_confirmations_match_core_after_reorg`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_harness.rs#L1339) | process |

Status: internal level is strong (request budgets, fanout, retry ordering);
process level holds for compact-block serving, the witness fetch path, and the
IBD transaction gate. Inventory count codecs are synthetic-boundary evidence.

Missing:

- No `p2p_block_sync.py`-shaped scenario: IBD completed with **only inbound
  peers and no outbound peer**. The scripted-peer process tests do drive the
  node over inbound connections, but none asserts the "no outbound exists"
  variant explicitly.
- No non-genesis buffered-prefix oracle proves that delivered contiguous bodies
  apply before a later request is emitted; the named `tick_applies...` case
  exercises only genesis bootstrap.
- Unrequested/low-work body floods at the process level are untested; the refusal
  exists internally (`crates/p2p/src/sync/tests/head_sync.rs`:
  [`unrequested_body_at_the_count_budget_is_refused`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/head_sync.rs#L531),
  `crates/p2p/src/sync/tests.rs`:
  [`unrequested_body_gate_rejects_below_floor_and_below_applied_work`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests.rs#L1715)).
- `p2p_mutated_blocks.py`'s specific claim — an attacker cannot clear honest
  peers' in-flight `blocktxn` requests with unsolicited mutated blocks — has
  no direct equivalent. The nearest internal tests are
  `crates/p2p/src/sync/tests/witness_staging_gate.rs`
  ([`malformed_body_dropped_then_correct_body_staged`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L112),
  [`malformed_pending_owner_is_disconnected_and_other_peer_gets_same_hash`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L143))
  and `behavior_6.rs`: [`mutated_forward_body_preserves_descendant_for_retry`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_6.rs#L102).
- High-bandwidth compact-block negotiation
  (`p2p_compactblocks_hb.py`) has no equivalent; BIP152 relay with a live Core
  peer is covered by `crates/p2p/tests/core_interop_live.rs`:
  [`live_bitcoin_core_p2p_interop_matches_contract`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_interop_live.rs#L190) (evidence-gated, see §9).

## 3. Stalled peer recovery and failover

Bitcoin Core:

- [`p2p_ibd_stalling.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_ibd_stalling.py)
  — stalling logic during IBD
- [`p2p_timeouts.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_timeouts.py)
  — version/verack/all-traffic handshake timeouts
- Historical sync regressions: Core's stall-detection and
  peer-rotation fixes (`net_processing.cpp` stalling work)

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| A stalled window front wedges into request backpressure; the staller is not churned away | `crates/p2p/src/sync/tests/behavior_3.rs`: [`stalled_front_stripe_wedges_into_request_backpressure_not_evict_churn`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_3.rs#L52) | internal |
| A cold-start stall hedges the front without reassigning the owning request | `behavior_3.rs`: [`cold_start_stall_hedges_front_without_reassigning_owner`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_3.rs#L104) | internal |
| When the eligible peer pool recovers, fanout replaces the preferred peer | `behavior_3.rs`: [`fanout_replaces_preferred_peer_when_eligible_pool_recovers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_3.rs#L198) | internal |
| Apply-side backpressure is never blamed on the front peer | `behavior_3.rs`: [`apply_side_backpressure_never_blamed_on_front_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_3.rs#L334), [`staged_frontier_stuck_past_bound_escalates_without_blame`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_3.rs#L441) | internal |
| A wedged window expires the stalled front, re-requests through the count clamp, and a byte-wedged window recovers by disconnecting the staller | `crates/p2p/src/sync/tests/transitions_4.rs`: [`wedged_window_expires_stalled_front_and_rerequests_through_count_clamp`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L192), [`byte_wedged_window_recovers_via_staller_disconnect_before_received_timeout`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L430) | internal |
| A same-address reconnect neither inherits its predecessor's stalled inflight nor loses its own work | `transitions_4.rs`: [`same_address_reconnect_does_not_inherit_stalled_inflight`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L304); `frontier_model.rs`: [`convicted_connection_cannot_pass_its_stall_to_a_replacement`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L478) (#1129) | internal |
| Stall eviction never disconnects the replacement connection | `transitions_4.rs`: [`stall_eviction_does_not_disconnect_replacement_connection`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L370) | internal |
| Slow-but-served download is never misread as a stall: a trickling front peer is observed but not disconnected, and uniform slow fanout completes without disconnects | `crates/p2p/src/sync/tests/transitions_5.rs`: [`slow_trickle_front_peer_observable_but_never_disconnected`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_5.rs#L4), [`uniform_slow_saturated_fanout_disconnects_no_peer_and_completes`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_5.rs#L96), [`single_peer_can_fill_default_pending_window`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_5.rs#L241) | internal |
| A mid-window peer disconnect requeues its blocks to remaining peers | `crates/p2p/src/sync/tests/transitions_6.rs`: [`peer_disconnect_mid_window_requeues_blocks_to_remaining_peers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_6.rs#L136) | internal |
| With one connection, an expired request is retried on that connection's receiver; the adjacent reconnecting-staller wrapper covers disconnection/cooldown registration, not a completed reconnect | `crates/p2p/src/sync/tests/transitions_6.rs`: [`sole_peer_staller_disconnected_and_usable_again_as_last_resort`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_6.rs#L215), [`reconnecting_staller_held_out_of_window_front_by_cooldown`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_6.rs#L209) | internal |
| A frontier whose owner dies recovers as unowned and schedules recovery on a capable peer; probes rotate past dead owners and evict them | `crates/p2p/src/sync/tests/frontier_model.rs`: [`unowned_frontier_schedules_recovery_when_a_capable_peer_exists`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L125), [`in_flight_frontier_on_a_dead_connection_recovers_as_unowned`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L175), [`probe_rotates_past_the_dead_pending_owner`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L289); `frontier_recovery.rs`: [`failed_probe_send_falls_back_to_best_peer_in_the_same_tick`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_recovery.rs#L264), [`dead_probe_peer_is_evicted_and_not_repicked_on_the_next_tick`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_recovery.rs#L367) | internal |
| After serving peers time out one after another, replacements carry the frontier and the apply frontier advances | `crates/p2p/src/sync/tests/issue_1153.rs`: [`replacements_carry_frontier_after_serving_peer_timeouts`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/issue_1153.rs#L53) (#1153) | internal |
| Expired pending requests demote the owning peer and retry on an alternate peer | `behavior_1.rs`: [`tick_demotes_peer_after_expired_pending_and_retries_on_alternate_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L469) | internal |
| A stale-tip node is allowed to dial extra outbound peers past its slot cap | `crates/p2p/src/sync/tests/stale_tip.rs`: [`the_stale_tip_allowance_dials_past_the_slot_cap`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/stale_tip.rs#L34) (pinned to Core `ThreadOpenConnections`) | internal |
| In a daemon process, one scripted peer serves every body but the tip and disconnects mid-download; a second peer's untracked body delivery still converges the chain to the tip with no request-cursor rewind | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: [`untracked_delivery_of_tree_known_block_converges`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/head_sync_e2e.rs#L429) | process |
| In a daemon process, a body arriving with an unknown parent is recovered via `getheaders` and applied in place once ancestry lands | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: [`missing_parent_delivery_recovers_via_getheaders`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/live_head_carried_e2e.rs#L346) | process |

Status: internal level covers the stall/failover state machine in depth;
process level covers one two-peer mid-download **disconnect** failover
(`head_sync_e2e.rs` T4) and one missing-ancestry recovery. The headline
`p2p_ibd_stalling.py` invariant — *a connected but stalled peer during IBD
cannot permanently stop sync progress* — is **not asserted end-to-end at
process level**.

Missing:

- No process-level test where a live peer serves headers then stalls block
  delivery mid-IBD while a second live peer carries the node to the tip. The
  T4 process case covers the disconnection half of this, but not a peer that
  stays connected while stalling.
- Core's `p2p_timeouts.py` version/verack/all-traffic handshake timeouts have
  no mapped daemon test. `e2e/tests/p2p_sync.rs`:
  [`ping_answers_immediately`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/p2p_sync.rs#L98) is RPC policy and does not cover handshake
  timeout behavior. `bin/bitcoin-rs/tests/overhaul_process_p2p.rs`:
  [`p2p_connect_to_an_absent_listener_has_a_fixed_deadline`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_p2p.rs#L49) covers the harness
  connector, while [`p2p_timeout_releases_the_connected_peer_and_process`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_p2p.rs#L63)
  times out the harness waiting for an unsent nonce, explicitly drops the
  peer, and then observes cleanup; neither proves node-driven stall eviction.

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
| An equal-work rival supplied as a header only does not displace the applied chain; once that branch has strictly higher work and its bodies become available, it wins and committed coins converge with a clean sync | `e2e/tests/reorg_state.rs`: [`equal_work_then_one_block_reorg_matches_clean_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L158) | process |
| A deeper competing branch mined on Core re-points the node tip; the old branch is gone from the active height map | `e2e/tests/reorg.rs`: [`core_reorg_repoints_node_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg.rs#L59) | process |
| A duplicate equal-work competing child keeps its original id and does not reorg (first-received tiebreak) | `crates/chain/tests/header_sync_roundtrip.rs`: [`duplicate_equal_work_competing_child_returns_original_id_and_does_not_reorg`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/tests/header_sync_roundtrip.rs#L276) | internal |
| A staged higher-work winner stays staged across the pending switch instead of drain/fail/re-request cycles | `bin/bitcoin-rs/tests/head_sync_e2e.rs`: [`pending_reorg_keeps_staged_winner_then_switches`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/head_sync_e2e.rs#L291) | process |
| Fork download starts at the common-ancestor child; buffered applies wait for the pending reorg | `crates/p2p/src/sync/tests/behavior_1.rs`: [`fork_getdata_starts_at_common_ancestor_child`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L95), [`pending_reorg_frontier_is_first_connect_node`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L209), [`apply_buffered_blocks_waits_for_pending_reorg`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L225) | internal |
| Retargeting drops losing-branch hashes from pending requests and staged bodies; an outweighed branch target accepts a shorter higher-work branch | `crates/p2p/src/sync/tests/transitions_2.rs`: [`retargeting_pending_requests_drops_losing_branch_hashes`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_2.rs#L119), [`retarget_purges_staged_off_branch_bodies`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_2.rs#L155), [`outweighed_branch_target_accepts_shorter_higher_work_branch`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_2.rs#L207) | internal |
| A deeper reorg plans to the common fork | `crates/chain/tests/reorg_deep.rs`: [`plans_deep_reorg_to_common_fork`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/tests/reorg_deep.rs#L10) | internal |
| A branch switch whose plan races a competing connect replans on the moved tip and still lands | `crates/node/tests/unit/sync/tests/transitions_2.rs`: [`branch_switch_replans_after_a_competing_connect_before_transition`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_2.rs#L107) | internal |
| Dispatcher responses follow a replaced, injected `FakeChain` query view; the test does not execute production activation or publication | `crates/p2p/tests/core_compat.rs`: [`reorg_switches_which_chain_a_peer_sees`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L1190) | synthetic boundary |
| `getchaintips` reports the active tip and, after a rewind, the dead branch remains visible with a valid status | `e2e/tests/chain_queries.rs`: [`chain_tips_and_tx_stats`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/chain_queries.rs#L103); `e2e/tests/reorg.rs`: [`invalidateblock_rewinds_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg.rs#L18) | process |
| `invalidateblock` rewinds the tip and mining continues on a provably different branch | `e2e/tests/reorg.rs`: [`invalidateblock_rewinds_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg.rs#L18) | process |

Status: process and internal levels hold, including the scripted-peer
staged-winner case. Natural (non-`invalidateblock`) higher-work switching is
covered at process level via Core-mined competitors. The injected `FakeChain`
dispatcher case is synthetic-boundary evidence only.

Missing:

- `feature_chain_tiebreaks.py` also covers timestamp/first-seen tiebreaks
  beyond the duplicate-child case; only the first-received equal-work
  invariant is mapped.
- [`rpc_preciousblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_preciousblock.py)
  has no equivalent surface: `preciousblock` is `Unimplemented` in the
  [RPC registry (source only)](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/src/registry.rs#L161)
  ("No manual block-preference surface"), and per the constraint it is not a
  compatibility requirement. [`rpc_invalidateblock.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_invalidateblock.py)
  is covered above; `reconsiderblock` is likewise `Unimplemented`.

## 5. Reorg execution and recovery

Owned by [#1280](https://github.com/gosuda/bitcoin-rs/issues/1280); the full
mapping lives in [REORG-COVERAGE.md](REORG-COVERAGE.md). Snapshot of what that
slice proves, for domain completeness:

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| Multi-block disconnect/forward-connect mempool reconciliation equals a clean sync | `e2e/tests/reorg_state.rs`: [`deep_reorg_mempool_matches_clean_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L317) | process |
| A consensus-invalid higher-work branch cannot change committed coins and cannot poison later valid sync | `e2e/tests/reorg_state.rs`: [`invalid_higher_work_body_cannot_change_active_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L417) | process |
| ZMQ `sequence` reports exact disconnect-then-connect order | `crates/rpc/tests/reorg_notifications.rs`: [`sequence_reports_exact_disconnect_connect_order`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/reorg_notifications.rs#L229) | process |
| SIGKILL/restart around a branch switch preserves the settled chainstate | `e2e/tests/reorg_state.rs`: [`invalid_higher_work_body_cannot_change_active_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L417); `crates/rpc/tests/reorg_notifications.rs`: [`sequence_reports_exact_disconnect_connect_order`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/reorg_notifications.rs#L229), per [REORG-COVERAGE.md](REORG-COVERAGE.md) `RCV-08` row | process |
| A permanent reorg failure invalidates descendants; a mutated connect body through a switch preserves the subtree | `crates/node/tests/unit/sync/tests/transitions_3.rs`: [`permanent_reorg_failure_invalidates_descendants`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_3.rs#L97); `crates/node/tests/unit/sync/tests/transitions_7.rs`: [`mutated_connect_body_through_switch_to_branch_preserves_subtree`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_7.rs#L5) | internal |
| A deep reorg streams bounded prefixes to an independently replayed reference | `crates/node/tests/unit/state/tests/recovery.rs`: [`deep_reorg_streams_bounded_prefixes_to_the_exact_reference`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L695) | internal |
| A reorg rooted in deleted history refuses before mutation, while a retained shallow reorg executes and reaches the expected height | `crates/node/tests/unit/state/tests/recovery.rs`: [`prune_then_reorg_refuses_deleted_history_but_keeps_retained_reorgs`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L632) | internal |
| Readiness returns to ready on the forked tip after a reorg | `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: [`reorg_returns_readiness_to_ready_on_the_forked_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_harness.rs#L1300) | process |

Core references in this domain are enumerated in
[REORG-COVERAGE.md](REORG-COVERAGE.md) (`feature_block.py`,
`mempool_reorg.py`, `interface_zmq.py`, Core `ReplayBlocks` recovery). Gaps
recorded there — e.g. `savemempool`/mempool reload is `Unimplemented` in the
[RPC registry (source only)](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/src/registry.rs#L163)
— stay gaps here too.

## 6. Header-tip vs applied-tip convergence

Bitcoin Core:

- [`p2p_initial_headers_sync.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/p2p_initial_headers_sync.py),
  [`rpc_blockchain.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/rpc_blockchain.py)
  — `getblockchaininfo`'s `headers`/`blocks` split and IBD progress
- [`feature_maxtipage.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_maxtipage.py)
  — IBD exit semantics by tip age

| Observable invariant | bitcoin-rs test | Level |
| --- | --- | --- |
| While headers run ahead of bodies, the node keeps fetching and applying until the two tips converge | `bin/bitcoin-rs/tests/live_head_carried_e2e.rs`: [`announced_live_head_applies_and_continues`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/live_head_carried_e2e.rs#L226) (observed heights are monotonic once an earlier tip applied) | process |
| An applied-tip rewind with unchanged headers refetches the missing prefix | `crates/p2p/src/sync/tests/frontier_recovery.rs`: [`applied_rewind_with_unchanged_headers_refetches_the_missing_prefix`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_recovery.rs#L19) | internal |
| Header sync requests stop when the header tip matches the peer's height | `crates/p2p/src/sync/tests/transitions_3.rs`: [`tick_skips_getheaders_when_header_tip_matches_peer_height`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_3.rs#L4) | internal |
| The frontier reports `at_tip` only when applied reaches header tip; unresolvable diverged tips are reported as such | `crates/p2p/src/sync/tests/frontier_model.rs`: [`at_tip_reports_at_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L214), [`diverged_tips_with_unresolvable_frontier_report_frontier_unresolvable`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/frontier_model.rs#L233) | internal |
| With the transition barrier held, `getblockchaininfo` still answers and reports the last published `bestblockhash`; the test does not compare `headers` with `blocks` | `crates/rpc/tests/core_parity.rs`: [`getblockchaininfo_returns_during_chain_transition`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/core_parity.rs#L354) | internal |
| The node exits IBD only with enough work and a recent tip, against Core's default 24h window | `crates/chain/src/ibd.rs` inline tests: [`a_recent_tip_with_enough_work_exits_initial_block_download`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/src/ibd.rs#L246), [`a_stale_tip_with_enough_work_is_still_initial_block_download`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/src/ibd.rs#L238), [`a_recent_tip_without_the_networks_minimum_work_is_still_initial_block_download`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/src/ibd.rs#L211), [`the_tip_age_boundary_is_twenty_four_hours`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/src/ibd.rs#L253) | internal |

Status: convergence is asserted at process level by the live-head tests and at
internal level by the frontier model. RPC availability and the published best
hash are asserted with the transition barrier held; paired `headers`/`blocks`
coherence is not.

Missing:

- No process-level test that pins `getblockchaininfo.headers` ahead of
  `blocks` during a partially synced catch-up and then equal at convergence.
- No internal transition test compares `getblockchaininfo.headers` and
  `getblockchaininfo.blocks` while publication is held; handler source is not
  test evidence for that paired-field invariant.
- `feature_maxtipage.py`'s process-level claim (a node whose tip is older than
  the window stays in IBD) has no process-level equivalent; `-maxtipage` is not
  an option yet ([IBD policy source only](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chain/src/ibd.rs#L16):
  "this node has no such option yet, so the default stands").

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
| After fully syncing five blocks and stopping cleanly, a node reopens the same datadir and catches up to three blocks mined after restart | `e2e/tests/reorg.rs`: [`restart_mid_chain_resumes_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg.rs#L99) | process |
| A mined tip survives a clean restart over the same datadir | `e2e/tests/lifecycle.rs`: [`restart_preserves_chain_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/lifecycle.rs#L80) | process |
| Clean restart restores readiness at the pinned tip with indexes intact; a destroyed index rebuilds from canonical data | `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: [`clean_restart_restores_ready_readiness_at_the_pinned_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_harness.rs#L1258), [`destroyed_index_rebuilds_from_canonical_data_and_restores_history`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_harness.rs#L1173) | process |
| Two `FakeChain` query doubles built from identical in-memory records return identical dispatcher answers; no node restart or persistence path is exercised | `crates/p2p/tests/core_compat.rs`: [`restart_rebuild_serves_identical_answers_to_peers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L1265) | synthetic boundary |
| SIGKILL leaves a valid journal frontier; torn disconnects replay to the parent tip, cold replay to the head, and a checkpoint above head rewinds to head | `crates/node/tests/crash_recovery.rs`: [`sigkill_restarts_at_valid_journal_frontier`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L28), [`torn_disconnect_replays_parent_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L39), [`torn_disconnect_cold_replays_head`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L61), [`torn_disconnect_checkpoint_above_head_rewinds_to_head`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L87) | internal |
| A checkpoint far below the durable head replays the whole authenticated gap and lands on the head | `crash_recovery.rs`: [`checkpoint_fallback_replays_wide_gap_to_durable_head`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L157); `crates/chainstate/tests/unit/durable_replay_tests.rs`: [`wide_authenticated_gap_replays_to_durable_head`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chainstate/tests/unit/durable_replay_tests.rs#L441), [`committed_gap_replays_to_head_without_recommitting_it`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chainstate/tests/unit/durable_replay_tests.rs#L116), [`cold_chainstate_replays_head_chain_from_genesis`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/chainstate/tests/unit/durable_replay_tests.rs#L259) | internal |
| Restart replays the durable journal suffix above the checkpoint; a disconnect rewrites the durable head before restart | `crates/node/tests/chainstate_journal.rs`: [`restart_replays_durable_journal_suffix_above_checkpoint`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/chainstate_journal.rs#L23), [`disconnect_rewrites_durable_head_before_restart`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/chainstate_journal.rs#L90) | internal |
| After apply/checkpoint/drop, durable head/body/undo rows are readable and restart continues the commit-id sequence; corrupt head rows fail startup closed | `crates/node/tests/overhaul_durable_head.rs`: [`durable_head_precedes_publication_and_survives_restart`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/overhaul_durable_head.rs#L281), [`corrupt_head_rows_fail_startup_fail_closed`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/overhaul_durable_head.rs#L352) | internal |
| A restarted chainstate reconstructs a consistent tip: the active-chain snapshot anchors at the restored tip, missing checkpoints replay the durable head chain, and uncommitted tails are discarded | `crates/node/tests/unit/state/tests/events.rs`: [`active_chain_snapshot_anchors_at_restored_tip_after_restart`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/events.rs#L57); `crates/node/tests/unit/state/tests/recovery.rs`: [`missing_checkpoint_replays_durable_head_chain_at_startup`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L454), [`checkpoint_resume_discards_only_incomplete_uncommitted_tail`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L517), [`full_revalidation_marker_resumes_on_durable_head`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L545) | internal |
| Prune frontier survives SIGKILL with deleted rows still absent and retained rows readable; storage restart refuses deleted heights | `crates/node/tests/crash_recovery.rs`: [`pruned_frontier_survives_sigkill_and_preserves_boundary`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/crash_recovery.rs#L202); `crates/storage/tests/prune_then_reorg.rs`: [`executed_frontier_survives_restart_and_refuses_deleted_heights`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/storage/tests/prune_then_reorg.rs#L488) | internal |

Status: restart-persistence is the strongest domain — process-level clean
restart/catch-up and rebuild cases plus a deep deterministic crash matrix
internally. No process test interrupts a partial body download.

Missing:

- `feature_dbcrash.py`'s randomized repeated-crash campaign (crash ratios,
  varying dbcache, long sync loops) has no equivalent; crash coverage is the
  deterministic boundary matrix above.
- No test interrupts a partially downloaded chain and proves resume without
  redownloading completed work. [`restart_mid_chain_resumes_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg.rs#L99) stops only
  after the initial five blocks have applied, then mines new work after the
  restart.
- No oracle in [`durable_head_precedes_publication_and_survives_restart`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/overhaul_durable_head.rs#L281)
  observes the head/body/undo writes before tip publication; its post-drop
  reads prove persistence and commit-id continuation, not durability ordering.
- No production restarted node is queried over P2P to compare pre/post-restart
  responses. [`restart_rebuild_serves_identical_answers_to_peers`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L1265) is a
  `FakeChain` reconstruction check only.
- [`mempool_persist.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/mempool_persist.py)
  has no equivalent: `savemempool`/`importmempool` are `Unimplemented`
  ([RPC registry source only](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/src/registry.rs#L159),
  "Mempool dump/reload persistence not implemented"). Restart assertions cover durable chainstate, not pool
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
| Invalid `nbits` headers disconnect the source and rotate `getheaders`; unattributed invalid headers disconnect nobody | `crates/p2p/src/sync/tests/transitions_4.rs`: [`invalid_nbits_headers_disconnect_source_and_rotate_getheaders`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L4), [`unattributed_invalid_headers_do_not_disconnect_any_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/transitions_4.rs#L93) | internal |
| A substituted header in the redownload pass disconnects the connection that served it and admits nothing | `crates/p2p/src/sync/tests/headers_presync.rs`: [`a_substituted_redownload_header_disconnects_the_connection`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L317) | internal |
| Body-carried low-work bad PoW/nbits headers are discarded and fault the delivering peer | `headers_presync.rs`: [`body_carried_low_work_bad_pow_is_discarded_and_faults_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L901), [`body_carried_low_work_bad_nbits_is_discarded_and_faults_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/headers_presync.rs#L918) | internal |
| Rejected matching peer headers release the `getheaders` gate and retry immediately; orphan headers keep the source connected | `crates/p2p/src/sync/tests/behavior_1.rs`: [`rejected_matching_peer_headers_release_gate_and_retry_immediately`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L328), [`orphan_headers_keep_source_peer_connected`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/behavior_1.rs#L381) | internal |
| A malformed pending body's owner is disconnected and another peer can serve the same hash; a later correct body still stages | `crates/p2p/src/sync/tests/witness_staging_gate.rs`: [`malformed_pending_owner_is_disconnected_and_other_peer_gets_same_hash`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L143), [`malformed_body_dropped_then_correct_body_staged`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L112), [`altered_non_witness_body_dropped_then_correct_body_staged`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L183) | internal |
| An inadmissible staged body is evicted; a stale source cannot settle its gate; rejected bodies restore peer credit | `crates/p2p/src/sync/tests/head_sync.rs`: [`staged_body_with_permanently_inadmissible_header_is_discarded`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/head_sync.rs#L314), [`staged_body_whose_resolved_header_is_inadmissible_is_evicted`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/head_sync.rs#L357), [`stale_owned_fetch_source_does_not_settle_the_gate`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/head_sync.rs#L587); `witness_staging_gate.rs`: [`idle_frontier_relearns_stale_peer_credit_after_rejected_body`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/src/sync/tests/witness_staging_gate.rs#L258) | internal |
| A compact block whose prefilled body does not match its header never applies; the node refetches the real body | `bin/bitcoin-rs/tests/compact_blocks_e2e.rs`: [`wrong_root_compact_block_falls_back_to_same_peer`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/compact_blocks_e2e.rs#L686) | process |
| A consensus-invalid higher-work branch cannot change committed coins and the valid branch keeps advancing | `e2e/tests/reorg_state.rs`: [`invalid_higher_work_body_cannot_change_active_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L417) | process |
| Reorg connect failures classify a mutated body as retryable without invalidating its headers, while a permanent invalid body invalidates descendants | `crates/node/tests/unit/sync/tests/transitions_3.rs`: [`branch_switch_retires_only_the_connected_prefix_after_connect_failure`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_3.rs#L4), [`permanent_reorg_failure_invalidates_descendants`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_3.rs#L97) | internal |
| The e2e client's `decode_frame` rejects malformed byte arrays without starting a daemon | `bin/bitcoin-rs/tests/overhaul_process_p2p.rs`: [`malformed_p2p_frames_are_protocol_failures_not_behavior_evidence`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_p2p.rs#L372) | synthetic boundary |
| Dispatcher/codec doubles reject pre-handshake messages and foreign-network frames | `crates/p2p/tests/core_compat.rs`: [`messages_before_handshake_disconnect_like_core`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L1074), [`foreign_network_frames_are_rejected_before_payload_decode`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L674) | synthetic boundary |
| Ban list round-trips over RPC | `e2e/tests/p2p_sync.rs`: [`ban_list_round_trip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/p2p_sync.rs#L142); `crates/p2p/tests/listener_ban.rs`: [`outbound_ban_short_circuits_before_connect_with_typed_error`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/listener_ban.rs#L19), [`inbound_ban_drops_connection_pre_handshake`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/listener_ban.rs#L62) | process / internal |
| `setban` stores finite relative/absolute expiry timestamps and rejects overflow or already-past timestamps without mutating the list | `crates/rpc/tests/setban_expiry.rs`: [`relative_defaults_and_explicit_durations_remain_finite`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/setban_expiry.rs#L84), [`absolute_expiry_uses_epoch_not_creation_time`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/setban_expiry.rs#L109), [`overflow_does_not_create_a_permanent_ban`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/setban_expiry.rs#L51), [`past_absolute_expiry_does_not_create_a_ban`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/setban_expiry.rs#L157) | internal |

Status: attribution rules are covered in depth internally; the process level
covers the invalid-branch and malformed compact-block invariants. Raw-frame
decoder and dispatcher checks are synthetic-boundary evidence, not process
protocol-failure coverage.

Missing:

- `p2p_invalid_block.py`'s re-request classification (duplicated-tx block is
  re-requested vs bad-coinbase block is not; future-timestamp blocks are
  accepted once valid) has no equivalent. The internal `BodyMutated` versus
  `Permanent` reorg cases above prove classification at the branch-switch
  boundary, but not Core's peer re-request scenarios.
- `p2p_invalid_locator.py` has no dedicated scenario; oversized locator
  rejection is covered at the synthetic codec/dispatcher boundary only by
  [`rejects_getheaders_message_with_more_than_max_locator_hashes`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/wire_codec.rs#L203)
  and
  [`oversized_getheaders_locator_disconnects_before_state_mutation`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_compat.rs#L788).
- No test advances time and proves that an existing ban disappears or stops
  blocking a peer. `setban_expiry.rs` covers timestamp arithmetic and invalid
  expiry rejection only. The `p2p_disconnect_ban.py` disconnect-vs-ban menu
  (e.g. `noban` disconnects) is also unmapped, same as §1.

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
| With the real transition barrier held over a fixed publication, status calls still answer: `getblockchaininfo` checks `bestblockhash`; `getchaintxstats` checks `txcount` and zero-window omissions | `crates/rpc/tests/core_parity.rs`: [`getblockchaininfo_returns_during_chain_transition`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/core_parity.rs#L354), [`getchaintxstats_returns_during_chain_transition`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/core_parity.rs#L381) (driven through the [`replay_during_chain_transition`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/core_parity.rs#L252) helper) | internal |
| A separate steady-state corpus gate decodes the configured `getblockchaininfo` fixtures into Core's typed wire shape | `crates/rpc/tests/core_parity.rs`: [`differential_loopback_authenticated_chain`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/tests/core_parity.rs#L114) | internal |
| After invalidate/mining finishes, readiness returns to ready and the process reports the fork tip; the reads do not overlap the reorg mutation | `bin/bitcoin-rs/tests/overhaul_process_harness.rs`: [`reorg_returns_readiness_to_ready_on_the_forked_tip`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/bin/bitcoin-rs/tests/overhaul_process_harness.rs#L1300) | process |
| Disconnect debt is settled by branch switches and `invalidateblock`; after a completed switch no active pruning lease remains | `crates/node/tests/unit/state/tests/recovery.rs`: [`invalidate_block_settles_disconnect_debt`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L19), [`switch_to_branch_settles_disconnect_debt`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L139), [`switch_to_branch_releases_retention_authority_once`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L363) | internal |
| Restart without periodic publication reconstructs the exact pre-restart tip and `commit_id` | `crates/node/tests/unit/state/tests/recovery.rs`: [`restart_without_periodic_publication_restores_tip_and_commit_id`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L782) | internal |
| Multi-block disconnect/reconnect and natural higher-work reorg cases land on the expected settled state | `e2e/tests/reorg_state.rs`: [`equal_work_then_one_block_reorg_matches_clean_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L158), [`deep_reorg_mempool_matches_clean_sync`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/e2e/tests/reorg_state.rs#L317); `crates/node/tests/unit/sync/tests/transitions_3.rs`: [`permanent_reorg_failure_invalidates_descendants`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/sync/tests/transitions_3.rs#L97) | process / internal |

Status: RPC availability against a fixed publication while the transition
barrier is held is pinned; settlement and post-commit recovery are covered
internally. Neither paired-field coherence during mutation nor reads
overlapping a real reorg are established.

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
- No test overlaps a status/readiness query with a real reorg mutation. The
  process readiness test queries only after invalidate/mining completes, and
  the RPC barrier cases hold a fixed seeded publication.
- [`switch_to_branch_releases_retention_authority_once`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/node/tests/unit/state/tests/recovery.rs#L363) observes zero active
  leases before and after the switch; it proves cleanup, not that one lease was
  acquired and released exactly once.

## 10. Out-of-scope Core behavior

Recorded so absence of coverage is not mistaken for a gap. These are Core
surfaces bitcoin-rs intentionally omits — optional behavior not required for
consensus or normal full-node participation.

**RPC registry entries** — `Unimplemented` by
[source-only declaration](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/rpc/src/registry.rs#L152):

- `preciousblock`, `reconsiderblock` (manual block preference) — see §4
- `savemempool`, `importmempool` (mempool dump/reload) — see §7
- `loadtxoutset` / `dumptxoutset` (`assumeutxo` snapshots),
  [`feature_assumeutxo.py`](https://github.com/bitcoin/bitcoin/blob/v31.1/test/functional/feature_assumeutxo.py)
- `getblockfrompeer`, `waitforblock`/`waitforblockheight`/`waitfornewblock`,
  `scanblocks`, `getmempoolcluster`, `getaddrmaninfo`

**Non-RPC omissions** (no such surface exists in bitcoin-rs; recorded as
gaps/omissions, not as registry declarations):

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
([`live_bitcoin_core_p2p_interop_matches_contract`](https://github.com/gosuda/bitcoin-rs/blob/73f9ee62115de60e6b89f1a05a97a71cd2032674/crates/p2p/tests/core_interop_live.rs#L190)) is `#[ignore]`d in ordinary
runs and judges evidence produced by `scripts/run-p2p-core-interop.sh` against
a live pinned `bitcoind` (handshake identity, chain identity, BIP152 relay).
Raw launch, RPC, and P2P evidence is retained under
`target/process-harness/e2e/` by the CI artifact upload.

When adding a sync test, give it a row in its domain with its observable
invariant and its level; do not record an internal state-machine test as a
process-level equivalent, and record missing coverage as a gap in the domain's
`Missing` list instead of inferring it.
