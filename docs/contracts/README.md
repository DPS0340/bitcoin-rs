# Contracts

A contract doc states behavior the code must keep, and names where the code
proves it. Every normative claim cites the file that implements it and the
test that pins it, both present in the tree. A contract page is short: the
invariants, the owners, the proof. Explanation lives in `docs/solutions/`,
history in `docs/plans/`.

## Precedence

When documents disagree, use this order:

1. A contract page under `docs/contracts/` wins. Each page is code-cited:
   file paths and test names, no prose-only claims about behavior.
2. Source comments (rustdoc and inline comments) come next. They explain
   local intent. They do not override the contract.
3. Everything else is context: `docs/policies/` for rules not yet given a
   contract page, `docs/solutions/`, `docs/plans/`, `docs/benchmarks/`,
   `CONCEPTS.md`, `README.md`.

On conflict between a contract page and the code, the drift is a bug. Fix the
code or amend the contract in the same commit. Never reword the contract to
match a regression. Where this tree and a `docs/policies/` authority overlap,
the pointer pages below fold that policy into this precedence chain; the
policy text stays the owner of its content.

## Index

| Contract page | Scope | Consumed by | Proven by |
| --- | --- | --- | --- |
| [chain-events.md](chain-events.md) | `ChainSnapshot`, `ChainEventHint`, `ChainEventPublisher`, `ConsumerCursor`: the seam between the apply path and reconciliation consumers | `crates/node/src/txindex_worker.rs` (first consumer); any index mirroring the applied chain | `crates/node/src/state.rs` tests `record_publishes_snapshot_and_hints_in_commit_order`, `record_drops_hints_when_channel_full`, `active_chain_snapshot_anchors_at_restored_tip_after_restart`; `crates/node/src/txindex_worker_reconcile_tests.rs` tests `forward_commit_overlapping_tip_extension_repairs_on_next_pass`, `snapshot_identity_changes_reconcile_from_the_cursor_position` |
| [mempool-mutations.md](mempool-mutations.md) | Gateway ordering invariant, `MutationResult` semantics, ZMQ `A`/`R` payload bytes | apply path (`crates/node/src/apply.rs`), `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`), ZMQ `sequence` subscribers (enforcer `--enable-mempool`) | `crates/mempool/src/gateway.rs` test `accepted_and_removed_events_arrive_in_commit_order`; `crates/node/src/mempool_observer.rs` test `block_inclusion_suppresses_r_frames`; `crates/node/src/zmq_publisher.rs` test `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence` |
| [p2p-wire.md](p2p-wire.md) | Pointer: peer-wire contract pinned to Core 31.1 | `crates/p2p` peers; `crates/node/src/p2p_chain.rs` chain-serving adapter | `crates/p2p/tests/core_compat.rs` (`cargo test -p bitcoin-rs-p2p --test core_compat`); live lane `scripts/run-p2p-core-interop.sh` |
| [external-api.md](external-api.md) | Pointer: JSON-RPC/REST/ZMQ manifest and the generated reference | RPC/REST/ZMQ clients; `tools/bip300301-enforcer` | `crates/rpc/tests/manifest_coverage.rs` tests `rpc_rows_and_the_live_registry_agree_both_ways`, `generated_reference_matches_checked_in` |
| [mempool-policy.md](mempool-policy.md) | Pointer: relay policy contract pinned to Core 31.1 | `sendrawtransaction`/`testmempoolaccept` (`crates/rpc/src/handlers/tx.rs`), P2P relay admission | `crates/mempool/tests/policy_contract.rs` and `crates/rpc/tests/policy_contract.rs` (`cargo test -p bitcoin-rs-mempool --test policy_contract` / `-p bitcoin-rs-rpc --test policy_contract`) |
| [qa-corpus.md](qa-corpus.md) | Pointer: fuzz seed provenance and refresh rules | `fuzz/fuzz_targets/{p2p_message,block_decode,tx_decode,script_eval}.rs`; CI fuzz lanes | `fuzz/CORPUS_PROVENANCE.md` mapping table; targets run under `cargo fuzz run <target> -- -runs=10000` |

## Vocabulary

Terms used above are defined in [../../CONCEPTS.md](../../CONCEPTS.md). A
contract page may reference a concept by name without redefining it.
