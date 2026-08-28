# External API contract (pointer)

The external-API contract is declared in code, not prose. This page adds
nothing normative; it places the owners under the
[contracts precedence rule](README.md).

- **Owner**: `MANIFEST` in `crates/rpc/src/manifest.rs` — the single source
  of truth for the dispatcher. A JSON-RPC method answers only when a
  non-`Unimplemented` row carries its name. Rows cover JSON-RPC, REST
  prefixes, and ZMQ topics, each with a status (`Implemented`,
  `Deviation`, `Extension`, `Unimplemented`) declared against Bitcoin Core
  31.x.
- **Generated reference**: [docs/rpc-reference.md](../rpc-reference.md) is a
  generated file. Do not edit it by hand. Regenerate with:
  `REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference`
- **Proven by**: `crates/rpc/tests/manifest_coverage.rs` —
  `rpc_rows_and_the_live_registry_agree_both_ways`,
  `rest_rows_and_router_registrations_agree_both_ways`,
  `zmq_rows_are_valid_core_topics`,
  `every_unimplemented_rpc_row_answers_method_not_found`, and
  `generated_reference_matches_checked_in` (fails when the checked-in
  reference drifts from the manifest).
- **Operator docs**: [docs/rest-interface.md](../rest-interface.md) documents
  enabling the REST gateway and the enforcer integration; the method list
  there defers to the manifest.
