# Extensions contract

The contract between the node core and node-side index consumers compiled as
extensions. Owners: `ExtensionDescriptor`, `HealthStatus`, `Extension`,
`CapabilitySnapshot` in `crates/ext-api`; the descriptor set, validation, and
capability report in `crates/node/src/extensions.rs`; the reference adapter in
`crates/ext-blockfilterindex`; the worker and query engine in
`crates/node/src/filterindex_worker.rs`.

## Descriptors outlive instances

- Every compiled extension contributes its `ExtensionDescriptor`
  unconditionally, in registry order: `txindex`, then `blockfilterindex`.
- An instance exists only while the extension's runtime toggle is enabled.
  Validation and `getcapabilities` can therefore reason about a disabled
  extension's requirements without opening its namespace.
- Descriptors carry the capability `id`, the namespace directory name under
  the data dir, the schema version, and required / incompatible capability
  ids.

## Validation runs before anything opens

- `validate_extensions(&config)` runs at the top of `run`, before
  `NodeState::open`: no storage is opened and no listener binds for an
  invalid combination. `Config::validate` repeats the checks as a backstop.
- A missing dependency fails with the literal phrasing
  `<capability> requires <dependency>`; a conflict fails with
  `<capability> requires <dependency> disabled`.
  The reference combinations: `blockfilterindex requires txindex` (the
  filter index resolves deep spent prevouts through the transaction index)
  and `blockfilterindex requires prune disabled` (the consumer needs every
  body).

## Extensions never abort core

- Extension lifecycle callbacks are best-effort wake-ups; they never block
  or fail the caller.
- The consumer runs on its own thread under `catch_unwind`. A panic or error
  publishes on the extension's runtime; the extension reports
  `HealthStatus::Failed` and stops. Block application, sync, and other
  indexes are unaffected: the apply path never touches an extension store.
- Extension work is positional reconciliation over the chain-event seam
  (`chain-events.md`). A dropped hint loses latency only.

## Namespace ownership

- One extension owns `data_dir/<namespace>` and nothing else. The reference
  namespace is `data_dir/blockfilterindex`.
- Schema versioning is per namespace. A stored version foreign to this build
  refuses — and refuses only — that extension namespace (the node logs and
  keeps starting, the capability reports as not running), per
  `docs/policies/db-migration.md`: never an in-place migration.
- Rows, the active pointer, the consumer cursor, and the lifecycle state
  commit in one atomic store batch.

## Capability report

- The registry produces a `CapabilitySnapshot`: one `CapabilityStatus` per
  compiled capability with `id`, `compiled`, `enabled`, and live `state`
  (`Ready` / `CatchingUp` / `Failed` / `Disabled`).
- RPC consumes the report through the `CapabilityProvider` trait only; the
  RPC crate never sees node internals or storage backends. The report backs
  the `getcapabilities` extension method and the `getindexinfo` index
  entries.

## Proven by

- `crates/node/src/extensions.rs` tests:
  `validation_names_the_missing_dependency_literally`,
  `validation_names_the_prune_conflict_literally`,
  `compiled_descriptors_carry_the_registry_namespaces`,
  `enabled_capabilities_follow_runtime_toggles`.
- `crates/node/tests/extensions.rs`:
  `extension_validation_rejects_incompatible_capabilities`,
  `filter_extension_tip_equivalence_disabled_vs_enabled`,
  `filter_extension_restarts_reconcile_from_persisted_pointer`,
  `filter_extension_apply_outpaces_a_lagging_consumer`.
- `crates/node/src/filterindex_worker.rs` tests:
  `store_write_failure_is_reported_not_swallowed`,
  `missing_body_fails_the_pass_without_touching_the_pointer`,
  `rewind_keeps_hash_addressed_rows`.
- `bin/bitcoin-rs/tests/gates/g16_extension_model.rs`: the invalid
  combination exits non-zero before any listener binds, with the literal
  error.
