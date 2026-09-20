# Dependency range contract

Declared Cargo ranges are the versions this workspace claims to support.
The committed `Cargo.lock` is one point inside that range, not the
contract.

## Clauses

### `DEP-01`: Minimum and maximum resolvable versions compile

- **Owner**: `scripts/check-dep-range.sh`.
- **Scope**: every direct workspace dependency declared in the root
  `Cargo.toml` `[workspace.dependencies]` table.
- `minimal` resolves each direct dependency at its oldest allowed version
  (`cargo +nightly update -Zdirect-minimal-versions`) and checks the
  workspace graph with all features enabled (`--all-features`).
- `maximum` resolves every crate to the newest version still inside its
  declared range (`cargo update`) and checks the default workspace graph.
- Both lanes run `cargo deny check bans` against the mutated lockfile. The `minimal`
  lane enables every feature, so it compiles the optional native storage
  engines at the oldest resolve. The named combinations themselves are
  owned by `FEAT-01`.
- Both lanes mutate `Cargo.lock`. They run on `main` only, never on a
  pull-request checkout.

### `DEP-02`: One copy of each consensus-stack crate

- **Owner**: `deny.toml` `[bans]`.
- **Scope**: the fully-featured resolve (`cargo metadata --all-features`)
  for `bitcoin`, `bitcoin_hashes`, `secp256k1`, and `secp256k1-sys`.
- Each of those crates must appear as exactly one package id. `deny.toml`
  `multiple-versions = "deny"` is the graph-wide companion; those four
  names must not gain a `[bans].skip` entry, including `crate@version`.
- Range-endpoint graphs are in scope: `cargo deny check bans` runs after
  each DEP-01 resolve. Missing cargo-deny is a failed prerequisite, not a skip.

## Proven by

- `scripts/check-dep-range.sh minimal` and
  `scripts/check-dep-range.sh maximum` (main workflow `dependency-range`
  job).
- `cargo deny check bans` (`deny.toml` `[bans] multiple-versions = "deny"`).
