# Mempool policy contract (pointer)

The relay-policy contract lives in
[docs/policies/mempool-policy.md](../policies/mempool-policy.md). That
document is the owner: it pins Bitcoin Core 31.1, declares the policy
surface per check with Core's behavior alongside, and keeps a deviation
ledger. This page adds nothing normative; it places the policy under the
[contracts precedence rule](README.md).

- **Owner**: `docs/policies/mempool-policy.md`. It covers relay policy only;
  consensus validation of scripts and sighashes is out of scope there and
  here.
- **Scope**: admission outlets `crates/mempool/src/standardness.rs`,
  `limits.rs`, `rbf.rs`, `eviction.rs`, `policy.rs` and the RPC surface
  `sendrawtransaction`/`testmempoolaccept` in
  `crates/rpc/src/handlers/tx.rs`.
- **Proven by**: `crates/mempool/tests/policy_contract.rs` and
  `crates/rpc/tests/policy_contract.rs` —
  `cargo test -p bitcoin-rs-mempool --test policy_contract` for direct-pool
  semantics, `-p bitcoin-rs-rpc --test policy_contract` for the RPC
  cross-check; per-rule RBF in `crates/mempool/tests/rbf_bip125.rs`;
  ancestor/descendant limits in
  `crates/mempool/tests/ancestor_limits.rs`.
