---
title: A clean workspace clippy does not predict the -D warnings CI lanes
date: 2026-08-08
category: docs/solutions/best-practices
module: .github/workflows/ci.yml (clippy, kernel-parity, test)
problem_type: best_practice
component: tooling
severity: medium
applies_when:
  - "Verifying a branch locally before pushing"
  - "A PR shows CI failures that no local command reproduces"
  - "Claiming a branch is green"
related_components:
  - development_workflow
tags:
  - ci-parity
  - clippy
  - verification-scope
  - feature-flags
---

# A clean workspace clippy does not predict the -D warnings CI lanes

## Symptom

A branch verified locally with

```
cargo test --workspace --release --no-fail-fast   # 0 failures
cargo clippy --workspace --all-targets            # 0 errors
cargo fmt --all --check                           # clean
```

was pushed as green and CI failed on `clippy`, `test`, and `kernel-parity`.

## Cause

Three differences, none visible from the workspace commands:

1. **`-D warnings` denies far more than the named lint set.** The workspace
   build denies specific lints such as `clippy::as-conversions`. The `clippy`
   and `kernel-parity` jobs add `-D warnings`, which promotes every remaining
   warning, including `dead_code`, `needless_borrow`, `doc_markdown`,
   `needless_collect`, and `too_many_lines`. A workspace run reports those as
   warnings and exits 0.

2. **A virtual workspace does not forward `--features`.** The top-level
   `Cargo.toml` has no `[package]`, so `--workspace --features` silently
   ignores the flags. CI uses `-p bitcoin-rs --no-default-features --features
   "$FULL_NODE_FEATURES"` to propagate all four storage backends and the
   kernel. `-p bitcoin-rs` also does not forward features to
   `bitcoin-rs-node`'s own test targets, which is why CI runs
   `cargo clippy -p bitcoin-rs-node --all-targets` as a separate step.

3. **`--include-ignored` and the debug profile.** `kernel-parity` runs the
   consensus suite with `--include-ignored`, so tests skipped by a plain
   `cargo test` run there. It also builds debug, not release.

## Fix

Run the workflow's own commands rather than an approximation of them:

```
cargo clippy -p bitcoin-rs --all-targets \
  --no-default-features --features "rocksdb,fjall,redb,mdbx,kernel" -- -D warnings
cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings
cargo clippy -p bitcoin-rs-consensus --all-targets -- -D warnings
cargo test -p bitcoin-rs-consensus --no-fail-fast -- --include-ignored
cargo test --workspace --no-fail-fast
cargo test -p bitcoin-rs --no-fail-fast \
  --no-default-features --features "rocksdb,fjall,redb,mdbx,kernel"
cargo deny check
```

`cargo clippy --fix` applies the machine-applicable suggestions for the
mechanical lints, which is safer than hand-editing dozens of sites: the
`needless_borrow` rewrites are the borrow the compiler already inserted.

## Guidance

1. **Read the workflow before claiming green.** Verification scope must match
   claim scope. "The suite passes" is a claim about the commands you ran, and
   CI runs different ones.
2. **A parallel local test run can produce a phantom failure.** Running the
   suite concurrently with clippy jobs against the same target directory
   produced one spurious `FAILED` that three serial reruns did not reproduce.
   Confirm a suspected regression serially before chasing it.
3. **`cargo deny` is a release gate, not a lint.** It caught RUSTSEC-2026-0220
   in `ruint 1.18.0`, whose truncated 256-bit shift amounts reach chainwork
   arithmetic in `bitcoin-rs-chain`. Treat an advisories failure as a bug
   report against the node, not as CI noise.
