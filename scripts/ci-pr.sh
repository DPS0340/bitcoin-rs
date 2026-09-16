#!/usr/bin/env bash
# Single owner of the pull-request gate commands.
#
# The CI jobs (.github/workflows/ci.yml), the pre-commit hooks, and
# CONTRIBUTING.md invoke this script. Do not restate these commands anywhere
# else: the copies drift (the pre-commit config kept referencing the removed
# mdbx backend after its deletion).
#
# Compile and test profiles are kernel-free and need no CMake or Boost. The
# deny profile selects `kernel` only for metadata resolution; cargo-deny does
# not compile that graph.
#
# The pull-request lanes fail fast (issue #1081): clippy and every test lane
# stop at the first failing profile so the author sees the first actionable
# failure without paying for the remaining profiles. The deep lane keeps the
# collect-all behavior (one failing profile must not hide the diagnostics of
# the profiles after it) for local diagnosis.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 {fmt|clippy|test-crates|test-binary|test-workspace|test|deny|deep|all}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage

# Fail-fast runner for the pull-request lanes: the first failing command
# aborts the lane immediately (set -e propagates the exit status).
failfast() {
  local label="$1"
  shift
  echo "==> ${label}"
  "$@"
  echo "==> ok: ${label}"
}

# Collect-all runner for the deep lane.
failures=0

profile() {
  local label="$1"
  shift
  echo "==> ${label}"
  if "$@"; then
    echo "==> ok: ${label}"
  else
    echo "==> FAILED: ${label}" >&2
    failures=$((failures + 1))
  fi
}

finish() {
  if [[ ${failures} -gt 0 ]]; then
    echo "${failures} profile(s) failed" >&2
    exit 1
  fi
}

# Each profile command list exists once; the runner argument (failfast for
# the pull-request lanes, profile for deep) selects the failure behavior, so
# the two modes cannot drift apart.
clippy_profiles() {
  # Three kernel-free all-target profiles; consensus and node have
  # kernel-enabled defaults, so they are checked separately without it.
  "$1" "clippy: workspace (kernel-free)" \
    cargo clippy --locked --workspace --all-targets \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node \
      -- -D warnings
  "$1" "clippy: bitcoin-rs-consensus (native)" \
    cargo clippy --locked -p bitcoin-rs-consensus \
      --no-default-features --all-targets -- -D warnings
  "$1" "clippy: bitcoin-rs-node (fjall,zmq)" \
    cargo clippy --locked -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq --all-targets -- -D warnings
}

test_crates_profiles() {
  # Fixture-free per-crate profiles; only the binary's tests read the pinned
  # Core and Apalache fixtures. Smallest first.
  "$1" "test: bitcoin-rs-consensus (native)" \
    cargo test --locked -p bitcoin-rs-consensus --no-default-features --no-fail-fast
  "$1" "test: bitcoin-rs-node (fjall,zmq)" \
    cargo test --locked -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq --no-fail-fast
  # Isolated so node's default zmq feature cannot unify this package on.
  "$1" "test: bitcoin-rs-rpc (no default features)" \
    cargo test --locked -p bitcoin-rs-rpc --no-default-features --no-fail-fast
}

test_binary_profiles() {
  # Expects the pinned Core and Apalache fixtures:
  # bash scripts/provision-ci-reference-fixtures.sh
  # The formal solver run lives in the operator-invoked model-check-manual
  # lane (K=128 needs ~30h+, measured); every CI lane skips it and runs
  # only the cheap pin tests.
  "$1" "test: bitcoin-rs binary (rocksdb,fjall,redb)" \
    cargo test --locked -p bitcoin-rs --no-fail-fast \
      --no-default-features --features "rocksdb,fjall,redb" \
      -- --exact --skip all_model_specs_check_with_apalache
}

test_workspace_profiles() {
  # Also expects the pinned fixtures: bin/bitcoin-rs is a workspace member,
  # so this profile runs its default-feature (fjall,redb,zmq) test binaries,
  # including the process-harness suite that launches the pinned bitcoind.
  # Same solver skip as the binary profile.
  "$1" "test: workspace (kernel-free)" \
    cargo test --locked --workspace --no-fail-fast \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-node \
      -- --skip all_model_specs_check_with_apalache
}

case "$1" in
  fmt)
    cargo fmt --all -- --check
    ;;

  clippy)
    clippy_profiles failfast
    ;;

  test-crates)
    test_crates_profiles failfast
    ;;

  test-binary)
    test_binary_profiles failfast
    ;;

  test-workspace)
    test_workspace_profiles failfast
    ;;

  test)
    # Local composition of every test lane, smallest first. CI runs the
    # lanes as parallel jobs (.github/workflows/ci.yml); this subcommand
    # stays the full sequential gate for pre-commit and local use.
    "$0" test-crates
    "$0" test-binary
    "$0" test-workspace
    ;;

  deny)
    # Full dependency graph: every storage backend plus the kernel engine.
    # cargo-deny 0.20 takes the cargo metadata flags before the subcommand.
    cargo deny \
      --workspace --no-default-features --features "rocksdb,fjall,redb,kernel" \
      check
    ;;

  deep)
    # Collect-all variant: every clippy and test profile runs to completion
    # even after one fails, maximizing diagnostics per invocation.
    clippy_profiles profile
    test_crates_profiles profile
    test_binary_profiles profile
    test_workspace_profiles profile
    finish
    ;;

  all)
    "$0" fmt || failures=$((failures + 1))
    "$0" deep || failures=$((failures + 1))
    "$0" deny || failures=$((failures + 1))
    finish
    ;;

  *)
    usage
    ;;
esac