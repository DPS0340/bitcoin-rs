#!/usr/bin/env bash
# Local pre-push verification: fmt → clippy → check (affected crates).
# Designed for WSL or Linux. Run before push to avoid CI feedback loops.
#
# Usage:
#   ./scripts/local-verify.sh              # verify all changed crates
#   ./scripts/local-verify.sh -p node      # verify specific crate
#   ./scripts/local-verify.sh --full       # full workspace check + tests
set -euo pipefail

cd "$(dirname "$0")/.."

# Prefer rustup-managed cargo over system cargo
export HOME="${HOME:-$(eval echo ~)}"
export PATH="$HOME/.cargo/bin:$PATH"
CARGO="${CARGO:-cargo}"
PACKAGE=""
FULL=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -p|--package) PACKAGE="$2"; shift 2 ;;
    --full) FULL=true; shift ;;
    *) echo "usage: $0 [-p crate] [--full]" >&2; exit 2 ;;
  esac
done

failures=0
step() {
  local label="$1"; shift
  echo "==> $label"
  if "$@"; then
    echo "==> ok: $label"
  else
    echo "==> FAILED: $label" >&2
    failures=$((failures + 1))
  fi
}

# 1. Format check (instant)
step "fmt" $CARGO fmt --check

# 2. Determine affected crates from git diff
if [ -n "$PACKAGE" ]; then
  TARGETS="bitcoin-rs-${PACKAGE}"
else
  TARGETS=$(git diff --name-only origin/main...HEAD 2>/dev/null \
    | sed -n 's|crates/\([^/]*\)/.*|bitcoin-rs-\1|p' \
    | sort -u)
  if [ -z "$TARGETS" ]; then
    TARGETS=$(git diff --name-only HEAD~1 2>/dev/null \
      | sed -n 's|crates/\([^/]*\)/.*|bitcoin-rs-\1|p' \
      | sort -u)
  fi
fi

if [ -z "$TARGETS" ]; then
  echo "==> no changed crates detected; skipping check"
  echo "==> ALL PASSED"
  exit 0
fi

echo "==> affected crates: $TARGETS"

# 3. Clippy on affected crates (catches move/borrow/lint errors)
for crate in $TARGETS; do
  case "$crate" in
    bitcoin-rs-consensus)
      step "clippy: $crate" $CARGO clippy --locked -p "$crate" \
        --no-default-features --all-targets -- -D warnings
      ;;
    bitcoin-rs-chainstate)
      step "clippy: $crate" $CARGO clippy --locked -p "$crate" \
        --no-default-features --features fjall --all-targets -- -D warnings
      ;;
    bitcoin-rs-node)
      step "clippy: $crate" $CARGO clippy --locked -p "$crate" \
        --no-default-features --features fjall,zmq --all-targets -- -D warnings
      ;;
    *)
      step "clippy: $crate" $CARGO clippy --locked -p "$crate" \
        --all-targets -- -D warnings
      ;;
  esac
done

# 4. Full workspace check (only with --full)
if [ "$FULL" = true ]; then
  step "check: workspace" $CARGO check --locked --workspace
  step "test: g17 gate" $CARGO test --locked -p bitcoin-rs \
    --no-default-features --test g17_dependency_direction
fi

if [ $failures -gt 0 ]; then
  echo "==> $failures step(s) failed" >&2
  exit 1
fi

echo "==> ALL PASSED"
