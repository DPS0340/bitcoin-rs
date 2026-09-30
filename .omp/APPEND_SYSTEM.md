# Verification policy

This project runs on Windows with WSL for cargo. When the change is
type-safe by construction (cfg gating, field additions, rename, doc
changes, CI/script changes), `cargo fmt --check` is sufficient before
yielding. Full `cargo check` or `cargo test` is optional for such
changes; CI will catch regressions at merge time.

Use `wsl ./scripts/local-verify.sh -p <crate>` for local verification
when in doubt. The script runs fmt + clippy on affected crates in ~30-50s.
