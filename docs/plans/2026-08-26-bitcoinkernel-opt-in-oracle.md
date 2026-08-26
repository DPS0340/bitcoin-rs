## Context

Issue [gosuda/bitcoin-rs#166](https://github.com/gosuda/bitcoin-rs/issues/166) requires a Rust-only authoritative block/apply path and makes `bitcoinkernel` an opt-in verification oracle rather than an alternate execution backend. Current `origin/main` still default-enables `kernel` through `bin/bitcoin-rs -> bitcoin-rs-node -> bitcoin-rs-consensus`; `KernelBlock::txids()` feeds `BlockTxPlan`, Merkle/BIP30/UTXO decisions, and the Rust interpreter only verifies bare `OP_TRUE` and Taproot key-path spends. The work will run as one draft PR opened from a plan-only first commit, followed by review-gated stage commits; the PR becomes ready only after Rust parsing, native script consensus, fail-fast oracle comparison, historical parity, and the default-feature inversion are all proven.

## Approach

1. Fetch `origin`, record `BASE_SHA=$(git rev-parse origin/main)`, and create `feat/bitcoinkernel-verification-oracle` from that exact commit; leave the unrelated `remove-wallet-crate` checkout and its untracked task evidence untouched. Copy this approved plan to `docs/plans/2026-08-26-bitcoinkernel-opt-in-oracle.md`, commit only that file as `docs(plan): define bitcoinkernel oracle migration`, push, and immediately open a **draft** PR titled `refactor(consensus): make bitcoinkernel a verification oracle` with `Closes #166`. Post the Stage 0 status/direction review as the first PR comment. Then create untracked `.agent-tasks/bitcoinkernel-verification-oracle/GOALS.md` plus `tests/`, stage exact paths so those temporary files never enter the PR, and append every stage's command output there until merge.
2. For Stages 1–7, loop: commit the named stage; run its focused checks and require a nonzero executed-test count; push; run correctness, testing, and architecture reviews against `origin/main...HEAD`; fix every regression or P0–P2 finding by amending and force-pushing with lease; repeat checks/reviews until clean; only then post one final PR comment headed `## Stage <N> review — <final-sha>`. Each comment records commands/results and a direction table with `Rust authority`, `kernel isolation`, and `promotion evidence` marked `advanced`, `unchanged`, or `regressed`, followed by the next stage. Fixed stage numbers: 0 plan, 1 Rust block data, 2 execution context, 3 legacy/P2SH, 4 SegWit/Tapscript, 5 oracle, 6a gate, 6b evidence, 7 defaults.
3. Commit `refactor(consensus): make Rust block data authoritative`. Add `bitcoin_slices.workspace = true` to `crates/node/Cargo.toml` and reuse the `Visitor` plus `bsl::Transaction::txid_sha2()` pattern from `crates/index/src/index.rs`, converting each digest to `bitcoin::Txid` and pinning byte order against `Transaction::compute_txid`. Make `parse_block_for_apply` return a `PreparedApply` with exactly one canonical `bytes::Bytes`, the Rust-derived `BlockTxPlan`, resolved state, and—only until Stage 5 in kernel builds—a `kernel_scripts: KernelBlock` used solely for script execution: validate caller-supplied bytes with `bytes_are_block`, or serialize a direct/local block once; visit that same buffer for ordered txids; reject visitor errors/count mismatches as `ConsensusError::Encoding`; reuse the buffer for body persistence, indexes, ZMQ, window proofs, reorg reconnects, and later oracle input. Only Rust txids feed Merkle/BIP30, same-block planning, scratch/UTXO keys, and persistence. Remove `KernelBlock::txids()`, delete the portable txid/decode stand-in, and eliminate every second local serialization or `compute_txid` planner helper.
4. Commit `refactor(script): establish the consensus execution context`. Add public `bitcoin_rs_consensus::ResolvedBlockInputs`, which owns one immutable per-transaction/input prevout matrix for both engines; replace `Option::take` preparation with index-based `PreparedTx` records into that matrix. Add `ScriptFailure { tx_index, input_index, reason }` and `BlockCheckFailure::{NonScript(ConsensusError), Script(ScriptFailure)}` so single-block, batched, window, and reorg paths preserve transaction coordinates without parsing error strings. Replace flat per-input Rayon jobs with per-transaction jobs: each worker owns one mutable `SighashCache`, verifies that transaction's inputs serially, transactions run in parallel, and the final scan preserves block → transaction → phase (`pre < script < post`) → input error order. Keep `Interpreter` as the external seam, change `execute`/`execute_with_prevouts` to `Result<(), ScriptError>`, migrate production, benchmark, integration, property, and in-module unit-test callers, and redefine `ScriptItem` as raw `SmallVec<[u8; 32]>` so numeric minimality and negative zero remain observable.
5. In Stage 2, add private `SigVersion::{Base, WitnessV0, TapScript}` and `EvalContext` carrying transaction, input index, amount, ordered prevouts, script code, `VerifyFlags`, code-separator position, the per-transaction sighash cache, and Tapscript validation-weight budget. Adapt the production shapes from `reardencode/rbitcoin` commit `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937` into exact local paths: keep the evaluator in `crates/script/src/interpreter.rs`; create `classify.rs`, `nested.rs`, `p2pkh.rs`, `p2wpkh.rs`, `p2wsh.rs`, and `signature.rs`; extend existing `taproot.rs` rather than adding a parallel P2TR module. Replace the source's `ScriptCheckJob`, `rbitcoin_query::TxPrecompute`, and storage/query dependencies with `ResolvedBlockInputs`/`EvalContext`, and retain provenance in every adapted module. Do not add `rbitcoin`, `blvm-consensus`, or `bitcoin-scriptexec` dependencies and do not upgrade the workspace `bitcoin` range to fit the reference.
6. Commit `feat(script): implement legacy and P2SH consensus`. Implement bounded stack/altstack, numeric/boolean encodings, push parsing, control flow, limits, disabled/reserved opcodes, arithmetic/stack/hash opcodes, legacy sighash including `FindAndDelete`/`OP_CODESEPARATOR`, lax DER plus `DERSIG`/`STRICTENC`/`LOW_S`, `CHECKSIG`, `CHECKMULTISIG`, `NULLDUMMY`, `NULLFAIL`, CLTV, CSV, P2PK/P2PKH/bare, BIP16 P2SH, and push-only/minimal-data/clean-stack rules. Drive valid/invalid legacy and P2SH fixtures through the shipped `Interpreter`, including the existing mainnet/testnet P2SH exception flag sets.
7. Commit `feat(script): implement SegWit and Tapscript consensus`. Add native/P2SH-wrapped P2WPKH/P2WSH, BIP143, witness limits/unknown versions, BIP341 annex/control-block/output-key checks, key-path, BIP342 Tapscript, `OP_SUCCESSx`, `CHECKSIGADD`, Tapscript `MINIMALIF`, public-key-version rules, validation weight, and code-separator positions. Replace `crates/consensus/tests/vectors.rs` load-only checks with all-row execution of Bitcoin Core v31.1 commit `9be056a8a72b624dae9623b2f7bded92c2a21c91` `script_tests.json`, `tx_valid.json`, `tx_invalid.json`, `sighash.json`, and new `bip341_wallet_vectors.json`; the shipped path must report zero skipped or allowlisted rows. Update `kernel_block_parity.rs` so all six class fixtures and every mutation assert Rust/kernel agreement.
8. Commit `refactor(consensus): make kernel a fail-fast oracle`. Rust executes first and is always authoritative; only `BlockCheckFailure::Script` enters script-verdict comparison, while every non-script failure returns unchanged without consulting kernel. In `bitcoin-rs-consensus`, define `ValidationOracle: Send + Sync` with `verify_block(&self, request: OracleBlock<'_>) -> Result<OracleReport, OracleError>`: `OracleBlock` borrows canonical raw bytes, Rust txids, `ResolvedBlockInputs`, and flags; `OracleReport` exposes only first txid-mismatch index, `ScriptVerdict::{Accepted, Rejected(ScriptFailure)}`, and bounded comparison counts—never kernel hashes/transactions/precomputations; `OracleError::Unavailable(String)` covers setup failure. Map only `KernelError::ScriptVerify(ScriptVerifyError::Invalid)` to script rejection; invalid input index/flags/spent-output requirements, parse, precompute, conversion, and internal failures are unavailable. The concrete adapter lives under feature-gated `kernel_oracle`; `ApplyHandles` stores `Option<Arc<dyn bitcoin_rs_consensus::ValidationOracle>>`.
9. In Stage 5, add `Config::verify_kernel: bool` and `ConfigLayer::verify_kernel: Option<bool>` with TOML, `BITCOIN_RS_VERIFY_KERNEL`, and Clap `--verify-kernel[=true|false]`; default false. A non-kernel binary given true fails with `--verify-kernel requires a binary built with the kernel feature`; feature-present/false constructs no adapter and performs no kernel call; feature-present/true compares kernel parse/count/txids and scripts against Rust without feeding a kernel value into apply. Any parser, txid, or script disagreement emits structured `kernel_oracle_mismatch` fields, increments `consensus.kernel_oracle.compared_inputs_total`/`mismatch_total`, and returns the corresponding `ConsensusError::KernelMismatch` before writes. Both script rejects preserve the Rust script error; both accepts continue. Kernel unavailable becomes `ConsensusError::Kernel`. There is no observe mode or fallback. Add `scripts/check-kernel-feature-inert.sh`: it builds `mainnet_prefix_replay` into separate target directories with `fjall` and `fjall,kernel`, runs both **without** `--verify-kernel` on the same deterministic fixture into fresh state roots, byte-compares canonical validation artifacts, and rejects any oracle counter/context creation in the feature-present run.
10. Make fail-before-mutation true on every route in Stage 5. Change window proofing from empty-vector fallback to `Result<Option<Vec<ProvenApply>>, ApplyError>`: `Ok(None)` alone permits ordinary fallback; `KernelMismatch`/`Kernel` returns `WindowApplyError { applied: 0, ... }`. Before a reorg disconnect, while holding `chain_transition`, load/decode all disconnect `UndoBatch` records, apply `restores()`/`removes()` to a scratch `WindowOverlay`, resolve every available reconnect block in order, run Rust/oracle verification, and carry the resulting proofs into connect; mismatch/unavailable exits before the first disconnect. Route `KernelMismatch`/`Kernel` in forward sync and reorg as operational hard stops: close `ApplyAdmission`, set the process shutdown flag, never invalidate the header subtree, never count/drop the block for retry, and preserve the old applied state. `assume_valid` skips both scripts and oracle; evidence runs force height 0.
11. Commit `test(consensus): add the Rust promotion gate`. Extend `mainnet_prefix_replay` with `--verify-kernel` and required non-overlapping `--kernel-root`; keep Rust state, kernel chainstate/blocks, corpus archive, and manifest disjoint. Add an offline parser check that visits each raw block independently with `bitcoin_slices` and `bitcoinkernel::Block`, compares count and ordered txids, and records first mismatch without passing kernel values into `BlockTxPlan`. Use isolated `bitcoinkernel::ChainstateManager` only in this driver for coarse block/tip parity. Replace G3 with a fail-closed validator for `G3_PROMOTION_ARTIFACT`, a `consensus-promotion-v1` manifest containing Stage 6a SHA and SHA-256 references to five compact reports: feature-absent Rust full replay, kernel-oracle full replay, Core v31.1 all-row vectors, deterministic invalid/activation/same-block/reorg scenarios, and the processing performance panel. Add `scripts/run-consensus-promotion.sh` to build/hash both revisions, run every guarded replay/test/report in fixed order, and call `scripts/produce-consensus-promotion-artifact.sh`; the producer independently validates and aggregates those reports so no cell is inferred from the linear replay alone.
12. Before Stage 1, record `BASE_SHA`; on Stage 6a, `scripts/run-consensus-promotion.sh` builds that exact base and the Stage 6a candidate from isolated worktrees into separate target directories and hashes both binaries. It runs the `0..150_000` panel in order `B,C,C,B,B,C` with `taskset -c 0-31`, identical archive/manifest/fjall/assume-valid=0 inputs, external wall/CPU/RSS capture, and a fresh guarded run root per arm; it rejects identity/state mismatch or candidate medians above 1.05× baseline on any resource axis. It then runs separate full-tip Rust-only and `--features kernel --verify-kernel` replays, executes Core/scenario reports, and aggregates:

   ```sh
   scripts/produce-consensus-promotion-artifact.sh \
     --output "$G3_PROMOTION_ARTIFACT" \
     --tested-commit "$STAGE6A_SHA" \
     --rust-replay "$G3_RUST_REPORT" \
     --oracle-replay "$G3_ORACLE_REPORT" \
     --core-vectors "$G3_CORE_VECTOR_REPORT" \
     --scenarios "$G3_SCENARIO_REPORT" \
     --performance-panel "$G3_PERFORMANCE_REPORT"
   ```

   Every replay/corpus creation runs through `scripts/run-g14-guarded.sh` using a **fresh mutable run/output root** as `--fixture`, never the pre-existing read-only archive. The driver computes `--max-fixture-bytes` as twice the archive size plus 137438953472 bytes for a Rust+kernel run (archive size plus 68719476736 for Rust-only), uses `--reserve-bytes 107374182400`, `--max-rss-bytes 17179869184`, `--interval-seconds 60`, explicit stdout/stderr paths, and a unique unit name; it retains compact reports and removes successful disposable roots before the next arm.
13. Commit only the accepted compact reports/manifest under `docs/benchmarks/data/consensus-promotion/` as `test(consensus): record Rust promotion evidence` (Stage 6b). `tested_commit` is Stage 6a; G3 requires full git history, ancestry, hashes, zero mismatches, exact full-tip state parity, complete coverage cells, and the 1.05 panel. Then commit `refactor(consensus): make kernel verification opt-in` (Stage 7): consensus defaults `[]`, node `["fjall"]`, binary `["rocksdb","fjall","redb","mdbx"]`; keep explicit `kernel` forwarding and `checksig-census -> kernel`; remove CMake/Boost from normal CI/Docker/dev paths; remove `kernel` from normal `.pre-commit-config.yaml` hooks; retain an explicit kernel-parity lane with `fetch-depth: 0`, all-row/differential tests, the committed G3 manifest, and a two-build feature-inert replay comparison. Stage 7 may edit only exact default-feature/comment hunks in root `Cargo.toml`, `crates/consensus/Cargo.toml`, `crates/node/Cargo.toml`, and `bin/bitcoin-rs/Cargo.toml`—never dependencies/profiles/targets or `Cargo.lock`—plus `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `Dockerfile`, `README.md`, `docs/getting-started.md`, `crates/script/README.md`, `crates/consensus/README.md`, `crates/node/README.md`, `CONCEPTS.md`, `DEVIATIONS.md`, and `scripts/run-g14-bitcoin-rs-mainnet-ibd.sh`. Mark ready only after the final review and all GitHub checks are green.

## Critical files & anchors

- `crates/node/src/apply.rs`: `PreparedApply`, window proofing, `parse_block_for_apply`, `verify_block_transactions`, and `BlockTxPlan` own canonical bytes, Rust txids, no-write oracle preflight, and operational error routing.
- `crates/consensus/src/verify_tx.rs`: `prepare_block_script_checks`, `PreparedTx`, and the ordered batch scan must become indexed per-transaction Rust jobs with structured script verdicts.
- `crates/consensus/src/kernel.rs`: `KernelBlock`, `PreparedKernelTx`, and `verify_prepared_input` are renamed/reduced behind `ValidationOracle`.
- `crates/script/src/interpreter.rs`: `verify_non_taproot_portable` is replaced by the complete local engine and Core all-row seam.
- `crates/node/src/reorg.rs`: `execute_loaded_plan` currently disconnects before reconnect verification and must gain undo-backed non-mutating preflight plus hard-stop routing.

## Verification

Run from `/home/gosunuts/workspace/bitcoin-rs`. Rust 1.95.0/rustfmt/clippy are pinned by `rust-toolchain.toml`; kernel builds require CMake and Boost. Core vectors are pinned to official v31.1 commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`; the current lock resolves `bitcoinkernel 0.2.1`.

1. Stage 1 adds `rust_block_data_tests` and runs:

   ```sh
   cargo test -p bitcoin-rs-node --lib \
     --no-default-features --features fjall \
     --no-fail-fast rust_block_data_tests
   cargo test -p bitcoin-rs-node --test sync_smoke \
     --no-default-features --features fjall --no-fail-fast
   ```

   The first command must execute nonzero tests proving visitor txids equal `compute_txid`, malformed/count-mismatched bytes fail, supplied/local bytes are retained once, persistence/window/reorg reuse them, and no kernel txid method remains.
2. Stages 2–4 run `cargo test -p bitcoin-rs-script --no-fail-fast` and `cargo test -p bitcoin-rs-consensus --no-default-features --no-fail-fast` after each commit. Stage 3 additionally runs:

   ```sh
   cargo test -p bitcoin-rs-consensus \
     --no-default-features --features kernel \
     --test kernel_block_parity --no-fail-fast \
     legacy_and_p2sh_differential -- --exact
   ```

   Stage 4 runs:

   ```sh
   cargo test -p bitcoin-rs-consensus \
     --test vectors --no-default-features --no-fail-fast
   cargo test -p bitcoin-rs-consensus \
     --no-default-features --features kernel \
     --test kernel_block_parity --no-fail-fast
   ```

   Stage comments record nonzero row/mutation counts; final output must name all five Core files, all six script-class fixtures, zero skipped/allowlisted rows, and zero Rust/kernel verdict mismatches.
3. Stage 5 adds exact `oracle_tests`, `oracle_window_tests`, and `oracle_reorg_tests` modules and runs:

   ```sh
   cargo test -p bitcoin-rs-node --test config_layered \
     --no-default-features --features fjall --no-fail-fast
   cargo test -p bitcoin-rs-node --lib \
     --no-default-features --features fjall,kernel \
     --no-fail-fast oracle_tests
   cargo test -p bitcoin-rs-node --lib \
     --no-default-features --features fjall,kernel \
     --no-fail-fast oracle_window_tests
   cargo test -p bitcoin-rs-node --lib \
     --no-default-features --features fjall,kernel \
     --no-fail-fast oracle_reorg_tests
   cargo test -p bitcoin-rs-consensus \
     --no-default-features --features kernel \
     --no-fail-fast -- --include-ignored
   scripts/check-kernel-feature-inert.sh \
     --blocks-file "$G3_SMOKE_BLOCKS" \
     --corpus-manifest "$G3_SMOKE_MANIFEST" \
     --stop-height "$G3_SMOKE_HEIGHT" \
     --work-root "$G3_SMOKE_ROOT"
   ```

   Tests cover accept/accept, reject/reject, Rust-accept/kernel-reject, Rust-reject/kernel-accept, unavailable adapter, parser/txid mismatch, forward sync, window fallback, and reorg. Every mismatch/unavailable case must report `applied=0`, leave all state digests unchanged, close admission/set shutdown, and neither invalidate nor schedule retry. The two-build script must compare separate `fjall` and `fjall,kernel` binaries with the flag absent and prove byte-identical validation artifacts plus zero oracle activity.
4. Stage 6a runs the complete producer, which owns the guarded command construction and B,C,C,B,B,C campaign:

   ```sh
   scripts/run-consensus-promotion.sh \
     --base-sha "$BASE_SHA" \
     --candidate-sha "$STAGE6A_SHA" \
     --blocks-file "$G3_BLOCKS_FILE" \
     --corpus-manifest "$G3_CORPUS_MANIFEST" \
     --tip-height "$G3_TIP_HEIGHT" \
     --work-root "$G3_WORK_ROOT" \
     --output-dir "$G3_OUTPUT_DIR"
   ```

   It must create and validate `rust-mainnet-replay.json`, `kernel-oracle-mainnet-replay.json`, `core-vectors-v31.1.json`, `consensus-scenarios.json`, `processing-panel.json`, and `consensus-promotion-v1.json`. Full replays end at the manifest tip with `assume_valid_height=0`; Rust-only/oracle state digests match; parser, txid, script, transaction, block, activation, same-block, invalid, and reorg cells report zero mismatch; candidate wall/CPU/RSS medians each satisfy ≤1.05× baseline.
5. After Stage 6b commits the compact files, validate the committed manifest:

   ```sh
   G3_PROMOTION_ARTIFACT=docs/benchmarks/data/consensus-promotion/consensus-promotion-v1.json \
     cargo test -p bitcoin-rs --test g03_kernel_parity \
       kernel_parity_gate -- --exact --ignored --nocapture
   ```

   Missing history, non-ancestor `tested_commit`, changed protected code, hash/schema mismatch, incomplete cells, or a failed threshold must fail closed.
6. Before Stage 7 is marked ready, run:

   ```sh
   cargo fmt --all -- --check
   cargo test --workspace --no-fail-fast
   cargo test -p bitcoin-rs --no-default-features \
     --features rocksdb,fjall,redb,mdbx --no-fail-fast
   cargo test -p bitcoin-rs --no-default-features \
     --features rocksdb,fjall,redb,mdbx,kernel --no-fail-fast
   cargo test -p bitcoin-rs-consensus --no-default-features \
     --features kernel --no-fail-fast -- --include-ignored
   cargo clippy -p bitcoin-rs --all-targets -- -D warnings
   cargo clippy -p bitcoin-rs-node --all-targets -- -D warnings
   cargo clippy -p bitcoin-rs --all-targets --no-default-features \
     --features rocksdb,fjall,redb,mdbx,kernel -- -D warnings
   cargo clippy -p bitcoin-rs-consensus --all-targets \
     --no-default-features --features kernel -- -D warnings
   cargo bench -p bitcoin-rs --no-run --no-default-features \
     --features rocksdb,fjall,redb,mdbx
   cargo deny check --workspace --no-default-features \
     --features rocksdb,fjall,redb,mdbx
   pre-commit run --all-files
   ```

   Then watch the draft PR HEAD until every GitHub job is green. A branch-attributable failure is fixed in its owning stage commit and re-reviewed; a failure proven identical on current `origin/main` is linked with the exact main run/job log and does not authorize unrelated edits.

## Assumptions & contingencies

- The full issue ships through one draft PR with preserved stage commits. The plan commit opens the PR before behavioral work; no stage is squashed away because its final review comment names its SHA.
- Runtime parser, txid, or script disagreement is fail-fast before mutation. There is no observe/continue mode and no kernel fallback.
- The native engine adapts `reardencode/rbitcoin` at `b6ad818e4aa36e5b4a9f8a0ad83feb8f3b036937` under MIT/Apache-2.0, without adding it, `blvm-consensus`, or explicitly non-consensus `bitcoin-scriptexec` as dependencies.
- `PLAN.md` is historical and does not impose its stale 12-month rule. Issue #166's current cells plus the executable `consensus-promotion-v1` manifest are authoritative.
- A rebase before Stage 6a invalidates `BASE_SHA` custody: record the new base, rebuild both campaign binaries, and rerun stage checks. A rebase after Stage 6a invalidates every promotion artifact: reconstruct through the rebased Stage 6a code commit, rerun the full campaign, recommit Stage 6b evidence, reapply Stage 7, and review again. Never relabel old evidence.
- If the full-tip corpus is absent, create it under a fresh, initially nonexistent `$G3_CORPUS_ROOT`:

  ```sh
  scripts/run-g14-guarded.sh \
    --fixture "$G3_CORPUS_ROOT" \
    --max-fixture-bytes 1374389534720 \
    --reserve-bytes 107374182400 \
    --max-rss-bytes 17179869184 \
    --interval-seconds 60 \
    --stdout "$G3_CORPUS_STDOUT" \
    --stderr "$G3_CORPUS_STDERR" \
    --unit-name "bitcoin-rs-g3-corpus" -- \
    cargo run --release -p bitcoin-rs-node \
      --example export_active_chain_corpus \
      --no-default-features --features fjall -- \
      --data-dir "$SYNCED_NODE_DATA_DIR" \
      --network mainnet --stop-height "$G3_TIP_HEIGHT" \
      --archive "$G3_CORPUS_ROOT/blocks.dat" \
      --manifest "$G3_CORPUS_ROOT/manifest.json"
  ```

  Do not substitute a 100k/150k prefix for full historical promotion.
- If any Core row remains unsupported, any oracle mismatch/unavailable result appears, or any performance axis exceeds 1.05, keep the PR draft and current defaults unchanged. Fix the Rust parser/interpreter or evidence harness in its owning stage; kernel-derived data and kernel authority remain prohibited.
