# FLIP-166 — Kernel flip investigation and blocking finding

**Date:** 2026-09-02
**Issue:** #166 — Make the kernel an opt-in verification oracle
**Verdict:** BLOCKED — the portable Rust interpreter cannot validate ordinary spends; the flip cannot proceed until a full opcode interpreter exists.

## What was attempted

The original scope was to flip `libbitcoinkernel` from a production dependency to an opt-in verification oracle across all crates, based on two proven gates:

1. **Correctness gate** (G03 differential parity): block-parse parity over 15 mainnet blocks, script-verdict parity over 6 fixtures × mutations, and vector oracle parity over 121 `tx_valid` + 84 `tx_invalid` rows through the kernel. See `.outline/sdd/reports/parity-harness.md`.
2. **Performance gate** (PERF-V5): native apply-path median 15.747 ms vs kernel baseline 36.136 ms (2.29x), with both arithmetic conditions (`native < kernel`, `native * 1.05 <= kernel`) passing. See `docs/benchmarks/data/overhaul-native-apply-20260902.md`.

The flip would have changed `crates/consensus/Cargo.toml` `default = ["kernel"]` → `default = []` and `crates/node/Cargo.toml` `default = ["fjall", "kernel", "zmq"]` → `default = ["fjall", "zmq"]`, making the kernel opt-in everywhere.

## Why the flip is blocked

Main halted the work before any manifest edits after discovering that the performance gate's 2.29x "speedup" is a **capability gap**, not a speedup:

### The portable interpreter is a stub

`crates/script/src/interpreter.rs` `verify_non_taproot_portable` (line ~397):

```rust
fn verify_non_taproot_portable(
    input_idx: usize,
    _prevout: &TxOut,
    spending: &Tx,
    script_pubkey: &[u8],
) -> Result<bool, ScriptError> {
    let input = spending.inputs.get(input_idx)...;
    if script_pubkey == [0x51] && input.script_sig.is_empty() && input.witness.is_empty() {
        return Ok(true);
    }
    Err(ScriptError::Verification(
        "portable script backend cannot verify this non-taproot spend".to_owned(),
    ))
}
```

This accepts **only** bare `OP_TRUE` spends (`script_pubkey == [0x51]`, empty scriptSig, empty witness). Every other non-Taproot spend — Legacy P2PKH, P2SH multisig, bare multisig, SegWit v0 — returns `Err`.

Only **Taproot key-path** verification is implemented in full (`verify_taproot_keypath`, same file). Taproot script-path spends are rejected with `TaprootUnsupportedWitness`.

### No opcode interpreter exists

`crates/script` has 1,406 lines across its `src/` directory:

| File | Lines |
|---|---:|
| `script.rs` | 559 |
| `interpreter.rs` | 452 |
| `sigops.rs` | 170 |
| `stack.rs` | 99 |
| `taproot.rs` | 49 |
| `batch.rs` | 43 |
| `lib.rs` | 34 |
| **Total** | **1,406** |

`script.rs` lexes raw bytes into `Instruction::PushBytes` / `Instruction::Op` variants (a script *parser*), but no file in the crate evaluates opcodes against a stack. There is zero opcode dispatch — no `match opcode { OP_DUP => ..., OP_CHECKSIG => ..., ... }` execution engine.

### The benchmark corpus exploited the stub

The PERF-V5 corpus (`crates/node/benches/sync_pipeline.rs`, `spend_heavy_proxy_blocks()`) uses `push_int(1)` as `script_pubkey` — exactly `[0x51]`, the one shape the portable stub accepts. So the native arm verified zero signatures while the kernel arm ran Core's full script engine. The 2.29x ratio measures apply-path overhead (parse, prevout resolution, state plumbing) on trivially satisfiable scripts, not validation cost.

`CONCEPTS.md` → *Rust interpreter (portable posture)* already records the consequence: "a mainnet sync stops early on the first real spend."

### Consequence of flipping today

Making `kernel` opt-in across all crates would make `cargo build -p bitcoin-rs` (already kernel-free) the canonical build, producing a node that cannot validate ordinary mainnet spends. The `crates/consensus` and `crates/node` library defaults would also lose the kernel, so `cargo test -p bitcoin-rs-consensus` and `cargo test -p bitcoin-rs-node --lib` would run against the stub. This is a regression in validation capability, not an improvement in build ergonomics.

## What was proven

### G03 differential parity (correctness)

The g03 gate (`bin/bitcoin-rs/tests/gates/g03_kernel_parity.rs`, `#![cfg(feature = "kernel")]`) covers:

1. **Block-parse parity**: 15 committed mainnet blocks parsed through both `Block::consensus_decode` (native) and `KernelBlock::parse` (kernel), comparing transaction counts and every txid byte-for-byte. Zero mismatches.
2. **Script-verdict parity**: 6 committed mainnet fixtures × 4–6 mutations each, differentials kernel vs Rust interpreter across all 5 script classes (P2PKH, P2SH, bare multisig, segwit v0, taproot). 3/3 tests pass.
3. **Vector oracle parity**: 121 `tx_valid` + 84 `tx_invalid` rows from Core's consensus test vectors through the kernel, asserting verdict equality. 66/66 mandatory-flag `tx_valid` rows accepted; 84/84 `tx_invalid` rows rejected.
4. **Non-vacuity**: RED/GREEN proofs confirm the assertion logic catches mismatches in both directions.

See `.outline/sdd/reports/parity-harness.md` for the full transcript.

### PERF-V5 apply-path overhead (performance)

| Metric | Kernel baseline | Native (this run) |
|---|---:|---:|
| Median | 36.136 ms | 15.747 ms |
| Speedup | 1.0x | 2.29x |

Both gate conditions pass:
- Gate 1: 15.747 ms < 36.136 ms ✓
- Gate 2: 15.747 × 1.05 = 16.534 ms ≤ 36.136 ms ✓

**Scope:** the corpus spends bare `OP_TRUE` outputs, so neither arm verifies a signature. The number measures apply-path overhead, not validation cost. It cannot license the default flip while the portable backend rejects every non-trivial spend.

## What remains

A portable Rust opcode interpreter covering:

- **Legacy script execution**: P2PKH, P2SH, bare multisig, and all standard script forms with full opcode dispatch (OP_DUP, OP_CHECKSIG, OP_CHECKMULTISIG, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, etc.).
- **SegWit v0**: P2WPKH and P2WSH script execution with the BIP143 sighash digest.
- **Taproot script-path**: BIP342 script execution with the BIP341 sighash digest, annex handling, and `OP_CHECKSIGADD`.
- **All sighash variants**: Legacy (BIP143 pre-segwit), SegWit v0 (BIP143), and Taproot (BIP341) sighash types including `SIGHASH_ALL`, `SIGHASH_NONE`, `SIGHASH_SINGLE`, `SIGHASH_ANYONECANPAY`, and Taproot `SIGHASH_DEFAULT`.

Until this interpreter exists and passes its own differential parity against the kernel over real mainnet spends, the `kernel` feature must remain the default in `crates/consensus` and `crates/node`.

## Cargo tree verification

The `bin/bitcoin-rs` binary already excludes `bitcoinkernel` from its default dependency graph:

```
$ cargo tree -p bitcoin-rs 2>&1 | grep -c bitcoinkernel
0

$ cargo tree -p bitcoin-rs --features kernel 2>&1 | grep -c bitcoinkernel
2
```

With `--features kernel`, the two lines are:
```
│   ├── bitcoinkernel v0.2.1
│   │   └── libbitcoinkernel-sys v0.3.0
```

The chain is: `bitcoin-rs` → `bitcoin-rs-node` → `bitcoin-rs-consensus` → `bitcoinkernel`.

This confirms that `bin/bitcoin-rs/Cargo.toml` `default = ["fjall", "redb", "zmq"]` (no `kernel`), combined with the workspace declaring `bitcoin-rs-node` with `default-features = false`, already excludes `bitcoinkernel` from the default binary build today. The `crates/consensus` and `crates/node` library crates still default to `kernel`, so `cargo test -p bitcoin-rs-consensus` and `cargo test -p bitcoin-rs-node --lib` run with the kernel engine.

## Prose corrections made

The following in-repo prose claimed the native path can replace the kernel or that `--verify-kernel` exists. Each was corrected:

| File:line (before edit) | False claim | Correction |
|---|---|---|
| `README.md:3-4` | "pure-Rust defaults, native consensus validation, and an opt-in kernel oracle" | Rewritten: default binary is pure Rust; kernel is the production engine when enabled; portable path verifies Taproot key-path only (see #166) |
| `README.md:9-11` | "Native consensus validation: pure-Rust script execution covering Legacy, SegWit v0, and Taproot key-path and script-path spends" | Rewritten: kernel verifies all script classes; portable interpreter covers Taproot key-path only; other classes stubbed (see #166) |
| `README.md:12-14` | "Opt-in verification oracle: compile with `--features kernel` to enable `--verify-kernel`" | Rewritten: `--features kernel` enables `libbitcoinkernel` as the consensus engine; `--verify-kernel` flag does not exist in code and was removed from docs |
| `README.md:63-72` | "Optional kernel oracle build" with `--verify-kernel` | Renamed to "Kernel consensus build"; removed `--verify-kernel` from the example |
| `README.md:102-106` | "native script execution runs in parallel" + `kernel_oracle.rs` reference | Rewritten: script execution runs in parallel under kernel; portable handles Taproot key-path only; file is `kernel.rs` not `kernel_oracle.rs` |
| `README.md:117-118` | "Validation engine \| Native Rust" + "Kernel verification oracle \| Off" | Rewritten: validation engine is `libbitcoinkernel` with `--features kernel`, portable Rust (Taproot key-path only) otherwise |
| `docs/getting-started.md:9` | "The default build is pure Rust and requires no C++ compiler" | Added: portable interpreter verifies Taproot key-path only, cannot validate ordinary mainnet spends (see #166) |
| `docs/getting-started.md:11-12` | "optional `kernel` feature for differential verification" | Rewritten: `kernel` feature for production consensus validation via `libbitcoinkernel` |
| `docs/getting-started.md:28-30` | "Consensus validation runs natively in pure Rust across all script types" | Rewritten: default binary uses portable interpreter (Taproot key-path only); other classes stubbed (see #166) |
| `docs/getting-started.md:32` | "optional `libbitcoinkernel` verification oracle" | Rewritten: `libbitcoinkernel` as the consensus engine for full script validation |
| `docs/getting-started.md:81` | `\|--verify-kernel\| off (requires --features kernel build)` | Replaced with `\|--features kernel (build-time)\| off in default binary; enables libbitcoinkernel consensus engine` |
| `CONCEPTS.md:77` | "production consensus default across consensus, node, and binary crates" | Rewritten: default in consensus and node but NOT in bin/bitcoin-rs; cargo build -p bitcoin-rs excludes bitcoinkernel |
| `DEVIATIONS.md:82` | "kernel is now a default feature" (implying all crates) | Rewritten: default in consensus and node, not in bin/bitcoin-rs |
| `DEVIATIONS.md:92` | "Default ON across consensus, node, and binary crates" | Rewritten: Default ON in consensus and node; Default OFF in bin/bitcoin-rs; #166 flip blocked |
| `DEVIATIONS.md:94` | "Default builds link `bitcoinkernel`" | Rewritten: `cargo build -p bitcoin-rs` does not link bitcoinkernel; `--features kernel` does |
| `DEVIATIONS.md:99` | "G3 is exercised on the default build" | Rewritten: G3 is exercised on the kernel-parity CI lane with `--features kernel` |
| `docs/benchmarks/end-to-end-sync.md:3` | "became the default production consensus engine across bitcoin-rs-consensus, bitcoin-rs-node, and bitcoin-rs" | Rewritten: default in consensus and node; binary later dropped kernel from defaults |
| `docs/benchmarks/end-to-end-sync.md:5` | "Default builds now require system dependencies" | Rewritten: builds with kernel require system dependencies |
| `Cargo.toml:64-65` | "bitcoinkernel is now the production default verifier" | Rewritten: bitcoinkernel is the production consensus engine; kernel defaults ON in consensus/node but OFF in bin/bitcoin-rs; #166 flip blocked |
| `crates/consensus/src/lib.rs:3-8` | "The `kernel` feature is the production default" (implying all crates) + "portable path" without mentioning stub limitation | Rewritten: kernel is default in this crate and node but not binary; portable path's non-Taproot arm is a stub (see #166) |

## Ready-to-post issue comment for #166

```markdown
## #166 kernel flip — blocked by portable interpreter capability gap

### What was attempted

The flip was scoped to make `libbitcoinkernel` opt-in across all crates by changing `crates/consensus` `default = ["kernel"]` → `default = []` and `crates/node` `default = ["fjall", "kernel", "zmq"]` → `default = ["fjall", "zmq"]`, based on two proven gates:

- **G03 differential parity** (correctness): 15 mainnet blocks parsed through both engines with txid equality, 6 script fixtures × mutations with kernel-vs-interpreter verdict parity, and 121 tx_valid + 84 tx_invalid Core consensus vectors through the kernel with verdict equality. All pass under `--features kernel`.
- **PERF-V5 apply-path measurement** (performance): native median 15.747 ms vs kernel baseline 36.136 ms (2.29x), both gate conditions passing.

### Why the flip is blocked

The 2.29x performance ratio is a **capability gap**, not a speedup. The PERF-V5 corpus spends bare `OP_TRUE` outputs (`push_int(1)` as `script_pubkey`), so neither arm verifies a signature. The number measures apply-path overhead (parse, prevout resolution, state plumbing) on trivially satisfiable scripts.

The portable Rust interpreter (`crates/script/src/interpreter.rs`) cannot validate ordinary spends:

- `verify_non_taproot_portable` accepts **only** `script_pubkey == [0x51]` (`OP_TRUE`) with empty `script_sig` and `witness`. Every other non-Taproot spend returns `Err`.
- Only **Taproot key-path** is implemented in full (`verify_taproot_keypath`).
- **Taproot script-path**, **Legacy** (P2PKH, P2SH, bare multisig), and **SegWit v0** (P2WPKH, P2WSH) are not verified.
- `crates/script` has **no opcode interpreter** — 1,406 lines across `src/`, zero opcode dispatch. `script.rs` lexes bytes into instructions but no file evaluates them against a stack.

`CONCEPTS.md` already records the consequence: "a mainnet sync stops early on the first real spend."

Flipping `kernel` to opt-in today would ship a node that cannot validate mainnet in more build configurations.

### What was proven

- **G03 differential parity** passes under `--features kernel`: block-parse parity (15 blocks, zero txid mismatches), script-verdict parity (6 fixtures × mutations, 3/3 tests), vector oracle parity (66/66 tx_valid accepted, 84/84 tx_invalid rejected), with RED/GREEN non-vacuity proofs.
- **Apply-path overhead** measured: native 15.747 ms vs kernel 36.136 ms (2.29x) on identical `OP_TRUE` corpus. Both arithmetic gates pass. The number is real but scoped to apply-path overhead, not validation cost.

### What remains

A portable Rust opcode interpreter covering:

1. **Legacy script execution**: P2PKH, P2SH, bare multisig with full opcode dispatch (OP_DUP, OP_CHECKSIG, OP_CHECKMULTISIG, OP_EQUAL, OP_EQUALVERIFY, OP_HASH160, etc.).
2. **SegWit v0**: P2WPKH and P2WSH with BIP143 sighash digest.
3. **Taproot script-path**: BIP342 execution with BIP341 sighash, annex handling, and OP_CHECKSIGADD.
4. **All sighash variants**: Legacy, SegWit v0 (BIP143), and Taproot (BIP341) including SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY, and SIGHASH_DEFAULT.

Until this interpreter exists and passes differential parity against the kernel over real mainnet spends, the `kernel` feature must remain the default in `crates/consensus` and `crates/node`.

### Current state

No manifest defaults were changed. `bin/bitcoin-rs` already excludes `bitcoinkernel` from its default graph (`cargo tree -p bitcoin-rs` returns 0 `bitcoinkernel` lines; `--features kernel` returns 2). Prose across README.md, docs/getting-started.md, CONCEPTS.md, DEVIATIONS.md, and the workspace Cargo.toml was corrected to accurately describe the portable path's limitations and the kernel's role as the production consensus engine.
```
