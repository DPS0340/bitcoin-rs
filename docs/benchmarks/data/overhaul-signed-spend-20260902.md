# Signed-spend proxy measurement (PERF-V6)

This measurement controls the signed-spend performance gate for issue #166. Unlike the prior `overhaul-native-apply-20260902.md` and `overhaul-kernel-baseline-20260829.md`, which measured trivially-satisfiable `OP_TRUE` spends, this corpus carries real ECDSA signatures verified by the script engine.

## Configuration

- Git commit: `a1c0e18` (detached worktree `~/.omp/wt/perf-measure`)
- Command (native): `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall -- signed_spend`
- Command (kernel): `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall,kernel -- signed_spend`
- Host: Intel Xeon Gold 6138 (80 cores), Linux x86-64
- Storage backend: fjall
- Transaction index: disabled
- Criterion samples per run: 100
- Independent runs: 2 per arm
- Env: `env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR TMPDIR=$PWD/target/tmp`

## Corpus

`signed_spend_proxy_blocks()` in `crates/node/benches/sync_pipeline.rs`. Same 117-block skeleton as `spend_heavy_proxy_blocks()`: heights 1..100 are fanout coinbase blocks (64 outputs each), heights 101..116 are spend blocks consuming the coinbase from 100 blocks back. Coinbase maturity 100, height ceiling < 150, 64-output fanout, 16 spend blocks.

The spend classes are:
- P2PKH (legacy ECDSA, `SIGHASH_ALL`): outputs 0..22 per coinbase, 22 spends per spend block.
- P2WPKH (BIP143 segwit v0 ECDSA): outputs 22..44 per coinbase, 22 spends per spend block.
- P2WSH 2-of-3 multisig (BIP143): outputs 44..64 per coinbase, 20 spends per spend block.

Signatures are produced with rust-bitcoin 0.32 `SighashCache` + secp256k1 0.29 as an independent oracle, then consensus-serialized and decoded into native `Tx` (the `to_native` pattern from `crates/script/tests/proptest.rs`). Witness-bearing blocks carry a BIP141 witness commitment output on the coinbase with a 32-byte reserved witness element.

Criterion 0.8 cannot report p95/p99/max (its stats module is private). A manual timed sample loop inside `iter_custom` collects per-sweep durations and prints the percentile table after the Criterion run. The Criterion median is retained for comparability with the existing docs.

## Results

### Native arm (`--features fjall`)

| Run | Criterion median (ms) | Manual p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---:|---:|---:|---:|---:|---:|
| 1 | 588.24 | 485.6 | 531.9 | 550.4 | 834.4 |
| 2 | 819.31 | 638.5 | 710.4 | 748.4 | 777.9 |

### Kernel arm (`--features fjall,kernel`)

| Run | Criterion median (ms) | Manual p50 (ms) | p95 (ms) | p99 (ms) | max (ms) |
|---:|---:|---:|---:|---:|---:|
| 1 | 532.21 | 244.4 | 533.2 | 563.0 | 595.4 |
| 2 | 616.60 | 487.2 | 540.6 | 548.2 | 552.8 |

### Comparison

| Metric | Native (run 1) | Kernel (run 1) | Native (run 2) | Kernel (run 2) |
|---|---:|---:|---:|---:|
| Criterion median | 588.24 ms | 532.21 ms | 819.31 ms | 616.60 ms |
| Manual p50 | 485.6 ms | 244.4 ms | 638.5 ms | 487.2 ms |

Native median > kernel median on both runs. **Native does NOT win.** The native portable interpreter is slower than bitcoinkernel on this signed-spend corpus.

## Verdict

**Gate fails.** The native portable interpreter's median is higher than the kernel median on the signed-spend corpus. This is consistent with the prior `OP_TRUE` measurement being vacuous — the real signature verification cost exposes the native interpreter as slower than Core's engine. The #166 default flip remains blocked.
