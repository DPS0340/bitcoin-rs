# Kernel apply-path baseline

This baseline controls the native-validation performance gate for issue #166.

## Configuration

- Git commit: `930893170cd044a96e1e4006153e0a1bef780647`
- Command: `cargo bench -p bitcoin-rs-node --bench sync_pipeline --no-default-features --features fjall,kernel -- sync_pipeline_apply_spend_heavy_proxy`
- Host: Intel Xeon Gold 6138, Linux x86-64
- Storage backend: fjall
- Transaction index: disabled
- Criterion samples per run: 100
- Independent runs: 3
- Free-space reserve: 100 GB; free space remained above 2.38 TB

The controlling corpus is generated in-process by `spend_heavy_proxy_blocks()`. It contains 117 regtest blocks: 100 blocks establish coinbase maturity, then 16 blocks each exercise 64 `OP_TRUE` spends. The timed operation applies the full corpus to a fresh `NodeState`. Setup remains outside the Criterion timed closure.

## Results

| Run | Criterion interval | Median estimate |
|---:|---:|---:|
| 1 | 34.390-35.993 ms | 35.182 ms |
| 2 | 36.221-37.930 ms | 37.072 ms |
| 3 | 35.399-36.895 ms | 36.136 ms |

Median of run medians: **36.136 ms**.

Sample standard deviation across run medians: **0.945 ms**, or **2.62%** of the median. This is below the 20% noise ceiling.

Criterion did not emit p95, p99, or maximum estimates for this benchmark. They are not used by the gate. The native arm must use the same command, source corpus, sample count, backend, and host, with only the feature set changed from `fjall,kernel` to `fjall`. It passes only when its median is lower and `native_median * 1.05 <= 36.136 ms`.
