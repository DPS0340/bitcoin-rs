# Goals

- Remove benchmark-only listener no-op cases that do not represent a supported
  production configuration.
- Remove duplicate UTXO benchmark setup/build and shard-distribution reporting
  paths while retaining production-shaped commit and lookup coverage.
- Preserve active `kernel_verify_spike` and `CoinStatsListener` consumers.
- Keep the workspace formatted and ensure Cargo metadata still exposes the
  intended benchmark targets.
