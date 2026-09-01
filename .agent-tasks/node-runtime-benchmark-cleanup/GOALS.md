# Goals

- Remove benchmark-only listener no-op cases that do not represent a supported
  production configuration.
- Remove duplicate UTXO benchmark setup/build and shard-distribution reporting
  paths while retaining production-shaped commit and lookup coverage.
- Remove completed G14, benchmark-campaign, CHECKSIG-census, corpus, and memory
  attribution executables rather than preserving historical campaigns.
- Preserve active `CoinStatsListener` coverage while reducing it to a small
  production-shaped performance contract.
- Remove historical `before_*` / `after_*` benchmark arms when the comparison
  exists only to preserve an obsolete implementation.
- Retain only the canonical node apply shapes that protect current runtime
  throughput.
- Preserve correctness fuzz targets; remove none unless they consume a retired
  benchmark or replay format.
- Keep the workspace formatted and ensure Cargo metadata still exposes the
  intended benchmark targets.
