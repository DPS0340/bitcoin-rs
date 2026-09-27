- `kernel`: compiles bitcoinkernel support in (`bitcoin-rs-consensus/kernel`).
  Selection is the runtime `validation.engine` setting (`native` by default);
  the feature alone never routes consensus verification to the kernel.
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the production listener itself is controlled by `metrics_bind`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
