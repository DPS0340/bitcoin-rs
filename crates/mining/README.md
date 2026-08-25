# bitcoin-rs-mining

Block-template construction: coinbase assembly, transaction selection, and BIP22/23
block-template serialization.

`build_coinbase_template` assembles the coinbase transaction from a
`CoinbaseTemplateConfig`, drawing on `block_subsidy` for the emission schedule and
`witness_commitment_script` for the segwit witness commitment; failures surface as
`MiningError`. `MiningPolicy` (module `policy`) is the transaction-selection policy
that decides which mempool transactions a template carries — the mempool exposes its
fee-rate cohorts to template builders for exactly this. The `template` module
serializes the assembled result into a `BlockTemplate` of `TemplateTransaction`s,
parameterized by `BlockTemplateParams`, in the BIP22/23 block-template shape.

## Features
- `rocksdb`: forwarding marker for the rocksdb storage backend; gates no code in
  this crate.
- `fjall`: forwarding marker for the fjall storage backend; gates no code in this
  crate.
- `redb`: forwarding marker for the redb storage backend; gates no code in this
  crate.
- `mdbx`: forwarding marker for the mdbx storage backend; gates no code in this
  crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
