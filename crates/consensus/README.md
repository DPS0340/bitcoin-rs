# bitcoin-rs-consensus

Owns consensus validation: transaction and block rule checks for every active soft fork,
with the `kernel` feature (the production default) routing script verification through
bitcoinkernel — Bitcoin Core's native consensus engine — and a portable Rust path
retained for differential tests and builds without a native backend.

Rule checks live in small per-subject modules (`bip9`, `bip30`, `bip34`, `bip65`,
`bip66`, `bip68`, `bip112`, `bip113`, `bip141`, `bip143`, `bip341`, `bip342`), surfaced
through the `verify_transaction` family (with median-time-past and borrowed variants),
`is_final_tx`, and the `verify_block_rules` family including Merkle-root verification.
`kernel::KernelBlock` parses a serialized block exactly once with
`bitcoinkernel::Block::new`, yielding the txids and borrowed transaction objects that
script preparation reuses, and `kernel::KernelContext::verify_tx` verifies a
transaction's inputs through bitcoinkernel over any `UtxoView`. BIP9 activation is
`compute_state`
over a `DeploymentContext` with `DeploymentParams`. Consensus bounds are exported as
`MAX_SCRIPT_SIZE`, `MAX_MONEY`, and `MAX_BLOCK_SIGOPS_COST`; failures are `ConsensusError`
variants.

## Features
- `kernel` (default): routes script verification through
  [bitcoinkernel](../../CONCEPTS.md#bitcoinkernel)
- `checksig-census`: enables the `census_checkpoint` module, the non-terminal CHECKSIG
  census checkpoint ABI wrapper; implies `kernel`
- `rocksdb`, `fjall`, `redb`: empty in this crate, accepted so workspace-wide feature
  selection does not fail here

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
