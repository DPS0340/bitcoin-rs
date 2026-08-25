# bitcoin-rs-wallet

Watch-only wallet primitives: public output descriptors, address watching, coin selection, unsigned-PSBT construction, BIP125 fee bumping, and finalization of PSBTs returned by external signers — with no private-key material exposed, accepted, stored, derived, or signed with anywhere in the public API.

`Descriptor::parse` reads a supported public descriptor form (public keys only, with `BIP32Derivation` origin metadata) and `Descriptor::derive_address` derives its receive addresses; a `Watcher` indexes descriptors, exposes generic script-index scan prefixes, and caches outpoints seen per address. Spending starts with `select_coins`, which funds a `Target` from `Candidate` inputs under a `SelectStrategy` (branch-and-bound, knapsack, or waste-metric) and returns a `Selection`; `PsbtBuilder` then builds the unsigned PSBT from `PrevUtxo` funding inputs, an `ExternalSigner` signs it elsewhere, and `finalize_signed` verifies the signatures and finalizes it into a `Transaction`. Replacement is covered by the fee-bump helpers — `FeeBumpPlan`, `bump_psbt`, and `bump_psbt_with_rate_sat_per_kvb` — which refuse transactions that do not opt in to BIP125 replacement. Everything reports through `WalletError`.

## Features

- `rocksdb`, `fjall`, `redb`, `mdbx`: forward the storage-backend selection into the `storage` crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
