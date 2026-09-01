# Goals

- Remove stale PR #227 references to retired G14 artifact/reporting machinery.
- Describe the retained production-path benchmark contracts without implying that
  deleted campaign executables are still supported.
- Remove the obsolete benchmark-cleanup task bookkeeping while retaining this
  task's required local goals and verification record.
- Preserve the repository's current formatting, metadata, and targeted test
  contracts.
- Keep the retained node benchmark documentation clean under
  `clippy::doc_markdown`.
- Retain only production-path benchmark contracts: node sync/apply, reduced UTXO
  commits, end-to-end mempool admission, current Merkle dispatch, and the
  real-file index resolver.
- Remove RPC, storage, mining, spentby, codec, and CoinStats experimental
  benchmark targets and their stale Cargo/CI wiring.
