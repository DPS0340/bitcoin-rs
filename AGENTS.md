# AGENTS.md

CONCEPTS.md is the repository common vocabulary, utilize and manipulate it when you need it.

## Consensus

- Consensus authority is `libbitcoinkernel`. The Rust `Interpreter`
  (`--no-default-features`) is a differential-testing surface, never a
  production validation path.
- Parse each block once via `KernelBlock`; downstream borrows that parse (txids,
  `TransactionRef`), never re-serializes.
- Assume-valid skips script checks only after the active header chain proves
  the pinned anchor hash; sub-anchor or diverged chains verify fully.
- Internal `Network` is the consensus selector only. `--network` (incl.
  `drynet4`) changes P2P identity and bootstrap atomically; `drynet4` keeps
  mainnet consensus.
- Core RPC parity is value parity, not JSON text parity.
- No wallet, no private keys, no signing/funding RPCs.

## Chain state

- All chain mutation (sync, reorg, consensus-affecting RPC) goes through
  `ChainControl` under the chain-transition guard; nothing else touches the
  block tree or UTXO set. Whole-chainstate reads (`scantxoutset`) share that
  guard; multi-query responses (Esplora) fail with 503 rather than compose
  across an applied-tip change.
- Disconnect marker is armed before the first UTXO mutation and cleared only
  by the checkpoint that publishes the rolled-back state; startup refuses
  `InFlight`/`RolledBack`; a `Fatal` disconnect shuts the process down. On
  reorg, `pubsequence` emits `D` events tip-first before `C`.
- Undo records are keyed by height and block hash and survive disconnects.
- Derived indexes (`TxIndex`, filters) are outside the authoritative
  transaction; queries gate on their capability watermarks and refuse partial
  answers. Rows sharing a key across same-height blocks are checked against the
  identity-bearing header row before deletion.
- Window script batching: the front half of apply runs once per block; a
  `BlockValidationProof` is single-use, bypasses only the transaction-validation
  slot, and commit re-derives every bound field, discarding on mismatch.
  `commit_apply` never re-enters.

## Storage

- Breaking on-disk change: increment the single `CURRENT_SCHEMA` epoch, one
  reader, one writer, no converter or legacy fallback; the node never deletes
  user data, it demands a resync. A UTXO-admission semantics change is a
  snapshot codec version change.
- `CURRENT` is the only checkpoint commit point; body bytes are durable before
  any index row pointing at them is published.
- Weaker durability (`write_deferred`) is opt-in at the exact call site; never
  weaken a backend-wide write primitive.
- One logical record has exactly one byte string: minimal varints, narrowest
  directory width, compact/escape amount forms as exact complements.

## Engineering

- Clean cutover: when an interface, RPC schema, or data layout changes, delete
  the old path in the same change-set. No shims, aliases, transitional flags.
- MSRV bumps require a forced dependency floor or consensus/performance need
  and update `rust-toolchain.toml`, `Cargo.toml`, and the policy doc together;
  member-crate deps live in `[workspace.dependencies]`.
- Fan-out is decided by measured per-item cost, not loop shape: sub-µs items
  (UTXO lookups) get no rayon; the global rayon pool stays capped at
  `GLOBAL_RAYON_THREADS`. Windows are count-and-byte bounded.
- Stall detection uses window-blocked detection, never `applied_tip+1`
  stagnation, and does not blame a peer when our own backpressure binds.
- Benchmarks: production-matched binary (mimalloc, same features), report
  CPU-seconds alongside wall, both arms in one run, at-scale window; when
  harnesses disagree publish the conservative number. Retained benches exercise
  the shipped path on a product-shaped workload only.
