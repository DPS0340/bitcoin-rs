# Ultrareview log, 2026-05-19

> Status: historical record, moved out of `PLAN.md`. Dated review notes, critic
> findings, and dependency-audit rationale from 2026-05-19. Every accepted change
> already exists in the live tech-stack table and the crate implementations.

## Ultrareview Log (oracles + web research applied)

Recorded so subsequent reviewers can see what changed during the original plan's external review and why. Findings from the adversarial critic pass (`task: critic`) and four parallel web-research probes were folded back into [`PLAN.md`](../../PLAN.md).

### CRITICAL — fixed

1. **Self-referential `ShardInner` was Undefined Behavior on move.** The original sketch stored `Bump` + `HashTable<ArenaRef<'static>>` in one struct via `mem::transmute` to erase the lifetime. `[Shard; 256]` array initialization and `CachePadded` wrapping both move the struct after pointers are taken, dangling them. **Fix:** wrapped in `self_cell!` with `Box<bumpalo::Bump>` as the owner so the arena address is pin-stable; added `self_cell >=1.2` to workspace deps.
2. **Porting consensus from gocoin was a chain-split risk.** Original plan implemented PoW, sigops, merkle, script verification independently. **Fix:** `bitcoinkernel = ">=0.2"` is now a non-optional dependency; our Rust validator runs alongside and panics on any kernel disagreement. A `pure-rust-validation` feature is deferred until 12 months of clean mainnet parity.

### HIGH — fixed

3. **`parking_lot::Mutex` per shard would have stalled Electrum readers.** Electrum's `scripthash.get_history` does random-access reads against the UTXO map concurrent with consensus commits; under a `Mutex` shard, a block-commit holds every reader off for the entire commit window. **Fix:** restored `parking_lot::RwLock<ShardCell>`; block commits batch one write-lock per shard per block (not per UTXO op), so writer starvation is still bounded.
4. **Gocoin `UTXO.db` interop claim was a serialization minefield.** Go and Rust integer encoding, struct padding, varint shapes, and endianness assumptions do not match for free. **Fix:** snapshot uses our **own** format (`zerocopy`-backed, explicit LE, magic + version + muhash trailer); the gocoin import goal is explicitly out of scope. The ABORT / HURRY-UP channel pattern from gocoin is still ported because it is format-agnostic.

### MEDIUM — fixed

5. **Mainnet-diff verification did not exercise adversarial consensus boundaries.** Mainnet never replays CVE-2018-17144 (duplicate inputs), zero-value outputs, or many script edge cases. **Fix:** G4 vendors Core's `tx_valid.json`, `tx_invalid.json`, `script_tests.json`, `sighash.json`; G3 is the per-block kernel parity gate during IBD.

### Dependency spec errors corrected via web research

| Original claim | Actual fact | Source |
| --- | --- | --- |
| `sha2 >=0.10` with `features = ["asm"]` would always work | `sha2 0.11` **removed** the `asm` cargo feature; assembly is now picked automatically via stable inline asm | https://github.com/RustCrypto/hashes/blob/master/sha2/CHANGELOG.md |
| `bitcoin_hashes` feature is `sha2-asm` | Current workspace uses `bitcoin_hashes >=0.14.100, <0.15` with `std`; no `asm` feature is exposed in the active manifest line | Cargo.toml |
| `hashbrown` raw-entry feature is needed for `HashTable` | `HashTable` is the stable replacement for the experimental `raw` API; raw API is being phased out | https://docs.rs/crate/hashbrown/latest/source/CHANGELOG.md |
| `rustreexo >=0.3` exposes `Pollard`/`MemForest` | Current stable is `0.7.x`; older 0.3 line predates the three-accumulator public API | https://docs.rs/rustreexo |

### Dependency audit 2026-05-19 — additions, swaps, version floor bumps

Triggered by user feedback: *"RocksDB is also previous generation. Use better ones. I'll try them all first and put in what benches well."* All crate decisions below were re-verified against crates.io / GitHub release pages on 2026-05-19. The full per-area audit lives in `agent://5-ModernKvAudit` + sibling agents and is summarized here.

**Storage backend matrix expanded from 3 → 4.**

| Backend | Floor | Production users | Why added/kept | Source |
| --- | --- | --- | --- | --- |
| `rust-rocksdb` | `>=0.49` | Bitcoin Core, electrs, many indexers | Explicit production backend; zaidoon1 fork actively maintained (0.49.1 2026-05-18) | https://github.com/zaidoon1/rust-rocksdb |
| `signet-libmdbx` | `>=0.8` | **Reth (Paradigm's Rust Ethereum execution client), Erigon, Silkworm, Akula** — all use libmdbx as primary blockchain storage at mainnet scale (∼1.7 TiB) | Memory-mapped CoW B+tree, wait-free readers, no WAL, deterministic crash recovery | https://crates.io/crates/signet-libmdbx · https://github.com/init4tech/mdbx · https://reth.rs/ |
| `fjall` | `>=3.1` | Growing embedded use (axum/actix services) | Default backend; pure-Rust LSM with native column families + `WriteBatch` + serializable txns | https://github.com/fjall-rs/fjall |
| `redb` | `>=4.1` | electrs and other indexers | Pure-Rust single-file CoW B+tree with typed `TableDefinition` | https://github.com/cberner/redb |

**Rejected storage contenders (with primary-source rationale):**
- **Speedb (RocksDB-compatible fork)** — promising C++ perf (Paired Bloom Filter, 30–50 % write throughput claims per docs.speedb.io) but the Rust binding (`rust-speedb`) has had no commits in >2 years; reject until a maintained binding exists.
- **sled 1.0.0-alpha** — community consensus is "beta forever"; storage rewrite has moved to `komora/marble`; do not use.
- **canopydb / persy / surrealkv / marble / sanakirja** — all too early or too niche; no blockchain-scale production proof.
- **heed (LMDB wrapper)** — viable for read-heavy secondary indexes but adds a C dependency and single-writer limitation already covered by MDBX; not a fourth backend.

**Major dep-stack version floor bumps (every entry's latest stable on crates.io as of 2026-05-19):**

| Crate | Was | Now | Why |
| --- | --- | --- | --- |
| `mimalloc` | `>=0.1` | `>=0.1.50` | 0.1.50 (2026-04-22) latest |
| `hashbrown` | `>=0.15` | `>=0.17` | 0.17.1 (2026-05-09) latest; MSRV 1.95 matches; `HashTable` is the stable raw-insertion API |
| `bumpalo` | `>=3.16` | `>=3.20` | 3.20.2 (2026-02-19) latest |
| `self_cell` | `>=1.2` | `>=1.2.2` | 1.2.2 (2025-12-30) latest |
| `parking_lot` | `>=0.12` | `>=0.13` | 0.13.0 (2026-03) latest |
| `arc_swap` | `>=1.7` | `>=1.9` | 1.9.1 (2026-04-04) latest |
| `crossbeam-channel` | `>=0.5` | `>=0.5.15` | 0.5.15 (2025-04-08) latest |
| `rayon` | `>=1.10` | `>=1.12` | 1.12.0 (2026-04-14) latest |
| `foldhash` | `>=0.1` | `>=0.2` | 0.2.0 (2025-08-23) latest |
| `tinyvec` | `>=1.8` | `>=1.11` | 1.11.0 (2026-03-14) latest |
| `smallvec` | `>=1.13` | `>=1.15` | 1.15.1 (2025-06-06) latest |
| `compact_str` | `>=0.8` | `>=0.9` | 0.9.0 (2025-02-25) latest |
| `bytemuck` | `>=1.18` | `>=1.25` | 1.25.0 (2026-01-31) latest |
| `zerocopy` | `>=0.7` | `>=0.8` | 0.8 is a trait redesign (`TryFromBytes`/`IntoBytes`/`KnownLayout`); migrate now |
| `secp256k1` | `>=0.30` | `>=0.31` | 0.31 stable (batch Schnorr verify); 0.32 is still beta |
| `bitcoinkernel` | `>=0.1` | `>=0.2, <0.3` | Corrected to match the active workspace manifest and kernel parity gate. |
| `rustreexo` | `>=0.7` | `>=0.5` | Corrected: actual latest stable is 0.5.0; 0.7 does not exist on crates.io |
| `miniscript` | `>=12` | `>=13` | 13.0.0 (2025-10-28) latest stable |
| `thiserror` | `>=1.0` | `>=2.0` | 2.0.18 (2026-01-18) latest |
| `clap` | `>=4.5` | `>=4.6` | 4.6.1 (2026-04-15) latest |
| `signal-hook` | `>=0.3` | `>=0.4` | 0.4.4 (2026-04-04) latest |
| `proptest` | `>=1.5` | `>=1.11` | 1.11.0 (2026-03-24) latest |
| `criterion` | `>=0.5` | `>=0.8` | 0.8.2 (2026-02-04) latest |
| `fjall` | `>=2.4` | `>=3.1` | 3.1.4 (2026-04-14) latest — disk-format change vs 2.x |
| `redb` | `>=2.2` | `>=4.1` | 4.1.0 (2026-04-19) latest |
| `rust-rocksdb` | `>=0.36` | `>=0.49` | 0.49.1 (2026-05-18) latest |
| `metrics-exporter-prometheus` | `>=0.16` | `>=0.18` | 0.18.3 (2026-04-30) latest |
| `tracing-subscriber` | `>=0.3` | `>=0.3.23` | 0.3.23 (2026-03-13) latest |
| `metrics` | `>=0.24` | `>=0.24.6` | 0.24.6 (2026-05-13) latest |

**New crates added to the stack:**

| Crate | Floor | Role | Source |
| --- | --- | --- | --- |
| `signet-libmdbx` | `>=0.8` | 4th storage backend (MDBX) | crates.io/signet-libmdbx |
| `bitcoin_slices` | `>=0.11` | Zero-alloc block visitor used by `crates/index` (the real crate name behind electrs's `bsl::` namespace) | crates.io/bitcoin_slices |
| `bdk_coin_select` | `>=0.4` | BnB + knapsack + waste-metric coin selection for `crates/wallet` | crates.io/bdk_coin_select |
| `sonic-rs` | `>=0.5` | SIMD JSON parser (4-5× `serde_json` on RPC payloads) for `crates/rpc` + `crates/electrum` hot path | crates.io/sonic-rs · github.com/cloudwego/sonic-rs |
| `rustls` + `rustls-pki-types` | `>=0.23` / `>=1.14` | Electrum TLS listener; was implicit, now explicit | crates.io/rustls |
| `proptest-derive` | `>=0.8` | `#[derive(Arbitrary)]` for property tests | crates.io/proptest-derive |
| `portable-atomic` | `>=1.13` | Optional 128-bit atomics for future lock-free counters | crates.io/portable-atomic |
| `lz4_flex` | `>=0.11` | Pure-Rust LZ4 for snapshot + custom-format compression | crates.io/lz4_flex |
| `rapidhash` | `>=4.1` | Dev-dep only; future G14 comparison candidate | crates.io/rapidhash |
| `payjoin` | `>=1.0` | Optional feature `payjoin` (BIP78/77); default off | crates.io/payjoin |

**Rejected crate-stack alternatives (kept the current choice with rationale):**
- **Channels:** `flume` and `kanal` are fast but lack crossbeam-channel's `Select` macro — non-negotiable for the single-threaded event loop.
- **Allocators:** `snmalloc-rs` and `tikv-jemallocator` remain unadjudicated alternates; they are not current workspace dependencies and require a dedicated G14 alloc-comparison follow-up before any default change.
- **Thread pool:** `chili` is faster on micro-tasks but `rayon`'s work-stealing maturity wins for block-parallel script verify.
- **Self-ref pin:** `ouroboros` is heavier and exposes Pin; `self_cell` avoids proc-macro overhead.
- **Coin selection:** porting Core's C++ `coinselection.cpp` was the original plan; `bdk_coin_select` supersedes it (audited, BIP-aligned, Rust-native).
- **JSON-RPC framework:** every modern framework (`jsonrpsee`, `tower-jsonrpc`) requires tokio; `jsonrpc-core` is deprecated. Hand-rolled minimal sync HTTP/1.1 avoids async runtime dependencies.
- **Compact string:** `smartstring` is abandoned (2022); `flexstr` is interesting but `compact_str` is the established choice.
- **Stale crates rejected outright:** `arrayvec` (frozen since 2024-08), `base58` (frozen 2021), `usync` (dead 2022), `typed-arena` (2023), `rpmalloc-rs` (abandoned), `Speedb rust binding` (2 years stale).

**Architectural impact:** Goal, Architecture, Workspace Layout, Tech Stack table, Verification Gate G7, Task 4 (storage), Task 8 (index), Task 14 (wallet), Task 16 (rpc), Task 17 (electrum) all changed in [`PLAN.md`](../../PLAN.md) after this audit.

### Findings deliberately NOT actioned (with rationale)

- Critic flagged scope creep around `crates/{utreexo,rpc,electrum,mempool}` as MVP-bloat. Plan keeps them as required tasks because the **stated user goal** is "natively integrate UTXO based on electrs", which requires the Electrum surface and a mempool to ship; the user later explicitly extended scope to include wallet + mining + pruning, confirming the non-MVP direction.
- Critic flagged dependency-velocity risk on `bitcoin >=0.32` and `rust-rocksdb >=0.36`. Floors are kept loose by design — the workspace's `cargo update` + lockfile is the actual pin; floors only protect against trivial regressions.
- Critic suggested deferring fjall/redb behind features as "noise". User explicitly chose all three benchmarked. Backends remain feature-gated but all three ship and are gated by G7.
