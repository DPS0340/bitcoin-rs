# Concepts

Shared domain vocabulary for this project: entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound processes learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Node interfaces

### REST gateway
The optional, unauthenticated Bitcoin Core-compatible HTTP surface served on
the existing JSON-RPC listener. It is enabled with `rest=1`; JSON-RPC requests
on the same listener retain their configured authentication.

## Initial Block Download

### Initial Block Download (IBD)
The one-time bulk process of downloading and fully validating the chain from the start point (genesis, or a trusted snapshot) up to the network's current best tip; run when a node first starts or has fallen far behind normal operation. Its dominant cost at high block heights is download bandwidth, not local validation.

### Apply frontier
The greatest height up to which every block has been validated and committed to the UTXO set in one unbroken run — the contiguous tip of *applied* state, distinct from the header tip (how far valid headers are known) and from blocks already downloaded but not yet applied because an earlier block is still missing.

The frontier advances only over a contiguous run: a single missing or late block at the frontier stalls all apply progress even when many later blocks are already in hand. This is why a slow peer assigned the frontier block can freeze sync.

### Download window
The bounded set of blocks permitted to be in flight — requested from peers but not yet received — at any moment during sync. It is capped jointly by a block count and an estimated-bytes budget and is refilled as blocks arrive.

### Staller
A peer that holds up the apply frontier by having been assigned a frontier block it then fails to deliver promptly.

Stalling detection is the mechanism that identifies the staller and, in the reference (Bitcoin Core) design, disconnects it so another peer can supply the blocking block. Without stalling detection, a staller freezes apply progress until a long fixed timeout elapses.

### assumevalid
A validation mode that skips script-signature verification for blocks at or below a configured trusted height while still performing every other consensus check, used to accelerate IBD without abandoning validation; blocks above the height are fully verified. Mainnet nodes in `bitcoin-rs` default to assume-valid enabled at anchor height 938343.

### Hash-pinned assume-valid anchor
The mainnet consensus checkpoint (height 938343, block `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`) used by default on mainnet to gate historical script verification. The node skips script verification for blocks at or below height 938343 only after validating that the active header chain contains this exact anchor hash. Sub-anchor header tips and diverged chains remain untrusted and trigger full script verification. Passing `--assume-valid-height 0` explicitly requests full verification across all blocks. Custom nonzero heights skip script checks up to that height without hash gating. Non-mainnet networks default to height 0. Replay measurement tools like `mainnet_prefix_replay` retain a default of 0 to ensure full-validation benchmark fidelity.

### Optimized default posture
The standard node operational configuration tuned for mainnet sync: `fjall` storage backend, multi-peer block download active (outbound peer target 8, pending block budget 128, 16 in-flight requests per peer), hash-pinned assume-valid active on mainnet (height 938343), 450 MiB database cache (`dbcache`, matching Bitcoin Core parity), with secondary indexes (`txindex`, `blockfilterindex`), pruning, and `utreexo` stateless validation disabled by default.

### Container deployment posture
The checked-in Docker Compose specialization of the optimized default posture. The image compiles only the production `fjall` storage and `bitcoinkernel` verifier features and runs as an unprivileged user. The BIP300/301 integration Compose publishes P2P on the configured host port, keeps JSON-RPC on the host loopback interface, leaves `txindex` and the optional Electrum service disabled, supplies local-development RPC credential fallbacks that deployments should override, and namespaces node and enforcer data by `BITCOIN_RS_NETWORK` so incompatible P2P networks never reuse runtime state. Shutdown allows up to 5 minutes because the bounded subsystem drain is followed by an unbounded, synchronous full-UTXO clean checkpoint; this is an operational SIGKILL guard, not a checkpoint-duration guarantee.

### Node network selection
The user-facing `BITCOIN_RS_NETWORK`/`--network` selection that atomically supplies consensus rules and P2P bootstrap identity while preserving later, low-level overrides. Standard Bitcoin names use their matching consensus `Network`, message start, and DNS bootstrap. `drynet4` uses mainnet consensus history with message start `eca5d404`, disables Bitcoin DNS seeds, and connects to `drynet4.drivechain.dev:8533`. Compose passes the same selection to bitcoin-rs and the BIP300/301 enforcer and uses it to namespace their data directories. The internal consensus `Network` remains `mainnet` for drynet4.

### Sync regimes (download-bound vs processing-bound)
The two distinct cost regimes any sync measurement must name before its numbers mean anything. **Download-bound:** wall-clock is decided by the network path (peer scheduling, per-peer bandwidth, staller handling) — the regime of live IBD. **Processing-bound:** blocks are already local and wall-clock is decided by validation plus storage commit — the regime of reindex and offline replay. A node can rank differently in the two regimes, so a faster-than-X claim is meaningless without stating which regime was measured and with what validation posture. Within a regime the comparison is only as good as its least-matched input — see *Matched-harness comparison*.

## Consensus validation

### bitcoinkernel
Bitcoin Core's C++ consensus engine (`libbitcoinkernel`), compiled into `bitcoin-rs` as the production consensus default across consensus, node, and binary crates. Beyond script verification it is also the block **parser** on the apply path — see *One-shot kernel block parse*. It validates input scripts across all script classes (legacy, segwit, and Taproot key-path and script-path spends). Default builds require system dependencies (`cmake` and `libboost-dev`). Production transaction and block input-script verification route to bitcoinkernel when default features are enabled, while Rust performs surrounding non-script transaction and block consensus checks; the Rust `Interpreter` remains a separate portable script-verification surface under `--no-default-features`.
### bitcoinconsensus
Removed historical script verification backend. Previously linked as an extracted C library for non-taproot script checks before being deleted in favor of `bitcoinkernel`. The library lacked complete-prevout and Taproot script-path verification capabilities required for current mainnet script validation (exposed by block 938344 during mainnet IBD).

### Difficulty-1 target
The network-independent reference target used by Bitcoin Core's difficulty
calculation: compact nBits `0x1d00ffff`, rather than the selected network's
PoW limit. Confusing the two makes every network report difficulty `1.0` at
its easiest target. See
`docs/solutions/logic-errors/core-float-parity-is-value-parity-not-json-text-parity.md`.

### Float value/text parity
The distinction between equal IEEE-754 values and equal serialized spellings.
Core's UniValue uses `%.16g`, while the live RPC path's sonic-rs serializer
uses shortest-round-trip formatting, so compatibility means preserving the
value and operation order, not forcing JSON text to match. See
`docs/solutions/logic-errors/core-float-parity-is-value-parity-not-json-text-parity.md`.

### Rust interpreter (portable posture)
The pure-Rust script verification path maintained alongside the bitcoinkernel default. Enabled under `--no-default-features` without C++ build dependencies. Its non-Taproot path is a stub that accepts only a bare `OP_TRUE` spend with an empty scriptSig and witness, so it cannot validate ordinary spends either, and it has no Taproot script-path support. What it does verify is the Taproot key path, in full. It is retained for differential testing and lightweight non-production environments; a mainnet sync stops early on the first real spend.

### One-shot kernel block parse
Parsing each block exactly once with `bitcoinkernel::Block::new` (wrapped as `KernelBlock` in `crates/consensus/src/kernel.rs`) and reusing that parse for everything downstream. It supplies three things at once: the **txids** (Core's `CTransaction` hashes itself while deserializing, using the SHA-256 implementation Core selects at runtime — `avx2(8way)` on Skylake-SP), and the **transaction objects** that script preparation borrows via `TransactionRef` instead of re-serializing. It replaced a scalar `compute_txid` pass plus a per-transaction `encode::serialize` → `Transaction::new` round-trip, cutting `script_prepare` from 18.55s to 4.29s and the 0→150k replay from 137.3s to 121.9s. The costing lesson generalizes: **price a replacement by everything it subsumes**, not by the line item that motivated it — costed against parse-and-serialize alone the same change scores +1.54s and looks like a loss.

### Parallel granularity (per-item cost rule)
Whether a fan-out pays is decided by per-item work against dispatch cost, not by how parallelizable the loop looks. Measured both directions on the same apply path: script checks (~100 µs per input) wanted *more* parallelism, and lowering `MIN_PARALLEL_SCRIPT_CHECKS` from 16 to 4 bought 1.15×; UTXO lookups (~500 ns) wanted *none*, and deleting two rayon fan-outs bought 1.07× and 1.11×. Merkle nodes (~2.6 µs) sit in between: Rayon task fan-out over scalar nodes measured neutral-to-worse (SIMD multi-buffer hashing is a different lever because it reduces cost per group rather than changing task granularity). A threshold has an interior optimum in both directions — below 4 the script threshold turns back up, and pool width peaks at 32 then degrades at 64. Always gate on **elapsed**, never on the stage being targeted: parallel prepare makes `script_prepare` 30% faster and the whole run 4% slower by contending with the script-verify pool. See `docs/solutions/performance-issues/processing-bound-sync-performance-evolution.md`.

The AVX2 Merkle result pins the distinction. Reusing prepared txids and hashing eight independent 64-byte parent pairs in SIMD lanes cut the matched fjall replay from 56.517s to 48.020s (1.177×), while scalar-library swaps and Rayon folds had failed. SIMD paid because it reduced the cost of a homogeneous batch without scheduling more tasks. The same candidate passed the RocksDB and redb gates at 1.171× and 1.112×.

### Matched-harness comparison
The requirement that a cross-node benchmark match every input that is not the thing under test — block source, validation posture, CPU pinning, and time of measurement — before any ratio is quoted. Each mismatch found in this repo moved the headline materially: Core's reference was months stale (67s → re-derived 59.6s); bitcoin-rs fetched blocks over REST from a live `bitcoind` while Core read local `blk*.dat`, which cost ~35s of harness *and* contended for CPU (121.9s → 84.6s once `--blocks-file` matched it); and GoCoin skips script verification below its default `LastTrustedBlock` of #940000, so it must be compared either against an assume-valid bitcoin-rs run or with that asymmetry stated. Interleave both nodes back-to-back on an idle host and quote paired medians; comparing your best run against someone else's old run is not a measurement.

The allocator is part of the harness too. At commit `ff2615a`, the same local
0→150,000 replay measured 63.43s / 399.63 CPU-s with the system allocator and
56.16s / 396.50 CPU-s with production-matched mimalloc. The allocator changed
wall scheduling, not total work, and raised peak RSS by 15.8%. A replay control
must therefore match the production allocator and report RSS with both time
axes. See
`docs/solutions/performance/allocator-parity-changes-wall-not-cpu.md`.

The final prepared-txid plus AVX2 Merkle panel follows this rule: three candidate and three Core runs were interleaved on CPU set `0-31`, with a 30-second cooldown, identical local blocks 0→150k, and full validation. The medians were 49.356s versus 64.914s wall and 390.542s versus 481.092s CPU, so bitcoin-rs led by 1.315× wall and 1.232× CPU. All three storage backends reached the same tip and UTXO commitments. See `docs/benchmarks/data/end-to-end-sync/avx2-merkle-custody-v1.json`.

### Script-flag exceptions (BIP16Exception)
The historical blocks Bitcoin Core hardcodes in `consensus.script_flag_exceptions` (chainparams) to be validated under a reduced script-verification flag set, because they contain spends valid under the rules in force at the time but invalid under a later-enforced flag. As of Core v29: mainnet block 170060 (`…ac4f9c22`, the BIP16/P2SH exception) and 692261 (`…e1e395ad`, the Taproot exception); testnet3 block 394; none on testnet4/signet/regtest. The two **P2SH waivers** (170060, 394) are reproduced explicitly by `Network::is_bip16_p2sh_exception` (keyed by block hash, mainnet/testnet3 only); missing them rejects canonical blocks and wedges full-validation sync past the assume-valid height. The **692261 Taproot override** needs no rs exception: Core's override only strips TAPROOT (which Core defaults on for all blocks), and rs already height-gates taproot (`is_taproot_active`, 709632 > 692261) so it never sets TAPROOT there — its computed flags already match Core's effective set. Compare *effective* flag sets, not raw overrides. See `docs/solutions/architecture-patterns/p2sh-flag-must-honor-core-script-flag-exceptions.md`.

### Accepted-connection ownership proof
The check in `scripts/measure-g14-electrum-rss.sh` that the measured PID really owns the Electrum connection being timed, so an RSS figure cannot be attributed to the wrong process. It matches an ESTABLISHED row in `/proc/<pid>/net/tcp` on the exact four-tuple and then intersects that inode with the process fd table; only an inode in both is proof. The subtlety is that the kernel finishes the three-way handshake before the server calls `accept()`, so a connection waiting in the listen backlog is reported ESTABLISHED with **inode 0** — unaccepted, not malformed. Treating inode 0 as an error could only ever produce a false negative, because an inode of 0 is in no fd table and so can never survive the intersection; the parser counts those rows and lets the poll loop retry. See `docs/solutions/logic-errors/established-with-inode-zero-is-unaccepted-not-malformed.md`.

### CI lane parity
The rule that a branch is green only against the commands in `.github/workflows/ci.yml`, never against a local approximation of them. Three differences bite: `-D warnings` on the `clippy` and `kernel-parity` lanes promotes every warning the workspace lint job merely reports (`dead_code`, `needless_borrow`, `doc_markdown`, `needless_collect`, `too_many_lines`); a virtual workspace silently drops `--workspace --features`, so the four-backend and kernel surface is only reached through `-p bitcoin-rs --no-default-features --features "$FULL_NODE_FEATURES"` plus a separate `-p bitcoin-rs-node` pass for its test targets; and `kernel-parity` adds `--include-ignored` on a debug profile. `cargo deny` belongs in the same sweep and is a bug report, not lint noise. See `docs/solutions/best-practices/workspace-clippy-does-not-predict-the-d-warnings-lanes.md`.

### CPU-seconds as a first-class metric
The rule that a throughput change is measured against CPU time as well as wall time, because a many-core idle benchmark host lets wall-clock tuning spend cores for free. Sampling `utime+stime` from `/proc/<pid>/stat` while polling height is enough; no profiler or metrics plumbing is required, and per-thread attribution comes from summing `/proc/<pid>/task/*/stat` by thread name. On the loopback P2P sync to 150k, bitcoin-rs takes 76.3s wall and **318.4s CPU** against Core's 42.5s and **65.0s** — a 1.77× wall gap concealing a 4.9× CPU gap, which becomes wall time on the 4-8 core machines most nodes run on. The excess is broad rather than one hot spot: collapsing `SCRIPT_VERIFY_POOL` to a single thread still burns 230.1s, so rayon spin is a minority of it and no pool width converges. This also puts a caveat on every wall-only sweep in the performance note, `MIN_PARALLEL_SCRIPT_CHECKS` 16→4 most of all, since pushing more blocks through the pool is exactly the shape of change that trades CPU for wall.

The matched local-file processing panel at commit `ff2615a` supersedes the
older processing-bound CPU deficit: production-matched bitcoin-rs measured
56.16s / 396.50 CPU-s against Core 31.0 at 64.74s / 477.82 CPU-s. The loopback
P2P result above remains valid for its network regime; it cannot be carried
into the local replay regime. See
`docs/solutions/performance/allocator-parity-changes-wall-not-cpu.md`.

The final AVX2 panel adds the same proof after the Merkle change: bitcoin-rs beat Core by 1.315× wall and 1.232× CPU while using 1.042× its peak RSS. The CPU result rules out a wall-only win bought by extra parallel work; the kernel batches eight hashes in SIMD lanes inside one task.

### Global rayon pool cap
The process-wide rayon pool is capped at `GLOBAL_RAYON_THREADS` (4) by `cap_global_thread_pool` in `crates/node/src/run.rs`, called at the top of `run`. rayon otherwise sizes that pool at one worker per core, and because it leaves those workers unnamed they inherit the process name — which is why per-thread CPU attribution first blamed the async runtime. The pool runs only short coarse jobs (block txid hashing, shard commits) while `SCRIPT_VERIFY_POOL` separately holds up to 32 threads, so an uncapped global pool oversubscribes a many-core host and its workers spin for work that is not there. Capping it cut a loopback P2P sync to 150k from 75.6s wall / 314.4s CPU to 64.4s / 162.4s across three interleaved pairs — **both axes at once**, so it is not a wall-for-CPU trade. With the `MIN_PARALLEL_SCRIPT_CHECKS` correction stacked on top, that sync finally lands at 62.8s / 90.1s against Core's 45.9s / 67.8s. The width sweep is flat from 2 to 8; the full-verification replay is insensitive at every width because script verification dominates it and runs in its own pool. Contrast `Parallel granularity (per-item cost rule)`, which is about *when* to fan out; this is about *how wide* the shared pool may be.

### Contended-harness tuning artefact
The failure mode where a parallelism constant is tuned while the benchmark harness competes with the node for CPU, so the measured optimum is a property of the contention rather than of the code. In this repo it produced two wrong constants. `MIN_PARALLEL_SCRIPT_CHECKS` was walked down to 4 by a sweep whose harness fetched every block over REST from a second `bitcoind` on the same cores; the inflated serial path made ever-finer fan-out look free and the curve read as monotonic. Re-measured against local block files the ordering **inverts** — 4 becomes the worst point tested on both wall and CPU, and the optimum is 32 (75.5s / 649.6s versus 84.4s / 946.6s). The global rayon pool was the same mistake in a different guise: uncapped, it cost nothing measurable in wall time on an idle many-core host. Two rules follow: never tune a parallelism constant against a harness that shares CPU with the node, because contention changes the shape of the curve and not merely its offset; and never tune one on wall alone, because both bad constants were wall-optimal on the host that chose them. See also `CPU-seconds as a first-class metric` and `Global rayon pool cap`.

### Commit point (multi-store mutation)
The mutation that publishes a multi-store operation: the point after which readers see it as done. It marks where the operation becomes visible, not where it becomes atomic, and everything after it is cleanup. For block disconnect the commit point is the `applied_tip` rollback, which is why it runs last, after index rollback and UTXO undo. Naming it first shows which steps need atomicity. The index rollback is one disk batch. The UTXO set is RAM-resident and becomes durable only at a clean checkpoint. A checkpoint flushes the shared storage backend before it publishes the matching UTXO state. What does not follow is that every step before the commit point is safe to re-enter. The UTXO undo walks shards and can fail after other shards committed, leaving the set partly undone with the tip still describing the block. Retry is ruled out because the commit fires the set's change listener and coinstats is one listener, so a second pass double-counts where the set converges. `DisconnectError` therefore splits `Refused` (nothing touched) from `Fatal` (partly rolled back). An in-flight marker in `UndoData` is armed and flushed before the first mutation. A fatal outcome closes apply admission and triggers the shared process shutdown. Startup then refuses to serve the torn state. See *Disconnect marker phase* and `docs/solutions/architecture-patterns/node-reorg-execution-design.md`.

### Refusing default (trait participation)
A trait method whose default returns success lets an implementation that never opted in be mistaken for one that did. Where a consumer must participate in an invariant, the default must refuse. `IndexerLike::rollback_block` returns `IndexError::UnsupportedRollback` rather than zeroed counts: a silent no-op would let the node advance its tip believing a stale index is consistent, which is the exact failure the method exists to prevent. The eight existing implementations still compile untouched, and only fail if a reorg is genuinely driven through one that cannot handle it.

### Undo record

The per-block inverse of a UTXO commit: the outputs the block spent, with
enough metadata to recreate them, plus the outputs it created. Connection queues
the record before later apply mutations. The clean checkpoint flushes the shared
storage backend before it publishes the matching UTXO state, so the queued
record is not a separate per-block fsync boundary. The key contains height
**and** block hash so an abandoned branch record cannot be replayed against a
different block at the same height. The node retains the record after a
disconnect because flip-flop between competing branches is normal.

### Owed derived state

State that connection writes and disconnection must account for. Naming the
whole set is what turns "disconnect works" into a checkable claim, and the
answers are not uniform, which is why the list is kept rather than summarised.

Handled, in three different ways. `coin_stats` needed an explicit inverse for
its block-level fields only, because the per-coin ones ride the UTXO change
listener and the undo already reverses them. The filter index needed no
rollback, because its rows are hash-addressed like block bodies and stay valid
for a block that left the chain; only its last-tip cache is repointed, and that
cache and the `blocks` RPC pop are best-effort refreshes rather than atomic
inverses. `transactions` needed nothing, because connection never populates it.

`switch_to_branch` (`crates/node/src/reorg.rs`) is the production disconnect
caller. Sync drives it when the header and applied tips diverge. Each attempt
loads all disconnect bodies and the available contiguous connect prefix. The
disconnect preload is $O(\text{disconnect depth})$. A `ChainTransition`
witness then requires the complete authoritative plan to equal the preloaded
plan before mutation starts.

The available prefix becomes one coherent applied-tip checkpoint. If the next
body is absent, `MissingBody` identifies that suffix and sync resumes from the
published tip. A permanent connect failure invalidates the failed header and
its descendants, selects the best valid tip, and purges their bounded staging
and download ownership. An operational failure leaves the branch eligible and
keeps its ownership for retry.

Still open around it: returning a disconnected block's transactions through one
production admission pipeline shared by Electrum, P2P relay, and reorg handling;
and backfilling the filter index after a gap. The `pubsequence` stream publishes
block connect/disconnect notifications, but intentionally does not publish
mempool `A`/`R` events: the current mempool counter and mutation reasons cannot
yet guarantee the enforcer's required contiguous transaction event sequence.
Raw mempool insertion is not reconsideration because it cannot reconstruct fee,
policy, conflict, and ancestry metadata.

### Backfillable derived state

State that is a deterministic projection of the authoritative applied chain and
can own its progress outside block application. The planned #77 proof is
TxIndex: core retains the applied tip, anchored ancestry, and exact block
bodies; a TxIndex worker owns its rows and `(height, hash)` watermark. This is a
boundary and recovery contract, not a generic consumer trait. Filter indexes,
Utreexo, and other consumers must separately prove how they move backward and
what source data they require before adopting it. See
`docs/plans/2026-08-13-issue-77-async-txindex-reconciliation-plan.md`.

### TxIndex watermark

The planned #77 durable statement of exactly which applied-chain block the
TxIndex rows represent: `(height, block_hash)`. Row additions or deletions and
the terminal watermark commit in one TxIndex DB batch. A row count is not a
watermark. TxIndex may durably lead the core checkpoint restored after a crash,
but only because it can identity-check the watermark block body, delete that
block's rows, and atomically retreat to its parent. This consumer-ahead rule is
TxIndex-specific. A watermark above the reconciliation target retreats before
any same-height ancestry comparison. If the watermark's expected header
identity row is absent, the index is inconsistent: rollback must leave both
rows and watermark unchanged and fail the worker rather than treating the
block as already removed.

### Reconciliation attempt target

One captured `applied_tip` used to anchor ancestry reads during a planned
TxIndex reconciliation pass. It prevents a worker from mixing heights from
different live tips, but it does not pin or retain the branch. If its forward
ancestry disappears and core has published a different tip, the worker abandons
the attempt and captures a fresh target. If the same published target cannot be
resolved, or the durable watermark body needed for rollback is missing, that is
a source failure rather than an ordinary retry.

### TxIndex completeness gate

The planned #77 read boundary that prevents asynchronous index lag from being
reported as an authoritative negative. A complete TxIndex query requires a
healthy worker and a committed watermark equal to the captured applied tip,
excludes worker mutation for the logical query, and verifies before returning
that the applied tip did not move. Lag, failure, or concurrent chain movement
returns unavailable (or a bounded retry), not "not found." Rich Electrum
readiness and partial-history policy are separate concerns.

### Coalesced index wake

The planned #77 capacity-one, payload-free notification sent after a successful
runtime `applied_tip` publication. It means only "reconcile again"; it carries
no ordering or recovery truth. Duplicate wakes may coalesce because startup
always reconciles and a worker compares its watermark with a fresh applied tip
before sleeping. It is not a chain event, WAL record, event cursor, or sequence
stream.

### Sequence stream

The Core-compatible `pubsequence` ZMQ stream is a unified block-event stream.
Each event carries the block hash, one label (`C` for connect or `D` for
disconnect), and a topic-local little-endian `u32` sequence counter. Reorg
disconnects are emitted tip-first before connects on the replacement branch.
This implementation deliberately omits mempool `A`/`R` events until the
mempool has per-transaction sequence assignment and explicit removal reasons.

### Chain control

Consensus-affecting RPCs do not mutate the RPC context's block-tree handle
directly. They delegate through the node-owned `ChainControl` boundary so the
same apply-admission and chain-transition locks protect RPC-triggered and
sync-triggered reorganizations. `invalidateblock` marks the named subtree
invalid, republishes the best remaining header tip, and moves applied
chainstate to it through the normal disconnect path. Before changing header
status it previews the replacement tip and loads every body required by the
complete disconnect/connect plan. The same chain-transition witness remains
held from that preflight through header invalidation and branch switching, so
another apply or reorg cannot enter between them; successful disconnects emit
the same `pubsequence` `D` events as an organic reorg.

### Dispatch-bound parallelism

A stage that is parallel in shape but serial in effect because each dispatch is
too small to amortise waking the workers. Script verification on mainnet
0..150_000 is the case: 2,868,199 input checks at a mean 69.4 us each yield only
4.4x on 32 threads. Blocks in the parallel row carry about 114 checks, while
14.6% of all checks fall below `MIN_PARALLEL_SCRIPT_CHECKS` and run serially.
The parallel rows still pay roughly 11s of dispatch across 21,474 fan-outs. The
diagnosis is a scaling sweep, not a profiler: measure the stage at 1, 4 and 32
threads and compare the speedup against the thread count. Coarsening each
dispatch does not fix it and makes it worse, because it throttles the blocks
that were scaling; only issuing fewer, larger dispatches does. See
`docs/solutions/performance/script-batching-needs-a-split-apply-path.md`.

### Window script batching

Verifying the input scripts of several consecutive blocks in one parallel
dispatch, so the fan-out is amortised over a run of blocks rather than paid per
block. The window prepares each block against an ordered overlay, dispatches
once, and issues a per-block proof; the blocks then commit one at a time and in
order, so every rule needing committed state still sees the real chain. On
mainnet 0..150_000 this took the replay from 78.4s / 643.4s CPU to 69.6s /
558.4s, with the dispatch itself falling from 44.08s to 12.55s. The proof binds
the block hash, its predecessor, the height, the flags, and the locktime cutoff,
travels bundled with the prepared state it covers, and is re-checked against
what the apply derives; a window that cannot be proven yields nothing and every
block verifies normally. The historical pre-batching capture measured 78.4s /
643.4s CPU. The separate shipped capture measured 69.6s / 558.4s CPU; these are
not one interleaved run. See
`docs/solutions/performance/script-batching-needs-a-split-apply-path.md`.

### Script-check floor

The native reference baseline for script verification, calculated by
running the exact captured input corpus through `CPubKey::Verify` from
libbitcoinkernel-sys 0.3.0 (via bitcoinkernel 0.2.1, embedding Bitcoin Core
31.99.0 development sources: public key parsing, lax DER parsing, signature
normalization, and `secp256k1_ecdsa_verify`). On mainnet 0..150,000, all
2,868,199 input checks execute exactly one `OP_CHECKSIG` and one successful
ECDSA verification ($a = 1.0$). Native `CPubKey::Verify` execution averages
39.32 µs per attempt ($Y$), while width-1 kernel verification takes 73.62 µs
per check ($X$).

The residual $R = X - F = 34.30\ \mu\text{s/check}$ represents non-ECDSA
overhead (legacy sighash re-serialization, script parsing/evaluation, and FFI
wrapper costs). The residual is a ceiling over non-native per-check work, not a
promised or wholly removable gain. At 46.59% of per-check verification cost,
this residual exceeds the 27.73% threshold required for a 5% total wall-time
improvement (a 5.85s ceiling within the 12.55s script stage), keeping the
non-crypto script optimization lever open. See
`docs/solutions/performance/checksig-census-and-the-script-check-floor.md`.

### Front-half duplication

The failure mode where a batched fast path recomputes the sequential path's
preparation instead of replacing it, so a real saving is paid straight back.
Cross-block script batching cut crypto dispatch from 44.08s to 12.53s and moved
wall time not at all, because the batch resolved every prevout and parsed every
block that `apply_block` then resolved and parsed again for coinbase maturity,
BIP68, and the UTXO change set. The tell is that the accelerated stage shrinks
by roughly what the new stage costs. The fix is never a cheaper second pass; it
is splitting the sequential path into a prepare half and a commit half so the
preparation happens once.

### Disconnect marker phase
The durable record that a block disconnect started, and how far it got. Armed and flushed BEFORE the first mutation, not written on the error path: a process that dies mid-rollback writes no error anywhere, and that is the case the marker exists for. Armed above the index rollback too, because that rollback commits a delete batch, so a crash between the two would leave the index rolled back while the UTXO set and tip still name the block. It carries a phase because two different callers clear it and they know different things. `InFlight` means mutation started and never reported finishing; a checkpoint refuses to clear it, since checkpointing a half-finished rollback captures the damage instead of repairing it. `RolledBack` means the rollback completed in memory and is owed durability; only this may be cleared, and only by the checkpoint that makes it durable. Both phases refuse a startup. The refusal path has a third operation, `cancel_disconnect`, because an index rollback that failed touched nothing and must clear unconditionally — routing it through the checkpoint's guarded clear would no-op on an `InFlight` marker and strand a false poison on an undamaged node. What this does not close: the UTXO set and tip live behind periodic checkpoints while the index persists immediately, so a crash after a clean disconnect but before the next checkpoint still restores a tip whose index rows are gone. Closing that needs a replay path this node does not have.

### Count-and-byte bound
A window sized by whichever of two caps binds first. A count alone is wrong wherever item size varies by orders of magnitude: early-chain blocks average 4.6 KB, so 1024 of them is 5 MB, while at the tip the same 1024 is 2 GB. A byte cap alone is wrong in the other direction, letting a window hold tens of thousands of tiny items. Taking the minimum makes the batch large exactly where items are small and per-batch overhead dominates, and small where items are large and it does not. The script window uses it, and the same shape is owed by the sync staging budget, whose count is still sized for tip-scale blocks. One item larger than the whole byte cap still goes through alone: refusing it would stall the chain rather than process it.

### Identity-bearing key
A key that distinguishes which producer wrote a row, as opposed to one that merely locates it. The index's funding, spending, and txid keys are an 8-byte prefix plus a height, so two blocks at one height that share an output script derive identical keys, and rolling the first back a second time deletes the second's rows. The block-header row is identity-bearing because its key is the 80-byte serialized header and the block hash is the double-SHA256 of exactly those bytes. Checking it before deleting is a proxy for rekeying the other three families, taken because rekeying breaks the electrs-compatible layout and forces a reindex.

### Resolution-time sampling
Recording a statistic when its outcome is known rather than when the subject arrives. The fee estimator counted a transaction against every confirmation target the moment it entered, so a fresh arrival was already a failure at every target and a burst silenced the estimator before anything had missed a deadline. It also broke the decay: the denominator had been decaying since entry while a confirmation arrived undecayed, reporting 81 successes in 100 as roughly 85%. Sampling numerator and denominator together at the moment a target resolves fixes both, because they then decay from the same block. The counterpart rule is that a subject leaving for an unrelated reason is untracked without being sampled: an eviction says something about the mempool, not about whether the transaction would have confirmed.
