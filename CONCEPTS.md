# Concepts

Shared domain vocabulary for this project: entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound processes learnings; direct edits are fine. Glossary only, not a spec or catch-all.

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

### Sync regimes (download-bound vs processing-bound)
The two distinct cost regimes any sync measurement must name before its numbers mean anything. **Download-bound:** wall-clock is decided by the network path (peer scheduling, per-peer bandwidth, staller handling) — the regime of live IBD. **Processing-bound:** blocks are already local and wall-clock is decided by validation plus storage commit — the regime of reindex and offline replay. A node can rank differently in the two regimes, so a faster-than-X claim is meaningless without stating which regime was measured and with what validation posture. Within a regime the comparison is only as good as its least-matched input — see *Matched-harness comparison*.

## Consensus validation

### bitcoinkernel
Bitcoin Core's C++ consensus engine (`libbitcoinkernel`), compiled into `bitcoin-rs` as the production consensus default across consensus, node, and binary crates. Beyond script verification it is also the block **parser** on the apply path — see *One-shot kernel block parse*. It validates input scripts across all script classes (legacy, segwit, and Taproot key-path and script-path spends). Default builds require system dependencies (`cmake` and `libboost-dev`). Production transaction and block input-script verification route to bitcoinkernel when default features are enabled, while Rust performs surrounding non-script transaction and block consensus checks; the Rust `Interpreter` remains a separate portable script-verification surface under `--no-default-features`.
### bitcoinconsensus
Removed historical script verification backend. Previously linked as an extracted C library for non-taproot script checks before being deleted in favor of `bitcoinkernel`. The library lacked complete-prevout and Taproot script-path verification capabilities required for current mainnet script validation (exposed by block 938344 during mainnet IBD).

### Rust interpreter (portable posture)
The pure-Rust script verification path maintained alongside the bitcoinkernel default. Enabled under `--no-default-features` without C++ build dependencies. It cannot validate Taproot script-path scripts (such as those past height 709635 / block 938344 on mainnet) and is retained for differential testing and lightweight non-production environments.

### One-shot kernel block parse
Parsing each block exactly once with `bitcoinkernel::Block::new` (wrapped as `KernelBlock` in `crates/consensus/src/kernel.rs`) and reusing that parse for everything downstream. It supplies three things at once: the **txids** (Core's `CTransaction` hashes itself while deserializing, using the SHA-256 implementation Core selects at runtime — `avx2(8way)` on Skylake-SP), and the **transaction objects** that script preparation borrows via `TransactionRef` instead of re-serializing. It replaced a scalar `compute_txid` pass plus a per-transaction `encode::serialize` → `Transaction::new` round-trip, cutting `script_prepare` from 18.55s to 4.29s and the 0→150k replay from 137.3s to 121.9s. The costing lesson generalizes: **price a replacement by everything it subsumes**, not by the line item that motivated it — costed against parse-and-serialize alone the same change scores +1.54s and looks like a loss.

### Parallel granularity (per-item cost rule)
Whether a fan-out pays is decided by per-item work against dispatch cost, not by how parallelizable the loop looks. Measured both directions on the same apply path: script checks (~100 µs per input) wanted *more* parallelism, and lowering `MIN_PARALLEL_SCRIPT_CHECKS` from 16 to 4 bought 1.15×; UTXO lookups (~500 ns) wanted *none*, and deleting two rayon fan-outs bought 1.07× and 1.11×. Merkle nodes (~2.6 µs) sit in between and measured neutral-to-worse. A threshold has an interior optimum in both directions — below 4 the script threshold turns back up, and pool width peaks at 32 then degrades at 64. Always gate on **elapsed**, never on the stage being targeted: parallel prepare makes `script_prepare` 30% faster and the whole run 4% slower by contending with the script-verify pool. See `docs/solutions/performance-issues/txid-parallelization-delivers-2x-but-core-still-leads.md`.

### Matched-harness comparison
The requirement that a cross-node benchmark match every input that is not the thing under test — block source, validation posture, CPU pinning, and time of measurement — before any ratio is quoted. Each mismatch found in this repo moved the headline materially: Core's reference was months stale (67s → re-derived 59.6s); bitcoin-rs fetched blocks over REST from a live `bitcoind` while Core read local `blk*.dat`, which cost ~35s of harness *and* contended for CPU (121.9s → 84.6s once `--blocks-file` matched it); and GoCoin skips script verification below its default `LastTrustedBlock` of #940000, so it must be compared either against an assume-valid bitcoin-rs run or with that asymmetry stated. Interleave both nodes back-to-back on an idle host and quote paired medians; comparing your best run against someone else's old run is not a measurement.

### Script-flag exceptions (BIP16Exception)
The historical blocks Bitcoin Core hardcodes in `consensus.script_flag_exceptions` (chainparams) to be validated under a reduced script-verification flag set, because they contain spends valid under the rules in force at the time but invalid under a later-enforced flag. As of Core v29: mainnet block 170060 (`…ac4f9c22`, the BIP16/P2SH exception) and 692261 (`…e1e395ad`, the Taproot exception); testnet3 block 394; none on testnet4/signet/regtest. The two **P2SH waivers** (170060, 394) are reproduced explicitly by `Network::is_bip16_p2sh_exception` (keyed by block hash, mainnet/testnet3 only); missing them rejects canonical blocks and wedges full-validation sync past the assume-valid height. The **692261 Taproot override** needs no rs exception: Core's override only strips TAPROOT (which Core defaults on for all blocks), and rs already height-gates taproot (`is_taproot_active`, 709632 > 692261) so it never sets TAPROOT there — its computed flags already match Core's effective set. Compare *effective* flag sets, not raw overrides. See `docs/solutions/architecture-patterns/p2sh-flag-must-honor-core-script-flag-exceptions.md`.

### Accepted-connection ownership proof
The check in `scripts/measure-g14-electrum-rss.sh` that the measured PID really owns the Electrum connection being timed, so an RSS figure cannot be attributed to the wrong process. It matches an ESTABLISHED row in `/proc/<pid>/net/tcp` on the exact four-tuple and then intersects that inode with the process fd table; only an inode in both is proof. The subtlety is that the kernel finishes the three-way handshake before the server calls `accept()`, so a connection waiting in the listen backlog is reported ESTABLISHED with **inode 0** — unaccepted, not malformed. Treating inode 0 as an error could only ever produce a false negative, because an inode of 0 is in no fd table and so can never survive the intersection; the parser counts those rows and lets the poll loop retry. See `docs/solutions/logic-errors/established-with-inode-zero-is-unaccepted-not-malformed.md`.

### CI lane parity
The rule that a branch is green only against the commands in `.github/workflows/ci.yml`, never against a local approximation of them. Three differences bite: `-D warnings` on the `clippy` and `kernel-parity` lanes promotes every warning the workspace lint job merely reports (`dead_code`, `needless_borrow`, `doc_markdown`, `needless_collect`, `too_many_lines`); a virtual workspace silently drops `--workspace --features`, so the four-backend and kernel surface is only reached through `-p bitcoin-rs --no-default-features --features "$FULL_NODE_FEATURES"` plus a separate `-p bitcoin-rs-node` pass for its test targets; and `kernel-parity` adds `--include-ignored` on a debug profile. `cargo deny` belongs in the same sweep and is a bug report, not lint noise. See `docs/solutions/best-practices/workspace-clippy-does-not-predict-the-d-warnings-lanes.md`.

### CPU-seconds as a first-class metric
The rule that a throughput change is measured against CPU time as well as wall time, because a many-core idle benchmark host lets wall-clock tuning spend cores for free. Sampling `utime+stime` from `/proc/<pid>/stat` while polling height is enough; no profiler or metrics plumbing is required, and per-thread attribution comes from summing `/proc/<pid>/task/*/stat` by thread name. On the loopback P2P sync to 150k, bitcoin-rs takes 76.3s wall and **318.4s CPU** against Core's 42.5s and **65.0s** — a 1.77× wall gap concealing a 4.9× CPU gap, which becomes wall time on the 4-8 core machines most nodes run on. The excess is broad rather than one hot spot: collapsing `SCRIPT_VERIFY_POOL` to a single thread still burns 230.1s, so rayon spin is a minority of it and no pool width converges. This also puts a caveat on every wall-only sweep in the performance note, `MIN_PARALLEL_SCRIPT_CHECKS` 16→4 most of all, since pushing more blocks through the pool is exactly the shape of change that trades CPU for wall.

### Global rayon pool cap
The process-wide rayon pool is capped at `GLOBAL_RAYON_THREADS` (4) by `cap_global_thread_pool` in `crates/node/src/run.rs`, called at the top of `run`. rayon otherwise sizes that pool at one worker per core, and because it leaves those workers unnamed they inherit the process name — which is why per-thread CPU attribution first blamed the async runtime. The pool runs only short coarse jobs (block txid hashing, shard commits) while `SCRIPT_VERIFY_POOL` separately holds up to 32 threads, so an uncapped global pool oversubscribes a many-core host and its workers spin for work that is not there. Capping it cut a loopback P2P sync to 150k from 75.6s wall / 314.4s CPU to 64.4s / 162.4s across three interleaved pairs — **both axes at once**, so it is not a wall-for-CPU trade. With the `MIN_PARALLEL_SCRIPT_CHECKS` correction stacked on top, that sync finally lands at 62.8s / 90.1s against Core's 45.9s / 67.8s. The width sweep is flat from 2 to 8; the full-verification replay is insensitive at every width because script verification dominates it and runs in its own pool. Contrast `Parallel granularity (per-item cost rule)`, which is about *when* to fan out; this is about *how wide* the shared pool may be.

### Contended-harness tuning artefact
The failure mode where a parallelism constant is tuned while the benchmark harness competes with the node for CPU, so the measured optimum is a property of the contention rather than of the code. In this repo it produced two wrong constants. `MIN_PARALLEL_SCRIPT_CHECKS` was walked down to 4 by a sweep whose harness fetched every block over REST from a second `bitcoind` on the same cores; the inflated serial path made ever-finer fan-out look free and the curve read as monotonic. Re-measured against local block files the ordering **inverts** — 4 becomes the worst point tested on both wall and CPU, and the optimum is 32 (75.5s / 649.6s versus 84.4s / 946.6s). The global rayon pool was the same mistake in a different guise: uncapped, it cost nothing measurable in wall time on an idle many-core host. Two rules follow: never tune a parallelism constant against a harness that shares CPU with the node, because contention changes the shape of the curve and not merely its offset; and never tune one on wall alone, because both bad constants were wall-optimal on the host that chose them. See also `CPU-seconds as a first-class metric` and `Global rayon pool cap`.
### Commit point (multi-store mutation)
The single mutation that decides a multi-store operation happened; everything after it is cleanup. For block disconnect the commit point is the `applied_tip` rollback, which is why it runs last, after index rollback and UTXO undo. Naming it first is what tells you which steps need atomicity, and the answer differs per store: the index is on disk, so a partial rollback survives a crash and must be one atomic write batch; the UTXO set is RAM-resident with checkpoint durability, so a crash discards its partial mutation entirely. What does not follow is that the steps before the commit point are therefore safe to re-enter. Index rollback runs before the fallible UTXO undo, and that undo is not all-or-nothing: it walks shards and can fail after other shards committed, so a failure leaves the index rolled back, the UTXO set partly undone, and the tip still describing the block. Separately, a checkpoint can retain a UTXO commit whose undo record was lost with the journal. Retry is ruled out as the answer: each UTXO operation is idempotent on the set, but the commit fires the set's change listener and coinstats is one, so a second pass double-counts where the set converges. A failed multi-store rollback is fatal and poisons the path. Whether a durable phase boundary should additionally detect a crash-time mismatch is open, and belongs with the recovery protocol. See `docs/solutions/architecture-patterns/node-reorg-execution-design.md`.

### Refusing default (trait participation)
A trait method whose default returns success lets an implementation that never opted in be mistaken for one that did. Where a consumer must participate in an invariant, the default must refuse. `IndexerLike::rollback_block` returns `IndexError::UnsupportedRollback` rather than zeroed counts: a silent no-op would let the node advance its tip believing a stale index is consistent, which is the exact failure the method exists to prevent. The eight existing implementations still compile untouched, and only fail if a reorg is genuinely driven through one that cannot handle it.

### Undo record

The per-block inverse of a UTXO commit: the outputs the block spent, with
enough metadata to recreate them, plus the outputs it created. Written during
connection, keyed by height **and** block hash so a record from an abandoned
branch can never be replayed against a different block at the same height.
Retained after a disconnect, because flip-flop between competing branches is
normal.

### Owed derived state

State that connection writes and disconnection does not yet undo: `coin_stats`,
the filter index and its header cache, and the `blocks` and `transactions` RPC
caches. Named as owed rather than silently skipped, and the reason
`disconnect_block` has no production caller.
