
### Disconnect marker phase
The durable record that an authoritative disconnect started and how far it got. Armed and flushed before the UTXO mutation, not on the error path, because a process that dies mid-rollback writes no error. `InFlight`: rollback started, completion unreported; an ordinary checkpoint must not clear it. `RolledBack`: UTXO set and applied tip moved together and need one clean checkpoint. Startup recovers automatically from either phase: it reconciles the certified durable-head chain with the restored state — rewinding a checkpoint the disconnect outran, replaying a gap that trails it — warns with the mode chosen, publishes a clean checkpoint, and retires the marker only after that publication is durable; durable evidence the head chain cannot authenticate still fails closed.

### Undo record
The per-block inverse of a UTXO commit, queued before later apply mutations and made durable by the clean checkpoint rather than a per-block fsync. Keyed by height **and** block hash so an abandoned-branch record cannot replay against another block at the same height. Retained after a disconnect because branch flip-flop is normal.

### Owed derived state
State that connection writes and disconnection must account for. `coin_stats` needs an explicit inverse for its block-level fields (the default node recomputes them at checkpoint and stable reads). `TxIndex` is durable derived state outside the authoritative transaction (see *TxIndex capability watermarks*). `switch_to_branch` (`crates/node/src/reorg.rs`) is the production disconnect caller: it preloads all disconnect bodies and the available contiguous connect prefix, and a `ChainTransition` requires the authoritative plan to equal the preloaded plan before mutation. A permanent connect failure invalidates the failed header and descendants; an operational failure leaves the branch eligible for retry.

## Derived indexes

### TxIndex capability watermarks
Versioned durable `(height, block hash)` cursors identifying the exact active-chain prefix each independently ready row family represents. `TxLookup` owns `TxConfirmed` (`--txindex`); `ScriptHistory` owns `Funding` and `Spending` (`--scriptindex=full`, which also builds internal `TxLookup` rows for Esplora without changing Core txindex advertisement); `ScriptLive` owns compact live-output locators (`--scriptindex=utxo` or `full`) and is rebuilt from the authoritative UTXO set rather than block history. `BlockHeaders` is shared rollback-integrity metadata whose row order and count must never be read as the active chain. Equal cursors advance in one body scan and one atomic batch; a lagging cursor moves independently. Height alone cannot prove identity across a reorg. On startup the node keeps the current format, upgrades format 3 in place by resetting `ScriptHistory` only, and fully resets any other version or an unversioned cursorless table for rebuild (`IndexWriter::open` in `crates/index/src/index.rs`, `open_writer` in `crates/index/src/recovery.rs`); a crash-resumable reset marker makes restart finish deletion before the writer is exposed.

### Coalesced TxIndex wake
The nonblocking hint published after a committed `applied_tip.store`: an atomic revision incremented with `Release` plus `try_send` on a capacity-one channel. Tokens may coalesce or drop; the worker checks the authoritative revision before sleeping and also wakes on a bounded timeout.

### Complete derived-index query
A query returns a result only when one snapshot proves every capability it consumes covers the exact applied tip: capture tip and revision, open one typed snapshot, check the required watermark(s) by height and hash, recheck tip and revision before returning. Live UTXO answers also hold chain-transition authority across that check and the authoritative UTXO lookup, because apply commits coins before publishing the tip. Capability lag, worker failure, missing body, truncated scan, budget exhaustion, tip change, or ABA revision change return `Retry` or `Unavailable`; a configured-off capability returns `Unavailable` with a distinct disabled reason. None of these can become a false absence.

### Identity-bearing key
A key that says which producer wrote a row, not merely where it is. Funding, spending, and txid keys are an 8-byte prefix plus height, so two same-height blocks sharing a script collide and a second rollback of the first would delete the second's rows. The block-header row (keyed by the 80-byte header whose hash is the block hash) is identity-bearing; checking it before deleting stands in for rekeying the other families, which would break the electrs-compatible layout.

### All-or-scan position fallback
Index row values carry transaction byte positions without a block tag. The reader validates the whole position list (nonempty, strictly increasing, unique, in-bounds, no overflow), reads each range from the canonical `(height, full hash)` body, and exact-checks the decoded txid or scripthash. If any position fails it discards every tentative result for that row and scans the full block — never skipping one position and keeping the rest.

## Storage

### UTXO snapshot read contract
The node accepts only complete native version-4 snapshots: exact magic and version, validated v4 records, the declared record count, a 384-byte MuHash trailer, and end-of-file. Versions 2 and 3 fail startup with a remove-and-resync instruction; there is no legacy reader.

### Deferred block-body index durability
`KvStore::write_deferred` (`crates/storage/src/trait_.rs`) writes a batch without its own fsync and leaves durability to the next checkpoint flush. Block-body index rows use it because a lost row is rebuilt from the block file. Correctness rests on ordering: body bytes are durable before the index row pointing at them is published. Weaker durability is opt-in per call site, never backend-wide.

### Directory-layout record
`UtxoRecord` v5: `txid || output_count || inline_len || widths || vout_dir || len_dir || payloads`, with per-item keys and lengths in fixed-width arrays ahead of the items so `find_output(vout)` touches about two bytes per output instead of walking every earlier script. Each directory entry uses the narrowest width the record needs; the script is whatever remains of its payload, so no length is stored twice. See `docs/benchmarks/utxo-memory.md`.

### Canonical record spelling
One logical record has exactly one byte string; `UtxoRecord` compares and hashes by bytes. v5 enforces it with three rules: minimal varints, narrowest directory width, and compact/escape amount forms that are exact complements. The last is a safety rule: `decompress_amount` multiplies by up to a billion, so an unbounded input panics in debug and wraps in release. `decompress_accepts_exactly_the_encoder_image` states the whole rule as one property.

### Work-count assertion
Asserting how much of an expensive operation a code path performs, instead of how long it takes. A wall-clock assertion in a test suite is a flake generator, and an assertion that a function merely returns something passes for a stub. Counting the calls a path makes (for example, how many amounts `find_output` decompresses for a hit, a miss, and `max_vout`) states an algorithmic claim deterministically at any input size. The counterpart is the case a count cannot make: where the claim really is about elapsed time, the assertion belongs in a paired-arm benchmark, not a test.

### Chain snapshot
The coherent, non-torn view of the applied tip the chain-event publisher keeps in one `RwLock`ed cell: `{ epoch, sequence, tip_hash, tip_height }` (`crates/node/src/state.rs`). The single writer replaces the whole cell per commit, so a reader never mixes two commit points. `epoch` is a persisted, strictly monotonic per-data-dir counter that makes an old run's cursors stale; `sequence` advances once per committed connect or disconnect and starts at 1. The snapshot is live state, never persisted per-event; readers take `NodeState::active_chain_snapshot`.

### Chain-event hint
The bounded-channel wake-up `ChainEventPublisher::record` emits after replacing the snapshot cell: `{ kind, height, hash, epoch, sequence }`, one per committed connect or disconnect. Hints carry no payload to apply and a full channel drops them without blocking the commit path; recovery is always positional re-planning over the chain itself. Hints are not a recovery log.

### Reconciliation consumer
An index that mirrors the applied chain by re-planning positionally against a fresh chain snapshot instead of receiving inline writes from the apply path. The txindex worker is the current consumer. A consumer owns its rows, its cursor, and its batch atomicity, and a failure or lag in it can never stall block application.

### ScriptLive view
The compact, rebuildable reverse view from script-hash prefix to currently
unspent outpoints. A `ScriptLive` row stores only an empty value and the full
outpoint after the lossy eight-byte prefix; the authoritative UTXO set owns
coin value, height, and script bytes. Queries hold the chain-transition
authority, resolve locators from one stable UTXO view, and exact-check the full
script before returning a result. Its watermark is independent of historical
script rows, so live queries can become ready while history is still catching
up.

### Logical owner ledger
Exact serialized key and value bytes for each column family or owning
subsystem. Explains data-model growth. It is not filesystem allocation and
must not be added to the physical ledger.

### Physical namespace ledger
Allocated filesystem blocks (`st_blocks * 512`) for each top-level
data-directory namespace. The source of the data-directory budget. A snapshot
is a lower bound on peak allocation; a passing sub-1-TB default-node result
requires a conservative high-water from an isolated filesystem or project
quota. See [docs/contracts/storage-footprint.md](docs/contracts/storage-footprint.md).

### Consumer cursor
The durable 52-byte record `{ epoch, sequence, height, hash }` naming the exact chain state a consumer's rows already mirror (`crates/index/src/reconcile.rs`). Position (`height`, `hash`) anchors row truth; `epoch` and `sequence` are advisory identity that a restart or epoch bump invalidates without invalidating rows. It is written only when the publisher snapshot provably names the tip the rows reached, and always in the same atomic batch as the row mutations it describes.

### Capability status
The node-owned status report for concrete services exposed by the RPC layer. It
contains compiled/enabled state and progress facts without introducing a
generic extension registry or lifecycle abstraction.

## Mempool

### Resolution-time sampling
Recording a statistic when its outcome is known rather than when the subject arrives. The fee estimator samples numerator and denominator together at the moment a confirmation target resolves, so both decay from the same block. A transaction leaving for an unrelated reason (eviction) is untracked without being sampled.

## Measurement

### Product performance cell
One coordinate of the frozen 36-cell denominator: one product domain
(`offline`, `p2p`, `muhash`), one corpus (`c150` or `cmodern`), one native
architecture (`x86_64` or `arm64`), and one backend (`fjall`, `rocksdb`,
or `redb`). Diagnostics are not cells. See
`docs/contracts/hot-path-attribution.md`.

### Hot-path attribution ledger
The single inventory of product hot paths, overlap groups, and
dispositions. Nested stage histograms are diagnostics. A cell residual
stays `unmeasured` until seven valid bitcoin-rs walls exist and the
exclusive union is subtracted from whole-run wall. Owner:
`docs/benchmarks/hot-path-ledger.toml`.

### Retained benchmark contract
Permanent benchmarks call the shipped production path, use a product-shaped workload, and protect a regression that still matters. A/B refactor harnesses, synthetic microbenchmarks, and future-work measuring tools are not retained, and the historical campaign JSON evidence is retired by #224 (`docs/contracts/hot-path-attribution.md`). The retained Criterion targets are the `benches/` directories of the owning crates (currently consensus Merkle, UTXO commit, node sync pipeline and chainstate journal replay, mempool priority index, real-file index resolver, and P2P message write). Which targets CI compiles is owned by the `bench-smoke` job in `.github/workflows/main.yml`, not by this glossary.

### C150
The historical product corpus: mainnet genesis through height 150,000. Pre-P2SH, pre-SegWit, pre-Taproot. Identities, census, and state are owned by `docs/contracts/campaign-corpora.md`.

### Cmodern
The modern product corpus: mainnet genesis through height 709,635, the first height with executed examples of every required post-P2SH script class. Identities, census, and oracle are owned by `docs/contracts/campaign-corpora.md`.

### Matched-harness comparison
A cross-node benchmark matches every input that is not the thing under test — block source, validation posture, allocator, CPU pinning, time of measurement — before any ratio is quoted. Interleave both nodes back-to-back on an idle host and quote paired medians.

### Offline full-validation comparator
The processing-bound cross-node oracle: Bitcoin Core 31.1 and bitcoin-rs both
build chainstate from one hash-pinned Core-framed archive under full
validation, matched index posture, and production durability. Wall time is
process start through durable clean exit. The harness lives in
`tools/benchmark-campaign/offline_full_validation.py`; see
`docs/benchmarks/offline-full-validation.md`.

### CPU-seconds as a first-class metric
A throughput change is measured against CPU time as well as wall time, because an idle many-core host lets wall-clock tuning spend cores for free. Sampling `utime+stime` from `/proc/<pid>/stat` while polling height is enough; per-thread attribution comes from `/proc/<pid>/task/*/stat`.

### Contended-harness tuning artefact
A parallelism constant tuned while the harness competes with the node for CPU, so the optimum measures the contention. Never tune a parallelism constant against a harness sharing CPU with the node, and never on wall alone.

### CI lane parity
A branch is green only against `scripts/ci-pr.sh`, which `.github/workflows/ci.yml` invokes — never a local approximation. The required PR jobs are `fmt`, `deny`, `clippy`, `test-crates`, `test-binary`, and `test-workspace`: the format check, the full-graph `cargo deny` audit, and four parallel fail-fast kernel-free lanes — clippy (per-crate `-p` invocations because a virtual workspace drops `--workspace --features`) plus the three test lanes — with the pinned Core and Apalache fixtures backing the binary and workspace lanes. `.github/workflows/main.yml` runs on `main` pushes and manual dispatch only: the full-node feature set with the C++ kernel, `--include-ignored` for the consensus fixture corpus, the `kernel-oracle` parity tests (not `#[ignore]`; skipped if `--ignored` is passed), bench-smoke compilation, the Python comparator tests, the MSRV compile, and native-script evidence. `cargo deny` failures are bug reports, not lint noise.
