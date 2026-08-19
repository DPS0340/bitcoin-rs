# `gettxoutproof` benchmarks

Baseline and refactor-set measurement for the one RPC handler that did unbounded
work per call. `crates/rpc` had no benchmarks at all before this page, so no
number existed for it.

Harness: `crates/rpc/benches/txoutproof.rs`. Criterion, both arms of the refactor
set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

The arms differ by whether the `Context` carries a txindex. `before_scan` is the
pre-index path: no indexer, so the handler walks every block record, loads each
body, deserializes it and hashes every transaction in it. `after_index` is the
same call on the same fixture with a populated `Indexer<RocksDbStore>` attached.

Block bodies are served from a real `FlatFileBlockStore`, the same open /
`fstat` / seek / read sequence production takes. Serving them from an in-memory
map would leave the syscalls out entirely, which is the mistake
`docs/benchmarks/index-read-path.md` records having made and corrected.

## What was measured

Fixture: 2,000 blocks of 8 transactions each, RocksDB-backed index, flat block
files. Machine otherwise idle — the mainnet IBD sharing this host was stopped
first and the run waited for writeback to drain (`loadavg` 0.65 at start).

| Arm | `first_block` | `last_block` |
|---|---:|---:|
| `before_scan` | 29.248 µs | **21.118 ms** |
| `after_index` | 28.222 µs | **32.983 µs** |
| ratio | 1.04x | **640x** |

Two positions, because the scan is position-dependent and the index is not.
`first_block` is the scan's best case: it finds the block on the first record and
stops, and there the two arms are within noise of each other — the index costs
nothing it does not save. `last_block` is the scan's worst case. Reporting only
the worst would overstate the win; reporting only the best would hide it.

The index arm is flat at 28-33 µs across both positions. That is the finding: the
answer no longer depends on where in the chain the transaction is.

## Extrapolating to a real chain, and why the number below is a floor

The scan is linear in the number of block records. At 2,000 blocks it costs
21.118 ms, or 10.56 µs per record; at the 963,124 records a mainnet node holds at
the time of writing that is **about 10 seconds of unbounded work for one RPC
call**.

Treat that as a **lower bound, not a prediction**. Fixture blocks hold 8 small
transactions, so their per-record cost is dominated by the file open and read.
Real mainnet blocks hold up to a few thousand transactions each, and the scan
deserializes every one and computes every txid. The per-record cost at tip is
therefore much higher than the fixture's, and the ratio correspondingly larger.
See
`docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`
for why the small window cannot be scaled naively in the other direction either.

## What is not claimed

- **No latency budget is touched.** `gettxoutproof` is not a G14 budget item. The
  case for the change is that one authenticated RPC call should not do O(chain)
  work and evict every cache on the node while it does.
- **The fixture is synthetic.** It is not a mainnet corpus; it establishes the
  shape of the cost, not its absolute value on real data.
- **Only the no-block-hash path changed.** Called with an explicit `blockhash`,
  the handler does what it always did, and that path is not in this benchmark.

## Correctness, and how the tests were checked

The scan is retained whole as `proof_from_records`: it is the fallback whenever
the index cannot answer, and the oracle the equivalence tests compare against.
Twelve tests cover the set — nine in `crates/rpc/src/handlers/tx.rs`, three in
`crates/index/src/index.rs`.

The tests were then audited by mutation, because a green suite proves nothing
until it is shown to fail when the behaviour it claims to pin is removed:

| Mutation | Expected | Result |
|---|---|---|
| `proof_via_index` always returns `None` | red | 1 test failed |
| the all-wanted-txids guard never fires | red | the 2 predicted tests failed |
| `resolve_transaction_height` always returns `None` | red | 2 failed; the test that pins `None` correctly stayed green |

Two real defects surfaced during that audit and were fixed:

- The three `crates/index` tests **were not running at all**. That module is
  `#[cfg(all(test, feature = "rocksdb"))]` and the crate's default feature set is
  empty, so they were being filtered out while appearing to pass.
- `resolve_transaction_height_agrees_with_the_transaction_resolver` passed
  vacuously: both resolvers returning `None` satisfied the equality. It now pins
  the resolved height before comparing.
