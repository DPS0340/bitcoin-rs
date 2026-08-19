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

Two fixture shapes, because one cannot answer the question. With 8 tiny
transactions per block the per-record cost is the file open and read, which
understates a real chain; with 500 it is the deserialize-and-hash of the body,
which is what a mainnet block actually costs. Block counts differ so each shape
stays inside a Criterion run.

RocksDB-backed index, flat block files, machine otherwise idle — the mainnet IBD
sharing this host was stopped first and the run waited for writeback to drain.

| Shape | Arm | `first_block` | `last_block` |
|---|---|---:|---:|
| 2,000 blocks x 8 tx | `before_scan` | 16.366 µs | **20.824 ms** |
| | `after_index` | 26.987 µs | **31.312 µs** |
| | ratio | **0.61x** | **665x** |
| 200 blocks x 500 tx | `before_scan` | 542.54 µs | **57.228 ms** |
| | `after_index` | 701.30 µs | **700.34 µs** |
| | ratio | **0.77x** | **81.7x** |

Two positions, because the scan is position-dependent and the index is not.

**The index arm is slower in the scan's best case, and that is a real cost, not
noise.** It runs 10.6 µs longer at 8 transactions per block and 158.8 µs longer
at 500. That is what consulting an index costs — a row lookup, a ranged read and
a txid comparison — and it does not go away, because the proof still needs the
block loaded either way. An earlier revision of this page reported the best case
as "within noise at 1.04x"; that was measured on a single fixture shape and was
wrong.

What makes it acceptable is what "the scan's best case" means: the scan walks
from height 0, so it wins only when the wanted transaction is in the *first block
on the chain*. On any real chain that case does not arise. The case that does
arise is the one the second column measures, where the index arm is flat at
31 µs / 700 µs regardless of position while the scan grows without bound.

## Extrapolating to a real chain

The scan is linear in the number of block records. Per record it costs **10.41 µs**
at 8 transactions per block and **286.1 µs** at 500. Against the 963,124 records a
mainnet node holds at the time of writing, that brackets one `gettxoutproof` call
at **10 seconds to 4.6 minutes** of unbounded work.

The earlier revision of this page gave only the lower bound and called it a floor.
It still is one — real blocks range from a single coinbase to a few thousand
transactions, so neither shape is the chain — but the range is now bounded from
above as well as below. See
`docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`
for why neither number should be scaled naively.

Note also what the fixture cannot show: at 200-2,000 records, `Context::block_by_height`
resolves a record by linear scan in negligible time. At 963k records that scan is
itself O(chain), and the index arm pays it too. Fixing it is separate work.
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
