# Block-record lookup benchmarks

Baseline and refactor-set measurement for `Context::record_for_hash`, the
hash-to-record resolver under `getblock`, `getblockheader`, `getblockstats`,
`getrawtransaction` with a blockhash, the REST block endpoint, and
`gettxoutproof`'s explicit-hash path.

Harness: `crates/rpc/benches/blocklookup.rs`. Criterion, both arms of the
refactor set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

## What was wrong

`record_for_hash` step 1 asks the block tree for the hash. The tree answers with
the height. It then scanned the block-record log linearly for the matching
`(hash, height)` pair — with the height already in hand, and over a log that is
ordered by height and grows one entry per block forever.

`verifychain` calls it once per block it checks, so that RPC was quadratic in
chain length.

This is a hotter path than the chain-info fold in
`docs/benchmarks/chain-info-fold.md`: `getblockchaininfo` is a status call, while
`getblockheader` is what a tip-following client polls.

## What was measured

| Records | Hash at | `before_scan` | `after_search` | ratio |
|---:|:---|---:|---:|---:|
| 10,000 | tip | 14.59 µs | 37.4 ns | **390x** |
| 10,000 | middle | 5.41 µs | 41.9 ns | **129x** |
| 100,000 | tip | 433.4 µs | 38.5 ns | **11,265x** |
| 100,000 | middle | 77.8 µs | 40.1 ns | **1,942x** |
| 500,000 | tip | 3.850 ms | 44.0 ns | **87,551x** |
| 500,000 | middle | 1.747 ms | 44.6 ns | **39,213x** |
| 963,124 | tip | **6.263 ms** | **42.2 ns** | **148,548x** |
| 963,124 | middle | 3.448 ms | 46.9 ns | **73,548x** |

The new arm is flat — 37 ns to 47 ns across 96x the records — because it is a
binary search: ~20 steps at a mainnet tip.

Two lookup positions are measured because measuring only one would have been
flattering to the scan in whichever direction was chosen. A hash at the *end* of
the log is what a tip-following client asks for and is the scan's worst case; a
hash in the *middle* is what a wallet rescanning history asks for, and costs the
scan half as much. Both are reported.

## What replaced it

`BlockLog::record_at_height_hash` and `BlockLog::record_at_height`. The log is
appended in height order and only ever popped from the tail
(`apply::disconnect_block` checks the tail's hash before popping), so it is
non-decreasing by height and can be searched.

A reorg can leave more than one record at a height, so the search locates the run
and then walks it. The run is the number of times that height has been connected
— not a function of chain length.

`record_at_height` tries the direct index first, because a log with no gaps and
no duplicate heights holds the record for height `h` at index `h`. It accepts
that answer only when the record *and its predecessor* agree, so a log that has
drifted falls through to the search rather than answering with the wrong record.

These are not new code. `crates/node/src/block_source.rs` already had both
functions, private, over `&[BlockRecord]`; they now live on `BlockLog` beside the
data and the node calls them. The change deletes a duplicate implementation
rather than adding one.

## Correctness, and how the tests were checked

The linear scan is the oracle. It is written out in the tests and in the
benchmark's `before` arm rather than called through the crate: it is three lines,
and an oracle that shares code with the implementation cannot disagree with it.
The scan makes no assumption about the log's ordering, which is the point — the
search assumes it is non-decreasing by height.

`record_at_height_hash_matches_the_scan_it_replaced` sweeps every height in and
around the fixture against every hash in it, including hashes at the wrong
height, which must find nothing.
`record_at_height_matches_the_scan_it_replaced` does the same for the height-only
lookup, which has to return the *first* record at a duplicated height because
that is what the scan returned.

| Mutation | Expected | Result |
|---|---|---|
| the search stops at the first record of the height run | red | 2 tests failed |
| the run boundary lands after the height, not before it | red | 5 tests failed |
| a height the log does not hold answers with its neighbour | red | 2 tests failed |
| `record_at_height` trusts the direct index unconditionally | red | 2 tests failed |
| `record_at_height` ignores the duplicate-height rewind | red | 2 tests failed |
| `record_for_hash` ignores the hash and takes the height run head | red | 1 test failed |
| `block_by_height` without a tip answers the last record | red | 1 test failed |

Two of these **survived the first pass**, and both were the fixture's fault
rather than the tests':

**The fixture started at height 0.** The predecessor check in the direct-index
shortcut only matters when index `h` holds a record at height `h` that is *not*
the first at that height, and a log starting at zero can never be in that state.
The fixture now starts at height 1, which puts a duplicate at index 3 and the run
head at index 2 — exactly where the shortcut and the search disagree. **A fixture
that cannot reach the state a check defends against tests the check by not
reaching it.**

**Nothing exercised `block_by_height` with no applied tip.** That is the path a
Context takes before the first tip is published, and replacing its whole body
with "the last record in the log" turned nothing red.
`block_by_height_without_an_applied_tip_reads_the_log` now covers it, and it is
among the killers for four of the seven mutations.

One invalid mutation is recorded as invalid: an anchor for the run-boundary
mutation stopped matching after `cargo fmt` rewrapped the expression across three
lines. It was reformulated against the current text, not counted as a pass.

## What is not claimed

- **The end-to-end RPC is not measured here.** The benchmark times the lookup,
  not `getblock`, which also deserializes a body. Populating a 963k-node block
  tree — which `record_for_hash` step 1 needs — is not something this harness
  builds. What is measured is that the lookup went from 6.26 ms to 42 ns.
- **Step 2 is still linear, deliberately.** When the block tree has no node for
  the hash there is no height, so there is nothing to search on. That path exists
  for cache-only fixtures and for blocks seen before a checkpoint restore.
- **The fixture is synthetic**, and its hashes are height-derived. It establishes
  the shape of the cost.
- **No G14 budget item is touched directly.** The case is that resolving one
  block record should not cost time linear in chain length.
