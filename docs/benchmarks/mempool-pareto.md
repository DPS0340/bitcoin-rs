# Mempool priority-index benchmarks

Baseline and refactor-set measurement for `ParetoFront`, the mempool's fee
priority index. `crates/mempool` had no benchmarks before this page, so no number
existed for it.

Harness: `crates/mempool/benches/pareto.rs`. Criterion, both arms of the refactor
set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

## What was wrong

`ParetoFront::insert` held its keys in a flat `TinyVec` and, on every insert, did
a linear `remove` followed by `sort_by` over the whole index. Filling an index of
`n` entries was therefore `O(n^2 log n)`.

This is not an idle path. `Mempool::insert_entry` — the path that accepts a
transaction from a peer — calls `recompute_all_metadata`, which discards the
priority index and re-inserts every entry. So the quadratic cost was paid once
per accepted transaction, by anyone able to put transactions in the mempool.

## What was measured

| Entries | `before_sorted` | `after_ordered` | ratio |
|---:|---:|---:|---:|
| 1,000 | 2.064 ms | 151.0 µs | **13.7x** |
| 4,000 | 45.65 ms | 626.2 µs | **72.9x** |
| 16,000 | 464.7 ms | 3.046 ms | **152.6x** |
| 50,000 | **4.497 s** | **10.45 ms** | **430.4x** |

The ratio grows with `n` because the two arms have different complexity, which is
the claim. Across the 1,000 → 50,000 span (50x the entries) the old arm takes
2,183x longer — a measured exponent of **1.97**, i.e. `n^2`. The new arm takes 69x
longer over the same span against the 78x that `n log n` predicts.

Fee rates are spread by a multiplicative hash rather than ascending with the
insertion order. An index fed entries already in priority order never has to
reorder anything, and would have measured the best case of the arm being
replaced.

## What replaced it

An ordered set keyed by the priority comparison, plus a map from entry id to the
key currently indexed for it. Insert and remove are both `O(log n)`.

The id-to-key map is not redundant: removals arrive as an entry id while the
ordered set is keyed by priority, so without it a removal would have to search
the set — reintroducing the linear scan.

The final tiebreak on entry id in the ordering is load-bearing for the same
reason it was cosmetic before. The index is now a *set of keys*: two entries
whose keys compared equal would collapse into one, and a transaction would
silently vanish from the priority index. Entry ids are unique, so no two distinct
entries can compare equal. `entries_with_identical_priority_fields_are_all_retained`
pins it.

## The quadratic is not closed by this change

`Mempool::insert_entry` is still superlinear, because `recompute_all_metadata`
walks every entry on every insert regardless of how fast the index is:

| Transactions | fill | per transaction |
|---:|---:|---:|
| 200 | 2.572 ms | 12.9 µs |
| 800 | 51.27 ms | 64.1 µs |
| 3,200 | **1.057 s** | **330 µs** |

That is a measured exponent of **2.17** across the span, *with this change
already applied*. Extrapolating to a Core-default mempool (`-maxmempool=300MB`,
on the order of 10^5 transactions) puts a full fill around **30 minutes**.

So this change removes one quadratic term and leaves the outer one. It is
reported here rather than claimed as fixed. The follow-up is to make
`recompute_all_metadata` incremental: inserting one transaction changes only its
own ancestor totals — which `insert_entry` already computes at lines 153-165 and
then throws away — and the `descendant_size`/`descendant_fee` of its ancestors,
which are bounded by the ancestor-count policy limit. Note that an ancestor's
*ancestor* fee rate does not change when a child arrives, so the priority keys of
existing entries do not need reindexing at all.

## Correctness, and how the tests were checked

The flat-vector index is retained whole as `SortedParetoFront`: it is the oracle
the equivalence tests compare against and the benchmark's `before` arm. Five
tests cover the set in `crates/mempool/tests/pareto_ordering.rs`, and the two
equivalence tests compare the *whole* index rather than a prefix — a `top_n(10)`
check passes while everything below the tenth entry is misordered, and
`mining::policy` reads the whole index via `top_n(len())`.

The tests were then audited by mutation:

| Mutation | Expected | Result |
|---|---|---|
| a replacement leaves the stale key in the ordered set | red | 2 tests failed |
| the ordering drops its entry-id tiebreak | red | 3 tests failed |
| the ordering puts the lowest fee rate first | red | 3 tests failed |
| `remove` forgets the ordered set | red | 2 tests failed |

The audit found a real defect in the tests themselves. `SortedParetoFront`
originally shared `ParetoKey`'s `Ord` with the replacement, which looked tidy and
made the oracle worthless: under the reversed-ordering mutation both
implementations agreed with each other, so both equivalence tests stayed green
while the index was ordered backwards. Only `pool::tests::prioritise_reorders_priority_index`
caught it. The oracle now keeps its own verbatim copy of the comparison, and the
same mutation kills all three ordering tests. **An oracle that shares code with
the implementation cannot disagree with it.**

One measurement artefact, recorded because it briefly read as a coverage gap:
`cargo test -p <crate>` stops at the first failing target by default, so a
mutation that fails the lib suite never runs the integration suites. The
reversed-ordering mutation looked as though it killed only one test until it was
re-run against `--test pareto_ordering` directly.

## What is not claimed

- **No G14 budget item is touched directly.** The case for the change is that
  transaction acceptance should not cost time quadratic in mempool size.
- **The fixture is synthetic.** Fees and sizes are generated, not sampled from a
  real mempool; it establishes the shape of the cost, not its value on real
  traffic.
- **The 30-minute figure is an extrapolation**, from an exponent measured over
  200-3,200 transactions, and is quoted to say "the outer term still matters",
  not as a prediction. See
  `docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`.
