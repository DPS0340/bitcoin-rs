# UTXO set memory attribution

Step 2.1 of the memory campaign: measurement only, no encoding change. It exists
to decide whether the encoding and allocation work planned after it is worth
doing at all.

The question. `UtxoSet` is fully memory-resident across 256 shards with no
eviction tier, and the published tip-RSS evidence reached **13.83 GiB at height
645,804** without making the tip, against a G14 budget of 16 GiB. Nothing had
ever attributed that figure. The record constants predict roughly 5 GB at that
height, leaving ~9 GiB unexplained, and the plan named allocator fragmentation
across tens of millions of small allocations as the leading suspect.

Harness: `crates/utxo/examples/utxo_memory_attribution.rs`, backed by
`UtxoSetView::memory_report()`. Synthetic set with a mainnet-shaped script mix
(P2WPKH 22 B, P2PKH 25 B, P2SH 23 B, P2TR 34 B) and 1.5 live outputs per record.
System allocator, Apple Silicon.

```
cargo run -p bitcoin-rs-utxo --example utxo_memory_attribution --release -- [records] [churn_rounds]
```

## What a UTXO costs

Bytes per live output, constant across every size measured:

| Layer | Bytes/output | Share |
|---|---:|---:|
| Record payload | 69.6 | 63% |
| ...plus allocation header and slack | 74.9 | 68% |
| ...plus hash-table backing store | 87.5 | 79% |
| Process RSS, 200% churn | 110.5 | 100% |

The absolute RSS-to-accounted ratio falls with scale as the fixed process
baseline amortizes — 1.431x at 750k outputs, 1.207x at 3M, 1.163x at 6M — so the
honest figure is the **marginal** cost between the 3M and 6M points, which
removes the baseline entirely: **97.96 bytes of RSS per output against 87.5
accounted, a 1.12x allocator overhead.**

## Where the payload goes

The 69.6 bytes of payload per output decompose as:

| Item | Bytes/output |
|---|---:|
| Record header amortized (37 B over 1.5 outputs) | 24.7 |
| ...of which the 32-byte txid alone | 21.3 |
| Per-output metadata (`vout`, value, height, coinbase, script_len) | 19.0 |
| Script bytes | 25.9 |

**The single largest item is the txid**, at 21.3 bytes per output, because a
record averages only 1.5 live outputs to amortize it over. It is also the one
item that cannot be compressed: the 8-byte key prefix is lossy and the full txid
is what makes a lookup exact.

## Fragmentation is not the answer

The plan's leading hypothesis was allocator fragmentation from tens of millions
of small allocations. Tested directly by spending the oldest tenth of the set and
refilling it, repeatedly, holding the live count constant:

| Churn | RSS bytes/output | RSS / accounted |
|---|---:|---:|
| None (monotonic insert) | 105.7 | 1.207x |
| 50% of the set replaced | 108.3 | 1.237x |
| 200% of the set replaced | 110.5 | 1.263x |

Churning twice the whole set costs **5% more RSS**, and the curve is flattening,
not climbing. Uniform small allocations are the case a size-class allocator
handles well. **The hypothesis is refuted at this scale on this allocator** —
with two caveats worth keeping: production links mimalloc rather than the system
allocator, and 645,804 blocks is far more churn than twenty rounds.

## Measured on a real chainstate

A pruned mainnet sync to **height 412,732** (38,145,360 outputs across
10,519,335 records) settled the assumptions above. Taken from the checkpoint
path, so sync has stopped and the subsystems have drained — in-flight samples
swing between 1.1 and 3.2 GB and measure block staging, not the set.

| Layer | Bytes/output | Total |
|---|---:|---:|
| Record payload | 55.1 | 1.96 GiB |
| ...plus allocation header and slack | 57.3 | |
| ...plus hash-table backing store | 61.2 | 2.18 GiB |
| **Process RSS** | **79.2** | **2.81 GiB** |

**The UTXO set is 77.4% of process RSS**, not the ~44% an in-flight sample
suggested. The remaining 0.64 GiB is fjall, CoinStats, the block-record log and
the runtime.

An earlier revision attributed 450 MB of that residual to the configured
`dbcache`. That was wrong: `Config::dbcache_mb` is parsed but **never reaches a
backend constructor** — `NodeStorage::open` does not pass it, fjall takes builder
defaults and RocksDB a fixed 256 MiB block cache. Issue #51 tracks it. The
residual is therefore not a configured, bounded component the way that claim
implied, and it has not been attributed.

**The synthetic harness is validated.** Re-run at the measured 3.626 outputs per
record it predicts 54.6 B/output of payload against 55.1 measured (0.9% apart)
and 62.0 accounted against 61.2 (1.3%). The v4 snapshot on disk is 57.3
B/output, a third independent path agreeing.

**Outputs per record was the assumption that mattered, and it was wrong.** The
first pass assumed 1.5; the real trajectory is 2.296 at height 183k, 3.427 at
302k, 4.056 at 390k (the 2015 UTXO-spam era) and 3.626 at 412k. It has not
converged, and the tip value is still unknown.

## Verdict

| | Tip projection, 180M outputs | Share of the 16 GiB budget |
|---|---:|---:|
| Today | **13.28 GiB** | **83%** |
| With the Step 2.2 encoding work | **9.61 GiB** | 60% |

The 17 B/output those changes remove is **28% of process RSS**, about 3.7 GiB at
tip. At 83% of budget on the UTXO path alone — before `txindex` and
`blockfilterindex`, which the G14 budget requires — that margin decides the gate.

**Step 2.2 is justified. Step 2.4 is not**: fragmentation measured 5% after
churning twice the whole set.

The projection holds outputs per record at 3.626, which has not converged and
remains the number the result is most sensitive to.

## Superseded: the pre-measurement sizing

The section below was written from the synthetic harness alone, assuming 1.5
outputs per record. It concluded encoding work was worth ~7% of process RSS and
recommended against starting it. Both inputs were wrong. Kept because the
reasoning error is the instructive part: it priced a change against a component
size that had never been measured.

Extrapolating 110 bytes/output to the ~67M outputs live at height 645,804 gives
**about 6.9 GiB** — roughly **half** of the observed 13.83 GiB. The UTXO set is
not where the other ~7 GiB is. Candidates never yet measured: fjall/RocksDB
memtables and block caches, CoinStats MuHash state, the `Vec<BlockRecord>` log,
and the sync staging budgets.

Sizing the planned encoding work against the measured layout:

| Planned change | Saving | Share of UTXO RSS |
|---|---:|---:|
| Hoist `height` + `coinbase` to the record header | 5 B/output | 4.5% |
| Compressed amounts (8 B -> ~3 B) | 5 B/output | 4.5% |
| Varint `vout` and `script_len` (6 B -> ~2 B) | 4 B/output | 3.6% |
| Core-style script compression | ~3 B/output | 2.7% |
| **Total** | **~17 B/output** | **~15%** |

Fifteen percent of a component that is itself about half of process RSS is
**roughly 7% of the number the G14 budget is written against**. The arena work in
Step 2.4 targets the 8-byte allocation header plus the fragmentation measured
above — around 10% of UTXO RSS, or ~5% of process RSS — and it is the largest and
riskiest item in the plan.

**Recommendation: do not start Step 2.2 or 2.4 on this evidence.** Neither is
wrong, both are small, and the half of the problem that has never been measured
is larger than everything they can win together. Attribute the non-UTXO half
first.

## Caveats

- **1.5 live outputs per record is an assumption**, and it is the one the result
  is most sensitive to: the 32-byte txid amortizes over it directly. At 1.2
  outputs per record the txid share rises to 26.7 B/output; at 2.0 it falls to
  16 B/output. A real distribution should be taken from a synced node before the
  encoding table above is used to make a decision.
- The script mix is representative, not measured from chainstate.
- System allocator, not the mimalloc production links.
- Whether the 13.83 GiB run had `txindex` and `blockfilterindex` enabled is not
  recorded, so the ~7 GiB residual cannot yet be split between index structures
  and everything else.
