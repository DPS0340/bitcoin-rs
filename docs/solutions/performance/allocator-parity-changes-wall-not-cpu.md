# Allocator parity changes wall time, not CPU time

Status: **MEASURED.** The processing-bound 0→150,000 replay must use
production-matched mimalloc. On the same source and local block corpus,
mimalloc reduced median process wall time from 63.43s to 56.16s (1.129×), but
changed total CPU only from 399.63s to 396.50s (1.008×). It increased median
peak RSS from 573,440,000 to 664,252,416 bytes (1.158×).

The allocator was therefore a load-bearing wall-time mismatch, not the source
of the previously reported CPU deficit.

## Experiment contract

The experiment used commit `ff2615a2946cfdf980ed80ed14c0ad5986631d8a` and
built two otherwise-identical release binaries:

- system allocator: `--no-default-features --features fjall,kernel`;
- mimalloc: `--no-default-features --features fjall,kernel,mimalloc`.

Both binaries used the workspace release profile (`opt-level=3`, fat LTO, one
codegen unit, aborting panics), Rust 1.95.0, and `taskset -c 0-31`. The input was
the 688,584,209-byte local length-prefixed corpus
`/tmp/blocks-0-150000.bin`, SHA-256
`c0a2b9aa35498dacdf1aec792a1b68d9ec68e372fba88ef0e62bbccb1732fe2c`.
Every run used full verification (`assume_valid_height=0`) and a fresh fjall
data directory.

The three rounds used a Latin-square order:

1. Core, system allocator, mimalloc;
2. mimalloc, Core, system allocator;
3. system allocator, mimalloc, Core.

No compiler, other replay, or other `bitcoind` process ran with a measured arm.
A 30-second cooldown separated arms. A direct-child `wait4` runner recorded
process wall time, user CPU, system CPU, and peak RSS. Performance runs did not
request the optional UTXO validation scan.

## Three-run panel

| Arm | Process wall runs | Median wall | Median user CPU | Median system CPU | Median total CPU | Median peak RSS |
|---|---:|---:|---:|---:|---:|---:|
| bitcoin-rs, system allocator | 63.43 / 64.03 / 62.21s | **63.43s** | 364.21s | 35.42s | **399.63s** | **573,440,000 B** |
| bitcoin-rs, mimalloc | 57.39 / 56.16 / 55.73s | **56.16s** | 359.59s | 36.62s | **396.50s** | **664,252,416 B** |
| Bitcoin Core 31.0 | 67.69 / 64.73 / 64.74s | **64.74s** | 459.07s | 19.44s | **477.82s** | **680,341,504 B** |

The mimalloc arm beats the fresh Core median by 1.153× on wall time and 1.205×
on total CPU. The system-allocator arm also uses less total CPU than Core. This
falsifies the earlier premise that the current matched replay has an 87–92
CPU-second deficit. That premise came from a stale, differently matched panel.

The wall result clears the 1.05× mechanism gate. The CPU result does not:
mimalloc changes scheduling and allocation latency enough to remove 7.27s of
median wall time while saving only 3.12 CPU-seconds. The 15.8% peak-RSS increase
must remain visible in every summary.

## Correctness custody

A separate, untimed validation replay scanned the final UTXO set for each
allocator. Both allocator artifacts were byte-identical:

- stop hash: `0000000000000a3290f20e75860d505ce0e948a1d1d846bec7e39015d242884b`;
- UTXO count: 1,127,181;
- total amount: 749,989,998,999,999 sat;
- MuHash: `383a0b41ac28ddf6ac91723b41527fa64c0b54451cee5f2c4b3823ef92117116`;
- local `hash_serialized_3`: `c9c0a3928001d21a20cff79ba4163b4f0d4b4b637f10da6313bc9d310680436a`.

Bitcoin Core 31.0's height-150,000 CoinStats index returned the same stop hash,
UTXO count, total amount, and MuHash. Core cannot query historical
`hash_serialized_3`, so the cross-node oracle is MuHash; the two bitcoin-rs
allocator arms still match each other on both commitments.

## Decision

1. Use mimalloc for all later replay controls because the production binary
   already uses it and the wall effect is material.
2. Preserve the system-allocator panel. Mimalloc's wall win costs 15.8% peak
   RSS and does not clear the CPU gate.
3. Do not start CPU attribution to close a deficit that the matched panel
   falsified. Reopen attribution only after a fresh panel shows a gate-sized
   bitcoin-rs CPU loss.
4. Continue independent wall candidates only against the 56.16s / 396.50s
   mimalloc baseline. Each must still clear 1.05× on a whole-process axis and
   preserve the other axis plus correctness.
5. The fjall panel now beats Core on both required axes. RocksDB and redb remain
   separate final gates; this result does not stand in for them.

The machine-readable source of record is
[`allocator-custody-v1.json`](../../benchmarks/data/end-to-end-sync/allocator-custody-v1.json).
