---
title: P2SH (and every script flag) must honor Core's script_flag_exceptions, not be hardcoded
date: 2026-06-14
category: docs/solutions/architecture-patterns
module: crates/node
problem_type: logic_error
component: tooling
severity: high
symptoms:
  - "Full-validation sync wedges at a fixed mainnet height (170060) with 'kernel script verification failed at input 0', retrying the same block forever"
  - "A block libbitcoinkernel/bitcoinconsensus rejects that Bitcoin Core accepts on the same chain"
  - "The wedge never appears in assume-valid benchmarks because they stop at or below the assume-valid height"
root_cause: logic_error
resolution_type: code_fix
related_components:
  - consensus
  - script-verification
  - network-params
tags:
  - p2sh
  - bip16
  - bip16exception
  - script-flag-exceptions
  - consensus
  - softfork-activation
  - kernel
  - bitcoinconsensus
  - assume-valid
  - byte-order
---

# P2SH (and every script flag) must honor Core's script_flag_exceptions, not be hardcoded

## Problem

`compute_verify_flags` (`crates/node/src/apply.rs`) built the per-block script-verification flag set
by seeding P2SH **unconditionally**:

```rust
// P2SH (BIP16) is effectively always-on for supported validation paths.
let mut flags = VerifyFlags::P2SH;
```

Every *other* softfork in the same function was correctly height-gated (`is_bip66_active`,
`is_bip65_active`, CSV, SegWit, `is_taproot_active`). P2SH was the lone hardcoded flag. The comment
was *almost* right — P2SH is effectively always-on **except for the blocks Bitcoin Core hardcodes in
`consensus.script_flag_exceptions`**. Missing those exceptions made the node reject real, canonical
mainnet/testnet3 blocks and wedge.

## Symptoms

- A full-validation run (assume-valid height passed, scripts actually executing) reaches mainnet
  height 170059, then loops forever on height 170060
  (`00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22`) with
  `consensus: script verification failed at input 0: kernel script verification failed`. Observed:
  ~477k identical retries over ~30h, ~15-19% CPU per node.
- libbitcoinkernel is **Core's own validator**, so it never rejects a block Core accepts — the fault
  is rs handing it the wrong *flags* (or wrong prevout) for that block.

## What didn't work / what masked it

- **assume-valid benchmarks hid it for the entire campaign.** Every A/B run used
  `--assume-valid-height 150000` and measured only to height 150000, so scripts were skipped below
  the wall and the run "succeeded." The wedge sits at 170060, just past the measured window — it only
  surfaced because two benchmark node processes were left running *past* the assume-valid height into
  full verification. **Any bench that syncs past the assume-valid height exercises code the benchmark
  number never covers.**

## Solution

Block 170060 is Core's mainnet `consensus.BIP16Exception`: it contains a P2SH-template spend
(`OP_HASH160 <h> OP_EQUAL`) that is valid as a bare script but invalid under P2SH rules, so Core
grandfathers exactly that one block from P2SH enforcement. Core also has a second mainnet exception
(692261, the "Taproot exception") and a testnet3 exception (block 394). Gate the P2SH flag on a
network-keyed predicate, keyed by **block hash** (not height — a fork block at the same height must
still enforce P2SH), mirroring Core:

```rust
// crates/primitives/src/network.rs
pub fn is_bip16_p2sh_exception(self, block_hash: Hash256) -> bool {
    match self {
        Self::Mainnet => block_hash == BIP16_EXCEPTION_MAINNET,   // block 170060
        Self::Testnet3 => block_hash == BIP16_EXCEPTION_TESTNET3, // block 394
        _ => false,                                               // Core has none elsewhere
    }
}

// crates/node/src/apply.rs — compute_verify_flags
let mut flags = VerifyFlags::NONE;
if !network.is_bip16_p2sh_exception(block_hash) {
    flags = flags.union(VerifyFlags::P2SH);
}
// ...all other softforks unchanged...
```

The block hash is already computed at the top of `apply_block`
(`Hash256::from_le_bytes(block.block_hash().as_byte_array())`); thread it into
`compute_verify_flags`. `compute_verify_flags` is the single chokepoint feeding `verify_block_transactions`,
so the fix covered every backend at the time uniformly: the kernel, the
since-removed `bitcoinconsensus` path, and the Rust interpreter.

Commits: `49bf5cd` (mainnet fix + unit tests), `de97248` (end-to-end regression test), `badf017`
(testnet3 exception).

### Byte-order trap

The exception constant is a `Hash256` stored in **consensus little-endian** — the display/RPC hash
string reversed byte-wise (`bitcoin::BlockHash::as_byte_array()` returns internal LE, the reverse of
the `0000…` display form). Derive the constant programmatically (reverse the display hex), never by
eye. Lock orientation in a test that derives the same hash by an **independent** path —
`"0000…".parse::<bitcoin::BlockHash>()?.as_byte_array()` — so a transcription error fails the test
instead of silently shipping a constant that matches nothing.

## Why this works

Core's `GetBlockScriptFlags` (`src/validation.cpp`) is:

```cpp
uint32_t flags{P2SH | WITNESS | TAPROOT};        // base: these three default ON for all blocks
if (script_flag_exceptions.count(hash)) flags = exception_value;  // FULL override
if (DERSIG active) flags |= DERSIG;              // re-OR the height-gated ones back in
if (CLTV active)   flags |= CLTV;
if (CSV active)    flags |= CSV;
if (SEGWIT active) flags |= NULLDUMMY;
```

The exception is a full override of the base `{P2SH, WITNESS, TAPROOT}` set, after which the
height-gated flags are re-added. For block 170060 the override is `SCRIPT_VERIFY_NONE` and nothing
re-adds (all softforks inactive at 170060) → effective `NONE`, which the rs exception reproduces.

## Why mainnet block 692261 is NOT a second bug (the non-obvious part)

Core's second mainnet exception, block 692261 (`…e1e395ad`, "Taproot exception"), overrides to
`P2SH | WITNESS`. It is tempting to conclude Core *waives* DERSIG/CLTV/CSV/NULLDUMMY there and that rs
(which sets them) is stricter → a second wedge. **Wrong.** The override strips only **TAPROOT** (which
Core's base initializer turns on for every block); DERSIG/CLTV/CSV/NULLDUMMY are re-OR'd back in
immediately after the override, so Core's effective flags at 692261 are
`P2SH|WITNESS|DERSIG|CLTV|CSV|NULLDUMMY`. rs uses the **structural inverse**: it never defaults TAPROOT
on, it *height-gates* it (`is_taproot_active`, activation 709632), and 692261 < 709632, so rs never
sets TAPROOT there and has nothing to strip. rs's computed flags equal Core's effective flags
byte-for-byte. No exception entry is needed on the additive-construction side — *for this block*.

This is the load-bearing insight: **an additive height-gated flag construction and Core's
strip-from-a-loaded-default construction converge only when the exception's net effect is to remove a
flag the additive side wouldn't have set yet.** A `script_flag_exception` whose net effect removes a
flag that *is* active at that height (e.g. the 170060 P2SH waiver) DOES require an explicit exception
in the additive model. Always reason about the *effective* flag set on both sides, never the raw
override value.

## Prevention

When touching softfork activation or script flags, audit against Core's pinned
`src/kernel/chainparams.cpp` and `src/validation.cpp::GetBlockScriptFlags`:

1. **No script flag is unconditional.** Every flag is either height-gated against a per-network
   activation, or governed by a `script_flag_exceptions` entry. A hardcoded `VerifyFlags::X` seed is a
   smell — P2SH was the one that slipped through.
2. **Enumerate every `script_flag_exceptions` entry on every network.** As of Core v29: mainnet
   {170060 → NONE, 692261 → P2SH|WITNESS}, testnet3 {394 → NONE}; testnet4/signet/regtest have none.
   Key them by **block hash**, mainnet-and-testnet3-only.
3. **Compare effective flag sets, not raw overrides** (see the 692261 analysis above).
4. **Benchmarks that stop at the assume-valid height do not exercise full script verification past
   it.** A green assume-valid IBD number is not evidence the node can validate the chain above that
   height. To prove a post-AV consensus fix end-to-end, either run a real sync past the wall or write
   a verifier-level test that feeds the production flag function into the real script backend (see
   `de97248`).
5. The orientation-lock test pattern (independent `BlockHash` parse) is mandatory for any hardcoded
   consensus hash constant.

## Related

- [script-verification-delegated-to-core-c-no-rust-headroom.md](script-verification-delegated-to-core-c-no-rust-headroom.md) — why script verification runs Core's
  C engine in the first place (the reason a flag mismatch surfaces as a *kernel* rejection).
- CONCEPTS.md → Consensus validation (bitcoinkernel, bitcoinconsensus, script-flag exceptions).
