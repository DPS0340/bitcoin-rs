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
The two distinct cost regimes any sync measurement must name before its numbers mean anything. **Download-bound:** wall-clock is decided by the network path (peer scheduling, per-peer bandwidth, staller handling) — the regime of live IBD. **Processing-bound:** blocks are already local and wall-clock is decided by validation plus storage commit — the regime of reindex and offline replay. A node can rank differently in the two regimes, so a faster-than-X claim is meaningless without stating which regime was measured and with what validation posture.

## Consensus validation

### bitcoinkernel
Bitcoin Core's C++ consensus engine (`libbitcoinkernel`), compiled into `bitcoin-rs` as the production consensus default across consensus, node, and binary crates. It validates input scripts across all script classes (legacy, segwit, and Taproot key-path and script-path spends). Default builds require system dependencies (`cmake` and `libboost-dev`). Production transaction and block input-script verification route to bitcoinkernel when default features are enabled, while Rust performs surrounding non-script transaction and block consensus checks; the Rust `Interpreter` remains a separate portable script-verification surface under `--no-default-features`.
### bitcoinconsensus
Removed historical script verification backend. Previously linked as an extracted C library for non-taproot script checks before being deleted in favor of `bitcoinkernel`. The library lacked complete-prevout and Taproot script-path verification capabilities required for current mainnet script validation (exposed by block 938344 during mainnet IBD).

### Rust interpreter (portable posture)
The pure-Rust script verification path maintained alongside the bitcoinkernel default. Enabled under `--no-default-features` without C++ build dependencies. It cannot validate Taproot script-path scripts (such as those past height 709635 / block 938344 on mainnet) and is retained for differential testing and lightweight non-production environments.

### Script-flag exceptions (BIP16Exception)
The historical blocks Bitcoin Core hardcodes in `consensus.script_flag_exceptions` (chainparams) to be validated under a reduced script-verification flag set, because they contain spends valid under the rules in force at the time but invalid under a later-enforced flag. As of Core v29: mainnet block 170060 (`…ac4f9c22`, the BIP16/P2SH exception) and 692261 (`…e1e395ad`, the Taproot exception); testnet3 block 394; none on testnet4/signet/regtest. The two **P2SH waivers** (170060, 394) are reproduced explicitly by `Network::is_bip16_p2sh_exception` (keyed by block hash, mainnet/testnet3 only); missing them rejects canonical blocks and wedges full-validation sync past the assume-valid height. The **692261 Taproot override** needs no rs exception: Core's override only strips TAPROOT (which Core defaults on for all blocks), and rs already height-gates taproot (`is_taproot_active`, 709632 > 692261) so it never sets TAPROOT there — its computed flags already match Core's effective set. Compare *effective* flag sets, not raw overrides. See `docs/solutions/architecture-patterns/p2sh-flag-must-honor-core-script-flag-exceptions.md`.
