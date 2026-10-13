# BIP support matrix

The BIPs materially implemented by the merged default branch, grouped by
area. This page is the human-readable coverage map the adoption policy
requires ([policies/bip-adoption.md](policies/bip-adoption.md)); per-surface
external-evidence status lives in [api/ecosystem-compat.toml](api/ecosystem-compat.toml).

Status vocabulary:

- **Shipped** — actual shipped behavior on the default branch for the stated scope.
- **Partial** — shipped for part of the BIP; the note names the missing part.
- **Experimental** — present but default-off or draft-pinned; not a
  production-ready commitment.
- **Planned** — open PR or issue only. Does not count toward shipped totals.
- **Unsupported** — not implemented; a policy or registry row names the gap.

`Externally verified` is a separate axis: only a recorded run of an unmodified
external consumer (pinned Bitcoin Core, kyoto, a wallet) upgrades a row, never
an in-tree test. Rows below state which level their evidence reached.

## Consensus and script

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 9 (versionbits) | Shipped | CSV/Segwit deployments over MTP windows; `DeploymentState` machine | `crates/consensus/src/bip9.rs` unit tests; activation offsets in `crates/primitives/src/network.rs` tests |
| 125 (RBF) | Shipped | Opt-in signaling (rule 0, `sequence < 0xfffffffe`) plus replacement rules 1–6 with descendant sweeps; default `full_rbf` is a recorded deviation | `crates/mempool/src/entry.rs`, `rbf.rs`; `crates/rpc/tests/policy_contract.rs` |
| 16 (P2SH) | Shipped | Enforced from Core's activation heights minus the grandfathered block-170060/394 exceptions | `Network::is_bip16_p2sh_exception`; differential acceptance cases |
| 34 (coinbase height) | Shipped | Enforced from Core's activation heights; BIP34-implies-BIP30 recheck limit | `crates/consensus/src/bip34.rs`; `crates/chainstate/src/connect.rs` |
| 65 (CLTV) | Shipped | Enforced from Core's activation heights | `crates/consensus/src/verify_block.rs` flags; script interpreter `OP_CHECKLOCKTIMEVERIFY` |
| 66 (strict DER) | Shipped | Enforced from Core's activation heights | `crates/consensus/src/verify_block.rs` flags; `tx_valid`/`tx_invalid` vectors |
| 68/112/113 (CSV) | Shipped | Relative locks over MTP; BIP9 deployment | `crates/consensus/src/bip68.rs`; `crates/chainstate/src/connect.rs`; `shared_sighash` |
| 94 (timewarp) | Shipped | Testnet4-enforced candidate-timestamp floor at retarget boundaries | `crates/chain/src/header_sync.rs`; `rejects_testnet4_bip94_timewarp_candidate`; `crates/chain/tests/header_sync_roundtrip.rs` |
| 141 (segwit block/tx) | Shipped | Commitment selection, weight bound, sigop accounting | `crates/consensus/src/verify_block.rs`; `witness_commitment_rules.rs`; `witness_sigop_activation.rs` |
| 143 (segwit v0 sighash) | Shipped | Native BIP143 digests | `crates/primitives/tests/bip_vectors.rs`; `shared_sighash.rs` |
| 147 (NULLDUMMY) | Shipped | WITNESS flag carries NULLDUMMY | `crates/script/src/eval.rs`; `verify_block.rs` |
| 320 (pay-to-contract) | Unsupported | BIP341 key-path spends embed the TapTweak contract; a dedicated BIP320 tool surface is out of scope | — |
| 341 (taproot) | Shipped | Height-gated TAPROOT flag; key-path and script-path execution | `crates/script/src/interpreter.rs`, `taproot.rs`; BIP341 wallet vectors in `bip_vectors.rs` |
| 342 (tapscript) | Shipped | `OP_SUCCESSx`, NUMS exclusion, BIP340 tagged hashes | `crates/script/src/eval.rs`, `taproot.rs` |
| 431 (TRUC v3) | Shipped | v3 standardness, topology/sibling/ephemeral-spend rules | `crates/mempool/src/truc.rs`; `crates/mempool/src/package.rs` |

## P2P and network

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 111 (NODE_BLOOM) | Partial | `filterload`/`filteradd`/`filterclear`/`merkleblock` decode but are ignored; `NODE_BLOOM` is not advertised | `crates/p2p/src/wire.rs`; policy §5 message table |
| 130 (sendheaders) | Shipped | Handshake negotiation; headers-first announcements up to 8 headers | `crates/p2p/src/block_announce.rs`; `assert_block_announcements` live lane |
| 133 (feefilter) | Shipped | Per-connection outbound inventory filter; rounded local floors on refresh | `crates/p2p/src/tx_policy/relay.rs`; policy §5 |
| 144 (segwit relay) | Shipped | `MSG_WITNESS_BLOCK`/`MSG_WITNESS_TX` preserve stored witness bytes | `crates/p2p/src/dispatch.rs`; `getdata_block_encoding_matches_requested_inventory_on_wire` |
| 152 (compact blocks) | Shipped(verified) | Low/high-bandwidth relay, reconstruction, `getblocktxn` bounds, stale-block serving | `crates/p2p/src/compact_blocks.rs`; `assert_bip152_relay` in `crates/p2p/tests/core_interop_live.rs` against pinned Core 31.1 |
| 155 (addrv2) | Shipped | Wire decode with 1,000-entry bound; non-IP transports ignored at admission | `crates/p2p/src/wire.rs` `decode_addrv2`; `crates/p2p/src/listener.rs` learn path |
| 157/158 (compact filters) | Planned | Open PR builds BIP158 basic filters and `getblockfilter`/`getcf*` serving behind `--blockfilterindex` | PR #1554; issue #1502. Not shipped |
| 159 (NODE_NETWORK_LIMITED) | Shipped | Pruned nodes advertise `NETWORK_LIMITED` + `WITNESS` | `crates/node/src/state_open.rs`; `pruned_version_message_advertises_network_limited_only` |
| 324 (v2 transport) | Experimental | Full v2 key exchange, packet framing, v1 fallback behind `v2transport` (off by default) | `crates/p2p/src/bip324*`, `transport.rs`; BIP324 CSV vectors. Live bidirectional Core 31.1 evidence pending; policy §2 still records v1-only as the shipped default |
| 330 (Erlay) | Unsupported | Backlog/watch; no `sendtxrcncl` (decoded unknown, ignored) | `crates/p2p/src/compat.rs`; issue #1501 |
| 339 (wtxid relay) | Shipped | Handshake negotiation; wtxid-based announcements and `getdata` | `crates/p2p/src/peer.rs` `WtxidRelayState`; dispatch tests |
| 35 (mempool request) | Partial | `mempool` decoded then ignored (a recorded silent deviation from Core) | `crates/p2p/src/dispatch.rs`; policy §5 |

## Mining

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 22 (getblocktemplate) | Shipped | Template contract incl. proposal mode without PoW; BIP23 `submitold`/`workid` extras not emitted | `crates/mining/src/bip22.rs`; `crates/mining/tests/template_shape.rs`; RPC `mining_fixture` |
| 23 (GBT extensions) | Partial | Long-poll ID, `vbavailable`/`version_bits_available` exposed; `submitold`/`workid` extras absent by design | `crates/mining/src/coordinator.rs`; RPC mining tests |
| 141/152 integration | Shipped | Template witness commitment and coinbase rules | `crates/mining/src/coinbase.rs`; `coinbase_template.rs` |

## Wallet, index, and application

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 32 (BIP32 derivation) | Partial | `getdescriptorinfo`/`deriveaddresses` over `miniscript` descriptors; no in-node wallet key custody | `crates/rpc/src/handlers/util.rs` BIP32 test-vector 1 checks |
| 173/350 (segwit bech32 addresses) | Shipped | Address rendering for valid scripts through the wallet-free surface | `crates/rpc/src/convert.rs` `script_address`; projection fixture checks |
| 379/380 (output descriptors) | Partial | Fixed addr/raw/pkh/wpkh/sh(wpkh)/key-only tr descriptors incl. checksum; wildcard/multipath expansion unsupported | `getdescriptorinfo`, `deriveaddresses`, and `scantxoutset` handlers (`crates/rpc/src/handlers/util.rs`, `BIP380_INPUT_CHARSET` guards); `decodescript` notes |
| 352 (Silent Payments) | Planned | Keyless scan codec in an open PR; tweak service stays an issue | PR #1559; issue #1491. Not shipped |
| 324 aux vectors | Shipped(verified) | ellswift decode + packet-encoding CSV vectors from the pinned BIP commit | `crates/p2p/tests/data/bip324/` (SHA-256 pinned); `crates/p2p/src/bip324.rs` vector tests |

## Out of scope by policy

The adoption policy's wallet-only class: BIP 174 (PSBT signing roles beyond
the key-free combine/finalize helpers), BIP 380 hosted models, BIP 300/301
sidechains (run through the separate enforcer tool), and mnemonic/seed
handling (BIP 39) never become node features without a policy change.

## BIP adoption and coverage

BIP capabilities follow [policies/bip-adoption.md](policies/bip-adoption.md):
classification, the evidence-based adoption decision, opt-in/default rules,
and the lifecycle. This page is that policy's coverage map; per-surface
external evidence stays in [api/ecosystem-compat.toml](api/ecosystem-compat.toml).
Neither page duplicates a status table owned elsewhere.

## Update checklist

Update this page in the same change-set as any BIP-related capability change:

1. Verify the status against the merged default branch, not a PR head.
2. Confirm the evidence link names a test or script present in the tree.
3. Keep `Planned` rows out of shipped counts; promote only with the lifecycle
   evidence the policy defines.
4. Record external-consumer runs in `api/ecosystem-compat.toml` (`ECO-08`), not
   here; cite that row from the evidence column.
