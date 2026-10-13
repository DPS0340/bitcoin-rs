# BIP support matrix

The BIPs materially implemented by the merged default branch, grouped by
area. This page is the human-readable coverage map the adoption policy
requires ([policies/bip-adoption.md](policies/bip-adoption.md)); per-surface
external-evidence status lives in [api/ecosystem-compat.toml](api/ecosystem-compat.toml).

Status vocabulary:

- **Shipped** — actual shipped behavior on the default branch for the stated scope.
- **Partial** — shipped for part of the BIP; the note names the missing part.
- **Implemented; externally verified (scoped)** — a cell convention (not a new
  status class) for rows whose live evidence is recorded but scoped: the
  implementation stands, and the `evidence` column names the exact black-box
  outcomes (`ECO-09` limits log-derived counts to diagnostics). Used only
  where a live, unmodified external consumer exercised the row.
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
| 125 (RBF) | Partial | Replacement policy ships as full-RBF: signaling does not determine admission (`docs/policies/mempool-policy.md` §3, `crates/mempool/src/policy.rs` `full_rbf: true`); BIP125 metadata (`sequence < 0xfffffffe`, `crates/mempool/src/entry.rs`) remains for reporting. BIP125's signal-gated opt-in replacement is therefore not shipped; the recorded deviation is the replacement policy itself | `replacement_signaling_matches_pinned_core`; `crates/rpc/tests/policy_contract.rs` |
| 16 (P2SH) | Shipped | Enforced for every block except the two hash-pinned Core grandfathered exceptions (mainnet 170060, testnet3 394); not height-gated | `Network::is_bip16_p2sh_exception` (`crates/primitives/src/network.rs`); `verify_flags` in `crates/consensus/src/verify_block.rs`; differential acceptance cases |
| 34 (coinbase height) | Shipped | Enforced from Core's activation heights; BIP34-implies-BIP30 recheck limit | `crates/consensus/src/bip34.rs`; `crates/chainstate/src/connect.rs` |
| 65 (CLTV) | Shipped | Enforced from Core's activation heights | `crates/consensus/src/verify_block.rs` flags; script interpreter `OP_CHECKLOCKTIMEVERIFY` |
| 66 (strict DER) | Shipped | Enforced from Core's activation heights | `crates/consensus/src/verify_block.rs` flags; `tx_valid`/`tx_invalid` vectors |
| 68/112/113 (CSV) | Shipped | Relative locks over MTP; BIP9 deployment | `crates/consensus/src/bip68.rs`; `crates/chainstate/src/connect.rs`; `shared_sighash` |
| 94 (timewarp) | Shipped | Testnet4-enforced candidate-timestamp floor at retarget boundaries | `crates/chain/src/header_sync.rs`; `rejects_testnet4_bip94_timewarp_candidate`; `crates/chain/tests/header_sync_roundtrip.rs` |
| 141 (segwit block/tx) | Shipped | Commitment selection, weight bound, sigop accounting | `crates/consensus/src/verify_block.rs`; `witness_commitment_rules.rs`; `witness_sigop_activation.rs` |
| 143 (segwit v0 sighash) | Shipped | Native BIP143 digests | `crates/primitives/tests/bip_vectors.rs`; `shared_sighash.rs` |
| 147 (NULLDUMMY) | Shipped | WITNESS flag carries NULLDUMMY | `crates/script/src/eval.rs`; `verify_block.rs` |
| 320 (nVersion general-purpose bits) | Unsupported | No policy exists for general-purpose nVersion use; candidates carry only versionbits bits | `candidate_version` in `crates/chain/src/deployment.rs` |
| 341 (taproot) | Shipped | Height-gated TAPROOT flag; key-path and script-path execution | `crates/script/src/interpreter.rs`, `taproot.rs`; BIP341 wallet vectors in `bip_vectors.rs` |
| 342 (tapscript) | Shipped | `OP_SUCCESSx` handling and BIP340 tagged hashes; consensus-valid tapscript execution | `crates/script/src/eval.rs`, `taproot.rs` |
| 431 (TRUC v3) | Shipped | v3 standardness, topology/sibling/ephemeral-spend rules | `crates/mempool/src/truc.rs`; `crates/mempool/src/package.rs` |

## P2P and network

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 37 (bloom filters) | Partial | `filterload`/`filteradd`/`filterclear`/`merkleblock` decode then are ignored; `NODE_BLOOM` is not advertised so a default Core peer never sends them (a recorded deviation) | `crates/p2p/src/wire.rs`; policy §5 message table |
| 111 (NODE_BLOOM) | Unsupported | The `NODE_BLOOM` service bit is never advertised | `crates/p2p/src/wire.rs`; policy §5 |
| 130 (sendheaders) | Shipped | Handshake negotiation; headers-first announcements up to 8 headers | `crates/p2p/src/block_announce.rs`; `assert_block_announcements` live lane |
| 133 (feefilter) | Shipped | Per-connection outbound inventory filter; rounded local floors on refresh | `crates/p2p/src/tx_policy/relay.rs`; policy §5 |
| 144 (segwit relay) | Shipped | `MSG_WITNESS_BLOCK`/`MSG_WITNESS_TX` preserve stored witness bytes | `crates/p2p/src/dispatch.rs`; `getdata_block_encoding_matches_requested_inventory_on_wire` |
| 152 (compact blocks) | Implemented; externally verified (scoped) | Low/high-bandwidth relay, reconstruction, `getblocktxn` bounds, stale-block serving. Live evidence is scoped to the `CORE-03` black-box outcomes; reconstruction/recovery counts are log-derived and diagnostic only (`ECO-09`) | `crates/p2p/src/compact_blocks.rs`; `assert_bip152_relay` in `crates/p2p/tests/core_interop_live.rs` against pinned Core 31.1 |
| 155 (addrv2) | Partial | Wire decode with 1,000-entry bound and non-IP transports ignored at admission ship; `sendaddrv2` is negotiated and tracked, but `getaddr` still answers with legacy `addr` (`crates/p2p/src/listener.rs` gossip path), so the send-side `addrv2` response is not shipped | `crates/p2p/src/wire.rs` `decode_addrv2`; `crates/p2p/src/listener.rs` learn path and `getaddr` arm |
| 157/158 (compact filters) | Planned | Open PR builds BIP158 basic filters and `getblockfilter`/`getcf*` serving behind `--blockfilterindex` | PR #1554; issue #1502. Not shipped |
| 159 (NODE_NETWORK_LIMITED) | Shipped | Pruned nodes advertise `NETWORK_LIMITED` + `WITNESS` | `crates/node/src/state_open.rs`; `pruned_version_message_advertises_network_limited_only` |
| 324 (v2 transport) | Planned | v2 key exchange, packet framing, and v1 fallback exist in the tree behind `v2transport` (off by default), with in-tree vector/negotiation tests; the authoritative P2P policy still records v1-only as the shipped transport and live bidirectional Core 31.1 evidence is pending | `crates/p2p/src/bip324*`, `transport.rs`; `crates/p2p/src/listener/v2_transport_tests.rs`; policy §2 |
| 330 (Erlay) | Unsupported | Backlog/watch; no `sendtxrcncl` (decoded unknown, ignored) | `crates/p2p/src/compat.rs`; issue #1501 |
| 339 (wtxid relay) | Shipped | Handshake negotiation; wtxid-based announcements and `getdata` | `crates/p2p/src/peer.rs` `WtxidRelayState`; dispatch tests |
| 35 (mempool request) | Partial | `mempool` decoded then ignored (a recorded silent deviation from Core) | `crates/p2p/src/dispatch.rs`; policy §5 |

## Mining

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 22 (getblocktemplate) | Shipped | Template contract incl. proposal mode without PoW; BIP23 `submitold`/`workid` extras not emitted | `crates/mining/src/bip22.rs`; `crates/mining/tests/template_shape.rs`; RPC `mining_fixture` |
| 23 (GBT extensions) | Partial | Long-poll ID, `vbavailable`/`version_bits_available` exposed; `submitold`/`workid` extras absent by design | `crates/mining/src/coordinator.rs`; RPC mining tests |
| 141 (template witness commitment) | Shipped | Template builds the BIP141 witness commitment and coinbase rules | `crates/mining/src/coinbase.rs`; `coinbase_template.rs` |

## Wallet, index, and application

| BIP | bitcoin-rs | Scope | Evidence |
| :--- | :--- | :--- | :--- |
| 32 (BIP32 derivation) | Shipped | `getdescriptorinfo` expands multipath descriptors (`combo_multipath_is_expanded`) and `deriveaddresses` derives one address per range index (`a_ranged_descriptor_derives_one_address_per_index`); no in-node wallet key custody | `crates/rpc/src/handlers/util.rs` `deriveaddresses_tests` incl. BIP32 test-vector 1 and Core `rpc_deriveaddresses.py` combo regtest vectors |
| 173/350 (segwit bech32 addresses) | Shipped | Address rendering for valid scripts through the wallet-free surface | `crates/rpc/src/convert.rs` `script_address`; projection fixture checks |
| 379/380 (output descriptors) | Shipped | Full Core descriptor set through `getdescriptorinfo`/`deriveaddresses` incl. multipath and wildcard/range expansion with checksums; the measured limitation is `scantxoutset` only, which rejects ranged/multipath forms (a recorded deviation) | `getdescriptorinfo`, `deriveaddresses`, and `scantxoutset` handlers (`crates/rpc/src/handlers/util.rs`, `BIP380_INPUT_CHARSET` guards, ranged/multipath tests); `decodescript` notes |
| 352 (Silent Payments) | Planned | Keyless scan codec in an open PR; tweak service stays an issue | PR #1559; issue #1491. Not shipped |
| 324 aux vectors | Implemented; externally verified (scoped) | ellswift decode + packet-encoding CSV vectors, verbatim copies from the pinned bitcoin/bips commit; vector-data equivalence only, not transport interop | `crates/p2p/tests/data/bip324/` (SHA-256 pinned); `crates/p2p/src/bip324.rs` vector tests |

## Out of scope by policy

The adoption policy's wallet-only class filters the candidate list. Hosted
remote-scanner models come from the WIP BIP352 index-server design (#1491),
not from BIP380; BIP380 itself covers only output descriptors and checksums.
BIP 174 (PSBT signing roles beyond the key-free combine/finalize helpers),
BIP 300/301 sidechains (run through the separate enforcer tool), and
mnemonic/seed handling (BIP 39) never become node features without a policy
change.

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
