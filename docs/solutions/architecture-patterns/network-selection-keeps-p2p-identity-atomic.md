# Network selection keeps P2P identity atomic

## Problem

A fork network can reuse Bitcoin consensus history without joining Bitcoin's
P2P network. Describing that deployment as independent `network`, `p2p_magic`,
`connect`, and `dns_seeds_enabled` settings makes partially applied profiles
possible. In particular, mainnet DNS seeds combined with a fork message start
cannot bootstrap successfully, while omitting the custom message start joins
the wrong P2P network.

## Decision

The internal `Network` remains the consensus-rule selector. The user-facing
`BITCOIN_RS_NETWORK`/`--network` selection applies consensus and P2P bootstrap
defaults as one unit and additionally accepts `drynet4`. Configuration keeps
its normal precedence:

1. built-in defaults;
2. Bitcoin-compatible configuration;
3. TOML;
4. environment variables;
5. CLI arguments.

Within a layer, the network selection is applied first and explicit low-level
fields then override it. This makes the safe profile the short path without removing the
escape hatches needed for private peers and experiments.

The `drynet4` selection shares Bitcoin mainnet history through height 961631,
resets the height 961632 difficulty target once to mainnet's PoW limit
(`1d00ffff`), uses P2P magic `eca5d404`, connects to
`drynet4.drivechain.dev:8533`, and disables DNS seeding. The reset matches the
`EcashHeight` rule in the canonical `ecash-com/bitcoin` `drynet4` branch; later
retargets resume the ordinary mainnet calculation. Standard network names
select their matching consensus network, built-in message start, and DNS
bootstrap. Compose uses the same `BITCOIN_RS_NETWORK` for bitcoin-rs and the
BIP300/301 enforcer and includes it in both host data paths.

Fixed-peer hostnames remain unresolved in configuration and are resolved by
the P2P bootstrap worker on each retry. A transient resolver failure therefore
does not reject otherwise valid configuration or prevent the node from
starting, and all addresses returned for an endpoint remain eligible to dial.

## Guardrails

- A raw P2P magic override still requires mainnet consensus, a fixed peer, and
  disabled DNS seeds.
- The one-time difficulty reset travels with the `drynet4` preset through live
  header sync, block application, and checkpoint restoration. It is not a
  generic relaxation of mainnet `nBits` validation.
- Explicit fields in the same or a later layer override network-derived values.
- Switching networks switches data directories; it does not reuse another P2P
  network's runtime state.
