# P2P wire contract (pointer)

The peer-wire contract lives in
[docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md). That
document is the owner: it pins Bitcoin Core 31.1, declares the transport
envelope, the handshake fields, the 36-command message surface, the
reject-or-ignore policy, and the deviation ledger. This page adds nothing
normative; it places the policy under the
[contracts precedence rule](README.md).

- **Owner**: `docs/policies/p2p-compatibility.md`.
- **Scope**: `crates/p2p` wire, handshake, FSM, message policy; the
  chain-serving adapter `crates/node/src/p2p_chain.rs`; node network flags.
- **Proven by**: `crates/p2p/tests/core_compat.rs` —
  `cargo test -p bitcoin-rs-p2p --test core_compat` pins handshake fields,
  per-network framing, relay round-trips, the reject-or-ignore matrix, and
  peer-visible reorg/restart behavior. The live interop lane
  `crates/p2p/tests/core_interop_live.rs` runs via
  `scripts/run-p2p-core-interop.sh` when a `bitcoind` is provided; it is
  ignored by default.
