# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, the inbound message dispatcher, and peer and subnet banning.

Each `Peer` owns one connection's stream and handshake state. Live connections are
identified by a `ConnectionId`, cleaned up through a `PeerLease`, and tracked with
ready metadata by the shared `PeerLifecycle`; lifecycle-owned listener entry points
open outbound connections, while the `listener` module accepts inbound TCP connections
with graceful shutdown. A connection negotiates version/verack in
`handshake`, then runs the peer finite-state machine in `fsm`; `wire` is the protocol
codec, decoding `Message` values and reporting `PeerError`. Inbound traffic reaches
the host through `dispatch_inbound_with_chain`, which serves inventory as an
`InventoryResponse` and reads the active chain through the `ChainQuery` trait, a
read-only view for server-side responders; `inbound` hands over `InboundBlock` and
`InboundHeaders` with their wire bytes preserved. Misbehaving peers are filtered by
the node-owned `BannedSubnet` policy built from an `IpSubnet`. BIP155 addrv2 and
BIP339 wtxid-relay messages are handled directly by the `wire` codec.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
