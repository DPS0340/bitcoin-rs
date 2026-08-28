//! Machine-readable compatibility manifest for every external surface this
//! node exposes, declared against Bitcoin Core 31.x.
//!
//! [`MANIFEST`] is the single source of truth for the dispatcher: a JSON-RPC
//! method answers only when a non-`Unimplemented` RPC row carries its name,
//! so the manifest cannot drift from what actually dispatches. The coverage
//! gate (`crates/rpc/tests/manifest_coverage.rs`) proves the other
//! direction — it asserts set equality between the dispatcher's live
//! registry and the shipped rows in both directions — and regenerates
//! `docs/rpc-reference.md` from this table.
//!
//! Row semantics:
//! - `status`: [`Status::Implemented`] ships shape-compatible with Core;
//!   [`Status::Deviation`] ships with a recorded difference (the `notes`
//!   field cites the source file carrying it); [`Status::Extension`] has no
//!   Core counterpart; [`Status::Unimplemented`] is Core surface this node
//!   does not expose.
//! - `feature`: cargo feature that must be active for the surface to exist
//!   (empty for always-compiled surfaces).
//! - `core_version`: the Core contract version the row is declared against.
//! - `since`: the bitcoin-rs version whose surface the row describes;
//!   `pending` marks rows whose implementation lands in a later change.
//!
//! The `Unimplemented` JSON-RPC set was audited against Bitcoin Core v31.0
//! source command tables (`src/rpc/*.cpp`, `src/wallet/rpc/*.cpp`,
//! `src/rest.cpp` `StartREST`, `src/zmq/zmqpublishnotifier.cpp`) — the same
//! registrations Core's `help` output prints. Hidden test/administration
//! commands (`echo*`, `setmocktime`, `mockscheduler`, `addconnection`,
//! `addpeeraddress`, `sendmsgtopeer`, `getrawaddrman`,
//! `syncwithvalidationinterfacequeue`, the `generate*` family, `getorphantxs`,
//! `getmempoolfeeratediagram`) are intentionally absent from the table.

use std::format;
use std::string::String;

/// Transport kind of a manifest row.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum SurfaceKind {
    /// JSON-RPC method dispatched by [`crate::handlers::Handler`].
    Rpc,
    /// Core-registered REST route prefix under `/rest/`.
    Rest,
    /// ZMQ PUB notification topic.
    Zmq,
}

impl SurfaceKind {
    /// Lower-case label used in the generated reference.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Rpc => "json-rpc",
            Self::Rest => "rest",
            Self::Zmq => "zmq",
        }
    }

    /// Section heading used in the generated reference.
    #[must_use]
    pub const fn heading(self) -> &'static str {
        match self {
            Self::Rpc => "JSON-RPC methods",
            Self::Rest => "REST endpoints",
            Self::Zmq => "ZMQ topics",
        }
    }
}

/// Compatibility status of one surface.
///
/// Declaration order is also the section order of the generated reference.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Status {
    /// Shipped and shape-compatible with the Core contract.
    Implemented,
    /// Shipped with a recorded difference from Core; notes cite the source.
    Deviation,
    /// bitcoin-rs-specific surface with no Core counterpart.
    Extension,
    /// Core surface this node does not expose.
    Unimplemented,
}

impl Status {
    /// Label used in the generated reference.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Implemented => "Implemented",
            Self::Deviation => "Deviation",
            Self::Extension => "Extension",
            Self::Unimplemented => "Unimplemented",
        }
    }
}

/// One declared surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry {
    /// JSON-RPC method name, REST route prefix (`/rest/...`), or ZMQ topic.
    pub name: &'static str,
    /// Transport the surface is spoken over.
    pub kind: SurfaceKind,
    /// Compatibility with the Core contract.
    pub status: Status,
    /// Cargo feature that must be active; empty for always-compiled rows.
    pub feature: &'static str,
    /// Core contract version the row is declared against.
    pub core_version: &'static str,
    /// Deviation/extension rationale, citing the source file when the surface
    /// differs from Core.
    pub notes: &'static str,
    /// bitcoin-rs version whose surface the row describes; `pending` marks
    /// not-yet-landed rows.
    pub since: &'static str,
}

impl Entry {
    /// True when the surface exists in this build: its feature is compiled
    /// in, its status is not `Unimplemented`, and it is not a `pending`
    /// contract-only row. Mirrors registration.
    #[must_use]
    pub fn shipped(self) -> bool {
        self.status != Status::Unimplemented
            && self.since != "pending"
            && feature_active(self.feature)
    }
}

/// Core contract version every row is declared against.
pub const CORE_VERSION: &str = "31.x";

/// No-wallet policy note shared by every wallet-class row; the crate refuses
/// to hold private key material (see `crates/rpc/src/lib.rs`).
const NO_WALLET: &str =
    "No wallet: this process holds no private-key material (crates/rpc/src/lib.rs).";

/// Every external surface, declared against Core 31.x.
///
/// JSON-RPC rows keep the dispatcher's registration order; `Unimplemented`
/// rows follow Core's own category grouping. The dispatcher consumes this
/// table, so an added row without a matching `dispatch` arm fails the
/// coverage gate instead of panicking a live request.
pub const MANIFEST: &[Entry] = &[
    // -- JSON-RPC: shipped methods (registration order) --------------------
    Entry {
        name: "getblockchaininfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getdifficulty",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getchaintips",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getchaintxstats",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblockcount",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblockhash",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getbestblockhash",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblock",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblockheader",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblockstats",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "verifychain",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "gettxoutsetinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getindexinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblockfilter",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Requires the --blockfilterindex runtime toggle; without it the handler answers the Core 'Index is not enabled' error (crates/rpc/src/handlers/chain.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "pruneblockchain",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "invalidateblock",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "scantxoutset",
        kind: SurfaceKind::Rpc,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Accepts only addr() scan descriptors; Core supports the full descriptor set (crates/rpc/src/handlers/chain.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "getrawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "gettxout",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "gettxoutproof",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "verifytxoutproof",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "sendrawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "testmempoolaccept",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "decoderawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "createrawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "combinepsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "finalizepsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmempoolinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmempoolentry",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getrawmempool",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmempoolancestors",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmempooldescendants",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "estimatesmartfee",
        kind: SurfaceKind::Rpc,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No estimate_mode handling: Core parses the mode string and rejects unknown values with -8; conf_target is not range-checked against Core's 1-1008 (crates/rpc/src/handlers/util.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "uptime",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getrpcinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmemoryinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "mode=mallocinfo is rejected with an invalid-parameter error instead of returning allocator XML (crates/rpc/src/handlers/util.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "estimaterawfee",
        kind: SurfaceKind::Rpc,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Horizon objects carry only feerate; Core adds decay, scale, pass, fail, errors (crates/rpc/src/handlers/util.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "getzmqnotifications",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and --enablezmq* startup flags.",
        since: "0.4.0",
    },
    Entry {
        name: "validateaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getdescriptorinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "deriveaddresses",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getnetworkinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getpeerinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "ping",
        kind: SurfaceKind::Rpc,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Answers immediately; Core schedules a P2P ping and reports the seen pong (crates/rpc/src/handlers/network.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "addnode",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "disconnectnode",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getconnectioncount",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getnettotals",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getaddednodeinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "listbanned",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "setban",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "clearbanned",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "setnetworkactive",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getnodeaddresses",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getblocktemplate",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "getmininginfo",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "submitblock",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "prioritisetransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    // -- JSON-RPC: bitcoin-rs extension --------------------------------------
    Entry {
        name: "getcapabilities",
        kind: SurfaceKind::Rpc,
        status: Status::Extension,
        feature: "",
        core_version: CORE_VERSION,
        notes: "bitcoin-rs extension reporting compiled/enabled capabilities and index lifecycle state (crates/rpc/src/handlers/chain.rs, crates/node/src/extensions.rs).",
        since: "0.4.0",
    },
    // -- JSON-RPC: Core surface not exposed (blockchain/control) ------------
    Entry {
        name: "dumptxoutset",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "UTXO snapshot dump not implemented.",
        since: "n/a",
    },
    Entry {
        name: "getblockfrompeer",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No on-demand block fetch from peers.",
        since: "n/a",
    },
    Entry {
        name: "getchainstates",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Not implemented.",
        since: "n/a",
    },
    Entry {
        name: "getdeploymentinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Not implemented over JSON-RPC (the REST /rest/deploymentinfo route exists).",
        since: "n/a",
    },
    Entry {
        name: "getdescriptoractivity",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No wallet/scan index to serve it.",
        since: "n/a",
    },
    Entry {
        name: "getmempoolcluster",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Cluster mempool tracking not implemented.",
        since: "n/a",
    },
    Entry {
        name: "gettxspendingprevout",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Not implemented.",
        since: "n/a",
    },
    Entry {
        name: "importmempool",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Mempool import not implemented.",
        since: "n/a",
    },
    Entry {
        name: "loadtxoutset",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "UTXO snapshot load (assumeutxo) not implemented.",
        since: "n/a",
    },
    Entry {
        name: "preciousblock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No manual block-preference surface.",
        since: "n/a",
    },
    Entry {
        name: "reconsiderblock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No manual reorg-control surface.",
        since: "n/a",
    },
    Entry {
        name: "savemempool",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Mempool dump/reload persistence not implemented.",
        since: "n/a",
    },
    Entry {
        name: "scanblocks",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No BIP157/158 filter index to scan.",
        since: "n/a",
    },
    Entry {
        name: "waitforblock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No long-poll wait surface.",
        since: "n/a",
    },
    Entry {
        name: "waitforblockheight",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No long-poll wait surface.",
        since: "n/a",
    },
    Entry {
        name: "waitfornewblock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No long-poll wait surface.",
        since: "n/a",
    },
    Entry {
        name: "help",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No per-method help text renderer.",
        since: "n/a",
    },
    Entry {
        name: "logging",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Log-category controls not exposed over RPC.",
        since: "n/a",
    },
    Entry {
        name: "stop",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Lifecycle control not exposed over RPC.",
        since: "n/a",
    },
    // -- JSON-RPC: Core surface not exposed (mining/network/util/signer) ----
    Entry {
        name: "getnetworkhashps",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Network hash-rate estimate not implemented.",
        since: "n/a",
    },
    Entry {
        name: "getprioritisedtransactions",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Prioritisation map not queryable yet.",
        since: "n/a",
    },
    Entry {
        name: "submitheader",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Header-only submission not implemented.",
        since: "n/a",
    },
    Entry {
        name: "getaddrmaninfo",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Addrman table stats not exposed.",
        since: "n/a",
    },
    Entry {
        name: "abortprivatebroadcast",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Private-broadcast store not implemented.",
        since: "n/a",
    },
    Entry {
        name: "analyzepsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT analysis not implemented (combine/finalize only).",
        since: "n/a",
    },
    Entry {
        name: "combinerawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Raw-transaction combination not implemented.",
        since: "n/a",
    },
    Entry {
        name: "converttopsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT creation not implemented.",
        since: "n/a",
    },
    Entry {
        name: "createpsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT creation not implemented.",
        since: "n/a",
    },
    Entry {
        name: "decodepsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT analysis not implemented (combine/finalize only).",
        since: "n/a",
    },
    Entry {
        name: "decodescript",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Script decode helper not implemented.",
        since: "n/a",
    },
    Entry {
        name: "descriptorprocesspsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "fundrawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getprivatebroadcastinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Private-broadcast store not implemented.",
        since: "n/a",
    },
    Entry {
        name: "joinpsbts",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT merge not implemented (combine/finalize only).",
        since: "n/a",
    },
    Entry {
        name: "signrawtransactionwithkey",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Signing requires key material this process never holds.",
        since: "n/a",
    },
    Entry {
        name: "submitpackage",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Package acceptance not implemented.",
        since: "n/a",
    },
    Entry {
        name: "utxoupdatepsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "PSBT update from the UTXO set not implemented.",
        since: "n/a",
    },
    Entry {
        name: "enumeratesigners",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No external signer support.",
        since: "n/a",
    },
    Entry {
        name: "createmultisig",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "No key material (policy).",
        since: "n/a",
    },
    Entry {
        name: "signmessagewithprivkey",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Signing requires key material this process never holds.",
        since: "n/a",
    },
    Entry {
        name: "verifymessage",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Message-signature verification not implemented.",
        since: "n/a",
    },
    // -- JSON-RPC: Core wallet surface, excluded by the no-wallet policy ----
    Entry {
        name: "abandontransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "abortrescan",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "backupwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "bumpfee",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "createwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "createwalletdescriptor",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "encryptwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getaddressesbylabel",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getaddressinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getbalance",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getbalances",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "gethdkeys",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getnewaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getrawchangeaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getreceivedbyaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getreceivedbylabel",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "gettransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "getwalletinfo",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "importdescriptors",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "importprunedfunds",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "keypoolrefill",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listaddressgroupings",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listdescriptors",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listlabels",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listlockunspent",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listreceivedbyaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listreceivedbylabel",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listsinceblock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listtransactions",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listunspent",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listwalletdir",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "listwallets",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "loadwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "lockunspent",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "migratewallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "psbtbumpfee",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "removeprunedfunds",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "rescanblockchain",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "restorewallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "send",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "sendall",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "sendmany",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "sendtoaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "setlabel",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "setwalletflag",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "signmessage",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "signrawtransactionwithwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "simulaterawtransaction",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "unloadwallet",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletcreatefundedpsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletdisplayaddress",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletlock",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletpassphrase",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletpassphrasechange",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    Entry {
        name: "walletprocesspsbt",
        kind: SurfaceKind::Rpc,
        status: Status::Unimplemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: NO_WALLET,
        since: "n/a",
    },
    // -- REST (Core StartREST registration order) ---------------------------
    Entry {
        name: "/rest/tx/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/block/notxdetails/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/block/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/blockpart/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "bin/hex only; JSON rejected as in Core's original part endpoint.",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/blockfilter/",
        kind: SurfaceKind::Rest,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Route registered but answers unavailable unless the --blockfilterindex extension is enabled (crates/rpc/src/rest.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/blockfilterheaders/",
        kind: SurfaceKind::Rest,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Route registered but answers unavailable unless the --blockfilterindex extension is enabled (crates/rpc/src/rest.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/chaininfo",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/mempool/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/headers/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/getutxos",
        kind: SurfaceKind::Rest,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "URI-scheme input only; Core also accepts a POST raw-transaction body (crates/rpc/src/rest.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/deploymentinfo/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/deploymentinfo",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/blockhashbyheight/",
        kind: SurfaceKind::Rest,
        status: Status::Implemented,
        feature: "",
        core_version: CORE_VERSION,
        notes: "",
        since: "0.4.0",
    },
    Entry {
        name: "/rest/spenttxouts/",
        kind: SurfaceKind::Rest,
        status: Status::Deviation,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Always answers undo-unavailable: undo data is not persisted (crates/rpc/src/rest.rs).",
        since: "0.4.0",
    },
    Entry {
        name: "esplora/*",
        kind: SurfaceKind::Rest,
        status: Status::Extension,
        feature: "",
        core_version: CORE_VERSION,
        notes: "Esplora-compatible indexer HTTP surface, a separate non-Core contract (crates/rpc/src/esplora.rs, docs/rest-interface.md).",
        since: "0.4.0",
    },
    // -- ZMQ topics ----------------------------------------------------------
    Entry {
        name: "hashblock",
        kind: SurfaceKind::Zmq,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and a --zmqpubhashblock endpoint.",
        since: "0.4.0",
    },
    Entry {
        name: "hashtx",
        kind: SurfaceKind::Zmq,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and a --zmqpubhashtx endpoint.",
        since: "0.4.0",
    },
    Entry {
        name: "rawblock",
        kind: SurfaceKind::Zmq,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and a --zmqpubrawblock endpoint.",
        since: "0.4.0",
    },
    Entry {
        name: "rawtx",
        kind: SurfaceKind::Zmq,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and a --zmqpubrawtx endpoint.",
        since: "0.4.0",
    },
    Entry {
        name: "sequence",
        kind: SurfaceKind::Zmq,
        status: Status::Implemented,
        feature: "zmq",
        core_version: CORE_VERSION,
        notes: "Requires the zmq feature and a --zmqpubsequence endpoint. Publishes C/D block events and A/R mempool events; A/R carry reversed txid, the label byte, and the mempool sequence as u64 LE (crates/node/src/zmq_publisher.rs).",
        since: "0.4.0",
    },
];

/// True when `name` answers a dispatch for `kind` in this build.
///
/// The dispatcher routes registration through this predicate, so a row and
/// its dispatch arm cannot disagree about registrability.
#[must_use]
pub fn is_registered(kind: SurfaceKind, name: &str) -> bool {
    MANIFEST
        .iter()
        .any(|entry| entry.kind == kind && entry.name == name && entry.shipped())
}

/// Rows of one transport kind, in table order.
pub fn entries_of_kind(kind: SurfaceKind) -> impl Iterator<Item = &'static Entry> {
    MANIFEST.iter().filter(move |entry| entry.kind == kind)
}

fn feature_active(feature: &str) -> bool {
    match feature {
        "" => true,
        "zmq" => cfg!(feature = "zmq"),
        // An unknown feature name can never be active here; the coverage test
        // rejects such a row outright.
        _ => false,
    }
}

/// Renders `docs/rpc-reference.md` deterministically from [`MANIFEST`].
///
/// The output is a pure function of the table: fixed section order, fixed row
/// order, and a counts footer, so a one-row change always changes the bytes
/// and fails the drift test.
#[must_use]
pub fn render_reference() -> String {
    let mut out = String::new();
    out.push_str("# External API Compatibility Reference\n\n");
    out.push_str("<!-- GENERATED FILE - do not edit by hand.\n");
    out.push_str("     Source of truth: MANIFEST in crates/rpc/src/manifest.rs.\n");
    out.push_str(
        "     Regenerate: REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference\n",
    );
    out.push_str(
        "     The generated_reference_matches_checked_in test fails when this file drifts. -->\n\n",
    );
    out.push_str("Surface contract of bitcoin-rs against Bitcoin Core ");
    out.push_str(CORE_VERSION);
    out.push_str(".\n\n");
    out.push_str("- **Implemented** - shipped and shape-compatible with the Core contract.\n");
    out.push_str("- **Deviation** - shipped with a recorded difference from Core; notes cite the source file.\n");
    out.push_str("- **Extension** - bitcoin-rs-specific surface with no Core counterpart.\n");
    out.push_str("- **Unimplemented** - Core surface this node does not expose: JSON-RPC answers `method not found`, REST answers 404.\n\n");
    out.push_str("`since` is the bitcoin-rs version whose surface a row describes; `pending` marks a row whose implementation lands in a later change. Rows naming a cargo feature exist only when that feature is compiled.\n\n");
    out.push_str("Unimplemented-set derivation: audited against the Bitcoin Core v31.0 source command tables (src/rpc/*.cpp, src/wallet/rpc/*.cpp, src/rest.cpp StartREST, src/zmq/zmqpublishnotifier.cpp) - the same registrations Core's `help` output prints. Hidden test/administration commands are intentionally absent.\n");
    for kind in [SurfaceKind::Rpc, SurfaceKind::Rest, SurfaceKind::Zmq] {
        let mut printed_heading = false;
        for status in [
            Status::Implemented,
            Status::Deviation,
            Status::Extension,
            Status::Unimplemented,
        ] {
            let rows: Vec<&Entry> = entries_of_kind(kind)
                .filter(|entry| entry.status == status)
                .collect();
            if rows.is_empty() {
                continue;
            }
            if !printed_heading {
                out.push_str("\n## ");
                out.push_str(kind.heading());
                out.push('\n');
                printed_heading = true;
            }
            out.push_str("\n### ");
            out.push_str(status.label());
            out.push_str("\n\n");
            out.push_str("| surface | since | notes |\n");
            out.push_str("|---|---|---|\n");
            for entry in rows {
                out.push_str("| `");
                out.push_str(entry.name);
                out.push_str("` | ");
                out.push_str(entry.since);
                out.push_str(" | ");
                out.push_str(entry.notes);
                out.push_str(" |\n");
            }
        }
    }
    out.push_str("\nRow counts: ");
    for (index, status) in [
        Status::Implemented,
        Status::Deviation,
        Status::Extension,
        Status::Unimplemented,
    ]
    .into_iter()
    .enumerate()
    {
        if index > 0 {
            out.push_str(", ");
        }
        let count = MANIFEST.iter().filter(|e| e.status == status).count();
        out.push_str(&format!("{} {count}", status.label()));
    }
    let total = MANIFEST.len();
    out.push_str(&format!(" - total {total}.\n"));
    out
}
