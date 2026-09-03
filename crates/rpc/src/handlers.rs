use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_primitives::Txid;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value};

use crate::context::Context;
use crate::error::RpcError;

pub(crate) mod chain;
pub(crate) mod mempool;
pub(crate) mod mining;
pub(crate) mod network;
pub(crate) mod tx;
pub(crate) mod util;

use crate::manifest::{self, SurfaceKind};

/// Registration consults the compatibility manifest so the declared surface
/// and the dispatched surface cannot disagree.
fn is_registered_method(method: &str) -> bool {
    manifest::is_registered(SurfaceKind::Rpc, method)
}

/// Signature of one dispatch arm.
type HandlerFn = fn(&Arc<Context>, &Value) -> Result<Value, RpcError>;

/// One live registry row: a method name bound to the handler arm serving it.
pub(crate) struct DispatchEntry {
    name: &'static str,
    handler: HandlerFn,
}

/// The live dispatch registry: every JSON-RPC method name this build serves,
/// bound to its handler arm. `dispatch` routes through this table and the
/// manifest coverage gate enumerates it, so a name can neither dispatch
/// without a shipped manifest row nor ship a row without a live arm.
pub(crate) const DISPATCH_TABLE: &[DispatchEntry] = &[
    DispatchEntry {
        name: "getblockchaininfo",
        handler: chain::getblockchaininfo,
    },
    DispatchEntry {
        name: "getdifficulty",
        handler: chain::getdifficulty,
    },
    DispatchEntry {
        name: "getchaintips",
        handler: chain::getchaintips,
    },
    DispatchEntry {
        name: "getchaintxstats",
        handler: chain::getchaintxstats,
    },
    DispatchEntry {
        name: "getblockcount",
        handler: chain::getblockcount,
    },
    DispatchEntry {
        name: "getblockhash",
        handler: chain::getblockhash,
    },
    DispatchEntry {
        name: "getbestblockhash",
        handler: chain::getbestblockhash,
    },
    DispatchEntry {
        name: "getblock",
        handler: chain::getblock,
    },
    DispatchEntry {
        name: "getblockheader",
        handler: chain::getblockheader,
    },
    DispatchEntry {
        name: "getblockstats",
        handler: chain::getblockstats,
    },
    DispatchEntry {
        name: "verifychain",
        handler: chain::verifychain,
    },
    DispatchEntry {
        name: "gettxoutsetinfo",
        handler: chain::gettxoutsetinfo,
    },
    DispatchEntry {
        name: "getindexinfo",
        handler: chain::getindexinfo,
    },
    DispatchEntry {
        name: "getcapabilities",
        handler: chain::getcapabilities,
    },
    DispatchEntry {
        name: "pruneblockchain",
        handler: chain::pruneblockchain,
    },
    DispatchEntry {
        name: "invalidateblock",
        handler: chain::invalidateblock,
    },
    DispatchEntry {
        name: "scantxoutset",
        handler: chain::scantxoutset,
    },
    DispatchEntry {
        name: "getrawtransaction",
        handler: tx::getrawtransaction,
    },
    DispatchEntry {
        name: "gettxout",
        handler: tx::gettxout,
    },
    DispatchEntry {
        name: "gettxoutproof",
        handler: tx::gettxoutproof,
    },
    DispatchEntry {
        name: "verifytxoutproof",
        handler: tx::verifytxoutproof,
    },
    DispatchEntry {
        name: "sendrawtransaction",
        handler: tx::sendrawtransaction,
    },
    DispatchEntry {
        name: "testmempoolaccept",
        handler: tx::testmempoolaccept,
    },
    DispatchEntry {
        name: "decoderawtransaction",
        handler: tx::decoderawtransaction,
    },
    DispatchEntry {
        name: "createrawtransaction",
        handler: tx::createrawtransaction,
    },
    DispatchEntry {
        name: "combinepsbt",
        handler: tx::combinepsbt,
    },
    DispatchEntry {
        name: "finalizepsbt",
        handler: tx::finalizepsbt,
    },
    DispatchEntry {
        name: "getmempoolinfo",
        handler: mempool::getmempoolinfo,
    },
    DispatchEntry {
        name: "getmempoolentry",
        handler: mempool::getmempoolentry,
    },
    DispatchEntry {
        name: "getrawmempool",
        handler: mempool::getrawmempool,
    },
    DispatchEntry {
        name: "getmempoolancestors",
        handler: mempool::getmempoolancestors,
    },
    DispatchEntry {
        name: "getmempooldescendants",
        handler: mempool::getmempooldescendants,
    },
    DispatchEntry {
        name: "estimatesmartfee",
        handler: util::estimatesmartfee,
    },
    DispatchEntry {
        name: "uptime",
        handler: util::uptime,
    },
    DispatchEntry {
        name: "getrpcinfo",
        handler: util::getrpcinfo,
    },
    DispatchEntry {
        name: "getmemoryinfo",
        handler: util::getmemoryinfo,
    },
    DispatchEntry {
        name: "estimaterawfee",
        handler: util::estimaterawfee,
    },
    #[cfg(feature = "zmq")]
    DispatchEntry {
        name: "getzmqnotifications",
        handler: util::getzmqnotifications,
    },
    DispatchEntry {
        name: "validateaddress",
        handler: util::validateaddress,
    },
    DispatchEntry {
        name: "getdescriptorinfo",
        handler: util::getdescriptorinfo,
    },
    DispatchEntry {
        name: "deriveaddresses",
        handler: util::deriveaddresses,
    },
    DispatchEntry {
        name: "getnetworkinfo",
        handler: network::getnetworkinfo,
    },
    DispatchEntry {
        name: "getpeerinfo",
        handler: network::getpeerinfo,
    },
    DispatchEntry {
        name: "ping",
        handler: network::ping,
    },
    DispatchEntry {
        name: "addnode",
        handler: network::addnode,
    },
    DispatchEntry {
        name: "disconnectnode",
        handler: network::disconnectnode,
    },
    DispatchEntry {
        name: "getconnectioncount",
        handler: network::getconnectioncount,
    },
    DispatchEntry {
        name: "getnettotals",
        handler: network::getnettotals,
    },
    DispatchEntry {
        name: "getaddednodeinfo",
        handler: network::getaddednodeinfo,
    },
    DispatchEntry {
        name: "listbanned",
        handler: network::listbanned,
    },
    DispatchEntry {
        name: "setban",
        handler: network::setban,
    },
    DispatchEntry {
        name: "clearbanned",
        handler: network::clearbanned,
    },
    DispatchEntry {
        name: "setnetworkactive",
        handler: network::setnetworkactive,
    },
    DispatchEntry {
        name: "getnodeaddresses",
        handler: network::getnodeaddresses,
    },
    DispatchEntry {
        name: "getblocktemplate",
        handler: mining::getblocktemplate,
    },
    DispatchEntry {
        name: "getmininginfo",
        handler: mining::getmininginfo,
    },
    DispatchEntry {
        name: "submitblock",
        handler: mining::submitblock,
    },
    DispatchEntry {
        name: "prioritisetransaction",
        handler: mining::prioritisetransaction,
    },
];

/// Enumerates the live registry names in table order.
///
/// Exposed for the manifest coverage gate
/// (`crates/rpc/tests/manifest_coverage.rs`), which asserts set equality
/// with the shipped manifest rows in both directions. Names are gated by
/// the same cargo features as the manifest rows.
pub fn live_registry() -> impl Iterator<Item = &'static str> {
    DISPATCH_TABLE.iter().map(|entry| entry.name)
}

/// JSON-RPC method dispatcher backed by shared node context.
#[derive(Clone, Debug)]
pub struct Handler {
    ctx: Arc<Context>,
}

impl Handler {
    /// Builds a dispatcher over `ctx`.
    #[must_use]
    pub const fn new(ctx: Arc<Context>) -> Self {
        Self { ctx }
    }

    /// Returns the shared context used by the handlers.
    #[must_use]
    pub fn context(&self) -> &Arc<Context> {
        &self.ctx
    }

    /// Dispatches one Bitcoin Core-compatible JSON-RPC method.
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        if !is_registered_method(method) {
            return Err(RpcError::MethodNotFound(method.to_owned()));
        }
        let Some(arm) = DISPATCH_TABLE.iter().find(|entry| entry.name == method) else {
            unreachable!("registered RPC method missing a dispatch arm: {method}");
        };
        (arm.handler)(&self.ctx, params)
    }
}

pub(crate) fn ensure_no_params(params: &Value) -> Result<(), RpcError> {
    if params.is_null() {
        return Ok(());
    }
    let Some(array) = params.as_array() else {
        return Err(RpcError::InvalidParams("params must be an array"));
    };
    if array.is_empty() {
        Ok(())
    } else {
        Err(RpcError::InvalidParams("method does not accept parameters"))
    }
}

pub(crate) fn params_array(params: &Value) -> Result<&sonic_rs::Array, RpcError> {
    params
        .as_array()
        .ok_or(RpcError::InvalidParams("params must be an array"))
}

pub(crate) fn optional_bool(params: &Value, index: usize, default: bool) -> Result<bool, RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(default);
    };
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_bool()
        .ok_or(RpcError::InvalidType("parameter must be boolean"))
}

pub(crate) fn required_str<'a>(
    params: &'a Value,
    index: usize,
    name: &'static str,
) -> Result<&'a str, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_str)
        .ok_or(RpcError::InvalidParams(name))
}

pub(crate) fn required_u64(
    params: &Value,
    index: usize,
    name: &'static str,
) -> Result<u64, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_u64)
        .ok_or(RpcError::InvalidParams(name))
}

/// Parses one 64-hex-character transaction id, rejecting anything else.
pub(crate) fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}
#[cfg(test)]
mod registry_tests {
    use alloc::collections::BTreeSet;
    use alloc::sync::Arc;

    use sonic_rs::json;

    #[cfg(feature = "zmq")]
    use super::DISPATCH_TABLE;
    use super::{Handler, live_registry};
    use crate::context::Context;
    use crate::error::RpcError;
    use crate::manifest::{self, SurfaceKind};

    const POLICY_ABSENCES: &[&str] = &[
        "clearmempool",
        "dumpprivkey",
        "dumpwallet",
        "importprivkey",
        "importwallet",
        "importmulti",
        "sethdseed",
    ];

    fn shipped_rpc_rows() -> impl Iterator<Item = &'static manifest::Entry> {
        manifest::entries_of_kind(SurfaceKind::Rpc).filter(|entry| entry.shipped())
    }

    #[test]
    fn core_method_registry_has_the_expected_surface() {
        let live: BTreeSet<&str> = live_registry().collect();
        let shipped: BTreeSet<&str> = shipped_rpc_rows().map(|entry| entry.name).collect();
        assert_eq!(
            live, shipped,
            "live dispatch registry must equal the shipped manifest rows"
        );
        let handler = Handler::new(Arc::new(Context::new()));
        for entry in shipped_rpc_rows() {
            assert!(
                !matches!(
                    handler.dispatch(entry.name, &json!([])),
                    Err(RpcError::MethodNotFound(_))
                ),
                "{} is listed but not dispatchable",
                entry.name
            );
        }
        for method in POLICY_ABSENCES {
            assert!(matches!(
                handler.dispatch(method, &json!([])),
                Err(RpcError::MethodNotFound(_))
            ));
        }
    }

    #[cfg(feature = "zmq")]
    #[test]
    fn zmq_build_adds_exactly_one_method() {
        assert_eq!(
            DISPATCH_TABLE
                .iter()
                .filter(|arm| arm.name == "getzmqnotifications")
                .count(),
            1
        );
        let handler = Handler::new(Arc::new(Context::new()));
        assert!(!matches!(
            handler.dispatch("getzmqnotifications", &json!([])),
            Err(RpcError::MethodNotFound(_))
        ));
    }

    #[cfg(not(feature = "zmq"))]
    #[test]
    fn non_zmq_build_omits_notification_method() {
        assert!(!live_registry().any(|name| name == "getzmqnotifications"));
        let handler = Handler::new(Arc::new(Context::new()));
        assert!(matches!(
            handler.dispatch("getzmqnotifications", &json!([])),
            Err(RpcError::MethodNotFound(_))
        ));
    }
}
