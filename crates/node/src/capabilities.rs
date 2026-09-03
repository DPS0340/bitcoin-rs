//! RPC status for the concrete node-owned transaction index.
//!
//! This module is intentionally specific to the transaction index. It does
//! not define a generic extension registry, lifecycle interface, namespace
//! schema, or capability framework.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::context::{
    CapabilityProvider, CapabilitySnapshot, CapabilityState, CapabilityStatus, TxIndexQuery,
};
use parking_lot::Mutex;

use crate::NodeConfig;

/// Stable identifier used by the RPC capability report.
pub(crate) const TXINDEX_CAPABILITY: &str = "txindex";

/// Live inputs consumed by the transaction-index status provider.
pub(crate) struct CapabilityInputs {
    /// Applied-tip handle; its height is the catch-up target.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Transaction-index query adapter, present when index rows are built.
    pub tx_query: Option<Arc<dyn TxIndexQuery>>,
    /// Transaction-index runtime handle, present when the worker runs.
    pub tx_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    /// Whether the Core `--txindex` surface or its script-index dependency is enabled.
    pub txindex_enabled: bool,
}

/// Node-owned provider for the concrete RPC capability report.
pub(crate) struct NodeCapabilities {
    inputs: Mutex<CapabilityInputs>,
}

impl NodeCapabilities {
    pub(crate) fn new(inputs: CapabilityInputs) -> Self {
        Self {
            inputs: Mutex::new(inputs),
        }
    }

    fn applied_height(applied_tip: &ArcSwapOption<TipSnapshot>) -> u32 {
        applied_tip.load().as_ref().map_or(0, |tip| tip.height)
    }

    fn txindex_status(inputs: &CapabilityInputs) -> CapabilityStatus {
        let state = if !inputs.txindex_enabled {
            CapabilityState::Disabled
        } else if let Some(message) = inputs
            .tx_runtime
            .as_ref()
            .and_then(|runtime| runtime.failure_message())
        {
            CapabilityState::Failed {
                reason: message.to_string(),
            }
        } else {
            let target = Self::applied_height(&inputs.applied_tip);
            match inputs.tx_query.as_ref().map(|query| query.index_info()) {
                Some(Ok(info)) if info.synced => CapabilityState::Ready,
                Some(Ok(info)) => CapabilityState::CatchingUp {
                    processed_height: info.best_block_height,
                    target_height: target,
                },
                Some(Err(error)) => CapabilityState::Failed {
                    reason: error.to_string(),
                },
                None => CapabilityState::Disabled,
            }
        };
        CapabilityStatus {
            id: TXINDEX_CAPABILITY.to_owned(),
            compiled: true,
            enabled: inputs.txindex_enabled,
            state,
        }
    }
}

impl CapabilityProvider for NodeCapabilities {
    fn snapshot(&self) -> CapabilitySnapshot {
        let inputs = self.inputs.lock();
        CapabilitySnapshot {
            capabilities: vec![Self::txindex_status(&inputs)],
        }
    }
}

/// Returns whether the transaction-index capability is enabled by config.
#[must_use]
pub(crate) fn txindex_enabled(config: &NodeConfig) -> bool {
    config.indexes.txindex || config.indexes.script_index.is_enabled()
}
