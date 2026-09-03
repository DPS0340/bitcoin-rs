//! RPC status for the concrete node-owned transaction index.
//!
//! This module is intentionally specific to the transaction index. It does
//! not define a generic extension registry, lifecycle interface, namespace
//! schema, or capability framework.

use std::sync::Arc;

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::context::{
    CapabilityProvider, CapabilitySnapshot, CapabilityState, CapabilityStatus, TxIndexQuery as _,
};
use parking_lot::Mutex;

use crate::NodeConfig;
use crate::txindex_worker::{ReconcilePhase, TxIndexLifecycle, TxIndexRuntime};

/// Stable identifier used by the RPC capability report.
pub(crate) const TXINDEX_CAPABILITY: &str = "txindex";

/// Live inputs consumed by the transaction-index status provider.
pub(crate) struct CapabilityInputs {
    /// Applied-tip handle; its height is the catch-up target.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Worker-published lifecycle snapshot, present when the worker runs.
    pub tx_lifecycle: Option<Arc<ArcSwap<TxIndexLifecycle>>>,
    /// Transaction-index runtime handle, present when the worker runs.
    pub tx_runtime: Option<Arc<TxIndexRuntime>>,
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

    /// Maps the worker-owned lifecycle and reconciliation phase onto the RPC
    /// state. Health comes from the worker's own publications; the query
    /// engine is consulted only for the watermark position once the worker
    /// is serving and moving forward.
    fn txindex_status(inputs: &CapabilityInputs) -> CapabilityStatus {
        let state = match (&inputs.tx_lifecycle, &inputs.tx_runtime) {
            (Some(lifecycle), Some(runtime)) if inputs.txindex_enabled => {
                Self::worker_state(&lifecycle.load(), runtime, &inputs.applied_tip)
            }
            _ => CapabilityState::Disabled,
        };
        CapabilityStatus {
            id: TXINDEX_CAPABILITY.to_owned(),
            compiled: true,
            enabled: inputs.txindex_enabled,
            state,
        }
    }

    fn worker_state(
        lifecycle: &TxIndexLifecycle,
        runtime: &TxIndexRuntime,
        applied_tip: &ArcSwapOption<TipSnapshot>,
    ) -> CapabilityState {
        if let Some(message) = runtime.failure_message() {
            return CapabilityState::Failed {
                reason: message.to_string(),
            };
        }
        let engine = match lifecycle {
            TxIndexLifecycle::Opening => return CapabilityState::Opening,
            TxIndexLifecycle::ShutdownAbandoned => return CapabilityState::ShutdownAbandoned,
            TxIndexLifecycle::Failed(reason) => {
                return CapabilityState::Failed {
                    reason: reason.to_string(),
                };
            }
            TxIndexLifecycle::Serving(engine) => engine,
        };
        let target_height = Self::applied_height(applied_tip);
        match runtime.phase() {
            ReconcilePhase::RollingBack {
                from_height,
                to_height,
            } => CapabilityState::RollingBack {
                from_height,
                to_height,
            },
            ReconcilePhase::Rebuilding { .. } => CapabilityState::Rebuilding {
                processed_height: engine.index_info().map_or(0, |info| info.best_block_height),
                target_height,
            },
            ReconcilePhase::Forward => match engine.index_info() {
                Ok(info) if info.synced => CapabilityState::Ready,
                Ok(info) => CapabilityState::CatchingUp {
                    processed_height: info.best_block_height,
                    target_height,
                },
                Err(error) => CapabilityState::Failed {
                    reason: error.to_string(),
                },
            },
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
    config.txindex || config.script_index.is_enabled()
}
