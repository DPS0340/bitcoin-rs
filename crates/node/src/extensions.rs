//! Node-side extension registry: descriptors, validation, capability report.
//!
//! Every compiled extension contributes its [`ExtensionDescriptor`]
//! unconditionally, so validation can reason about capability requirements
//! even when the runtime toggle is off. Instances exist only for enabled
//! extensions and live in the node crate's worker modules; this module owns
//! the descriptor set, the pre-open validation, and the live
//! [`CapabilitySnapshot`] served to RPC.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_ext_api::{
    CapabilityProvider, CapabilitySnapshot, CapabilityStatus, Extension, ExtensionDescriptor,
    HealthStatus,
};
use bitcoin_rs_rpc::context::TxIndexQuery;
use parking_lot::Mutex;

use crate::Config;

/// Capability id of the Core-compatible transaction index.
pub const TXINDEX_CAPABILITY: &str = "txindex";

/// Capability id of the BIP157/158 basic block filter index.
pub const BLOCKFILTERINDEX_CAPABILITY: &str = bitcoin_rs_ext_blockfilterindex::CAPABILITY_ID;

/// Descriptor of the `txindex` capability.
///
/// `txindex` is the first reconciliation consumer; it is registered through
/// the same descriptor surface so `getcapabilities` reports it beside the
/// filter extension, while its worker keeps the txindex reconciliation loop.
pub const TXINDEX_DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
    id: TXINDEX_CAPABILITY,
    name: "Transaction index",
    namespace: "txindex",
    schema_version: bitcoin_rs_index::INDEX_FORMAT_VERSION,
    requires: &[],
    incompatible_with: &[],
};

/// Every descriptor compiled into this build, in registry order.
#[must_use]
pub fn compiled_descriptors() -> Vec<&'static ExtensionDescriptor> {
    vec![
        &TXINDEX_DESCRIPTOR,
        &bitcoin_rs_ext_blockfilterindex::DESCRIPTOR,
    ]
}

/// Capability ids enabled by the runtime toggles of `config`.
#[must_use]
pub fn enabled_capabilities(config: &Config) -> Vec<&'static str> {
    let mut enabled = Vec::new();
    if config.txindex || config.script_index.is_enabled() {
        enabled.push(TXINDEX_CAPABILITY);
    }
    if config.blockfilterindex {
        enabled.push(BLOCKFILTERINDEX_CAPABILITY);
    }
    enabled
}

/// Validates enabled extension combinations.
///
/// Called by `run` before `NodeState::open`, so an invalid combination fails
/// before any storage is opened and before networking exists.
/// `Config::validate` keeps the same checks as a backstop for direct openers.
///
/// # Errors
///
/// Names the capability and the missing or conflicting dependency with the
/// literal `"<capability> requires <dependency>"` phrasing.
pub fn validate_extensions(config: &Config) -> anyhow::Result<()> {
    let enabled = enabled_capabilities(config);
    for descriptor in compiled_descriptors() {
        if !enabled.contains(&descriptor.id) {
            continue;
        }
        if let Some(missing) = descriptor.first_unmet_requirement(&enabled) {
            anyhow::bail!(
                "{capability} requires {missing}",
                capability = descriptor.id
            );
        }
        for incompatible in descriptor.incompatible_with {
            let conflicting = match *incompatible {
                "prune" => config.prune_target_mb > 0,
                other => enabled.contains(&other),
            };
            if conflicting {
                anyhow::bail!(
                    "{capability} requires {incompatible} disabled",
                    capability = descriptor.id
                );
            }
        }
    }
    Ok(())
}

/// Live inputs one capability-report read consumes.
pub(crate) struct CapabilityInputs {
    /// Applied-tip handle; its height is the report's catch-up target.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Transaction-index query adapter, present when index rows are built.
    pub tx_query: Option<Arc<dyn TxIndexQuery>>,
    /// Transaction-index runtime handle, present when the worker runs.
    pub tx_runtime: Option<Arc<crate::txindex_worker::TxIndexRuntime>>,
    /// Whether the Core `--txindex` surface is advertised.
    pub txindex_enabled: bool,
    /// Filter-index status handle, present when the extension instance runs.
    pub filter_status: Option<Arc<crate::filterindex_worker::FilterIndexStatus>>,
}

/// Implementation of [`CapabilityProvider`] over live node handles.
///
/// Every `snapshot` call recomputes the report from the live handles, so RPC
/// answers never read a stale copy of index progress.
pub struct NodeCapabilities {
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
            HealthStatus::Disabled
        } else if let Some(message) = inputs
            .tx_runtime
            .as_ref()
            .and_then(|runtime| runtime.failure_message())
        {
            HealthStatus::Failed {
                reason: message.to_string(),
            }
        } else {
            let target = Self::applied_height(&inputs.applied_tip);
            match inputs.tx_query.as_ref().map(|query| query.index_info()) {
                Some(Ok(info)) if info.synced => HealthStatus::Ready,
                Some(Ok(info)) => HealthStatus::CatchingUp {
                    processed_height: info.best_block_height,
                    target_height: target,
                },
                Some(Err(error)) => HealthStatus::Failed {
                    reason: error.to_string(),
                },
                None => HealthStatus::Disabled,
            }
        };
        CapabilityStatus {
            id: TXINDEX_CAPABILITY.to_owned(),
            compiled: true,
            enabled: inputs.txindex_enabled,
            state,
        }
    }

    fn filter_status(inputs: &CapabilityInputs) -> CapabilityStatus {
        let enabled = inputs.filter_status.is_some();
        let state = match inputs.filter_status.as_ref() {
            None => HealthStatus::Disabled,
            Some(status) => status.health(),
        };
        CapabilityStatus {
            id: BLOCKFILTERINDEX_CAPABILITY.to_owned(),
            compiled: true,
            enabled,
            state,
        }
    }
}

impl CapabilityProvider for NodeCapabilities {
    fn snapshot(&self) -> CapabilitySnapshot {
        let inputs = self.inputs.lock();
        CapabilitySnapshot {
            capabilities: vec![Self::txindex_status(&inputs), Self::filter_status(&inputs)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with(build: impl FnOnce(&mut Config)) -> Config {
        let mut config = Config::default_for_network(bitcoin_rs_primitives::Network::Regtest);
        build(&mut config);
        config
    }

    #[test]
    fn enabled_capabilities_follow_runtime_toggles() {
        let config = config_with(|_| {});
        assert!(enabled_capabilities(&config).is_empty());

        let config = config_with(|config| config.txindex = true);
        assert_eq!(enabled_capabilities(&config), vec![TXINDEX_CAPABILITY]);

        let config =
            config_with(|config| config.script_index = crate::config::ScriptIndexMode::Full);
        assert_eq!(enabled_capabilities(&config), vec![TXINDEX_CAPABILITY]);

        let config = config_with(|config| {
            config.txindex = true;
            config.blockfilterindex = true;
        });
        assert_eq!(
            enabled_capabilities(&config),
            vec![TXINDEX_CAPABILITY, BLOCKFILTERINDEX_CAPABILITY]
        );
    }

    #[test]
    fn validation_names_the_missing_dependency_literally() {
        let config = config_with(|config| config.blockfilterindex = true);
        let error = match validate_extensions(&config) {
            Ok(()) => panic!("missing txindex must be rejected"),
            Err(error) => error,
        };
        assert_eq!(error.to_string(), "blockfilterindex requires txindex");
    }

    #[test]
    fn compiled_descriptors_carry_the_registry_namespaces() {
        let descriptors = compiled_descriptors();
        assert_eq!(descriptors.len(), 2);
        assert_eq!(descriptors[0].id, TXINDEX_CAPABILITY);
        assert_eq!(descriptors[0].namespace, "txindex");
        assert_eq!(
            descriptors[0].schema_version,
            bitcoin_rs_index::INDEX_FORMAT_VERSION
        );
        assert_eq!(descriptors[1].id, BLOCKFILTERINDEX_CAPABILITY);
        assert_eq!(descriptors[1].namespace, "blockfilterindex");
        assert_eq!(
            descriptors[1].schema_version,
            bitcoin_rs_ext_api::EXT_SCHEMA_VERSION
        );
    }

    #[test]
    fn validation_names_the_prune_conflict_literally() {
        let config = config_with(|config| {
            config.txindex = true;
            config.blockfilterindex = true;
            config.prune_target_mb = 10;
        });
        let error = match validate_extensions(&config) {
            Ok(()) => panic!("prune conflict must be rejected"),
            Err(error) => error,
        };
        assert_eq!(
            error.to_string(),
            "blockfilterindex requires prune disabled"
        );
    }

    #[test]
    fn validation_accepts_the_reference_combination() {
        let config = config_with(|config| {
            config.txindex = true;
            config.blockfilterindex = true;
        });
        assert!(validate_extensions(&config).is_ok());
    }
}
