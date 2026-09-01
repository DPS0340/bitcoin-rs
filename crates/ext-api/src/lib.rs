//! Extension contract between the node core and node-side index consumers.
//!
//! A *capability* is a named node service an extension can depend on (for
//! example `txindex`). An *extension* is a derived-state consumer that keeps
//! its own rows in a namespace directory under the node's data dir and
//! reconciles against the chain-event seam (`docs/contracts/chain-events.md`).
//!
//! Two rules bind every implementation:
//!
//! 1. **Descriptors outlive instances.** A compiled extension always
//!    contributes its [`ExtensionDescriptor`] so validation can reason about
//!    capability requirements even when the runtime toggle is off; a live
//!    instance exists only while the extension is enabled.
//! 2. **Extensions never abort core.** Every lifecycle callback is
//!    best-effort: a failing or lagging extension reports through
//!    [`Extension::health`] and never blocks block application, sync, or RPC
//!    of unrelated capabilities.

use bitcoin_rs_primitives::Hash256;
use serde::{Deserialize, Serialize};

/// Current extension namespace schema contract version.
///
/// Each extension stores its own schema version in its own namespace
/// directory. A stored value other than [`EXT_SCHEMA_VERSION`] refuses that
/// extension namespace only (log, no instance), per
/// `docs/policies/db-migration.md`: never an in-place migration, never a
/// core refusal.
pub const EXT_SCHEMA_VERSION: u32 = 1;

/// Static description of one compiled extension.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtensionDescriptor {
    /// Capability id the extension provides, e.g. `"blockfilterindex"`.
    pub id: &'static str,
    /// Human-readable name.
    pub name: &'static str,
    /// Namespace directory name resolved under the node data dir.
    pub namespace: &'static str,
    /// Schema version of the extension's durable rows.
    pub schema_version: u32,
    /// Capability ids that must be enabled for this extension to start.
    pub requires: &'static [&'static str],
    /// Capability ids that cannot be enabled together with this extension.
    pub incompatible_with: &'static [&'static str],
}

impl ExtensionDescriptor {
    /// Returns whether every required capability is present in `enabled`.
    #[must_use]
    pub fn requirements_met(&self, enabled: &[&str]) -> bool {
        self.requires
            .iter()
            .all(|required| enabled.contains(required))
    }

    /// Returns the first unmet required capability, if any.
    #[must_use]
    pub fn first_unmet_requirement(&self, enabled: &[&str]) -> Option<&'static str> {
        self.requires
            .iter()
            .find(|required| !enabled.contains(*required))
            .copied()
    }
}

/// Lifecycle state of one extension instance, as reported to RPC.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// Rows mirror the applied tip and the consumer cursor is current.
    Ready,
    /// The consumer is still moving rows toward the applied tip.
    CatchingUp {
        /// Height the consumer's rows already cover.
        processed_height: u32,
        /// Height of the applied tip the consumer is moving toward.
        target_height: u32,
    },
    /// The consumer failed permanently and needs operator attention.
    Failed {
        /// Failure description.
        reason: String,
    },
    /// The extension is compiled but not enabled in this run.
    Disabled,
    /// The index store is opening on its worker; queries are unavailable.
    Opening,
    /// The worker was abandoned at shutdown and its namespace is poisoned.
    ShutdownAbandoned,
}

/// One live extension instance the node core drives.
///
/// Callbacks are wake-ups and teardown only; they must never block or fail
/// the caller. Recovery from a missed wake is positional over the chain-event
/// seam, so dropping a callback loses at most latency.
pub trait Extension: Send + Sync {
    /// Static descriptor this instance was constructed from.
    fn descriptor(&self) -> &'static ExtensionDescriptor;

    /// Best-effort wake after one committed block connect.
    fn on_block_connected(&self, height: u32, hash: Hash256);

    /// Best-effort wake after one committed block disconnect.
    fn on_block_disconnected(&self, height: u32, hash: Hash256);

    /// Current lifecycle state.
    fn health(&self) -> HealthStatus;

    /// Requests a graceful stop; the instance must not outlive the call by
    /// mutating its namespace.
    fn shutdown(&self);
}

/// Live status of one capability in a [`CapabilitySnapshot`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilityStatus {
    /// Capability id, matching [`ExtensionDescriptor::id`].
    pub id: String,
    /// Whether the capability is compiled into this build.
    pub compiled: bool,
    /// Whether the runtime toggle enabled it in this run.
    pub enabled: bool,
    /// Current lifecycle state.
    pub state: HealthStatus,
}

/// Point-in-time report served by the `getcapabilities` RPC method.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    /// One entry per compiled capability, in registry order.
    pub capabilities: Vec<CapabilityStatus>,
}

/// Read adapter serving [`CapabilitySnapshot`] to RPC.
///
/// The node owns the implementation; RPC sees only this trait so the RPC
/// crate never depends on node internals or storage backends.
pub trait CapabilityProvider: Send + Sync {
    /// Captures the current capability report.
    fn snapshot(&self) -> CapabilitySnapshot;
}

#[cfg(test)]
mod tests {
    use super::*;

    const DESCRIPTOR: ExtensionDescriptor = ExtensionDescriptor {
        id: "blockfilterindex",
        name: "Basic block filter index",
        namespace: "blockfilterindex",
        schema_version: EXT_SCHEMA_VERSION,
        requires: &["txindex"],
        incompatible_with: &[],
    };

    #[test]
    fn descriptor_requirements_check_enabled_capabilities() {
        assert!(DESCRIPTOR.requirements_met(&["txindex"]));
        assert!(!DESCRIPTOR.requirements_met(&[]));
        assert_eq!(DESCRIPTOR.first_unmet_requirement(&[]), Some("txindex"));
        assert_eq!(DESCRIPTOR.first_unmet_requirement(&["txindex"]), None);
    }

    #[expect(
        clippy::expect_used,
        reason = "test: serialization of a plain enum cannot fail"
    )]
    #[test]
    fn health_status_serializes_round_trip() {
        for status in [
            HealthStatus::Ready,
            HealthStatus::CatchingUp {
                processed_height: 3,
                target_height: 9,
            },
            HealthStatus::Failed {
                reason: "schema mismatch".to_owned(),
            },
            HealthStatus::Disabled,
            HealthStatus::Opening,
            HealthStatus::ShutdownAbandoned,
        ] {
            let text = sonic_rs::to_string(&status).expect("serialize");
            let back: HealthStatus = sonic_rs::from_str(&text).expect("deserialize");
            assert_eq!(back, status);
        }
    }

}
