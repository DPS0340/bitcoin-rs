use parking_lot::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::IndexWatermark;

/// Process-local worker health. It is never persisted as lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IndexWorkerHealth {
    /// The worker has not yet loaded its durable watermark.
    Starting,
    /// The worker is operational. It may still be behind the applied tip.
    Healthy,
    /// The worker stopped after an index/source invariant or storage error.
    Failed(String),
}

/// One coherent observation of the worker and its last committed watermark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexRuntimeSnapshot {
    /// Ephemeral worker health.
    pub health: IndexWorkerHealth,
    /// Last watermark published after a successful atomic DB transition.
    pub watermark: Option<IndexWatermark>,
}

/// Shared process-local boundary between the `TxIndex` worker and complete readers.
pub struct TxIndexRuntime {
    state: RwLock<IndexRuntimeSnapshot>,
    gate: RwLock<()>,
}

impl Default for TxIndexRuntime {
    fn default() -> Self {
        Self {
            state: RwLock::new(IndexRuntimeSnapshot {
                health: IndexWorkerHealth::Starting,
                watermark: None,
            }),
            gate: RwLock::new(()),
        }
    }
}

impl TxIndexRuntime {
    /// Builds an empty process-local runtime observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Prevents worker publication while one complete logical query runs.
    pub fn read_gate(&self) -> RwLockReadGuard<'_, ()> {
        self.gate.read()
    }

    /// Excludes complete queries while one DB transition and watermark publication commit.
    pub fn write_gate(&self) -> RwLockWriteGuard<'_, ()> {
        self.gate.write()
    }

    /// Returns one coherent state observation.
    #[must_use]
    pub fn snapshot(&self) -> IndexRuntimeSnapshot {
        self.state.read().clone()
    }

    /// Publishes the durable watermark loaded or committed by an operational worker.
    pub fn publish_healthy(&self, watermark: Option<IndexWatermark>) {
        *self.state.write() = IndexRuntimeSnapshot {
            health: IndexWorkerHealth::Healthy,
            watermark,
        };
    }

    /// Makes complete queries unavailable after the worker stops.
    pub fn publish_failed(&self, error: impl Into<String>) {
        let mut state = self.state.write();
        state.health = IndexWorkerHealth::Failed(error.into());
    }
}

impl core::fmt::Debug for TxIndexRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexRuntime")
            .field("state", &self.snapshot())
            .finish_non_exhaustive()
    }
}
