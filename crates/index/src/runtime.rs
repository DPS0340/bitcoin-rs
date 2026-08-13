use parking_lot::RwLock;

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

/// Process-local worker status. Durable index progress lives only in the DB watermark.
pub struct TxIndexRuntime {
    health: RwLock<IndexWorkerHealth>,
}

impl Default for TxIndexRuntime {
    fn default() -> Self {
        Self {
            health: RwLock::new(IndexWorkerHealth::Starting),
        }
    }
}

impl TxIndexRuntime {
    /// Builds an empty process-local runtime observation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the worker's current process-local health.
    #[must_use]
    pub fn health(&self) -> IndexWorkerHealth {
        self.health.read().clone()
    }

    /// Marks the worker operational after it has loaded the durable watermark.
    pub fn publish_healthy(&self) {
        *self.health.write() = IndexWorkerHealth::Healthy;
    }

    /// Makes complete queries unavailable after the worker stops.
    pub fn publish_failed(&self, error: impl Into<String>) {
        *self.health.write() = IndexWorkerHealth::Failed(error.into());
    }
}

impl core::fmt::Debug for TxIndexRuntime {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TxIndexRuntime")
            .field("health", &self.health())
            .finish_non_exhaustive()
    }
}
