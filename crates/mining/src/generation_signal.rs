//! Wake seam between authoritative mutations and the template coordinator.

use std::sync::Arc;

use bitcoin_rs_mempool::MempoolObserver;
use bitcoin_rs_mempool::MutationEnvelope;
use parking_lot::RwLock;

use crate::MempoolSequenceWake;
use crate::MiningControl;

/// Wake seam between authoritative mutations and the template coordinator.
///
/// `MiningCoordinator::publish_generation` documents that every long-poll
/// waiter must observe each authoritative applied-tip or mempool mutation,
/// but the coordinator is built after node state, so it cannot be referenced
/// from the apply path or the mempool gateway directly. This signal is
/// created with the node state, wired into the gateway's mutation observer
/// and the apply-path tip publication points, and the coordinator attaches
/// itself at startup: [`Self::publish_generation`] then forwards to the live
/// coordinator. With nothing attached it is a no-op — there is no waiter to
/// wake before the coordinator exists.
#[derive(Default)]
pub struct MiningGenerationSignal {
    coordinator: RwLock<Option<std::sync::Weak<dyn MiningControl>>>,
    /// Lock-free mempool-sequence wake; set by [`Self::attach_sequence_wake`].
    sequence_wake: RwLock<Option<std::sync::Weak<dyn MempoolSequenceWake>>>,
}

impl MiningGenerationSignal {
    /// Creates a detached signal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Points the signal at `coordinator` without extending its ownership.
    ///
    /// The RPC context owns the coordinator; this wake seam must not create
    /// an ownership cycle through `MiningCoordinator::apply_handles`, which
    /// carries the same signal back. A weak reference keeps the seam
    /// observational: the coordinator's lifetime is the context's, and a
    /// wake against a torn-down coordinator is a no-op.
    pub fn attach(&self, coordinator: &Arc<dyn MiningControl>) {
        *self.coordinator.write() = Some(Arc::downgrade(coordinator));
    }

    /// Points the signal at a lock-free mempool-sequence wake.
    ///
    /// When attached, [`Self::publish_generation_from`] forwards to `wake`
    /// without taking the mempool read lock. Without it, that method falls
    /// back to [`Self::publish_generation`].
    pub fn attach_sequence_wake(&self, wake: &Arc<dyn MempoolSequenceWake>) {
        *self.sequence_wake.write() = Some(Arc::downgrade(wake));
    }

    /// Forwards one authoritative-mutation wake to the attached coordinator.
    pub fn publish_generation(&self) {
        if let Some(coordinator) = self
            .coordinator
            .read()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            coordinator.publish_generation();
        }
    }

    /// Forwards one mempool-sequence wake to the attached coordinator.
    ///
    /// Uses the lock-free [`MempoolSequenceWake`] path when attached;
    /// otherwise falls back to [`Self::publish_generation`].
    pub fn publish_generation_from(&self, sequence: u64) {
        if let Some(wake) = self
            .sequence_wake
            .read()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            wake.publish_generation_from(sequence);
        } else {
            self.publish_generation();
        }
    }
}

impl MempoolObserver for MiningGenerationSignal {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let wake_sequence = result
            .sequence_of(result.changes.len().saturating_sub(1))
            .unwrap_or(result.sequence_base);
        self.publish_generation_from(wake_sequence);
    }
}

#[cfg(test)]
mod tests;
