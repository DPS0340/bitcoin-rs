use super::{
    Arc, ArcSwap, CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource,
    DerivedIndexLifecycle, DerivedIndexRuntime, IndexCapabilities, IndexProgress, TxQueryError,
    derived_index_status,
};

use crate::reconcile::{ChainCursorSource, ConsumerCursor, ReconcilePhase};
use crate::{CapabilitySnapshot, CapabilitySnapshotError};

/// Progress reads that raced a tip or revision move before the status
/// report gives up on a coherent answer for this snapshot.
const PROGRESS_READ_ATTEMPTS: usize = 4;

/// Worker-owned txindex facts for the RPC capability projection.
pub struct DerivedIndexCapability {
    lifecycle: Option<Arc<ArcSwap<DerivedIndexLifecycle>>>,
    runtime: Option<Arc<DerivedIndexRuntime>>,
    enabled: IndexCapabilities,
    chain: Arc<dyn ChainCursorSource>,
}

impl DerivedIndexCapability {
    /// Builds the capability projection over the worker publication cells.
    #[must_use]
    pub fn new(
        lifecycle: Option<Arc<ArcSwap<DerivedIndexLifecycle>>>,
        runtime: Option<Arc<DerivedIndexRuntime>>,
        enabled: IndexCapabilities,
        chain: Arc<dyn ChainCursorSource>,
    ) -> Self {
        Self {
            lifecycle,
            runtime,
            enabled,
            chain,
        }
    }

    fn report(
        lifecycle: &DerivedIndexLifecycle,
        phase: ReconcilePhase,
        failure: Option<&str>,
        enabled: IndexCapabilities,
    ) -> Result<(CapabilityState, Option<IndexProgress>), TxQueryError> {
        if let Some(message) = failure {
            return Ok((
                CapabilityState::Failed {
                    reason: message.to_owned(),
                },
                None,
            ));
        }
        let engine = match lifecycle {
            DerivedIndexLifecycle::Opening => return Ok((CapabilityState::Opening, None)),
            DerivedIndexLifecycle::ShutdownAbandoned => {
                return Ok((CapabilityState::ShutdownAbandoned, None));
            }
            DerivedIndexLifecycle::Failed(reason) => {
                return Ok((
                    CapabilityState::Failed {
                        reason: reason.to_string(),
                    },
                    None,
                ));
            }
            DerivedIndexLifecycle::Serving(engine) => engine,
        };
        if let Some((from_height, to_height)) = phase.rolling_back() {
            return Ok((
                CapabilityState::RollingBack {
                    from_height,
                    to_height,
                },
                None,
            ));
        }
        let rebuilding = phase.rebuilding();
        if rebuilding != IndexCapabilities::NONE {
            let progress = engine.index_progress_for(rebuilding)?;
            return Ok((
                CapabilityState::Rebuilding {
                    processed_height: progress.processed_height,
                    target_height: progress.target_height,
                },
                Some(progress),
            ));
        }
        let progress = engine.index_progress_for(enabled)?;
        let state = if progress.synced {
            CapabilityState::Ready
        } else {
            CapabilityState::CatchingUp {
                processed_height: progress.processed_height,
                target_height: progress.target_height,
            }
        };
        Ok((state, Some(progress)))
    }

    fn snapshot_at(cursor: ConsumerCursor, status: CapabilityStatus) -> CapabilitySnapshot {
        CapabilitySnapshot::from_cursor(cursor, vec![status])
    }
}

impl DerivedIndexCapabilitySource for DerivedIndexCapability {
    fn snapshot(&self) -> Result<CapabilitySnapshot, CapabilitySnapshotError> {
        let enabled = !self.enabled.is_empty();
        for _ in 0..PROGRESS_READ_ATTEMPTS {
            let cursor_before = self.chain.cursor();
            let (Some(lifecycle), Some(runtime)) = (&self.lifecycle, &self.runtime) else {
                let cursor_after = self.chain.cursor();
                if cursor_before == cursor_after {
                    return Ok(Self::snapshot_at(
                        cursor_before,
                        derived_index_status(false, CapabilityState::Disabled),
                    ));
                }
                continue;
            };
            if !enabled {
                let cursor_after = self.chain.cursor();
                if cursor_before == cursor_after {
                    return Ok(Self::snapshot_at(
                        cursor_before,
                        derived_index_status(false, CapabilityState::Disabled),
                    ));
                }
                continue;
            }

            let lifecycle_before = lifecycle.load_full();
            let phase_before = runtime.phase_snapshot();
            let failure_before = runtime.failure_message();
            let report = Self::report(
                &lifecycle_before,
                *phase_before,
                failure_before.as_deref(),
                self.enabled,
            );
            let lifecycle_after = lifecycle.load_full();
            let phase_after = runtime.phase_snapshot();
            let failure_after = runtime.failure_message();
            let cursor_after = self.chain.cursor();

            if cursor_before != cursor_after
                || !Arc::ptr_eq(&lifecycle_before, &lifecycle_after)
                || !Arc::ptr_eq(&phase_before, &phase_after)
                || failure_before != failure_after
            {
                continue;
            }
            let (state, progress) = match report {
                Ok(report) => report,
                Err(TxQueryError::Retry) => continue,
                Err(error) => (
                    CapabilityState::Failed {
                        reason: error.to_string(),
                    },
                    None,
                ),
            };
            if progress.is_some_and(|progress| {
                progress.target_height != cursor_before.height
                    || progress.target_hash != cursor_before.hash
            }) {
                continue;
            }
            return Ok(Self::snapshot_at(
                cursor_before,
                derived_index_status(true, state),
            ));
        }
        Err(CapabilitySnapshotError::Changed)
    }
}
