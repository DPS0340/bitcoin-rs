use super::{
    Arc, ArcSwap, CapabilityOwnerHealth, CapabilityOwnerLifecycle, CapabilityOwnerRevision,
    CapabilityState, CapabilityStatus, DerivedIndexCapabilitySource, DerivedIndexLifecycle,
    DerivedIndexRuntime, IndexCapabilities, IndexProgress, TxQueryError, derived_index_status,
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
    ) -> Result<(CapabilityState, Option<IndexProgress>, Option<u64>), TxQueryError> {
        if let Some(message) = failure {
            let index_state_revision = match lifecycle {
                DerivedIndexLifecycle::Serving(engine) => {
                    engine.index_state_revision().ok().flatten()
                }
                DerivedIndexLifecycle::Opening
                | DerivedIndexLifecycle::Failed(_)
                | DerivedIndexLifecycle::ShutdownAbandoned => None,
            };
            return Ok((
                CapabilityState::Failed {
                    reason: message.to_owned(),
                },
                None,
                index_state_revision,
            ));
        }
        let engine = match lifecycle {
            DerivedIndexLifecycle::Opening => {
                return Ok((CapabilityState::Opening, None, None));
            }
            DerivedIndexLifecycle::ShutdownAbandoned => {
                return Ok((CapabilityState::ShutdownAbandoned, None, None));
            }
            DerivedIndexLifecycle::Failed(reason) => {
                return Ok((
                    CapabilityState::Failed {
                        reason: reason.to_string(),
                    },
                    None,
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
                engine.index_state_revision()?,
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
                progress.state_revision,
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
        Ok((state, Some(progress), progress.state_revision))
    }

    fn owner_revision(
        lifecycle: &DerivedIndexLifecycle,
        failure: Option<&str>,
        phase: ReconcilePhase,
    ) -> CapabilityOwnerRevision {
        let lifecycle = match lifecycle {
            DerivedIndexLifecycle::Opening => CapabilityOwnerLifecycle::Opening,
            DerivedIndexLifecycle::Serving(_) => CapabilityOwnerLifecycle::Serving,
            DerivedIndexLifecycle::Failed(_) => CapabilityOwnerLifecycle::Failed,
            DerivedIndexLifecycle::ShutdownAbandoned => CapabilityOwnerLifecycle::ShutdownAbandoned,
        };
        let health = if failure.is_some() || lifecycle == CapabilityOwnerLifecycle::Failed {
            CapabilityOwnerHealth::Failed
        } else {
            CapabilityOwnerHealth::Healthy
        };
        CapabilityOwnerRevision {
            lifecycle,
            health,
            phase,
        }
    }

    fn snapshot_at(
        cursor: ConsumerCursor,
        index_state_revision: Option<u64>,
        index_owner: CapabilityOwnerRevision,
        status: CapabilityStatus,
    ) -> CapabilitySnapshot {
        CapabilitySnapshot::from_cursor(cursor, index_state_revision, index_owner, vec![status])
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
                        None,
                        CapabilityOwnerRevision::default(),
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
                        None,
                        CapabilityOwnerRevision::default(),
                        derived_index_status(false, CapabilityState::Disabled),
                    ));
                }
                continue;
            }

            let lifecycle_before = lifecycle.load_full();
            let phase_before = runtime.phase_snapshot();
            let failure_before = runtime.failure_snapshot();
            let failure = failure_before
                .as_deref()
                .map(compact_str::CompactString::as_str);
            let index_owner = Self::owner_revision(&lifecycle_before, failure, *phase_before);
            let report = Self::report(&lifecycle_before, *phase_before, failure, self.enabled);
            let lifecycle_after = lifecycle.load_full();
            let phase_after = runtime.phase_snapshot();
            let failure_after = runtime.failure_snapshot();
            let cursor_after = self.chain.cursor();

            if cursor_before != cursor_after
                || !Arc::ptr_eq(&lifecycle_before, &lifecycle_after)
                || !Arc::ptr_eq(&phase_before, &phase_after)
                || !option_arc_ptr_eq(failure_before.as_ref(), failure_after.as_ref())
            {
                continue;
            }
            let (state, progress, index_state_revision) = match report {
                Ok(report) => report,
                Err(TxQueryError::Retry) => continue,
                Err(error) => (
                    CapabilityState::Failed {
                        reason: error.to_string(),
                    },
                    None,
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
                index_state_revision,
                index_owner,
                derived_index_status(true, state),
            ));
        }
        Err(CapabilitySnapshotError::Changed)
    }
}

fn option_arc_ptr_eq<T>(left: Option<&Arc<T>>, right: Option<&Arc<T>>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => Arc::ptr_eq(left, right),
        (None, None) => true,
        _ => false,
    }
}
