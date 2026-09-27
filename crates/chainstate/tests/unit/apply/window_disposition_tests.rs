//! Engine-independent failure classification: the engine work must never
//! turn a caller wiring error into a header invalidation, and must never
//! soften a real native script verdict into a retry loop.

use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};

use crate::{ApplyError, WindowApplyDisposition, classify_apply_error};

/// `UnsupportedEngine` is a build/selection wiring error, not a verdict
/// about the block or its header. `Operational` keeps the block retryable
/// and leaves the header subtree valid; `Permanent` would invalidate a
/// possibly-valid header subtree with no retry path.
#[test]
fn unsupported_engine_selection_is_operational_not_permanent() {
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::UnsupportedEngine {
            engine: ValidationEngine::Kernel,
        })),
        WindowApplyDisposition::Operational
    );
}

/// Backend-neutral prevout-shape errors are caller wiring bugs with the
/// same disposition under both engines.
#[test]
fn prevout_shape_wiring_errors_stay_operational() {
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::PrevoutCount {
            input_count: 2,
            prevout_count: 1,
        })),
        WindowApplyDisposition::Operational
    );
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::PrevoutMatrixSize {
            expected: 2,
            actual: 1,
        })),
        WindowApplyDisposition::Operational
    );
}

/// The engine dispatch must not soften a genuine script verdict: a native
/// `Script` failure still proves the block invalid.
#[test]
fn native_script_verdicts_remain_permanent() {
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::Script {
            input_index: 0,
            reason: "script failed: false".to_owned(),
        })),
        WindowApplyDisposition::Permanent
    );
}

/// Kernel-backend failures stay Operational (issue #618: `bitcoinkernel`
/// can reject a valid block depending on process state). `Kernel` carries
/// backend parse/precompute failures; a per-input verdict arrives as
/// `Script` instead.
#[test]
fn kernel_backend_failures_remain_operational() {
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::Kernel(
            "kernel transaction parse failed".to_owned()
        ))),
        WindowApplyDisposition::Operational
    );
}

/// A kernel per-input verdict surfaces as `Script` with the
/// `kernel script verification failed:` prefix; classification still treats
/// it as the retryable #618 backend outcome rather than a proof the header
/// is invalid.
#[test]
fn kernel_script_verdicts_stay_operational() {
    assert_eq!(
        classify_apply_error(&ApplyError::Consensus(ConsensusError::Script {
            input_index: 0,
            reason: "kernel script verification failed: test".to_owned(),
        })),
        WindowApplyDisposition::Operational
    );
}
