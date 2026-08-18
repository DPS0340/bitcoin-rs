//! Safe wrapper for the non-terminal CHECKSIG census checkpoint C ABI.
//!
//! This module is compiled only when the `checksig-census` feature is enabled
//! and the patched `libbitcoinkernel-sys` crate is linked through the
//! `bitcoinkernel` dependency. It provides a typed Rust wrapper around the
//! private `btck_census_checkpoint` and `btck_census_flush` symbols.

#![allow(missing_docs)]
use std::ffi::c_int;
use std::mem;

use thiserror::Error;

/// C ABI version for the non-terminal checkpoint structure.
pub const ABI_VERSION: u32 = 1;

const STRUCT_SIZE_BYTES: usize = 56;

/// Expected in-memory size of [`CensusCheckpoint`] on the C side.
#[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
pub const STRUCT_SIZE: u32 = STRUCT_SIZE_BYTES as u32;

/// Fixed size of a BRSREC1 row in bytes.
const RECORD_ROW_SIZE: u64 = 224;

/// Fixed size of a BRSJRN1 row in bytes.
const JOURNAL_ROW_SIZE: u64 = 56;

/// Minimum size of a BRSCTX1 row in bytes (`row_len` field + fixed fields).
const CONTEXT_ROW_MIN_SIZE: u64 = 56;

/// Non-terminal checkpoint returned by the patched kernel census sinks.
///
/// This is a byte-for-byte mirror of `btck_CensusCheckpoint` in the native
/// instrumentation patch. Endpoints include the 8-byte magic and 8-byte
/// placeholder count header (16 bytes total) for each binary sink.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CensusCheckpoint {
    pub abi_version: u32,
    pub struct_size: u32,
    pub context_rows: u64,
    pub context_end: u64,
    pub record_rows: u64,
    pub record_end: u64,
    pub journal_rows: u64,
    pub journal_end: u64,
}

const _: () = assert!(
    mem::size_of::<CensusCheckpoint>() == STRUCT_SIZE_BYTES,
    "CensusCheckpoint layout must match the C ABI"
);

impl CensusCheckpoint {
    /// Verify that the reported endpoints are at least 16 bytes and that the
    /// fixed-size record/journal sinks have byte offsets matching their row
    /// counts. Context rows are variable-length, so only a minimum bound is
    /// checked.
    pub fn validate_coherent(&self) -> Result<(), CensusCheckpointError> {
        for (name, endpoint) in [
            ("context", self.context_end),
            ("record", self.record_end),
            ("journal", self.journal_end),
        ] {
            if endpoint < 16 {
                return Err(CensusCheckpointError::Incoherent(format!(
                    "{name}_end {endpoint} is below the 16-byte stream header"
                )));
            }
        }

        let expected_record_end = self
            .record_rows
            .checked_mul(RECORD_ROW_SIZE)
            .and_then(|b| b.checked_add(16))
            .ok_or_else(|| CensusCheckpointError::Incoherent("record row count overflow".into()))?;
        if self.record_end != expected_record_end {
            return Err(CensusCheckpointError::Incoherent(format!(
                "record_end {} != 16 + record_rows * {} = {}",
                self.record_end, RECORD_ROW_SIZE, expected_record_end
            )));
        }

        let expected_journal_end = self
            .journal_rows
            .checked_mul(JOURNAL_ROW_SIZE)
            .and_then(|b| b.checked_add(16))
            .ok_or_else(|| {
                CensusCheckpointError::Incoherent("journal row count overflow".into())
            })?;
        if self.journal_end != expected_journal_end {
            return Err(CensusCheckpointError::Incoherent(format!(
                "journal_end {} != 16 + journal_rows * {} = {}",
                self.journal_end, JOURNAL_ROW_SIZE, expected_journal_end
            )));
        }

        let min_context_end = self
            .context_rows
            .checked_mul(CONTEXT_ROW_MIN_SIZE)
            .and_then(|b| b.checked_add(16))
            .ok_or_else(|| {
                CensusCheckpointError::Incoherent("context row count overflow".into())
            })?;
        if self.context_end < min_context_end {
            return Err(CensusCheckpointError::Incoherent(format!(
                "context_end {} is below the minimum 16 + context_rows * {} = {}",
                self.context_end, CONTEXT_ROW_MIN_SIZE, min_context_end
            )));
        }

        Ok(())
    }
}

/// Errors returned by the checkpoint wrapper.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CensusCheckpointError {
    /// The native checkpoint call returned a non-zero status.
    #[error("native checkpoint failed with status {0}")]
    KernelFailed(c_int),
    /// The returned ABI version does not match the Rust wrapper.
    #[error("ABI version mismatch: expected {expected}, got {actual}")]
    AbiMismatch { expected: u32, actual: u32 },
    /// The returned struct size does not match the Rust layout.
    #[error("struct size mismatch: expected {expected}, got {actual}")]
    StructSizeMismatch { expected: u32, actual: u32 },
    /// The checkpoint reported incoherent counts or endpoints.
    #[error("checkpoint endpoint incoherent: {0}")]
    Incoherent(String),
    /// The terminal flush call returned a non-zero status.
    #[error("terminal flush failed with status {0}")]
    FlushFailed(c_int),
}

// SAFETY: these symbols are only available when the patched
// `libbitcoinkernel-sys` crate is linked through the `bitcoinkernel`
// dependency (the `checksig-census` feature enables this). Default builds
// never compile this module and therefore never reference these private C
// symbols.
unsafe extern "C" {
    fn btck_census_checkpoint(out: *mut CensusCheckpoint, out_size: usize) -> c_int;
    fn btck_census_flush() -> c_int;
}

/// Capture a non-terminal checkpoint from the native census sinks.
///
/// The wrapper initializes a zeroed [`CensusCheckpoint`], calls the private C
/// ABI, and validates the returned ABI version, struct size, and endpoint
/// coherence. It does not perform any I/O itself; the native function holds the
/// sink mutex, flushes all three streams, and returns committed counts and byte
/// positions.
pub fn capture() -> Result<CensusCheckpoint, CensusCheckpointError> {
    let mut raw = CensusCheckpoint::default();

    // SAFETY: `btck_census_checkpoint` is only linked when the patched kernel
    // is in use. The pointer is valid for the call and `out_size` exactly
    // matches the C struct size.
    let rc = unsafe { btck_census_checkpoint(&raw mut raw, mem::size_of::<CensusCheckpoint>()) };
    if rc != 0 {
        return Err(CensusCheckpointError::KernelFailed(rc));
    }

    if raw.abi_version != ABI_VERSION {
        return Err(CensusCheckpointError::AbiMismatch {
            expected: ABI_VERSION,
            actual: raw.abi_version,
        });
    }
    if raw.struct_size != STRUCT_SIZE {
        return Err(CensusCheckpointError::StructSizeMismatch {
            expected: STRUCT_SIZE,
            actual: raw.struct_size,
        });
    }

    raw.validate_coherent()?;
    Ok(raw)
}

/// Terminally flush the native census sinks.
///
/// This patches the 16-byte header counts, flushes, and closes the three binary
/// streams. It is the only way to finalize a diagnostic run.
pub fn flush() -> Result<(), CensusCheckpointError> {
    // SAFETY: `btck_census_flush` is only linked when the patched kernel is in
    // use. It is idempotent and returns 0 on success.
    let rc = unsafe { btck_census_flush() };
    if rc != 0 {
        Err(CensusCheckpointError::FlushFailed(rc))
    } else {
        Ok(())
    }
}

/// Returns true if `next` is a non-shrinking successor of `prev`.
pub fn is_monotonic(prev: &CensusCheckpoint, next: &CensusCheckpoint) -> bool {
    next.context_rows >= prev.context_rows
        && next.record_rows >= prev.record_rows
        && next.journal_rows >= prev.journal_rows
        && next.context_end >= prev.context_end
        && next.record_end >= prev.record_end
        && next.journal_end >= prev.journal_end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_size_matches_c_expectation() {
        assert_eq!(mem::size_of::<CensusCheckpoint>(), 56);
        assert_eq!(STRUCT_SIZE, 56);
    }

    #[test]
    fn validate_coherent_accepts_exact_fixed_sinks() {
        let cp = CensusCheckpoint {
            abi_version: ABI_VERSION,
            struct_size: STRUCT_SIZE,
            context_rows: 0,
            context_end: 16,
            record_rows: 2,
            record_end: 16 + 2 * RECORD_ROW_SIZE,
            journal_rows: 1,
            journal_end: 16 + JOURNAL_ROW_SIZE,
        };
        assert_eq!(cp.validate_coherent(), Ok(()));
    }

    #[test]
    fn validate_coherent_accepts_exact_context_row_minimum() {
        let mut checkpoint = CensusCheckpoint {
            context_rows: 1,
            context_end: 16 + 4 + 52,
            record_end: 16,
            journal_end: 16,
            ..Default::default()
        };
        assert_eq!(checkpoint.validate_coherent(), Ok(()));

        checkpoint.context_end -= 1;
        assert!(checkpoint.validate_coherent().is_err());
    }

    #[test]
    fn validate_coherent_rejects_short_endpoints() {
        let mut cp = CensusCheckpoint {
            context_end: 15,
            record_end: 16,
            journal_end: 16,
            ..Default::default()
        };
        assert!(cp.validate_coherent().is_err());
        cp.context_end = 16;
        cp.record_end = 15;
        assert!(cp.validate_coherent().is_err());
    }

    #[test]
    fn validate_coherent_rejects_mismatched_record_size() {
        let cp = CensusCheckpoint {
            record_rows: 1,
            record_end: 16 + RECORD_ROW_SIZE - 1,
            journal_rows: 0,
            journal_end: 16,
            context_rows: 0,
            context_end: 16,
            ..Default::default()
        };
        assert!(cp.validate_coherent().is_err());
    }

    #[test]
    fn is_monotonic_detects_shrink() {
        let a = CensusCheckpoint {
            record_rows: 2,
            record_end: 100,
            ..Default::default()
        };
        let mut b = a;
        assert!(is_monotonic(&a, &b));
        b.record_rows = 1;
        assert!(!is_monotonic(&a, &b));
        b.record_rows = 3;
        b.record_end = 99;
        assert!(!is_monotonic(&a, &b));
    }
}
