//! Kernel FFI liveness check; ignored locally and executed by the kernel CI job.
//!
//! This proves only that the kernel loads and builds a context. Verdict
//! comparison lives where the corpora are: `kernel_block_parity.rs` runs a
//! script-verdict differential over mainnet fixtures, and the script crate's
//! `core_vectors.rs` runs Core's `script_tests`, `tx_valid`, `tx_invalid` and
//! `sighash` corpora through both a native and a kernel column.
//!
//! A single-row verdict smoke test used to live here. It is gone because those
//! columns cover the same rows and more: the native column now passes all four
//! corpora with zero failures.

#[cfg(feature = "kernel")]
#[test]
#[ignore = "kernel parity requires libboost-dev and the kernel CI job"]
fn kernel_context_builds_for_mainnet() {
    bitcoin_rs_consensus::kernel::KernelContext::new(bitcoin_rs_primitives::Network::Mainnet)
        .unwrap_or_else(|error| panic!("kernel context should build: {error}"));
}

#[cfg(not(feature = "kernel"))]
#[test]
#[ignore = "kernel feature is off in portable verification"]
const fn kernel_parity_skipped_without_kernel_feature() {}
