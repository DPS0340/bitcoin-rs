//! Shared process-stderr assertion for the live-wire sync harnesses.

use bitcoin_rs_e2e::ProcessNode;
use bitcoin_rs_e2e::helpers::node_stderr;

/// Asserts the node's stderr shows no panic and no `PrevHashMismatch` —
/// `context` names where a mismatch would indicate commit churn.
pub(crate) fn assert_clean_stderr(node: &ProcessNode, context: &str) {
    let stderr = node_stderr(node);
    assert_eq!(
        stderr.matches("panic").count(),
        0,
        "node stderr contains a panic"
    );
    assert_eq!(
        stderr.matches("PrevHashMismatch").count(),
        0,
        "node stderr shows PrevHashMismatch: {context}"
    );
}
