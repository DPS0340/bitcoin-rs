//! HTTP response mapping for the Esplora surfaces.
//!
//! Esplora-specific policy lives here: query-limit parsing and the mapping
//! from transaction-query and RPC failures onto HTTP statuses. The response
//! shapes themselves come from [`crate::rest`], the one owner of response
//! construction for the crate.

use crate::context::{AdmissionFailure, TxQueryError};
use crate::rest::{Response, bad_request, internal_error, not_found, service_unavailable};

pub(super) fn query_limit(query: &str, name: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(super) fn query_error(e: TxQueryError) -> Response {
    match e {
        TxQueryError::Retry | TxQueryError::Unavailable(_) => service_unavailable(e.to_string()),
        TxQueryError::Storage(_) => internal_error(e.to_string()),
    }
}

/// API-10: transaction refusals are 400; an exhausted stale-state retry
/// budget remains an unavailable response with the existing body text.
pub(super) fn admission_error(error: AdmissionFailure) -> Response {
    match error {
        // Preserve the existing public rejection strings, including the
        // maximum-fee prefix and Core's missing-input/cluster spellings.
        AdmissionFailure::Policy(reason) => {
            dispatch_error(crate::handlers::tx::reject_reason_to_rpc_error(reason))
        }
        AdmissionFailure::Consensus => bad_request(error.into_string()),
        AdmissionFailure::RetryExhausted => {
            service_unavailable(format!("internal error: {}", error.into_string()))
        }
    }
}

pub(super) fn dispatch_error(e: crate::RpcError) -> Response {
    match e {
        crate::RpcError::NotFound(_) => not_found(),
        // 400: the request is the problem, and re-sending it unchanged will not
        // help. That covers a malformed request and a refused transaction
        // alike -- `service_unavailable` is 503, which tells a broadcaster to
        // retry, and the one thing a rejected transaction will not do is
        // succeed on a retry. Esplora answers `POST /tx` with 400 and the
        // reject reason, and a wallet reads that as "fix the transaction"
        // rather than "come back later".
        //
        // `TxRejected` is what policy or consensus refused; `TxVerifyError` a
        // guard the caller configured themselves. Neither improves with time.
        crate::RpcError::InvalidParams(_)
        | crate::RpcError::InvalidType(_)
        | crate::RpcError::Deserialization(_)
        | crate::RpcError::TxRejected(_)
        | crate::RpcError::TxVerifyError(_) => bad_request(e.to_string()),
        _ => service_unavailable(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::admission_error;
    use crate::context::AdmissionFailure;

    #[test]
    fn admission_consensus_and_retry_failures_preserve_the_http_dialect() {
        let consensus = admission_error(AdmissionFailure::Consensus);
        assert_eq!(consensus.status, 400);
        assert_eq!(consensus.body, b"consensus-verification-failed");
        let retry = admission_error(AdmissionFailure::RetryExhausted);
        assert_eq!(retry.status, 503);
        assert_eq!(retry.body, b"internal error: admission retry exhausted: chain or mempool changed during submission");
    }
}
