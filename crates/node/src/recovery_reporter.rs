//! Node-owned composition adapter: wires the storage-owned recovery evidence
//! publisher into the index worker (`IndexAheadSink`) and RPC
//! (`RollbackWarningSource`).

use std::path::PathBuf;

use bitcoin_rs_storage::recovery_evidence::{EvidenceError, RecoveryEvidencePublisher};

/// Node-side adapter around `RecoveryEvidencePublisher`.
pub(crate) struct RecoveryReporter {
    publisher: RecoveryEvidencePublisher,
}

impl RecoveryReporter {
    pub(crate) fn new(data_dir: PathBuf, genesis_hash: String, detecting_epoch: u64) -> Self {
        Self {
            publisher: RecoveryEvidencePublisher::new(data_dir, genesis_hash, detecting_epoch),
        }
    }

    /// Reports a checkpoint-fallback event. Marker failure aborts
    /// `NodeState::open`.
    pub(crate) fn report_checkpoint_fallback(
        &self,
        witness_height: u32,
        restored_height: u32,
        restored_hash: &str,
        source: &str,
        old_hash: &str,
        time: u64,
    ) -> Result<(), EvidenceError> {
        self.publisher.publish_checkpoint_fallback(
            witness_height,
            restored_height,
            restored_hash,
            source,
            old_hash,
            time,
        )
    }

    /// Renders all warnings in deterministic order from one immutable load.
    pub(crate) fn warnings(&self) -> Vec<String> {
        self.publisher.warnings()
    }
}

impl bitcoin_rs_index::runtime::IndexAheadSink for RecoveryReporter {
    fn report_index_ahead(
        &self,
        capability: &str,
        index_height: u32,
        tip_height: u32,
        tip_hash_be: &str,
        index_hash_be: &str,
        depth: u32,
        unix_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.publisher
            .publish_index_ahead(
                capability,
                index_height,
                tip_height,
                tip_hash_be,
                index_hash_be,
                depth,
                unix_secs,
            )
            .map_err(|error| -> Box<dyn std::error::Error + Send + Sync> { error.into() })
    }
}

impl bitcoin_rs_index::RollbackWarningSource for RecoveryReporter {
    fn rollback_warnings(&self) -> Vec<String> {
        self.warnings()
    }
}
