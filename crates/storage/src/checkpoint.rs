//! Filesystem, format, and atomic publication primitives for chainstate checkpoints.

mod format;
pub mod fs;
mod io;
mod load;
mod publish;

#[cfg(test)]
mod tests;

pub use format::{decode_hex, hex_encode, network_name};
pub use fs::{
    CURRENT_SCHEMA_FILE, create_file, current_schema_bytes, ensure_current_schema, open_data_dir,
    read_file, sync_dir,
};

use cap_std::fs::File;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{BufWriter, Write};
use thiserror::Error;

pub const CHECKPOINT_ROOT: &str = "chainstate-checkpoints";
pub const CURRENT_FILE: &str = "CURRENT";
pub const MANIFEST_FILE: &str = "manifest-v1.json";
pub const HEADERS_FILE: &str = "headers-v1.dat";
pub const UTXO_FILE: &str = "utxo-v4.dat";
pub const COINSTATS_FILE: &str = "coinstats-v1.dat";
pub const CURRENT_FORMAT: &str = "bitcoin-rs-chainstate-current";
pub const MANIFEST_FORMAT: &str = "bitcoin-rs-chainstate-checkpoint";
pub const HEADER_CODEC: &str = "bitcoin-rs-canonical-headers";
pub const UTXO_CODEC: &str = "bitcoin-rs-utxo-spendable-v1";
pub const COINSTATS_CODEC: &str = "bitcoin-rs-coinstats-v1";
pub const CURRENT_VERSION: u32 = 1;
pub const MANIFEST_VERSION: u32 = 1;
pub const UTXO_VERSION: u32 = 4;
pub const COINSTATS_VERSION: u32 = 1;
pub const COINSTATS_MAGIC: [u8; 8] = *b"BRSSTAT\0";
pub const COINSTATS_PAYLOAD_LEN: u32 = 804;
pub const COINSTATS_ARTIFACT_LEN: u64 = 820;
pub const MAX_CHECKPOINT_PAYLOAD_BYTES: u64 = 64_u64 * 1024 * 1024 * 1024;
pub const MAX_CHECKPOINT_METADATA_BYTES: u64 = 1024 * 1024;
const CHECKPOINT_WRITE_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentV1 {
    pub format: String,
    pub version: u32,
    pub generation: u64,
    pub directory: String,
    pub manifest_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointTipV1 {
    pub height: u32,
    pub hash: String,
    pub chainwork: String,
    /// Cumulative transaction count of the chain through this tip.
    ///
    /// Only meaningful for the applied tip; the best-header tip records `0`,
    /// since headers carry no transactions.
    pub chain_tx_count: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadersArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub header_count: u64,
    pub best_chain_sha256: String,
    pub applied_chain_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UtxoArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub record_count: u64,
    pub output_count: u64,
    pub muhash_trailer_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoinStatsArtifactV1 {
    pub file: String,
    pub codec: String,
    pub version: u32,
    pub bytes: u64,
    pub sha256: String,
    pub height: u32,
    pub total_amount: u64,
    pub bogo_size: u64,
    pub tx_count: u64,
    pub utxo_count: u64,
    pub muhash: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointManifestV1 {
    pub format: String,
    pub version: u32,
    pub generation: u64,
    pub network: String,
    pub network_magic: String,
    pub genesis_hash: String,
    pub applied_tip: CheckpointTipV1,
    pub best_header_tip: CheckpointTipV1,
    pub headers: HeadersArtifactV1,
    pub utxo: UtxoArtifactV1,
    pub coinstats: CoinStatsArtifactV1,
}

#[derive(Debug, Error)]
pub enum CheckpointError {
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("checkpoint invariant failed: {0}")]
    Invalid(String),
}
#[derive(Debug, Error)]
pub enum CheckpointCorruption {
    #[error(
        "corrupt current-schema checkpoint: {reason}; remove or replace the datadir and restart to perform a full resync"
    )]
    Invalid { reason: String },
}
#[derive(Debug, Error)]
pub enum CheckpointLoadError {
    #[error(transparent)]
    Corrupt(#[from] CheckpointCorruption),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckpointFailpoint {
    /// Before headers bytes are written.
    HeadersWrite,
    /// Before headers are synchronized.
    HeadersSync,
    /// Before UTXO bytes are written.
    UtxoWrite,
    /// Before UTXO bytes are synchronized.
    UtxoSync,
    /// Before `CoinStats` bytes are written.
    CoinStatsWrite,
    /// Before `CoinStats` bytes are synchronized.
    CoinStatsSync,
    /// Before the manifest is written.
    ManifestWrite,
    /// Before the manifest is synchronized.
    ManifestSync,
    /// Before staging directory synchronization.
    StageSync,
    /// Before generation publication rename.
    GenerationRename,
    /// Before generation-root synchronization.
    GenerationRootSync,
    /// Before temporary CURRENT bytes are written.
    CurrentTempWrite,
    /// Before temporary CURRENT is synchronized.
    CurrentTempSync,
    /// Before CURRENT publication rename.
    CurrentRename,
    /// Before final checkpoint-root synchronization.
    CurrentRootSync,
}
pub(crate) struct GenerationPaths {
    #[cfg(any(
        target_vendor = "apple",
        target_os = "linux",
        target_os = "android",
        target_os = "redox"
    ))]
    pub staging: String,
    pub final_dir: String,
    pub current_temp: String,
    pub directory: String,
}
pub(crate) struct HashingWriter<'a> {
    file: BufWriter<&'a mut File>,
    hasher: Sha256,
    bytes: u64,
    fail: bool,
}
impl<'a> HashingWriter<'a> {
    pub(crate) fn new(
        file: &'a mut File,
        configured: Option<CheckpointFailpoint>,
        boundary: CheckpointFailpoint,
    ) -> Self {
        Self {
            file: BufWriter::with_capacity(CHECKPOINT_WRITE_BUFFER_SIZE, file),
            hasher: Sha256::new(),
            bytes: 0,
            fail: configured == Some(boundary),
        }
    }
    pub(crate) fn finish(mut self) -> std::io::Result<(u64, [u8; 32])> {
        self.file.flush()?;
        Ok((self.bytes, self.hasher.finalize().into()))
    }
}
impl Write for HashingWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.fail {
            return Err(std::io::Error::from_raw_os_error(28));
        }
        let written = self.file.write(bytes)?;
        self.hasher.update(&bytes[..written]);
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(written).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("checkpoint byte count overflow"))?;
        Ok(written)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointIdentity {
    pub network: bitcoin_rs_primitives::Network,
    pub genesis: bitcoin_rs_primitives::Hash256,
}

pub use load::{
    CheckpointOpen, classify_checkpoint_error, classify_checkpoint_io, coinstats_artifact_payload,
    corrupt_checkpoint, open_current_checkpoint, read_manifest, require_filename, verify_artifact,
};
pub use publish::{ArtifactDigest, CheckpointStage, begin_publication, commit_publication};
