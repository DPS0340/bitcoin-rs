//! Checkpoint formats, loading, and publication.

mod load;
mod publish;
pub(crate) mod publisher;

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_primitives::Hash256;
#[cfg(test)]
use bitcoin_rs_storage::checkpoint::open_data_dir;
use bitcoin_rs_storage::checkpoint::{
    CheckpointError as StoreError, CheckpointIdentity, open_current_checkpoint, read_manifest,
};
pub(crate) use bitcoin_rs_storage::checkpoint::{
    CheckpointLoadError, CheckpointOpen, classify_checkpoint_io, corrupt_checkpoint,
};
use bitcoin_rs_utxo::UtxoSet;
#[cfg(test)]
use bitcoin_rs_utxo::stats::CoinStatsListener;
use bitcoin_rs_utxo::stats::{CoinStats, coin_stats::COIN_STATS_ENCODED_LEN};
use cap_std::fs::Dir;
use load::load_headers;
use load::load_payloads;
#[cfg(test)]
use parking_lot::RwLock;
pub(crate) use publish::write_checkpoint_from_dir;
#[cfg(test)]
use std::path::Path;
use thiserror::Error;

fn classify_checkpoint_error(error: CheckpointError) -> CheckpointLoadError {
    match error {
        // Direct checkpoint I/O or domain I/O failed transiently.
        CheckpointError::Io(error)
        | CheckpointError::FullRevalidationMarker(error)
        | CheckpointError::Utxo(bitcoin_rs_utxo::UtxoError::Io(error))
        | CheckpointError::Storage(bitcoin_rs_storage::StorageError::Io(error)) => {
            classify_checkpoint_io(error)
        }
        // Storage protocol validation failed and owns its classification.
        CheckpointError::Store(error) => {
            bitcoin_rs_storage::checkpoint::classify_checkpoint_error(error)
        }
        // Domain decoding or consistency validation failed.
        error => corrupt_checkpoint(error.to_string()),
    }
}

pub(crate) mod headers;

pub(crate) use bitcoin_rs_storage::checkpoint::hex_encode;
#[cfg(test)]
pub(crate) use bitcoin_rs_storage::checkpoint::{
    CHECKPOINT_ROOT, CURRENT_FILE, CheckpointCorruption, CheckpointFailpoint, CurrentV1,
    MANIFEST_FILE,
};
pub(crate) use bitcoin_rs_storage::checkpoint::{
    COINSTATS_ARTIFACT_LEN, COINSTATS_CODEC, COINSTATS_FILE, COINSTATS_MAGIC,
    COINSTATS_PAYLOAD_LEN, COINSTATS_VERSION, CheckpointManifestV1, CheckpointTipV1,
    CoinStatsArtifactV1, HEADER_CODEC, HEADERS_FILE, HeadersArtifactV1, MANIFEST_FORMAT,
    MANIFEST_VERSION, UTXO_CODEC, UTXO_FILE, UTXO_VERSION, UtxoArtifactV1,
};

pub(crate) enum CheckpointLoad {
    Cold,
    Complete(Box<RestoredChainstate>),
}

pub(crate) struct RestoredChainstate {
    /// Authenticated immutable checkpoint generation from `CURRENT`/manifest.
    pub(crate) generation: u64,
    pub(crate) tree: BlockTree,
    pub(crate) utxo: UtxoSet,
    pub(crate) coin_stats: CoinStats,
    pub(crate) applied_tip: TipSnapshot,
    /// Cumulative transaction count through `applied_tip`, or `0` when the
    /// manifest predates the field.
    pub(crate) chain_tx_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CheckpointWrite {
    SkippedNoAppliedTip,
    Published { generation: u64 },
}

#[derive(Debug, Error)]
pub(crate) enum CheckpointError {
    #[error("header checkpoint failed: {0}")]
    Header(#[from] headers::HeaderCheckpointError),
    #[error("checkpoint chain state failed: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error("UTXO checkpoint failed: {0}")]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error("CoinStats checkpoint decode failed: {0}")]
    CoinStats(#[from] bitcoin_rs_utxo::stats::CoinStatsDecodeError),
    #[error("checkpoint I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("checkpoint block-body durability failed: {0}")]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("checkpoint refused while disconnect of block {hash} at height {height} is in flight")]
    DisconnectInFlight { hash: Hash256, height: u32 },
    #[error(
        "checkpoint of tip {tip} at height {tip_height} is ahead of the durable head {head} at height {head_height}"
    )]
    AheadOfDurableHead {
        tip: Hash256,
        tip_height: u32,
        head: Hash256,
        head_height: u32,
    },
    /// The replacement checkpoint's `CURRENT` is already durable; retiring the sticky
    /// full-revalidation marker failed. Retryable I/O owned by the checkpoint worker,
    /// not checkpoint corruption.
    #[error("failed to retire full-revalidation marker: {0}")]
    FullRevalidationMarker(std::io::Error),
}

#[allow(clippy::as_conversions)]
const _: () = assert!(COINSTATS_PAYLOAD_LEN as usize == COIN_STATS_ENCODED_LEN);

pub(crate) fn load_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let opened = open_current_checkpoint(data_dir)?;
    let CheckpointOpen::Current {
        generation_dir,
        current,
    } = opened
    else {
        return Ok(CheckpointLoad::Cold);
    };
    let manifest = read_manifest(
        &generation_dir,
        &current,
        CheckpointIdentity {
            network: config.network,
            genesis: config.genesis,
        },
    )
    .map_err(|error| classify_checkpoint_error(error.into()))?;
    if manifest.headers.version != headers::HEADER_VERSION {
        return Err(corrupt_checkpoint(format!(
            "headers checkpoint version {} is not current",
            manifest.headers.version
        )));
    }
    if manifest.headers.codec != HEADER_CODEC {
        return Err(corrupt_checkpoint(format!(
            "unexpected headers checkpoint codec {}",
            manifest.headers.codec
        )));
    }
    let restored_headers = match load_headers(&generation_dir, config, &manifest) {
        Ok(headers) => headers,
        // Header codec reported a checkpoint version newer than this node.
        Err(CheckpointError::Header(headers::HeaderCheckpointError::UnsupportedVersion {
            actual,
        })) => {
            return Err(corrupt_checkpoint(format!(
                "headers checkpoint version {actual} is not current"
            )));
        }
        // Header loading failed for a non-version corruption or I/O reason.
        Err(error) => return Err(classify_checkpoint_error(error)),
    };
    if manifest.utxo.version != UTXO_VERSION {
        return Err(corrupt_checkpoint(format!(
            "UTXO checkpoint version {} is not current",
            manifest.utxo.version
        )));
    }
    if manifest.coinstats.version != COINSTATS_VERSION {
        return Err(corrupt_checkpoint(format!(
            "CoinStats checkpoint version {} is not current",
            manifest.coinstats.version
        )));
    }
    if manifest.utxo.codec != UTXO_CODEC || manifest.coinstats.codec != COINSTATS_CODEC {
        return Err(corrupt_checkpoint(format!(
            "unexpected payload codecs UTXO={} CoinStats={}",
            manifest.utxo.codec, manifest.coinstats.codec
        )));
    }
    match load_payloads(&generation_dir, &manifest, restored_headers) {
        Ok(restored) => Ok(CheckpointLoad::Complete(Box::new(restored))),
        // Payload loading failed after authenticated metadata checks.
        Err(error) => Err(classify_checkpoint_error(error)),
    }
}

#[cfg(test)]
fn write_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
) -> Result<CheckpointWrite, CheckpointError> {
    let data_dir = open_data_dir(data_dir)?;
    write_checkpoint_from_dir(
        &data_dir,
        config,
        block_tree,
        utxo,
        coin_stats,
        applied_tip,
        0,
    )
}

#[cfg(test)]
pub(crate) fn load_checkpoint(
    data_dir: &Path,
    config: headers::HeaderCheckpointConfig,
) -> Result<CheckpointLoad, CheckpointLoadError> {
    let data_dir = match open_data_dir(data_dir) {
        Ok(data_dir) => data_dir,
        Err(_) => return Ok(CheckpointLoad::Cold),
    };
    load_checkpoint_from_dir(&data_dir, config)
}

#[cfg(test)]
std::thread_local! {
    static NEXT_CHECKPOINT_FAILPOINT: std::cell::Cell<Option<CheckpointFailpoint>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject_next_checkpoint_failpoint(failpoint: CheckpointFailpoint) {
    NEXT_CHECKPOINT_FAILPOINT.with(|slot| slot.set(Some(failpoint)));
}

#[cfg(test)]
mod tests;
