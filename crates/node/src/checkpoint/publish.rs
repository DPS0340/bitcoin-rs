//! One checkpoint publication transaction: prepare artifacts, sync, publish CURRENT, then retire old generations.

use super::headers;
use super::{
    COINSTATS_CODEC, COINSTATS_FILE, COINSTATS_MAGIC, COINSTATS_PAYLOAD_LEN, COINSTATS_VERSION,
    CheckpointError, CheckpointManifestV1, CheckpointTipV1, CheckpointWrite, CoinStatsArtifactV1,
    HEADER_CODEC, HEADERS_FILE, MANIFEST_FORMAT, MANIFEST_VERSION, UTXO_CODEC, UTXO_FILE,
    UTXO_VERSION,
};
use bitcoin_rs_chain::{BlockTree, NodeId, TipSnapshot};
use bitcoin_rs_storage::checkpoint::{
    CheckpointError as StoreError, CheckpointFailpoint, begin_publication, commit_publication,
    hex_encode, network_name,
};
use bitcoin_rs_utxo::{
    UtxoSet,
    stats::{CoinStatsAccumulator, CoinStatsListener},
    write_snapshot_observed,
};
use cap_std::fs::Dir;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

pub(super) fn checkpoint_best_tip_id(
    tree: &BlockTree,
    applied_tip: &TipSnapshot,
) -> Result<NodeId, CheckpointError> {
    let applied_id = tree.lookup(applied_tip.hash).ok_or_else(|| {
        CheckpointError::Store(StoreError::Invalid(
            "applied tip disappeared during checkpoint".to_owned(),
        ))
    })?;
    let best_tip_id = tree.tip_id().ok_or_else(|| {
        CheckpointError::Store(StoreError::Invalid(
            "applied tip exists without a best header tip".to_owned(),
        ))
    })?;
    if tree.node_at_height_from(best_tip_id, applied_tip.height) == Some(applied_id) {
        return Ok(best_tip_id);
    }
    Ok(applied_id)
}
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) fn write_checkpoint_from_dir(
    data_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    block_tree: &RwLock<BlockTree>,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    applied_tip: Option<&TipSnapshot>,
    chain_tx_count: u64,
) -> Result<CheckpointWrite, CheckpointError> {
    let Some(applied_tip) = applied_tip else {
        return Ok(CheckpointWrite::SkippedNoAppliedTip);
    };
    #[cfg(test)]
    let failpoint = super::NEXT_CHECKPOINT_FAILPOINT.with(std::cell::Cell::take);
    #[cfg(not(test))]
    let failpoint = None;
    let stage = begin_publication(data_dir, failpoint).map_err(CheckpointError::Store)?;
    let (headers_meta, headers_digest) = {
        let tree = block_tree.read();
        let (meta, digest) = stage.write_artifact(
            HEADERS_FILE,
            CheckpointFailpoint::HeadersWrite,
            CheckpointFailpoint::HeadersSync,
            |writer| {
                let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
                let point = headers::HeaderCheckpointPoint {
                    height: applied_tip.height,
                    hash: applied_tip.hash,
                };
                let metadata = if tree.tip_id() == Some(best_tip_id) {
                    headers::write_headers(writer, &tree, config, best_tip_id, point)?
                } else {
                    headers::write_selected_headers(writer, &tree, config, best_tip_id, point)?
                };
                Ok::<_, CheckpointError>(metadata)
            },
        )?;
        (meta, digest)
    };
    let (utxo_result, utxo_digest) = stage.write_artifact(
        UTXO_FILE,
        CheckpointFailpoint::UtxoWrite,
        CheckpointFailpoint::UtxoSync,
        |writer| {
            let (trailer, acc) = write_snapshot_observed(
                utxo,
                &applied_tip.hash,
                applied_tip.height,
                writer,
                CoinStatsAccumulator::with_parallel_muhash(applied_tip.height),
            )?;
            Ok::<_, CheckpointError>((trailer, acc))
        },
    )?;
    let (trailer, accumulator) = utxo_result;
    let listener_stats = coin_stats.snapshot();
    if listener_stats.height != applied_tip.height {
        return Err(CheckpointError::Store(StoreError::Invalid(format!(
            "CoinStats height {} does not match applied height {}",
            listener_stats.height, applied_tip.height
        ))));
    }
    let mut fused_stats = accumulator.into_stats();
    fused_stats.tx_count = listener_stats.tx_count;
    let record_count = utxo.record_count();
    if trailer == [0_u8; 384] {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "scanned UTXO snapshot has a zero MuHash trailer".to_owned(),
        )));
    }
    let persisted_stats = fused_stats;
    let ((), stats_digest) = stage.write_artifact(
        COINSTATS_FILE,
        CheckpointFailpoint::CoinStatsWrite,
        CheckpointFailpoint::CoinStatsSync,
        |writer| {
            writer.write_all(&COINSTATS_MAGIC)?;
            writer.write_all(&COINSTATS_VERSION.to_le_bytes())?;
            writer.write_all(&COINSTATS_PAYLOAD_LEN.to_le_bytes())?;
            writer.write_all(&persisted_stats.to_bytes())?;
            Ok::<_, CheckpointError>(())
        },
    )?;
    let tree = block_tree.read();
    let best_tip_id = checkpoint_best_tip_id(&tree, applied_tip)?;
    let best = tree.node(best_tip_id)?;
    if best.hash != headers_meta.metadata.best.hash
        || best.height != headers_meta.metadata.best.height
        || best.chainwork != headers_meta.metadata.best.chainwork
    {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "best header tip changed during checkpoint".to_owned(),
        )));
    }
    drop(tree);
    let record_count = u64::try_from(record_count).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "UTXO record count does not fit u64".to_owned(),
        ))
    })?;
    let manifest = CheckpointManifestV1 {
        format: MANIFEST_FORMAT.to_owned(),
        version: MANIFEST_VERSION,
        generation: stage.generation(),
        network: network_name(config.network).to_owned(),
        network_magic: hex_encode(&config.network.magic()),
        genesis_hash: config.genesis.to_string_be(),
        applied_tip: manifest_tip(headers_meta.metadata.applied, chain_tx_count),
        best_header_tip: manifest_tip(headers_meta.metadata.best, 0),
        headers: super::HeadersArtifactV1 {
            file: HEADERS_FILE.to_owned(),
            codec: HEADER_CODEC.to_owned(),
            version: headers::HEADER_VERSION,
            bytes: headers_digest.bytes,
            sha256: hex_encode(&headers_digest.sha256),
            header_count: headers_meta.metadata.header_count,
            best_chain_sha256: hex_encode(&headers_meta.metadata.best_chain_commitment),
            applied_chain_sha256: hex_encode(&headers_meta.metadata.applied_prefix_commitment),
        },
        utxo: super::UtxoArtifactV1 {
            file: UTXO_FILE.to_owned(),
            codec: UTXO_CODEC.to_owned(),
            version: UTXO_VERSION,
            bytes: utxo_digest.bytes,
            sha256: hex_encode(&utxo_digest.sha256),
            record_count,
            output_count: persisted_stats.utxo_count,
            muhash_trailer_sha256: hex_encode(&Sha256::digest(trailer)),
        },
        coinstats: CoinStatsArtifactV1 {
            file: COINSTATS_FILE.to_owned(),
            codec: COINSTATS_CODEC.to_owned(),
            version: COINSTATS_VERSION,
            bytes: stats_digest.bytes,
            sha256: hex_encode(&stats_digest.sha256),
            height: persisted_stats.height,
            total_amount: persisted_stats.total_amount,
            bogo_size: persisted_stats.bogo_size,
            tx_count: persisted_stats.tx_count,
            utxo_count: persisted_stats.utxo_count,
            muhash: hex_encode(&persisted_stats.muhash.finalize()),
        },
    };
    let generation = commit_publication(stage, &manifest)?;
    Ok(CheckpointWrite::Published { generation })
}
fn manifest_tip(tip: headers::HeaderCheckpointTip, chain_tx_count: u64) -> CheckpointTipV1 {
    let chainwork: [u8; 32] = tip.chainwork.to_be_bytes();
    CheckpointTipV1 {
        height: tip.height,
        hash: tip.hash.to_string_be(),
        chainwork: hex_encode(&chainwork),
        chain_tx_count,
    }
}
