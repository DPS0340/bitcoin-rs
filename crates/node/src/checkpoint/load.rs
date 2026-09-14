//! Authenticated checkpoint loading, strict payload validation, and typed corruption classification.

use super::headers;
use super::{
    COINSTATS_ARTIFACT_LEN, COINSTATS_FILE, CheckpointError, CheckpointManifestV1,
    CoinStatsArtifactV1, HEADERS_FILE, RestoredChainstate, UTXO_FILE,
};
use bitcoin_rs_chain::{ChainWork, TipSnapshot};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::checkpoint::{
    CheckpointError as StoreError, coinstats_artifact_payload, decode_hex, hex_encode,
    require_filename, verify_artifact,
};
use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsAccumulator};
use bitcoin_rs_utxo::{UtxoSet, read_snapshot_strict_v4_observed};
use cap_std::fs::{Dir, File};
use sha2::Digest;
use std::io::{BufReader, Read};

pub(super) fn load_headers(
    generation_dir: &Dir,
    config: headers::HeaderCheckpointConfig,
    manifest: &CheckpointManifestV1,
) -> Result<headers::RestoredHeaders, CheckpointError> {
    require_filename(&manifest.headers.file, HEADERS_FILE).map_err(CheckpointError::Store)?;
    let mut file = verify_artifact(
        generation_dir,
        HEADERS_FILE,
        manifest.headers.bytes,
        &manifest.headers.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let expected = headers::HeaderCheckpointMetadata {
        header_count: manifest.headers.header_count,
        best: parse_tip(&manifest.best_header_tip)?,
        applied: parse_tip(&manifest.applied_tip)?,
        best_chain_commitment: decode_hex(&manifest.headers.best_chain_sha256)?,
        applied_prefix_commitment: decode_hex(&manifest.headers.applied_chain_sha256)?,
    };
    headers::read_headers(&mut file, config, expected).map_err(CheckpointError::Header)
}
pub(super) fn load_payloads(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    mut headers: headers::RestoredHeaders,
) -> Result<RestoredChainstate, CheckpointError> {
    let chain_tx_count = manifest.applied_tip.chain_tx_count;
    let (utxo, coin_stats) = load_payloads_inner(generation_dir, manifest, &headers)?;
    // Header reconstruction initializes counts to zero. Restore the exact
    // cumulative count on the applied tip; ancestor counts remain unknown.
    let mut cursor = Some(headers.applied_tip_id);
    while let Some(node_id) = cursor {
        let parent = headers
            .tree
            .node(node_id)
            .map_err(|error| CheckpointError::Header(error.into()))?
            .parent;
        headers.tree.restore_chain_tx_count(
            node_id,
            if node_id == headers.applied_tip_id {
                chain_tx_count
            } else {
                0
            },
        )?;
        cursor = parent;
    }
    let applied_node = headers
        .tree
        .node(headers.applied_tip_id)
        .map_err(|error| CheckpointError::Header(error.into()))?;
    let applied_tip = TipSnapshot {
        tip_id: headers.applied_tip_id,
        height: applied_node.height,
        chainwork: applied_node.chainwork,
        hash: applied_node.hash,
    };
    Ok(RestoredChainstate {
        generation: manifest.generation,
        tree: headers.tree,
        utxo,
        coin_stats,
        applied_tip,
        chain_tx_count,
    })
}
pub(super) fn load_payloads_inner(
    generation_dir: &Dir,
    manifest: &CheckpointManifestV1,
    headers: &headers::RestoredHeaders,
) -> Result<(UtxoSet, CoinStats), CheckpointError> {
    require_filename(&manifest.utxo.file, UTXO_FILE).map_err(CheckpointError::Store)?;
    require_filename(&manifest.coinstats.file, COINSTATS_FILE).map_err(CheckpointError::Store)?;
    if manifest.coinstats.bytes != COINSTATS_ARTIFACT_LEN {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats artifact is not exactly 820 bytes".to_owned(),
        )));
    }
    let utxo_file = verify_artifact(
        generation_dir,
        UTXO_FILE,
        manifest.utxo.bytes,
        &manifest.utxo.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let mut coinstats_file = verify_artifact(
        generation_dir,
        COINSTATS_FILE,
        manifest.coinstats.bytes,
        &manifest.coinstats.sha256,
    )
    .map_err(CheckpointError::Store)?;
    let expected_applied = parse_tip(&manifest.applied_tip)?;
    let (snapshot, mut derived) =
        read_checkpoint_snapshot(utxo_file, manifest.utxo.bytes, expected_applied.height)?;
    if (snapshot.height, snapshot.tip_hash) != (expected_applied.height, expected_applied.hash) {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO tip does not match manifest applied tip".to_owned(),
        )));
    }
    let record_count = u64::try_from(snapshot.set.record_count()).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "loaded UTXO record count does not fit u64".to_owned(),
        ))
    })?;
    if record_count != manifest.utxo.record_count {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO record count does not match manifest".to_owned(),
        )));
    }
    let trailer_digest: [u8; 32] = sha2::Sha256::digest(snapshot.muhash_trailer).into();
    if trailer_digest != decode_hex(&manifest.utxo.muhash_trailer_sha256)? {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO MuHash trailer digest does not match manifest".to_owned(),
        )));
    }
    let mut bytes = Vec::with_capacity(usize::try_from(COINSTATS_ARTIFACT_LEN).map_err(|_| {
        CheckpointError::Store(StoreError::Invalid(
            "CoinStats artifact length does not fit usize".to_owned(),
        ))
    })?);
    coinstats_file.read_to_end(&mut bytes)?;
    let payload = coinstats_artifact_payload(&bytes).map_err(CheckpointError::Store)?;
    let coin_stats = CoinStats::from_bytes(payload)?;
    validate_coinstats_manifest(&coin_stats, &manifest.coinstats)?;
    // Transaction count is chain metadata and cannot be derived from live coins.
    derived.tx_count = coin_stats.tx_count;
    if derived != coin_stats {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats does not match loaded UTXO traversal".to_owned(),
        )));
    }
    if coin_stats.utxo_count != manifest.utxo.output_count {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO output count does not match manifest".to_owned(),
        )));
    }
    if snapshot.muhash_trailer != coin_stats.muhash.finalize() {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "UTXO trailer does not match restored CoinStats".to_owned(),
        )));
    }
    let applied = headers.tree.node(headers.applied_tip_id)?;
    if (applied.height, applied.hash) != (snapshot.height, snapshot.tip_hash) {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "restored header and UTXO applied tips differ".to_owned(),
        )));
    }
    Ok((snapshot.set, coin_stats))
}
pub(super) fn read_checkpoint_snapshot(
    utxo_file: File,
    encoded_len: u64,
    height: u32,
) -> Result<(bitcoin_rs_utxo::SnapshotLoad, CoinStats), CheckpointError> {
    let mut limited =
        BufReader::new(utxo_file).take(encoded_len.checked_add(1).ok_or_else(|| {
            CheckpointError::Store(StoreError::Invalid("UTXO byte length overflow".to_owned()))
        })?);
    let (snapshot, accumulator) = read_snapshot_strict_v4_observed(
        &mut limited,
        CoinStatsAccumulator::with_parallel_muhash(height),
    )?;
    Ok((snapshot, accumulator.into_stats()))
}
pub(super) fn validate_coinstats_manifest(
    stats: &CoinStats,
    expected: &CoinStatsArtifactV1,
) -> Result<(), CheckpointError> {
    if stats.height != expected.height
        || stats.total_amount != expected.total_amount
        || stats.bogo_size != expected.bogo_size
        || stats.tx_count != expected.tx_count
        || stats.utxo_count != expected.utxo_count
        || hex_encode(&stats.muhash.finalize()) != expected.muhash
    {
        return Err(CheckpointError::Store(StoreError::Invalid(
            "CoinStats fields do not match manifest".to_owned(),
        )));
    }
    Ok(())
}
pub(super) fn parse_tip(
    tip: &super::CheckpointTipV1,
) -> Result<headers::HeaderCheckpointTip, CheckpointError> {
    Ok(headers::HeaderCheckpointTip {
        height: tip.height,
        hash: Hash256::from_str_be(&tip.hash)
            .map_err(|e| CheckpointError::Store(StoreError::Invalid(e.to_string())))?,
        chainwork: ChainWork::from_be_bytes(decode_hex::<32>(&tip.chainwork)?),
    })
}
