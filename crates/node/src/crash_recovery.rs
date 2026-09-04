//! Crash-recovery progress names a tip whose bodies are durable.
//!
//! On boot, the node loads the clean-checkpoint base and replays `(base + 1)..=H`
//! from stored bodies. The unrecovered window is bounded by
//! [`PROGRESS_INTERVAL_BLOCKS`] and [`PROGRESS_INTERVAL`].

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result, bail};
use serde::{Deserialize, Serialize};

use crate::apply::PruneBodyStore;
use crate::state::NodeState;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_storage::StorageError;

/// Filename of the recovery sidecar inside the data directory.
pub const META_FILENAME: &str = "recovery_meta.json";

/// Blocks applied between two recovery-progress publications.
pub const PROGRESS_INTERVAL_BLOCKS: u32 = 1_000;
/// Wall-clock bound between two recovery-progress publications.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

/// Recovery sidecar contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Height through which stored block bodies are durable.
    pub height: u32,
    /// Big-endian hexadecimal hash of the durable tip.
    pub tip_hash_hex: String,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum ProgressError {
    #[error("body sync failed: {0}")]
    BodySync(#[source] StorageError),
    #[error("recovery sidecar write failed: {0}")]
    Sidecar(#[source] anyhow::Error),
}

struct Cadence {
    height: u32,
    at: Instant,
}

/// Owns the crash-recovery sidecar: makes the stored block bodies durable,
/// then names the applied tip.
pub(crate) struct ProgressPublisher {
    meta_path: PathBuf,
    body_store: Arc<dyn PruneBodyStore>,
    cadence: parking_lot::Mutex<Cadence>,
}

impl ProgressPublisher {
    pub(crate) fn new(
        meta_path: PathBuf,
        body_store: Arc<dyn PruneBodyStore>,
        base_height: u32,
    ) -> Self {
        Self {
            meta_path,
            body_store,
            cadence: parking_lot::Mutex::new(Cadence {
                height: base_height,
                at: Instant::now(),
            }),
        }
    }

    /// Records an applied block when the progress cadence is due.
    ///
    /// Never publishes a height at or below the last named durable height.
    /// Recovery replay and a later time-cadence tick therefore cannot overwrite
    /// the sidecar with a lower height; [`Self::publish_now`] is the explicit
    /// rollback path after a checkpoint or reorg.
    pub(crate) fn record_applied(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<bool, ProgressError> {
        let mut cadence = self.cadence.lock();
        if height <= cadence.height {
            return Ok(false);
        }
        if height < cadence.height.saturating_add(PROGRESS_INTERVAL_BLOCKS)
            && cadence.at.elapsed() < PROGRESS_INTERVAL
        {
            return Ok(false);
        }

        self.publish_inner(&mut cadence, height, hash)?;
        Ok(true)
    }

    /// Publishes the supplied tip immediately, bypassing the normal cadence.
    pub(crate) fn publish_now(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), ProgressError> {
        let mut cadence = self.cadence.lock();
        self.publish_inner(&mut cadence, height, hash)
    }

    fn publish_inner(
        &self,
        cadence: &mut Cadence,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), ProgressError> {
        self.body_store.sync().map_err(ProgressError::BodySync)?;
        write_meta_to_path(
            &self.meta_path,
            &Meta {
                height,
                tip_hash_hex: hash.to_string_be(),
            },
        )
        .map_err(ProgressError::Sidecar)?;
        cadence.height = height;
        cadence.at = Instant::now();
        Ok(())
    }

    fn set_cadence(&self, height: u32) {
        let mut cadence = self.cadence.lock();
        cadence.height = height;
        cadence.at = Instant::now();
    }

    #[cfg(test)]
    fn expire_cadence(&self) {
        let mut cadence = self.cadence.lock();
        cadence.at = Instant::now()
            .checked_sub(PROGRESS_INTERVAL)
            .unwrap_or(cadence.at);
    }
}

fn meta_path(state: &NodeState) -> PathBuf {
    state.data_dir().join(META_FILENAME)
}

/// Reads the recovery sidecar, returning `None` if no file exists yet.
pub fn read_meta(state: &NodeState) -> Result<Option<Meta>> {
    let path = meta_path(state);
    read_meta_from_path(&path)
}

/// Reads the recovery sidecar from `path`, returning `None` if no file exists.
fn read_meta_from_path(path: &Path) -> Result<Option<Meta>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(path).with_context(|| format!("read recovery meta {}", path.display()))?;
    let meta: Meta = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse recovery meta {}", path.display()))?;
    Ok(Some(meta))
}

/// Overwrites the recovery sidecar with `meta`.
pub fn write_meta(state: &NodeState, meta: &Meta) -> Result<()> {
    write_meta_to_path(&meta_path(state), meta)
}

/// Writes the recovery sidecar at `path` using atomic rename + fsync.
pub fn write_meta_to_path(path: &Path, meta: &Meta) -> Result<()> {
    use std::io::Write as _;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = path.with_extension("json.tmp");
    let json = serde_json::to_vec_pretty(meta)
        .with_context(|| format!("encode recovery meta {}", path.display()))?;

    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open tmp recovery meta {}", tmp.display()))?;
        file.write_all(&json)
            .with_context(|| format!("write tmp recovery meta {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync tmp recovery meta {}", tmp.display()))?;
    }

    std::fs::rename(&tmp, path)
        .with_context(|| format!("atomic rename recovery meta {}", path.display()))?;
    // Best-effort directory fsync. POSIX allows the rename to be re-ordered until
    // the parent directory's inode is synced. Failing the fsync (e.g. on filesystems
    // that don't support it) is non-fatal — the rename already happened.
    if let Ok(dir_handle) = std::fs::File::open(dir) {
        let _ = dir_handle.sync_all();
    }

    Ok(())
}

/// Detects a gap between the restored checkpoint and the last applied tip,
/// and replays it from stored block bodies.
pub fn recover_if_needed(state: &NodeState) -> Result<()> {
    let Some(meta) = read_meta(state)? else {
        tracing::debug!("no recovery metadata; fresh node");
        return Ok(());
    };

    let restored_applied_tip = state.applied_tip().load_full();
    let gap_base = restored_applied_tip.as_ref().map_or(0, |tip| tip.height);
    if restored_applied_tip.is_some() && meta.height <= gap_base {
        tracing::debug!(height = meta.height, gap_base, "no gap; recovery skipped");
        return Ok(());
    }

    tracing::warn!(
        height = meta.height,
        gap_base,
        "crash-recovery gap detected: base at {} but tip was at {}",
        gap_base,
        meta.height
    );

    let tip_hash = parse_hash_hex(&meta.tip_hash_hex)
        .ok_or_else(|| anyhow::anyhow!("invalid recovery tip hash {}", meta.tip_hash_hex))?;
    // Adopt the sidecar's named height before replay so `record_applied` cannot
    // publish a lower height once the time cadence elapses. If replay fails,
    // withdraw that high-water mark to the restored base so a refetch can
    // republish after `PROGRESS_INTERVAL_BLOCKS`.
    if let Some(progress) = &state.apply_handles().recovery_progress {
        progress.set_cadence(meta.height);
    }
    match replay_from_bodies(
        state,
        restored_applied_tip.as_deref(),
        meta.height,
        tip_hash,
    ) {
        Ok(replayed) => {
            for height in &replayed {
                state.push_replayed(*height);
            }
            let first_replayed = replayed.first().copied().unwrap_or(gap_base);
            let last_replayed = replayed.last().copied().unwrap_or(gap_base);
            tracing::info!(
                replayed = replayed.len(),
                from = first_replayed,
                to = last_replayed,
                "crash recovery replayed from stored bodies"
            );
        }
        Err(error) => {
            if let Some(progress) = &state.apply_handles().recovery_progress {
                progress.set_cadence(gap_base);
            }
            tracing::warn!(
                %error,
                "replay from stored bodies failed; node resumes at the restored base and sync will refetch the gap"
            );
        }
    }
    Ok(())
}

/// Walks backward from `(tip_height, tip_hash)` to the restored tip,
/// collecting blocks, then applies them forward through the apply path.
fn replay_from_bodies(
    state: &NodeState,
    restored_tip: Option<&TipSnapshot>,
    tip_height: u32,
    tip_hash: bitcoin_rs_primitives::Hash256,
) -> Result<Vec<u32>> {
    let handles = state.apply_handles();
    let body_store = handles
        .block_body_store
        .as_ref()
        .context("no block body store available for crash recovery replay")?;

    // Walk backward from the tip, collecting (height, block) pairs.
    let mut blocks: Vec<(u32, bitcoin_rs_primitives::Block)> = Vec::new();
    let mut current_hash = tip_hash;
    let mut current_height = tip_height;

    let restored_height = restored_tip.map(|tip| tip.height);
    loop {
        if restored_height.is_some_and(|base| current_height <= base) {
            break;
        }
        let body_bytes = body_store
            .load_block_body(current_height, current_hash)
            .with_context(|| format!("load block body for replay at height {current_height}"))?
            .with_context(|| {
                format!(
                    "block body missing for replay at height {current_height}; \
                     it may have been pruned or not yet flushed to disk"
                )
            })?;

        let block: bitcoin_rs_primitives::Block =
            bitcoin_rs_primitives::encode::deserialize(&body_bytes)
                .with_context(|| format!("deserialize block body at height {current_height}"))?;

        let prev_hash = block.header.prev_blockhash.0;
        blocks.push((current_height, block));

        if current_height == 0 {
            break;
        }
        current_hash = prev_hash;
        current_height -= 1;
    }
    if let Some(restored_tip) = restored_tip
        && current_hash != restored_tip.hash
    {
        bail!(
            "stored bodies at height {} do not descend from the restored tip {}",
            tip_height,
            restored_tip.hash.to_string_be()
        );
    }

    // Reverse to apply in forward order.
    blocks.reverse();

    let mut replayed = Vec::with_capacity(blocks.len());
    for (height, block) in blocks {
        let tip = state
            .apply_block(&block)
            .map_err(|error| anyhow::anyhow!("replay apply failed at height {height}: {error}"))?;
        tracing::debug!(
            height,
            hash = %tip.hash.to_string_be(),
            "replayed block through apply path"
        );
        replayed.push(height);
    }

    Ok(replayed)
}

/// Parses a big-endian hex string into a `Hash256`.
fn parse_hash_hex(hex: &str) -> Option<bitcoin_rs_primitives::Hash256> {
    bitcoin_rs_primitives::Hash256::from_str_be(hex).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct MapBodyStore {
        path: PathBuf,
        sync_calls: AtomicUsize,
        fail_sync: AtomicBool,
        #[allow(clippy::option_option)]
        sidecar_seen_at_sync: parking_lot::Mutex<Option<Option<Meta>>>,
    }

    impl MapBodyStore {
        fn new(path: PathBuf) -> Self {
            Self {
                path,
                sync_calls: AtomicUsize::new(0),
                fail_sync: AtomicBool::new(false),
                sidecar_seen_at_sync: parking_lot::Mutex::new(None),
            }
        }
    }

    impl PruneBodyStore for MapBodyStore {
        fn persist_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
            _body: &[u8],
        ) -> core::result::Result<(), StorageError> {
            Ok(())
        }

        fn load_block_body(
            &self,
            _height: u32,
            _hash: bitcoin_rs_primitives::Hash256,
        ) -> core::result::Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }

        fn sync(&self) -> core::result::Result<(), StorageError> {
            self.sync_calls.fetch_add(1, Ordering::Relaxed);
            let current = read_meta_from_path(&self.path).unwrap_or_default();
            *self.sidecar_seen_at_sync.lock() = Some(current);
            if self.fail_sync.load(Ordering::Relaxed) {
                return Err(StorageError::Backend("injected sync failure".to_owned()));
            }
            Ok(())
        }
    }

    fn hash(byte: u8) -> bitcoin_rs_primitives::Hash256 {
        bitcoin_rs_primitives::Hash256::from_le_bytes(&[byte; 32])
    }

    #[test]
    fn progress_is_published_only_after_bodies_sync() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join(META_FILENAME);
        let store = Arc::new(MapBodyStore::new(path.clone()));
        let publisher = ProgressPublisher::new(path.clone(), store.clone(), 0);

        assert!(publisher.record_applied(PROGRESS_INTERVAL_BLOCKS, hash(1))?);
        assert_eq!(store.sync_calls.load(Ordering::Relaxed), 1);
        assert_eq!(*store.sidecar_seen_at_sync.lock(), Some(None));
        assert_eq!(
            read_meta_from_path(&path)?,
            Some(Meta {
                height: PROGRESS_INTERVAL_BLOCKS,
                tip_hash_hex: hash(1).to_string_be(),
            })
        );
        Ok(())
    }

    #[test]
    fn sync_failure_leaves_prior_progress_in_place() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join(META_FILENAME);
        let store = Arc::new(MapBodyStore::new(path.clone()));
        let publisher = ProgressPublisher::new(path.clone(), store.clone(), 0);
        let first = hash(1);
        let second = hash(2);
        let third = hash(3);

        assert!(publisher.record_applied(1_000, first)?);
        store.fail_sync.store(true, Ordering::Relaxed);
        assert!(publisher.record_applied(2_000, second).is_err());
        assert_eq!(
            read_meta_from_path(&path)?,
            Some(Meta {
                height: 1_000,
                tip_hash_hex: first.to_string_be(),
            })
        );
        store.fail_sync.store(false, Ordering::Relaxed);
        assert!(publisher.record_applied(2_001, third)?);
        assert_eq!(
            read_meta_from_path(&path)?,
            Some(Meta {
                height: 2_001,
                tip_hash_hex: third.to_string_be(),
            })
        );
        Ok(())
    }

    #[test]
    fn progress_is_not_published_before_the_cadence() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join(META_FILENAME);
        let store = Arc::new(MapBodyStore::new(path.clone()));
        let publisher = ProgressPublisher::new(path.clone(), store.clone(), 0);

        assert!(!publisher.record_applied(1, hash(1))?);
        assert_eq!(store.sync_calls.load(Ordering::Relaxed), 0);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn record_applied_does_not_regress_published_height_after_cadence_elapses() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join(META_FILENAME);
        let store = Arc::new(MapBodyStore::new(path.clone()));
        let publisher = ProgressPublisher::new(path.clone(), store, 0);
        let first = hash(1);
        let lower = hash(2);

        assert!(publisher.record_applied(11_000, first)?);
        publisher.expire_cadence();
        assert!(!publisher.record_applied(10_001, lower)?);
        assert_eq!(
            read_meta_from_path(&path)?,
            Some(Meta {
                height: 11_000,
                tip_hash_hex: first.to_string_be(),
            })
        );
        Ok(())
    }

    #[test]
    fn failed_replay_cadence_allows_block_count_republication() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join(META_FILENAME);
        let store = Arc::new(MapBodyStore::new(path.clone()));
        let publisher = ProgressPublisher::new(path.clone(), store, 0);
        let recovered = hash(1);
        let refetched = hash(2);

        publisher.set_cadence(11_000);
        publisher.expire_cadence();
        assert!(!publisher.record_applied(10_001, recovered)?);
        publisher.set_cadence(0);
        assert!(publisher.record_applied(PROGRESS_INTERVAL_BLOCKS, refetched)?);
        assert_eq!(
            read_meta_from_path(&path)?,
            Some(Meta {
                height: PROGRESS_INTERVAL_BLOCKS,
                tip_hash_hex: refetched.to_string_be(),
            })
        );
        Ok(())
    }
}
