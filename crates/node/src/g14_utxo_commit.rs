//! G14 UTXO commit timing sample emission for applied-block evidence.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, Result, bail, ensure};
use bitcoin_rs_primitives::Hash256;
use parking_lot::Mutex;
use serde::Serialize;

const LARGE_BLOCK_MIN_BYTES: u64 = 1_000_000;

type Samples = BTreeMap<u32, G14UtxoCommitSample>;

#[derive(Clone, Debug, PartialEq, Serialize)]
struct G14UtxoCommitSample {
    height: u32,
    block_hash: String,
    block_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_commit_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_commit_ms: Option<f64>,
}

pub(crate) struct G14UtxoCommitSampler {
    path: PathBuf,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: String,
    ibd_stop_hash: String,
    state: Mutex<G14UtxoCommitSamplerState>,
}

#[derive(Default)]
struct G14UtxoCommitSamplerState {
    samples: Samples,
    written: bool,
}

impl G14UtxoCommitSampler {
    pub(crate) fn open(
        path: impl Into<PathBuf>,
        ibd_start_height: u32,
        ibd_stop_height: u32,
        ibd_start_hash: String,
        ibd_stop_hash: String,
    ) -> Result<Self> {
        ensure!(
            ibd_stop_height >= ibd_start_height,
            "g14_utxo_commit_ibd_stop_height must be greater than or equal to g14_utxo_commit_ibd_start_height"
        );
        validate_block_hash(&ibd_start_hash, "g14_utxo_commit_ibd_start_hash")?;
        validate_block_hash(&ibd_stop_hash, "g14_utxo_commit_ibd_stop_hash")?;
        let path = path.into();
        ensure!(
            !path.exists(),
            "G14 UTXO commit sample path {} already exists",
            path.display()
        );
        Ok(Self {
            path,
            ibd_start_height,
            ibd_stop_height,
            ibd_start_hash,
            ibd_stop_hash,
            state: Mutex::new(G14UtxoCommitSamplerState::default()),
        })
    }

    pub(crate) fn wants_height(&self, height: u32) -> bool {
        (self.ibd_start_height..=self.ibd_stop_height).contains(&height)
    }

    pub(crate) fn record(
        &self,
        height: u32,
        block_hash: Hash256,
        block_size_bytes: usize,
        utxo_commit_dur: Duration,
    ) -> Result<()> {
        if !self.wants_height(height) {
            return Ok(());
        }
        let block_size_bytes = u64::try_from(block_size_bytes)
            .with_context(|| format!("block_size_bytes overflow at height {height}"))?;
        let is_boundary = height == self.ibd_start_height || height == self.ibd_stop_height;
        if !is_boundary && block_size_bytes < LARGE_BLOCK_MIN_BYTES {
            return Ok(());
        }
        let block_hash = block_hash.to_string_be();
        self.validate_bound_hash(height, &block_hash)?;
        let utxo_commit_us = u64::try_from(utxo_commit_dur.as_micros())
            .with_context(|| format!("utxo_commit_us overflow at height {height}"))
            .map(|micros| micros.max(1))?;
        let sample = G14UtxoCommitSample {
            height,
            block_hash,
            block_size_bytes,
            utxo_commit_us: Some(utxo_commit_us),
            utxo_commit_ms: None,
        };
        self.record_sample(sample)
    }

    fn validate_bound_hash(&self, height: u32, block_hash: &str) -> Result<()> {
        if height == self.ibd_start_height {
            ensure!(
                block_hash == self.ibd_start_hash,
                "G14 UTXO commit sample at start height {height} has hash {block_hash}, expected {}",
                self.ibd_start_hash
            );
        }
        if height == self.ibd_stop_height {
            ensure!(
                block_hash == self.ibd_stop_hash,
                "G14 UTXO commit sample at stop height {height} has hash {block_hash}, expected {}",
                self.ibd_stop_hash
            );
        }
        Ok(())
    }

    fn record_sample(&self, sample: G14UtxoCommitSample) -> Result<()> {
        let height = sample.height;
        let mut state = self.state.lock();
        if let Some(existing) = state.samples.get(&height) {
            ensure!(
                existing == &sample,
                "G14 UTXO commit sample height {height} changed"
            );
            if height == self.ibd_stop_height && !state.written {
                self.write_final_samples(&state.samples)?;
                state.written = true;
            }
            return Ok(());
        }
        validate_sample(
            &sample,
            self.ibd_start_height,
            self.ibd_stop_height,
            &self.ibd_start_hash,
            &self.ibd_stop_hash,
        )?;
        state.samples.insert(height, sample);
        if height == self.ibd_stop_height {
            self.write_final_samples(&state.samples)?;
            state.written = true;
        }
        Ok(())
    }

    fn write_final_samples(&self, samples: &Samples) -> Result<()> {
        validate_samples(
            samples,
            self.ibd_start_height,
            self.ibd_stop_height,
            &self.ibd_start_hash,
            &self.ibd_stop_hash,
        )?;
        write_samples(&self.path, samples)
    }
}

fn validate_block_hash(value: &str, name: &str) -> Result<()> {
    ensure!(
        is_lower_hex_hash(value),
        "{name} must be 64 lowercase hex characters"
    );
    Ok(())
}

fn validate_samples(
    samples: &Samples,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: &str,
    ibd_stop_hash: &str,
) -> Result<()> {
    ensure!(
        samples.contains_key(&ibd_start_height),
        "G14 UTXO commit samples missing start height {ibd_start_height}"
    );
    ensure!(
        samples.contains_key(&ibd_stop_height),
        "G14 UTXO commit samples missing stop height {ibd_stop_height}"
    );
    for (height, sample) in samples {
        ensure!(
            *height == sample.height,
            "G14 UTXO commit sample map key {height} must match sample height {}",
            sample.height
        );
        validate_sample(
            sample,
            ibd_start_height,
            ibd_stop_height,
            ibd_start_hash,
            ibd_stop_hash,
        )?;
    }
    Ok(())
}

fn validate_sample(
    sample: &G14UtxoCommitSample,
    ibd_start_height: u32,
    ibd_stop_height: u32,
    ibd_start_hash: &str,
    ibd_stop_hash: &str,
) -> Result<()> {
    let height = sample.height;
    ensure!(
        height >= ibd_start_height && height <= ibd_stop_height,
        "G14 UTXO commit sample height {height} is outside configured IBD window [{ibd_start_height}, {ibd_stop_height}]"
    );
    validate_block_hash(&sample.block_hash, "sample block_hash")?;
    if height == ibd_start_height {
        ensure!(
            sample.block_hash == ibd_start_hash,
            "G14 UTXO commit sample at start height {height} has hash {}, expected {ibd_start_hash}",
            sample.block_hash
        );
    }
    if height == ibd_stop_height {
        ensure!(
            sample.block_hash == ibd_stop_hash,
            "G14 UTXO commit sample at stop height {height} has hash {}, expected {ibd_stop_hash}",
            sample.block_hash
        );
    }
    if height != ibd_start_height && height != ibd_stop_height {
        ensure!(
            sample.block_size_bytes >= LARGE_BLOCK_MIN_BYTES,
            "G14 UTXO commit sample at height {height} has block_size_bytes {}, below {LARGE_BLOCK_MIN_BYTES}",
            sample.block_size_bytes
        );
    }
    if sample.utxo_commit_us.is_some() && sample.utxo_commit_ms.is_some() {
        bail!(
            "G14 UTXO commit sample at height {height} must not include both utxo_commit_us and utxo_commit_ms"
        );
    }
    if let Some(us) = sample.utxo_commit_us {
        ensure!(us > 0, "utxo_commit_us must be positive at height {height}");
    }
    if let Some(ms) = sample.utxo_commit_ms {
        ensure!(
            ms.is_finite() && ms > 0.0,
            "utxo_commit_ms must be finite and positive at height {height}"
        );
    }
    if sample.utxo_commit_us.is_none() && sample.utxo_commit_ms.is_none() {
        bail!(
            "G14 UTXO commit sample at height {height} must include utxo_commit_us or utxo_commit_ms"
        );
    }
    Ok(())
}

fn parent_dir(path: &Path) -> Option<&Path> {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
}

fn prepare_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = parent_dir(path) {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "create G14 UTXO commit sample directory {}",
                parent.display()
            )
        })?;
    }
    Ok(())
}

fn write_samples(path: &Path, samples: &Samples) -> Result<()> {
    prepare_parent_dir(path)?;
    let body = serde_json::to_vec(&samples.values().collect::<Vec<&G14UtxoCommitSample>>())
        .with_context(|| format!("encode G14 UTXO commit samples {}", path.display()))?;
    let tmp = temp_path(path, "samples");
    {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp)
            .with_context(|| format!("open tmp G14 UTXO commit samples {}", tmp.display()))?;
        std::io::Write::write_all(&mut file, &body)
            .with_context(|| format!("write tmp G14 UTXO commit samples {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("fsync tmp G14 UTXO commit samples {}", tmp.display()))?;
    }
    std::fs::hard_link(&tmp, path)
        .with_context(|| format!("publish G14 UTXO commit samples {}", path.display()))?;
    let _ = std::fs::remove_file(&tmp);
    if let Some(parent) = parent_dir(path)
        && let Ok(dir) = std::fs::File::open(parent)
    {
        let _ = dir.sync_all();
    }
    Ok(())
}

fn temp_path(path: &Path, tag: &str) -> PathBuf {
    let mut file_name = path
        .file_name()
        .map_or_else(|| OsString::from("g14-utxo.samples.json"), OsString::from);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    file_name.push(format!(".{}.{}.{}.tmp", std::process::id(), nonce, tag));
    path.with_file_name(file_name)
}

fn is_lower_hex_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const START_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const STOP_HASH: &str = "000000000000000000000000000000000000000000000000000000000000000a";

    fn start_hash_bytes() -> [u8; 32] {
        [0; 32]
    }

    fn stop_hash_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        bytes[0] = 0x0a;
        bytes
    }

    fn parse_samples_json(path: &Path) -> Result<Vec<Value>> {
        let text = std::fs::read_to_string(path)?;
        let value: Value = serde_json::from_str(&text)?;
        value
            .as_array()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("G14 UTXO commit samples JSON must be an array"))
    }

    fn sample_height(sample: &Value) -> Result<u32> {
        let height = sample["height"]
            .as_u64()
            .ok_or_else(|| anyhow::anyhow!("sample height must be a u64"))?;
        u32::try_from(height).context("sample height must fit u32")
    }

    fn open_sampler(path: &Path) -> Result<G14UtxoCommitSampler> {
        G14UtxoCommitSampler::open(path, 0, 10, START_HASH.to_owned(), STOP_HASH.to_owned())
    }

    #[test]
    fn writes_compact_sparse_json() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(1),
        )?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            1_000_000,
            Duration::from_micros(2),
        )?;
        sampler.record(
            10,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            1_000_000,
            Duration::from_micros(3),
        )?;
        sampler.record(
            10,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            1_000_000,
            Duration::from_micros(3),
        )?;

        assert!(path.exists());
        let bytes = std::fs::read(&path)?;
        assert!(
            !bytes.contains(&b'\n'),
            "sample output must be compact JSON"
        );

        let samples = parse_samples_json(&path)?;
        assert_eq!(samples.len(), 3);
        let heights = samples
            .iter()
            .map(sample_height)
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(heights, vec![0, 1, 10]);
        Ok(())
    }

    #[test]
    fn interior_below_threshold_is_absent() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            999_999,
            Duration::from_micros(1),
        )?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            999_999,
            Duration::from_micros(2),
        )?;
        sampler.record(
            10,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            100,
            Duration::from_micros(3),
        )?;

        let samples = parse_samples_json(&path)?;
        assert_eq!(samples.len(), 2);
        assert!(
            samples.iter().all(|s| s["height"].as_u64() != Some(1)),
            "below-threshold interior must not be sampled"
        );
        let heights = samples
            .iter()
            .map(sample_height)
            .collect::<Result<Vec<_>>>()?;
        assert_eq!(heights, vec![0, 10]);
        assert_eq!(samples[0]["block_size_bytes"].as_u64(), Some(999_999));
        assert_eq!(samples[1]["block_size_bytes"].as_u64(), Some(100));
        Ok(())
    }

    #[test]
    fn interior_at_threshold_is_present() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(1),
        )?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            1_000_000,
            Duration::from_micros(2),
        )?;
        sampler.record(
            10,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            1_000_000,
            Duration::from_micros(3),
        )?;

        let samples = parse_samples_json(&path)?;
        assert_eq!(samples.len(), 3);
        let interior = samples
            .iter()
            .find(|sample| sample["height"].as_u64() == Some(1))
            .ok_or_else(|| anyhow::anyhow!("threshold interior must be present"))?;
        assert_eq!(interior["block_size_bytes"].as_u64(), Some(1_000_000));
        assert_eq!(interior["utxo_commit_us"].as_u64(), Some(2));
        Ok(())
    }

    #[test]
    fn low_size_boundaries_are_present() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler =
            G14UtxoCommitSampler::open(&path, 0, 1, START_HASH.to_owned(), STOP_HASH.to_owned())?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            999_999,
            Duration::from_micros(1),
        )?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            100,
            Duration::from_micros(2),
        )?;

        let samples = parse_samples_json(&path)?;
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0]["height"].as_u64(), Some(0));
        assert_eq!(samples[0]["block_size_bytes"].as_u64(), Some(999_999));
        assert_eq!(samples[1]["height"].as_u64(), Some(1));
        assert_eq!(samples[1]["block_size_bytes"].as_u64(), Some(100));
        Ok(())
    }

    #[test]
    fn start_equals_stop_works() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler =
            G14UtxoCommitSampler::open(&path, 5, 5, START_HASH.to_owned(), START_HASH.to_owned())?;
        sampler.record(
            5,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(7),
        )?;

        let samples = parse_samples_json(&path)?;
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0]["height"].as_u64(), Some(5));
        assert_eq!(samples[0]["block_size_bytes"].as_u64(), Some(1_000_000));
        Ok(())
    }

    #[test]
    fn rejects_existing_path() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        std::fs::write(&path, b"[]")?;
        let result =
            G14UtxoCommitSampler::open(&path, 0, 10, START_HASH.to_owned(), STOP_HASH.to_owned());
        let Err(error) = result else {
            panic!("expected open to fail when path already exists");
        };
        assert!(error.to_string().contains("already exists"));
        Ok(())
    }

    #[test]
    fn rejects_inconsistent_existing_sample() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            1_000_000,
            Duration::from_micros(10),
        )?;
        let error = match sampler.record(
            1,
            Hash256::from_le_bytes(&[2; 32]),
            1_000_000,
            Duration::from_micros(10),
        ) {
            Err(e) => e,
            Ok(()) => panic!("expected record to fail on inconsistent sample"),
        };
        assert!(error.to_string().contains("changed"));
        Ok(())
    }

    #[test]
    fn file_not_created_before_stop_height() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(1),
        )?;
        sampler.record(
            1,
            Hash256::from_le_bytes(&[1; 32]),
            1_000_000,
            Duration::from_micros(2),
        )?;
        assert!(
            !path.exists(),
            "sample file must not exist before stop height"
        );
        Ok(())
    }

    #[test]
    fn retries_stop_write_after_failure() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let blocked_parent = dir.path().join("blocked");
        let path = blocked_parent.join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(1),
        )?;
        std::fs::write(&blocked_parent, b"not a directory")?;
        assert!(
            sampler
                .record(
                    10,
                    Hash256::from_le_bytes(&stop_hash_bytes()),
                    1_000_000,
                    Duration::from_micros(2),
                )
                .is_err()
        );
        assert!(!path.exists());

        std::fs::remove_file(&blocked_parent)?;
        std::fs::create_dir(&blocked_parent)?;
        sampler.record(
            10,
            Hash256::from_le_bytes(&stop_hash_bytes()),
            1_000_000,
            Duration::from_micros(2),
        )?;
        assert!(path.exists());
        Ok(())
    }

    #[test]
    fn retry_rejects_destination_created_after_failure() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let blocked_parent = dir.path().join("blocked");
        let path = blocked_parent.join("utxo.samples.json");
        let sampler = open_sampler(&path)?;
        sampler.record(
            0,
            Hash256::from_le_bytes(&start_hash_bytes()),
            1_000_000,
            Duration::from_micros(1),
        )?;
        std::fs::write(&blocked_parent, b"not a directory")?;
        assert!(
            sampler
                .record(
                    10,
                    Hash256::from_le_bytes(&stop_hash_bytes()),
                    1_000_000,
                    Duration::from_micros(2),
                )
                .is_err()
        );

        std::fs::remove_file(&blocked_parent)?;
        std::fs::create_dir(&blocked_parent)?;
        std::fs::write(&path, b"stale evidence")?;
        assert!(
            sampler
                .record(
                    10,
                    Hash256::from_le_bytes(&stop_hash_bytes()),
                    1_000_000,
                    Duration::from_micros(2),
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&path)?, b"stale evidence");
        Ok(())
    }
}
