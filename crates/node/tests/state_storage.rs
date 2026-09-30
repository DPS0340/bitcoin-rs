//! Integration test: `NodeState` opens the configured storage backend, and
//! hands it the cache share the process budget allocated to chainstate.

use std::sync::Arc;

use hashbrown::HashMap;
use parking_lot::Mutex;

use anyhow::Result;
use bitcoin_rs_node::{Network, NodeConfig, state::NodeState};
use metrics::{
    Counter, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

#[test]
fn opens_storage_backend() -> Result<()> {
    #[cfg(feature = "rocksdb")]
    assert_backend_opens("rocksdb")?;
    #[cfg(feature = "fjall")]
    assert_backend_opens("fjall")?;
    #[cfg(feature = "redb")]
    assert_backend_opens("redb")?;
    Ok(())
}

fn assert_backend_opens(backend: &str) -> Result<()> {
    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join(backend);
    config.storage.backend = backend.parse().map_err(anyhow::Error::msg)?;
    config.p2p.listen.clear();

    let state = NodeState::open(config, None)?;

    assert_eq!(state.storage_kind(), backend);
    assert!(state.data_dir().join("chainstate").is_dir());
    Ok(())
}

/// The chainstate cache share must reach the backend that was opened: a
/// `dbcache` the operator set is only honored if the byte count survives every
/// hop from [`NodeState::open`] down to `open_with_cache`. A hop that drops it
/// falls back to the engine default, which no other assertion notices, so this
/// reads the capacity the backend published on open.
#[test]
#[cfg(feature = "fjall")]
fn open_gives_the_chainstate_backend_its_budgeted_cache_share() -> Result<()> {
    const ENGINE_DEFAULT_CACHE_BYTES: u64 = 32 * 1024 * 1024;

    let temp = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = temp.path().join("budget");
    config.storage.backend = "fjall".parse().map_err(anyhow::Error::msg)?;
    config.storage.dbcache_mb = 64;
    config.p2p.listen.clear();

    // No derived index in this deployment, so chainstate owns the whole budget
    // and the txindex namespace cannot publish a capacity under the same label.
    assert!(
        !config.indexes.txindex,
        "deployment must be chainstate-only"
    );
    let budget = bitcoin_rs_storage::clamp_dbcache_bytes(config.storage.dbcache_mb);
    let expected = bitcoin_rs_storage::split_cache_budget(budget, false)[0].bytes;
    assert_ne!(
        expected, ENGINE_DEFAULT_CACHE_BYTES,
        "the budget must differ from the engine default or this test proves nothing"
    );

    let gauges = GaugeSpy::default();
    let state = metrics::with_local_recorder(&gauges, || NodeState::open(config, None))?;

    assert_capacity_eq(
        &gauges,
        "storage.cache_capacity_bytes{backend=\"fjall\"}",
        expected,
    );
    drop(state);
    Ok(())
}

/// Asserts a published capacity equals the expected byte count. Both are small
/// integers (< 2^31) that `f64` represents exactly.
#[cfg(feature = "fjall")]
#[expect(
    clippy::cast_precision_loss,
    reason = "byte counts < 2^31, lossless in f64"
)]
#[expect(clippy::as_conversions, reason = "byte counts < 2^31, lossless in f64")]
fn assert_capacity_eq(gauges: &GaugeSpy, key: &str, expected: u64) {
    let actual = gauges.get(key);
    assert!(
        actual.is_some_and(|value| (value - expected as f64).abs() < 1.0),
        "{key}: expected {expected}, published {actual:?}"
    );
}

/// Captures gauge values keyed `name{label="value",...}`; counters and
/// histograms are discarded.
#[derive(Clone, Default)]
struct GaugeSpy {
    gauges: Arc<Mutex<HashMap<String, f64>>>,
}

impl GaugeSpy {
    fn key(key: &Key) -> String {
        let labels = key
            .labels()
            .map(|label| format!("{}=\"{}\"", label.key(), label.value()))
            .collect::<Vec<_>>()
            .join(",");
        if labels.is_empty() {
            key.name().to_owned()
        } else {
            format!("{}{{{}}}", key.name(), labels)
        }
    }

    fn get(&self, key: &str) -> Option<f64> {
        self.gauges.lock().get(key).copied()
    }
}

impl Recorder for GaugeSpy {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, _key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::noop()
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(GaugeCell {
            gauges: Arc::clone(&self.gauges),
            name: Self::key(key),
        }))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(DiscardHistogram))
    }
}

struct GaugeCell {
    gauges: Arc<Mutex<HashMap<String, f64>>>,
    name: String,
}

impl GaugeFn for GaugeCell {
    fn increment(&self, value: f64) {
        *self.gauges.lock().entry(self.name.clone()).or_insert(0.0) += value;
    }

    fn decrement(&self, value: f64) {
        self.increment(-value);
    }

    fn set(&self, value: f64) {
        self.gauges.lock().insert(self.name.clone(), value);
    }
}

struct DiscardHistogram;

impl HistogramFn for DiscardHistogram {
    fn record(&self, _value: f64) {}
}
