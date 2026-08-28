//! Backend metric contracts: one logical write is counted exactly once per
//! durability path, and explicit budgeted cache sizes are configured verbatim
//! (no backend floor may raise a share above its allocation).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use bitcoin_rs_storage::cache_budget::{MIN_DBCACHE_BYTES, split_cache_budget};
use bitcoin_rs_storage::{ColumnFamily, KvStore, WriteBatch};
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};

/// The filters share of the minimum 16 MiB budget — smaller than every
/// backend's historical floor, so configuring it verbatim is the regression.
fn filters_share() -> u64 {
    let share = split_cache_budget(MIN_DBCACHE_BYTES, true, true)[2].bytes;
    assert_eq!(share, 1_677_721, "filters keeps a floored 10% of 16 MiB");
    share
}

/// Records labeled metric values keyed `name{label="value",...}`.
#[derive(Clone, Debug, Default)]
struct LabeledRecorder {
    counters: Arc<Mutex<HashMap<String, u64>>>,
    gauges: Arc<Mutex<HashMap<String, f64>>>,
}

impl LabeledRecorder {
    fn metric_key(key: &Key) -> String {
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

    fn counter(&self, key: &str) -> u64 {
        *self.counters.lock().get(key).unwrap_or(&0)
    }

    fn writes_total(&self, backend: &str) -> u64 {
        let prefix = format!("storage.writes_total{{backend=\"{backend}\"");
        self.counters
            .lock()
            .iter()
            .filter(|(key, _)| key.starts_with(&prefix))
            .map(|(_, value)| value)
            .sum()
    }

    fn gauge(&self, key: &str) -> f64 {
        *self.gauges.lock().get(key).unwrap_or(&0.0)
    }
}

impl Recorder for LabeledRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let name = Self::metric_key(key);
        self.counters.lock().entry(name.clone()).or_insert(0);
        Counter::from_arc(Arc::new(CounterCell {
            counters: Arc::clone(&self.counters),
            name,
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let name = Self::metric_key(key);
        self.gauges.lock().entry(name.clone()).or_insert(0.0);
        Gauge::from_arc(Arc::new(GaugeCell {
            gauges: Arc::clone(&self.gauges),
            name,
        }))
    }

    fn register_histogram(&self, _key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(NoopHistogram))
    }
}

struct CounterCell {
    counters: Arc<Mutex<HashMap<String, u64>>>,
    name: String,
}

impl CounterFn for CounterCell {
    fn increment(&self, value: u64) {
        *self.counters.lock().entry(self.name.clone()).or_insert(0) += value;
    }

    fn absolute(&self, value: u64) {
        self.counters.lock().insert(self.name.clone(), value);
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
        if let Some(entry) = self.gauges.lock().get_mut(&self.name) {
            *entry -= value;
        }
    }

    fn set(&self, value: f64) {
        self.gauges.lock().insert(self.name.clone(), value);
    }
}

struct NoopHistogram;

impl HistogramFn for NoopHistogram {
    fn record(&self, _value: f64) {}
}

fn writes_total(backend: &str, durability: &str) -> String {
    format!("storage.writes_total{{backend=\"{backend}\",durability=\"{durability}\"}}")
}

fn cache_capacity(backend: &str) -> String {
    format!("storage.cache_capacity_bytes{{backend=\"{backend}\"}}")
}

fn put_one_row(store: &impl KvStore) {
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
    store.write(batch).expect("batch write");
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_counts_each_durability_path_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), filters_share())?;
    metrics::with_local_recorder(&recorder, || {
        put_one_row(&store);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write_durable(batch).expect("durable write");
    });
    assert_eq!(recorder.counter(&writes_total("fjall", "default")), 1);
    assert_eq!(recorder.counter(&writes_total("fjall", "durable")), 1);
    assert_eq!(
        recorder.writes_total("fjall"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "fjall")]
fn fjall_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = filters_share();
    metrics::with_local_recorder(&recorder, || {
        bitcoin_rs_storage::FjallStore::open_with_cache(dir.path(), share)
            .expect("fjall open with budgeted share");
    });
    assert_eq!(recorder.gauge(&cache_capacity("fjall")), share as f64);
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_counts_each_durability_path_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::RedbStore::open_with_cache(dir.path(), filters_share())?;
    metrics::with_local_recorder(&recorder, || {
        put_one_row(&store);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write_durable(batch).expect("durable write");
    });
    assert_eq!(recorder.counter(&writes_total("redb", "deferred")), 1);
    assert_eq!(recorder.counter(&writes_total("redb", "durable")), 1);
    assert_eq!(
        recorder.writes_total("redb"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = filters_share();
    metrics::with_local_recorder(&recorder, || {
        bitcoin_rs_storage::RedbStore::open_with_cache(dir.path(), share)
            .expect("redb open with budgeted share");
    });
    assert_eq!(recorder.gauge(&cache_capacity("redb")), share as f64);
    Ok(())
}

#[test]
#[cfg(feature = "redb")]
fn redb_txindex_wrapper_configures_the_budgeted_share_verbatim(
) -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = filters_share();
    metrics::with_local_recorder(&recorder, || {
        bitcoin_rs_storage::open_redb_tx_index_store_with_cache(dir.path(), share)
            .expect("redb txindex open with budgeted share");
    });
    assert_eq!(recorder.gauge(&cache_capacity("redb-txindex")), share as f64);
    Ok(())
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_deferred_and_durable_writes_count_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), filters_share())?;
    metrics::with_local_recorder(&recorder, || {
        put_one_row(&store);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write_deferred(batch).expect("deferred write");
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write_durable(batch).expect("durable write");
    });
    // Each durability path counts exactly once: write_deferred must not leak a
    // second increment through the default write path it delegates to.
    assert_eq!(recorder.counter(&writes_total("rocksdb", "default")), 1);
    assert_eq!(recorder.counter(&writes_total("rocksdb", "deferred")), 1);
    assert_eq!(recorder.counter(&writes_total("rocksdb", "durable")), 1);
    assert_eq!(
        recorder.writes_total("rocksdb"),
        3,
        "three logical writes must produce exactly three events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "rocksdb")]
fn rocksdb_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = filters_share();
    metrics::with_local_recorder(&recorder, || {
        bitcoin_rs_storage::RocksDbStore::open_with_cache(dir.path(), share)
            .expect("rocksdb open with budgeted share");
    });
    assert_eq!(recorder.gauge(&cache_capacity("rocksdb")), share as f64);
    Ok(())
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_durable_write_counts_once() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let store = bitcoin_rs_storage::MdbxStore::open_with_cache(dir.path(), filters_share())?;
    metrics::with_local_recorder(&recorder, || {
        put_one_row(&store);
        let mut batch = store.new_batch();
        batch.put(ColumnFamily::BlockBodies, b"metrics-key", b"value");
        store.write_durable(batch).expect("durable write");
    });
    // write_durable must not leak a second increment through the default write
    // path it delegates to.
    assert_eq!(recorder.counter(&writes_total("mdbx", "durable")), 1);
    assert_eq!(recorder.counter(&writes_total("mdbx", "default")), 1);
    assert_eq!(
        recorder.writes_total("mdbx"),
        2,
        "two logical writes must produce exactly two events"
    );
    Ok(())
}

#[test]
#[cfg(feature = "mdbx")]
fn mdbx_configures_the_budgeted_share_verbatim() -> Result<(), Box<dyn std::error::Error>> {
    let recorder = LabeledRecorder::default();
    let dir = tempfile::tempdir()?;
    let share = filters_share();
    metrics::with_local_recorder(&recorder, || {
        bitcoin_rs_storage::MdbxStore::open_with_cache(dir.path(), share)
            .expect("mdbx open with budgeted share");
    });
    assert_eq!(recorder.gauge(&cache_capacity("mdbx")), share as f64);
    Ok(())
}
