use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use parking_lot::Mutex;

type MetricCell = Arc<Mutex<MetricValue>>;

#[derive(Clone, Debug)]
pub(crate) struct MetricsHandle {
    recorder: InMemoryRecorder,
}

impl MetricsHandle {
    pub(crate) fn snapshot(&self) -> HashMap<String, MetricValue> {
        self.recorder
            .values
            .lock()
            .iter()
            .map(|(key, value)| (key.clone(), *value.lock()))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram { count: u64, sum: f64 },
}

#[derive(Clone, Debug, Default)]
struct InMemoryRecorder {
    values: Arc<Mutex<HashMap<String, MetricCell>>>,
}

impl InMemoryRecorder {
    fn metric_key(key: &Key) -> String {
        key.name().to_owned()
    }

    fn ensure_counter(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Counter(0))
    }

    fn ensure_gauge(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Gauge(0.0))
    }

    fn ensure_histogram(&self, key: String) -> MetricCell {
        self.ensure_metric(key, MetricValue::Histogram { count: 0, sum: 0.0 })
    }

    fn ensure_metric(&self, key: String, initial: MetricValue) -> MetricCell {
        self.values
            .lock()
            .entry(key)
            .or_insert_with(|| Arc::new(Mutex::new(initial)))
            .clone()
    }
}

impl Recorder for InMemoryRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        let value = self.ensure_counter(Self::metric_key(key));
        Counter::from_arc(Arc::new(CounterHandle { value }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        let value = self.ensure_gauge(Self::metric_key(key));
        Gauge::from_arc(Arc::new(GaugeHandle { value }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        let value = self.ensure_histogram(Self::metric_key(key));
        Histogram::from_arc(Arc::new(HistogramHandle { value }))
    }
}

struct GaugeHandle {
    value: MetricCell,
}

impl GaugeFn for GaugeHandle {
    fn increment(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Gauge(current) = &mut *entry {
            *current += value;
        }
    }

    fn decrement(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Gauge(current) = &mut *entry {
            *current -= value;
        }
    }

    fn set(&self, value: f64) {
        *self.value.lock() = MetricValue::Gauge(value);
    }
}

struct CounterHandle {
    value: MetricCell,
}

impl CounterFn for CounterHandle {
    fn increment(&self, value: u64) {
        let mut entry = self.value.lock();
        if let MetricValue::Counter(current) = &mut *entry {
            *current = current.saturating_add(value);
        }
    }

    fn absolute(&self, value: u64) {
        let mut entry = self.value.lock();
        if let MetricValue::Counter(current) = &mut *entry {
            *current = (*current).max(value);
        }
    }
}

struct HistogramHandle {
    value: MetricCell,
}

impl HistogramFn for HistogramHandle {
    fn record(&self, value: f64) {
        let mut entry = self.value.lock();
        if let MetricValue::Histogram { count, sum } = &mut *entry {
            *count = count.saturating_add(1);
            *sum += value;
        }
    }
}

pub(crate) fn install() -> Result<MetricsHandle> {
    let recorder = InMemoryRecorder::default();
    metrics::set_global_recorder(recorder.clone())?;
    Ok(MetricsHandle { recorder })
}
