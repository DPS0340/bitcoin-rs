//! The observability boundary is exercised, not just documented: retired
//! per-event stage timers must never reach the metrics API again
//! (`docs/observability.md`, OBS-02/OBS-06).
//!
//! PRE: a regtest chainstate with the in-memory test stores and the
//! test-seam apply/window entry points.
//! POST: one single-block apply and one grouped window drain run under a
//! recording `metrics::Recorder`; the retired names that those paths formerly
//! emitted are absent, while kept operator signals and hot-path ledger hooks
//! are present.

use std::sync::Arc;

use bitcoin_rs_primitives::{Network, consensus_bytes};
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::HashSet;
use metrics::{
    Counter, CounterFn, Gauge, GaugeFn, Histogram, HistogramFn, Key, KeyName, Metadata, Recorder,
    SharedString, Unit,
};
use parking_lot::Mutex;

use super::persistence_tests::{handles, mined_child, seed_genesis};

/// Names the single-block fixture emitted before the #1195 boundary.
const RETIRED_APPLY_METRICS: &[&str] = &[
    "node.apply_block.contextual_header_seconds",
    "node.apply_block.pow_self_consistency_seconds",
    "node.apply_block.coinbase_maturity_seconds",
    "node.apply_block.bip68_seconds",
    "node.apply_block.utxo_changes_seconds",
    "node.apply_block.durable_sync_seconds",
    "node.apply_block.durable_commit_seconds",
    "node.apply_block.script_verify_coinbase_only_seconds",
    "node.apply_block.script_resolution_seconds",
    "node.apply_block.script_prepare_seconds",
    "node.apply_block.script_parallel_seconds",
    "node.utxo.listener.event_batches_seconds",
];

/// Names the grouped-window fixture emitted before the #1195 boundary.
const RETIRED_WINDOW_METRICS: &[&str] = &[
    "node.durable_head.group_sync_seconds",
    "node.durable_head.group_commit_seconds",
    "node.durable_head.group_blocks",
    "node.window.checks_seconds",
];

/// Captures the metric names a path registers, and nothing else.
#[derive(Default)]
struct NameRecorder {
    names: Arc<Mutex<HashSet<String>>>,
}

impl NameRecorder {
    fn saw(&self, name: &str) -> bool {
        self.names.lock().contains(name)
    }
}

/// Marks recorded values so a kept counter/histogram proves the recorder was
/// live on the path under test.
#[derive(Default)]
struct NameCell {
    names: Arc<Mutex<HashSet<String>>>,
    name: String,
}

impl CounterFn for NameCell {
    fn increment(&self, _value: u64) {
        self.names.lock().insert(self.name.clone());
    }

    fn absolute(&self, _value: u64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl GaugeFn for NameCell {
    fn increment(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }

    fn decrement(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }

    fn set(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl HistogramFn for NameCell {
    fn record(&self, _value: f64) {
        self.names.lock().insert(self.name.clone());
    }
}

impl Recorder for NameRecorder {
    fn describe_counter(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_gauge(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}
    fn describe_histogram(&self, _key: KeyName, _unit: Option<Unit>, _description: SharedString) {}

    fn register_counter(&self, key: &Key, _metadata: &Metadata<'_>) -> Counter {
        Counter::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }

    fn register_gauge(&self, key: &Key, _metadata: &Metadata<'_>) -> Gauge {
        Gauge::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }

    fn register_histogram(&self, key: &Key, _metadata: &Metadata<'_>) -> Histogram {
        Histogram::from_arc(Arc::new(NameCell {
            names: Arc::clone(&self.names),
            name: key.name().to_string(),
        }))
    }
}

fn assert_names_absent(recorder: &NameRecorder, names: &[&str]) {
    let recorded = recorder.names.lock();
    for name in names {
        assert!(
            !recorded.contains(*name),
            "{name} is a diagnostic (OBS-02/OBS-06) and must not reach the metrics API"
        );
    }
}

/// A one-block apply runs under the recorder: retired per-block timers stay
/// off the metrics API while the operator totals stay on it.
#[test]
fn retired_apply_stage_timings_never_reach_the_metrics_api()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = NameRecorder::default();
    let genesis = Network::Regtest.genesis_block();
    metrics::with_local_recorder(&recorder, || -> Result<(), Box<dyn std::error::Error>> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        seed_genesis(&handles)?;
        let first = mined_child(genesis.block_hash(), 1)?;
        handles.apply_block(&first, None)?;
        Ok(())
    })?;
    assert_names_absent(&recorder, RETIRED_APPLY_METRICS);
    assert!(
        recorder.saw("node.apply_block.total_seconds"),
        "the apply.commit hot-path hook is a kept signal (OBS-04)"
    );
    assert!(
        recorder.saw("node.apply_block.txs_applied"),
        "the apply throughput counter is a kept operator signal (OBS-01)"
    );
    Ok(())
}

/// A grouped window drain runs under the recorder: the retired group and
/// window-check timers stay off the metrics API while the ledger hooks stay
/// on it.
#[test]
fn retired_group_and_check_timings_never_reach_the_metrics_api()
-> Result<(), Box<dyn std::error::Error>> {
    let recorder = NameRecorder::default();
    let genesis = Network::Regtest.genesis_block();
    metrics::with_local_recorder(&recorder, || -> Result<(), Box<dyn std::error::Error>> {
        let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
        let first = mined_child(genesis.block_hash(), 1)?;
        let second = mined_child(first.block_hash(), 2)?;
        seed_genesis(&handles)?;
        {
            let mut tree = handles.block_tree.write();
            bitcoin_rs_chain::accept_headers(
                &mut tree,
                &[first.header, second.header],
                Network::Regtest,
                bitcoin_rs_chain::current_unix_seconds(),
                bitcoin_rs_chain::HeaderValidationMode::LiveAdmission,
            )?;
        }
        let blocks = [&first, &second];
        let serialized: Vec<bytes::Bytes> = blocks
            .iter()
            .map(|block| bytes::Bytes::from(consensus_bytes(*block)))
            .collect();
        let transition = handles.begin_transition()?;
        transition.connect_window(&blocks, &serialized)?;
        Ok(())
    })?;
    assert_names_absent(&recorder, RETIRED_WINDOW_METRICS);
    assert!(
        recorder.saw("node.window.verify_seconds"),
        "the apply.prove_window hot-path hook is a kept signal (OBS-04)"
    );
    Ok(())
}
