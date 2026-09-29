//! Metrics instrumentation and optional exposition.
//!
//! `MetricsServer` serves the Prometheus text scrape and projects one coherent
//! txindex capability snapshot per request; `EvidenceIdentity` carries the
//! artifact/configuration/durability every sample is labeled with.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use anyhow::Result;
use bitcoin_rs_index::{CapabilityState, DerivedIndexCapabilitySource};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use parking_lot::Mutex;

/// A SHA-256 digest carried as 64 lowercase hex characters in evidence.
///
/// A digest is bytes, not a label: a placeholder such as "unmeasured" cannot
/// parse, so an identity is either real or absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sha256Hex(pub [u8; 32]);

impl Sha256Hex {
    /// Hashes `bytes` with SHA-256.
    #[must_use]
    pub fn digest(bytes: &[u8]) -> Self {
        use sha2::Digest as _;
        Self(sha2::Sha256::digest(bytes).into())
    }
}

impl core::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Sha256Hex {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        let malformed = || format!("digest {text:?} is not 64 lowercase hex characters");
        if text.len() != 64 {
            return Err(malformed());
        }
        let mut bytes = [0_u8; 32];
        for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
            let text = core::str::from_utf8(pair).map_err(|_| malformed())?;
            if text.bytes().any(|c| c.is_ascii_uppercase()) {
                return Err(malformed());
            }
            *byte = u8::from_str_radix(text, 16).map_err(|_| malformed())?;
        }
        Ok(Self(bytes))
    }
}

impl serde::Serialize for Sha256Hex {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Sha256Hex {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// The corpus a measurement replayed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorpusIdentity {
    /// Corpus identifier from `docs/contracts/campaign-corpora.md`.
    pub id: String,
    /// Digest of the corpus manifest.
    pub manifest_sha256: Sha256Hex,
}

/// Everything a measurement was taken under.
///
/// A number without this record is a rumor: it cannot be matched against a
/// control cell or regenerated later.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIdentity {
    /// Digest of the executable that produced the sample.
    pub binary_sha256: Sha256Hex,
    /// Crate version of that executable.
    pub version: String,
    /// Digest of the fully resolved configuration.
    pub config_sha256: Sha256Hex,
    /// Replayed corpus. A live node has none; a product cell always has one.
    pub corpus: Option<CorpusIdentity>,
    /// Storage backend that held the state.
    pub backend: String,
    /// Durability policy in force, for example `journal:500b/5s`.
    pub durability: String,
    /// Hardware the sample ran on: CPU model and logical core count.
    pub hardware: String,
}

/// CPU model and core count, the two hardware facts a matched treatment
/// must share before its numbers are comparable.
fn hardware_identity() -> String {
    let model = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|info| {
            info.lines()
                .find_map(|line| line.strip_prefix("model name"))
                .and_then(|rest| rest.split_once(':'))
                .map(|(_, model)| model.trim().to_owned())
        })
        .unwrap_or_else(|| "unknown-cpu".into());
    let cores = std::thread::available_parallelism().map_or(0, usize::from);
    format!("{model} x{cores}")
}

impl EvidenceIdentity {
    /// Identity for the running process under `config`.
    ///
    /// The digest covers the executable file on disk and the resolved
    /// configuration's debug rendering, which is the one canonical form the
    /// runtime already owns.
    pub fn of_process(config: &crate::config::NodeConfig) -> Result<Self> {
        let executable = std::env::current_exe()?;
        let binary_sha256 = Sha256Hex::digest(&std::fs::read(&executable)?);
        let journal = config.chainstate_journal;
        let durability = if journal.enabled {
            format!("journal:{}b/{}s", journal.blocks, journal.seconds)
        } else {
            "checkpoint-only".into()
        };
        Ok(Self {
            binary_sha256,
            version: env!("CARGO_PKG_VERSION").into(),
            config_sha256: Sha256Hex::digest(format!("{config:?}").as_bytes()),
            corpus: None,
            backend: config.storage.backend.as_str().into(),
            durability,
            hardware: hardware_identity(),
        })
    }

    /// The identity as Prometheus global labels.
    #[must_use]
    pub fn labels(&self) -> Vec<(&'static str, String)> {
        let mut labels = vec![
            ("binary_sha256", self.binary_sha256.to_string()),
            ("version", self.version.clone()),
            ("config_sha256", self.config_sha256.to_string()),
            ("backend", self.backend.clone()),
            ("durability", self.durability.clone()),
            ("hardware", self.hardware.clone()),
        ];
        if let Some(corpus) = &self.corpus {
            labels.push(("corpus_id", corpus.id.clone()));
            labels.push(("corpus_manifest_sha256", corpus.manifest_sha256.to_string()));
        }
        labels
    }
}

fn describe_node_metrics() {
    metrics::describe_counter!("node.event_loop.sync_ticks", "block sync ticks");
    metrics::describe_counter!(
        "node.event_loop.sync_wakes",
        "block sync wakeups from inbound p2p data"
    );
    metrics::describe_gauge!(
        "node.shutdown.requested",
        "whether shutdown has been requested"
    );
    metrics::describe_histogram!(
        "node.event_loop.tick_seconds",
        "event loop tick latency seconds"
    );
    metrics::describe_counter!(
        "node.sync.duplicate_deliveries",
        "blocks received that were already staged"
    );
    metrics::describe_histogram!(
        "node.sync.apply_idle_seconds",
        "durations the apply frontier stayed starved while the window owed downloads"
    );
    metrics::describe_histogram!(
        "node.sync.download_blocked_by_apply_seconds",
        "durations the window front stayed in flight while apply held the frontier"
    );
    metrics::describe_gauge!(
        "node.sync.pending_blocks_high_water",
        "highest in-flight block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.pending_bytes_high_water",
        "highest in-flight byte estimate observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_blocks_high_water",
        "highest staged block count observed"
    );
    metrics::describe_gauge!(
        "node.sync.staged_bytes_high_water",
        "highest staged byte total observed"
    );
    metrics::describe_counter!(
        "storage.writes_total",
        "storage write batches applied, by backend and durability"
    );
    metrics::describe_counter!(
        "storage.flushes_total",
        "storage durability flushes by backend"
    );
    metrics::describe_histogram!("storage.write_bytes", "storage write batch payload bytes");
    metrics::describe_gauge!(
        "storage.cache_capacity_bytes",
        "configured per-engine cache capacity in bytes"
    );
}

static PROMETHEUS_HANDLE: Mutex<Option<(EvidenceIdentity, PrometheusHandle)>> = Mutex::new(None);

/// One process serves one identity: every scraped sample carries the
/// artifact, configuration, corpus and durability it was taken under as
/// global labels, so a reader can never attribute a value to the wrong build.
fn prometheus_handle(identity: &EvidenceIdentity) -> Result<PrometheusHandle> {
    let mut slot = PROMETHEUS_HANDLE.lock();
    if let Some((installed, handle)) = slot.as_ref() {
        anyhow::ensure!(
            installed == identity,
            "metrics recorder already serves a different evidence identity"
        );
        return Ok(handle.clone());
    }
    let mut builder = PrometheusBuilder::new();
    for (label, value) in identity.labels() {
        builder = builder.add_global_label(label, value);
    }
    let handle = builder
        .install_recorder()
        .map_err(|error| anyhow::anyhow!("install prometheus recorder: {error}"))?;
    *slot = Some((identity.clone(), handle.clone()));
    Ok(handle)
}

/// Process-global Prometheus scrape listener bound by [`start_metrics`].
pub struct MetricsServer {
    local_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl MetricsServer {
    /// Binds `addr` before installing the recorder, then serves Prometheus text.
    ///
    /// Listener-first ordering keeps an occupied-address failure from consuming
    /// the process-global recorder slot, so a later in-process retry cannot hit
    /// `SetRecorderError`.
    pub fn bind(
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        identity: &EvidenceIdentity,
    ) -> Result<Self> {
        Self::bind_with_source(addr, shutdown, identity, None)
    }

    /// Binds a listener whose readiness families are rendered from `source`
    /// once per scrape rather than copied through process-global gauges.
    pub(crate) fn bind_with_source(
        addr: SocketAddr,
        shutdown: Arc<AtomicBool>,
        identity: &EvidenceIdentity,
        source: Option<Arc<dyn DerivedIndexCapabilitySource>>,
    ) -> Result<Self> {
        let listener = TcpListener::bind(addr)?;
        let local_addr = listener.local_addr()?;
        let handle = prometheus_handle(identity)?;
        describe_node_metrics();
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let identity = identity.clone();
        let thread = thread::Builder::new()
            .name("bitcoin-rs-metrics".into())
            .spawn(move || {
                serve_metrics(
                    &listener,
                    &handle,
                    &thread_stop,
                    &shutdown,
                    &identity,
                    source.as_deref(),
                );
            })?;
        Ok(Self {
            local_addr,
            stop,
            thread: Some(thread),
        })
    }

    /// Address the scrape thread is listening on.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Signals the scrape thread and waits for it to exit.
    pub(crate) fn stop_and_join(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for MetricsServer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Starts the production scrape listener when `metrics_bind` is configured.
///
/// This is the entry `run` uses after [`crate::state::NodeState::open`].
pub(crate) fn start_metrics(
    bind: Option<SocketAddr>,
    shutdown: Arc<AtomicBool>,
    identity: &EvidenceIdentity,
    source: Arc<dyn DerivedIndexCapabilitySource>,
) -> Result<Option<MetricsServer>> {
    bind.map(|addr| MetricsServer::bind_with_source(addr, shutdown, identity, Some(source)))
        .transpose()
}

fn serve_metrics(
    listener: &TcpListener,
    handle: &PrometheusHandle,
    stop: &Arc<AtomicBool>,
    shutdown: &Arc<AtomicBool>,
    identity: &EvidenceIdentity,
    source: Option<&dyn DerivedIndexCapabilitySource>,
) {
    loop {
        if stop.load(Ordering::Acquire) || shutdown.load(Ordering::Acquire) {
            break;
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nodelay(true);
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                serve_scrape(&mut stream, handle, identity, source);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
}

fn serve_scrape(
    stream: &mut TcpStream,
    handle: &PrometheusHandle,
    identity: &EvidenceIdentity,
    source: Option<&dyn DerivedIndexCapabilitySource>,
) {
    let mut buf = [0_u8; 1024];
    let _ = stream.read(&mut buf);
    let mut body = handle.render();
    if let Some(source) = source {
        render_capability_metrics(&mut body, source, identity);
    }
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Gauge name for the txindex readiness outcome.
pub(crate) const TXINDEX_READINESS_GAUGE: &str = "node_capability_txindex_readiness";

fn escaped_label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('"', "\\\"")
}

fn labels(identity: &EvidenceIdentity, extra: &[(&str, &str)]) -> String {
    let mut rendered = identity
        .labels()
        .into_iter()
        .map(|(name, value)| format!("{name}=\"{}\"", escaped_label(&value)))
        .collect::<Vec<_>>();
    rendered.extend(
        extra
            .iter()
            .map(|(name, value)| format!("{name}=\"{}\"", escaped_label(value))),
    );
    rendered.join(",")
}

fn hash_words(hash: &str) -> Option<[u32; 8]> {
    if hash.len() != 64 {
        return None;
    }
    let mut words = [0_u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        let start = index * 8;
        *word = u32::from_str_radix(&hash[start..start + 8], 16).ok()?;
    }
    Some(words)
}

fn write_sample(
    body: &mut String,
    name: &str,
    identity: &EvidenceIdentity,
    extra: &[(&str, &str)],
    value: u64,
) {
    let _ = writeln!(body, "{name}{{{}}} {value}", labels(identity, extra));
}

/// Appends all readiness facts from one immutable source snapshot. Revision
/// halves and hash words stay within Prometheus' exact integer range and use
/// bounded labels, avoiding both precision loss and hash-label cardinality.
fn render_capability_metrics(
    body: &mut String,
    source: &dyn DerivedIndexCapabilitySource,
    identity: &EvidenceIdentity,
) {
    if !body.is_empty() && !body.ends_with('\n') {
        body.push('\n');
    }
    body.push_str("# HELP node_capability_snapshot_available Whether one coherent capability snapshot was captured for this scrape.\n");
    body.push_str("# TYPE node_capability_snapshot_available gauge\n");
    let Ok(snapshot) = source.snapshot() else {
        write_sample(body, "node_capability_snapshot_available", identity, &[], 0);
        return;
    };
    let (Some(revision), Some(tip)) = (snapshot.revision, snapshot.tip.as_ref()) else {
        write_sample(body, "node_capability_snapshot_available", identity, &[], 0);
        return;
    };
    let Some(words) = hash_words(&tip.hash) else {
        write_sample(body, "node_capability_snapshot_available", identity, &[], 0);
        return;
    };
    write_sample(body, "node_capability_snapshot_available", identity, &[], 1);

    let status = snapshot.capabilities.first();
    let active = status.map_or("Disabled", |status| status.state.wire_name());
    body.push_str(
        "# HELP node_capability_txindex_compiled Whether txindex is compiled into this node.\n",
    );
    body.push_str("# TYPE node_capability_txindex_compiled gauge\n");
    body.push_str(
        "# HELP node_capability_txindex_enabled Whether txindex is enabled for this node.\n",
    );
    body.push_str("# TYPE node_capability_txindex_enabled gauge\n");
    for (name, value) in [
        (
            "node_capability_txindex_compiled",
            status.is_some_and(|status| status.compiled),
        ),
        (
            "node_capability_txindex_enabled",
            status.is_some_and(|status| status.enabled),
        ),
    ] {
        write_sample(body, name, identity, &[], u64::from(value));
    }
    body.push_str("# HELP node_capability_txindex_readiness Txindex lifecycle outcome from this scrape's capability snapshot.\n");
    body.push_str("# TYPE node_capability_txindex_readiness gauge\n");
    for outcome in CapabilityState::ALL {
        let state = outcome.wire_name();
        write_sample(
            body,
            TXINDEX_READINESS_GAUGE,
            identity,
            &[("state", state)],
            u64::from(state == active),
        );
    }

    render_owner_revision(body, identity, revision);
    body.push_str(
        "# HELP node_capability_tip_height Applied tip height in this capability snapshot.\n",
    );
    body.push_str("# TYPE node_capability_tip_height gauge\n");
    write_sample(
        body,
        "node_capability_tip_height",
        identity,
        &[],
        u64::from(tip.height),
    );
    body.push_str("# HELP node_capability_tip_hash_word Applied tip hash as eight exact big-endian 32-bit words.\n");
    body.push_str("# TYPE node_capability_tip_hash_word gauge\n");
    for (index, word) in words.into_iter().enumerate() {
        let word_index = index.to_string();
        write_sample(
            body,
            "node_capability_tip_hash_word",
            identity,
            &[("word", &word_index)],
            u64::from(word),
        );
    }
}

fn render_owner_revision(
    body: &mut String,
    identity: &EvidenceIdentity,
    revision: bitcoin_rs_index::CapabilityRevision,
) {
    body.push_str("# HELP node_capability_chain_revision Authoritative chain revision split into exact 32-bit parts.\n");
    body.push_str("# TYPE node_capability_chain_revision gauge\n");
    for (field, value) in [("epoch", revision.epoch), ("sequence", revision.sequence)] {
        for (part, half) in [("high", value >> 32), ("low", value & u64::from(u32::MAX))] {
            write_sample(
                body,
                "node_capability_chain_revision",
                identity,
                &[("field", field), ("part", part)],
                half,
            );
        }
    }
    body.push_str("# HELP node_capability_index_state_revision_available Whether the durable index-state revision is available in this capability snapshot.\n");
    body.push_str("# TYPE node_capability_index_state_revision_available gauge\n");
    write_sample(
        body,
        "node_capability_index_state_revision_available",
        identity,
        &[],
        u64::from(revision.index_state.is_some()),
    );
    if let Some(index_state) = revision.index_state {
        body.push_str("# HELP node_capability_index_state_revision Durable ordinary index-state revision split into exact 32-bit parts.\n");
        body.push_str("# TYPE node_capability_index_state_revision gauge\n");
        for (part, half) in [
            ("high", index_state >> 32),
            ("low", index_state & u64::from(u32::MAX)),
        ] {
            write_sample(
                body,
                "node_capability_index_state_revision",
                identity,
                &[("part", part)],
                half,
            );
        }
    }
    body.push_str(
        "# HELP node_capability_index_owner Captured index-owner lifecycle and health identity.\n",
    );
    body.push_str("# TYPE node_capability_index_owner gauge\n");
    write_sample(
        body,
        "node_capability_index_owner",
        identity,
        &[
            ("lifecycle", revision.index_owner.lifecycle.wire_name()),
            ("health", revision.index_owner.health.wire_name()),
        ],
        1,
    );
    body.push_str("# HELP node_capability_index_phase Captured reconciliation phase: 0 forward, 1 rebuilding, 2 rolling back.\n");
    body.push_str("# TYPE node_capability_index_phase gauge\n");
    for (capability, name) in [
        (bitcoin_rs_index::IndexCapability::TxLookup, "tx_lookup"),
        (
            bitcoin_rs_index::IndexCapability::ScriptHistory,
            "script_history",
        ),
        (bitcoin_rs_index::IndexCapability::ScriptLive, "script_live"),
    ] {
        let (phase, from, to) = match revision.index_owner.phase.leg(capability) {
            bitcoin_rs_index::reconcile::ReconcileLeg::Forward => (0, 0, 0),
            bitcoin_rs_index::reconcile::ReconcileLeg::Rebuilding => (1, 0, 0),
            bitcoin_rs_index::reconcile::ReconcileLeg::RollingBack {
                from_height,
                to_height,
            } => (2, from_height, to_height),
        };
        for (field, value) in [("kind", phase), ("from_height", from), ("to_height", to)] {
            write_sample(
                body,
                "node_capability_index_phase",
                identity,
                &[("capability", name), ("field", field)],
                u64::from(value),
            );
        }
    }
}

#[cfg(test)]
#[path = "../tests/unit/metrics/tests.rs"]
mod tests;
