//! Node configuration DTOs, resolution, and validation.

use core::fmt;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Result, ensure};
use bitcoin_rs_primitives::Network;
use bitcoin_rs_storage::StorageBackend;
use crossbeam_channel::Receiver;

const DEFAULT_STORAGE_BACKEND: StorageBackend = StorageBackend::Fjall;
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_RPC_USER: &str = "bitcoin-rs";
const DEFAULT_RPC_PASSWORD: &str = "bitcoin-rs";
const DEFAULT_DBCACHE_MB: u64 = 450;
const DEFAULT_INDEX_ROLLBACK_REBUILD_CUTOVER: u32 = 100_000;
const DEFAULT_ZMQ_HWM: u32 = 1_000;
const DRYNET4_CONNECT: &str = "drynet4.drivechain.dev:8533";
const DRYNET4_P2P_MAGIC: [u8; 4] = [0xec, 0xa5, 0xd4, 0x04];

/// A built-in node network and its associated P2P bootstrap profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkSelection {
    /// Bitcoin mainnet.
    Mainnet,
    /// Legacy Bitcoin testnet.
    Testnet3,
    /// Bitcoin testnet4.
    Testnet4,
    /// Bitcoin signet.
    Signet,
    /// Local regression-test network.
    Regtest,
    /// ecash drynet4: mainnet consensus history on a distinct P2P network.
    Drynet4,
}

impl NetworkSelection {
    /// Parses the accepted network spellings.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "main" | "mainnet" | "bitcoin" => Some(Self::Mainnet),
            "test" | "testnet" | "testnet3" => Some(Self::Testnet3),
            "testnet4" => Some(Self::Testnet4),
            "signet" => Some(Self::Signet),
            "regtest" => Some(Self::Regtest),
            "drynet4" => Some(Self::Drynet4),
            _ => None,
        }
    }

    /// Returns the consensus network selected by this profile.
    #[must_use]
    pub const fn consensus_network(self) -> Network {
        match self {
            Self::Mainnet | Self::Drynet4 => Network::Mainnet,
            Self::Testnet3 => Network::Testnet3,
            Self::Testnet4 => Network::Testnet4,
            Self::Signet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

impl FromStr for NetworkSelection {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value).ok_or_else(|| format!("unknown network {value}"))
    }
}

impl From<Network> for NetworkSelection {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::Mainnet,
            Network::Testnet3 => Self::Testnet3,
            Network::Testnet4 => Self::Testnet4,
            Network::Signet => Self::Signet,
            Network::Regtest => Self::Regtest,
        }
    }
}

/// RPC authentication configuration.
#[derive(Clone, Eq, PartialEq)]
pub enum Auth {
    /// HTTP Basic credentials.
    Basic {
        /// RPC username.
        user: String,
        /// RPC password.
        password: String,
    },
    /// Bitcoin Core cookie-auth file.
    Cookie {
        /// Cookie file path.
        path: PathBuf,
    },
}

impl Auth {
    /// Constructs Basic authentication credentials.
    #[must_use]
    pub fn basic(user: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Basic {
            user: user.into(),
            password: password.into(),
        }
    }

    /// Converts this configuration into the RPC crate's runtime auth policy.
    pub fn to_rpc_auth(&self) -> Result<bitcoin_rs_rpc::Auth> {
        match self {
            Self::Basic { user, password } => {
                Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
            }
            Self::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
        }
    }

    fn basic_parts(&self) -> (String, String) {
        match self {
            Self::Basic { user, password } => (user.clone(), password.clone()),
            Self::Cookie { .. } => (DEFAULT_RPC_USER.to_owned(), DEFAULT_RPC_PASSWORD.to_owned()),
        }
    }
}

impl fmt::Debug for Auth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Basic { user, .. } => f
                .debug_struct("Auth::Basic")
                .field("user", user)
                .field("password", &"<redacted>")
                .finish(),
            Self::Cookie { .. } => f
                .debug_struct("Auth::Cookie")
                .field("path", &"<redacted>")
                .finish(),
        }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self::basic(DEFAULT_RPC_USER, DEFAULT_RPC_PASSWORD)
    }
}

/// One configured ZMQ PUB notification endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZmqPublication {
    /// Notification topic name.
    pub topic: crate::zmq_publisher::ZmqTopic,
    /// ZMQ endpoint to bind.
    pub endpoint: String,
    /// PUB socket high-water mark.
    pub hwm: u32,
}

/// How much of the derived `ScriptIndex` a node maintains.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub enum ScriptIndexMode {
    /// No `ScriptIndex` capability is maintained.
    #[default]
    Disabled,
    /// Maintain only the compact live-output view.
    Utxo,
    /// Maintain both the live-output view and historical script activity.
    Full,
}

impl ScriptIndexMode {
    /// Whether any `ScriptIndex` capability is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }

    /// Whether historical funding/spending rows are maintained.
    #[must_use]
    pub const fn keeps_history(self) -> bool {
        matches!(self, Self::Full)
    }

    /// Whether this mode has a durable store backing every view it claims.
    #[must_use]
    pub const fn has_live_store(self) -> bool {
        !matches!(self, Self::Utxo)
    }

    /// Parses a mode, including the historical boolean spellings.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "utxo" => Some(Self::Utxo),
            "full" | "true" | "1" | "yes" => Some(Self::Full),
            "false" | "0" | "no" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// User-supplied storage overrides.
#[derive(Clone, Debug, Default)]
pub struct StorageOverrides {
    /// Selected storage backend.
    pub backend: Option<StorageBackend>,
    /// Database cache budget in MiB.
    pub dbcache_mb: Option<u64>,
    /// Pruning target in MiB.
    pub prune_target_mb: Option<u64>,
}

/// User-supplied P2P overrides.
#[derive(Clone, Debug, Default)]
pub struct P2pOverrides {
    /// P2P message-start bytes.
    pub magic: Option<[u8; 4]>,
    /// P2P listener bind addresses.
    pub listen: Option<Vec<SocketAddr>>,
    /// Whether DNS seeds are enabled.
    pub dns_seeds: Option<bool>,
    /// Fixed outbound peer endpoints.
    pub connect: Option<Vec<String>>,
}

/// User-supplied RPC overrides.
#[derive(Clone, Debug, Default)]
pub struct RpcOverrides {
    /// JSON-RPC bind address.
    pub bind: Option<SocketAddr>,
    /// Whether the REST gateway is enabled.
    pub rest: Option<bool>,
    /// Basic-auth username.
    pub user: Option<String>,
    /// Basic-auth password.
    pub password: Option<String>,
    /// Cookie-auth path.
    pub cookie: Option<PathBuf>,
}

/// User-supplied index overrides.
#[derive(Clone, Debug, Default)]
pub struct IndexOverrides {
    /// Whether the transaction index is enabled.
    pub txindex: Option<bool>,
    /// Script index mode.
    pub script_index: Option<ScriptIndexMode>,
    /// Txindex rollback/rebuild cutover.
    pub rollback_rebuild_cutover: Option<u32>,
}

/// User-supplied observability overrides.
#[derive(Clone, Debug, Default)]
pub struct ObservabilityOverrides {
    /// Tracing filter level.
    pub log_level: Option<String>,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
}

/// User-supplied ZMQ overrides.
#[derive(Clone, Debug, Default)]
pub struct ZmqOverrides {
    /// PUB endpoints by topic.
    pub endpoints: BTreeMap<crate::zmq_publisher::ZmqTopic, Vec<String>>,
    /// PUB high-water marks by topic.
    pub hwm: BTreeMap<crate::zmq_publisher::ZmqTopic, u32>,
}

/// User-supplied validation overrides.
#[derive(Clone, Debug, Default)]
pub struct ValidationOverrides {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: Option<u32>,
}

/// A parser-independent source layer.
#[derive(Clone, Debug, Default)]
pub struct UserConfig {
    /// Network profile.
    pub network: Option<NetworkSelection>,
    /// Node data directory.
    pub data_dir: Option<PathBuf>,
    /// Storage settings.
    pub storage: StorageOverrides,
    /// P2P settings.
    pub p2p: P2pOverrides,
    /// RPC settings.
    pub rpc: RpcOverrides,
    /// Index settings.
    pub indexes: IndexOverrides,
    /// Logging and metrics settings.
    pub observability: ObservabilityOverrides,
    /// ZMQ settings.
    pub zmq: ZmqOverrides,
    /// Validation settings.
    pub validation: ValidationOverrides,
}

/// Resolved storage configuration.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Selected storage backend.
    pub backend: StorageBackend,
    /// Database cache budget in MiB.
    pub dbcache_mb: u64,
    /// Pruning target in MiB.
    pub prune_target_mb: u64,
}

/// Resolved P2P configuration.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    /// P2P message-start bytes.
    pub magic: [u8; 4],
    /// P2P listener bind addresses.
    pub listen: Vec<SocketAddr>,
    /// Whether DNS seeds are enabled.
    pub dns_seeds_enabled: bool,
    /// Fixed outbound peer endpoints.
    pub connect: Vec<String>,
}

/// Resolved RPC configuration.
#[derive(Clone, Debug)]
pub struct RpcConfig {
    /// JSON-RPC bind address.
    pub bind: SocketAddr,
    /// Whether REST is enabled.
    pub rest: bool,
    /// RPC authentication.
    pub auth: Auth,
}

/// Resolved index configuration.
#[derive(Clone, Debug)]
pub struct IndexConfig {
    /// Whether txindex is enabled.
    pub txindex: bool,
    /// Script index mode.
    pub script_index: ScriptIndexMode,
    /// Txindex rollback/rebuild cutover.
    pub rollback_rebuild_cutover: u32,
}

/// Resolved observability configuration.
#[derive(Clone, Debug)]
pub struct ObservabilityConfig {
    /// Tracing filter level.
    pub log_level: String,
    /// Optional Prometheus metrics bind address.
    pub metrics_bind: Option<SocketAddr>,
}

/// Resolved validation configuration.
#[derive(Clone, Debug)]
pub struct ValidationConfig {
    /// Height through which script verification may be skipped.
    pub assume_valid_height: u32,
}

/// Fully resolved, validated node configuration consumed by the runtime.
#[derive(Clone, Debug)]
pub struct NodeConfig {
    /// Consensus network.
    pub network: Network,
    /// Node data directory.
    pub data_dir: PathBuf,
    /// Storage settings.
    pub storage: StorageConfig,
    /// P2P settings.
    pub p2p: P2pConfig,
    /// RPC settings.
    pub rpc: RpcConfig,
    /// Index settings.
    pub indexes: IndexConfig,
    /// Logging and metrics settings.
    pub observability: ObservabilityConfig,
    /// ZMQ publications in Core notifier order.
    pub zmq: Vec<ZmqPublication>,
    /// Validation settings.
    pub validation: ValidationConfig,
}

impl NodeConfig {
    /// Returns resolved defaults for a network.
    #[must_use]
    pub fn default_for_network(network: Network) -> Self {
        let mut config = Self {
            network: Network::Mainnet,
            data_dir: PathBuf::from(".bitcoin-rs"),
            storage: StorageConfig {
                backend: DEFAULT_STORAGE_BACKEND,
                dbcache_mb: DEFAULT_DBCACHE_MB,
                prune_target_mb: 0,
            },
            p2p: P2pConfig {
                magic: Network::Mainnet.magic(),
                listen: Vec::new(),
                dns_seeds_enabled: true,
                connect: Vec::new(),
            },
            rpc: RpcConfig {
                bind: SocketAddr::from(([127, 0, 0, 1], Network::Mainnet.default_rpc_port())),
                rest: false,
                auth: Auth::default(),
            },
            indexes: IndexConfig {
                txindex: false,
                script_index: ScriptIndexMode::Disabled,
                rollback_rebuild_cutover: DEFAULT_INDEX_ROLLBACK_REBUILD_CUTOVER,
            },
            observability: ObservabilityConfig {
                log_level: DEFAULT_LOG_LEVEL.to_owned(),
                metrics_bind: None,
            },
            zmq: Vec::new(),
            validation: ValidationConfig {
                assume_valid_height: 0,
            },
        };
        config.apply_network_selection(NetworkSelection::from(network));
        config
    }

    /// Resolves one source layer.
    pub fn resolve(user: &UserConfig) -> Result<Self> {
        resolve(&[user])
    }

    /// Validates backend availability and cross-field constraints.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.storage.backend.is_compiled_in(),
            "unsupported storage backend {}",
            self.storage.backend
        );
        if self.p2p.magic != self.network.magic() {
            ensure!(
                self.network == Network::Mainnet,
                "P2P magic overrides currently require --network mainnet"
            );
            ensure!(
                !self.p2p.connect.is_empty(),
                "P2P magic overrides require at least one --connect peer"
            );
            ensure!(
                !self.p2p.dns_seeds_enabled,
                "P2P magic overrides require --dns-seeds-enabled=false"
            );
        }
        ensure!(
            self.indexes.script_index.has_live_store(),
            "scriptindex=utxo is not yet usable: the compact live-output store it \
             requires does not exist (#225). Only `full` and `disabled` are accepted. \
             Blocked on #226 Q5, which selects the ScriptLive locator format."
        );
        for publication in &self.zmq {
            ensure!(
                publication.hwm <= 2_147_483_647,
                "{}hwm exceeds libzmq SNDHWM range",
                publication.topic.notifier_type()
            );
        }
        Ok(())
    }

    fn apply_layer(&mut self, layer: &UserConfig) {
        if let Some(network) = layer.network {
            self.apply_network_selection(network);
        }
        if let Some(magic) = layer.p2p.magic {
            self.p2p.magic = magic;
        }
        if let Some(data_dir) = &layer.data_dir {
            self.data_dir.clone_from(data_dir);
        }
        if let Some(backend) = layer.storage.backend {
            self.storage.backend = backend;
        }
        if let Some(value) = layer.storage.dbcache_mb {
            self.storage.dbcache_mb = value;
        }
        if let Some(value) = layer.storage.prune_target_mb {
            self.storage.prune_target_mb = value;
        }
        if let Some(bind) = layer.rpc.bind {
            self.rpc.bind = bind;
        }
        if let Some(rest) = layer.rpc.rest {
            self.rpc.rest = rest;
        }
        if let Some(path) = &layer.rpc.cookie {
            self.rpc.auth = Auth::Cookie { path: path.clone() };
        } else if layer.rpc.user.is_some() || layer.rpc.password.is_some() {
            let (old_user, old_password) = self.rpc.auth.basic_parts();
            self.rpc.auth = Auth::basic(
                layer.rpc.user.clone().unwrap_or(old_user),
                layer.rpc.password.clone().unwrap_or(old_password),
            );
        }
        if let Some(value) = layer.indexes.txindex {
            self.indexes.txindex = value;
        }
        if let Some(value) = layer.indexes.script_index {
            self.indexes.script_index = value;
        }
        if let Some(value) = layer.indexes.rollback_rebuild_cutover {
            self.indexes.rollback_rebuild_cutover = value;
        }
        if let Some(value) = &layer.observability.log_level {
            self.observability.log_level.clone_from(value);
        }
        if let Some(value) = layer.observability.metrics_bind {
            self.observability.metrics_bind = Some(value);
        }
        if let Some(value) = &layer.p2p.listen {
            self.p2p.listen.clone_from(value);
        }
        if let Some(value) = layer.p2p.dns_seeds {
            self.p2p.dns_seeds_enabled = value;
        }
        if let Some(value) = &layer.p2p.connect {
            self.p2p.connect.clone_from(value);
        }
        if let Some(value) = layer.validation.assume_valid_height {
            self.validation.assume_valid_height = value;
        }
        for (topic, endpoints) in &layer.zmq.endpoints {
            let hwm = layer.zmq.hwm.get(topic).copied();
            let inherited_hwm = self
                .zmq
                .iter()
                .find(|publication| publication.topic == *topic)
                .map_or(DEFAULT_ZMQ_HWM, |publication| publication.hwm);
            self.zmq.retain(|publication| publication.topic != *topic);
            self.zmq
                .extend(endpoints.iter().cloned().map(|endpoint| ZmqPublication {
                    topic: *topic,
                    endpoint,
                    hwm: hwm.unwrap_or(inherited_hwm),
                }));
        }
        for (topic, hwm) in &layer.zmq.hwm {
            for publication in &mut self.zmq {
                if publication.topic == *topic {
                    publication.hwm = *hwm;
                }
            }
        }
    }

    fn apply_network_selection(&mut self, selection: NetworkSelection) {
        let network = selection.consensus_network();
        self.network = network;
        self.p2p.magic = network.magic();
        self.rpc.bind = SocketAddr::from(([127, 0, 0, 1], network.default_rpc_port()));
        self.p2p.listen = vec![SocketAddr::from(([0, 0, 0, 0], network.default_p2p_port()))];
        self.p2p.dns_seeds_enabled = true;
        self.p2p.connect.clear();
        self.validation.assume_valid_height = network
            .assume_valid_anchor()
            .map_or(0, |(height, _)| height);
        if selection == NetworkSelection::Drynet4 {
            self.p2p.magic = DRYNET4_P2P_MAGIC;
            self.p2p.dns_seeds_enabled = false;
            self.p2p.connect = vec![DRYNET4_CONNECT.to_owned()];
        }
    }
}

/// Resolves layers from lowest to highest precedence.
pub fn resolve(layers: &[&UserConfig]) -> Result<NodeConfig> {
    let mut config = NodeConfig::default_for_network(Network::Mainnet);
    for layer in layers {
        config.apply_layer(layer);
    }
    config.zmq.sort_by_key(|publication| publication.topic);
    config.validate()?;
    Ok(config)
}

/// Process and test dependencies that are not configuration.
#[derive(Default)]
pub struct RuntimeInputs {
    /// Optional in-process shutdown notification receiver.
    pub shutdown: Option<Receiver<()>>,
    /// Optional test-only mempool observer.
    pub mempool_observer: Option<Arc<dyn bitcoin_rs_mempool::MempoolObserver>>,
}

impl RuntimeInputs {
    /// Returns a copy with the given shutdown receiver.
    #[must_use]
    pub fn with_shutdown(mut self, rx: Receiver<()>) -> Self {
        self.shutdown = Some(rx);
        self
    }

    /// Returns a copy with the given mempool observer.
    #[must_use]
    pub fn with_mempool_observer(
        mut self,
        observer: Arc<dyn bitcoin_rs_mempool::MempoolObserver>,
    ) -> Self {
        self.mempool_observer = Some(observer);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_debug_redacts_secrets() {
        let auth = Auth::basic("operator", "s3cret");
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("operator"));
        assert!(!rendered.contains("s3cret"));
        assert!(rendered.contains("<redacted>"));

        let auth = Auth::Cookie {
            path: PathBuf::from("/secret/.cookie"),
        };
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("/secret/.cookie"));
        assert!(rendered.contains("<redacted>"));
    }
}
