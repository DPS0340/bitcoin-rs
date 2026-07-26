//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use crate as bitcoin_rs_node;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, bail};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};

use crate::address_book::{AddressBook, CandidateFilter};
use crate::config::Config;
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{crash_recovery, logging, shutdown};

const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const P2P_OUTBOUND_ACTIVE_LIMIT: usize = crate::state::P2P_OUTBOUND_QUEUE_LIMIT;
/// Target number of live outbound peers for normal operation and fan-out eligibility.
///
/// Must equal `sync::MIN_PEERS_FOR_FANOUT`; verified by the gate test.
const P2P_OUTBOUND_PEER_TARGET: usize = 8;
/// How often the DNS peer maintenance loop wakes to check the live peer count.
const DNS_MAINTENANCE_INTERVAL: Duration = Duration::from_secs(5);
/// Retry a connectionless bootstrap before normal DNS maintenance.
const DNS_BOOTSTRAP_REFILL_INTERVAL: Duration = Duration::from_secs(1);
/// Maximum fast refills before returning to the normal maintenance cadence.
const DNS_BOOTSTRAP_FAST_REFILL_LIMIT: u8 = 2;
const PEER_POOL_PREWARM_FLOOR: usize = 32;
const QUEUED_ATTEMPT_TIMEOUT: Duration = Duration::from_mins(1);
const DNS_REFRESH_INTERVAL: Duration = Duration::from_mins(5);
const PEER_DISCOVERY_CHANNEL_CAPACITY: usize = 4_096;

type PeerRegistry = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>;
type PeerOutboundMap = Arc<
    parking_lot::RwLock<
        hashbrown::HashMap<
            std::net::SocketAddr,
            crossbeam_channel::Sender<bitcoin_rs_p2p::Message>,
        >,
    >,
>;
type BannedSubnets = Arc<parking_lot::RwLock<Vec<bitcoin_rs_p2p::BannedSubnet>>>;
type P2pChainQuery = Arc<dyn bitcoin_rs_p2p::ChainQuery>;
type OutboundConnectionHandle =
    std::thread::JoinHandle<core::result::Result<(), bitcoin_rs_p2p::PeerError>>;

/// Bounds rapid DNS retries while the initial outbound pool is still empty.
#[derive(Default)]
struct DnsBootstrapRefill {
    fast_refills: u8,
}

impl DnsBootstrapRefill {
    fn next_delay(&mut self, live: usize, queued: usize) -> Duration {
        if live > 0 {
            self.fast_refills = 0;
            return DNS_MAINTENANCE_INTERVAL;
        }
        if queued == 0 || self.fast_refills >= DNS_BOOTSTRAP_FAST_REFILL_LIMIT {
            return DNS_MAINTENANCE_INTERVAL;
        }
        self.fast_refills = self.fast_refills.saturating_add(1);
        DNS_BOOTSTRAP_REFILL_INTERVAL
    }
}

fn build_rpc_auth(node_auth: &crate::Auth) -> Result<bitcoin_rs_rpc::Auth> {
    match node_auth {
        crate::Auth::Basic { user, password } => {
            Ok(bitcoin_rs_rpc::Auth::basic(user.clone(), password))
        }
        crate::Auth::Cookie { path } => Ok(bitcoin_rs_rpc::Auth::cookie(path)?),
    }
}

fn spawn_electrum_listener(
    config: &bitcoin_rs_node::Config,
    state: &NodeState,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> anyhow::Result<Option<std::thread::JoinHandle<Result<(), bitcoin_rs_electrum::ElectrumError>>>>
{
    let Some(addr) = config.electrum_bind else {
        return Ok(None);
    };

    if let Some(cert) = &config.electrum_tls_cert {
        tracing::warn!(
            cert = %cert.display(),
            "electrum TLS cert configured but TLS wiring deferred; serving plaintext"
        );
    }

    let network = match state.config().network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    let Some(index) = state.electrum_index_handle() else {
        bail!("electrum listener requires txindex");
    };
    let Some(history_reader) = state.electrum_history_reader() else {
        bail!("electrum listener requires txindex history reader");
    };
    let index = index
        .with_history_reader(history_reader)
        .with_network(network);
    let mempool = bitcoin_rs_electrum::MempoolHandle::from_arc(state.mempool());
    let cfg = bitcoin_rs_electrum::ServerConfig::default();
    let server = bitcoin_rs_electrum::ElectrumServer::bind(addr, index, mempool, cfg)
        .map_err(anyhow::Error::from)?;
    let local_addr = server.local_addr()?;
    tracing::info!(addr = %local_addr, "electrum listener bound");

    let electrum_shutdown = Arc::clone(shutdown);
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-electrum".into())
            .spawn(move || server.run_with_shutdown(electrum_shutdown))?,
    ))
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
fn spawn_p2p_listeners(
    config: &bitcoin_rs_node::Config,
    shutdown: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
    banned: BannedSubnets,
    inbound_headers_tx: crossbeam_channel::Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: crossbeam_channel::Sender<bitcoin_rs_p2p::InboundBlock>,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
) -> anyhow::Result<Vec<std::thread::JoinHandle<Result<(), bitcoin_rs_p2p::listener::ListenerError>>>>
{
    let mut handles = Vec::with_capacity(config.p2p_listen.len());
    let magic = bitcoin::p2p::Magic::from_bytes(config.network.magic());
    for addr in &config.p2p_listen {
        let listener_addr = *addr;
        let listener_shutdown = std::sync::Arc::clone(shutdown);
        let listener_peers = Arc::clone(peers);
        let listener_peer_outbound = Arc::clone(peer_outbound);
        let listener_banned = Arc::clone(&banned);
        let listener_inbound_headers_tx = inbound_headers_tx.clone();
        let listener_inbound_blocks_tx = inbound_blocks_tx.clone();
        let listener_sync_wake_tx = sync_wake_tx.clone();
        let listener_chain_query = Arc::clone(&chain_query);
        let handle = std::thread::Builder::new()
            .name(format!("bitcoin-rs-p2p-{listener_addr}"))
            .spawn(move || {
                bitcoin_rs_p2p::listener::serve_with_shutdown_with_chain_and_sync_wake(
                    listener_addr,
                    listener_shutdown,
                    magic,
                    listener_peers,
                    listener_peer_outbound,
                    listener_inbound_headers_tx,
                    listener_inbound_blocks_tx,
                    listener_banned,
                    Some(listener_chain_query),
                    Some(listener_sync_wake_tx),
                )
            })?;
        tracing::info!(addr = %listener_addr, "p2p listener bound");
        handles.push(handle);
    }
    Ok(handles)
}

fn reap_finished_outbound_connections(
    active: &mut hashbrown::HashSet<SocketAddr>,
    handles: &mut Vec<(SocketAddr, OutboundConnectionHandle)>,
) {
    let mut index = 0;
    while index < handles.len() {
        if !handles[index].1.is_finished() {
            index += 1;
            continue;
        }

        let (addr, handle) = handles.swap_remove(index);
        active.remove(&addr);
        match handle.join() {
            Ok(Ok(())) => tracing::debug!(addr = %addr, "p2p outbound connection exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(addr = %addr, %error, "p2p outbound connection exited with error");
            }
            Err(_) => tracing::warn!(addr = %addr, "p2p outbound connection panicked"),
        }
    }
}

fn outbound_addr_available(
    addr: SocketAddr,
    active: &hashbrown::HashSet<SocketAddr>,
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
) -> bool {
    if active.contains(&addr) {
        return false;
    }
    if peer_outbound.read().contains_key(&addr) {
        return false;
    }
    !peers.read().iter().any(|peer| peer.addr == addr)
}

#[allow(clippy::needless_pass_by_value)]
fn spawn_p2p_outbound_drain(
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
    peers: &PeerRegistry,
    peer_outbound: &PeerOutboundMap,
    banned: BannedSubnets,
    sync_wake_tx: crossbeam_channel::Sender<()>,
    chain_query: P2pChainQuery,
    discovery_tx: Option<Sender<bitcoin_rs_p2p::discovery::PeerDiscoveryEvent>>,
) -> anyhow::Result<std::thread::JoinHandle<()>> {
    let outbound_rx = state.p2p_outbound_receiver();
    let magic = bitcoin::p2p::Magic::from_bytes(state.config().network.magic());
    let outbound_registry = Arc::clone(peers);
    let outbound_peer_outbound = Arc::clone(peer_outbound);
    let outbound_banned = Arc::clone(&banned);
    let outbound_headers_tx = state.inbound_headers_sender();
    let outbound_blocks_tx = state.inbound_blocks_sender();
    let outbound_sync_wake_tx = sync_wake_tx;
    let outbound_shutdown = Arc::clone(shutdown);
    let outbound_chain_query = Arc::clone(&chain_query);

    Ok(std::thread::Builder::new()
        .name("bitcoin-rs-p2p-outbound-drain".to_owned())
        .spawn(move || {
            let mut active = hashbrown::HashSet::new();
            let mut handles = Vec::new();
            while !outbound_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                reap_finished_outbound_connections(&mut active, &mut handles);
                if active.len() >= P2P_OUTBOUND_ACTIVE_LIMIT {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                let recv = {
                    let guard = outbound_rx.lock();
                    guard.recv_timeout(Duration::from_secs(1))
                };
                match recv {
                    Ok(addr) => {
                        if !outbound_addr_available(
                            addr,
                            &active,
                            &outbound_registry,
                            &outbound_peer_outbound,
                        ) {
                            tracing::debug!(addr = %addr, "p2p outbound request skipped: already active");
                            continue;
                        }
                        let handle = bitcoin_rs_p2p::listener::spawn_outbound_connection_with_chain_sync_and_discovery(
                            addr,
                            magic,
                            Arc::clone(&outbound_registry),
                            Arc::clone(&outbound_peer_outbound),
                            outbound_headers_tx.clone(),
                            outbound_blocks_tx.clone(),
                            Arc::clone(&outbound_banned),
                            Some(Arc::clone(&outbound_chain_query)),
                            Some(outbound_sync_wake_tx.clone()),
                            discovery_tx.clone(),
                        );
                        active.insert(addr);
                        handles.push((addr, handle));
                    }
                    Err(crossbeam_channel::RecvTimeoutError::Timeout) => continue,
                    Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                }
            }
        })?)
}

struct PeerPoolMaintenance<R> {
    resolver: R,
    seeds: Vec<&'static str>,
    book: AddressBook,
    queued: hashbrown::HashMap<SocketAddr, Instant>,
    last_dns_refresh: Option<Instant>,
}

impl<R: bitcoin_rs_p2p::DnsResolver> PeerPoolMaintenance<R> {
    fn new(resolver: R, seeds: Vec<&'static str>, book: AddressBook) -> Self {
        Self {
            resolver,
            seeds,
            book,
            queued: hashbrown::HashMap::new(),
            last_dns_refresh: None,
        }
    }

    fn tick(
        &mut self,
        peer_outbound: &PeerOutboundMap,
        banned: &BannedSubnets,
        outbound_tx: &Sender<SocketAddr>,
        discovery_rx: &Receiver<bitcoin_rs_p2p::discovery::PeerDiscoveryEvent>,
        now: SystemTime,
        monotonic_now: Instant,
    ) -> usize {
        self.drain_discovery(discovery_rx, now);
        let active: hashbrown::HashSet<SocketAddr> = peer_outbound.read().keys().copied().collect();
        self.queued.retain(|addr, queued_at| {
            !active.contains(addr)
                && monotonic_now.saturating_duration_since(*queued_at) < QUEUED_ATTEMPT_TIMEOUT
        });
        let deficit =
            P2P_OUTBOUND_PEER_TARGET.saturating_sub(active.len().saturating_add(self.queued.len()));
        let mut candidates = self.select(deficit, &active, banned, now);
        let eligible = self.eligible_count(&active, banned, now);
        let refresh_due = self.last_dns_refresh.is_none_or(|last| {
            monotonic_now.saturating_duration_since(last) >= DNS_REFRESH_INTERVAL
        });
        if candidates.len() < deficit || (eligible < PEER_POOL_PREWARM_FLOOR && refresh_due) {
            self.resolve_dns(now);
            self.last_dns_refresh = Some(monotonic_now);
            candidates = self.select(deficit, &active, banned, now);
        }

        let mut queued = 0;
        for addr in candidates {
            match outbound_tx.try_send(addr) {
                Ok(()) => {
                    self.queued.insert(addr, monotonic_now);
                    queued += 1;
                }
                Err(TrySendError::Full(_)) => break,
                Err(TrySendError::Disconnected(_)) => {
                    tracing::warn!("peer-pool maintenance: outbound channel disconnected");
                    break;
                }
            }
        }
        if let Err(error) = self.book.save_if_dirty() {
            tracing::warn!(%error, "failed to persist peer address book");
        }
        queued
    }

    fn drain_discovery(
        &mut self,
        discovery_rx: &Receiver<bitcoin_rs_p2p::discovery::PeerDiscoveryEvent>,
        now: SystemTime,
    ) {
        use bitcoin_rs_p2p::discovery::{PeerDiscoveryEvent, PeerTerminalOutcome};

        for event in discovery_rx.try_iter() {
            match event {
                PeerDiscoveryEvent::Announced(peer) => self.book.record_announcement(peer, now),
                PeerDiscoveryEvent::HandshakeReady { addr, services } => {
                    self.queued.remove(&addr);
                    self.book.record_handshake(addr, services, now);
                }
                PeerDiscoveryEvent::Terminal { addr, outcome, .. } => {
                    self.queued.remove(&addr);
                    if !matches!(
                        outcome,
                        PeerTerminalOutcome::Clean | PeerTerminalOutcome::Shutdown
                    ) {
                        self.book.record_failure(addr, now);
                    }
                }
            }
        }
    }

    fn resolve_dns(&mut self, now: SystemTime) {
        for seed in &self.seeds {
            match self.resolver.resolve(seed) {
                Ok(addresses) => {
                    for addr in addresses {
                        self.book.record_dns(addr, now);
                    }
                }
                Err(error) => {
                    tracing::warn!(seed = %seed, %error, "dns seed resolution failed");
                }
            }
        }
    }

    fn eligible_count(
        &self,
        active: &hashbrown::HashSet<SocketAddr>,
        banned: &BannedSubnets,
        now: SystemTime,
    ) -> usize {
        let queued: hashbrown::HashSet<SocketAddr> = self.queued.keys().copied().collect();
        self.book.eligible_count(&CandidateFilter {
            now,
            active,
            queued: &queued,
            banned: &banned.read(),
        })
    }

    fn select(
        &self,
        limit: usize,
        active: &hashbrown::HashSet<SocketAddr>,
        banned: &BannedSubnets,
        now: SystemTime,
    ) -> Vec<SocketAddr> {
        let queued: hashbrown::HashSet<SocketAddr> = self.queued.keys().copied().collect();
        self.book.select(
            limit,
            &CandidateFilter {
                now,
                active,
                queued: &queued,
                banned: &banned.read(),
            },
        )
    }
}

fn curated_peer_pool_enabled(config: &Config) -> bool {
    config.connect.is_empty()
        && config.dns_seeds_enabled
        && !matches!(config.network, bitcoin_rs_primitives::Network::Regtest)
}

#[allow(clippy::too_many_arguments)]
fn spawn_dns_peer_maintenance_with_resolver<R>(
    config: &Config,
    shutdown: Arc<AtomicBool>,
    peer_outbound: PeerOutboundMap,
    banned: BannedSubnets,
    outbound_tx: Sender<SocketAddr>,
    discovery_rx: Receiver<bitcoin_rs_p2p::discovery::PeerDiscoveryEvent>,
    resolver: R,
) -> anyhow::Result<Option<std::thread::JoinHandle<()>>>
where
    R: bitcoin_rs_p2p::DnsResolver + Send + 'static,
{
    if !curated_peer_pool_enabled(config) {
        tracing::debug!("curated peer-pool maintenance disabled");
        return Ok(None);
    }

    let seeds = config.network.dns_seeds().to_vec();
    let (book, warning) = AddressBook::load(&config.data_dir, config.network);
    if let Some(warning) = warning {
        tracing::warn!(?warning, "peer address book ignored");
    }

    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-peer-pool-maintenance".to_owned())
            .spawn(move || {
                let mut maintenance = PeerPoolMaintenance::new(resolver, seeds, book);
                let mut bootstrap_refill = DnsBootstrapRefill::default();
                let queued = maintenance.tick(
                    &peer_outbound,
                    &banned,
                    &outbound_tx,
                    &discovery_rx,
                    SystemTime::now(),
                    Instant::now(),
                );
                let mut delay = bootstrap_refill.next_delay(0, queued);
                while !shutdown.load(std::sync::atomic::Ordering::Acquire) {
                    std::thread::sleep(delay);
                    if shutdown.load(std::sync::atomic::Ordering::Acquire) {
                        break;
                    }
                    let live = peer_outbound.read().len();
                    let queued = maintenance.tick(
                        &peer_outbound,
                        &banned,
                        &outbound_tx,
                        &discovery_rx,
                        SystemTime::now(),
                        Instant::now(),
                    );
                    delay = bootstrap_refill.next_delay(live, queued);
                }
                maintenance.drain_discovery(&discovery_rx, SystemTime::now());
                if let Err(error) = maintenance.book.save_if_dirty() {
                    tracing::warn!(%error, "failed to persist peer address book at shutdown");
                }
            })?,
    ))
}

fn spawn_dns_peer_maintenance(
    config: &Config,
    shutdown: Arc<AtomicBool>,
    peer_outbound: PeerOutboundMap,
    banned: BannedSubnets,
    outbound_tx: Sender<SocketAddr>,
    discovery_rx: Receiver<bitcoin_rs_p2p::discovery::PeerDiscoveryEvent>,
) -> anyhow::Result<Option<std::thread::JoinHandle<()>>> {
    let resolver = bitcoin_rs_p2p::SystemDnsResolver::new(config.network.default_p2p_port());
    spawn_dns_peer_maintenance_with_resolver(
        config,
        shutdown,
        peer_outbound,
        banned,
        outbound_tx,
        discovery_rx,
        resolver,
    )
}

/// Maintains outbound connections to the fixed peers from `--connect`.
///
/// When `connect` is configured, DNS bootstrap is disabled and the node dials
/// only these addresses, re-queueing any that are not currently connected so a
/// dropped link is re-established (Bitcoin Core `-connect` semantics).
fn spawn_fixed_peer_bootstrap(
    state: &NodeState,
    shutdown: &Arc<AtomicBool>,
) -> anyhow::Result<Option<std::thread::JoinHandle<()>>> {
    let connect = state.config().connect.clone();
    if connect.is_empty() {
        return Ok(None);
    }
    let outbound_tx = state.p2p_outbound_sender();
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let bootstrap_shutdown = Arc::clone(shutdown);
    Ok(Some(
        std::thread::Builder::new()
            .name("bitcoin-rs-fixed-peer-bootstrap".to_owned())
            .spawn(move || {
                while !bootstrap_shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                    for addr in &connect {
                        if peer_outbound.read().contains_key(addr)
                            || peers.read().iter().any(|peer| peer.addr == *addr)
                        {
                            continue;
                        }
                        if outbound_tx.try_send(*addr).is_err() {
                            // Queue full or closed; retry on the next tick.
                            break;
                        }
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })?,
    ))
}

/// Boots the node from a resolved [`Config`] and runs until shutdown.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. Open / create the node data directory and resolve state.
/// 3. Run crash recovery against the persisted sidecar.
/// 4. Acquire a shutdown signal — either the in-process receiver wired via
///    [`Config::with_shutdown_receiver`] (tests) or a fresh SIGINT/SIGTERM
///    handler (production).
/// 5. Spin the event loop until shutdown is requested.
/// 6. Drain subsystems within [`DRAIN_DEADLINE`].
#[allow(clippy::too_many_lines)]
pub fn run(mut config: Config) -> Result<()> {
    logging::install_tracing(&config.log_level)?;

    let injected_shutdown = config.shutdown_signal.take();
    let state = NodeState::open(config)?;
    crash_recovery::recover_if_needed(&state)?;

    tracing::info!(
        network = ?state.config().network,
        data_dir = %state.data_dir().display(),
        storage_backend = %state.config().storage_backend,
        "bitcoin-rs node booting"
    );

    let shutdown_rx: Receiver<()> = if let Some(rx) = injected_shutdown {
        rx
    } else {
        let (tx, rx) = bounded(1);
        // Forwards process signals into our channel; the JoinHandle outlives `run`.
        let _signal_thread = crate::signal::install_shutdown_handler(tx)?;
        rx
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let banned = state.banned_subnets();
    let block_body_source = state.block_body_source();
    let p2p_chain_query: P2pChainQuery = Arc::new(
        crate::NodeP2pChainQuery::new(state.block_tree(), state.blocks())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, state.sync(), sync_wake_rx);
    let rpc_auth = Arc::new(build_rpc_auth(&state.config().rpc_auth)?);
    let mut rpc_context = bitcoin_rs_rpc::Context::from_handles(
        state.chain_tip(),
        state.applied_tip(),
        state.mempool(),
        state.blocks(),
        state.transactions(),
        state.utxo(),
        state.coin_stats(),
        state.filter_index(),
        state.network(),
        state.mining_template_id(),
        state.peers(),
        state.block_tree(),
        state.config().network,
        Some(state.inbound_blocks_sender()),
        Some(state.p2p_outbound_sender()),
        Arc::clone(&banned),
        Arc::new(parking_lot::RwLock::new(Vec::new())),
        state.tx_index(),
    );
    rpc_context = rpc_context.with_block_body_source(block_body_source);
    if let Some(prune_service) = state.prune_service() {
        rpc_context = rpc_context.with_prune_service(prune_service);
    }
    rpc_context = rpc_context.with_zmq_notifications(state.active_zmq_notifications());
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::new(rpc_context)));
    let rpc_server = bitcoin_rs_rpc::RpcServer::bind(
        state.config().rpc_bind,
        rpc_auth,
        rpc_handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
    )?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    // TODO(rpc_smoke): cover the RPC listener once the test ergonomics improve.
    let rpc_shutdown = Arc::clone(&shutdown);
    let rpc_thread = std::thread::Builder::new()
        .name("bitcoin-rs-rpc".into())
        .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?;
    let electrum_thread = spawn_electrum_listener(state.config(), &state, &shutdown)?;
    let peers = state.peers();
    let peer_outbound = state.peer_outbound();
    let p2p_threads = spawn_p2p_listeners(
        state.config(),
        &shutdown,
        &peers,
        &peer_outbound,
        Arc::clone(&banned),
        state.inbound_headers_sender(),
        state.inbound_blocks_sender(),
        sync_wake_tx.clone(),
        Arc::clone(&p2p_chain_query),
    )?;
    let discovery_enabled = curated_peer_pool_enabled(state.config());
    let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
    let _outbound_worker = spawn_p2p_outbound_drain(
        &state,
        &shutdown,
        &peers,
        &peer_outbound,
        Arc::clone(&banned),
        sync_wake_tx,
        Arc::clone(&p2p_chain_query),
        discovery_enabled.then_some(discovery_tx),
    )?;
    let bootstrap_worker = if state.config().connect.is_empty() {
        spawn_dns_peer_maintenance(
            state.config(),
            Arc::clone(&shutdown),
            Arc::clone(&peer_outbound),
            Arc::clone(&banned),
            state.p2p_outbound_sender(),
            discovery_rx,
        )?
    } else {
        spawn_fixed_peer_bootstrap(&state, &shutdown)?
    };
    loop_handle.spin(&shutdown)?;
    if let Some(handle) = bootstrap_worker {
        if handle.join().is_err() {
            tracing::error!("peer-pool maintenance panicked");
        } else {
            tracing::info!("peer-pool maintenance exited cleanly");
        }
    }
    if let Some(handle) = electrum_thread {
        match handle.join() {
            Ok(Ok(())) => tracing::info!("electrum listener exited cleanly"),
            Ok(Err(error)) => tracing::warn!(%error, "electrum listener exited with error"),
            Err(_) => tracing::error!("electrum listener panicked"),
        }
    }
    match rpc_thread.join() {
        Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
        Ok(Err(error)) => tracing::warn!(%error, "rpc listener exited with i/o error"),
        Err(_) => tracing::error!("rpc listener panicked"),
    }
    for handle in p2p_threads {
        let thread_name = handle
            .thread()
            .name()
            .unwrap_or("bitcoin-rs-p2p")
            .to_owned();
        match handle.join() {
            Ok(Ok(())) => tracing::info!(thread = %thread_name, "p2p listener exited cleanly"),
            Ok(Err(error)) => {
                tracing::warn!(thread = %thread_name, %error, "p2p listener exited with error");
            }
            Err(_) => tracing::error!(thread = %thread_name, "p2p listener panicked"),
        }
    }

    shutdown::drain_and_shutdown(DRAIN_DEADLINE)?;
    tracing::info!("bitcoin-rs node exited cleanly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::UNIX_EPOCH;

    use bitcoin::p2p::ServiceFlags;
    use bitcoin_rs_p2p::discovery::{DiscoveredPeer, PeerDiscoveryEvent, PeerTerminalOutcome};

    use super::*;

    #[derive(Clone)]
    struct RecordingResolver {
        calls: Arc<AtomicUsize>,
        addresses: Vec<SocketAddr>,
    }

    impl bitcoin_rs_p2p::DnsResolver for RecordingResolver {
        fn resolve(&self, _seed: &str) -> Result<Vec<SocketAddr>, bitcoin_rs_p2p::PeerError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.addresses.clone())
        }
    }

    fn empty_peer_outbound() -> PeerOutboundMap {
        Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()))
    }

    fn empty_banned() -> BannedSubnets {
        Arc::new(parking_lot::RwLock::new(Vec::new()))
    }

    fn public_addr(group: u8, host: u8) -> SocketAddr {
        SocketAddr::from(([23, group, 0, host], 8333))
    }

    fn announcement(addr: SocketAddr) -> PeerDiscoveryEvent {
        PeerDiscoveryEvent::Announced(DiscoveredPeer {
            addr,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
            seen_at: 1_800_000_000,
        })
    }

    fn send_announcements(tx: &Sender<PeerDiscoveryEvent>, count: u8) {
        for group in 1..=count {
            tx.send(announcement(public_addr(group, 1)))
                .unwrap_or_else(|error| panic!("discovery test channel disconnected: {error}"));
        }
    }

    fn test_maintenance(
        data_dir: &std::path::Path,
        calls: Arc<AtomicUsize>,
        addresses: Vec<SocketAddr>,
    ) -> PeerPoolMaintenance<RecordingResolver> {
        let book = AddressBook::load(data_dir, bitcoin_rs_primitives::Network::Signet).0;
        PeerPoolMaintenance::new(
            RecordingResolver { calls, addresses },
            vec!["seed.test"],
            book,
        )
    }

    fn test_now() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_800_000_100)
    }

    #[test]
    fn connectionless_bootstrap_refills_are_fast_and_bounded() {
        let mut refill = DnsBootstrapRefill::default();

        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_BOOTSTRAP_REFILL_INTERVAL
        );
        assert_eq!(
            refill.next_delay(0, P2P_OUTBOUND_PEER_TARGET),
            DNS_MAINTENANCE_INTERVAL
        );
        assert_eq!(refill.next_delay(1, 0), DNS_MAINTENANCE_INTERVAL);
    }

    #[test]
    fn announcements_fill_live_deficit_without_dns() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut maintenance = test_maintenance(dir.path(), Arc::clone(&calls), Vec::new());
        let peer_outbound = empty_peer_outbound();
        let banned = empty_banned();
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        send_announcements(&discovery_tx, 40);

        let queued = maintenance.tick(
            &peer_outbound,
            &banned,
            &dial_tx,
            &discovery_rx,
            test_now(),
            Instant::now(),
        );

        assert_eq!(queued, P2P_OUTBOUND_PEER_TARGET);
        assert_eq!(dial_rx.try_iter().count(), P2P_OUTBOUND_PEER_TARGET);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn successful_peer_is_selected_before_announcements() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut maintenance = test_maintenance(dir.path(), Arc::clone(&calls), Vec::new());
        let peer_outbound = empty_peer_outbound();
        let banned = empty_banned();
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        send_announcements(&discovery_tx, 32);
        let successful = public_addr(32, 1);
        discovery_tx.send(PeerDiscoveryEvent::HandshakeReady {
            addr: successful,
            services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        })?;

        maintenance.tick(
            &peer_outbound,
            &banned,
            &dial_tx,
            &discovery_rx,
            test_now(),
            Instant::now(),
        );

        assert_eq!(dial_rx.try_recv()?, successful);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn unreachable_ipv6_is_backed_off_without_disabling_ipv6()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut maintenance = test_maintenance(dir.path(), calls, Vec::new());
        let peer_outbound = empty_peer_outbound();
        let banned = empty_banned();
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        let failed = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1),
            8333,
            0,
            0,
        ));
        let healthy = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2607, 0xf8b0, 0, 0, 0, 0, 0, 1),
            8333,
            0,
            0,
        ));
        discovery_tx.send(announcement(failed))?;
        discovery_tx.send(announcement(healthy))?;
        discovery_tx.send(PeerDiscoveryEvent::Terminal {
            addr: failed,
            handshake_completed: false,
            connected_for: None,
            outcome: PeerTerminalOutcome::Io,
        })?;

        maintenance.tick(
            &peer_outbound,
            &banned,
            &dial_tx,
            &discovery_rx,
            test_now(),
            Instant::now(),
        );

        let dialed: Vec<_> = dial_rx.try_iter().collect();
        assert_eq!(dialed, vec![healthy]);
        Ok(())
    }

    #[test]
    fn refill_diversifies_before_reusing_network_group() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut maintenance = test_maintenance(dir.path(), calls, Vec::new());
        let peer_outbound = empty_peer_outbound();
        let banned = empty_banned();
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        let first_group = SocketAddr::from(([1, 1, 1, 1], 8333));
        let reused_group = SocketAddr::from(([1, 1, 2, 1], 8333));
        discovery_tx.send(announcement(first_group))?;
        discovery_tx.send(announcement(reused_group))?;
        for group in 2..=32 {
            discovery_tx.send(announcement(public_addr(group, 1)))?;
        }

        maintenance.tick(
            &peer_outbound,
            &banned,
            &dial_tx,
            &discovery_rx,
            test_now(),
            Instant::now(),
        );

        let dialed: Vec<_> = dial_rx.try_iter().collect();
        assert!(dialed.contains(&first_group));
        assert!(!dialed.contains(&reused_group));
        Ok(())
    }

    #[test]
    fn live_and_queued_peers_bound_refill_to_actual_deficit()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let mut maintenance = test_maintenance(dir.path(), calls, Vec::new());
        let peer_outbound = empty_peer_outbound();
        for group in 50..53 {
            let (tx, _rx) = crossbeam_channel::unbounded();
            peer_outbound.write().insert(public_addr(group, 1), tx);
        }
        let banned = empty_banned();
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        send_announcements(&discovery_tx, 32);
        let now = Instant::now();

        assert_eq!(
            maintenance.tick(
                &peer_outbound,
                &banned,
                &dial_tx,
                &discovery_rx,
                test_now(),
                now,
            ),
            5
        );
        assert_eq!(
            maintenance.tick(
                &peer_outbound,
                &banned,
                &dial_tx,
                &discovery_rx,
                test_now(),
                now + Duration::from_secs(1),
            ),
            0
        );
        assert_eq!(dial_rx.try_iter().count(), 5);
        Ok(())
    }

    #[test]
    fn clean_shutdown_persists_candidates_for_restart_without_dns()
    -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let mut config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        config.data_dir = dir.path().to_path_buf();
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = RecordingResolver {
            calls: Arc::clone(&calls),
            addresses: Vec::new(),
        };
        let shutdown = Arc::new(AtomicBool::new(true));
        let peer_outbound = empty_peer_outbound();
        let banned = empty_banned();
        let (dial_tx, _dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        let (discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        send_announcements(&discovery_tx, 32);

        let handle = spawn_dns_peer_maintenance_with_resolver(
            &config,
            shutdown,
            peer_outbound,
            banned,
            dial_tx,
            discovery_rx,
            resolver,
        )?
        .ok_or_else(|| std::io::Error::other("signet peer pool must start"))?;
        handle
            .join()
            .map_err(|_| std::io::Error::other("peer-pool maintenance panicked"))?;

        let (book, warning) = AddressBook::load(dir.path(), config.network);
        assert!(warning.is_none());
        assert_eq!(book.len(), 32);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn fixed_connect_mode_disables_curated_discovery() -> anyhow::Result<()> {
        let mut config = Config::default_for_network(bitcoin_rs_primitives::Network::Signet);
        config.connect.push(public_addr(1, 1));
        assert!(!curated_peer_pool_enabled(&config));
        let dir = tempfile::tempdir()?;
        config.data_dir = dir.path().to_path_buf();
        let calls = Arc::new(AtomicUsize::new(0));
        let (_discovery_tx, discovery_rx) = bounded(PEER_DISCOVERY_CHANNEL_CAPACITY);
        let (dial_tx, _dial_rx) = bounded(P2P_OUTBOUND_PEER_TARGET);
        let handle = spawn_dns_peer_maintenance_with_resolver(
            &config,
            Arc::new(AtomicBool::new(false)),
            empty_peer_outbound(),
            empty_banned(),
            dial_tx,
            discovery_rx,
            RecordingResolver {
                calls: Arc::clone(&calls),
                addresses: Vec::new(),
            },
        )?;
        assert!(handle.is_none());
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn outbound_addr_available_rejects_active_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut active = hashbrown::HashSet::new();
        active.insert(addr);
        let peers: PeerRegistry = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let peer_outbound: PeerOutboundMap = empty_peer_outbound();

        assert!(!outbound_addr_available(
            addr,
            &active,
            &peers,
            &peer_outbound
        ));
    }

    #[test]
    fn outbound_addr_available_rejects_connected_duplicate() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let active = hashbrown::HashSet::new();
        let peers: PeerRegistry = Arc::new(parking_lot::RwLock::new(Vec::new()));
        let peer_outbound: PeerOutboundMap = empty_peer_outbound();
        let (tx, _rx) = crossbeam_channel::unbounded();
        peer_outbound.write().insert(addr, tx);

        assert!(!outbound_addr_available(
            addr,
            &active,
            &peers,
            &peer_outbound
        ));
    }

    #[test]
    fn outbound_drain_reaps_finished_attempts() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let mut active = hashbrown::HashSet::new();
        active.insert(addr);
        let handle = std::thread::spawn(|| Ok::<(), bitcoin_rs_p2p::PeerError>(()));
        while !handle.is_finished() {
            std::thread::yield_now();
        }
        let mut handles = vec![(addr, handle)];

        reap_finished_outbound_connections(&mut active, &mut handles);

        assert!(active.is_empty());
        assert!(handles.is_empty());
    }
}
