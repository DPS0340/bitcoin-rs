use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use bitcoin::p2p::Magic;
use crossbeam_channel::Sender;
use parking_lot::RwLock;

use thiserror::Error;

use crate::discovery::{
    PeerDiscoveryEvent, PeerTerminalOutcome, candidate_from_addr, candidate_from_addr_v2,
};
use crate::handshake::run_inbound_handshake;
use crate::peer::Peer;

const POLL_INTERVAL: Duration = Duration::from_millis(100);
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_mins(1);
type ChainQueryHandle = Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>;
type SyncWakeHandle = Option<Sender<()>>;

#[derive(Clone)]
struct InboundSyncSinks {
    headers_tx: Sender<Vec<bitcoin::block::Header>>,
    blocks_tx: Sender<crate::InboundBlock>,
    wake_tx: SyncWakeHandle,
}

impl InboundSyncSinks {
    fn send_headers(&self, peer_addr: SocketAddr, headers: Vec<bitcoin::block::Header>) {
        if let Err(error) = self.headers_tx.send(headers) {
            tracing::warn!(
                peer_addr = %peer_addr,
                %error,
                "p2p inbound headers channel disconnected",
            );
        } else {
            wake_sync(self.wake_tx.as_ref());
        }
    }

    fn send_block(&self, peer_addr: SocketAddr, block: bitcoin::Block, serialized: bytes::Bytes) {
        if let Err(error) = self.blocks_tx.send(crate::InboundBlock {
            block,
            serialized,
            source_peer: Some(peer_addr),
        }) {
            tracing::warn!(
                peer_addr = %peer_addr,
                %error,
                "p2p inbound blocks channel disconnected",
            );
        } else {
            wake_sync(self.wake_tx.as_ref());
        }
    }
}

/// Errors returned by the P2P listener accept loop.
#[derive(Debug, Error)]
pub enum ListenerError {
    /// Failed to bind the TCP listener.
    #[error("bind {addr}: {source}")]
    Bind {
        /// Address the listener attempted to bind.
        addr: SocketAddr,
        /// Underlying bind or listener setup failure.
        source: io::Error,
    },
    /// Accept loop returned a fatal I/O error.
    #[error("accept: {0}")]
    Accept(#[from] io::Error),
}

/// Binds `addr` and runs an accept loop until `shutdown` is set.
///
/// On each accepted connection, spawns a thread that runs the inbound
/// handshake followed by a message-dispatch loop. The handshake uses
/// `HANDSHAKE_READ_TIMEOUT` (60s); after handshake, the message loop polls
/// inbound reads every second while enforcing a 60s inbound idle timeout.
/// The thread terminates on:
///   - successful handshake then idle (60s of no inbound messages)
///   - wire / FSM error
///   - explicit FSM disconnect transition
///
/// Per-connection threads are NOT joined by the outer shutdown — they
/// outlive the listener by up to the timeout. On exit (clean or error),
/// the peer is removed from `peer_registry` via address-match retain.
///
/// Successful inbound handshakes append their public metadata to
/// `peer_registry`. The peer is removed from `peer_registry` when the
/// per-connection thread exits.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> Result<(), ListenerError> {
    serve_with_shutdown_with_chain_and_sync_wake(
        addr,
        shutdown,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
        None,
    )
}

/// Binds `addr` and runs an accept loop with active-chain and sync-wake handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn serve_with_shutdown_with_chain_and_sync_wake(
    addr: SocketAddr,
    shutdown: Arc<AtomicBool>,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
) -> Result<(), ListenerError> {
    let inbound_sync_sinks = InboundSyncSinks {
        headers_tx: inbound_headers_tx,
        blocks_tx: inbound_blocks_tx,
        wake_tx: sync_wake_tx,
    };
    let listener =
        TcpListener::bind(addr).map_err(|source| ListenerError::Bind { addr, source })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| ListenerError::Bind { addr, source })?;
    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer_addr)) => {
                if crate::subnet::is_banned(&banned.read(), peer_addr.ip(), SystemTime::now()) {
                    drop(stream);
                    tracing::debug!(peer_addr = %peer_addr, "p2p inbound rejected: banned");
                    continue;
                }
                spawn_handshake_thread(
                    stream,
                    peer_addr,
                    magic,
                    Arc::clone(&peer_registry),
                    Arc::clone(&peer_outbound),
                    inbound_sync_sinks.clone(),
                    chain_query.clone(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(ListenerError::Accept(error)),
        }
    }
    Ok(())
}

/// Spawns an outbound TCP connection and enters the shared message loop.
///
/// This compatibility entry point does not request or emit peer discovery.
#[allow(clippy::needless_pass_by_value)]
pub fn spawn_outbound_connection(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_outbound_connection_with_chain_sync_and_discovery(
        addr,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        None,
        None,
        None,
    )
}

/// Spawns an outbound connection with active-chain and sync-wake handles.
///
/// This compatibility entry point does not request or emit peer discovery.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_chain_and_sync_wake(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    spawn_outbound_connection_with_chain_sync_and_discovery(
        addr,
        magic,
        peer_registry,
        peer_outbound,
        inbound_headers_tx,
        inbound_blocks_tx,
        banned,
        chain_query,
        sync_wake_tx,
        None,
    )
}

/// Spawns an outbound connection with chain, sync-wake, and discovery handles.
#[allow(clippy::needless_pass_by_value, clippy::too_many_arguments)]
pub fn spawn_outbound_connection_with_chain_sync_and_discovery(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_headers_tx: Sender<Vec<bitcoin::block::Header>>,
    inbound_blocks_tx: Sender<crate::InboundBlock>,
    banned: Arc<RwLock<Vec<crate::BannedSubnet>>>,
    chain_query: Option<Arc<dyn crate::dispatch::ChainQuery + 'static>>,
    sync_wake_tx: Option<Sender<()>>,
    discovery_tx: Option<Sender<PeerDiscoveryEvent>>,
) -> std::thread::JoinHandle<Result<(), crate::wire::PeerError>> {
    let inbound_sync_sinks = InboundSyncSinks {
        headers_tx: inbound_headers_tx,
        blocks_tx: inbound_blocks_tx,
        wake_tx: sync_wake_tx,
    };
    let spawn_failure_tx = discovery_tx.clone();
    let thread_name = format!("bitcoin-rs-p2p-outbound-{addr}");
    let result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            run_outbound_connection(
                addr,
                magic,
                &peer_registry,
                &peer_outbound,
                &inbound_sync_sinks,
                &banned,
                &chain_query,
                discovery_tx.as_ref(),
            )
        });

    match result {
        Ok(handle) => handle,
        Err(error) => {
            tracing::warn!(
                addr = %addr,
                %error,
                "p2p outbound spawn failed",
            );
            send_discovery_event(
                spawn_failure_tx.as_ref(),
                PeerDiscoveryEvent::Terminal {
                    addr,
                    handshake_completed: false,
                    connected_for: None,
                    outcome: PeerTerminalOutcome::Io,
                },
            );
            std::thread::spawn(move || Err(crate::wire::PeerError::Io(error)))
        }
    }
}

fn run_outbound_connection(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_sync_sinks: &InboundSyncSinks,
    banned: &RwLock<Vec<crate::BannedSubnet>>,
    chain_query: &ChainQueryHandle,
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
) -> Result<(), crate::wire::PeerError> {
    let mut handshake_completed = false;
    let mut ready_at = None;
    let detailed_result = run_outbound_connection_inner(
        addr,
        magic,
        peer_registry,
        peer_outbound,
        inbound_sync_sinks,
        banned,
        chain_query,
        discovery_tx,
        &mut handshake_completed,
        &mut ready_at,
    );
    send_terminal_event(
        discovery_tx,
        addr,
        handshake_completed,
        ready_at,
        &detailed_result,
        Instant::now(),
    );
    detailed_result.map(|_| ())
}

#[allow(clippy::too_many_arguments)]
fn run_outbound_connection_inner(
    addr: SocketAddr,
    magic: Magic,
    peer_registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_sync_sinks: &InboundSyncSinks,
    banned: &RwLock<Vec<crate::BannedSubnet>>,
    chain_query: &ChainQueryHandle,
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
    handshake_completed: &mut bool,
    ready_at: &mut Option<Instant>,
) -> Result<PeerTerminalOutcome, crate::wire::PeerError> {
    if crate::subnet::is_banned(&banned.read(), addr.ip(), SystemTime::now()) {
        return Err(crate::wire::PeerError::BannedDestination(addr.ip()));
    }

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(10))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    let nonce = generate_nonce(addr);
    let mut peer = Peer::new(stream, magic);
    run_outbound_handshake(&mut peer, nonce, 0)?;
    *handshake_completed = true;
    *ready_at = Some(Instant::now());

    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after outbound handshake",
        ));
    };
    let remote_services = remote_version.services;
    let conn_time = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let info = crate::PeerInfo::outbound_from_version(addr, remote_version, conn_time);
    peer_registry.write().push(info);

    let writer_stream = peer
        .stream
        .try_clone()
        .map_err(crate::wire::PeerError::Io)?;
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let writer = spawn_connection_writer(writer_stream, magic, outbound_rx, addr)
        .map_err(crate::wire::PeerError::Io)?;
    peer_outbound.write().insert(addr, outbound_tx.clone());
    begin_peer_discovery(discovery_tx, &outbound_tx, addr, remote_services);

    tracing::info!(
        peer_addr = %addr,
        "p2p outbound handshake complete; entering message loop",
    );

    let loop_result = (|| {
        peer.stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(crate::wire::PeerError::Io)?;
        run_message_loop(
            &mut peer,
            addr,
            &outbound_tx,
            peer_outbound,
            inbound_sync_sinks,
            chain_query.as_deref(),
            discovery_tx,
        )
    })();

    peer_outbound.write().remove(&addr);
    peer_registry.write().retain(|p| p.addr != addr);
    let _ = peer.stream.shutdown(std::net::Shutdown::Both);
    drop(outbound_tx);
    let _ = writer.join();
    if let Err(error) = &loop_result {
        tracing::warn!(peer_addr = %addr, %error, "p2p outbound peer disconnected with error");
    } else {
        tracing::debug!(peer_addr = %addr, "p2p outbound peer disconnected cleanly");
    }
    loop_result
}

fn run_outbound_handshake<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    nonce: u64,
    start_height: i32,
) -> Result<(), crate::wire::PeerError> {
    let outbound_messages = crate::handshake::start(peer, nonce, start_height);
    for message in outbound_messages {
        peer.send(&message)?;
    }

    while peer.state != crate::peer::PeerState::Ready {
        let (inbound, _) = crate::wire::read_message(&mut peer.stream, peer.magic)?;
        let responses = crate::dispatch::dispatch_inbound(peer, &inbound)?;
        for response in responses {
            peer.send(&response)?;
        }
    }

    Ok(())
}

fn begin_peer_discovery(
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
    outbound_tx: &Sender<crate::Message>,
    addr: SocketAddr,
    services: bitcoin::p2p::ServiceFlags,
) {
    let Some(discovery_tx) = discovery_tx else {
        return;
    };
    let _ = discovery_tx.try_send(PeerDiscoveryEvent::HandshakeReady { addr, services });
    let _ = outbound_tx.try_send(bitcoin::p2p::message::NetworkMessage::GetAddr);
}

fn send_announced_peers(
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
    message: &bitcoin::p2p::message::NetworkMessage,
) {
    let Some(discovery_tx) = discovery_tx else {
        return;
    };
    match message {
        bitcoin::p2p::message::NetworkMessage::Addr(entries) => {
            for (time, address) in entries {
                if let Some(candidate) = candidate_from_addr(*time, address) {
                    let _ = discovery_tx.try_send(PeerDiscoveryEvent::Announced(candidate));
                }
            }
        }
        bitcoin::p2p::message::NetworkMessage::AddrV2(entries) => {
            for entry in entries {
                if let Some(candidate) = candidate_from_addr_v2(entry) {
                    let _ = discovery_tx.try_send(PeerDiscoveryEvent::Announced(candidate));
                }
            }
        }
        _ => {}
    }
}

fn send_terminal_event(
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
    addr: SocketAddr,
    handshake_completed: bool,
    ready_at: Option<Instant>,
    result: &Result<PeerTerminalOutcome, crate::wire::PeerError>,
    finished_at: Instant,
) {
    let outcome = match result {
        Ok(outcome) => *outcome,
        Err(crate::wire::PeerError::Io(_)) => PeerTerminalOutcome::Io,
        Err(
            crate::wire::PeerError::BannedDestination(_)
            | crate::wire::PeerError::InvalidBanEntry(_),
        ) => PeerTerminalOutcome::Policy,
        Err(
            crate::wire::PeerError::Encode(_)
            | crate::wire::PeerError::InvalidCommand(_)
            | crate::wire::PeerError::WrongNetwork { .. }
            | crate::wire::PeerError::PayloadTooLarge(_)
            | crate::wire::PeerError::BadChecksum
            | crate::wire::PeerError::Protocol(_),
        ) => PeerTerminalOutcome::Protocol,
    };
    send_discovery_event(
        discovery_tx,
        PeerDiscoveryEvent::Terminal {
            addr,
            handshake_completed,
            connected_for: ready_at.map(|started| finished_at.saturating_duration_since(started)),
            outcome,
        },
    );
}

fn send_discovery_event(
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
    event: PeerDiscoveryEvent,
) {
    if let Some(discovery_tx) = discovery_tx {
        let _ = discovery_tx.try_send(event);
    }
}

fn spawn_handshake_thread(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    registry: Arc<RwLock<Vec<crate::PeerInfo>>>,
    peer_outbound: Arc<RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>>,
    inbound_sync_sinks: InboundSyncSinks,
    chain_query: ChainQueryHandle,
) {
    let thread_name = format!("bitcoin-rs-p2p-handshake-{peer_addr}");
    let spawn_result = std::thread::Builder::new()
        .name(thread_name)
        .spawn(move || {
            if let Err(error) = run_handshake(
                stream,
                peer_addr,
                magic,
                &registry,
                &peer_outbound,
                &inbound_sync_sinks,
                &chain_query,
            ) {
                tracing::warn!(
                    peer_addr = %peer_addr,
                    %error,
                    "p2p inbound handshake failed",
                );
            }
        });

    if let Err(error) = spawn_result {
        tracing::warn!(
            peer_addr = %peer_addr,
            %error,
            "failed to spawn p2p inbound handshake thread",
        );
    }
    // The handle is intentionally dropped: per-connection threads outlive
    // this listener thread by up to HANDSHAKE_READ_TIMEOUT.
}

fn run_handshake(
    stream: TcpStream,
    peer_addr: SocketAddr,
    magic: Magic,
    registry: &RwLock<Vec<crate::PeerInfo>>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_sync_sinks: &InboundSyncSinks,
    chain_query: &ChainQueryHandle,
) -> Result<(), crate::wire::PeerError> {
    stream
        .set_nonblocking(false)
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_read_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;
    stream
        .set_write_timeout(Some(HANDSHAKE_READ_TIMEOUT))
        .map_err(crate::wire::PeerError::Io)?;

    let nonce = generate_nonce(peer_addr);
    let mut peer = Peer::new(stream, magic);
    run_inbound_handshake(&mut peer, nonce, 0)?;

    let Some(remote_version) = peer.remote_version.as_ref() else {
        return Err(crate::wire::PeerError::Protocol(
            "missing remote version after successful handshake",
        ));
    };
    let conn_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let info = crate::PeerInfo::inbound_from_version(peer_addr, remote_version, conn_time);
    registry.write().push(info);

    let writer_stream = peer
        .stream
        .try_clone()
        .map_err(crate::wire::PeerError::Io)?;
    let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded::<crate::Message>();
    let writer = spawn_connection_writer(writer_stream, magic, outbound_rx, peer_addr)
        .map_err(crate::wire::PeerError::Io)?;
    peer_outbound.write().insert(peer_addr, outbound_tx.clone());

    tracing::info!(
        peer_addr = %peer_addr,
        "p2p inbound handshake complete; entering message loop",
    );

    let loop_result = (|| {
        peer.stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .map_err(crate::wire::PeerError::Io)?;
        run_message_loop(
            &mut peer,
            peer_addr,
            &outbound_tx,
            peer_outbound,
            inbound_sync_sinks,
            chain_query.as_deref(),
            None,
        )
    })();

    peer_outbound.write().remove(&peer_addr);
    registry.write().retain(|p| p.addr != peer_addr);
    let _ = peer.stream.shutdown(std::net::Shutdown::Both);
    drop(outbound_tx);
    let _ = writer.join();
    if let Err(error) = &loop_result {
        tracing::warn!(peer_addr = %peer_addr, %error, "p2p peer disconnected with error");
    } else {
        tracing::debug!(peer_addr = %peer_addr, "p2p peer disconnected cleanly");
    }
    loop_result.map(|_| ())
}

fn run_message_loop<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    peer_addr: SocketAddr,
    outbound_tx: &Sender<crate::Message>,
    peer_outbound: &RwLock<hashbrown::HashMap<SocketAddr, Sender<crate::Message>>>,
    inbound_sync_sinks: &InboundSyncSinks,
    chain_query: Option<&dyn crate::dispatch::ChainQuery>,
    discovery_tx: Option<&Sender<PeerDiscoveryEvent>>,
) -> Result<PeerTerminalOutcome, crate::wire::PeerError> {
    use crate::peer::PeerState;
    use std::time::Instant;

    const IDLE_DISCONNECT: Duration = Duration::from_mins(1);

    let mut last_inbound = Instant::now();

    loop {
        if peer.state == PeerState::Disconnecting {
            return Ok(PeerTerminalOutcome::Clean);
        }

        // The peer's entry in `peer_outbound` is the connection's lease: it
        // is inserted exactly once before this loop and normally removed only
        // by this thread on exit, so an external removal (the node sync
        // layer's staller disconnect) is a disconnect request. The loop wakes
        // at least once per second (1s read timeout), bounding the teardown
        // latency.
        if !peer_outbound.read().contains_key(&peer_addr) {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer lease revoked; closing");
            return Ok(PeerTerminalOutcome::Other);
        }

        if last_inbound.elapsed() >= IDLE_DISCONNECT {
            tracing::debug!(peer_addr = %peer_addr, "p2p peer idle 60s; closing");
            return Ok(PeerTerminalOutcome::Other);
        }

        match crate::wire::read_message(&mut peer.stream, peer.magic) {
            Ok((message, raw)) => {
                last_inbound = Instant::now();
                tracing::trace!(
                    peer_addr = %peer_addr,
                    command = ?std::mem::discriminant(&message),
                    "p2p message received",
                );
                send_announced_peers(discovery_tx, &message);
                let responses =
                    crate::dispatch::dispatch_inbound_with_chain(peer, &message, chain_query)?;
                match message {
                    bitcoin::p2p::message::NetworkMessage::Headers(headers) => {
                        inbound_sync_sinks.send_headers(peer_addr, headers);
                    }
                    bitcoin::p2p::message::NetworkMessage::Block(block) => {
                        inbound_sync_sinks.send_block(peer_addr, block, raw);
                    }
                    _ => {}
                }
                for response in responses {
                    if outbound_tx.send(response).is_err() {
                        return Ok(PeerTerminalOutcome::Other);
                    }
                }
            }
            Err(crate::wire::PeerError::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Spawns a per-connection writer thread that drains queued outbound messages
/// and writes them to the peer. Decoupling writes from the blocking inbound
/// read ensures a momentarily silent peer can never delay outbound sends (the
/// next `getdata` during IBD). Exits when every sender drops or a write fails.
fn spawn_connection_writer(
    mut stream: TcpStream,
    magic: Magic,
    outbound_rx: crossbeam_channel::Receiver<crate::Message>,
    peer_addr: SocketAddr,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("bitcoin-rs-p2p-writer-{peer_addr}"))
        .spawn(move || {
            while let Ok(message) = outbound_rx.recv() {
                if let Err(error) = crate::wire::write_message(&mut stream, magic, &message) {
                    tracing::debug!(peer_addr = %peer_addr, %error, "p2p writer thread exiting");
                    break;
                }
            }
        })
}

fn wake_sync(sync_wake_tx: Option<&Sender<()>>) {
    if let Some(tx) = sync_wake_tx {
        let _ = tx.try_send(());
    }
}

fn generate_nonce(peer_addr: SocketAddr) -> u64 {
    use std::hash::{BuildHasher, Hash, Hasher};
    use std::time::{SystemTime, UNIX_EPOCH};

    let random_state = std::collections::hash_map::RandomState::new();
    let mut hasher = random_state.build_hasher();
    peer_addr.hash(&mut hasher);
    std::thread::current().id().hash(&mut hasher);
    if let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) {
        duration.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod outbound_tests {
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;
    use std::time::Duration;

    use bitcoin::p2p::{Magic, ServiceFlags, address::Address, message::NetworkMessage};
    use parking_lot::RwLock;

    use super::{
        run_inbound_handshake, spawn_outbound_connection,
        spawn_outbound_connection_with_chain_sync_and_discovery,
    };
    use crate::discovery::{PeerDiscoveryEvent, PeerTerminalOutcome};
    use crate::peer::Peer;

    #[test]
    fn spawn_outbound_connection_to_closed_port_fails_quickly()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);

        let registry = Arc::new(RwLock::new(Vec::new()));
        let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));

        let handle = spawn_outbound_connection(
            addr,
            Magic::BITCOIN,
            registry,
            outbound,
            headers_tx,
            blocks_tx,
            banned,
        );
        let inner = match handle.join() {
            Ok(inner) => inner,
            Err(error) => std::panic::resume_unwind(error),
        };

        assert!(
            inner.is_err(),
            "expected connection failure to unlistened port"
        );

        Ok(())
    }

    #[test]
    fn discovery_spawn_emits_one_terminal_for_connect_failure()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        drop(listener);
        let registry = Arc::new(RwLock::new(Vec::new()));
        let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));
        let (discovery_tx, discovery_rx) = crossbeam_channel::bounded(2);

        let handle = spawn_outbound_connection_with_chain_sync_and_discovery(
            addr,
            Magic::BITCOIN,
            registry,
            outbound,
            headers_tx,
            blocks_tx,
            banned,
            None,
            None,
            Some(discovery_tx),
        );
        let inner = match handle.join() {
            Ok(inner) => inner,
            Err(error) => std::panic::resume_unwind(error),
        };
        assert!(inner.is_err());
        assert_eq!(
            discovery_rx.try_recv()?,
            PeerDiscoveryEvent::Terminal {
                addr,
                handshake_completed: false,
                connected_for: None,
                outcome: PeerTerminalOutcome::Io,
            }
        );
        assert!(
            discovery_rx.try_recv().is_err(),
            "terminal must be emitted once"
        );
        Ok(())
    }

    #[test]
    fn discovery_spawn_routes_handshake_getaddr_announcement_and_terminal()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let addr = listener.local_addr()?;
        let announced_addr = SocketAddr::from(([1, 1, 1, 1], 8333));
        let server = std::thread::spawn(move || -> Result<(), crate::wire::PeerError> {
            let (stream, peer_addr) = listener.accept()?;
            stream.set_read_timeout(Some(Duration::from_secs(5)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            let mut peer = Peer::new(stream, Magic::BITCOIN);
            run_inbound_handshake(&mut peer, 7, 0)?;
            let (message, _) = crate::wire::read_message(&mut peer.stream, Magic::BITCOIN)?;
            if !matches!(message, NetworkMessage::GetAddr) {
                return Err(crate::wire::PeerError::Protocol(
                    "expected getaddr after outbound handshake",
                ));
            }
            peer.send(&NetworkMessage::Addr(vec![(
                1,
                Address::new(&announced_addr, ServiceFlags::WITNESS),
            )]))?;
            tracing::trace!(%peer_addr, "test discovery peer closing");
            Ok(())
        });

        let registry = Arc::new(RwLock::new(Vec::new()));
        let outbound = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        let banned = Arc::new(RwLock::new(Vec::new()));
        let (discovery_tx, discovery_rx) = crossbeam_channel::bounded(4);
        let client = spawn_outbound_connection_with_chain_sync_and_discovery(
            addr,
            Magic::BITCOIN,
            registry,
            outbound,
            headers_tx,
            blocks_tx,
            banned,
            None,
            None,
            Some(discovery_tx),
        );

        let server_result = match server.join() {
            Ok(result) => result,
            Err(error) => std::panic::resume_unwind(error),
        };
        server_result?;
        let client_result = match client.join() {
            Ok(result) => result,
            Err(error) => std::panic::resume_unwind(error),
        };
        assert!(client_result.is_err(), "server close must end the client");

        let events: Vec<_> = discovery_rx.try_iter().collect();
        assert_eq!(events.len(), 3);
        assert!(matches!(
            events[0],
            PeerDiscoveryEvent::HandshakeReady { addr: event_addr, services }
                if event_addr == addr
                    && services.has(ServiceFlags::NETWORK)
                    && services.has(ServiceFlags::WITNESS)
        ));
        assert!(matches!(
            events[1],
            PeerDiscoveryEvent::Announced(candidate)
                if candidate.addr == announced_addr
        ));
        assert!(matches!(
            events[2],
            PeerDiscoveryEvent::Terminal {
                addr: event_addr,
                handshake_completed: true,
                connected_for: Some(_),
                outcome: PeerTerminalOutcome::Io,
            } if event_addr == addr
        ));
        Ok(())
    }
}

#[cfg(test)]
mod lease_tests {
    use std::io::{self, Cursor};
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    use bitcoin::p2p::Magic;
    use parking_lot::RwLock;

    use super::{InboundSyncSinks, run_message_loop};
    use crate::discovery::PeerTerminalOutcome;
    use crate::peer::{Peer, PeerState};

    type OutboundMap =
        Arc<RwLock<hashbrown::HashMap<SocketAddr, crossbeam_channel::Sender<crate::Message>>>>;

    fn sinks() -> InboundSyncSinks {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, _blocks_rx) = crossbeam_channel::unbounded();
        InboundSyncSinks {
            headers_tx,
            blocks_tx,
            wake_tx: None,
        }
    }

    #[test]
    fn block_sink_preserves_delivery_peer() -> Result<(), Box<dyn std::error::Error>> {
        let (headers_tx, _headers_rx) = crossbeam_channel::unbounded();
        let (blocks_tx, blocks_rx) = crossbeam_channel::unbounded();
        let sinks = InboundSyncSinks {
            headers_tx,
            blocks_tx,
            wake_tx: None,
        };
        let peer_addr = SocketAddr::from(([127, 0, 0, 1], 8333));
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let serialized = bytes::Bytes::from(bitcoin::consensus::encode::serialize(&block));

        sinks.send_block(peer_addr, block, serialized.clone());

        let received = blocks_rx.try_recv()?;
        assert_eq!(received.source_peer, Some(peer_addr));
        assert_eq!(received.serialized, serialized);
        Ok(())
    }

    /// A stream that revokes the connection's `peer_outbound` lease on the
    /// first read, then reports `WouldBlock` — modelling the sync layer
    /// removing the entry while the loop is blocked in its 1s read timeout.
    struct RevokingStream {
        peer_outbound: OutboundMap,
        addr: SocketAddr,
    }

    impl io::Read for RevokingStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            self.peer_outbound.write().remove(&self.addr);
            Err(io::ErrorKind::WouldBlock.into())
        }
    }

    impl io::Write for RevokingStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A stream the loop must never read from (the lease is already gone
    /// before the first iteration).
    struct UnreadableStream;

    impl io::Read for UnreadableStream {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            panic!("message loop must check the lease before reading")
        }
    }

    impl io::Write for UnreadableStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn message_loop_exits_cleanly_when_lease_already_revoked() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_444));
        let peer_outbound: OutboundMap = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        let mut peer = Peer::new(UnreadableStream, Magic::BITCOIN);
        peer.state = PeerState::Ready;

        let result = run_message_loop(
            &mut peer,
            addr,
            &outbound_tx,
            &peer_outbound,
            &sinks(),
            None,
            None,
        );

        assert!(matches!(result, Ok(PeerTerminalOutcome::Other)));
    }

    #[test]
    fn message_loop_exits_after_external_lease_revocation() {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_445));
        let peer_outbound: OutboundMap = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (outbound_tx, _outbound_rx) = crossbeam_channel::unbounded();
        peer_outbound.write().insert(addr, outbound_tx.clone());
        let mut peer = Peer::new(
            RevokingStream {
                peer_outbound: Arc::clone(&peer_outbound),
                addr,
            },
            Magic::BITCOIN,
        );
        peer.state = PeerState::Ready;

        let result = run_message_loop(
            &mut peer,
            addr,
            &outbound_tx,
            &peer_outbound,
            &sinks(),
            None,
            None,
        );

        assert!(matches!(result, Ok(PeerTerminalOutcome::Other)));
        assert!(!peer_outbound.read().contains_key(&addr));
    }

    #[test]
    fn message_loop_classifies_local_writer_loss_as_other() -> Result<(), Box<dyn std::error::Error>>
    {
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 18_446));
        let peer_outbound: OutboundMap = Arc::new(RwLock::new(hashbrown::HashMap::new()));
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        drop(outbound_rx);
        peer_outbound.write().insert(addr, outbound_tx.clone());
        let mut wire = Vec::new();
        crate::wire::write_message(
            &mut wire,
            Magic::BITCOIN,
            &bitcoin::p2p::message::NetworkMessage::Ping(1),
        )?;
        let mut peer = Peer::new(Cursor::new(wire), Magic::BITCOIN);
        peer.state = PeerState::Ready;

        let result = run_message_loop(
            &mut peer,
            addr,
            &outbound_tx,
            &peer_outbound,
            &sinks(),
            None,
            None,
        );

        assert!(matches!(result, Ok(PeerTerminalOutcome::Other)));
        Ok(())
    }
}

#[cfg(test)]
mod sync_wake_tests {
    use super::wake_sync;

    #[test]
    fn sync_wake_is_bounded_and_nonblocking() {
        let (wake_tx, wake_rx) = crossbeam_channel::bounded(1);

        wake_sync(Some(&wake_tx));
        wake_sync(Some(&wake_tx));

        assert_eq!(wake_rx.try_iter().count(), 1);
    }

    #[test]
    fn missing_sync_wake_is_noop() {
        wake_sync(None);
    }
}

#[cfg(test)]
mod discovery_tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::time::{Duration, Instant};

    use bitcoin::p2p::{
        ServiceFlags,
        address::{AddrV2, AddrV2Message, Address},
        message::NetworkMessage,
    };

    use crate::discovery::{PeerDiscoveryEvent, PeerTerminalOutcome};

    use super::{begin_peer_discovery, send_announced_peers, send_terminal_event};

    fn public_addr(octets: [u8; 4]) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(octets), 8333))
    }

    #[test]
    fn discovery_lifecycle_is_ordered_and_bounded() -> Result<(), Box<dyn std::error::Error>> {
        let peer_addr = public_addr([8, 8, 8, 8]);
        let announced_addr = public_addr([8, 8, 4, 4]);
        let (discovery_tx, discovery_rx) = crossbeam_channel::bounded(3);
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        let started = Instant::now();

        begin_peer_discovery(
            Some(&discovery_tx),
            &outbound_tx,
            peer_addr,
            ServiceFlags::NETWORK,
        );
        let announced = NetworkMessage::Addr(vec![(
            1,
            Address::new(&announced_addr, ServiceFlags::WITNESS),
        )]);
        send_announced_peers(Some(&discovery_tx), &announced);
        send_terminal_event(
            Some(&discovery_tx),
            peer_addr,
            true,
            Some(started),
            &Ok(PeerTerminalOutcome::Clean),
            started + Duration::from_secs(3),
        );

        assert!(matches!(outbound_rx.try_recv()?, NetworkMessage::GetAddr));
        assert!(outbound_rx.try_recv().is_err(), "getaddr must be one-shot");
        let events: Vec<_> = discovery_rx.try_iter().collect();
        assert_eq!(
            events,
            vec![
                PeerDiscoveryEvent::HandshakeReady {
                    addr: peer_addr,
                    services: ServiceFlags::NETWORK,
                },
                PeerDiscoveryEvent::Announced(crate::discovery::DiscoveredPeer {
                    addr: announced_addr,
                    services: ServiceFlags::WITNESS,
                    seen_at: 1,
                }),
                PeerDiscoveryEvent::Terminal {
                    addr: peer_addr,
                    handshake_completed: true,
                    connected_for: Some(Duration::from_secs(3)),
                    outcome: PeerTerminalOutcome::Clean,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn addrv2_announcements_are_filtered() {
        let (discovery_tx, discovery_rx) = crossbeam_channel::bounded(2);
        let valid = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 8333,
        };
        let private = AddrV2Message {
            time: 1,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 8333,
        };

        send_announced_peers(
            Some(&discovery_tx),
            &NetworkMessage::AddrV2(vec![private, valid]),
        );

        let events: Vec<_> = discovery_rx.try_iter().collect();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], PeerDiscoveryEvent::Announced(_)));
    }

    #[test]
    fn discovery_backpressure_never_blocks_getaddr() -> Result<(), Box<dyn std::error::Error>> {
        let addr = public_addr([8, 8, 8, 8]);
        let (discovery_tx, discovery_rx) = crossbeam_channel::bounded(1);
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();
        discovery_tx.try_send(PeerDiscoveryEvent::HandshakeReady {
            addr,
            services: ServiceFlags::NETWORK,
        })?;

        begin_peer_discovery(
            Some(&discovery_tx),
            &outbound_tx,
            addr,
            ServiceFlags::NETWORK,
        );

        assert!(matches!(outbound_rx.try_recv()?, NetworkMessage::GetAddr));
        assert_eq!(discovery_rx.try_iter().count(), 1);
        Ok(())
    }

    #[test]
    fn missing_discovery_sink_preserves_message_stream() {
        let addr = public_addr([8, 8, 8, 8]);
        let (outbound_tx, outbound_rx) = crossbeam_channel::unbounded();

        begin_peer_discovery(None, &outbound_tx, addr, ServiceFlags::NETWORK);
        send_announced_peers(
            None,
            &NetworkMessage::Addr(vec![(1, Address::new(&addr, ServiceFlags::NETWORK))]),
        );

        assert!(outbound_rx.try_recv().is_err());
    }

    #[test]
    fn terminal_errors_have_stable_small_classifications() -> Result<(), Box<dyn std::error::Error>>
    {
        let addr = public_addr([8, 8, 8, 8]);
        let cases = [
            (
                crate::wire::PeerError::Io(std::io::ErrorKind::ConnectionReset.into()),
                PeerTerminalOutcome::Io,
            ),
            (
                crate::wire::PeerError::Protocol("bad message"),
                PeerTerminalOutcome::Protocol,
            ),
            (
                crate::wire::PeerError::BannedDestination(addr.ip()),
                PeerTerminalOutcome::Policy,
            ),
        ];

        for (error, expected) in cases {
            let (tx, rx) = crossbeam_channel::bounded(1);
            send_terminal_event(Some(&tx), addr, false, None, &Err(error), Instant::now());
            let PeerDiscoveryEvent::Terminal {
                handshake_completed,
                connected_for,
                outcome,
                ..
            } = rx.try_recv()?
            else {
                return Err(std::io::Error::other("expected terminal event").into());
            };
            assert!(!handshake_completed);
            assert_eq!(connected_for, None);
            assert_eq!(outcome, expected);
        }
        Ok(())
    }
}
