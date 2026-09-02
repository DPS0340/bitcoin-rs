//! Top-level orchestration: wire subsystems, spin the event loop, drain.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use crossbeam_channel::{Receiver, bounded};

use crate::config::Config;
use crate::event_loop::EventLoop;
use crate::state::NodeState;
use crate::{crash_recovery, logging, shutdown};

const DRAIN_DEADLINE: Duration = Duration::from_secs(5);
const RPC_MAX_CONNECTIONS: usize = 128;
const RPC_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

type P2pChainQuery = Arc<dyn bitcoin_rs_p2p::ChainQuery>;

#[derive(Clone)]
struct RpcChainControl {
    handles: crate::apply::ApplyHandles,
}

impl bitcoin_rs_rpc::context::ChainControl for RpcChainControl {
    fn invalidate_block(
        &self,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> core::result::Result<(), bitcoin_rs_rpc::context::ChainControlError> {
        crate::reorg::invalidate_block(&self.handles, hash).map_err(|error| match error {
            crate::reorg::ReorgError::UnknownBlock(_) => {
                bitcoin_rs_rpc::context::ChainControlError::UnknownBlock
            }
            crate::reorg::ReorgError::CannotInvalidateGenesis => {
                bitcoin_rs_rpc::context::ChainControlError::Genesis
            }
            other => bitcoin_rs_rpc::context::ChainControlError::Failed(other.to_string()),
        })
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

/// Boots the node from a resolved [`Config`] and runs until shutdown.
///
/// Flow:
/// 1. Install JSON tracing on stderr.
/// 2. Open / create the node data directory and resolve state.
/// 3. Resume an authenticated chainstate checkpoint, or run crash recovery on a cold startup.
/// 4. Acquire a shutdown signal ??either the in-process receiver wired via
///    [`Config::with_shutdown_receiver`] (tests) or a fresh SIGINT/SIGTERM
///    handler (production).
/// 5. Spin the event loop until shutdown is requested.
/// 6. Drain subsystems within [`DRAIN_DEADLINE`].
/// 7. Publish one immutable clean-shutdown chainstate checkpoint.
#[allow(clippy::too_many_lines)]
pub fn run(mut config: Config) -> Result<()> {
    logging::install_tracing(&config.log_level)?;
    cap_global_thread_pool();

    let injected_shutdown = config.shutdown_signal.take();
    let state = NodeState::open(config)?;
    if state.resume_source() == crate::state::ResumeSource::Cold {
        crash_recovery::recover_if_needed(&state)?;
    }

    tracing::info!(
        network = ?state.config().network,
        data_dir = %state.data_dir().display(),
        storage_backend = %state.config().storage_backend,
        "bitcoin-rs node booting"
    );

    crate::metrics::start_metrics(state.config().metrics_bind, state.shutdown())?;

    let shutdown = state.shutdown();
    let shutdown_rx: Receiver<()> = if let Some(rx) = injected_shutdown {
        rx
    } else {
        let (tx, rx) = bounded(1);
        // Forwards process signals into our channel; the JoinHandle outlives `run`.
        let _signal_thread =
            crate::signal::install_shutdown_handler(std::sync::Arc::clone(&shutdown), tx)?;
        rx
    };
    let p2p = state.p2p();
    let block_body_source = state.block_body_source();
    let p2p_chain_query: P2pChainQuery = Arc::new(
        crate::NodeP2pChainQuery::new(state.block_tree())
            .with_block_body_source(Arc::clone(&block_body_source)),
    );
    let (sync_wake_tx, sync_wake_rx) = bounded(1);
    let sync = state.sync();
    let peer_ready = sync.peer_ready_handle();
    let loop_handle = EventLoop::with_sync_wake(shutdown_rx, sync, sync_wake_rx);
    let mining_control: Arc<dyn bitcoin_rs_rpc::context::MiningControl> =
        Arc::new(crate::MiningCoordinator::new(
            state.config().network,
            state.applied_tip(),
            state.block_tree(),
            state.mempool(),
            state.apply_handles(),
            bitcoin::ScriptBuf::new(),
            Arc::clone(&shutdown),
        ));
    let rpc_auth = Arc::new(build_rpc_auth(&state.config().rpc_auth)?);
    let mut rpc_context =
        bitcoin_rs_rpc::context::Context::from_handles(bitcoin_rs_rpc::context::ContextHandles {
            chain_tip: state.chain_tip(),
            applied_tip: state.applied_tip(),
            mempool: state.mempool(),
            blocks: state.blocks(),
            transactions: state.transactions(),
            utxo: state.utxo(),
            coin_stats: state.coin_stats(),
            network: state.network(),
            p2p: Arc::clone(&p2p),
            block_tree: state.block_tree(),
            chain_network: state.config().network,
            tx_index: state.tx_index_query(),
            script_index: state.script_index_query(),
        })
        .with_esplora_tx_index(state.esplora_tx_index_query());
    rpc_context = rpc_context.with_block_body_source(block_body_source);
    rpc_context = rpc_context.with_chain_tx_count(state.chain_tx_count_handle());
    rpc_context =
        rpc_context.with_chain_transition(Arc::clone(&state.apply_handles().chain_transition));
    if let Some(prune_service) = state.prune_service() {
        rpc_context = rpc_context.with_prune_service(prune_service);
    }
    rpc_context = rpc_context.with_chain_control(Arc::new(RpcChainControl {
        handles: state.apply_handles(),
    }));
    rpc_context = rpc_context.with_zmq_notifications(state.active_zmq_notifications());
    rpc_context = rpc_context.with_mining_control(Arc::clone(&mining_control));
    rpc_context = rpc_context.with_debug_log_path(state.data_dir().join("debug.log"));
    let rpc_handler = Arc::new(bitcoin_rs_rpc::Handler::new(Arc::new(rpc_context)));
    let rpc_server = bitcoin_rs_rpc::RpcServer::bind(
        state.config().rpc_bind,
        rpc_auth,
        rpc_handler,
        RPC_MAX_CONNECTIONS,
        RPC_IDLE_TIMEOUT,
        state.config().rest,
    )?;
    let rpc_local_addr = rpc_server.local_addr()?;
    tracing::info!(addr = %rpc_local_addr, "rpc listener bound");
    let rpc_shutdown = Arc::clone(&shutdown);
    let rpc_thread = std::thread::Builder::new()
        .name("bitcoin-rs-rpc".into())
        .spawn(move || rpc_server.serve_with_shutdown(rpc_shutdown))?;
    p2p.start(Some(&p2p_chain_query), Some(&sync_wake_tx), &peer_ready)?;
    loop_handle.spin(&shutdown)?;
    match rpc_thread.join() {
        Ok(Ok(())) => tracing::info!("rpc listener exited cleanly"),
        Ok(Err(error)) => tracing::warn!(%error, "rpc listener exited with i/o error"),
        Err(_) => tracing::error!("rpc listener panicked"),
    }
    p2p.shutdown();
    p2p.join();
    shutdown::drain_and_shutdown(DRAIN_DEADLINE)?;
    // Defer the checkpoint result so a publication failure cannot bypass the
    // shutdown drain below.
    let clean_checkpoint = state.write_clean_checkpoint();
    match &clean_checkpoint {
        Ok(crate::checkpoint::CheckpointWrite::SkippedNoAppliedTip) => {
            tracing::info!("no applied tip; clean checkpoint publication skipped");
        }
        Ok(crate::checkpoint::CheckpointWrite::Published { generation }) => {
            tracing::info!(generation, "published clean chainstate checkpoint");
        }
        Err(error) => {
            tracing::error!(%error, "clean checkpoint publication failed");
        }
    }
    // A checkpoint failure means the node did not exit cleanly; propagate it
    // after all P2P workers and shutdown-owned resources have been drained.
    clean_checkpoint?;
    tracing::info!("bitcoin-rs node exited cleanly");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_shutdown_publishes_checkpoint_and_returns_success() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = Config::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node-success");
        config.rpc_bind = "127.0.0.1:0".parse().expect("valid loopback address");
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = false;
        config.p2p_listen.clear();
        config.metrics_bind = None;

        let state = crate::state::NodeState::open(config.clone())?;
        state.apply_block(&bitcoin::blockdata::constants::genesis_block(
            bitcoin::Network::Regtest,
        ))?;
        state.write_clean_checkpoint()?;
        drop(state);
        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous_current = std::fs::read(&current_path)?;

        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;
        let reopen_config = config.clone();
        config = config.with_shutdown_receiver(shutdown_rx);
        run(config)?;
        assert_ne!(std::fs::read(&current_path)?, previous_current);

        let resumed = crate::state::NodeState::open(reopen_config)?;
        assert_eq!(
            resumed.resume_source(),
            crate::state::ResumeSource::Checkpoint
        );
        Ok(())
    }

    #[test]
    fn shutdown_checkpoint_error_is_returned_after_p2p_shutdown() -> anyhow::Result<()> {
        let temp = tempfile::tempdir()?;
        let mut config = Config::default_for_network(crate::Network::Regtest);
        config.data_dir = temp.path().join("node");
        config.rpc_bind = "127.0.0.1:0".parse().expect("valid loopback address");
        config.rpc_auth = crate::Auth::basic("user", "password");
        config.script_index = false;
        config.p2p_listen.clear();
        config.metrics_bind = None;
        config.connect = vec!["127.0.0.1:1".to_owned()];

        let state = crate::state::NodeState::open(config.clone())?;
        state.apply_block(&bitcoin::blockdata::constants::genesis_block(
            bitcoin::Network::Regtest,
        ))?;
        state.write_clean_checkpoint()?;
        drop(state);

        let current_path = config
            .data_dir
            .join("chainstate-checkpoints")
            .join("CURRENT");
        let previous_current = std::fs::read(&current_path)?;
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded(1);
        shutdown_tx.send(())?;
        config = config.with_shutdown_receiver(shutdown_rx);
        crate::checkpoint::inject_next_checkpoint_failpoint(
            crate::checkpoint::CheckpointFailpoint::ManifestWrite,
        );

        assert!(run(config).is_err());
        assert_eq!(std::fs::read(current_path)?, previous_current);
        Ok(())
    }
}
/// Threads for the process-wide rayon pool.
///
/// rayon defaults the global pool to one worker per core. That pool only runs
/// the short coarse jobs in apply ??block txid hashing and shard commits ??/// while script verification holds its own pool of up to
/// `MAX_SCRIPT_VERIFY_THREADS` and the node holds its own I/O threads besides.
/// On a many-core host the process therefore oversubscribes by a wide margin
/// and the global workers spend their time spinning for work that is not there.
///
/// Measured on a loopback P2P sync to height `150_000`, `taskset -c 0-31`, three
/// interleaved pairs:
///
/// | global pool | wall | CPU |
/// | one per core (32) | 75.6s | 314.4s |
/// | 4 | 64.4s | 162.4s |
///
/// Both axes improve together, so this is not a wall-for-CPU trade. The sweep
/// is flat from 2 to 8 and climbs above it. A full-verification replay of the
/// same window is insensitive at every width (84-88s) because script
/// verification dominates there and runs in its own pool, so this cap costs
/// that path nothing.
const GLOBAL_RAYON_THREADS: usize = 4;

/// Caps the global rayon pool before any parallel iterator runs.
///
/// Idempotent by necessity: `build_global` fails if a pool already exists, and
/// that is not an error worth aborting a node boot over ??it means something
/// else already sized the pool, and the default is merely slower, not wrong.
fn cap_global_thread_pool() {
    let available = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    let threads = available.min(GLOBAL_RAYON_THREADS);
    if let Err(error) = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
    {
        tracing::debug!(%error, "global rayon pool already configured, keeping it");
    }
}
