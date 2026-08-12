use core::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use arc_swap::ArcSwapOption;
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_pruning::policy::CORE_REORG_SAFETY_MARGIN;
use bitcoin_rs_rpc::PruneService;
use crossbeam_channel::{Receiver, never, select, tick};

use crate::shutdown;

const STATS_INTERVAL: u64 = 1024;

const MEMPOOL_TICK: Duration = Duration::from_secs(1);
const METRICS_TICK: Duration = Duration::from_secs(10);
const SYNC_TICK: Duration = Duration::from_secs(1);

/// Central v1 event loop for process-level tick coordination.
///
/// The p2p, JSON-RPC, and Electrum subsystems still own their connection
/// channels and worker threads. This loop coordinates the shared tick-style
/// work that must stop cleanly with the process.
pub struct EventLoop {
    shutdown_signal: Receiver<()>,
    mempool_tick: Receiver<Instant>,
    metrics_scrape: Receiver<Instant>,
    sync_tick: Receiver<Instant>,
    sync_wake: Receiver<()>,
    sync: Arc<crate::BlockSync>,
    auto_prune: Option<AutoPrune>,
}

struct AutoPrune {
    service: Arc<dyn PruneService>,
    applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
}

impl EventLoop {
    /// Builds an event loop from an already-bridged shutdown signal receiver.
    #[must_use]
    pub fn new(shutdown_signal: Receiver<()>, sync: Arc<crate::BlockSync>) -> Self {
        Self::with_sync_wake(shutdown_signal, sync, never())
    }

    /// Builds an event loop that can also wake sync work from inbound P2P data.
    #[must_use]
    pub fn with_sync_wake(
        shutdown_signal: Receiver<()>,
        sync: Arc<crate::BlockSync>,
        sync_wake: Receiver<()>,
    ) -> Self {
        Self {
            shutdown_signal,
            mempool_tick: tick(MEMPOOL_TICK),
            metrics_scrape: tick(METRICS_TICK),
            sync_tick: tick(SYNC_TICK),
            sync_wake,
            sync,
            auto_prune: None,
        }
    }

    /// Enables automatic pruning against the best fully-applied block.
    #[must_use]
    pub fn with_auto_pruning(
        mut self,
        service: Arc<dyn PruneService>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    ) -> Self {
        self.auto_prune = Some(AutoPrune {
            service,
            applied_tip,
        });
        self
    }

    /// Runs the event loop until a shutdown notification arrives.
    pub fn spin(self, shutdown: &AtomicBool) -> Result<()> {
        shutdown::mark_draining();
        let mut iterations: u64 = 0;
        let mut mempool_ticks: u64 = 0;
        let mut metrics_scrapes: u64 = 0;
        let mut sync_ticks: u64 = 0;
        while !shutdown.load(Ordering::Acquire) {
            iterations += 1;
            if iterations.is_multiple_of(STATS_INTERVAL) {
                tracing::debug!(
                    iterations,
                    mempool_ticks,
                    metrics_scrapes,
                    sync_ticks,
                    "event loop heartbeat"
                );
            }
            select! {
                recv(self.shutdown_signal) -> _ => {
                    shutdown.store(true, Ordering::Release);
                    metrics::gauge!("node.shutdown.requested").set(1.0);
                    break;
                }
                recv(self.mempool_tick) -> ticked => {
                    if ticked.is_ok() {
                        mempool_ticks += 1;
                        Self::on_mempool_tick();
                    }
                }
                recv(self.metrics_scrape) -> ticked => {
                    if ticked.is_ok() {
                        metrics_scrapes += 1;
                        self.on_metrics_scrape();
                    }
                }
                recv(self.sync_tick) -> ticked => {
                    if ticked.is_ok() {
                        sync_ticks += 1;
                        self.on_sync_tick();
                    }
                }
                recv(self.sync_wake) -> woke => {
                    if woke.is_ok() {
                        sync_ticks += 1;
                        metrics::counter!("node.event_loop.sync_wakes").increment(1);
                        self.on_sync_tick();
                    }
                }
            }
        }
        shutdown::notify_drained();
        Ok(())
    }

    fn on_mempool_tick() {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.mempool_ticks").increment(1);
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("mempool maintenance tick");
    }

    fn on_metrics_scrape(&self) {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.metrics_scrapes").increment(1);
        self.on_auto_prune();
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
        tracing::trace!("metrics scrape tick");
    }

    fn on_auto_prune(&self) {
        let Some(auto_prune) = &self.auto_prune else {
            return;
        };
        let Some(tip) = auto_prune.applied_tip.load_full() else {
            return;
        };
        let Some(requested_height) =
            automatic_prune_height(tip.height, auto_prune.service.status().pruneheight)
        else {
            return;
        };

        match auto_prune.service.prune_to_height(requested_height) {
            Ok(result) => tracing::info!(
                tip_height = tip.height,
                pruneheight = result.pruneheight,
                block_rows_removed = result.block_rows_removed,
                undo_rows_removed = result.undo_rows_removed,
                bytes_freed = result.bytes_freed,
                "automatic pruning pass completed"
            ),
            Err(error) => {
                tracing::warn!(%error, tip_height = tip.height, "automatic pruning pass failed")
            }
        }
    }

    fn on_sync_tick(&self) {
        let started = quanta::Instant::now();
        metrics::counter!("node.event_loop.sync_ticks").increment(1);
        self.sync.tick();
        metrics::histogram!("node.event_loop.tick_seconds").record(started.elapsed().as_secs_f64());
    }
}

fn automatic_prune_height(applied_height: u32, pruneheight: Option<u32>) -> Option<u32> {
    let requested_height = applied_height.saturating_sub(CORE_REORG_SAFETY_MARGIN);
    (requested_height > 0 && pruneheight.is_none_or(|height| height < requested_height))
        .then_some(requested_height)
}

#[cfg(test)]
mod tests {
    use super::automatic_prune_height;

    #[test]
    fn automatic_pruning_keeps_the_reorg_safety_window() {
        assert_eq!(automatic_prune_height(288, None), None);
        assert_eq!(automatic_prune_height(289, None), Some(1));
        assert_eq!(automatic_prune_height(1_000, Some(711)), Some(712));
        assert_eq!(automatic_prune_height(1_000, Some(712)), None);
    }
}
