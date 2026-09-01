use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::Result;
use parking_lot::{Condvar, Mutex, const_mutex};

static DRAINED: Mutex<bool> = const_mutex(true);
static DRAINED_CVAR: Condvar = Condvar::new();

/// Broadcast state for a shutdown request.
///
/// Split from the process-wide static as a type so the request/wake contract
/// is testable on isolated instances; the free functions delegate to the one
/// process-wide instance.
struct ShutdownBroadcast {
    requested: Mutex<bool>,
    wake: Condvar,
}
impl ShutdownBroadcast {
    const fn new() -> Self {
        Self {
            requested: const_mutex(false),
            wake: Condvar::new(),
        }
    }

    /// Marks the first request and wakes every parked waiter exactly once.
    fn request(&self) -> bool {
        let mut requested = self.requested.lock();
        if *requested {
            return false;
        }
        *requested = true;
        self.wake.notify_all();
        true
    }

    /// Stores `flag` with Release ordering, then publishes the first broadcast.
    fn trigger(&self, flag: &AtomicBool) -> bool {
        if flag
            .compare_exchange(false, true, Ordering::Release, Ordering::Acquire)
            .is_err()
        {
            return false;
        }
        self.request()
    }

    fn requested(&self) -> bool {
        *self.requested.lock()
    }

    /// Parks until the request arrives or `deadline` elapses.
    ///
    /// Returns whether shutdown is requested; a request that raced ahead of
    /// the park is observed through the flag, so no wake can be lost.
    fn wait_for(&self, deadline: Duration) -> bool {
        let mut requested = self.requested.lock();
        if *requested {
            return true;
        }
        let _timed_out = self.wake.wait_for(&mut requested, deadline);
        *requested
    }
}

static SHUTDOWN: ShutdownBroadcast = ShutdownBroadcast::new();

/// Marks subsystem draining as active.
pub(crate) fn mark_draining() {
    *DRAINED.lock() = false;
}

/// Notifies waiters that all v1 tick subsystems have drained.
pub(crate) fn notify_drained() {
    *DRAINED.lock() = true;
    DRAINED_CVAR.notify_all();
}

/// Waits for subsystem drain notification or the shutdown deadline.
pub fn drain_and_shutdown(deadline: Duration) -> Result<()> {
    let mut drained = DRAINED.lock();
    if !*drained {
        let _timeout = DRAINED_CVAR.wait_for(&mut drained, deadline);
    }
    Ok(())
}

/// Sets `flag` before publishing the process-wide shutdown broadcast.
///
/// The store uses `Release` so any waiter that wakes from the broadcast can
/// observe the flag with `Acquire`. Repeated calls stay idempotent: the flag
/// remains true and the broadcast is published again without a second state
/// transition.
pub fn trigger_shutdown(flag: &AtomicBool) -> bool {
    SHUTDOWN.trigger(flag)
}

/// Marks shutdown as requested and wakes every [`wait_for_shutdown`] waiter.
///
/// Idempotent. Long-poll style waiters block in [`wait_for_shutdown`] and must
/// observe a shutdown decision the moment it is made — not at their next
/// timeout slice — which is the wake Core's shutdown sequence gives its own
/// long-lived waiters. Production signal and event-loop paths call
/// [`trigger_shutdown`] so the node-owned flag is visible before this wake.
pub fn request_shutdown() -> bool {
    SHUTDOWN.request()
}

/// Returns whether shutdown has been requested.
#[must_use]
pub fn shutdown_requested() -> bool {
    SHUTDOWN.requested()
}

/// Blocks until shutdown is requested or `deadline` elapses.
///
/// Returns `true` when shutdown is (or became) requested; `false` only when
/// the deadline elapsed without a request.
pub fn wait_for_shutdown(deadline: Duration) -> bool {
    SHUTDOWN.wait_for(deadline)
}
