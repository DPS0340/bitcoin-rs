use std::thread::{self, JoinHandle};

use anyhow::Result;
use crossbeam_channel::Sender;
#[cfg(not(windows))]
use signal_hook::{
    consts::signal::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// Installs SIGINT/SIGTERM handling on a dedicated forwarding thread.
#[cfg(not(windows))]
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
    let mut signals = Signals::new([SIGTERM, SIGINT])?;
    let handle = thread::spawn(move || {
        for _signal in signals.forever() {
            if shutdown_tx.try_send(()).is_err() {
                break;
            }
        }
    });
    Ok(handle)
}

/// Windows builds do not expose `signal-hook`'s Unix signal iterator.
#[cfg(windows)]
pub fn install_shutdown_handler(shutdown_tx: Sender<()>) -> Result<JoinHandle<()>> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::Duration;

    use signal_hook::{
        consts::signal::{SIGINT, SIGTERM},
        flag,
    };

    let signaled = Arc::new(AtomicBool::new(false));
    flag::register(SIGINT, Arc::clone(&signaled))?;
    flag::register(SIGTERM, Arc::clone(&signaled))?;
    Ok(thread::spawn(move || {
        while !signaled.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(100));
        }
        let _ = shutdown_tx.try_send(());
    }))
}
