//! Shared wire helpers the e2e crate does not export: a strict deadline
//! check and the soft/hard receive-error classification the pump loops
//! use to decide whether a failed read is fatal.

use std::time::{Duration, Instant};

use bitcoin_rs_e2e::Error;

/// The remaining slice of `deadline`, or an error naming `message` once the
/// deadline has already passed.
pub(crate) fn remaining(deadline: Instant, message: &str) -> Result<Option<Duration>, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| *d >= Duration::from_micros(1))
        .map(Some)
        .ok_or_else(|| Error::Protocol(format!("{message} ran past the deadline")))
}

/// True when a frame-read failure is just "no data yet" (read timeout or
/// deadline bookkeeping) rather than a dropped connection.
pub(crate) fn is_soft_recv_error(error: &Error) -> bool {
    match error {
        Error::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ),
        Error::Protocol(detail) => detail.contains("deadline"),
        _ => false,
    }
}
