//! Raw Bitcoin P2P frame I/O shared by the process-level peer harnesses.
//!
//! The deadline bounds only the wait for a frame's first byte: once a frame
//! is partially consumed it must run to completion or the wire stream
//! desynchronizes for every later read. A reached deadline is reported as
//! `message`; callers classify it with [`is_soft_recv_error`] and keep their
//! own deadline bookkeeping to decide the outcome.

use std::io::Read as _;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin_rs_e2e::Error;

/// The protocol's fixed frame header length.
pub(crate) const HEADER_BYTES: usize = 24;
/// Frames are read with the protocol payload bound, not the harness's 4 MiB
/// cap: a full `block` reply for a heavier block is legal and must not be
/// mistaken for a transport failure.
pub(crate) const MAX_PAYLOAD_BYTES: usize = 32 * 1024 * 1024;

/// Time left before `deadline` as a socket timeout; a deadline already
/// reached is the named error.
pub(crate) fn remaining(
    deadline: Instant,
    message: &'static str,
) -> Result<Option<Duration>, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| *time >= Duration::from_micros(1))
        .map(Some)
        .ok_or_else(|| Error::Protocol(message.to_owned()))
}

/// Reads one framed P2P message body off `stream`, deadline-bounded on the
/// first byte only.
pub(crate) fn read_frame(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Vec<u8>, Error> {
    fn read_exact(
        stream: &mut TcpStream,
        mut bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), Error> {
        let total = bytes.len();
        while !bytes.is_empty() {
            let wait = if bytes.len() == total {
                remaining(deadline, "read deadline reached")?
            } else {
                Some(Duration::from_secs(10))
            };
            stream.set_read_timeout(wait)?;
            let count = stream.read(bytes)?;
            if count == 0 {
                return Err(Error::Protocol("truncated P2P frame".to_owned()));
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }
    let mut header = [0; HEADER_BYTES];
    read_exact(stream, &mut header, deadline)?;
    let raw = u32::from_le_bytes(
        header[16..20]
            .try_into()
            .map_err(|_| Error::Protocol("truncated P2P header".to_owned()))?,
    );
    let length = usize::try_from(raw).map_err(|error| Error::Protocol(error.to_string()))?;
    if length > MAX_PAYLOAD_BYTES {
        return Err(Error::Protocol("P2P payload byte limit".to_owned()));
    }
    let mut frame = header.to_vec();
    frame.resize(HEADER_BYTES + length, 0);
    read_exact(stream, &mut frame[HEADER_BYTES..], deadline)?;
    Ok(frame)
}

/// Decodes one regtest frame into its payload.
pub(crate) fn decode_frame(frame: &[u8]) -> Result<NetworkMessage, Error> {
    let envelope: RawNetworkMessage = bitcoin::consensus::deserialize(frame)
        .map_err(|error| Error::Protocol(format!("invalid P2P envelope: {error}")))?;
    if *envelope.magic() != Magic::REGTEST {
        return Err(Error::Protocol("P2P network mismatch".to_owned()));
    }
    Ok(envelope.into_payload())
}

/// Whether a recv failure is transient (timeout-class) rather than a dead
/// wire.
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
