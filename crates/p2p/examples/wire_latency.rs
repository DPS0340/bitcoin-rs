//! Ping/pong round-trip latency harness for the `TCP_NODELAY` + writev PR.
//!
//! Measures end-to-end request/response latency (the pattern `ping/pong`,
//! `getdata`/`tx`, `getheaders`/`headers` follow) for four write-path
//! configurations:
//!
//! - `main`:            pre-PR behavior — 5x `write_all`, Nagle enabled.
//! - `legacy5_nodelay`: 5x `write_all` + `TCP_NODELAY`.
//! - `writev_nagle`:    single `write_vectored`, Nagle enabled.
//! - `pr`:              PR behavior — single `write_vectored` + `TCP_NODELAY`.
//!
//! Each configuration runs over loopback and over an emulated WAN link: a
//! userspace store-and-forward delay proxy that holds every ~MSS-sized chunk
//! for a fixed one-way delay (20 ms), so each in-flight segment and its ACK
//! pay WAN-like latency. This makes Nagle stalls (a small write held back
//! until the previous segment is `ACKed`) visible without root/`tc netem`.
//!
//! Output is one CSV row per scenario:
//! `scenario,link,iters,min_us,avg_us,p50_us,p95_us,max_us`
//! `scripts/run-pr2-wire-bench.sh` aggregates repeated runs.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::time::{Duration, Instant};

use bitcoin::p2p::Magic;
use bitcoin::p2p::message::NetworkMessage;
use sha2::{Digest, Sha256};

use bitcoin_rs_p2p::wire::{encode_payload, read_message, write_message};

const MAGIC: Magic = Magic::REGTEST;
const WAN_DELAY: Duration = Duration::from_millis(20);
const LOOPBACK_ITERS: usize = 300;
const WAN_ITERS: usize = 40;

/// Pre-PR writer: one `write_all` per header field plus the payload (5 writes).
fn legacy_write_message(stream: &mut TcpStream, message: &NetworkMessage) -> std::io::Result<()> {
    let payload = encode_payload(message).map_err(std::io::Error::other)?;
    let hash = Sha256::digest(Sha256::digest(&payload));
    let command = message.command();
    let name: &str = command.as_ref();
    let mut raw_command = [0u8; 12];
    raw_command[..name.len()].copy_from_slice(name.as_bytes());

    stream.write_all(&MAGIC.to_bytes())?;
    stream.write_all(&raw_command)?;
    let len = u32::try_from(payload.len()).map_err(std::io::Error::other)?;
    stream.write_all(&len.to_le_bytes())?;
    stream.write_all(&hash[..4])?;
    stream.write_all(&payload)?;
    stream.flush()
}

#[derive(Clone, Copy)]
enum Config {
    /// `main`: 5x `write_all`, Nagle on.
    Main,
    /// 5x `write_all` + `TCP_NODELAY`.
    Legacy5Nodelay,
    /// `write_vectored`, Nagle on.
    WritevNagle,
    /// PR: `write_vectored` + `TCP_NODELAY`.
    Pr,
}

impl Config {
    const ALL: [Self; 4] = [
        Self::Main,
        Self::Legacy5Nodelay,
        Self::WritevNagle,
        Self::Pr,
    ];

    fn label(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Legacy5Nodelay => "legacy5_nodelay",
            Self::WritevNagle => "writev_nagle",
            Self::Pr => "pr",
        }
    }

    fn nodelay(self) -> bool {
        matches!(self, Self::Legacy5Nodelay | Self::Pr)
    }

    fn send(self, stream: &mut TcpStream, message: &NetworkMessage) -> std::io::Result<()> {
        match self {
            Self::Main | Self::Legacy5Nodelay => legacy_write_message(stream, message),
            Self::WritevNagle | Self::Pr => {
                write_message(stream, MAGIC, message).map_err(std::io::Error::other)
            }
        }
    }
}

/// Accept connections and answer every `Ping` with a matching `Pong`, using
/// the same write-path configuration as the client under test.
fn spawn_responder(config: Config) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind responder");
    let addr = listener.local_addr().expect("responder addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let mut stream = conn.expect("accept");
            stream
                .set_nodelay(config.nodelay())
                .expect("responder nodelay");
            std::thread::spawn(move || {
                loop {
                    match read_message(&mut stream, MAGIC) {
                        Ok((NetworkMessage::Ping(nonce), _)) => {
                            if config
                                .send(&mut stream, &NetworkMessage::Pong(nonce))
                                .is_err()
                            {
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// Spawn a store-and-forward relay: every chunk read from `from` is held for
/// `delay` before being written to `to`, emulating one-way WAN latency (and,
/// because ACKs traverse the same relay, WAN-like RTT for Nagle purposes).
fn spawn_relay(from: TcpStream, mut to: TcpStream, delay: Duration) {
    std::thread::spawn(move || {
        let mut from = from;
        let mut buf = [0u8; 1500];
        loop {
            match from.read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    std::thread::sleep(delay);
                    if to.write_all(&buf[..n]).is_err() {
                        return;
                    }
                }
            }
        }
    });
}

/// Listen on loopback and relay each accepted connection to `target` with
/// `delay` applied per direction. Returns the proxy address clients dial.
fn spawn_delay_proxy(target: SocketAddr, delay: Duration) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind proxy");
    let addr = listener.local_addr().expect("proxy addr");
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            let inbound = conn.expect("proxy accept");
            let outbound = TcpStream::connect(target).expect("proxy connect");
            let inbound_reverse = inbound.try_clone().expect("clone inbound");
            let outbound_reverse = outbound.try_clone().expect("clone outbound");
            spawn_relay(inbound, outbound, delay);
            spawn_relay(outbound_reverse, inbound_reverse, delay);
        }
    });
    addr
}

#[allow(clippy::as_conversions)] // f64 percentile indexing; no fallible f64<->usize path exists
fn percentile(sorted: &[f64], p: f64) -> f64 {
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

#[allow(clippy::as_conversions)] // usize sample count -> f64; no fallible path exists
fn mean(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn run_scenario(config: Config, link: &str, dial: SocketAddr, iters: usize) {
    let mut stream = TcpStream::connect(dial).expect("connect");
    stream.set_nodelay(config.nodelay()).expect("set nodelay");

    let ping = NetworkMessage::Ping(42);
    let warmup = (iters / 10).max(2);
    for _ in 0..warmup {
        config.send(&mut stream, &ping).expect("warmup send");
        read_message(&mut stream, MAGIC).expect("warmup recv");
    }

    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        config.send(&mut stream, &ping).expect("send ping");
        let (message, _) = read_message(&mut stream, MAGIC).expect("recv pong");
        debug_assert!(matches!(message, NetworkMessage::Pong(42)));
        samples.push(start.elapsed().as_secs_f64() * 1e6);
    }

    samples.sort_by(f64::total_cmp);
    let min = samples[0];
    let max = samples[samples.len() - 1];
    let avg = mean(&samples);
    let p50 = percentile(&samples, 0.50);
    let p95 = percentile(&samples, 0.95);
    println!(
        "{},{},{},{:.1},{:.1},{:.1},{:.1},{:.1}",
        config.label(),
        link,
        iters,
        min,
        avg,
        p50,
        p95,
        max
    );
}

fn main() {
    println!("scenario,link,iters,min_us,avg_us,p50_us,p95_us,max_us");
    for config in Config::ALL {
        let responder = spawn_responder(config);
        run_scenario(config, "loopback", responder, LOOPBACK_ITERS);
        let proxy = spawn_delay_proxy(responder, WAN_DELAY);
        run_scenario(config, "wan_20ms", proxy, WAN_ITERS);
    }
}
