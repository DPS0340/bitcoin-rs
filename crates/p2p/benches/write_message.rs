//! Benchmark for `wire::write_message` over a loopback `TcpStream`.
//!
//! Compares four write-path configurations so the two changes in the PR can
//! be attributed separately:
//!
//! - `main`:            pre-PR behavior — 5x `write_all` (magic, command,
//!                      length, checksum, payload), Nagle enabled.
//! - `legacy5_nodelay`: 5x `write_all` + `TCP_NODELAY`.
//! - `writev_nagle`:    single `write_vectored`, Nagle enabled.
//! - `pr`:              PR behavior — single `write_vectored` + `TCP_NODELAY`.
//!
//! Each configuration is measured for a small `ping` and a genesis-sized
//! `block` payload. Loopback has ~0 RTT, so this bench captures syscall and
//! serialization overhead; Nagle/delayed-ACK latency effects are covered by
//! `examples/wire_latency.rs`.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::NetworkMessage;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use sha2::{Digest, Sha256};

use bitcoin_rs_p2p::wire::{encode_payload, write_message};

const MAGIC: Magic = Magic::BITCOIN;

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

/// Open a connected loopback pair and drain the read side on a thread so the
/// writer never blocks on a full socket buffer.
fn connected_pair(nodelay: bool) -> (TcpStream, JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let writer = TcpStream::connect(addr).expect("connect loopback");
    writer.set_nodelay(nodelay).expect("set nodelay");
    let (mut reader, _) = listener.accept().expect("accept loopback");
    let drain = std::thread::spawn(move || {
        let mut buf = [0u8; 64 * 1024];
        while reader.read(&mut buf).is_ok_and(|n| n > 0) {}
    });
    (writer, drain)
}

fn bench_write_message(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_message");

    let ping = NetworkMessage::Ping(42);
    let block = NetworkMessage::Block(genesis_block(Network::Regtest));

    for (payload_label, message) in [("ping_8B", &ping), ("block_285B", &block)] {
        for config in Config::ALL {
            group.bench_function(BenchmarkId::new(payload_label, config.label()), |b| {
                let (mut stream, _drain) = connected_pair(config.nodelay());
                b.iter(|| config.send(&mut stream, message).expect("write message"));
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_write_message);
criterion_main!(benches);
