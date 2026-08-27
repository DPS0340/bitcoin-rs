//! Benchmark for `wire::write_message` over a loopback TcpStream.
//!
//! Measures the end-to-end cost of emitting one p2p message onto a real
//! socket (small `ping` vs a genesis-sized `block` payload) so transport
//! changes such as write coalescing and TCP_NODELAY can be compared.
//!
//! Note: loopback has ~0 RTT, so Nagle/delayed-ACK latency effects from
//! wide-area links are not visible here; this bench primarily captures
//! syscall and serialization overhead.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::thread::JoinHandle;

use bitcoin::Network;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::NetworkMessage;
use criterion::{Criterion, criterion_group, criterion_main};

use bitcoin_rs_p2p::wire::write_message;

/// Open a connected loopback pair and drain the read side on a thread so the
/// writer never blocks on a full socket buffer.
fn connected_pair() -> (TcpStream, JoinHandle<()>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind loopback");
    let addr = listener.local_addr().expect("listener addr");
    let writer = TcpStream::connect(addr).expect("connect loopback");
    writer.set_nodelay(true).expect("set nodelay");
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

    group.bench_function("ping_8B_payload", |b| {
        let (mut stream, _drain) = connected_pair();
        b.iter(|| write_message(&mut stream, Magic::BITCOIN, &ping).expect("write ping"));
    });

    group.bench_function("block_285B_payload", |b| {
        let (mut stream, _drain) = connected_pair();
        b.iter(|| write_message(&mut stream, Magic::BITCOIN, &block).expect("write block"));
    });

    group.finish();
}

criterion_group!(benches, bench_write_message);
criterion_main!(benches);
