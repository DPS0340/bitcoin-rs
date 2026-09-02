//! P2P listener shutdown integration coverage.
use bitcoin::p2p::Magic;
use bitcoin_rs_p2p::PeerLifecycle;
use bitcoin_rs_p2p::listener::serve_with_shutdown_with_lifecycle_and_chain_and_sync_wake;
use std::error::Error;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

#[test]
fn serve_with_shutdown_exits_when_flag_set() -> Result<(), Box<dyn Error>> {
    let bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let helper = TcpListener::bind(bind_addr)?;
    let addr = helper.local_addr()?;
    drop(helper);

    let _unused_stream: Option<TcpStream> = None;
    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = Arc::clone(&shutdown);
    let network_active = Arc::new(AtomicBool::new(true));
    let (tx, rx) = mpsc::channel();
    let registry = Arc::new(parking_lot::RwLock::new(Vec::new()));
    let outbound = Arc::new(parking_lot::RwLock::new(hashbrown::HashMap::new()));
    let lifecycle = Arc::new(PeerLifecycle::new(
        Arc::clone(&registry),
        Arc::clone(&outbound),
    ));
    let (inbound_headers_tx, _inbound_headers_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundHeaders>();
    let (inbound_blocks_tx, _inbound_blocks_rx) =
        crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundBlock>();
    let banned = Arc::new(parking_lot::RwLock::new(Vec::new()));

    let listener_lifecycle = Arc::clone(&lifecycle);
    let listener_banned = Arc::clone(&banned);
    let listener_network_active = Arc::clone(&network_active);
    let handle = thread::spawn(move || {
        let result = serve_with_shutdown_with_lifecycle_and_chain_and_sync_wake(
            addr,
            listener_shutdown,
            listener_network_active,
            Magic::BITCOIN,
            listener_lifecycle,
            listener_banned,
            inbound_headers_tx,
            inbound_blocks_tx,
            None,
            None,
            None,
        );
        let _ = tx.send(result);
    });

    thread::sleep(Duration::from_millis(50));
    shutdown.store(true, Ordering::Relaxed);

    let result = rx.recv_timeout(Duration::from_secs(1))?;
    match handle.join() {
        Ok(()) => {}
        Err(_) => return Err(io::Error::other("listener thread panicked").into()),
    }

    result?;
    assert!(registry.read().is_empty());
    Ok(())
}
