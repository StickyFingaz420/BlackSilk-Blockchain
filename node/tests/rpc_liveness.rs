//! RPC liveness while the chain lock is held for a long time (research
//! dossier 34, Stage 0; findings F34-4, F34-6), over the real router.
//!
//! The hold is a stalled block append on the block-submission path
//! (`chain/tests/support/stall.rs`); nothing in the node is instrumented.
//! Numbering follows the Stage 0 assignment: L4 here is the dossier's L5, L5
//! the dossier's L6 (see `p2p/tests/liveness.rs`). L4 fails until Stage 1 (34's
//! snapshot) and is ignored (`-- --ignored` runs it). L5 passes since the RPC
//! admission classes (36 W2, `node/src/guard.rs`) and runs by default.

#[path = "../../chain/tests/support/stall.rs"]
mod stall;

use blacksilk_chain::manager::ChainManager;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_node::{router, Shared};
use blacksilk_tx::params::TxRules;
use stall::{Holder, SlowStore, StallControl};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct ZeroPow;

impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

/// Runtime worker threads of the RPC server.
const WORKERS: usize = 2;

/// The RPC server's threads alive now, and the most ever alive at once.
#[derive(Default)]
struct ThreadCount {
    alive: AtomicUsize,
    peak: AtomicUsize,
}

struct Server {
    rt: tokio::runtime::Runtime,
    addr: SocketAddr,
    shared: Shared,
    ctl: Arc<StallControl>,
    threads: Arc<ThreadCount>,
}

/// The RPC router over a chain whose store can stall, on a runtime of
/// [`WORKERS`] workers that counts its threads (workers and blocking threads)
/// through the runtime's public start/stop hooks.
fn serve() -> Server {
    let params = ChainParams::regtest();
    let rules = TxRules::for_chain(&params);
    let (store, ctl) = SlowStore::new();
    let manager =
        ChainManager::open(params, rules, Arc::new(ZeroPow), Box::new(store), [3; 32]).unwrap();
    let shared: Shared = Arc::new(Mutex::new(manager));
    let threads = Arc::new(ThreadCount::default());
    let (up, down) = (threads.clone(), threads.clone());
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(WORKERS)
        .enable_all()
        .on_thread_start(move || {
            let n = up.alive.fetch_add(1, Ordering::SeqCst) + 1;
            up.peak.fetch_max(n, Ordering::SeqCst);
        })
        .on_thread_stop(move || {
            down.alive.fetch_sub(1, Ordering::SeqCst);
        })
        .build()
        .unwrap();
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router(shared.clone());
    rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
    Server {
        rt,
        addr,
        shared,
        ctl,
        threads,
    }
}

/// `GET path`; the HTTP status, or `None` without a full answer in `timeout`.
fn get(addr: SocketAddr, path: &str, timeout: Duration) -> Option<u16> {
    let mut s = std::net::TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(timeout)).ok()?;
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok()?;
    resp.split(' ').nth(1)?.parse().ok()
}

/// L4 (F34-4; dossier L5): `/info` answers within 100 ms during a 40 s hold.
/// Today every RPC chain call waits for the chain lock (on a blocking
/// thread), so `/info` answers only when the hold ends.
#[test]
#[ignore = "fails until Stage 1 (34)"]
fn l4_info_answers_promptly_during_a_hold() {
    let s = serve();
    assert_eq!(get(s.addr, "/info", Duration::from_secs(5)), Some(200));
    let holder = Holder::start(s.shared.clone(), s.ctl.clone(), Duration::from_secs(40));
    for i in 0..5 {
        let start = Instant::now();
        let status = get(s.addr, "/info", Duration::from_secs(3));
        let took = start.elapsed();
        assert!(holder.holding(), "the hold is still on");
        assert_eq!(
            status,
            Some(200),
            "/info {i} not answered within 3 s ({took:?}) during the hold"
        );
        assert!(
            took < Duration::from_millis(100),
            "/info {i} took {took:?} during the hold"
        );
    }
    assert!(holder.release());
}

/// Control for L4: without a hold, `/info` meets the same 100 ms bound, so a
/// Stage 1 failure of L4 is about the hold, not the machine.
#[test]
fn control_info_answers_within_100_ms_without_a_hold() {
    let s = serve();
    assert_eq!(get(s.addr, "/info", Duration::from_secs(5)), Some(200));
    for i in 0..5 {
        let start = Instant::now();
        assert_eq!(get(s.addr, "/info", Duration::from_secs(3)), Some(200));
        let took = start.elapsed();
        assert!(took < Duration::from_millis(100), "/info {i} took {took:?}");
    }
}

/// The RPC concurrency cap of Stage 1 (item 1d; the dossier's example
/// value); requests beyond it are refused (503), not queued on blocking
/// threads. The admission classes (`node/src/guard.rs`) allow at most 9.
const RPC_CHAIN_CAP: usize = 16;
const BURST: usize = 1000;

/// L5 (F34-6; dossier L6): a burst of 1,000 `/info` requests during a hold
/// starts at most [`RPC_CHAIN_CAP`] blocking threads, and every request is
/// answered (200 or 503) once the hold ends. Before the admission classes,
/// each request parked one blocking thread on the chain lock, up to tokio's
/// default of 512, which the P2P tasks share.
#[test]
fn l5_an_rpc_burst_during_a_hold_stays_within_the_blocking_thread_cap() {
    let s = serve();
    assert_eq!(get(s.addr, "/info", Duration::from_secs(5)), Some(200));
    let holder = Holder::start(s.shared.clone(), s.ctl.clone(), Duration::from_secs(60));
    let before = s.threads.alive.load(Ordering::SeqCst);
    s.threads.peak.store(before, Ordering::SeqCst);

    let addr = s.addr;
    let client = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let tasks: Vec<_> = (0..BURST)
                .map(|_| {
                    tokio::spawn(async move {
                        let mut c = tokio::net::TcpStream::connect(addr).await.ok()?;
                        let req = format!(
                            "GET /info HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
                        );
                        c.write_all(req.as_bytes()).await.ok()?;
                        let mut resp = Vec::new();
                        tokio::time::timeout(Duration::from_secs(120), c.read_to_end(&mut resp))
                            .await
                            .ok()?
                            .ok()?;
                        let resp = String::from_utf8_lossy(&resp).into_owned();
                        resp.split(' ').nth(1)?.parse::<u16>().ok()
                    })
                })
                .collect();
            let mut statuses = Vec::with_capacity(BURST);
            for t in tasks {
                statuses.push(t.await.unwrap());
            }
            statuses
        })
    });
    // Every request has reached the server well within this.
    std::thread::sleep(Duration::from_secs(5));
    let peak = s.threads.peak.load(Ordering::SeqCst);
    let still_held = holder.holding();
    assert!(holder.release(), "the held block connects");
    let statuses = client.join().unwrap();
    let answered = statuses
        .iter()
        .filter(|s| matches!(s, Some(200) | Some(503)))
        .count();
    let blocking = peak.saturating_sub(WORKERS);
    println!("peak blocking threads during the burst: {blocking}; answered {answered}/{BURST}");
    assert!(still_held, "the burst was measured during the hold");
    assert!(
        blocking <= RPC_CHAIN_CAP,
        "{blocking} blocking threads during the burst (cap {RPC_CHAIN_CAP})"
    );
    assert_eq!(answered, BURST, "every request is answered (200 or 503)");
    drop(s.rt);
}
