//! RPC security properties over the real router and serve loop (research
//! dossier 36: W1 browser guard, W2 resource controls, W3 cookie auth, W5
//! `/block` admission; docs/blocks.md §9.1-§9.2).
//!
//! Each property here was first shown to fail on the base commit (d915be4)
//! with a test asserting the secure behaviour (docs/evidence/rpc-security-2026-09-27).
//! These tests prove server behaviour; browser behaviour is cited, not tested.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_node::guard::{Limits, MAX_OUTPUTS_BODY_BYTES, MAX_TX_BODY_BYTES};
use blacksilk_node::serve::{self, ConnLimits, RpcSettings};
use blacksilk_node::{router, App, Shared, ROUTES, RPC_BLOCK_MAX_DEPTH};
use blacksilk_rpc::{Client, RpcError};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Accepts every header; counts its calls, and the calls made while the
/// chain lock was held (by anyone).
#[derive(Default)]
struct CountingPow {
    calls: AtomicUsize,
    under_lock: AtomicUsize,
    chain: OnceLock<Shared>,
}

impl PowFunction for CountingPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(c) = self.chain.get() {
            if c.try_lock().is_err() {
                self.under_lock.fetch_add(1, Ordering::SeqCst);
            }
        }
        [0; 32]
    }
}

/// Short limits, so the timing tests run in well under a second each.
fn test_conn() -> ConnLimits {
    ConnLimits {
        max_connections: 8,
        header_read_timeout: Duration::from_millis(300),
        max_head_bytes: 16 * 1024,
        shutdown_grace: Duration::from_secs(2),
    }
}

struct Node {
    rt: tokio::runtime::Runtime,
    addr: SocketAddr,
    shared: Shared,
    pow: Arc<CountingPow>,
    /// Set for [`Node::authenticated`].
    cookie: Option<std::path::PathBuf>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    done: Option<tokio::task::JoinHandle<Result<(), String>>>,
    _dir: Option<tempfile::TempDir>,
}

fn chain() -> (Shared, Arc<CountingPow>) {
    let params = ChainParams::regtest();
    let rules = TxRules::for_chain(&params);
    let pow = Arc::new(CountingPow::default());
    let m = ChainManager::open(
        params,
        rules,
        pow.clone(),
        Box::<MemoryStore>::default(),
        [3; 32],
    )
    .unwrap();
    let shared: Shared = Arc::new(Mutex::new(m));
    let _ = pow.chain.set(shared.clone());
    (shared, pow)
}

impl Node {
    /// `router(shared)` (guarded, no credential) behind the serve loop.
    fn guarded(conn: ConnLimits) -> Self {
        let (shared, pow) = chain();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let l = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = l.local_addr().unwrap();
        let app = router(shared.clone());
        rt.spawn(serve::serve(l, app, conn, std::future::pending()));
        Self {
            rt,
            addr,
            shared,
            pow,
            cookie: None,
            stop: None,
            done: None,
            _dir: None,
        }
    }

    /// The node binary's RPC: `serve::run` with a cookie in a data directory.
    fn authenticated() -> Self {
        let (shared, pow) = chain();
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let l = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = l.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let app = App::shared(shared.clone(), None);
        let data = dir.path().to_path_buf();
        let settings = RpcSettings {
            conn: test_conn(),
            ..RpcSettings::default()
        };
        let done = rt.spawn(async move {
            serve::run(l, app, &data, settings, async {
                let _ = stopped.await;
            })
            .await
        });
        let cookie = dir.path().join(blacksilk_rpc::COOKIE_FILE);
        let start = Instant::now();
        while !cookie.exists() {
            assert!(start.elapsed() < Duration::from_secs(10), "no cookie");
            std::thread::sleep(Duration::from_millis(10));
        }
        Self {
            rt,
            addr,
            shared,
            pow,
            cookie: Some(cookie),
            stop: Some(stop),
            done: Some(done),
            _dir: Some(dir),
        }
    }

    fn token(&self) -> String {
        std::fs::read_to_string(self.cookie.as_ref().unwrap()).unwrap()
    }

    fn shutdown(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let r = self.rt.block_on(self.done.take().unwrap()).unwrap();
        assert_eq!(r, Ok(()));
    }
}

/// An HTTP answer: status, head (lowercase) and body.
#[derive(Debug)]
struct Answer {
    status: u16,
    head: String,
    body: String,
}

/// Sends `raw` and reads the answer until the server closes (requests carry
/// `Connection: close`). `None`: no answer (closed or timed out).
fn send(addr: SocketAddr, raw: &[u8]) -> Option<Answer> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    // The server may answer (and close) before a large body is sent.
    let _ = s.write_all(raw);
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    Some(Answer {
        status: head.split(' ').nth(1)?.parse().ok()?,
        head: head.to_ascii_lowercase(),
        body: body.to_string(),
    })
}

fn get(addr: SocketAddr, path: &str, extra: &str) -> Option<Answer> {
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n");
    send(addr, req.as_bytes())
}

fn post(addr: SocketAddr, path: &str, extra: &str, body: &str) -> Option<Answer> {
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\n{extra}\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send(addr, req.as_bytes())
}

/// A request for `(method, path)` from [`ROUTES`] with `host` and `extra`
/// header lines (a missing `host` omits the header).
fn route_request(method: &str, path: &str, host: Option<&str>, extra: &str) -> String {
    let host = host.map_or(String::new(), |h| format!("Host: {h}\r\n"));
    let body = if method == "POST" { "{}" } else { "" };
    let ct = if method == "POST" {
        "Content-Type: application/json\r\n"
    } else {
        ""
    };
    format!(
        "{method} {path} HTTP/1.1\r\n{host}{ct}{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Every route, plus an unknown path and a method no route has.
fn all_targets() -> Vec<(&'static str, &'static str)> {
    let mut t = ROUTES.to_vec();
    t.push(("GET", "/no-such-route"));
    t.push(("DELETE", "/info"));
    t
}

// ---------------------------------------------------------------- W1

#[test]
fn every_route_refuses_foreign_hosts() {
    let n = Node::guarded(test_conn());
    for (method, path) in all_targets() {
        for host in [
            Some("evil.example:29333"),
            Some("evil.example"),
            Some("0.0.0.0:29333"),
            Some("[::]:1"),
            Some("localhost.evil.example"),
            Some("[::ffff:127.0.0.1]:29333"),
        ] {
            let a = send(n.addr, route_request(method, path, host, "").as_bytes()).unwrap();
            assert_eq!(a.status, 403, "{method} {path} Host {host:?}");
        }
        // Missing and duplicate Host headers.
        let a = send(n.addr, route_request(method, path, None, "").as_bytes()).unwrap();
        assert_eq!(a.status, 400, "{method} {path} without Host");
        let dup = route_request(method, path, Some("127.0.0.1"), "Host: evil.example\r\n");
        assert_eq!(send(n.addr, dup.as_bytes()).unwrap().status, 400);
    }
    // An absolute-form target naming another host.
    let req = format!(
        "GET http://evil.example:29333/info HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        n.addr
    );
    assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 403);
}

#[test]
fn loopback_hosts_are_served() {
    let n = Node::guarded(test_conn());
    let port = n.addr.port();
    for host in [
        format!("127.0.0.1:{port}"),
        format!("127.1.2.3:{port}"),
        format!("[::1]:{port}"),
        format!("LOCALHOST:{port}"),
        "localhost".to_string(),
    ] {
        let req = format!("GET /info HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
        let a = send(n.addr, req.as_bytes()).unwrap();
        assert_eq!(a.status, 200, "Host {host}: {}", a.body);
    }
    // The client library passes the guard.
    assert!(Client::new(&n.addr.to_string()).info().is_ok());
}

#[test]
fn browser_requests_are_refused_on_every_route() {
    let n = Node::guarded(test_conn());
    for (method, path) in all_targets() {
        for extra in [
            "Origin: https://evil.example\r\n",
            "Origin: null\r\n",
            "Sec-Fetch-Site: cross-site\r\n",
            "Sec-Fetch-Site: same-origin\r\n",
            "Sec-Fetch-Site: none\r\n",
            "Sec-Fetch-Mode: no-cors\r\n",
            "Sec-Fetch-Dest: image\r\n",
            "Sec-Fetch-User: ?1\r\n",
        ] {
            let host = n.addr.to_string();
            let req = route_request(method, path, Some(&host), extra);
            let a = send(n.addr, req.as_bytes()).unwrap();
            assert_eq!(a.status, 403, "{method} {path} with {extra:?}");
            assert!(!a.head.contains("access-control-"), "{}", a.head);
        }
    }
    // A CORS preflight is refused and never granted.
    for extra in [
        "Origin: https://evil.example\r\nAccess-Control-Request-Method: POST\r\n",
        "",
    ] {
        let req = format!(
            "OPTIONS /tx HTTP/1.1\r\nHost: {}\r\n{extra}Connection: close\r\n\r\n",
            n.addr
        );
        let a = send(n.addr, req.as_bytes()).unwrap();
        assert!(matches!(a.status, 403 | 405), "{}", a.status);
        assert!(!a.head.contains("access-control-"), "{}", a.head);
    }
}

#[test]
fn a_post_must_be_json_and_other_methods_carry_no_body() {
    let n = Node::guarded(test_conn());
    for ct in [
        "text/plain",
        "application/x-www-form-urlencoded",
        "multipart/form-data; boundary=x",
    ] {
        let req = format!(
            "POST /tx HTTP/1.1\r\nHost: {}\r\nContent-Type: {ct}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
            n.addr
        );
        assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 415, "{ct}");
    }
    let req = format!(
        "POST /tx HTTP/1.1\r\nHost: {}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
        n.addr
    );
    assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 415);
    // JSON, with or without parameters, reaches the handler (400: not a
    // transaction).
    let a = post(n.addr, "/tx", "", r#"{"hex":"00"}"#).unwrap();
    assert_eq!(a.status, 400, "{}", a.body);
    assert!(a.body.starts_with("transaction"), "{}", a.body);
    let req = format!(
        "POST /tx HTTP/1.1\r\nHost: {}\r\nContent-Type: Application/JSON; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\n{{\"hex\":\"00\"}}",
        n.addr
    );
    assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 400);
    let req = format!(
        "GET /info HTTP/1.1\r\nHost: {}\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello",
        n.addr
    );
    assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 413);
}

/// Every listed route exists (the list the guard tests enumerate is the
/// router's), and an unknown path is answered 404 after the guard.
#[test]
fn the_route_list_is_the_router() {
    let n = Node::guarded(test_conn());
    for (method, path) in ROUTES {
        let host = n.addr.to_string();
        let a = send(
            n.addr,
            route_request(method, path, Some(&host), "").as_bytes(),
        )
        .unwrap();
        assert!(
            !matches!(a.status, 404 | 405),
            "{method} {path}: {}",
            a.status
        );
    }
    assert_eq!(get(n.addr, "/no-such-route", "").unwrap().status, 404);
}

// ---------------------------------------------------------------- W2

#[test]
fn oversized_bodies_are_refused_before_reading() {
    let n = Node::guarded(test_conn());
    for (path, limit) in [
        ("/tx", MAX_TX_BODY_BYTES),
        ("/outputs", MAX_OUTPUTS_BODY_BYTES),
    ] {
        // Declared too large: refused from the head alone.
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            n.addr,
            limit + 1
        );
        assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 413, "{path}");
    }
    // Sent in full, chunked (no declared length): cut at the limit.
    let body = format!("{{\"hex\":\"{}\"}}", "00".repeat(MAX_TX_BODY_BYTES / 2 + 1));
    let req = format!(
        "POST /tx HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
        n.addr,
        body.len()
    );
    assert_eq!(send(n.addr, req.as_bytes()).unwrap().status, 413);
}

#[test]
fn a_maximum_size_block_body_is_still_read() {
    let n = Node::guarded(test_conn());
    // The largest body `/block` accepts: read in full, then refused as a
    // block (400), not as a body (413).
    let hex_len = (blacksilk_node::guard::MAX_BLOCK_BODY_BYTES - 16) & !1;
    let body = format!("{{\"hex\":\"{}\"}}", "0".repeat(hex_len));
    assert!(body.len() <= blacksilk_node::guard::MAX_BLOCK_BODY_BYTES);
    let a = post(n.addr, "/block", "", &body).unwrap();
    assert_eq!(a.status, 400, "{}", a.body);
}

#[test]
fn oversized_headers_are_refused() {
    let n = Node::guarded(test_conn());
    let pad = "a".repeat(100 * 1024);
    let a = get(n.addr, "/info", &format!("X-Pad: {pad}\r\n"));
    assert!(a.as_ref().is_none_or(|a| a.status == 431), "{a:?}");
    // Well within the bound: served.
    let a = get(n.addr, "/info", &format!("X-Pad: {}\r\n", "a".repeat(4096))).unwrap();
    assert_eq!(a.status, 200);
}

/// The connection is closed within the header timeout (after a 408 or
/// nothing), whether the head is partial or never started.
fn closed_within(mut s: TcpStream, within: Duration) -> bool {
    s.set_read_timeout(Some(within)).unwrap();
    let start = Instant::now();
    let mut buf = Vec::new();
    let closed = s.read_to_end(&mut buf).is_ok();
    let text = String::from_utf8_lossy(&buf);
    closed && start.elapsed() < within && (buf.is_empty() || text.starts_with("HTTP/1.1 408"))
}

#[test]
fn slow_and_idle_connections_are_closed() {
    let n = Node::guarded(test_conn());
    // Slowloris: a partial head, trickled.
    let mut s = TcpStream::connect(n.addr).unwrap();
    s.write_all(b"GET /info HTTP/1.1\r\nHost: 127.0.0.1\r\n")
        .unwrap();
    assert!(
        closed_within(s, Duration::from_secs(3)),
        "partial head kept open"
    );
    // A connection that never sends anything.
    let s = TcpStream::connect(n.addr).unwrap();
    assert!(
        closed_within(s, Duration::from_secs(3)),
        "idle connection kept open"
    );
    // A kept-alive connection after its request.
    let mut s = TcpStream::connect(n.addr).unwrap();
    write!(s, "GET /info HTTP/1.1\r\nHost: {}\r\n\r\n", n.addr).unwrap();
    let mut first = [0u8; 12];
    s.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"HTTP/1.1 200");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut rest = Vec::new();
    let start = Instant::now();
    assert!(
        s.read_to_end(&mut rest).is_ok(),
        "kept-alive connection not closed"
    );
    assert!(start.elapsed() < Duration::from_secs(3));
    // The production default.
    assert_eq!(
        ConnLimits::default().header_read_timeout,
        Duration::from_secs(10)
    );
}

#[test]
fn a_slow_body_is_cut() {
    let (shared, _pow) = chain();
    let rt = tokio::runtime::Runtime::new().unwrap();
    let l = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let addr = l.local_addr().unwrap();
    let policy = blacksilk_node::guard::Policy {
        limits: Limits {
            body_timeout: Duration::from_millis(300),
            ..Limits::default()
        },
        ..Default::default()
    };
    let app = blacksilk_node::router_secured(App::shared(shared, None), policy);
    rt.spawn(serve::serve(l, app, test_conn(), std::future::pending()));
    let mut s = TcpStream::connect(addr).unwrap();
    write!(
        s,
        "POST /tx HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{\"hex\":"
    )
    .unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut resp = String::new();
    let _ = s.read_to_string(&mut resp);
    assert!(resp.starts_with("HTTP/1.1 408"), "{resp}");
}

#[test]
fn connections_beyond_the_cap_are_refused() {
    let conn = ConnLimits {
        header_read_timeout: Duration::from_secs(30),
        ..test_conn()
    };
    let n = Node::guarded(conn);
    let held: Vec<TcpStream> = (0..8)
        .map(|_| TcpStream::connect(n.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(300));
    // The ninth is closed at once, without an answer.
    let mut s = TcpStream::connect(n.addr).unwrap();
    let _ = write!(
        s,
        "GET /info HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        n.addr
    );
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    assert!(buf.is_empty(), "served beyond the cap");
    // Slots come back when connections close.
    drop(held);
    let start = Instant::now();
    loop {
        if get(n.addr, "/info", "").is_some_and(|a| a.status == 200) {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "no slot freed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A full admission class answers 503 at once; the chain lock is held by the
/// test, so the admitted requests wait on it. They read the chain
/// (`/distribution`): `/info` answers from the published chain summary
/// without the lock (dossier 34 Stage 1) and would free its slot at once.
/// Two more requests than the class has slots are sent; the class is known
/// to be full once two of them were refused (no fixed sleep: under a loaded
/// test run the fillers may take longer than any fixed delay to arrive).
#[test]
fn a_full_class_answers_busy_at_once() {
    let n = Node::guarded(ConnLimits {
        max_connections: 32,
        ..test_conn()
    });
    let reads = Limits::default().reads;
    let extra = 2;
    let guard = n.shared.lock().unwrap();
    let addr = n.addr;
    let (tx, rx) = std::sync::mpsc::channel();
    for _ in 0..reads + extra {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send(get(addr, "/distribution?to=0", "").map(|a| a.status));
        });
    }
    let mut statuses = Vec::new();
    while statuses.len() < extra {
        let s = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("the class fills up");
        assert_eq!(
            s,
            Some(503),
            "only refusals come back while the lock is held"
        );
        statuses.push(s);
    }
    let start = Instant::now();
    let a = get(addr, "/distribution?to=0", "").unwrap();
    assert_eq!(a.status, 503, "{}", a.body);
    assert!(a.head.contains("retry-after: 1"));
    assert!(start.elapsed() < Duration::from_secs(2));
    let a = get(addr, "/px/contracts?from=0", "").unwrap();
    assert_eq!(a.status, 503);
    drop(guard);
    for _ in 0..reads {
        statuses.push(rx.recv_timeout(Duration::from_secs(20)).unwrap());
    }
    let ok = statuses.iter().filter(|s| **s == Some(200)).count();
    assert_eq!(
        ok, reads,
        "every admitted request is answered: {statuses:?}"
    );
    assert_eq!(get(addr, "/info", "").unwrap().status, 200);
}

// ---------------------------------------------------------------- W3

#[test]
fn the_node_rpc_requires_its_cookie_on_every_route() {
    let mut n = Node::authenticated();
    let token = n.token();
    assert!(blacksilk_rpc::is_token(&token));
    let addr = n.addr;
    let mut wrong = token.clone().into_bytes();
    wrong[63] = if wrong[63] == b'0' { b'1' } else { b'0' };
    let wrong = String::from_utf8(wrong).unwrap();
    for (method, path) in all_targets() {
        let host = addr.to_string();
        for auth in [
            String::new(),
            format!("Authorization: Bearer {wrong}\r\n"),
            format!("Authorization: Bearer {}\r\n", &token[..63]),
            format!("Authorization: Basic {token}\r\n"),
            format!("Authorization: {token}\r\n"),
            "Authorization: Bearer\r\n".to_string(),
            format!("Authorization: Bearer {token}\r\nAuthorization: Bearer {token}\r\n"),
        ] {
            let a = send(
                addr,
                route_request(method, path, Some(&host), &auth).as_bytes(),
            )
            .unwrap();
            assert_eq!(a.status, 401, "{method} {path} with {auth:?}");
            assert!(a.head.contains("www-authenticate: bearer"), "{}", a.head);
        }
        let ok = format!("Authorization: Bearer {token}\r\n");
        let a = send(
            addr,
            route_request(method, path, Some(&host), &ok).as_bytes(),
        )
        .unwrap();
        assert!(
            !matches!(a.status, 401 | 403),
            "{method} {path}: {}",
            a.status
        );
    }
    // A failure is answered after the fixed delay.
    let start = Instant::now();
    assert_eq!(get(addr, "/info", "").unwrap().status, 401);
    assert!(start.elapsed() >= Limits::default().auth_failure_delay);
    // The host and browser checks still come first.
    let ok = format!("Authorization: Bearer {token}\r\n");
    let req = format!("GET /info HTTP/1.1\r\nHost: evil.example\r\n{ok}Connection: close\r\n\r\n");
    assert_eq!(send(addr, req.as_bytes()).unwrap().status, 403);
    assert_eq!(
        get(addr, "/info", &format!("{ok}Origin: null\r\n"))
            .unwrap()
            .status,
        403
    );

    // The client reads the cookie.
    let cookie = n.cookie.clone().unwrap();
    let c = Client::new(&addr.to_string())
        .with_cookie_file(&cookie)
        .unwrap();
    assert_eq!(c.info().unwrap().network, "regtest");
    assert!(matches!(
        Client::new(&addr.to_string()).info(),
        Err(RpcError::Status(401, _))
    ));
    let other = Client::new(&addr.to_string()).with_token(&wrong).unwrap();
    assert!(matches!(other.info(), Err(RpcError::Status(401, _))));

    // A clean shutdown removes the cookie; a restart writes a new one.
    n.shutdown();
    assert!(!cookie.exists(), "cookie left after shutdown");
    #[cfg(unix)]
    {
        let m = Node::authenticated();
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(m.cookie.as_ref().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
    let m = Node::authenticated();
    assert_ne!(m.token(), token);
}

// ---------------------------------------------------------------- W5

fn block_on(m: &ChainManager, parent: &Hash, seed: u64) -> Block {
    let t = m.template_on(parent).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (miner, _) = WalletKeys::generate(&mut rng);
    let cb = build_coinbase(
        t.height,
        &[Payment {
            address: miner.address(SubaddressIndex::PRIMARY),
            amount: t.reward,
        }],
        &miner.hedge_secret(),
        &mut rng,
    )
    .unwrap();
    let txs = vec![Transaction::Coinbase(cb)];
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let header = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t
            .min_timestamp
            .max(m.params().genesis.timestamp + 120 * t.height),
        difficulty: t.difficulty,
        tx_root: tx_root(&ids),
        nonce: seed,
    };
    Block { header, txs }
}

fn submit(addr: SocketAddr, b: &Block) -> blacksilk_rpc::SubmitResult {
    Client::new(&addr.to_string())
        .submit_block(&b.encode())
        .unwrap()
}

#[test]
fn a_deep_fork_block_is_refused_without_pow_or_storage() {
    let n = Node::guarded(test_conn());
    let nid = ChainParams::regtest().network_id;
    {
        let mut m = n.shared.lock().unwrap();
        for i in 0..20 {
            let tip = m.tip_id();
            let b = block_on(&m, &tip, 100 + i);
            let now = b.header.timestamp;
            m.submit_block(b, now).unwrap();
        }
    }
    let depth_limit = RPC_BLOCK_MAX_DEPTH;
    for depth in [depth_limit + 1, 18, 20] {
        let fork = {
            let m = n.shared.lock().unwrap();
            let parent = m.headers().main_id_at(20 - depth).unwrap();
            block_on(&m, &parent, 7 + depth)
        };
        let before = n.pow.calls.load(Ordering::SeqCst);
        let r = submit(n.addr, &fork);
        assert!(!r.accepted);
        assert!(
            r.error.as_deref().unwrap().starts_with("NotNearTip"),
            "{r:?}"
        );
        assert_eq!(
            n.pow.calls.load(Ordering::SeqCst),
            before,
            "PoW at depth {depth}"
        );
        let id = fork.header.id(nid);
        assert!(n.shared.lock().unwrap().header(&id).is_none(), "stored");
    }
    // An unknown parent: refused the same way.
    let mut orphan = {
        let m = n.shared.lock().unwrap();
        block_on(&m, &m.tip_id(), 3)
    };
    orphan.header.prev_id = [9; 32];
    let before = n.pow.calls.load(Ordering::SeqCst);
    assert!(!submit(n.addr, &orphan).accepted);
    assert_eq!(n.pow.calls.load(Ordering::SeqCst), before);

    // Within the depth: a competing block is verified and kept as a side
    // branch, as before.
    let near = {
        let m = n.shared.lock().unwrap();
        let parent = m.headers().main_id_at(20 - depth_limit).unwrap();
        block_on(&m, &parent, 55)
    };
    let r = submit(n.addr, &near);
    assert!(r.accepted, "{r:?}");
    assert_eq!(r.on_best_chain, Some(false));
}

#[test]
fn a_tip_block_is_accepted_with_its_pow_computed_off_the_lock() {
    let n = Node::guarded(test_conn());
    for i in 0..5 {
        let b = {
            let m = n.shared.lock().unwrap();
            block_on(&m, &m.tip_id(), 200 + i)
        };
        let calls = n.pow.calls.load(Ordering::SeqCst);
        let r = submit(n.addr, &b);
        assert!(r.accepted, "{r:?}");
        assert_eq!(r.on_best_chain, Some(true));
        assert!(n.pow.calls.load(Ordering::SeqCst) > calls, "PoW computed");
    }
    assert_eq!(n.shared.lock().unwrap().height(), 5);
    assert_eq!(
        n.pow.under_lock.load(Ordering::SeqCst),
        0,
        "RandomX ran under the chain lock"
    );
}
