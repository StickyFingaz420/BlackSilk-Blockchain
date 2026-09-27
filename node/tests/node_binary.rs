//! The `blacksilk-node` binary's RPC, end to end (docs/blocks.md §9.1): the
//! real executable on a temporary regtest data directory, without P2P.
//!
//! - a request without the cookie is refused (`401`), one with it served;
//! - the cookie exists while the node runs, and a clean shutdown removes it
//!   (Unix: `SIGINT`, as systemd's `KillSignal`); a restart after a hard kill
//!   replaces the stale cookie;
//! - the connection cap of the serve loop applies.
//!
//! On the base commit (2985a50) the binary served `/info` without a
//! credential, through `axum::serve` (docs/evidence/rpc-security-2026-09-27).

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const NODE: &str = env!("CARGO_BIN_EXE_blacksilk-node");

struct NodeProc {
    child: Child,
    addr: SocketAddr,
    data: PathBuf,
    log: PathBuf,
}

fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

impl NodeProc {
    fn start(data: &Path, extra: &[&str]) -> Self {
        let addr = free_port();
        let log = data.with_extension(format!("{}.log", addr.port()));
        let f = std::fs::File::create(&log).unwrap();
        let mut args = vec![
            "--network".to_string(),
            "regtest".into(),
            "--no-p2p".into(),
            "--data-dir".into(),
            data.display().to_string(),
            "--rpc-bind".into(),
            addr.to_string(),
        ];
        args.extend(extra.iter().map(|s| s.to_string()));
        let child = Command::new(NODE)
            .args(&args)
            .env("RUST_LOG", "info")
            .stdout(Stdio::from(f.try_clone().unwrap()))
            .stderr(Stdio::from(f))
            .spawn()
            .unwrap();
        let mut n = Self {
            child,
            addr,
            data: data.to_path_buf(),
            log,
        };
        n.wait_listening();
        n
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits until the RPC port accepts connections and the cookie file
    /// exists (the node binds the port before it writes the cookie).
    fn wait_listening(&mut self) {
        let start = Instant::now();
        while TcpStream::connect(self.addr).is_err() || !self.cookie().exists() {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("the node exited ({status}); log:\n{}", self.log_text());
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "the node did not listen or write its cookie; log:\n{}",
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn cookie(&self) -> PathBuf {
        self.data.join(blacksilk_rpc::COOKIE_FILE)
    }

    fn wait_exit(&mut self, within: Duration) -> Option<std::process::ExitStatus> {
        let start = Instant::now();
        while start.elapsed() < within {
            if let Some(s) = self.child.try_wait().unwrap() {
                return Some(s);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// `GET path` with `extra` header lines; the status, or `None` when the
/// connection was closed without an answer.
fn get(addr: SocketAddr, path: &str, extra: &str) -> Option<(u16, String)> {
    let mut s = TcpStream::connect(addr).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(20))).ok()?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\n{extra}Connection: close\r\n\r\n");
    let _ = s.write_all(req.as_bytes());
    let mut resp = Vec::new();
    let _ = s.read_to_end(&mut resp);
    let text = String::from_utf8_lossy(&resp).into_owned();
    let (head, body) = text.split_once("\r\n\r\n")?;
    Some((head.split(' ').nth(1)?.parse().ok()?, body.to_string()))
}

fn bearer(token: &str) -> String {
    format!("Authorization: Bearer {token}\r\n")
}

/// The binary writes its cookie, refuses requests without it on every
/// route and serves them with it; the client library reads the cookie.
#[test]
fn the_node_binary_requires_its_cookie() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let n = NodeProc::start(&data, &[]);
    let (status, _) = get(n.addr, "/info", "").expect("an answer");
    assert_eq!(
        status,
        401,
        "the binary serves /info without a credential; log:\n{}",
        n.log_text()
    );
    for (method, path) in blacksilk_node::ROUTES {
        if *method == "GET" {
            assert_eq!(get(n.addr, path, "").unwrap().0, 401, "GET {path}");
        }
    }
    let cookie = n.cookie();
    assert!(cookie.exists(), "cookie written at start");
    let token = std::fs::read_to_string(&cookie).unwrap();
    assert!(blacksilk_rpc::is_token(&token));
    let (status, body) = get(n.addr, "/info", &bearer(&token)).unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"network\":\"regtest\""), "{body}");
    let c = blacksilk_rpc::Client::new(&n.addr.to_string())
        .with_cookie_file(&cookie)
        .unwrap();
    assert_eq!(c.info().unwrap().height, 0);
    assert!(matches!(
        blacksilk_rpc::Client::new(&n.addr.to_string()).info(),
        Err(blacksilk_rpc::RpcError::Status(401, _))
    ));
}

/// The serve loop's connection cap (64 by default) applies to the binary:
/// the connection beyond it is closed without an answer.
#[test]
fn the_node_binary_caps_its_connections() {
    let dir = tempfile::tempdir().unwrap();
    let n = NodeProc::start(&dir.path().join("node"), &[]);
    let token = std::fs::read_to_string(n.cookie()).unwrap();
    // Idle connections are closed after the 10 s header-read timeout: the
    // test stays well within it.
    let held: Vec<TcpStream> = (0..64)
        .map(|_| TcpStream::connect(n.addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        get(n.addr, "/info", &bearer(&token)),
        None,
        "served beyond the cap"
    );
    drop(held);
    let start = Instant::now();
    while get(n.addr, "/info", &bearer(&token)).map(|a| a.0) != Some(200) {
        assert!(start.elapsed() < Duration::from_secs(5), "no slot freed");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A clean shutdown (`SIGINT`, the systemd unit's `KillSignal`) removes the
/// cookie. Windows has no way to deliver a console Ctrl-C to a child
/// without FFI; the same code path (`serve::run`) is covered there by
/// `rpc_security::the_node_rpc_requires_its_cookie_on_every_route`.
#[cfg(unix)]
#[test]
fn a_clean_shutdown_removes_the_cookie() {
    let dir = tempfile::tempdir().unwrap();
    let mut n = NodeProc::start(&dir.path().join("node"), &[]);
    let cookie = n.cookie();
    assert!(cookie.exists());
    let st = Command::new("kill")
        .args(["-INT", &n.child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let status = n
        .wait_exit(Duration::from_secs(30))
        .expect("the node stops");
    assert!(status.success(), "{status:?}; log:\n{}", n.log_text());
    assert!(!cookie.exists(), "cookie left after a clean shutdown");
}

/// After a crash (a hard kill leaves the cookie behind), the next start
/// writes a new credential; the old one no longer works.
#[test]
fn a_restart_after_a_crash_replaces_the_cookie() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let mut n = NodeProc::start(&data, &[]);
    let old = std::fs::read_to_string(n.cookie()).unwrap();
    n.child.kill().unwrap();
    n.wait_exit(Duration::from_secs(30)).expect("killed");
    assert!(n.cookie().exists(), "a crash leaves the cookie");
    drop(n);
    let m = NodeProc::start(&data, &[]);
    let start = Instant::now();
    let new = loop {
        let t = std::fs::read_to_string(m.cookie()).unwrap_or_default();
        if t != old && blacksilk_rpc::is_token(&t) {
            break t;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "cookie not replaced"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(get(m.addr, "/info", &bearer(&old)).unwrap().0, 401);
    assert_eq!(get(m.addr, "/info", &bearer(&new)).unwrap().0, 200);
}

/// `--rpc-allow-host` adds a host name the guard accepts; others stay
/// refused.
#[test]
fn allowed_hosts_are_configurable() {
    let dir = tempfile::tempdir().unwrap();
    let n = NodeProc::start(
        &dir.path().join("node"),
        &["--rpc-allow-host", "node.example"],
    );
    let token = std::fs::read_to_string(n.cookie()).unwrap();
    let ask = |host: &str| {
        let mut s = TcpStream::connect(n.addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        write!(
            s,
            "GET /info HTTP/1.1\r\nHost: {host}\r\n{}Connection: close\r\n\r\n",
            bearer(&token)
        )
        .unwrap();
        let mut resp = String::new();
        let _ = s.read_to_string(&mut resp);
        resp.split(' ').nth(1).unwrap_or("").to_string()
    };
    assert_eq!(ask("node.example"), "200");
    assert_eq!(ask("NODE.example:80"), "200");
    assert_eq!(ask("evil.example"), "403");
}
