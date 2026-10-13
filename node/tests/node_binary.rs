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
use std::time::{Duration, Instant, SystemTime};

const NODE: &str = env!("CARGO_BIN_EXE_blacksilk-node");

struct NodeProc {
    child: Child,
    addr: SocketAddr,
    data: PathBuf,
    log: PathBuf,
    /// When this process was spawned: its cookie is written after it.
    spawned: SystemTime,
}

fn free_port() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

impl NodeProc {
    fn start(data: &Path, extra: &[&str]) -> Self {
        Self::start_logged(data, None, extra)
    }

    /// As [`start`](Self::start), with the log at `log` instead of beside the
    /// data directory: for a data directory whose parents the node itself
    /// must create (CI run 123: the log beside `a/b` needed `a` first).
    fn start_logged(data: &Path, log: Option<&Path>, extra: &[&str]) -> Self {
        Self::launch(data, log, &["--no-p2p"], extra)
    }

    /// As [`start`](Self::start), with P2P on, given by `net` (P2P options).
    fn start_net(data: &Path, net: &[&str], extra: &[&str]) -> Self {
        Self::launch(data, None, net, extra)
    }

    fn launch(data: &Path, log: Option<&Path>, net: &[&str], extra: &[&str]) -> Self {
        let addr = free_port();
        let log = log.map_or_else(
            || data.with_extension(format!("{}.log", addr.port())),
            Path::to_path_buf,
        );
        let f = std::fs::File::create(&log).unwrap();
        let mut args = vec![
            "--network".to_string(),
            "regtest".into(),
            "--data-dir".into(),
            data.display().to_string(),
            "--rpc-bind".into(),
            addr.to_string(),
        ];
        args.extend(net.iter().map(|s| s.to_string()));
        args.extend(extra.iter().map(|s| s.to_string()));
        let spawned = SystemTime::now();
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
            spawned,
        };
        n.wait_listening();
        n
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Waits until the RPC port accepts connections and THIS process has
    /// written its cookie (the node binds the port before it writes the
    /// cookie, and a killed earlier node leaves its stale cookie behind: CI
    /// run 111 read that one and got 401).
    fn wait_listening(&mut self) {
        let start = Instant::now();
        let spawned = self.spawned;
        let fresh = |p: &Path| {
            std::fs::metadata(p)
                .and_then(|m| m.modified())
                .is_ok_and(|t| t >= spawned)
        };
        while TcpStream::connect(self.addr).is_err() || !fresh(&self.cookie()) {
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

/// Whether the server has closed `s` (a read sees end of stream or a reset
/// at once).
fn closed_by_peer(s: &TcpStream) -> bool {
    s.set_nonblocking(true).unwrap();
    let mut b = [0u8; 1];
    let mut r: &TcpStream = s;
    let closed = match r.read(&mut b) {
        Ok(n) => n == 0,
        Err(e) => e.kind() != std::io::ErrorKind::WouldBlock,
    };
    s.set_nonblocking(false).unwrap();
    closed
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
    // test stays well within it. The server may still hold slots for
    // `wait_listening`'s probe connections when these arrive, and refuses
    // (closes) the excess: those are opened again until all 64 have stayed
    // open through a whole pause (CI run 115, overflow build: a refused held
    // connection left its slot to the request below).
    let mut held: Vec<TcpStream> = (0..64)
        .map(|_| TcpStream::connect(n.addr).unwrap())
        .collect();
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let mut reopened = 0;
        for s in held.iter_mut() {
            if closed_by_peer(s) {
                *s = TcpStream::connect(n.addr).unwrap();
                reopened += 1;
            }
        }
        if reopened == 0 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "held connections keep being refused ({reopened} this round); log:
{}",
            n.log_text()
        );
    }
    let answer = get(n.addr, "/info", &bearer(&token));
    if answer.is_some() {
        // Diagnose before failing: a held connection the server already
        // closed frees its slot, which would explain an answer here.
        let closed = held.iter().filter(|s| closed_by_peer(s)).count();
        panic!(
            "served beyond the cap: {answer:?}; held connections already closed by the \
             server: {closed} of 64; log:\n{}",
            n.log_text()
        );
    }
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

// ------------------------------------------------ operator invalidation

/// Zero hash: meets any difficulty. The node trusts the PoW hash stored with
/// each block in its own store (docs/blocks.md §8), so a store written with
/// it replays in the binary without RandomX work.
struct ZeroPow;
impl blacksilk_consensus::PowFunction for ZeroPow {
    fn pow_hash(&self, _: &[u8; 32], _: &blacksilk_consensus::PowBlob) -> [u8; 32] {
        [0; 32]
    }
}

/// Writes `n` coinbase-only regtest blocks to `<data>/blocks.dat` with
/// [`ZeroPow`]'s stored hashes: a store the node's PoW check refuses
/// ([`a_store_with_forged_pow_hashes_is_refused`]); returns their ids.
fn regtest_store(data: &Path, n: usize) -> Vec<[u8; 32]> {
    regtest_store_with(data, n, std::sync::Arc::new(ZeroPow))
}

/// Writes `n` coinbase-only regtest blocks to `<data>/blocks.dat` as a node
/// would, with `pow`'s hashes stored; returns their ids.
fn regtest_store_with(
    data: &Path,
    n: usize,
    pow: std::sync::Arc<dyn blacksilk_consensus::PowFunction>,
) -> Vec<[u8; 32]> {
    use blacksilk_chain::block::Block;
    use blacksilk_chain::manager::ChainManager;
    use blacksilk_chain::store::FileStore;
    use blacksilk_consensus::merkle::tx_root;
    use blacksilk_consensus::{BlockHeader, ChainParams};
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_tx::builder::{build_coinbase, Payment};
    use blacksilk_tx::params::TxRules;
    use blacksilk_tx::types::Transaction;
    use rand_chacha::rand_core::SeedableRng;

    std::fs::create_dir_all(data).unwrap();
    let p = ChainParams::regtest();
    let mut m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow,
        Box::new(FileStore::open(data.join("blocks.dat")).unwrap()),
        [3; 32],
    )
    .unwrap();
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x35b);
    let (keys, _) = WalletKeys::generate(&mut rng);
    let mut ids = Vec::new();
    for _ in 0..n {
        let t = m.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: keys.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
            }],
            &keys.hedge_secret(),
            &mut rng,
        )
        .unwrap();
        let txs = vec![Transaction::Coinbase(cb)];
        let hashes: Vec<[u8; 32]> = txs.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(p.genesis.timestamp + p.target_block_time * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&hashes),
            output_count,
            output_root,
            px_root: t.px_root,
            nonce: 0,
        };
        let b = Block { header, txs };
        ids.push(b.id(p.network_id));
        m.submit_block(b, header.timestamp).unwrap();
    }
    ids
}

fn height_of(n: &NodeProc) -> u64 {
    blacksilk_rpc::Client::new(&n.addr.to_string())
        .with_cookie_file(&n.cookie())
        .unwrap()
        .info()
        .unwrap()
        .height
}

/// `--invalidate-block` end to end (docs/testnet.md §9): the binary starts
/// on the block's parent, keeps the verdict on a restart without the flag,
/// and `--reconsider-block` connects the block again. Invalidating genesis
/// and a malformed id stop the node with the configuration status (2)
/// before anything is written.
#[test]
fn the_node_binary_invalidates_and_reconsiders_a_block() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    // Real RandomX hashes: the node re-verifies stored ones at start-up.
    let ids = regtest_store_with(
        &data,
        3,
        std::sync::Arc::new(blacksilk_consensus::RandomXPow::new()),
    );
    let tip = hex::encode(ids[2]);
    let store = data.join("blocks.dat");

    let n = NodeProc::start(&data, &[]);
    assert_eq!(height_of(&n), 3, "log:\n{}", n.log_text());
    drop(n);

    let n = NodeProc::start(&data, &["--invalidate-block", &tip]);
    assert_eq!(height_of(&n), 2, "log:\n{}", n.log_text());
    let log = n.log_text();
    assert!(
        log.contains(&format!("block {tip} at height 3 is marked invalid")),
        "{log}"
    );
    drop(n);
    let len = std::fs::metadata(&store).unwrap().len();

    // The verdict is stored: no flag needed; giving it again writes nothing.
    let n = NodeProc::start(&data, &[]);
    assert_eq!(height_of(&n), 2, "log:\n{}", n.log_text());
    drop(n);
    let n = NodeProc::start(&data, &["--invalidate-block", &tip]);
    assert_eq!(height_of(&n), 2);
    assert!(n.log_text().contains("already marked invalid"));
    drop(n);
    assert_eq!(std::fs::metadata(&store).unwrap().len(), len);

    let n = NodeProc::start(&data, &["--reconsider-block", &tip]);
    assert_eq!(height_of(&n), 3, "log:\n{}", n.log_text());
    drop(n);

    let before = std::fs::read(&store).unwrap();
    let genesis = hex::encode(blacksilk_consensus::ChainParams::regtest().genesis_id());
    for (bad, text) in [(genesis.as_str(), "genesis"), ("12ab", "64 hex characters")] {
        let out = Command::new(NODE)
            .args(["--network", "regtest", "--no-p2p", "--data-dir"])
            .arg(&data)
            .args(["--rpc-bind", &free_port().to_string()])
            .args(["--invalidate-block", bad])
            .output()
            .unwrap();
        let text_out = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(2), "{bad}: {text_out}");
        assert!(text_out.contains(text), "{bad}: {text_out}");
    }
    assert_eq!(std::fs::read(&store).unwrap(), before, "nothing written");
}

// ------------------------------------------------ threat model round 2 (TM2-NODEOPS)

/// Runs the node on `data` with `extra` until it exits, at most `within`
/// (killed then): its exit status (`None` if it was still running) and its
/// log.
fn run_until_exit(
    data: &Path,
    extra: &[&str],
    within: Duration,
) -> (Option<std::process::ExitStatus>, String) {
    run_net_until_exit(data, &["--no-p2p"], extra, within)
}

/// As [`run_until_exit`], with the P2P options `net`.
fn run_net_until_exit(
    data: &Path,
    net: &[&str],
    extra: &[&str],
    within: Duration,
) -> (Option<std::process::ExitStatus>, String) {
    let addr = free_port();
    let log = data.with_extension(format!("{}.exit.log", addr.port()));
    let f = std::fs::File::create(&log).unwrap();
    let mut child = Command::new(NODE)
        .args(["--network", "regtest", "--data-dir"])
        .arg(data)
        .args(["--rpc-bind", &addr.to_string()])
        .args(net)
        .args(extra)
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(f.try_clone().unwrap()))
        .stderr(Stdio::from(f))
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break Some(s);
        }
        if start.elapsed() > within {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    (status, std::fs::read_to_string(&log).unwrap_or_default())
}

/// The `/info` body of a running node, read with its cookie.
fn info_body(n: &NodeProc) -> String {
    let token = std::fs::read_to_string(n.cookie()).unwrap();
    let (status, body) = get(n.addr, "/info", &bearer(&token)).expect("an answer");
    assert_eq!(status, 200, "{body}");
    body
}

fn randomx() -> std::sync::Arc<dyn blacksilk_consensus::PowFunction> {
    std::sync::Arc::new(blacksilk_consensus::RandomXPow::new())
}

/// TM2-3 (decision "Agent 08"): the node hashes the RandomX known answers
/// before it opens its store, and says so; `--skip-randomx-self-test` skips
/// it with a warning and shows in `/info`; `--randomx-self-test` runs only
/// the check (the per-device check) and exits 0 on a match.
#[test]
fn the_node_binary_runs_the_randomx_self_test() {
    let dir = tempfile::tempdir().unwrap();
    let n = NodeProc::start(&dir.path().join("node"), &[]);
    let log = n.log_text();
    assert!(log.contains("RandomX self-test passed"), "{log}");
    assert!(info_body(&n).contains("\"overrides\":[]"));
    drop(n);

    let n = NodeProc::start(&dir.path().join("skip"), &["--skip-randomx-self-test"]);
    let log = n.log_text();
    assert!(!log.contains("RandomX self-test passed"), "{log}");
    assert!(log.contains("--skip-randomx-self-test"), "{log}");
    let body = info_body(&n);
    assert!(
        body.contains("\"overrides\":[\"--skip-randomx-self-test\"]"),
        "{body}"
    );
    drop(n);

    let out = Command::new(NODE)
        .args(["--randomx-self-test"])
        .env("RUST_LOG", "info")
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("RandomX self-test passed"), "{text}");
}

/// TM2-2 and F48-9: `/info` says whether a network pre-shared key is loaded
/// (never the key), and lists the operator overrides of this run and the
/// operator's verdicts in force.
#[test]
fn info_shows_the_psk_state_overrides_and_verdicts() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let ids = regtest_store_with(&data, 3, randomx());
    let tip = hex::encode(ids[2]);
    let n = NodeProc::start(&data, &["--mine-from-stale-tip"]);
    let body = info_body(&n);
    assert!(body.contains("\"network_psk_loaded\":false"), "{body}");
    assert!(
        body.contains("\"overrides\":[\"--mine-from-stale-tip\"]"),
        "{body}"
    );
    assert!(body.contains("\"operator_verdicts\":[]"), "{body}");
    drop(n);
    let n = NodeProc::start(&data, &["--invalidate-block", &tip]);
    let body = info_body(&n);
    assert!(
        body.contains(&format!(
            "\"operator_verdicts\":[{{\"block\":\"{tip}\",\"height\":3}}]"
        )),
        "{body}"
    );
    assert!(
        body.contains(&format!("\"overrides\":[\"--invalidate-block {tip}\"]")),
        "{body}"
    );
    drop(n);
    // The verdict stays in force without the flag.
    let n = NodeProc::start(&data, &[]);
    let body = info_body(&n);
    assert!(body.contains(&format!("\"block\":\"{tip}\"")), "{body}");
    assert!(body.contains("\"overrides\":[]"), "{body}");
}

/// A fixed random network key for the tests below (`openssl rand -hex 32`).
const TEST_PSK: [u8; 32] = [
    0x6a, 0x4d, 0xec, 0xc9, 0x8b, 0x98, 0x15, 0x7a, 0xff, 0xd0, 0xbf, 0x4d, 0x23, 0x88, 0x40, 0x61,
    0x5a, 0xf5, 0x4c, 0x90, 0xa8, 0xd1, 0x64, 0xc8, 0xd8, 0xe6, 0x7e, 0xad, 0xca, 0xe4, 0x08, 0x89,
];

/// RFC 4648 base64 of `data` with the `alphabet`, padded or not.
fn base64(data: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(alphabet[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
        if pad {
            out.extend(std::iter::repeat_n('=', 3 - chunk.len()));
        }
    }
    out
}

/// Every encoding of `key` that `/info` or the log must not hold: its raw
/// bytes, hex in either case, base64 in the standard and URL-safe alphabets
/// with and without padding, and every 8-byte window of the raw bytes and of
/// the hex (a truncated key is still a leak).
fn key_encodings(key: &[u8; 32]) -> Vec<(String, Vec<u8>)> {
    const STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    // RFC 4648 §10 test vectors, and the URL-safe characters.
    assert_eq!(base64(b"fooba", STD, true), "Zm9vYmE=");
    assert_eq!(base64(b"foob", STD, false), "Zm9vYg");
    assert_eq!(base64(&[0xfb, 0xff], STD, true), "+/8=");
    assert_eq!(base64(&[0xfb, 0xff], URL, false), "-_8");
    let lower = hex::encode(key);
    let mut v: Vec<(String, Vec<u8>)> = vec![
        ("raw".into(), key.to_vec()),
        ("hex".into(), lower.clone().into_bytes()),
        ("HEX".into(), lower.to_uppercase().into_bytes()),
    ];
    for (name, alphabet) in [("base64", STD), ("base64url", URL)] {
        for pad in [true, false] {
            v.push((
                format!("{name} pad={pad}"),
                base64(key, alphabet, pad).into_bytes(),
            ));
        }
    }
    for (i, w) in key.windows(8).enumerate() {
        v.push((format!("raw[{i}..{}]", i + 8), w.to_vec()));
        let h = hex::encode(w);
        v.push((format!("hex[{i}..{}]", i + 8), h.clone().into_bytes()));
        v.push((
            format!("HEX[{i}..{}]", i + 8),
            h.to_uppercase().into_bytes(),
        ));
    }
    v
}

fn find(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The whole `/info` response of a running node (status line, headers and
/// body), as raw bytes.
fn info_response(n: &NodeProc) -> Vec<u8> {
    let token = std::fs::read_to_string(n.cookie()).unwrap();
    let mut s = TcpStream::connect(n.addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let req = format!(
        "GET /info HTTP/1.1\r\nHost: {}\r\n{}Connection: close\r\n\r\n",
        n.addr,
        bearer(&token)
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).unwrap();
    assert!(
        resp.starts_with(b"HTTP/1.1 200 "),
        "{}",
        String::from_utf8_lossy(&resp)
    );
    resp
}

/// The names of a JSON object's top-level members, in order.
fn top_level_keys(json: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    let mut current = String::new();
    let mut last_str: Option<String> = None;
    for c in json.trim().chars() {
        if in_str {
            match (esc, c) {
                (true, _) => {
                    esc = false;
                    current.push(c);
                }
                (false, '\\') => esc = true,
                (false, '"') => {
                    in_str = false;
                    last_str = Some(std::mem::take(&mut current));
                }
                (false, _) => current.push(c),
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            ':' if depth == 1 => keys.extend(last_str.take()),
            _ => {}
        }
        if c != '"' && c != ':' && !c.is_whitespace() {
            last_str = None;
        }
    }
    keys
}

/// Writes `TEST_PSK` to `path` as `openssl rand -hex 32` writes it (64 hex
/// characters and a newline). On Unix the file's permission bits are then
/// set to `mode` exactly, whatever the umask; elsewhere `mode` is unused
/// (the node checks the bits on Unix only).
fn write_test_psk(path: &Path, mode: u32) {
    std::fs::write(path, format!("{}\n", hex::encode(TEST_PSK))).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        let set = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(set, mode, "{}", path.display());
    }
    #[cfg(not(unix))]
    let _ = mode;
}

/// The P2P options of a regtest node that dials nobody: a loopback
/// listener, no seeds.
fn quiet_p2p(bind: &str) -> Vec<&str> {
    vec!["--p2p-bind", bind, "--no-builtin-seeds"]
}

/// TM2-2, F48-9, docs/testnet.md §12.3: with a network pre-shared key
/// loaded, `/info` reports `"network_psk_loaded": true` and nothing of the
/// key: not its bytes in any common encoding (nor an 8-byte piece of them),
/// not the key file's path or name, no member that a node without a key
/// does not have; the other members read the same. The start-up log says
/// the key is loaded, without the key, and (the key file being 0600) without
/// its path or name. (`--no-p2p` ignores the key file:
/// the key is P2P configuration, so P2P is on here.)
#[test]
fn info_reports_a_loaded_psk_and_never_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let key_file = dir.path().join("trial-network-key.psk");
    // Owner-only, as docs/testnet.md §12.3 asks: on Unix a key file its
    // group or others can read draws a start-up warning that names the file
    // (`p2p::transport::warn_if_shared`, tested by
    // `a_shared_psk_file_is_named_in_a_warning_but_the_key_never_is`), and a
    // new file under umask 022 is 0644 (CI run 38463712394). With 0600 the
    // path must be absent from the log on every platform.
    write_test_psk(&key_file, 0o600);
    let key_path = key_file.display().to_string();
    let bind = free_port().to_string();
    let info = |n: &NodeProc| {
        blacksilk_rpc::Client::new(&n.addr.to_string())
            .with_cookie_file(&n.cookie())
            .unwrap()
            .info()
            .unwrap()
    };

    // The same node, P2P on, without and then with the key.
    let n = NodeProc::start_net(&data, &quiet_p2p(&bind), &[]);
    let without = String::from_utf8(info_response(&n)).unwrap();
    let info_without = info(&n);
    drop(n);
    let mut net = quiet_p2p(&bind);
    net.extend(["--network-psk-file", &key_path]);
    let n = NodeProc::start_net(&data, &net, &[]);
    let raw = info_response(&n);
    let info_with = info(&n);
    let log = n.log_text();
    drop(n);

    let text = String::from_utf8(raw.clone()).expect("a UTF-8 response");
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    let (_, body_without) = without.split_once("\r\n\r\n").unwrap();
    assert!(body.contains("\"network_psk_loaded\":true"), "{body}");
    assert!(!body.contains("\"network_psk_loaded\":false"), "{body}");
    assert!(
        body_without.contains("\"network_psk_loaded\":false"),
        "{body_without}"
    );
    // The key in no encoding, in the response or the log.
    for (name, needle) in key_encodings(&TEST_PSK) {
        assert!(
            !find(&raw, &needle),
            "/info holds the key ({name}):\n{text}"
        );
        assert!(
            !find(log.as_bytes(), &needle),
            "the log holds the key ({name}):\n{log}"
        );
    }
    // Nor where it is kept, in the response or the start-up log (JSON
    // escapes a Windows path's backslashes).
    for p in [
        key_path.clone(),
        key_path.replace('\\', "\\\\"),
        "trial-network-key".into(),
    ] {
        assert!(
            !text.contains(&p),
            "/info holds the key file's path {p:?}:\n{text}"
        );
        assert!(
            !log.contains(&p),
            "the log holds the key file's path {p:?}:\n{log}"
        );
    }
    // The same members as without a key: nothing added about it.
    let keys = top_level_keys(body);
    assert_eq!(keys, top_level_keys(body_without), "{body}");
    assert!(keys.iter().any(|k| k == "network_psk_loaded"), "{keys:?}");
    assert!(keys.iter().any(|k| k == "overrides"), "{keys:?}");
    assert!(body.contains("\"overrides\":[]"), "{body}");
    assert!(body.contains("\"operator_verdicts\":[]"), "{body}");
    assert_eq!(info_with.network, info_without.network);
    assert_eq!(info_with.height, info_without.height);
    assert_eq!(info_with.tip, info_without.tip);
    assert_eq!(info_with.network_id, info_without.network_id);
    assert_eq!(info_with.genesis_id, info_without.genesis_id);
    assert_eq!((info_with.peers, info_without.peers), (0, 0));
    assert!(
        log.contains("P2P: network pre-shared key loaded; only nodes with it can connect"),
        "{log}"
    );
}

/// docs/testnet.md §12.3, `p2p::transport::warn_if_shared`: on Unix a key
/// file its group or others can read (here 0644, as umask 022 leaves a new
/// file) draws a start-up warning that names the file, gives its mode and
/// says `chmod 600`; the path is operator guidance, the key is never logged.
/// The node still starts with the key loaded, and `/info` holds neither the
/// key in any checked encoding nor the file's path or name.
#[cfg(unix)]
#[test]
fn a_shared_psk_file_is_named_in_a_warning_but_the_key_never_is() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let key_file = dir.path().join("shared-network-key.psk");
    write_test_psk(&key_file, 0o644);
    let key_path = key_file.display().to_string();
    let bind = free_port().to_string();
    let mut net = quiet_p2p(&bind);
    net.extend(["--network-psk-file", &key_path]);
    let n = NodeProc::start_net(&data, &net, &[]);
    let raw = info_response(&n);
    let log = n.log_text();
    drop(n);

    let text = String::from_utf8(raw.clone()).expect("a UTF-8 response");
    let (_, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(body.contains("\"network_psk_loaded\":true"), "{body}");
    let warning = format!(
        "the network key file {key_path} is readable by its group or other users (mode 644); \
         restrict it with `chmod 600`"
    );
    assert!(log.contains(&warning), "{log}");
    assert!(
        log.contains("P2P: network pre-shared key loaded; only nodes with it can connect"),
        "{log}"
    );
    for (name, needle) in key_encodings(&TEST_PSK) {
        assert!(
            !find(&raw, &needle),
            "/info holds the key ({name}):\n{text}"
        );
        assert!(
            !find(log.as_bytes(), &needle),
            "the log holds the key ({name}):\n{log}"
        );
    }
    for p in [key_path.as_str(), "shared-network-key"] {
        assert!(
            !text.contains(p),
            "/info holds the key file's path {p:?}:\n{text}"
        );
    }
}

/// docs/testnet.md §12.3, `NetworkPsk::load`: a missing key file, or one
/// that is not 64 hexadecimal characters of a non-zero key (truncated, all
/// zero, UTF-16 as Windows PowerShell 5.1's `>` writes it), stops the node
/// at start-up with exit status 1, before its RPC opens; the error names the
/// file and never echoes its contents.
#[test]
fn a_bad_network_psk_file_stops_the_node() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let lower = hex::encode(TEST_PSK);
    let utf16: Vec<u8> = std::iter::once(0xfeffu16)
        .chain(lower.encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    let cases: [(&str, Option<Vec<u8>>, &str); 4] = [
        ("missing", None, "cannot read the network key file"),
        (
            "truncated",
            Some(lower.as_bytes()[..62].to_vec()),
            "64 hexadecimal",
        ),
        ("zero", Some([b'0'; 64].to_vec()), "not all zero"),
        ("utf16", Some(utf16), "64 hexadecimal"),
    ];
    for (name, contents, reason) in cases {
        let path = dir.path().join(format!("{name}.psk"));
        if let Some(c) = &contents {
            std::fs::write(&path, c).unwrap();
        }
        let shown = path.display().to_string();
        let bind = free_port().to_string();
        let mut net = quiet_p2p(&bind);
        net.extend(["--network-psk-file", &shown]);
        let (status, log) = run_net_until_exit(&data, &net, &[], Duration::from_secs(120));
        let status = status.unwrap_or_else(|| panic!("{name}: the node started; log:\n{log}"));
        assert_eq!(status.code(), Some(1), "{name}; log:\n{log}");
        assert!(
            log.contains(&format!("network PSK file {shown}: ")),
            "{name}; log:\n{log}"
        );
        assert!(log.contains(reason), "{name}; log:\n{log}");
        assert!(!log.contains("RPC listening"), "{name}; log:\n{log}");
        assert!(!data.join(blacksilk_rpc::COOKIE_FILE).exists(), "{name}");
        // Not even a piece of what the file held.
        for (what, needle) in key_encodings(&TEST_PSK) {
            assert!(
                !find(log.as_bytes(), &needle),
                "{name}: the log holds {what}:\n{log}"
            );
        }
    }
}

/// TM2-5 (decisions "Agent 01"): a block store whose stored proof-of-work
/// hashes its headers do not produce (here a zero hash for every block, as
/// in a store planted by someone who can write the data directory) is
/// refused at start-up, by the sampled check (every block of a short store
/// is in the tip region) and by `--verify-store-pow`. Before the check the
/// node trusted the stored hashes and started on such a store.
#[test]
fn a_store_with_forged_pow_hashes_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    regtest_store(&data, 3);
    let before = std::fs::read(data.join("blocks.dat")).unwrap();
    for extra in [&[][..], &["--verify-store-pow"][..]] {
        let (status, log) = run_until_exit(&data, extra, Duration::from_secs(120));
        let status = status.unwrap_or_else(|| panic!("{extra:?}: the node started; log:\n{log}"));
        assert_eq!(
            status.code(),
            Some(blacksilk_node::STORE_POW_EXIT_CODE),
            "{extra:?}; log:\n{log}"
        );
        assert!(log.contains("proof-of-work"), "{log}");
        assert!(log.contains(&data.display().to_string()), "{log}");
        assert!(log.contains("--verify-store-pow"), "{log}");
    }
    // The store is left as it was (evidence for the incident).
    assert_eq!(std::fs::read(data.join("blocks.dat")).unwrap(), before);
}

/// A store written with the real RandomX hashes passes the check, sampled
/// and in full.
#[test]
fn a_store_with_real_pow_hashes_passes_the_check() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    regtest_store_with(&data, 3, randomx());
    for extra in [&[][..], &["--verify-store-pow"][..]] {
        let n = NodeProc::start(&data, extra);
        assert_eq!(height_of(&n), 3, "log:\n{}", n.log_text());
        let log = n.log_text();
        assert!(
            log.contains("stored proof-of-work hashes re-verified"),
            "{log}"
        );
    }
}

/// TM2-8: SIGTERM (`docker stop`, a plain `kill`) is a clean shutdown like
/// Ctrl-C: the node exits 0 and removes its cookie.
#[cfg(unix)]
#[test]
fn sigterm_is_a_clean_shutdown() {
    let dir = tempfile::tempdir().unwrap();
    let mut n = NodeProc::start(&dir.path().join("node"), &[]);
    let cookie = n.cookie();
    assert!(cookie.exists());
    let st = Command::new("kill")
        .args(["-TERM", &n.child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    let status = n
        .wait_exit(Duration::from_secs(30))
        .expect("the node stops");
    assert!(status.success(), "{status:?}; log:\n{}", n.log_text());
    assert!(!cookie.exists(), "cookie left after SIGTERM");
    assert!(n.log_text().contains("shutting down"));
}

/// TM2-3 data at rest (P-P2, N-3): the data directory is owner-only (0700)
/// and so is every file the node writes there (0600), whatever the umask; a
/// directory and files left too open by an earlier run are tightened at
/// start, with a warning.
#[cfg(unix)]
#[test]
fn the_data_directory_and_its_files_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    regtest_store_with(&data, 1, randomx());
    // As a manual run under umask 022 leaves them.
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    for f in ["blocks.dat", "originated.json", "peers.json"] {
        let p = data.join(f);
        if !p.exists() {
            std::fs::write(&p, b"{}").unwrap();
        }
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let n = NodeProc::start(&data, &[]);
    let log = n.log_text();
    assert!(log.contains("permissions tightened"), "{log}");
    assert_eq!(mode(&data), 0o700);
    for entry in std::fs::read_dir(&data).unwrap() {
        let p = entry.unwrap().path();
        assert_eq!(mode(&p), 0o600, "{}", p.display());
    }
    drop(n);

    // A fresh data directory, nested: every directory the node creates is
    // owner-only.
    let fresh = dir.path().join("a").join("b");
    let n = NodeProc::start_logged(&fresh, Some(&dir.path().join("fresh.log")), &[]);
    assert_eq!(mode(&dir.path().join("a")), 0o700);
    assert_eq!(mode(&fresh), 0o700);
    for entry in std::fs::read_dir(&fresh).unwrap() {
        let p = entry.unwrap().path();
        assert_eq!(mode(&p), 0o600, "{}", p.display());
    }
    drop(n);
}
