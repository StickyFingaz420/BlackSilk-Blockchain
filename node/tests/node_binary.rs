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
        let addr = free_port();
        let log = log.map_or_else(
            || data.with_extension(format!("{}.log", addr.port())),
            Path::to_path_buf,
        );
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
    fn pow_hash(&self, _: &[u8; 32], _: &[u8]) -> [u8; 32] {
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
        let header = BlockHeader {
            version: t.version,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(p.genesis.timestamp + p.target_block_time * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&hashes),
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
    let addr = free_port();
    let log = data.with_extension(format!("{}.exit.log", addr.port()));
    let f = std::fs::File::create(&log).unwrap();
    let mut child = Command::new(NODE)
        .args(["--network", "regtest", "--no-p2p", "--data-dir"])
        .arg(data)
        .args(["--rpc-bind", &addr.to_string()])
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
