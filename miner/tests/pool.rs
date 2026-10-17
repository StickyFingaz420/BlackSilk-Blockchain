//! Pool mode against a fake BlackSilk Pool in process (TCP on loopback):
//! login with the accepted mode and fee, jobs, shares that recompute with
//! light-mode RandomX and meet the job's target, new-job pushes, reconnects,
//! keepalives, refusal of malformed jobs and over-long lines, and refusal to
//! mine when the pool's stated fee or mode differs from the accepted one.
//!
//! Memory: a hashing test holds one light cache in the client and one in
//! the test (2 × 256 MiB); the tests take [`HASHING`] so that at most one
//! such pair exists at a time.

use blacksilk_miner::pool::{self, PoolConfig, PoolError, PoolMode, Summary, Timing};
use blacksilk_miner::{meets_share_target, RandomXBuilder, SeedPlan, SeedPlanner};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

static HASHING: Mutex<()> = Mutex::new(());

const ADDR: &str = "test-payout-address";
const SESSION: &str = "0011223344556677";
const SEED: [u8; 32] = [0x5a; 32];
const NOTICE: &str = "until the pool's first payout snapshot is declared (and during checkpoint gaps), pooled work is share-only";

fn hashing() -> std::sync::MutexGuard<'static, ()> {
    HASHING.lock().unwrap_or_else(|e| e.into_inner())
}

fn timing() -> Timing {
    Timing {
        connect: Duration::from_secs(2),
        login_reply: Duration::from_secs(5),
        keepalive: Duration::from_secs(600),
        silence: Duration::from_secs(60),
        write: Duration::from_secs(5),
        backoff_first: Duration::from_millis(50),
        backoff_max: Duration::from_millis(200),
        stable: Duration::from_secs(600),
    }
}

/// The 47-byte blob of a job: tag, a mining hash of `k`, zero nonce bytes,
/// the extranonce `x`.
fn blob(k: u8, x: u8) -> [u8; 47] {
    let mut b = [0u8; 47];
    b[..7].copy_from_slice(b"BSilk/1");
    b[7..39].copy_from_slice(&[k; 32]);
    b[43..].copy_from_slice(&[x, 0, 0, 0x80]);
    b
}

fn job(id: &str, blob: &[u8], target64: u64) -> Value {
    json!({
        "job_id": id,
        "blob": hex::encode(blob),
        "target": hex::encode(target64.to_le_bytes()),
        "algo": "rx/blacksilk",
        "height": 100,
        "seed_hash": hex::encode(SEED),
    })
}

fn confirmation(mode: &str, fee_bp: u64) -> Value {
    json!({"mode": mode, "fee_bp": fee_bp, "policy_version": 1, "notice": NOTICE})
}

fn login_reply(job: Value, blacksilk: Option<Value>) -> Value {
    let mut result = json!({
        "id": SESSION,
        "status": "OK",
        "extensions": ["algo", "keepalive"],
        "job": job,
    });
    if let Some(b) = blacksilk {
        result["blacksilk"] = b;
    }
    json!({"id": 1, "jsonrpc": "2.0", "error": null, "result": result})
}

struct FakePool {
    listener: TcpListener,
}

struct Conn {
    r: BufReader<TcpStream>,
    w: TcpStream,
}

impl FakePool {
    fn new() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        FakePool { listener }
    }

    fn addr(&self) -> String {
        self.listener.local_addr().unwrap().to_string()
    }

    /// The next connection, within 10 s.
    fn accept(&self) -> Conn {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match self.listener.accept() {
                Ok((s, _)) => {
                    s.set_nonblocking(false).unwrap();
                    s.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
                    return Conn {
                        r: BufReader::new(s.try_clone().unwrap()),
                        w: s,
                    };
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "no connection from the miner");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => panic!("accept: {e}"),
            }
        }
    }
}

impl Conn {
    /// The next message; `None` once the miner closed the connection.
    fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.r.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(serde_json::from_str(&line).expect("the miner sends JSON")),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => None,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionAborted => None,
            Err(e) => panic!("reading from the miner: {e}"),
        }
    }

    fn send(&mut self, v: &Value) {
        self.send_raw(&v.to_string());
    }

    fn send_raw(&mut self, line: &str) {
        self.w.write_all(line.as_bytes()).unwrap();
        self.w.write_all(b"\n").unwrap();
    }

    /// Reads the login request and checks it.
    fn login(&mut self, pass: &str) {
        let m = self.recv().expect("a login request");
        assert_eq!(m["method"], "login", "{m}");
        assert_eq!(m["id"], 1);
        assert_eq!(m["params"]["login"], ADDR);
        assert_eq!(m["params"]["pass"], pass);
        assert_eq!(m["params"]["algo"], json!(["rx/blacksilk"]));
        let agent = m["params"]["agent"].as_str().unwrap();
        assert!(agent.starts_with("blacksilk-miner/"), "{agent}");
    }

    /// The next submit (keepalives are answered on the way).
    fn submit(&mut self) -> Value {
        loop {
            let m = self.recv().expect("a submit");
            match m["method"].as_str() {
                Some("submit") => return m,
                Some("keepalived") => self.reply_ok(&m, "KEEPALIVED"),
                _ => panic!("unexpected {m}"),
            }
        }
    }

    fn reply_ok(&mut self, req: &Value, status: &str) {
        self.send(&json!({"id": req["id"], "jsonrpc": "2.0", "error": null,
                          "result": {"status": status}}));
    }

    fn reply_error(&mut self, id: Value, message: &str) {
        self.send(&json!({"id": id, "jsonrpc": "2.0",
                          "error": {"code": -1, "message": message}, "result": null}));
    }

    /// Reads until the miner closes the connection, within `within`;
    /// panics on any submit.
    fn expect_closed(&mut self, within: Duration) {
        self.r.get_ref().set_read_timeout(Some(within)).unwrap();
        while let Some(m) = self.recv() {
            assert_ne!(
                m["method"], "submit",
                "a share after the session ended: {m}"
            );
        }
    }

    fn close(self) {
        let _ = self.w.shutdown(Shutdown::Both);
    }
}

/// Checks a submit: session, job, formats, and that the result is the
/// light-mode RandomX hash of `blob` with the nonce and meets the target.
fn check_share(m: &Value, job_id: &str, blob: &[u8; 47], target64: u64, vm: &mut Verifier) {
    let p = &m["params"];
    assert_eq!(p["id"], SESSION, "{m}");
    assert_eq!(p["job_id"], job_id, "{m}");
    assert_eq!(p["algo"], "rx/blacksilk");
    let nonce = hex::decode(p["nonce"].as_str().unwrap()).unwrap();
    assert_eq!(nonce.len(), 4, "{m}");
    let result: [u8; 32] = hex::decode(p["result"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut b = *blob;
    b[39..43].copy_from_slice(&nonce);
    let h = vm.hash(&b);
    assert_eq!(h, result, "the submitted result recomputes");
    assert!(meets_share_target(&h, target64), "{m}");
}

/// The test's own light-mode RandomX for the key [`SEED`].
struct Verifier {
    cache: blacksilk_randomx::Cache,
}

impl Verifier {
    fn new() -> Self {
        Verifier {
            cache: blacksilk_randomx::Cache::new(&SEED),
        }
    }
    fn hash(&mut self, b: &[u8]) -> [u8; 32] {
        blacksilk_randomx::Vm::light(&self.cache).hash(b)
    }
}

type Client = (JoinHandle<Result<Summary, PoolError>>, Arc<AtomicBool>);

fn start(addr: String, mode: PoolMode, fee_bp: u16, timing: Timing) -> Client {
    let cfg = PoolConfig {
        pool: addr,
        login: ADDR.into(),
        mode,
        fee_bp,
        agent: "blacksilk-miner/test".into(),
        threads: 1,
        timing,
    };
    let planner = SeedPlanner::new(
        RandomXBuilder {
            threads: 1,
            first_threads: 1,
        },
        SeedPlan {
            full: false,
            prebuild: false,
            fallback: false,
        },
    );
    let stop = Arc::new(AtomicBool::new(false));
    let s = stop.clone();
    (std::thread::spawn(move || pool::run(cfg, planner, s)), stop)
}

fn finish((handle, stop): Client) -> Result<Summary, PoolError> {
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("the client thread")
}

/// Login, shares on the first job, a pushed job (new mining hash and
/// extranonce), then a dropped connection: the miner reconnects, logs in
/// again and mines the new session's job only.
#[test]
fn login_jobs_submits_and_reconnect() {
    let _g = hashing();
    let pool = FakePool::new();
    let client = start(pool.addr(), PoolMode::Pooled, 200, timing());
    let mut vm = Verifier::new();
    // Difficulty 2: about one hash in two is a share.
    let target = u64::MAX / 2;

    let mut c = pool.accept();
    c.login("mode=pooled;fee=200");
    let b1 = blob(1, 1);
    c.send(&login_reply(
        job("1", &b1, target),
        Some(confirmation("pooled", 200)),
    ));
    for _ in 0..3 {
        let m = c.submit();
        check_share(&m, "1", &b1, target, &mut vm);
        c.reply_ok(&m, "OK");
    }
    let b2 = blob(2, 2);
    c.send(&json!({"jsonrpc": "2.0", "method": "job", "params": job("2", &b2, target)}));
    let mut on_two = 0;
    while on_two < 2 {
        let m = c.submit();
        if m["params"]["job_id"] == "2" {
            check_share(&m, "2", &b2, target, &mut vm);
            on_two += 1;
        } else {
            // A share found just before the push, on the previous job.
            check_share(&m, "1", &b1, target, &mut vm);
        }
        c.reply_error(m["id"].clone(), "Stale job");
    }
    c.close();

    let mut c = pool.accept();
    c.login("mode=pooled;fee=200");
    let b3 = blob(3, 3);
    c.send(&login_reply(
        job("3", &b3, target),
        Some(confirmation("pooled", 200)),
    ));
    let m = c.submit();
    check_share(&m, "3", &b3, target, &mut vm);
    c.reply_ok(&m, "OK");

    let s = finish(client).expect("stopped cleanly");
    assert_eq!(s.logins, 2, "{s:?}");
    assert!(s.accepted >= 4 && s.rejected >= 2, "{s:?}");
}

/// A malformed job (wrong blob length), a login reply whose job has another
/// algorithm and an over-long line each end the session without a share on
/// them, and the miner reconnects each time.
#[test]
fn malformed_pool_messages_end_the_session() {
    let _g = hashing();
    let pool = FakePool::new();
    let client = start(pool.addr(), PoolMode::Solo, 300, timing());
    // A target no hash meets in practice: no shares on the valid job.
    let hard = 1;

    let mut c = pool.accept();
    c.login("mode=solo;fee=300");
    c.send(&login_reply(
        job("1", &blob(1, 1), hard),
        Some(confirmation("solo", 300)),
    ));
    let mut short = job("2", &blob(2, 2), u64::MAX);
    short["blob"] = json!(hex::encode(&blob(2, 2)[..46]));
    c.send(&json!({"jsonrpc": "2.0", "method": "job", "params": short}));
    c.expect_closed(Duration::from_secs(10));

    let mut c = pool.accept();
    c.login("mode=solo;fee=300");
    let mut other = job("3", &blob(3, 3), u64::MAX);
    other["algo"] = json!("rx/0");
    c.send(&login_reply(other, Some(confirmation("solo", 300))));
    c.expect_closed(Duration::from_secs(10));

    let mut c = pool.accept();
    c.login("mode=solo;fee=300");
    c.send(&login_reply(
        job("4", &blob(4, 4), hard),
        Some(confirmation("solo", 300)),
    ));
    c.send_raw(&"x".repeat(pool::MAX_LINE + 1));
    c.expect_closed(Duration::from_secs(10));

    let mut c = pool.accept();
    c.login("mode=solo;fee=300");
    let s = finish(client).expect("stopped cleanly");
    // The login whose job has another algorithm is refused, not counted.
    assert_eq!((s.logins, s.submitted), (2, 0), "{s:?}");
    c.expect_closed(Duration::from_secs(10));
}

/// Keepalives carry the session id once the client has sent nothing for
/// the keepalive interval.
#[test]
fn keepalives_keep_the_session() {
    let _g = hashing();
    let pool = FakePool::new();
    let t = Timing {
        keepalive: Duration::from_millis(200),
        ..timing()
    };
    let client = start(pool.addr(), PoolMode::Solo, 300, t);
    let mut c = pool.accept();
    c.login("mode=solo;fee=300");
    c.send(&login_reply(
        job("1", &blob(1, 1), 1),
        Some(confirmation("solo", 300)),
    ));
    for _ in 0..2 {
        let m = c.recv().expect("a keepalive");
        assert_eq!(m["method"], "keepalived", "{m}");
        assert_eq!(m["params"]["id"], SESSION);
        c.reply_ok(&m, "KEEPALIVED");
    }
    let s = finish(client).expect("stopped cleanly");
    assert_eq!(s.logins, 1);
}

/// The fee and the mode are explicit: a pool that states another fee or
/// mode than the accepted one, states none, or refuses the confirmation is
/// a configuration error, and nothing is mined. A transient refusal (`No
/// work available`) is retried instead.
#[test]
fn a_fee_or_mode_mismatch_refuses_to_mine() {
    let cases: [(Option<Value>, &str); 4] = [
        (Some(confirmation("pooled", 300)), "refusing to mine"),
        (Some(confirmation("solo", 200)), "refusing to mine"),
        (None, "no `blacksilk` object"),
        (None, "Fee mismatch"),
    ];
    for (i, (confirm, expect)) in cases.into_iter().enumerate() {
        let pool = FakePool::new();
        let (handle, _stop) = start(pool.addr(), PoolMode::Pooled, 200, timing());
        let mut c = pool.accept();
        c.login("mode=pooled;fee=200");
        if expect == "Fee mismatch" {
            c.reply_error(json!(1), "Fee mismatch: pooled fee is 250 bp (policy 1)");
        } else {
            c.send(&login_reply(job("1", &blob(1, 1), u64::MAX), confirm));
        }
        match handle.join().unwrap() {
            Err(PoolError::Config(e)) => assert!(e.contains(expect), "case {i}: {e}"),
            other => panic!("case {i}: {other:?}"),
        }
        c.expect_closed(Duration::from_secs(10));
    }

    let pool = FakePool::new();
    let client = start(pool.addr(), PoolMode::Pooled, 200, timing());
    let mut c = pool.accept();
    c.login("mode=pooled;fee=200");
    c.reply_error(json!(1), "No work available");
    let mut c2 = pool.accept();
    c2.login("mode=pooled;fee=200");
    let s = finish(client).expect("a transient refusal is retried");
    assert_eq!(s.logins, 0);
    let mut rest = Vec::new();
    let _ = c.r.read_to_end(&mut rest);
}
