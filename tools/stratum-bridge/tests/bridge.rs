//! The bridge against an in-process regtest node (chain manager, the node's
//! own router, `axum::serve`), with a fake proof of work.
//!
//! The SAME fake PoW instance (`FakePow`) is given to the node and to the
//! bridge, and the test client computes the same function: so these tests
//! check the bridge's protocol, checks and node round trip, not RandomX
//! (tests/real_pow.rs does, with the node's real `RandomXPow`).
//!
//! The client here is written independently of the bridge's helpers: it
//! writes its nonce as raw bytes at blob 39..43 and sends those bytes as hex.

use blacksilk_chain::address::encode_address;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::hash::H;
use blacksilk_consensus::{check_hash, ChainParams, Hash, Network, PowBlob, PowFunction};
use blacksilk_crypto::keys::{Address, SubaddressIndex, WalletKeys};
use blacksilk_node::{router, Shared};
use blacksilk_rpc::Client;
use blacksilk_stratum_bridge::recompute::{recompute, Options, VariantHasher};
use blacksilk_stratum_bridge::submit_log;
use blacksilk_stratum_bridge::{probe, Bridge, Config, ControlHash, StartError};
use blacksilk_tx::params::TxRules;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

// ------------------------------------------------------------- fake PoW

fn fake_hash(seed: &Hash, blob: &PowBlob) -> Hash {
    H::new().chain(b"fake-pow").chain(seed).chain(blob).finish()
}

fn fake_rx0(seed: &Hash, blob: &PowBlob) -> Hash {
    H::new().chain(b"fake-rx0").chain(seed).chain(blob).finish()
}

/// The fake proof of work of the node and the bridge. While `hold` is set,
/// every hash waits (to fill the bridge's queue); `entered` counts calls.
#[derive(Default)]
struct FakePow {
    hold: Mutex<bool>,
    cv: Condvar,
    entered: AtomicU64,
}

impl FakePow {
    fn set_hold(&self, on: bool) {
        *self.hold.lock().unwrap() = on;
        self.cv.notify_all();
    }
}

impl PowFunction for FakePow {
    fn pow_hash(&self, seed: &Hash, blob: &PowBlob) -> Hash {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let mut held = self.hold.lock().unwrap();
        while *held {
            held = self.cv.wait(held).unwrap();
        }
        fake_hash(seed, blob)
    }
}

struct FakeRx0;
impl ControlHash for FakeRx0 {
    fn rx0_hash(&self, seed: &Hash, blob: &PowBlob) -> Hash {
        fake_rx0(seed, blob)
    }
}

// ------------------------------------------------------------------ node

struct Node {
    _rt: tokio::runtime::Runtime,
    addr: SocketAddr,
    client: Client,
    pow: Arc<FakePow>,
    rng: ChaCha20Rng,
}

fn params_with_difficulty(d: u64) -> ChainParams {
    let mut p = ChainParams::regtest();
    p.initial_difficulty = d;
    p.genesis.difficulty = d;
    p
}

impl Node {
    fn start(params: ChainParams) -> Self {
        let pow = Arc::new(FakePow::default());
        let rules = TxRules::for_chain(&params);
        let manager = ChainManager::open(
            params,
            rules,
            pow.clone(),
            Box::<MemoryStore>::default(),
            [3; 32],
        )
        .unwrap();
        let shared: Shared = Arc::new(Mutex::new(manager));
        let rt = tokio::runtime::Runtime::new().unwrap();
        let listener = rt
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let app = router(shared);
        rt.spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            _rt: rt,
            addr,
            client: Client::new(&addr.to_string()),
            pow,
            rng: ChaCha20Rng::seed_from_u64(5),
        }
    }

    fn height(&self) -> u64 {
        self.client.info().unwrap().height
    }

    fn tip(&self) -> String {
        self.client.info().unwrap().tip
    }

    /// Mines one block straight to the node (not through the bridge), at
    /// the template's earliest timestamp (fast blocks raise the difficulty).
    fn mine_direct(&mut self) {
        let t = self.client.template().unwrap();
        let mut b =
            blacksilk_miner::build_block(&t, &payout(), &[9; 32], t.min_timestamp, &mut self.rng)
                .unwrap();
        let seed: Hash = hex::decode(&t.seed_id).unwrap().try_into().unwrap();
        let nid = ChainParams::regtest().network_id;
        while !check_hash(&fake_hash(&seed, &b.header.pow_blob(nid)), t.difficulty) {
            b.header.nonce += 1;
        }
        let r = self.client.submit_block(&b.encode()).unwrap();
        assert!(r.accepted, "{:?}", r.error);
    }
}

fn payout() -> Address {
    WalletKeys::from_seed(&[7; 32]).address(SubaddressIndex::PRIMARY)
}

fn config(node: &Node) -> Config {
    let mut c = Config::new(
        &node.addr.to_string(),
        &encode_address(Network::Regtest, &payout()),
    );
    c.listen = "127.0.0.1:0".parse().unwrap();
    c
}

fn bridge(node: &Node, c: Config) -> Bridge {
    Bridge::start_with(c, node.pow.clone(), Arc::new(FakeRx0)).unwrap()
}

fn wait_until(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(60);
    while !f() {
        assert!(Instant::now() < end, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn temp_file(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("bs-stratum-bridge-{}-{name}", std::process::id()));
    let _ = std::fs::remove_file(&p);
    p
}

// ---------------------------------------------------------------- client

const XMRIG_AGENT: &str = "XMRig/6.26.0 (test) libuv/1.51.0";

/// A stratum client written apart from the bridge's code.
struct Fake {
    r: BufReader<TcpStream>,
    w: TcpStream,
    next: u64,
    replies: HashMap<u64, Value>,
    jobs: VecDeque<Value>,
    session: String,
    job: Value,
}

/// The 4 bytes xmrig writes at blob 39..43 for nonce `n` (little-endian),
/// as 8 hex characters.
fn nonce_hex(n: u32) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff,
        n >> 24
    )
}

impl Fake {
    fn connect(addr: SocketAddr) -> Self {
        let s = TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
        Self {
            w: s.try_clone().unwrap(),
            r: BufReader::new(s),
            next: 1,
            replies: HashMap::new(),
            jobs: VecDeque::new(),
            session: String::new(),
            job: Value::Null,
        }
    }

    fn raw(&mut self, line: &str) {
        self.w.write_all(line.as_bytes()).unwrap();
        self.w.write_all(b"\n").unwrap();
    }

    /// Reads one line; `None` at the end of the connection.
    fn read(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.r.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => {
                let v: Value = serde_json::from_str(line.trim_end()).unwrap();
                if v["method"] == "job" {
                    self.jobs.push_back(v["params"].clone());
                } else if let Some(id) = v["id"].as_u64() {
                    self.replies.insert(id, v.clone());
                }
                Some(v)
            }
        }
    }

    fn send(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next;
        self.next += 1;
        let line = json!({"id": id, "jsonrpc": "2.0", "method": method, "params": params});
        self.raw(&line.to_string());
        id
    }

    fn reply(&mut self, id: u64) -> Value {
        loop {
            if let Some(v) = self.replies.remove(&id) {
                return v;
            }
            self.read().expect("connection closed before the reply");
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        let id = self.send(method, params);
        self.reply(id)
    }

    fn login_as(&mut self, agent: &str, algo: &[&str], pass: &str) -> Value {
        let r = self.call(
            "login",
            json!({"login": "x", "pass": pass, "agent": agent, "algo": algo}),
        );
        if r["error"].is_null() {
            self.session = r["result"]["id"].as_str().unwrap().to_string();
            self.job = r["result"]["job"].clone();
        }
        r
    }

    fn login(&mut self) -> Value {
        self.login_as(XMRIG_AGENT, &["rx/blacksilk", "rx/0"], "x")
    }

    fn submit_raw(&mut self, params: Value) -> Result<String, String> {
        outcome(&self.call("submit", params))
    }

    fn submit_on(&mut self, job: &Value, nonce: &str, result: &str) -> Result<String, String> {
        let p = json!({
            "id": self.session, "job_id": job["job_id"], "nonce": nonce,
            "result": result, "algo": job["algo"],
        });
        self.submit_raw(p)
    }

    fn submit(&mut self, nonce: &str, result: &str) -> Result<String, String> {
        let job = self.job.clone();
        self.submit_on(&job, nonce, result)
    }

    /// Takes queued job notifications; the latest becomes the job.
    fn drain(&mut self) -> bool {
        let mut any = false;
        while let Some(j) = self.jobs.pop_front() {
            self.job = j;
            any = true;
        }
        any
    }

    fn wait_job(&mut self) {
        while !self.drain() {
            self.read()
                .expect("connection closed while waiting for a job");
        }
    }

    fn closed(&mut self) -> bool {
        loop {
            match self.read() {
                None => return true,
                Some(v) if v["method"] == "job" => continue,
                Some(_) => return false,
            }
        }
    }
}

fn outcome(r: &Value) -> Result<String, String> {
    match r["error"]["message"].as_str() {
        Some(m) => Err(m.to_string()),
        None => Ok(r["result"]["status"].as_str().unwrap().to_string()),
    }
}

fn job_seed(job: &Value) -> Hash {
    hex::decode(job["seed_hash"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

/// The fake hash of `job`'s blob with nonce `n` written at 39..43.
fn client_hash(job: &Value, n: u32) -> Hash {
    let mut blob: PowBlob = hex::decode(job["blob"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    blob[39] = (n & 0xff) as u8;
    blob[40] = ((n >> 8) & 0xff) as u8;
    blob[41] = ((n >> 16) & 0xff) as u8;
    blob[42] = (n >> 24) as u8;
    fake_hash(&job_seed(job), &blob)
}

/// The first nonce from `start` whose hash satisfies `pred`.
fn find(job: &Value, start: u32, pred: impl Fn(&Hash) -> bool) -> (u32, Hash) {
    let mut n = start;
    loop {
        let h = client_hash(job, n);
        if pred(&h) {
            return (n, h);
        }
        n = n.wrapping_add(1);
    }
}

fn target_of(job: &Value) -> u64 {
    let b = hex::decode(job["target"].as_str().unwrap()).unwrap();
    u64::from_le_bytes(b.try_into().unwrap())
}

// ----------------------------------------------------------------- tests

/// Login reply and job shape: no `sig_key`, a 94-hex blob starting with
/// "BSilk/1" whose bytes 39..43 are zero, the template's seed and height,
/// a 16-hex target; keepalive and unknown methods.
#[test]
fn login_and_job_shape() {
    let node = Node::start(ChainParams::regtest());
    let mut c = config(&node);
    c.min_share_diff = 1000;
    let b = bridge(&node, c);
    let mut f = Fake::connect(b.local_addr());
    let r = f.login();
    assert!(r["error"].is_null(), "{r}");
    let res = &r["result"];
    assert_eq!(res["status"], "OK");
    assert_eq!(res["extensions"], json!(["algo", "keepalive"]));
    let id = res["id"].as_str().unwrap();
    assert_eq!(id.len(), 8);
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    let job = res["job"].as_object().unwrap();
    let mut keys: Vec<&str> = job.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(
        keys,
        ["algo", "blob", "height", "job_id", "seed_hash", "target"],
        "no sig_key, nothing else"
    );
    let blob = job["blob"].as_str().unwrap();
    assert_eq!(blob.len(), 94);
    assert!(blob.starts_with("4253696c6b2f31"), "BSilk/1");
    assert_eq!(&blob[78..86], "00000000", "bytes 39..43 are zero");
    let t = node.client.template().unwrap();
    assert_eq!(job["seed_hash"], json!(t.seed_id));
    assert_eq!(job["height"], json!(t.height));
    assert_eq!(job["algo"], "rx/blacksilk");
    let target = job["target"].as_str().unwrap();
    assert_eq!(target.len(), 16);
    assert_eq!(
        target,
        blacksilk_stratum_bridge::target::target_hex(1000),
        "max(block difficulty 1, floor 1000)"
    );
    let k = f.call("keepalived", json!({"id": f.session}));
    assert_eq!(k["result"]["status"], "KEEPALIVED");
    let u = f.call("getjob", json!({}));
    assert_eq!(u["error"]["message"], "Unsupported method");
    // A second session gets another extranonce.
    let mut g = Fake::connect(b.local_addr());
    g.login();
    assert_ne!(&g.job["blob"].as_str().unwrap()[86..94], &blob[86..94]);
    assert_eq!(&g.job["blob"].as_str().unwrap()[..78], &blob[..78]);
}

#[test]
fn login_refusals() {
    let node = Node::start(ChainParams::regtest());
    let b = bridge(&node, config(&node));
    let mut f = Fake::connect(b.local_addr());
    let r = f.login_as(XMRIG_AGENT, &["rx/0", "rx/2"], "x");
    assert_eq!(r["error"]["message"], "Unsupported algo");
    let r = f.login_as(XMRIG_AGENT, &["rx/blacksilk"], "diff=1");
    assert_eq!(r["error"]["message"], "Session difficulty not allowed");
    let s = f.call("submit", json!({}));
    assert_eq!(s["error"]["message"], "Not logged in");
    assert!(f.login()["error"].is_null());
    let again = f.login();
    assert_eq!(again["error"]["message"], "Already logged in");
}

/// Every rejection with its exact reply, the tip unchanged and the session
/// still open; then a wrong session id closes it, and so does an over-long
/// line.
#[test]
fn rejections_have_exact_replies() {
    let node = Node::start(ChainParams::regtest());
    let b = bridge(&node, config(&node));
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let tip = node.tip();
    let job = f.job.clone();
    let good = |n| hex::encode(client_hash(&job, n));
    let cases: Vec<(Value, &str)> = vec![
        (
            json!({"id": f.session, "job_id": "999999", "nonce": nonce_hex(1), "result": good(1), "algo": "rx/blacksilk"}),
            "Stale job",
        ),
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(1), "result": good(1), "algo": "rx/0"}),
            "Invalid algo",
        ),
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(1), "result": good(1)}),
            "Invalid algo",
        ),
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": "zz000000", "result": good(1), "algo": "rx/blacksilk"}),
            "Invalid nonce",
        ),
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": "0100000", "result": good(1), "algo": "rx/blacksilk"}),
            "Invalid nonce",
        ),
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(1), "result": &good(1)[1..], "algo": "rx/blacksilk"}),
            "Invalid result",
        ),
        // A wrong nonce with the right result of another nonce.
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(2), "result": good(1), "algo": "rx/blacksilk"}),
            "Invalid result",
        ),
        // A random result.
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(3), "result": "ab".repeat(32), "algo": "rx/blacksilk"}),
            "Invalid result",
        ),
        // The same share again: a duplicate (job still current).
        (
            json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(3), "result": "ab".repeat(32), "algo": "rx/blacksilk"}),
            "Duplicate share",
        ),
    ];
    for (p, want) in cases {
        assert_eq!(f.submit_raw(p.clone()), Err(want.to_string()), "{p}");
        assert_eq!(node.tip(), tip, "{p}");
    }
    assert_eq!(
        f.call("keepalived", json!({"id": f.session}))["result"]["status"],
        "KEEPALIVED"
    );
    let stats = b.stats();
    assert_eq!(stats.get("blocks_submitted"), None);
    assert_eq!(stats["invalid_result"], 2);
    // A wrong session id: Unauthenticated, and the session is closed.
    let r = f.submit_raw(json!({"id": "deadbeef", "job_id": job["job_id"], "nonce": nonce_hex(4), "result": good(4), "algo": "rx/blacksilk"}));
    assert_eq!(r, Err("Unauthenticated".into()));
    assert!(f.closed());
    // An over-long line closes the connection.
    let mut g = Fake::connect(b.local_addr());
    g.login();
    g.raw(&"x".repeat(20_000));
    let r = g.read().unwrap();
    assert_eq!(r["error"]["message"], "Line too long");
    assert!(g.closed());
    // Malformed JSON keeps the session.
    let mut h = Fake::connect(b.local_addr());
    h.login();
    h.raw("{not json");
    assert_eq!(h.read().unwrap()["error"]["message"], "Malformed request");
    assert_eq!(
        h.call("keepalived", json!({"id": h.session}))["result"]["status"],
        "KEEPALIVED"
    );
    assert_eq!(node.tip(), tip);
}

/// A valid share: OK only after the node accepted the block; the tip
/// advances, a new job arrives, and the old job's share is then stale.
#[test]
fn a_valid_share_is_a_block_and_then_stale() {
    let node = Node::start(ChainParams::regtest());
    let b = bridge(&node, config(&node));
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let job = f.job.clone();
    let (n, h) = find(&job, 0x1234, |_| true);
    let h0 = node.height();
    assert_eq!(f.submit(&nonce_hex(n), &hex::encode(h)), Ok("OK".into()));
    assert_eq!(node.height(), h0 + 1);
    assert_eq!(b.stats()["ok"], 1);
    f.wait_job();
    assert_ne!(f.job["job_id"], job["job_id"]);
    assert_eq!(
        f.job["height"],
        json!(h0 + 2),
        "the template after the new block"
    );
    // The same share on its old job: the tip has moved.
    let (m, hm) = find(&job, 0x9999, |_| true);
    assert_eq!(
        f.submit_on(&job, &nonce_hex(m), &hex::encode(hm)),
        Err("Stale job".into())
    );
    assert_eq!(
        f.submit_on(&job, &nonce_hex(n), &hex::encode(h)),
        Err("Stale job".into())
    );
    // Another session's job is stale for this one (jobs are per session).
    let mut g = Fake::connect(b.local_addr());
    g.login();
    let other = g.job.clone();
    let (k, hk) = find(&other, 7, |_| true);
    assert_eq!(
        f.submit_on(&other, &nonce_hex(k), &hex::encode(hk)),
        Err("Stale job".into())
    );
    assert_eq!(node.height(), h0 + 1);
}

/// Initial difficulty 16 and a share floor of 1000: the job's target is the
/// floor's, but a share is decided by the block's difficulty: a hash that
/// fails 16 is `Low difficulty share` (then `Duplicate share`), and a hash
/// that meets 16 is a block even though it misses the floor's target.
#[test]
fn block_difficulty_decides() {
    let node = Node::start(params_with_difficulty(16));
    let mut c = config(&node);
    c.min_share_diff = 1000;
    let b = bridge(&node, c);
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let job = f.job.clone();
    let t1000 = blacksilk_stratum_bridge::target::target64(1000);
    assert_eq!(target_of(&job), t1000);
    let tip = node.tip();
    let (n, h) = find(&job, 0, |h| !check_hash(h, 16));
    assert_eq!(
        f.submit(&nonce_hex(n), &hex::encode(h)),
        Err("Low difficulty share".into())
    );
    assert_eq!(
        f.submit(&nonce_hex(n), &hex::encode(h)),
        Err("Duplicate share".into())
    );
    assert_eq!(node.tip(), tip);
    let (m, hm) = find(&job, 0, |h| {
        check_hash(h, 16) && !blacksilk_stratum_bridge::target::xmrig_would_submit(h, t1000)
    });
    assert_eq!(f.submit(&nonce_hex(m), &hex::encode(hm)), Ok("OK".into()));
    assert_ne!(node.tip(), tip);
}

/// The block difficulty changes within one session (LWMA after fast
/// blocks): the share difficulty is per job, the new job's target follows
/// it, and shares are judged against the new difficulty.
#[test]
fn block_difficulty_changes_within_a_session() {
    let mut node = Node::start(ChainParams::regtest());
    let b = bridge(&node, config(&node));
    let mut f = Fake::connect(b.local_addr());
    f.login();
    assert_eq!(target_of(&f.job), u64::MAX, "difficulty 1");
    let mut d = 1;
    for _ in 0..400 {
        node.mine_direct();
        // One job per block: wait for the bridge, then take its job (the
        // socket buffer never fills).
        let tip = node.tip();
        wait_until("the bridge's work at the new tip", || {
            b.current_tip().map(hex::encode) == Some(tip.clone())
        });
        f.wait_job();
        d = node.client.template().unwrap().difficulty;
        if d > 1 {
            break;
        }
    }
    assert!(d > 1, "the difficulty never rose");
    let tip = node.tip();
    wait_until("the bridge's work at the new tip", || {
        b.current_tip().map(hex::encode) == Some(tip.clone())
    });
    // The last job notification is for the new work.
    let expected = json!(node.height() + 1);
    while f.job["height"] != expected {
        f.wait_job();
    }
    let job = f.job.clone();
    assert_eq!(
        target_of(&job),
        blacksilk_stratum_bridge::target::target64(d)
    );
    let (n, h) = find(&job, 0, |h| !check_hash(h, d));
    assert_eq!(
        f.submit(&nonce_hex(n), &hex::encode(h)),
        Err("Low difficulty share".into())
    );
    let (m, hm) = find(&job, 0, |h| check_hash(h, d));
    assert_eq!(f.submit(&nonce_hex(m), &hex::encode(hm)), Ok("OK".into()));
}

/// A full queue answers `Busy` and does not record the share: sent again, it
/// is verified (and is a block), not a `Duplicate share`.
#[test]
fn busy_then_the_same_share_is_verified() {
    let node = Node::start(ChainParams::regtest());
    let mut c = config(&node);
    c.queue_capacity = 1;
    let b = bridge(&node, c);
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let job = f.job.clone();
    let p = |n: u32, r: String| json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(n), "result": r, "algo": "rx/blacksilk"});
    let (good_n, good_h) = find(&job, 500, |_| true);
    let (pa, pb, pc) = (
        p(1, "11".repeat(32)),
        p(2, "22".repeat(32)),
        p(good_n, hex::encode(good_h)),
    );
    node.pow.set_hold(true);
    let before = node.pow.entered.load(Ordering::SeqCst);
    let ia = f.send("submit", pa);
    // A is in the verifier (hashing, held); B fills the queue of 1.
    wait_until("the verifier to take A", || {
        node.pow.entered.load(Ordering::SeqCst) > before
    });
    let ib = f.send("submit", pb);
    let ic = f.send("submit", pc.clone());
    assert_eq!(outcome(&f.reply(ic)), Err("Busy".into()));
    node.pow.set_hold(false);
    assert_eq!(outcome(&f.reply(ia)), Err("Invalid result".into()));
    assert_eq!(outcome(&f.reply(ib)), Err("Invalid result".into()));
    let h0 = node.height();
    assert_eq!(f.submit_raw(pc), Ok("OK".into()));
    assert_eq!(node.height(), h0 + 1);
    let s = b.stats();
    assert_eq!((s["busy"], s["ok"]), (1, 1));
    assert_eq!(s.get("duplicate"), None);
}

/// The test knobs and every network but regtest are refused, and the
/// listener must be a loopback address.
#[test]
fn refusals_at_start() {
    let testnet = Node::start(ChainParams::testnet());
    let mut c = config(&testnet);
    c.allow_session_diff = true;
    let e = Bridge::start(c, testnet.pow.clone()).err().unwrap();
    assert_eq!(
        e,
        StartError::TestKnobOffRegtest {
            knob: "--allow-session-diff",
            network: "testnet".into()
        }
    );
    let mut c = config(&testnet);
    c.negative_control_algo = Some("rx/0".into());
    let e = Bridge::start(c, testnet.pow.clone()).err().unwrap();
    assert_eq!(
        e,
        StartError::TestKnobOffRegtest {
            knob: "--negative-control-algo",
            network: "testnet".into()
        }
    );
    let e = Bridge::start(config(&testnet), testnet.pow.clone())
        .err()
        .unwrap();
    assert_eq!(e, StartError::NotRegtest("testnet".into()));

    let regtest = Node::start(ChainParams::regtest());
    let mut c = config(&regtest);
    c.listen = "0.0.0.0:0".parse().unwrap();
    assert!(matches!(
        Bridge::start(c, regtest.pow.clone()),
        Err(StartError::NotLoopback(_))
    ));
    let mut c = config(&regtest);
    c.negative_control_algo = Some("rx/2".into());
    assert!(matches!(
        Bridge::start(c, regtest.pow.clone()),
        Err(StartError::NegativeControlAlgo(_))
    ));
    let mut c = config(&regtest);
    c.payout = encode_address(Network::Testnet, &payout());
    assert!(matches!(
        Bridge::start(c, regtest.pow.clone()),
        Err(StartError::Payout(_))
    ));
    let mut c = config(&regtest);
    c.min_share_diff = 0;
    assert!(matches!(
        Bridge::start(c, regtest.pow.clone()),
        Err(StartError::Config(_))
    ));
    // With the knob on regtest, a session may set its floor.
    let mut c = config(&regtest);
    c.allow_session_diff = true;
    c.min_share_diff = 1000;
    let b = bridge(&regtest, c);
    let mut f = Fake::connect(b.local_addr());
    assert!(f.login_as(XMRIG_AGENT, &["rx/blacksilk"], "diff=3")["error"].is_null());
    assert_eq!(
        target_of(&f.job),
        blacksilk_stratum_bridge::target::target64(3)
    );
}

/// The negative control: jobs labelled rx/0, results identified as rx/0
/// (here the fake rx/0), BlackSilk's hash flagged as a failed control, and
/// no block ever submitted.
#[test]
fn negative_control() {
    let node = Node::start(ChainParams::regtest());
    let log = temp_file("nc.jsonl");
    let mut c = config(&node);
    c.negative_control_algo = Some("rx/0".into());
    c.submit_log = Some(log.clone());
    let b = bridge(&node, c);
    let mut f = Fake::connect(b.local_addr());
    let r = f.login_as(XMRIG_AGENT, &["rx/blacksilk"], "x");
    assert_eq!(r["error"]["message"], "Unsupported algo");
    assert!(f.login_as(XMRIG_AGENT, &["rx/blacksilk", "rx/0"], "x")["error"].is_null());
    let job = f.job.clone();
    assert_eq!(job["algo"], "rx/0");
    let tip = node.tip();
    let blob_with = |n: u32| {
        let mut blob: PowBlob = hex::decode(job["blob"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        blob[39..43].copy_from_slice(&[n as u8, (n >> 8) as u8, (n >> 16) as u8, (n >> 24) as u8]);
        blob
    };
    let seed = job_seed(&job);
    let wrong_algo = json!({"id": f.session, "job_id": job["job_id"], "nonce": nonce_hex(9), "result": "00".repeat(32), "algo": "rx/blacksilk"});
    assert_eq!(f.submit_raw(wrong_algo), Err("Invalid algo".into()));
    for (n, result) in [
        (1u32, fake_rx0(&seed, &blob_with(1))),
        (2, fake_hash(&seed, &blob_with(2))),
        (3, [0x5a; 32]),
    ] {
        assert_eq!(
            f.submit(&nonce_hex(n), &hex::encode(result)),
            Err("Invalid result".into())
        );
    }
    let s = b.stats();
    assert_eq!(s["nc_rx0_match"], 1);
    assert_eq!(s["nc_blacksilk_match"], 1);
    assert_eq!(s["nc_unidentified"], 1);
    assert_eq!(s.get("blocks_submitted"), None);
    assert_eq!(node.tip(), tip);
    let (records, bad) = submit_log::read(&log).unwrap();
    assert!(bad.is_empty());
    let mismatch: Vec<bool> = records
        .iter()
        .filter(|r| r.outcome.starts_with("nc_"))
        .map(|r| r.gate_mismatch)
        .collect();
    assert_eq!(mismatch, [true, false, true]);
    let _ = std::fs::remove_file(&log);
}

/// Every submit is in the submit log with its outcome and inputs, and the
/// offline recompute (here with the fake PoW) reproduces every result that
/// is a true hash, the stale and duplicate ones included.
#[test]
fn every_submit_is_logged_and_recomputed() {
    let node = Node::start(ChainParams::regtest());
    let log = temp_file("submits.jsonl");
    let stratum_log = temp_file("stratum.log");
    let mut c = config(&node);
    c.submit_log = Some(log.clone());
    c.stratum_log = Some(stratum_log.clone());
    let b = bridge(&node, c);
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let job = f.job.clone();
    let (n, h) = find(&job, 100, |_| true);
    let (m, hm) = find(&job, 200, |_| true);
    let mut results = vec![
        f.submit(&nonce_hex(5), &"cd".repeat(32)), // invalid result
        f.submit(&nonce_hex(n), &hex::encode(h)),  // OK
    ];
    // Once the bridge has the new tip, the old job is stale.
    f.wait_job();
    results.push(f.submit_on(&job, &nonce_hex(n), &hex::encode(h))); // stale
    results.push(f.submit_on(&job, &nonce_hex(m), &hex::encode(hm))); // stale, never hashed
    assert_eq!(results[1], Ok("OK".into()));
    assert_eq!(results[3], Err("Stale job".into()));
    let (records, bad) = submit_log::read(&log).unwrap();
    assert!(bad.is_empty());
    assert_eq!(records.len(), 4);
    assert_eq!(
        records
            .iter()
            .map(|r| r.outcome.as_str())
            .collect::<Vec<_>>(),
        ["invalid_result", "ok", "stale_job", "stale_job"]
    );
    assert!(records[0].gate_mismatch, "an xmrig agent's bad result");
    assert!(records[1].block_id.is_some());
    assert!(!records[3].hashed && records[3].blob.is_some());
    struct FakeVariants;
    impl VariantHasher for FakeVariants {
        fn hash(&mut self, _: blacksilk_randomx::Variant, seed: &Hash, blob: &PowBlob) -> Hash {
            fake_hash(seed, blob)
        }
    }
    let options = Options {
        only_agent: Some("XMRig/".into()),
        ..Options::default()
    };
    let s = recompute(&records, &options, &mut FakeVariants);
    assert_eq!(s.recomputed, 4);
    assert_eq!(s.hashed_live, 2);
    assert_eq!(s.matches, 3);
    assert_eq!(s.mismatches.len(), 1);
    assert!(s.inconsistent.is_empty(), "{}", s.render());
    let lines = std::fs::read_to_string(&stratum_log).unwrap();
    assert!(lines
        .lines()
        .any(|l| l.contains(" < ") && l.contains("\"login\"")));
    assert!(lines
        .lines()
        .any(|l| l.contains(" > ") && l.contains("Stale job")));
    let _ = std::fs::remove_file(&log);
    let _ = std::fs::remove_file(&stratum_log);
}

/// The probe's cases against the bridge, each with its exact reply, and the
/// replay of another session's share (case f).
#[test]
fn probe_cases() {
    let node = Node::start(ChainParams::regtest());
    let mut c = config(&node);
    c.allow_session_diff = true;
    c.min_share_diff = 50;
    let b = bridge(&node, c);
    let mut p = probe::ProbeClient::login(
        b.local_addr(),
        probe::PROBE_AGENT,
        &["rx/blacksilk"],
        "diff=1",
    )
    .unwrap()
    .unwrap();
    let mut hasher = |s: &Hash, blob: &PowBlob| fake_hash(s, blob);
    let mut tip = || node.client.info().ok().map(|i| i.tip);
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let results = probe::run_cases(&mut p, &mut hasher, &mut tip, &mut rng).unwrap();
    for r in &results {
        assert!(r.passed(), "{}", r.render());
    }
    assert_eq!(
        results.iter().map(|r| r.case.as_str()).collect::<Vec<_>>(),
        ["c", "a", "b", "e", "d", "e2"]
    );
    // Case f: a share of another session.
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let (n, h) = find(&f.job, 3, |_| true);
    let job_id = f.job["job_id"].as_str().unwrap().to_string();
    let r = probe::replay(&mut p, &job_id, &nonce_hex(n), &hex::encode(h), &mut tip).unwrap();
    assert!(r.passed(), "{}", r.render());
    // The probe's bad results are not GATE-MISMATCHes (not an xmrig agent).
    assert_eq!(b.stats()["invalid_result"], 2);
}

/// `--version` names the program and prints a `build flags:` line (the
/// format tools/check-build-flags.sh requires); a binary with test-only
/// code compiled in (as `cargo test` builds it) refuses to run.
#[test]
fn version_and_build_guard() {
    for (exe, name) in [
        (
            env!("CARGO_BIN_EXE_blacksilk-stratum-bridge"),
            "blacksilk-stratum-bridge",
        ),
        (
            env!("CARGO_BIN_EXE_blacksilk-stratum-probe"),
            "blacksilk-stratum-probe",
        ),
    ] {
        let out = std::process::Command::new(exe)
            .arg("--version")
            .output()
            .unwrap();
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        let first = text.lines().next().unwrap();
        assert_eq!(first.split(' ').next(), Some(name), "{text}");
        assert!(first.contains("(commit "), "{text}");
        let flags = text
            .lines()
            .find(|l| l.starts_with("build flags: "))
            .unwrap_or_else(|| panic!("no build flags line: {text}"));
        if flags != "build flags: none" {
            let out = std::process::Command::new(exe)
                .args(["recompute", "--log", "nonexistent"])
                .output()
                .unwrap();
            if name == "blacksilk-stratum-bridge" {
                assert_eq!(out.status.code(), Some(2), "a hooked build refuses to run");
                assert!(String::from_utf8_lossy(&out.stderr).contains("test-only code"));
            }
        }
    }
}

/// At most `max_connections` connections are open, logged in or not; one
/// more is closed at once, and a closed connection frees its slot.
#[test]
fn connections_are_capped_before_login() {
    let node = Node::start(ChainParams::regtest());
    let mut c = config(&node);
    c.max_connections = 2;
    let b = bridge(&node, c);
    let mut a = Fake::connect(b.local_addr());
    let _second = Fake::connect(b.local_addr());
    let mut third = Fake::connect(b.local_addr());
    assert!(third.closed(), "the third connection is closed at once");
    wait_until("the refusal to be counted", || {
        b.stats().get("connections_refused") == Some(&1)
    });
    assert!(a.login()["error"].is_null());
    a.w.shutdown(std::net::Shutdown::Both).unwrap();
    // The slot is free once the first connection's thread has ended.
    wait_until("a free slot", || {
        let mut d = Fake::connect(b.local_addr());
        // A refused connection may already be reset: a failed write is a
        // "not yet", not a test failure.
        let login = json!({"id": 1, "jsonrpc": "2.0", "method": "login",
            "params": {"login": "x", "pass": "x", "agent": XMRIG_AGENT, "algo": ["rx/blacksilk"]}});
        if d.w
            .write_all(
                format!(
                    "{login}
"
                )
                .as_bytes(),
            )
            .is_err()
        {
            return false;
        }
        let id = 1;
        loop {
            match d.read() {
                None => return false,
                Some(v) if v["id"] == json!(id) => return v["error"].is_null(),
                Some(_) => {}
            }
        }
    });
}

/// A share whose block the node accepts but not onto its best chain (a
/// second block on the same parent) gets its own status, apart from both
/// `OK` and a rejection.
#[test]
fn accepted_off_the_best_chain_is_its_own_outcome() {
    let node = Node::start(ChainParams::regtest());
    let b = bridge(&node, config(&node));
    let mut f = Fake::connect(b.local_addr());
    f.login();
    let mut g = Fake::connect(b.local_addr());
    g.login();
    let (fj, gj) = (f.job.clone(), g.job.clone());
    let (n, h) = find(&fj, 1, |_| true);
    let (m, hm) = find(&gj, 2, |_| true);
    node.pow.set_hold(true);
    let before = node.pow.entered.load(Ordering::SeqCst);
    let fa = f.send(
        "submit",
        json!({"id": f.session, "job_id": fj["job_id"], "nonce": nonce_hex(n), "result": hex::encode(h), "algo": "rx/blacksilk"}),
    );
    wait_until("the verifier to take the first share", || {
        node.pow.entered.load(Ordering::SeqCst) > before
    });
    // Queued while the tip has not moved yet: not stale.
    let gb = g.send(
        "submit",
        json!({"id": g.session, "job_id": gj["job_id"], "nonce": nonce_hex(m), "result": hex::encode(hm), "algo": "rx/blacksilk"}),
    );
    // The session thread handles lines in order: once the keepalive is
    // answered, the submit has passed the stale check and is on the queue.
    assert_eq!(
        g.call("keepalived", json!({"id": g.session}))["result"]["status"],
        "KEEPALIVED"
    );
    node.pow.set_hold(false);
    assert_eq!(outcome(&f.reply(fa)), Ok("OK".into()));
    assert_eq!(outcome(&g.reply(gb)), Ok("OK_OFF_BEST_CHAIN".into()));
    let s = b.stats();
    assert_eq!((s["ok"], s["ok_off_best_chain"]), (1, 1));
    assert_eq!(node.height(), 1);
}
