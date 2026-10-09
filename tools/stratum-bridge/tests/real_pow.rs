//! The bridge with the node's real proof of work: ONE `Arc<RandomXPow>`
//! shared by the in-process node and the bridge (so the node really checks
//! every block's RandomX hash), and a client that hashes with
//! `blacksilk_randomx` light mode itself, as xmrig would.
//!
//! Memory: the shared caches (256 MiB per key), the client's cache, and in
//! the negative control the bridge's and the client's `rx/0` caches: about
//! 1 GiB at the peak. The tests take a lock so they never run at the same
//! time; run this binary with `--test-threads=1` and nothing RandomX-heavy
//! beside it.

use blacksilk_chain::address::encode_address;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, Network, PowBlob, RandomXPow};
use blacksilk_crypto::keys::{Address, SubaddressIndex, WalletKeys};
use blacksilk_node::{router, Shared};
use blacksilk_randomx::{Cache, Variant, Vm};
use blacksilk_rpc::Client;
use blacksilk_stratum_bridge::probe::{self, ProbeClient};
use blacksilk_stratum_bridge::target::{xmrig_decode_target, xmrig_would_submit};
use blacksilk_stratum_bridge::{Bridge, Config};
use blacksilk_tx::params::TxRules;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

static SERIAL: Mutex<()> = Mutex::new(());

const AGENT: &str = "XMRig/6.26.0 (real-pow test)";

struct Node {
    _rt: tokio::runtime::Runtime,
    addr: SocketAddr,
    client: Client,
    pow: Arc<RandomXPow>,
    network_id: u32,
}

impl Node {
    fn start(params: ChainParams) -> Self {
        let pow = Arc::new(RandomXPow::new());
        let network_id = params.network_id;
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
            network_id,
        }
    }

    fn height(&self) -> u64 {
        self.client.info().unwrap().height
    }

    fn block_id(&self, height: u64) -> Hash {
        let h = self.client.headers(height, 1).unwrap();
        let bytes = hex::decode(&h.headers).unwrap();
        BlockHeader::from_bytes(&bytes).unwrap().id(self.network_id)
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

/// The client's light-mode hasher: one cache at a time, of `variant`.
struct ClientHasher {
    variant: Variant,
    cache: Option<(Hash, Cache)>,
}

impl ClientHasher {
    fn new(variant: Variant) -> Self {
        Self {
            variant,
            cache: None,
        }
    }

    fn hash(&mut self, seed: &Hash, blob: &PowBlob) -> Hash {
        if self.cache.as_ref().is_none_or(|(s, _)| s != seed) {
            self.cache = None;
            self.cache = Some((*seed, Cache::with_variant(seed, self.variant)));
        }
        Vm::light(&self.cache.as_ref().unwrap().1).hash(blob)
    }
}

/// The job's blob with nonce `n`'s 4 little-endian bytes at 39..43, and
/// those bytes as hex: written here, not with the bridge's helpers.
fn share_blob(job: &blacksilk_stratum_bridge::stratum::JobObject, n: u32) -> (PowBlob, String) {
    let mut blob: PowBlob = hex::decode(&job.blob).unwrap().try_into().unwrap();
    let raw = [n as u8, (n >> 8) as u8, (n >> 16) as u8, (n >> 24) as u8];
    blob[39..43].copy_from_slice(&raw);
    (blob, hex::encode(raw))
}

fn seed_of(job: &blacksilk_stratum_bridge::stratum::JobObject) -> Hash {
    hex::decode(&job.seed_hash).unwrap().try_into().unwrap()
}

/// Mines one block through the bridge on the client's current job: hashes
/// like xmrig (its target), submits, and retries on `Low difficulty share`.
fn mine_one(c: &mut ProbeClient, hasher: &mut ClientHasher, start: u32) -> u32 {
    c.drain_jobs();
    let job = c.job.clone();
    let seed = seed_of(&job);
    let target = xmrig_decode_target(&job.target);
    let mut n = start;
    loop {
        let (blob, nonce) = share_blob(&job, n);
        let h = hasher.hash(&seed, &blob);
        if xmrig_would_submit(&h, target) {
            match c
                .submit(&job.job_id, &nonce, &hex::encode(h), Some(&job.algo))
                .unwrap()
            {
                Ok(s) => {
                    assert_eq!(s, "OK");
                    return n;
                }
                Err(e) => assert_eq!(e, "Low difficulty share"),
            }
        }
        n = n.wrapping_add(1);
    }
}

/// At difficulty 4: a block whose hash misses the difficulty, sent straight
/// to the node, is refused with `InsufficientWork`; a block mined through
/// the bridge is accepted by the node, which verifies it with the same
/// RandomX; a wrong result is refused; and the negative control
/// identifies a client hashing with Monero's `rx/0` positively.
#[test]
fn real_randomx_through_the_bridge_and_the_node() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut params = ChainParams::regtest();
    params.initial_difficulty = 4;
    params.genesis.difficulty = 4;
    let node = Node::start(params);
    let b = Bridge::start(config(&node), node.pow.clone()).unwrap();
    let mut c = ProbeClient::login(b.local_addr(), AGENT, &["rx/blacksilk"], "x")
        .unwrap()
        .unwrap();
    let mut hasher = ClientHasher::new(Variant::BlackSilk);
    // The node itself refuses a block whose real hash misses the difficulty
    // (block 1 is at difficulty 4; after it, the genesis gap lowers it to 1).
    let mut rng = ChaCha20Rng::seed_from_u64(3);
    let mut h = |s: &Hash, b: &PowBlob| hasher.hash(s, b);
    let r = probe::direct_to_node(&node.client, &payout(), &mut h, &mut rng).unwrap();
    assert!(r.passed(), "{}", r.render());
    assert_eq!(node.height(), 0);
    assert_eq!(
        c.job.target,
        blacksilk_stratum_bridge::target::target_hex(4)
    );
    let n = mine_one(&mut c, &mut hasher, 0);
    assert_eq!(node.height(), 1);
    // The node checked the block's PoW with the shared RandomXPow.
    assert!(node.pow.builds() >= 1);

    // A wrong result: the true hash of n, sent for nonce n + 1.
    assert!(c.wait_job(Duration::from_secs(60)).unwrap());
    let job = c.job.clone();
    let (blob, _) = share_blob(&job, n);
    let h = hasher.hash(&seed_of(&job), &blob);
    let (_, next) = share_blob(&job, n.wrapping_add(1));
    let tip = node.client.info().unwrap().tip;
    assert_eq!(
        c.submit(&job.job_id, &next, &hex::encode(h), Some("rx/blacksilk"))
            .unwrap(),
        Err("Invalid result".into())
    );
    assert_eq!(node.client.info().unwrap().tip, tip);

    drop(hasher);

    // The negative control: jobs labelled rx/0, the client hashes with
    // Monero's rx/0, the bridge identifies the result and submits nothing.
    drop(c);
    drop(b);
    let mut nc = config(&node);
    nc.negative_control_algo = Some("rx/0".into());
    let b = Bridge::start(nc, node.pow.clone()).unwrap();
    let mut c = ProbeClient::login(b.local_addr(), AGENT, &["rx/blacksilk", "rx/0"], "x")
        .unwrap()
        .unwrap();
    assert_eq!(c.job.algo, "rx/0");
    let job = c.job.clone();
    let mut rx0 = ClientHasher::new(Variant::MoneroRx0);
    let (blob, nonce) = share_blob(&job, 77);
    let r = rx0.hash(&seed_of(&job), &blob);
    assert_eq!(
        c.submit(&job.job_id, &nonce, &hex::encode(r), Some("rx/0"))
            .unwrap(),
        Err("Invalid result".into())
    );
    let s = b.stats();
    assert_eq!(s["nc_rx0_match"], 1, "{s:?}");
    assert_eq!(s.get("blocks_submitted"), None);
    assert_eq!(node.height(), 1);
}

/// Across a RandomX key switch (short epoch: 16, lag 4, so blocks from
/// height 21 hash with block 16's id): every job carries the key of its
/// height, and the client, the bridge and the node agree on both sides of
/// the switch.
#[test]
fn real_randomx_across_a_key_switch() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut params = ChainParams::regtest();
    params.seed_epoch = 16;
    params.seed_lag = 4;
    let genesis = params.genesis_id();
    let node = Node::start(params);
    let b = Bridge::start(config(&node), node.pow.clone()).unwrap();
    let mut c = ProbeClient::login(b.local_addr(), AGENT, &["rx/blacksilk"], "x")
        .unwrap()
        .unwrap();
    let mut hasher = ClientHasher::new(Variant::BlackSilk);
    for height in 1..=22u64 {
        while c.job.height != height {
            assert!(
                c.wait_job(Duration::from_secs(60)).unwrap(),
                "no job for {height}"
            );
        }
        let seed = seed_of(&c.job);
        if height <= 20 {
            assert_eq!(seed, genesis, "height {height}");
        } else {
            assert_eq!(seed, node.block_id(16), "height {height}");
        }
        mine_one(&mut c, &mut hasher, (height as u32) << 8);
        assert_eq!(node.height(), height);
    }
}
