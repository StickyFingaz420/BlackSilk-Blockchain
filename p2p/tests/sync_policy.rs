//! Header-sync policy against RandomX key abuse (07 W3 / 31 S2, F07-4 and
//! F31-8): the proof-of-work chunk is capped by the key lag, so no header is
//! hashed under a key taken from an unverified header of its own chunk.

mod common;

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{
    seed_height, BlockHeader, Hash, HeaderChain, PowFunction, HEADER_VERSION, NONCE_OFFSET,
};
use blacksilk_p2p::message::Message;
use blacksilk_p2p::{HeaderPowBudget, NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
use common::{fast_config, params, raw_handshake, recv_until, ZeroPow};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Proof of work that fails headers carrying `BAD_NONCE` (the largest hash
/// meets no difficulty above 1), passes all others, and records every key it
/// is asked to hash under: where `RandomXPow` would build that key's cache.
const BAD_NONCE: u64 = 0xBAD0_BAD0;
#[derive(Default)]
struct SeedRecordingPow(Mutex<Vec<Hash>>);
impl PowFunction for SeedRecordingPow {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        self.0.lock().unwrap().push(*seed);
        let nonce = u64::from_le_bytes(blob[NONCE_OFFSET..NONCE_OFFSET + 8].try_into().unwrap());
        if nonce == BAD_NONCE {
            [0xff; 32]
        } else {
            [0; 32]
        }
    }
}

/// `n` linked headers on genesis, 1 s apart (the difficulty rises above 1),
/// valid under a PoW function accepting everything; the header at height
/// `bad` carries `BAD_NONCE`.
fn header_branch(n: usize, bad: u64) -> Vec<BlockHeader> {
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: if t.height == bad { BAD_NONCE } else { 0 },
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// F07-4 / F31-8 (07 T9): on a host with 128 PoW threads, a batch that
/// extends our tip across a key block S with junk proof of work at S, and
/// continues past S + lag + 1 (whose key is that fake S), must not make the
/// node hash anything under the fake key. Before the cap, the chunk was
/// `pow_threads` headers, so S and S + 65 were hashed together and the fake
/// key keyed a cache build before S's proof of work failed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_junk_key_block_never_keys_a_hash_in_its_own_batch() {
    let p = params();
    let (s, lag) = (p.seed_epoch, p.seed_lag);
    assert_eq!((s, lag), (2048, 64));
    let tip = s - 8;
    let branch = header_branch((s + lag + 60) as usize, s);
    let fake_key = branch[(s - 1) as usize].id(p.network_id);
    assert_eq!(branch[(s - 1) as usize].height, s);
    let keyed_by_fake = branch
        .iter()
        .filter(|h| seed_height(h.height, s, lag) == s)
        .count();
    assert!(keyed_by_fake > 50, "the batch reaches past S + lag");
    assert!(
        branch[(s - 1) as usize].difficulty > 1,
        "junk PoW fails at S"
    );

    let pow = Arc::new(SeedRecordingPow::default());
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow.clone(),
        Box::<MemoryStore>::default(),
        [5; 32],
    )
    .unwrap();
    {
        let mut m = m;
        for part in branch[..tip as usize].chunks(500) {
            m.accept_headers(part, u64::MAX / 2).unwrap();
        }
        let chain: SharedChain = Arc::new(Mutex::new(m));
        let mut cfg: NetConfig = fast_config(&[]);
        cfg.pow_threads = 128;
        let net = Network::start(cfg, chain.clone()).await.unwrap();
        let addr = net.local_addr().unwrap();
        pow.0.lock().unwrap().clear();

        let (_, mut r, mut w) = raw_handshake(addr, s + lag + 100, 5.0)
            .await
            .expect("handshake");
        let mut other = Vec::new();
        assert!(
            recv_until(&mut r, 5.0, &mut other, |m| matches!(
                m,
                Message::GetHeaders { .. }
            ))
            .await
            .is_some(),
            "the node asks for headers"
        );
        let batch = branch[tip as usize..].to_vec();
        w.send(&Message::Headers(batch).encode()).await.unwrap();
        // Verified once the header worker has hashed the header at S.
        let deadline = Instant::now() + Duration::from_secs(20);
        while net.header_queue_len() > 0 || pow.0.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "batch not verified");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while net.header_queue_len() > 0 {
            assert!(Instant::now() < deadline, "batch not verified");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let seeds = pow.0.lock().unwrap().clone();
        let under_fake = seeds.iter().filter(|k| **k == fake_key).count();
        assert_eq!(
            under_fake,
            0,
            "{under_fake} of {} hashes ran under the key of an unverified header",
            seeds.len()
        );
        assert!(
            seeds.len() <= lag as usize,
            "at most one capped chunk: {}",
            seeds.len()
        );
        assert!(
            chain.lock().unwrap().header_height() < s,
            "junk at S rejected"
        );
    }
}

/// Proof of work that takes `delay` per hash (a stand-in for RandomX light
/// mode's ~0.5 s) and fails headers whose nonce carries `JUNK_TAG` in its
/// top 16 bits; counts the junk hashes it ran.
const JUNK_TAG: u64 = 0xBAD0;
struct SlowJunkPow {
    delay: Duration,
    junk: AtomicU64,
}
impl PowFunction for SlowJunkPow {
    fn pow_hash(&self, _: &Hash, blob: &[u8]) -> Hash {
        std::thread::sleep(self.delay);
        let nonce = u64::from_le_bytes(blob[NONCE_OFFSET..NONCE_OFFSET + 8].try_into().unwrap());
        if nonce >> 48 == JUNK_TAG {
            self.junk.fetch_add(1, Relaxed);
            [0xff; 32]
        } else {
            [0; 32]
        }
    }
}

/// The difficulty a junk header must claim: any hash meets difficulty 1, so
/// junk proof of work fails only above it.
const JUNK_DIFFICULTY: u64 = 4;

/// The prototype of a plausible junk header on `hc`'s tip: every rule but
/// the proof of work holds (the required difficulty, at least
/// `JUNK_DIFFICULTY`), and it extends the best chain, so it passes the work
/// gate for as long as that block stays within 144 blocks of the tip.
fn junk_prototype(hc: &HeaderChain) -> BlockHeader {
    let t = hc.template();
    let parent = *hc.header(&t.prev_id).unwrap();
    assert!(t.difficulty >= JUNK_DIFFICULTY, "junk would be valid");
    BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(parent.timestamp + 1),
        difficulty: t.difficulty,
        tx_root: [0; 32],
        nonce: JUNK_TAG << 48,
    }
}

/// The `k`th distinct junk header of `proto`.
fn junk(proto: &BlockHeader, k: u64) -> BlockHeader {
    BlockHeader {
        nonce: (JUNK_TAG << 48) | k,
        ..*proto
    }
}

/// Linked headers on genesis, 1 s apart, until the next header's required
/// difficulty is at least `JUNK_DIFFICULTY` (the prefix junk is put on),
/// with the header chain they form.
fn steep_prefix() -> (Vec<BlockHeader>, HeaderChain) {
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    let mut out = Vec::new();
    while g.template().difficulty < JUNK_DIFFICULTY {
        assert!(out.len() < 100, "the difficulty never rose");
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: 0,
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    (out, g)
}

/// A node over a regtest chain holding the headers `prefix`, hashing with
/// `pow`, under `cfg`.
async fn pow_node(
    pow: Arc<SlowJunkPow>,
    seed: u8,
    cfg: NetConfig,
    prefix: &[BlockHeader],
) -> (SharedChain, Network) {
    let p = params();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow,
        Box::<MemoryStore>::default(),
        [seed; 32],
    )
    .unwrap();
    let mut m = m;
    if !prefix.is_empty() {
        m.accept_headers(prefix, u64::MAX / 2).unwrap();
    }
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let net = Network::start(cfg, chain.clone()).await.unwrap();
    (chain, net)
}

/// What one flood run measured.
struct FloodRun {
    /// Seconds from the honest node's new block to the victim storing its
    /// header, the largest over the run.
    max_lag: f64,
    junk_hashes: u64,
    secs: f64,
    throttled: u64,
}

/// R8-8: a victim V syncs from one outbound peer H, which mines a block
/// every 250 ms, while `attackers` inbound connections (loopback with
/// `allow_private`, so never banned: like onion peers or rotating
/// addresses) flood plausible single headers with junk proof of work, one
/// every 20 ms each, reconnecting whenever they are disconnected. Every hash
/// costs 30 ms.
async fn flood_run(budget: HeaderPowBudget, attackers: usize) -> FloodRun {
    const BLOCKS: u64 = 24;
    let honest = common::slow_node(0x51, fast_config(&[])).await;
    // H's first blocks come 1 s apart, so the difficulty rises enough for
    // junk proof of work to fail; the flood's junk extends that prefix.
    let c = honest.chain.clone();
    let (proto, prefix) = tokio::task::spawn_blocking(move || {
        let mut c = c.lock().unwrap();
        let mut i = 0;
        while c.headers().template().difficulty < JUNK_DIFFICULTY {
            assert!(i < 100, "the difficulty never rose");
            let t = c.headers().template();
            let parent = *c.headers().header(&t.prev_id).unwrap();
            let mut b = common::stall::next_block(&c, 0x7e00 + i, 0);
            b.header.timestamp = t.min_timestamp.max(parent.timestamp + 1);
            let now = b.header.timestamp;
            c.submit_block(b, now).unwrap();
            i += 1;
        }
        (junk_prototype(c.headers()), c.height())
    })
    .await
    .unwrap();
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(30),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[honest.addr]);
    cfg.header_pow_budget = budget;
    let (chain, net) = pow_node(pow.clone(), 0x52, cfg, &[]).await;
    let victim = net.local_addr().unwrap();
    let deadline = Instant::now() + Duration::from_secs(20);
    while net.stats().outbound == 0 {
        assert!(Instant::now() < deadline, "V never connected to H");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    while chain.lock().unwrap().header_height() < prefix {
        assert!(Instant::now() < deadline, "V never synced H's prefix");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();
    for _ in 0..attackers {
        let (stop, counter) = (stop.clone(), counter.clone());
        tasks.push(tokio::spawn(async move {
            while !stop.load(Relaxed) {
                let Some((_, mut r, mut w)) = raw_handshake(victim, 0, 5.0).await else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    continue;
                };
                // Read everything, as a real attacker would, to stay
                // connected.
                let drain = tokio::spawn(async move { while r.recv().await.is_ok() {} });
                while !stop.load(Relaxed) {
                    let k = counter.fetch_add(1, Relaxed);
                    let m = Message::Headers(vec![junk(&proto, k)]);
                    if w.send(&m.encode()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                drain.abort();
            }
        }));
    }
    // The flood fills the queue before the honest blocks start.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let start = Instant::now();
    let mut max_lag: f64 = 0.0;
    for n in prefix + 1..=prefix + BLOCKS {
        honest.mine(1).await;
        let mined = Instant::now();
        assert_eq!(honest.heights().await.1, n);
        let deadline = mined + Duration::from_secs(60);
        while chain.lock().unwrap().header_height() < n {
            assert!(Instant::now() < deadline, "honest header {n} never stored");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        max_lag = max_lag.max(mined.elapsed().as_secs_f64());
        let next = mined + Duration::from_millis(250);
        tokio::time::sleep(next.saturating_duration_since(Instant::now())).await;
    }
    let secs = start.elapsed().as_secs_f64() + 0.5;
    stop.store(true, Relaxed);
    for t in tasks {
        t.abort();
    }
    FloodRun {
        max_lag,
        junk_hashes: pow.junk.load(Relaxed),
        secs,
        throttled: net.stats().header_pow_throttled,
    }
}

/// R8-8 (header verification DoS): with the header proof-of-work budget, a
/// flood of junk single headers from 16 unbannable inbound identities costs
/// at most the budget's bound in hashes (`HeaderPowBudget::bound`), and the
/// honest outbound peer's headers are stored within one second of being
/// mined: they are verified before any untrusted batch, behind at most the
/// one batch already being hashed. Without a budget (priority alone) the
/// same flood keeps the worker hashing junk whenever it is idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_junk_header_flood_from_unbannable_peers_is_budgeted_and_honest_sync_goes_on() {
    let budget = HeaderPowBudget {
        class_burst: 2.0,
        class_rate: 0.5,
        global_burst: 3.0,
        global_rate: 1.0,
    };
    let bounded = flood_run(budget.clone(), 16).await;
    let bound = budget.bound(Duration::from_secs_f64(bounded.secs), 2);
    eprintln!(
        "budgeted: {} junk hashes in {:.1} s (bound {bound:.1}), {} batches throttled, \
         honest header lag at most {:.3} s",
        bounded.junk_hashes, bounded.secs, bounded.throttled, bounded.max_lag
    );
    assert!(
        bounded.junk_hashes as f64 <= bound,
        "{} junk hashes over the bound {bound}",
        bounded.junk_hashes
    );
    assert!(bounded.throttled > 0, "the flood was throttled");
    assert!(
        bounded.max_lag < 1.0,
        "honest headers waited {:.3} s",
        bounded.max_lag
    );

    let unlimited = flood_run(HeaderPowBudget::unlimited(), 16).await;
    eprintln!(
        "unbudgeted: {} junk hashes in {:.1} s, honest header lag at most {:.3} s",
        unlimited.junk_hashes, unlimited.secs, unlimited.max_lag
    );
    assert_eq!(unlimited.throttled, 0);
    assert!(
        unlimited.junk_hashes > 4 * bounded.junk_hashes,
        "the flood is real: {} unbudgeted against {} budgeted",
        unlimited.junk_hashes,
        bounded.junk_hashes
    );
}

/// The budget charges failures only: an honest inbound peer's valid headers
/// are refunded, so a budget of one hash with no refill still lets it
/// deliver header after header (after its first, it is trusted:
/// `Peer::pow_proven`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_inbound_peer_is_not_throttled_by_an_empty_refill() {
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(1),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[]);
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 0.0,
        global_burst: 1.0,
        global_rate: 0.0,
    };
    let (chain, net) = pow_node(pow, 0x53, cfg, &[]).await;
    let (_, _r, mut w) = raw_handshake(net.local_addr().unwrap(), 0, 5.0)
        .await
        .expect("handshake");
    for (i, h) in header_branch(5, u64::MAX).into_iter().enumerate() {
        w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while chain.lock().unwrap().header_height() < i as u64 + 1 {
            assert!(Instant::now() < deadline, "header {} not stored", i + 1);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let s = net.stats();
    assert_eq!((s.header_pow_failed, s.header_pow_throttled), (0, 0));
}

/// An untrusted inbound peer that sent junk is throttled once the budget is
/// spent, and a junk hash is never refunded: with one hash and no refill,
/// the second junk header (from a fresh identity) is dropped unhashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_spends_the_budget_and_the_next_untrusted_header_is_dropped_unhashed() {
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(1),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[]);
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 0.0,
        global_burst: 10.0,
        global_rate: 0.0,
    };
    let (prefix, g) = steep_prefix();
    let proto = junk_prototype(&g);
    let (_chain, net) = pow_node(pow.clone(), 0x54, cfg, &prefix).await;
    let addr = net.local_addr().unwrap();
    for k in 0..3u64 {
        let (_, _r, mut w) = raw_handshake(addr, 0, 5.0).await.expect("handshake");
        let m = Message::Headers(vec![junk(&proto, k)]);
        w.send(&m.encode()).await.unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let s = net.stats();
            if s.header_pow_failed + s.header_pow_throttled == k + 1 {
                break;
            }
            assert!(Instant::now() < deadline, "junk header {k} not handled");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let s = net.stats();
    assert_eq!((s.header_pow_failed, s.header_pow_throttled), (1, 2));
    assert_eq!(pow.junk.load(Relaxed), 1, "one junk hash, then none");
}
