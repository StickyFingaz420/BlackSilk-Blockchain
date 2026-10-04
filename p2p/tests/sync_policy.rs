//! Header-sync policy against RandomX key abuse (07 W3 / 31 S2, F07-4 and
//! F31-8): the proof-of-work chunk is capped by the key lag, so no header is
//! hashed under a key taken from an unverified header of its own chunk.

mod common;

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{
    seed_height, BlockHeader, Hash, HeaderChain, PowFunction, HEADER_VERSION, POW_NONCE_OFFSET,
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
    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        self.0.lock().unwrap().push(*seed);
        let nonce = u64::from_le_bytes(
            blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
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
            ..Default::default()
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
    fn pow_hash(&self, _: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        std::thread::sleep(self.delay);
        let nonce = u64::from_le_bytes(
            blob[POW_NONCE_OFFSET..POW_NONCE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
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
        ..Default::default()
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
            ..Default::default()
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

/// Mines H's first blocks 1 s apart until the difficulty is high enough for
/// junk proof of work to fail; returns the junk prototype on H's tip and
/// H's height.
async fn steep_blocks(honest: &common::SlowNode) -> (BlockHeader, u64) {
    let c = honest.chain.clone();
    tokio::task::spawn_blocking(move || {
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
    .unwrap()
}

/// Waits until `cond` holds, at most `secs`.
async fn wait_for(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Whether `chain` stores the header `id`.
fn stored(chain: &SharedChain, id: &Hash) -> bool {
    chain.lock().unwrap().headers().header(id).is_some()
}

/// The next valid header on `g`'s tip (tagged by `k`), accepted into `g`.
fn next_valid(g: &mut HeaderChain, k: u8) -> (BlockHeader, Hash) {
    let t = g.template();
    let parent = *g.header(&t.prev_id).unwrap();
    let h = BlockHeader {
        version: t.version,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(parent.timestamp + 1),
        difficulty: t.difficulty,
        tx_root: [k; 32],
        nonce: k as u64,
        ..Default::default()
    };
    let id = g.accept(h, u64::MAX / 2).unwrap().id;
    (h, id)
}

/// `n` flooding identities against `addr`: each sends a junk header of
/// `proto` every 20 ms, reading everything to stay connected, and
/// reconnects whenever it is disconnected (never banned on loopback with
/// `allow_private`: like onion peers or rotating addresses).
fn flood(
    addr: std::net::SocketAddr,
    proto: BlockHeader,
    n: usize,
    stop: &Arc<AtomicBool>,
    counter: &Arc<AtomicU64>,
) -> Vec<tokio::task::JoinHandle<()>> {
    (0..n)
        .map(|_| {
            let (stop, counter) = (stop.clone(), counter.clone());
            tokio::spawn(async move {
                while !stop.load(Relaxed) {
                    let Some((_, mut r, mut w)) = raw_handshake(addr, 0, 5.0).await else {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        continue;
                    };
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
            })
        })
        .collect()
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
/// every 250 ms, while `attackers` inbound identities flood junk headers
/// (`flood`). Every hash costs 30 ms.
async fn flood_run(budget: HeaderPowBudget, attackers: usize) -> FloodRun {
    const BLOCKS: u64 = 24;
    let honest = common::slow_node(0x51, fast_config(&[])).await;
    let (proto, prefix) = steep_blocks(&honest).await;
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(30),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[honest.addr]);
    cfg.header_pow_budget = budget;
    let (chain, net) = pow_node(pow.clone(), 0x52, cfg, &[]).await;
    let victim = net.local_addr().unwrap();
    wait_for("V synced the prefix of H", 20, || {
        chain.lock().unwrap().header_height() >= prefix
    })
    .await;

    let stop = Arc::new(AtomicBool::new(false));
    let tasks = flood(victim, proto, attackers, &stop, &Default::default());
    // The flood fills the queue before the honest blocks start.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let start = Instant::now();
    let mut max_lag: f64 = 0.0;
    for n in prefix + 1..=prefix + BLOCKS {
        honest.mine(1).await;
        let mined = Instant::now();
        assert_eq!(honest.heights().await.1, n);
        wait_for("honest header stored", 60, || {
            chain.lock().unwrap().header_height() >= n
        })
        .await;
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
/// flood of junk single headers from 16 unbannable inbound identities (one
/// class) costs at most the class bound in hashes
/// (`HeaderPowBudget::class_bound`), and the honest outbound peer's headers
/// are stored within one second of being mined: they are verified before any
/// untrusted batch, behind at most the one batch already being hashed.
/// Without a budget (priority alone) the same flood keeps the worker hashing
/// junk whenever it is idle.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_junk_header_flood_from_unbannable_peers_is_budgeted_and_honest_sync_goes_on() {
    let budget = HeaderPowBudget {
        class_burst: 3.0,
        class_rate: 1.0,
    };
    let bounded = flood_run(budget.clone(), 16).await;
    let bound = budget.class_bound(Duration::from_secs_f64(bounded.secs), 2);
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
    assert!(
        unlimited.junk_hashes > 4 * bounded.junk_hashes,
        "the flood is real: {} unbudgeted against {} budgeted",
        unlimited.junk_hashes,
        bounded.junk_hashes
    );
}

/// RT-HDRDOS F2 (the untrusted floor): a victim with no outbound peers is
/// flooded through two classes at once, 8 onion identities on its onion
/// listener and 8 IPv4 identities, while fresh honest IPv4 identities each
/// announce the next valid header. Classes have separate buckets (no
/// node-wide one), and within the IPv4 class the next batch is drawn at
/// random among the waiting ones. Model: every IPv4 attacker keeps one
/// batch waiting (it reconnects at once after its junk is hashed and
/// re-announces within 20 ms), so `k = 8` junk batches compete with the
/// honest one, and each token (1/s) is a draw with chance `1/(k + 1)`: the
/// honest wait is geometric with mean `(k + 1)/rate = 9 s`, median about
/// 6 s, and P(wait > 90 s) = (8/9)^90, about 2.5e-5 per round. The
/// sampled untrusted queue (both classes) confirms k. The test fails only
/// on a collapse: the median of 9 rounds above 30 s (about 3x the model
/// mean), or any single wait above 90 s (RT-HDRDOS2 R2-2: a mean of 5
/// samples flaked). The onion flood takes nothing from the IPv4 class.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_untrusted_peer_progresses_under_a_two_class_flood() {
    const ROUNDS: u8 = 9;
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(30),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[]);
    cfg.onion_listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 1.0,
    };
    let (prefix, mut g) = steep_prefix();
    let proto = junk_prototype(&g);
    let (chain, net) = pow_node(pow.clone(), 0x55, cfg, &prefix).await;
    let (clear, onion) = (net.local_addr().unwrap(), net.onion_local_addr().unwrap());
    let stop = Arc::new(AtomicBool::new(false));
    let counter = Arc::new(AtomicU64::new(0));
    let mut tasks = flood(onion, proto, 8, &stop, &counter);
    tasks.extend(flood(clear, proto, 8, &stop, &counter));
    // Samples the waiting batches (both untrusted classes) every 100 ms.
    let sampler = {
        let (net, stop) = (net.clone(), stop.clone());
        tokio::spawn(async move {
            let mut samples = Vec::new();
            while !stop.load(Relaxed) {
                samples.push(net.header_queue_len());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            samples
        })
    };
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let mut waits = Vec::new();
    for k in 1..=ROUNDS {
        let (h, id) = next_valid(&mut g, k);
        let (_, _r, mut w) = raw_handshake(clear, 0, 5.0).await.expect("handshake");
        let sent = Instant::now();
        w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
        wait_for("honest untrusted header stored", 120, || {
            stored(&chain, &id)
        })
        .await;
        waits.push(sent.elapsed().as_secs_f64());
    }
    stop.store(true, Relaxed);
    for t in tasks {
        t.abort();
    }
    let samples = sampler.await.unwrap();
    let queued = samples.iter().sum::<usize>() as f64 / samples.len().max(1) as f64;
    let mut sorted = waits.clone();
    sorted.sort_by(f64::total_cmp);
    let median = sorted[sorted.len() / 2];
    let mean = waits.iter().sum::<f64>() / waits.len() as f64;
    let max = sorted[sorted.len() - 1];
    let s = net.stats();
    eprintln!(
        "untrusted floor under a two-class flood: honest waits {waits:.2?} s \
         (median {median:.2}, mean {mean:.2}, max {max:.2}; model mean 9, median ~6); \
         {queued:.1} batches waiting on average (both classes; model 8 + 8 + the honest \
         one); {} junk hashes, {} throttled",
        pow.junk.load(Relaxed),
        s.header_pow_throttled
    );
    assert!(s.header_pow_throttled > 0, "the flood was throttled");
    assert!(
        median < 30.0,
        "the untrusted floor collapsed: median {median:.2} s"
    );
    assert!(max < 90.0, "an honest batch waited {max:.2} s");
}

/// RT-HDRDOS F1: identities that proved themselves (a live new tip each)
/// and then send junk are verified after outbound peers, so a stockpile of
/// them cannot delay the outbound peer's header beyond the batch already
/// being hashed. 16 proven identities each queue one junk header (100 ms a
/// hash: 1.6 s in a shared FIFO); the next header of H is stored within
/// 0.6 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proven_identities_cannot_delay_outbound_headers() {
    const PROVEN: usize = 16;
    let honest = common::slow_node(0x56, fast_config(&[])).await;
    let (proto, prefix) = steep_blocks(&honest).await;
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(100),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[honest.addr]);
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 0.0,
    };
    let (chain, net) = pow_node(pow.clone(), 0x57, cfg, &[]).await;
    let victim = net.local_addr().unwrap();
    wait_for("V synced the prefix of H", 30, || {
        chain.lock().unwrap().header_height() >= prefix
    })
    .await;
    // Each identity proves itself with a live new tip on the best chain of
    // V (headers only: H does not have them, so its next block is a side
    // branch that V still verifies and stores).
    let mut writers = Vec::new();
    for k in 0..PROVEN {
        let (_, r, mut w) = raw_handshake(victim, 0, 5.0).await.expect("handshake");
        let h = {
            let c = chain.lock().unwrap();
            let mut h = junk_prototype(c.headers());
            h.nonce = k as u64;
            h.tx_root = [k as u8 + 1; 32];
            h
        };
        let id = h.id(params().network_id);
        w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
        wait_for("proving header stored", 20, || stored(&chain, &id)).await;
        writers.push((r, w));
    }
    assert_eq!(net.stats().header_pow_failed, 0);
    // All of them queue junk at once, then H mines.
    for (k, (_, w)) in writers.iter_mut().enumerate() {
        let m = Message::Headers(vec![junk(&proto, 1000 + k as u64)]);
        w.send(&m.encode()).await.unwrap();
    }
    wait_for("the junk is queued", 20, || {
        pow.junk.load(Relaxed) >= 1 && net.header_queue_len() >= PROVEN / 2
    })
    .await;
    honest.mine(1).await;
    let mined = Instant::now();
    let id = honest.chain.lock().unwrap().tip_id();
    wait_for("the header of H stored", 30, || stored(&chain, &id)).await;
    let lag = mined.elapsed().as_secs_f64();
    wait_for("the junk is hashed", 30, || {
        pow.junk.load(Relaxed) >= PROVEN as u64
    })
    .await;
    let s = net.stats();
    eprintln!(
        "outbound header lag behind {PROVEN} proven junk senders: {lag:.3} s; \
         junk hashes {} (budgeted failures {})",
        pow.junk.load(Relaxed),
        s.header_pow_failed
    );
    assert_eq!(s.header_pow_failed, 0, "proven identities are not budgeted");
    assert!(lag < 0.6, "the header of H waited {lag:.3} s");
}

/// The budget charges failures only: an honest inbound peer's valid headers
/// are refunded, so a budget of one hash with no refill still lets it
/// deliver header after header (after its first, a live new tip, it is
/// proven: `Peer::pow_proven`).
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
    };
    let (chain, net) = pow_node(pow, 0x53, cfg, &[]).await;
    let (_, _r, mut w) = raw_handshake(net.local_addr().unwrap(), 0, 5.0)
        .await
        .expect("handshake");
    for (i, h) in header_branch(5, u64::MAX).into_iter().enumerate() {
        w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
        wait_for("header stored", 20, || {
            chain.lock().unwrap().header_height() > i as u64
        })
        .await;
    }
    let s = net.stats();
    assert_eq!((s.header_pow_failed, s.header_pow_throttled), (0, 0));
}

/// Junk spends the budget and is never refunded; later untrusted batches
/// wait (kept in the queue, not dropped) instead of being hashed: with one
/// hash and no refill, of three junk senders one is hashed and two wait.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_spends_the_budget_and_later_untrusted_batches_wait_unhashed() {
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(1),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[]);
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 0.0,
    };
    let (prefix, g) = steep_prefix();
    let proto = junk_prototype(&g);
    let (_chain, net) = pow_node(pow.clone(), 0x54, cfg, &prefix).await;
    let addr = net.local_addr().unwrap();
    let mut keep = Vec::new();
    for k in 0..3u64 {
        let (_, r, mut w) = raw_handshake(addr, 0, 5.0).await.expect("handshake");
        let m = Message::Headers(vec![junk(&proto, k)]);
        w.send(&m.encode()).await.unwrap();
        wait_for("junk handled", 20, || {
            let s = net.stats();
            s.header_pow_failed + s.header_pow_throttled == k + 1
        })
        .await;
        keep.push((r, w));
    }
    let s = net.stats();
    assert_eq!((s.header_pow_failed, s.header_pow_throttled), (1, 2));
    assert_eq!(pow.junk.load(Relaxed), 1, "one junk hash, then none");
    assert_eq!(net.header_queue_len(), 2, "the other two wait");
    // RT-HDRDOS2 R2-3: a waiting sender that disconnects frees its room at
    // once (the worker is woken; with no refill it would otherwise sleep
    // until the next batch arrives).
    drop(keep);
    wait_for("the departed batches are released", 10, || {
        net.header_queue_len() == 0
    })
    .await;
}

/// RT-HDRDOS F3: a batch that waits for the budget is verified once a token
/// frees, without a new announcement from its sender: an honest untrusted
/// peer's header, behind spent junk, is stored after the refill (no claimed
/// height lowered, no better chain hidden).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_waiting_batch_is_verified_after_the_refill() {
    let pow = Arc::new(SlowJunkPow {
        delay: Duration::from_millis(1),
        junk: AtomicU64::new(0),
    });
    let mut cfg = fast_config(&[]);
    cfg.header_pow_budget = HeaderPowBudget {
        class_burst: 1.0,
        class_rate: 0.5,
    };
    let (prefix, mut g) = steep_prefix();
    let proto = junk_prototype(&g);
    let (chain, net) = pow_node(pow.clone(), 0x58, cfg, &prefix).await;
    let addr = net.local_addr().unwrap();
    let (_, _jr, mut jw) = raw_handshake(addr, 0, 5.0).await.expect("handshake");
    jw.send(&Message::Headers(vec![junk(&proto, 0)]).encode())
        .await
        .unwrap();
    wait_for("junk hashed", 20, || pow.junk.load(Relaxed) == 1).await;
    let (h, id) = next_valid(&mut g, 9);
    let (_, _r, mut w) = raw_handshake(addr, 0, 5.0).await.expect("handshake");
    let sent = Instant::now();
    w.send(&Message::Headers(vec![h]).encode()).await.unwrap();
    wait_for("the batch waits", 5, || {
        net.stats().header_pow_throttled == 1
    })
    .await;
    assert!(!stored(&chain, &id));
    wait_for("stored after the refill", 20, || stored(&chain, &id)).await;
    let waited = sent.elapsed().as_secs_f64();
    eprintln!("a waiting batch was verified {waited:.2} s after it arrived (refill 2 s)");
    assert!(waited > 1.0, "it waited for the refill: {waited:.2} s");
}
