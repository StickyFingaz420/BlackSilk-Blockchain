//! A10-H1 over real TCP: an attacker announces a header on the tip and never
//! serves its body. Before 2026-09-27 the header tied the honest miner's next
//! block, the node kept the first-seen (bodiless) header as its best chain,
//! and the connected chain never moved again. Honest nodes must keep
//! advancing and converge (docs/blocks.md §6).
//!
//! The harness helpers are copied from `network.rs` (kept independent of it).

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_p2p::dandelion::DandelionParams;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, FrameReader, FrameWriter};
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::types::Transaction;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

struct TestNode {
    chain: SharedChain,
    _net: Network,
    addr: SocketAddr,
    miner: WalletKeys,
    rng: ChaCha20Rng,
}

fn fast_config(connect: &[SocketAddr]) -> NetConfig {
    let mut cfg = NetConfig::new(params().network_id);
    cfg.listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.allow_private = true;
    cfg.connect = connect.iter().map(|a| NetAddr::Ip(*a)).collect();
    cfg.max_outbound = 4;
    cfg.trickle_outbound = Duration::from_millis(50);
    cfg.trickle_inbound = Duration::from_millis(50);
    cfg.tick = Duration::from_millis(50);
    cfg.pow_threads = 2;
    cfg.dandelion = DandelionParams {
        epoch_min: Duration::from_secs(600),
        epoch_max: Duration::from_secs(600),
        fluff_probability: 0.0,
        stem_peers: 2,
        embargo_base: Duration::from_millis(1500),
        embargo_mean: Duration::from_millis(500),
    };
    cfg
}

async fn node(seed: u64, connect: &[SocketAddr]) -> TestNode {
    let p = params();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [seed as u8; 32],
    )
    .unwrap();
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let net = Network::start(fast_config(connect), chain.clone())
        .await
        .unwrap();
    let addr = net.local_addr().unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (miner, _) = WalletKeys::generate(&mut rng);
    TestNode {
        chain,
        _net: net,
        addr,
        miner,
        rng,
    }
}

impl TestNode {
    fn height(&self) -> u64 {
        self.chain.lock().unwrap().height()
    }

    fn tip(&self) -> Hash {
        self.chain.lock().unwrap().tip_id()
    }

    fn knows_header(&self, id: &Hash) -> bool {
        self.chain.lock().unwrap().knows_valid_header(id)
    }

    /// Mines one block on the local tip; returns whether it was connected.
    fn mine(&mut self) -> bool {
        let mut c = self.chain.lock().unwrap();
        let t = c.template();
        let fees: u64 = t.txs.iter().map(Transaction::fee).sum();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: self.miner.address(SubaddressIndex::PRIMARY),
                amount: t.reward + fees,
            }],
            &self.miner.hedge_secret(),
            &mut self.rng,
        )
        .unwrap();
        let mut txs = vec![Transaction::Coinbase(cb)];
        txs.extend(t.txs.iter().cloned());
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 0,
        };
        let b = Block { header, txs };
        let now = b.header.timestamp;
        c.submit_block(b, now).unwrap().on_best_chain
    }
}

async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

type RawReader = FrameReader<ReadHalf<TcpStream>>;
type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

/// A hand-driven peer claiming a chain of `height` blocks.
async fn raw_peer_at(addr: SocketAddr, network_id: u32, height: u64) -> (RawReader, RawWriter) {
    let s = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, network_id, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: network_id,
        nonce: 0xdead_beef,
        height,
        tip: [0; 32],
        listen: None,
        relay_txs: false,
    };
    w.send(&Message::Version(v).encode()).await.unwrap();
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Version(_)
    ));
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Verack
    ));
    (r, w)
}

/// The attacker's side of one connection: announces `header`, then answers
/// pings (so it stays connected) and every block request with `NotFound`
/// (it never serves a body; answering at once keeps the test fast, a silent
/// attacker only adds the request timeout). Counts requests for `header`.
async fn withholding_peer(
    addr: SocketAddr,
    height: u64,
    header: BlockHeader,
    asked: Arc<AtomicUsize>,
) {
    let nid = params().network_id;
    let id = header.id(nid);
    let (mut r, mut w) = raw_peer_at(addr, nid, height).await;
    w.send(&Message::Headers(vec![header]).encode())
        .await
        .unwrap();
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            let reply = match Message::decode(&frame) {
                Ok(Message::Ping(n)) => Message::Pong(n),
                Ok(Message::GetBlocks(ids)) => {
                    if ids.contains(&id) {
                        asked.fetch_add(1, Ordering::SeqCst);
                    }
                    Message::NotFound(ids)
                }
                Ok(Message::GetHeaders { .. }) => Message::Headers(vec![]),
                _ => continue,
            };
            if w.send(&reply.encode()).await.is_err() {
                break;
            }
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withheld_body_does_not_stall_honest_nodes() {
    let mut a = node(81, &[]).await;
    let mut b = node(82, &[a.addr]).await;
    wait_until("B synced to 5", 20, || {
        a.mine_n_if_needed(5);
        b.height() == 5
    })
    .await;
    let f = a.tip();
    assert_eq!(b.tip(), f);

    // The attacker's B1 on F: a valid header (regtest PoW) whose body does
    // not exist (its tx_root commits to nothing anyone has).
    let b1 = {
        let c = a.chain.lock().unwrap();
        let t = c.template_on(&f).unwrap();
        BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: f,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: [0xB1; 32],
            nonce: 7,
        }
    };
    let b1_id = b1.id(params().network_id);
    let asked = Arc::new(AtomicUsize::new(0));
    withholding_peer(a.addr, 5, b1, asked.clone()).await;
    withholding_peer(b.addr, 5, b1, asked.clone()).await;
    wait_until("both nodes accept the bodiless header", 20, || {
        a.knows_header(&b1_id) && b.knows_header(&b1_id)
    })
    .await;
    assert_eq!(a.chain.lock().unwrap().best_header_id(), b1_id);
    wait_until("the body is requested from the attacker", 20, || {
        asked.load(Ordering::SeqCst) > 0
    })
    .await;

    // A1 ties B1. It is connected at once, and B follows.
    assert!(a.mine(), "A1 is connected despite the tied bodiless header");
    assert_eq!(a.height(), 6);
    assert_eq!(
        a.chain.lock().unwrap().best_header_id(),
        b1_id,
        "equal work: the header chain still prefers the first-seen B1"
    );
    wait_until("B connects A1", 30, || b.tip() == a.tip()).await;

    // Both keep advancing and converge, whoever mines.
    assert!(b.mine());
    wait_until("A follows B", 30, || a.height() == 7 && a.tip() == b.tip()).await;
    for _ in 0..3 {
        assert!(a.mine());
    }
    wait_until("B at 10", 30, || b.height() == 10 && b.tip() == a.tip()).await;
    for n in [&a, &b] {
        let c = n.chain.lock().unwrap();
        assert!(!c.has_body(&b1_id), "the body never arrived");
        assert_ne!(c.best_header_id(), b1_id);
        assert!(c.missing_bodies(100).is_empty(), "B1 is no longer wanted");
    }
}

impl TestNode {
    fn mine_n_if_needed(&mut self, n: u64) {
        while self.height() < n {
            assert!(self.mine());
        }
    }
}
