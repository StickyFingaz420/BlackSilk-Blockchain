//! Multi-node tests over real TCP on localhost: propagation, header-first sync,
//! Dandelion++ relay, reorganization across the network, peer discovery, and
//! defenses against misbehaving peers.

use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{
    seed_height, BlockHeader, ChainParams, Hash, HeaderChain, PowFunction, HEADER_VERSION,
};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_p2p::dandelion::DandelionParams;
use blacksilk_p2p::limits::score;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, FrameReader, FrameWriter};
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
use blacksilk_tx::px_builder::{build_px, px_standard_fee, PxPlan};
use blacksilk_tx::scan::scan_block;
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use blacksilk_tx::TxError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
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
    net: Network,
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

async fn node_with(seed: u64, cfg: NetConfig) -> TestNode {
    node_with_pow(seed, cfg, Arc::new(ZeroPow)).await
}

async fn node_with_pow(seed: u64, cfg: NetConfig, pow: Arc<dyn PowFunction>) -> TestNode {
    let p = params();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        pow,
        Box::<MemoryStore>::default(),
        [seed as u8; 32],
    )
    .unwrap();
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let net = Network::start(cfg, chain.clone()).await.unwrap();
    let addr = net.local_addr().unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (miner, _) = WalletKeys::generate(&mut rng);
    TestNode {
        chain,
        net,
        addr,
        miner,
        rng,
    }
}

async fn node(seed: u64, connect: &[SocketAddr]) -> TestNode {
    node_with(seed, fast_config(connect)).await
}

impl TestNode {
    fn height(&self) -> u64 {
        self.chain.lock().unwrap().height()
    }

    fn tip(&self) -> Hash {
        self.chain.lock().unwrap().tip_id()
    }

    fn mempool_has(&self, id: &Hash) -> bool {
        self.chain.lock().unwrap().mempool().contains(id)
    }

    /// Mines one block on the local tip (with mempool transactions).
    fn mine(&mut self, nonce: u64) -> Block {
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
            nonce,
        };
        let b = Block { header, txs };
        let now = b.header.timestamp;
        c.submit_block(b.clone(), now).unwrap();
        b
    }

    fn mine_n(&mut self, n: u64, nonce: u64) {
        for _ in 0..n {
            self.mine(nonce);
        }
    }

    /// A 1-input transfer from this node's miner wallet to a fresh wallet.
    fn payment(&mut self) -> Transaction {
        let (plan, rules) = self.input_plan(0);
        let (dest, _) = WalletKeys::generate(&mut self.rng);
        let tx = build_transfer(
            &self.miner,
            vec![plan],
            &[Payment {
                address: dest.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &self.miner.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, &rules),
            &rules,
            &mut self.rng,
        )
        .unwrap();
        Transaction::from(tx)
    }

    /// A PX deposit of `amount` from this node's miner wallet (one proof).
    fn px_deposit(&mut self, amount: u64) -> Transaction {
        let fee = px_standard_fee();
        let (plan, rules) = self.input_plan(amount + fee);
        let root = self.chain.lock().unwrap().state().px().root();
        let acct = Account::from_seed(&[5; 32]);
        let rng = &mut self.rng;
        let witness = pxw::witness(
            root,
            amount,
            0,
            [pxw::dummy_input(rng), pxw::dummy_input(rng)],
            [
                pxw::output(rng, acct.owner(0), amount),
                pxw::empty_output(rng),
            ],
        );
        let tx = build_px(
            PxPlan {
                keys: Some(&self.miner),
                inputs: vec![plan],
                change: Some(self.miner.address(SubaddressIndex::PRIMARY)),
                payouts: vec![],
                witness,
                recipients: [Some(acct.address(0)), None],
                functions: vec![],
                fee,
                hedge_secret: [0x5e; 32],
            },
            &rules,
            &mut self.rng,
        )
        .unwrap();
        Transaction::Px(Box::new(tx))
    }

    /// An input plan for a mature, unspent miner output worth more than
    /// `min_amount`.
    fn input_plan(&mut self, min_amount: u64) -> (InputPlan, TxRules) {
        let c = self.chain.lock().unwrap();
        let table = SubaddressTable::new(self.miner.view_keys(), 1, 2);
        let next = c.height() + 1;
        let mut owned = None;
        for h in 1..=c.height() {
            let b = c.block_at(h).unwrap();
            let first = c.state().first_output_at(h).unwrap();
            for o in scan_block(self.miner.view_keys(), &table, &b.txs, h, first).owned {
                if next >= o.height + COINBASE_MATURITY
                    && o.received.amount > min_amount
                    && !c.state().is_key_image_spent(&o.key_image(&self.miner))
                {
                    owned = Some(o);
                }
            }
            if owned.is_some() {
                break;
            }
        }
        let owned = owned.expect("a mature coinbase");
        let state = c.state();
        let ring = select_ring(
            &mut self.rng,
            &state.cumulative_outputs(),
            next,
            120,
            owned.global_index,
            |i| {
                state.output(i).is_some_and(|r| {
                    let age = if r.coinbase {
                        COINBASE_MATURITY
                    } else {
                        SPENDABLE_AGE
                    };
                    next >= r.height + age
                })
            },
        )
        .unwrap();
        let decoys = ring
            .iter()
            .filter(|&&i| i != owned.global_index)
            .map(|&i| Decoy {
                global_index: i,
                key: state.output(i).unwrap().key,
            })
            .collect();
        (
            InputPlan {
                real: SpendableOutput::from(&owned),
                decoys,
            },
            *c.rules(),
        )
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

// ---------------------------------------------------------------- raw peer

type RawReader = FrameReader<ReadHalf<TcpStream>>;
type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

/// A hand-driven peer for adversarial tests.
async fn raw_peer(addr: SocketAddr, network_id: u32, relay_txs: bool) -> (RawReader, RawWriter) {
    raw_peer_at(addr, network_id, relay_txs, 0).await
}

/// A raw peer claiming a chain of `height` blocks (so the node asks it for
/// headers).
async fn raw_peer_at(
    addr: SocketAddr,
    network_id: u32,
    relay_txs: bool,
    height: u64,
) -> (RawReader, RawWriter) {
    let s = TcpStream::connect(addr).await.unwrap();
    try_raw_handshake(s, network_id, relay_txs, height)
        .await
        .expect("handshake")
}

/// The raw peer's handshake on an open stream; `None` if the node drops it.
async fn try_raw_handshake(
    s: TcpStream,
    network_id: u32,
    relay_txs: bool,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    try_raw_handshake_as(s, true, network_id, relay_txs, height).await
}

/// The raw peer's handshake, as the side that opened the connection
/// (`initiator`) or the side that accepted it.
async fn try_raw_handshake_as(
    s: TcpStream,
    initiator: bool,
    network_id: u32,
    relay_txs: bool,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    let (mut r, mut w) = handshake(
        s,
        initiator,
        network_id,
        &params().genesis_id(),
        Duration::from_secs(5),
    )
    .await
    .ok()?;
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: network_id,
        nonce: 0xdead_beef,
        height,
        tip: [0; 32],
        listen: None,
        relay_txs,
    };
    w.send(&Message::Version(v).encode()).await.ok()?;
    let m = Message::decode(&r.recv().await.ok()?).ok()?;
    if !matches!(m, Message::Version(_)) {
        return None;
    }
    w.send(&Message::Verack.encode()).await.ok()?;
    let m = Message::decode(&r.recv().await.ok()?).ok()?;
    matches!(m, Message::Verack).then_some((r, w))
}

/// A TCP connection to `addr` from the loopback address `src` (127.0.0.0/8
/// gives tests many distinct source IPs).
async fn connect_from(src: [u8; 4], addr: SocketAddr) -> std::io::Result<TcpStream> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.bind(SocketAddr::from((src, 0)))?;
    sock.connect(addr).await
}

/// A raw peer connecting from the loopback address `src`.
async fn raw_peer_from(
    src: [u8; 4],
    addr: SocketAddr,
    network_id: u32,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    let s = connect_from(src, addr).await.ok()?;
    try_raw_handshake(s, network_id, true, height).await
}

/// What an honest peer holding `branch` (on genesis) answers to `locator`:
/// the headers after the first locator entry it knows, at most 2000.
fn serve_headers(branch: &[BlockHeader], locator: &[Hash]) -> Vec<BlockHeader> {
    let nid = params().network_id;
    let from = locator
        .iter()
        .find_map(|id| {
            if *id == params().genesis_id() {
                return Some(0);
            }
            branch.iter().position(|h| h.id(nid) == *id).map(|i| i + 1)
        })
        .unwrap_or(0);
    branch[from..branch.len().min(from + 2000)].to_vec()
}

/// Answers every `GetHeaders` from the node as an honest peer holding
/// `branch` (headers only) would, until the connection closes.
fn serve_branch(mut r: RawReader, mut w: RawWriter, branch: Vec<BlockHeader>) {
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            let reply = match Message::decode(&frame) {
                Ok(Message::GetHeaders { locator, .. }) => {
                    Message::Headers(serve_headers(&branch, &locator))
                }
                // Headers only: bodies are "not found" (no timeout penalty).
                Ok(Message::GetBlocks(ids)) => Message::NotFound(ids),
                _ => continue,
            };
            if w.send(&reply.encode()).await.is_err() {
                break;
            }
        }
    });
}

/// Reads messages until one matches `want`; `None` if the connection closes or
/// `secs` pass first.
async fn recv_until(
    r: &mut RawReader,
    secs: f64,
    want: impl Fn(&Message) -> bool,
) -> Option<Message> {
    tokio::time::timeout(Duration::from_secs_f64(secs), async {
        loop {
            let frame = r.recv().await.ok()?;
            let m = Message::decode(&frame).ok()?;
            if want(&m) {
                return Some(m);
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// `n` linked headers on genesis that satisfy every header rule under a PoW
/// function accepting everything; blocks `dt` seconds apart. With `nonce`
/// fixed, a node's PoW function can recognize (and fail) them.
fn header_branch(n: usize, dt: u64, nonce: u64) -> Vec<BlockHeader> {
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let t = g.template();
        let parent = *g.header(&t.prev_id).unwrap();
        let h = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(parent.timestamp + dt),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce,
        };
        g.accept(h, u64::MAX / 2).unwrap();
        out.push(h);
    }
    out
}

/// Counts PoW evaluations of headers carrying `BAD_NONCE`, and fails them
/// (the largest hash never meets a difficulty above 1). Everything else passes.
const BAD_NONCE: u64 = 0xBAD0_BAD0;
#[derive(Default)]
struct CountingPow(std::sync::atomic::AtomicUsize);
impl PowFunction for CountingPow {
    fn pow_hash(&self, _: &Hash, blob: &[u8]) -> Hash {
        let nonce = u64::from_le_bytes(
            blob[blacksilk_consensus::NONCE_OFFSET..blacksilk_consensus::NONCE_OFFSET + 8]
                .try_into()
                .unwrap(),
        );
        if nonce == BAD_NONCE {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            [0xff; 32]
        } else {
            [0; 32]
        }
    }
}

/// `CountingPow` that also takes `ms` milliseconds per hash.
struct SlowCountingPow(u64, CountingPow);
impl PowFunction for SlowCountingPow {
    fn pow_hash(&self, key: &Hash, blob: &[u8]) -> Hash {
        std::thread::sleep(Duration::from_millis(self.0));
        self.1.pow_hash(key, blob)
    }
}

/// A slow PoW function (every hash takes `ms` milliseconds; all pass).
struct SlowPow(u64);
impl PowFunction for SlowPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        std::thread::sleep(Duration::from_millis(self.0));
        [0; 32]
    }
}

/// Reads messages until the connection closes; returns whether it closed within `secs`.
async fn closes_within(r: &mut RawReader, secs: u64) -> bool {
    tokio::time::timeout(Duration::from_secs(secs), async {
        while r.recv().await.is_ok() {}
    })
    .await
    .is_ok()
}

// ---------------------------------------------------------------- tests

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_propagate_along_a_line() {
    let mut a = node(1, &[]).await;
    let b = node(2, &[a.addr]).await;
    let c = node(3, &[b.addr]).await;
    wait_until("connections", 10, || {
        a.net.stats().peers == 1 && c.net.stats().peers == 1
    })
    .await;
    a.mine_n(5, 0);
    wait_until("C at height 5", 20, || c.height() == 5).await;
    assert_eq!(c.tip(), a.tip());
    assert_eq!(b.tip(), a.tip());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn new_node_syncs_headers_first() {
    let mut a = node(4, &[]).await;
    a.mine_n(150, 0);
    let d = node(5, &[a.addr]).await;
    wait_until("D synced to 150", 60, || d.height() == 150).await;
    assert_eq!(d.tip(), a.tip());
    let (ga, gd) = (
        a.chain.lock().unwrap().generated(),
        d.chain.lock().unwrap().generated(),
    );
    assert_eq!(ga, gd, "same emission after sync");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transactions_travel_the_stem_then_fluff_everywhere() {
    let mut a = node(6, &[]).await;
    a.mine_n(80, 0);
    let b = node(7, &[a.addr]).await;
    let c = node(8, &[b.addr]).await;
    let mut d = node(9, &[c.addr]).await;
    wait_until("all synced", 60, || {
        b.height() == 80 && c.height() == 80 && d.height() == 80
    })
    .await;
    // A needs an outbound peer to stem through: dial B.
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("A has an outbound stem peer", 10, || {
        a.net.stats().outbound >= 1
    })
    .await;

    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx).await.unwrap();
    // Stem phase: the transaction sits in stempools, not in A's mempool.
    assert!(
        !a.mempool_has(&id),
        "local transactions are not broadcast directly"
    );
    wait_until("B received the stem transaction", 10, || {
        b.net.stempool_contains(&id) || b.mempool_has(&id)
    })
    .await;
    // After the embargo it is diffused to everyone.
    wait_until("D's mempool has the transaction", 30, || d.mempool_has(&id)).await;
    // D mines it; everyone confirms it.
    d.mine(0);
    wait_until("A confirms", 20, || a.height() == 81 && !a.mempool_has(&id)).await;
    // Blocks spread headers-first over whatever links address exchange made,
    // so C need not have the block before A does.
    wait_until("C confirms", 20, || c.height() == 81 && !c.mempool_has(&id)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn heavier_chain_wins_when_partitions_join() {
    let mut a = node(10, &[]).await;
    let mut b = node(11, &[]).await;
    a.mine_n(3, 1);
    b.mine_n(6, 2);
    assert_ne!(a.tip(), b.tip());
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("A reorganized to B's chain", 20, || a.tip() == b.tip()).await;
    assert_eq!(a.height(), 6);
}

fn free_local_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peers_are_discovered_through_addr_exchange() {
    let a = node(12, &[]).await;
    // B connects to A and advertises its listen address (`--public-address`).
    let b_addr = free_local_addr();
    let mut cfg = fast_config(&[a.addr]);
    cfg.listen = Some(b_addr);
    cfg.public_address = Some(NetAddr::Ip(b_addr));
    let b = node_with(13, cfg).await;
    let ab = a.net.clone();
    wait_until("A learned B's address", 10, || {
        let (n, t) = ab.stats().known_addresses;
        n + t >= 1
    })
    .await;
    // C knows only A, asks it for addresses, and dials B on its own.
    let c = node(15, &[a.addr]).await;
    wait_until("C discovered and connected to B", 20, || {
        c.net.peers().iter().any(|p| p.addr == NetAddr::Ip(b_addr))
    })
    .await;
    drop(b);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_header_gets_the_peer_disconnected() {
    let a = node(16, &[]).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    // A header on genesis with a wrong difficulty.
    let bad = BlockHeader {
        version: HEADER_VERSION,
        height: 1,
        prev_id: params().genesis_id(),
        timestamp: params().genesis.timestamp + 120,
        difficulty: 999_999,
        tx_root: [0; 32],
        nonce: 0,
    };
    w.send(&Message::Headers(vec![bad]).encode()).await.unwrap();
    assert!(closes_within(&mut r, 5).await, "disconnected");
    wait_until("peer gone", 5, || a.net.stats().peers == 0).await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 1);
    assert_eq!(a.height(), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn malformed_messages_and_floods_are_cut_off() {
    let a = node(17, &[]).await;
    let nid = params().network_id;
    // Undecodable message of a known type (valid encryption): a `Ping`
    // with 3 of its 8 nonce bytes. (Unknown types are ignored, see
    // `unknown_message_types_are_ignored_but_charged`.)
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    w.send(&[2, 1, 2, 3]).await.unwrap();
    assert!(closes_within(&mut r, 5).await);
    // Flood: 700 pings in a burst exceed the 500-message budget; each excess
    // message costs 1 point, so the peer is cut off at 100 points.
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let reader = tokio::spawn(async move { closes_within(&mut r, 10).await });
    for i in 0..700u64 {
        if w.send(&Message::Ping(i).encode()).await.is_err() {
            break;
        }
    }
    assert!(reader.await.unwrap(), "flooding peer disconnected");
    // The flooder is cut off either by its rate-limit score or, if the replies
    // pile up first, by the slow-reader protection (bounded outbox). Both are
    // intended defenses; which fires first depends on scheduling.
    wait_until("both gone", 5, || {
        let st = a.net.stats();
        st.peers == 0 && st.misbehaving_disconnects + st.slow_disconnects >= 2
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_network_and_self_connections_are_refused() {
    let a = node(18, &[]).await;
    // Different network id: the first frame does not decrypt.
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(
        s,
        true,
        params().network_id + 1,
        &params().genesis_id(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let _ = w.send(&Message::Verack.encode()).await;
    assert!(
        r.recv().await.is_err(),
        "no valid frame from a node of another network"
    );
    // Same network id, another genesis (R15-3): refused the same way.
    let s = TcpStream::connect(a.addr).await.unwrap();
    let mut other_genesis = params().genesis_id();
    other_genesis[0] ^= 1;
    let (mut r, mut w) = handshake(
        s,
        true,
        params().network_id,
        &other_genesis,
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let _ = w.send(&Message::Verack.encode()).await;
    assert!(
        r.recv().await.is_err(),
        "no valid frame from a node of another genesis"
    );
    // Self connection.
    a.net.connect(NetAddr::Ip(a.addr));
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.net.stats().peers, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mempool_cannot_be_probed_with_gettx() {
    let mut a = node(19, &[]).await;
    a.mine_n(80, 0);
    let nid = params().network_id;
    // A block-relay-only spy: A never announces transactions to it.
    let (mut r, mut w) = raw_peer(a.addr, nid, false).await;
    let tx = a.payment();
    let id = tx.hash();
    a.chain.lock().unwrap().submit_tx(tx).unwrap(); // in A's mempool
    w.send(&Message::GetTx(vec![id]).encode()).await.unwrap();
    w.send(&Message::Ping(77).encode()).await.unwrap();
    // The answer is NotFound, exactly as for a transaction the node never had: the
    // reply does not reveal the mempool content.
    let mut not_found = false;
    loop {
        match Message::decode(&r.recv().await.unwrap()).unwrap() {
            Message::Pong(77) => break,
            Message::NotFound(ids) => {
                assert_eq!(ids, vec![id]);
                not_found = true;
            }
            Message::Tx(_) => panic!("served a transaction that was never announced to this peer"),
            _ => {}
        }
    }
    assert!(not_found);
    // Same answer for an id that does not exist at all.
    w.send(&Message::GetTx(vec![[0x55; 32]]).encode())
        .await
        .unwrap();
    loop {
        if let Message::NotFound(ids) = Message::decode(&r.recv().await.unwrap()).unwrap() {
            assert_eq!(ids, vec![[0x55; 32]]);
            break;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn connect_only_nodes_do_not_dial_discovered_addresses() {
    let a = node(20, &[]).await;
    let b_addr = free_local_addr();
    let mut cfg = fast_config(&[a.addr]);
    cfg.listen = Some(b_addr);
    cfg.public_address = Some(NetAddr::Ip(b_addr));
    let _b = node_with(21, cfg).await;
    let an = a.net.clone();
    wait_until("A learned B", 10, || {
        let (n, t) = an.stats().known_addresses;
        n + t >= 1
    })
    .await;
    let mut cfg = fast_config(&[a.addr]);
    cfg.connect_only = true;
    let c = node_with(22, cfg).await;
    wait_until("C connected to A", 10, || c.net.stats().peers >= 1).await;
    // C learns B's address from A but must not dial it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let peers = c.net.peers();
    assert_eq!(peers.len(), 1, "{peers:?}");
    assert_eq!(peers[0].addr, NetAddr::Ip(a.addr));
}

/// Regression (lab network finding): relaying a transaction that the node has just
/// seen confirmed is an honest race, not misbehavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relaying_an_already_confirmed_transaction_is_not_penalized() {
    let mut a = node(23, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let id = tx.hash();
    a.chain.lock().unwrap().submit_tx(tx.clone()).unwrap();
    a.mine(0); // confirms it: its key image is now spent
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    // The node asks for it (it is no longer in its mempool) ...
    loop {
        if let Message::GetTx(ids) = Message::decode(&r.recv().await.unwrap()).unwrap() {
            assert_eq!(ids, vec![id]);
            break;
        }
    }
    // ... and gets a transaction that is now invalid only because of chain state.
    w.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
    w.send(&Message::Ping(9).encode()).await.unwrap();
    loop {
        if let Message::Pong(9) = Message::decode(&r.recv().await.unwrap()).unwrap() {
            break;
        }
    }
    let peers = a.net.peers();
    assert_eq!(peers.len(), 1, "still connected");
    assert_eq!(peers[0].score, 0, "no penalty for a contextual failure");
    // A stateless-invalid transaction, by contrast, is penalized.
    let Transaction::Transfer(mut bad) = tx else {
        unreachable!()
    };
    bad.fee += 1; // breaks the balance (stateless rule T9)
    let bad = Transaction::from(*bad);
    w.send(&Message::InvTx(vec![bad.hash()]).encode())
        .await
        .unwrap();
    loop {
        if let Message::GetTx(_) = Message::decode(&r.recv().await.unwrap()).unwrap() {
            break;
        }
    }
    w.send(&Message::Tx(bad.encode()).encode()).await.unwrap();
    wait_until("penalized", 5, || {
        a.net.peers().first().is_some_and(|p| p.score >= 20)
    })
    .await;
}

/// A PX transaction (docs/px.md §11) takes the same Dandelion++ path as a
/// transfer: stem first (not in the origin's mempool), then diffusion; every
/// node verifies its proof, and once mined all nodes hold the same PX state.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn px_transactions_travel_the_stem_and_confirm_everywhere() {
    let mut a = node(30, &[]).await;
    a.mine_n(80, 0);
    let b = node(31, &[a.addr]).await;
    let c = node(32, &[b.addr]).await;
    wait_until("all synced", 60, || b.height() == 80 && c.height() == 80).await;
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("A has an outbound stem peer", 10, || {
        a.net.stats().outbound >= 1
    })
    .await;

    let tx = a.px_deposit(5_000_000);
    let id = tx.hash();
    let bytes = tx.encode();
    a.net.submit_tx(tx).await.unwrap();
    assert!(
        !a.mempool_has(&id),
        "PX transactions are stemmed, not broadcast"
    );
    wait_until("B received the stem transaction", 20, || {
        b.net.stempool_contains(&id) || b.mempool_has(&id)
    })
    .await;
    wait_until("C's mempool has the PX transaction", 60, || {
        c.mempool_has(&id)
    })
    .await;
    // No peer was penalized for relaying it.
    for n in [&a, &b, &c] {
        assert!(n.net.peers().iter().all(|p| p.score == 0));
    }
    let mut c = c;
    c.mine(0);
    wait_until("A and B confirm", 30, || {
        a.height() == 81 && b.height() == 81 && !a.mempool_has(&id) && !b.mempool_has(&id)
    })
    .await;
    let roots: Vec<_> = [&a, &b, &c]
        .iter()
        .map(|n| {
            let ch = n.chain.lock().unwrap();
            (ch.state().px().root(), ch.state().px().pool())
        })
        .collect();
    assert!(
        roots.windows(2).all(|w| w[0] == w[1]),
        "one PX state everywhere"
    );
    assert_eq!(roots[0].1, 5_000_000, "the pool holds the deposit");

    // Relay limits (docs/p2p.md §10). Five peers each stem the (now confirmed)
    // transaction 4 times: within each peer's share (burst 4). Every copy
    // fails the cheap contextual check (a spent nullifier) before the
    // node-wide PX token is taken, and no peer is penalized for it. A sixth
    // peer exceeding its own share is penalized.
    let nid = params().network_id;
    let before: Vec<_> = b.net.peers().iter().map(|p| p.id).collect();
    let mut raws = Vec::new();
    for _ in 0..5 {
        raws.push(raw_peer(b.addr, nid, true).await);
    }
    let (r6, mut w6) = raw_peer(b.addr, nid, true).await;
    for (_, w) in raws.iter_mut() {
        for _ in 0..4 {
            w.send(&Message::StemTx(bytes.clone()).encode())
                .await
                .unwrap();
        }
    }
    for _ in 0..8 {
        w6.send(&Message::StemTx(bytes.clone()).encode())
            .await
            .unwrap();
    }
    // A ping after the stems: its pong means they were all handled.
    raws.push((r6, w6));
    for (i, (r, w)) in raws.iter_mut().enumerate() {
        w.send(&Message::Ping(100 + i as u64).encode())
            .await
            .unwrap();
        loop {
            if let Message::Pong(n) = Message::decode(&r.recv().await.unwrap()).unwrap() {
                if n == 100 + i as u64 {
                    break;
                }
            }
        }
    }
    let scores: Vec<u32> = b
        .net
        .peers()
        .iter()
        .filter(|p| !before.contains(&p.id))
        .map(|p| p.score)
        .collect();
    assert_eq!(scores.len(), 6);
    let penalized: Vec<u32> = scores.into_iter().filter(|&s| s > 0).collect();
    assert_eq!(
        penalized.len(),
        1,
        "only the peer over its own share: {penalized:?}"
    );
    assert!(
        (3..=4).contains(&penalized[0]),
        "one point per excess message"
    );
}

/// A peer relaying an invalid PX transaction is penalized as misbehaving
/// when the failure is stateless (AUDIT.md ZK-F15, ZK-F23), and the
/// transaction is neither pooled nor stemmed further:
/// - a PX-only transaction (no v1 inputs) with a corrupted proof: `PxProof`;
/// - the same transaction with a fee that is not the standard fee.
///
/// A deposit's v1 ring signatures cover the proof bytes, so nobody can alter
/// the proof of someone else's deposit. Here the deposit is already mined,
/// so the altered copy fails on its spent key image first: contextual, not
/// penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_px_transactions_get_the_relaying_peer_penalized() {
    use blacksilk_px::delivery;
    use blacksilk_px::perm::HostPerm;
    use blacksilk_px::tree::Tree;

    let mut a = node(40, &[]).await;
    a.mine_n(80, 0);
    // A deposit to `acct` (larger than the standard fee), mined.
    let deposit = a.px_deposit(50_000_000);
    let Transaction::Px(dep) = deposit.clone() else {
        unreachable!()
    };
    a.chain.lock().unwrap().submit_tx(deposit).unwrap();
    a.mine(0);
    // `acct` spends it privately: a PX-only transaction (no v1 inputs).
    let acct = Account::from_seed(&[5; 32]);
    let fee = px_standard_fee();
    let entries = a.chain.lock().unwrap().state().px_records(0, u64::MAX);
    let mut perm = HostPerm::new();
    let mut tree = Tree::new(&mut perm);
    for e in &entries {
        tree.append(&mut perm, e.commitment).unwrap();
    }
    let (rec, pos) = entries
        .iter()
        .find_map(|e| {
            let rho = blacksilk_px::core::record::output_rho(&mut perm, &e.nf0, e.slot);
            delivery::open(
                &acct.delivery_keys(0),
                &acct.owner(0),
                &e.ciphertext,
                &e.commitment,
                &rho,
            )
            .map(|r| (r, e.position))
        })
        .expect("the deposit's record");
    let rng = &mut a.rng;
    let witness = pxw::witness(
        tree.root(),
        0,
        fee,
        [
            acct.spend(0, &rec, pos, tree.path(pos).unwrap()),
            pxw::dummy_input(rng),
        ],
        [
            pxw::output(rng, acct.owner(1), rec.value - fee),
            pxw::empty_output(rng),
        ],
    );
    let rules = TxRules::for_chain(&params());
    let spend = build_px(
        PxPlan {
            keys: None,
            inputs: vec![],
            change: None,
            payouts: vec![],
            witness,
            recipients: [Some(acct.address(1)), None],
            functions: vec![],
            fee,
            hedge_secret: [0x5e; 32],
        },
        &rules,
        &mut a.rng,
    )
    .unwrap();

    let mut bad_proof = spend.clone();
    let mid = bad_proof.proof.len() / 2;
    bad_proof.proof[mid] ^= 1;
    let mut bad_fee = spend.clone();
    bad_fee.fee += 1;
    let mut bad_deposit = (*dep).clone();
    let mid = bad_deposit.proof.len() / 2;
    bad_deposit.proof[mid] ^= 1;
    for (what, bad, penalized) in [
        ("corrupted proof", bad_proof, true),
        ("non-standard fee", bad_fee, true),
        ("corrupted deposit proof", bad_deposit, false),
    ] {
        let bad = Transaction::Px(Box::new(bad));
        let id = bad.hash();
        let verdict = a.chain.lock().unwrap().check_tx(&bad);
        match what {
            "corrupted proof" => assert!(
                matches!(
                    verdict,
                    Err(blacksilk_chain::mempool::MempoolError::Invalid(
                        blacksilk_tx::TxError::PxProof
                    ))
                ),
                "{verdict:?}"
            ),
            "non-standard fee" => assert!(
                matches!(
                    verdict,
                    Err(blacksilk_chain::mempool::MempoolError::Invalid(
                        blacksilk_tx::TxError::PxFeeNotStandard { .. }
                    ))
                ),
                "{verdict:?}"
            ),
            _ => assert!(
                matches!(
                    verdict,
                    Err(blacksilk_chain::mempool::MempoolError::Invalid(
                        blacksilk_tx::TxError::InvalidSignature { .. }
                            | blacksilk_tx::TxError::KeyImageSpent { .. }
                    ))
                ),
                "{verdict:?}"
            ),
        }
        let (r, mut w) = raw_peer(a.addr, params().network_id, true).await;
        w.send(&Message::StemTx(bad.encode()).encode())
            .await
            .unwrap();
        if penalized {
            wait_until(what, 60, || {
                a.net.peers().iter().any(|p| p.score >= score::INVALID_TX)
            })
            .await;
        } else {
            // Give the node time to process it; the peer stays unpenalized.
            tokio::time::sleep(Duration::from_secs(3)).await;
            assert!(a.net.peers().iter().all(|p| p.score == 0), "{what}");
        }
        assert!(
            !a.mempool_has(&id) && !a.net.stempool_contains(&id),
            "{what}"
        );
        drop((r, w));
        wait_until("the raw peer is gone", 20, || a.net.peers().is_empty()).await;
    }
}

/// Adversarial: a double spend across a partition. A and B share a history;
/// while apart, each confirms a different spend of the same output. When they
/// join, the heavier branch wins everywhere: exactly one spend survives, the
/// other disappears from every pool, a third node agrees, and no honest peer
/// is penalized for relaying the loser.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_spend_across_a_partition_resolves_to_one_spend() {
    let mut a = node(40, &[]).await;
    let mut b = node(41, &[]).await;
    a.mine_n(80, 0);
    // B gets the same history directly (the partition starts after it).
    {
        let ca = a.chain.lock().unwrap();
        let mut cb = b.chain.lock().unwrap();
        for h in 1..=ca.height() {
            let block = ca.block_at(h).unwrap();
            let now = block.header.timestamp;
            cb.submit_block(block, now).unwrap();
        }
    }
    assert_eq!(a.tip(), b.tip());
    // Two spends of the same output (the oldest mature coinbase), to
    // different payees.
    let tx1 = a.payment();
    let tx2 = a.payment();
    let ki = |t: &Transaction| *t.key_images()[0].bytes();
    assert_eq!(ki(&tx1), ki(&tx2), "the same output");
    assert_ne!(tx1.hash(), tx2.hash());
    a.chain.lock().unwrap().submit_tx(tx1.clone()).unwrap();
    b.chain.lock().unwrap().submit_tx(tx2.clone()).unwrap();
    a.mine(1); // A confirms tx1
    b.mine(2); // B confirms tx2 ...
    b.mine(2); // ... on a heavier branch
    assert_ne!(a.tip(), b.tip());

    // The partition heals; a third node joins both.
    a.net.connect(NetAddr::Ip(b.addr));
    let c = node(42, &[a.addr, b.addr]).await;
    wait_until("all on B's branch", 30, || {
        a.tip() == b.tip() && c.tip() == b.tip()
    })
    .await;
    assert_eq!(a.height(), 82);
    for n in [&a, &b, &c] {
        let m = n.chain.lock().unwrap();
        assert!(
            m.state().is_key_image_spent(&tx2.key_images()[0]),
            "the output is spent"
        );
        assert!(!m.mempool().contains(&tx1.hash()), "the loser is gone");
        assert!(!m.mempool().contains(&tx2.hash()), "the winner is mined");
        // Exactly one of the two spends is in the chain.
        let mined: Vec<Hash> = (1..=m.height())
            .flat_map(|h| m.block_at(h).unwrap().txs)
            .map(|t| t.hash())
            .filter(|id| *id == tx1.hash() || *id == tx2.hash())
            .collect();
        assert_eq!(mined, vec![tx2.hash()]);
    }
    assert_eq!(a.chain.lock().unwrap().deepest_reorg(), 1);
    for n in [&a, &b, &c] {
        assert!(
            n.net.peers().iter().all(|p| p.score == 0),
            "no honest peer penalized"
        );
    }
}

// ------------------------------------------ header sync hardening (N-1..N-4)

/// Defect 1: a peer's header batch is checked against every cheap rule before
/// any RandomX work. A solicited batch of MAX_HEADERS headers whose first
/// header has a wrong difficulty costs no PoW at all; one that passes the cheap
/// rules but not the PoW costs at most one chunk (`pow_threads`) of hashes
/// beyond its last valid header. Before the fix, the whole batch (2000 RandomX
/// hashes, ~900 CPU-seconds at testnet cost) was hashed first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_header_batches_cost_at_most_one_chunk_of_proof_of_work() {
    let pow = Arc::new(CountingPow::default());
    let a = node_with_pow(40, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let count = || pow.0.load(std::sync::atomic::Ordering::SeqCst);

    // (a) Cheap failure: header 0 has a wrong difficulty, the other 1999 are
    // well formed (and all carry the bad nonce).
    let mut junk = header_branch(2000, 120, BAD_NONCE);
    junk[0].difficulty += 7;
    for i in 1..junk.len() {
        junk[i].prev_id = junk[i - 1].id(nid);
    }
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10_000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some(),
        "the node asks for headers"
    );
    w.send(&Message::Headers(junk).encode()).await.unwrap();
    assert!(closes_within(&mut r, 10).await, "peer disconnected");
    assert_eq!(
        count(),
        0,
        "no proof of work for a batch failing the cheap rules"
    );

    // (b) Only the PoW fails. 1-second blocks lift the difficulty above 1
    // (regtest starts at 1, where every hash passes).
    let junk = header_branch(2000, 1, BAD_NONCE);
    let first_hard = junk
        .iter()
        .position(|h| h.difficulty > 1)
        .expect("difficulty rises");
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10_000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(junk).encode()).await.unwrap();
    assert!(closes_within(&mut r, 10).await, "peer disconnected");
    let threads = fast_config(&[]).pow_threads;
    assert!(
        count() <= first_hard + threads,
        "{} hashes for a batch that fails at header {first_hard}",
        count()
    );
    wait_until("both banned", 5, || {
        a.net.stats().misbehaving_disconnects == 2
    })
    .await;
    // Only the valid prefix (difficulty 1) was stored.
    assert!(a.chain.lock().unwrap().header_height() < first_hard as u64 + 1);
}

/// Defect 1 (cont.): headers nobody asked for must be a single tip
/// announcement. An unrequested batch is not verified at all and costs the
/// sender the unsolicited-message penalty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unrequested_header_batch_is_not_verified() {
    let pow = Arc::new(CountingPow::default());
    let a = node_with_pow(41, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    w.send(&Message::Headers(header_branch(50, 120, BAD_NONCE)).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(7).encode()).await.unwrap();
    assert!(recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(7)))
        .await
        .is_some());
    assert_eq!(pow.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(a.chain.lock().unwrap().header_height(), 0);
    assert_eq!(a.net.peers()[0].score, score::UNSOLICITED);
}

/// Counts every PoW evaluation; fails headers carrying `BAD_NONCE` (as
/// `CountingPow`).
#[derive(Default)]
struct CountAllPow(std::sync::atomic::AtomicUsize);
impl PowFunction for CountAllPow {
    fn pow_hash(&self, seed: &Hash, blob: &[u8]) -> Hash {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        CountingPow::default().pow_hash(seed, blob)
    }
}

/// RT-1: a header of a version above every version the schedule knows is not
/// penalized only if its proof of work is real. With junk proof of work the
/// sender is penalized like for any invalid header (one hash spent). With real
/// work the sender is not scored, and after `UNKNOWN_UPGRADE_DISCONNECT` (3)
/// such headers it is disconnected without a ban.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_version_headers_need_real_proof_of_work() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(43, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let hashes = || pow.0.load(std::sync::atomic::Ordering::SeqCst);
    // 1-second blocks lift the difficulty above 1 (at 1 every hash passes).
    let prefix = header_branch(30, 1, 0);
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &prefix {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let t = g.template();
    assert!(t.difficulty > 1);
    let newer = |nonce| BlockHeader {
        version: HEADER_VERSION + 6,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(prefix[29].timestamp + 1),
        difficulty: t.difficulty,
        tx_root: [0; 32],
        nonce,
    };

    // (a) Junk proof of work, at the end of a requested batch: penalized.
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10_000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    let mut batch = prefix.clone();
    batch.push(newer(BAD_NONCE));
    w.send(&Message::Headers(batch).encode()).await.unwrap();
    assert!(
        closes_within(&mut r, 10).await,
        "penalized and disconnected"
    );
    wait_until("penalized", 5, || {
        a.net.stats().misbehaving_disconnects == 1
    })
    .await;
    assert_eq!(
        a.chain.lock().unwrap().header_height(),
        30,
        "the prefix is stored"
    );

    // (b) Real proof of work, as tip announcements: not scored; disconnected
    // (not banned) at the third.
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    for k in 0..2u64 {
        let before = hashes();
        w.send(&Message::Headers(vec![newer(100 + k)]).encode())
            .await
            .unwrap();
        wait_until("hashed", 5, || hashes() > before).await;
        w.send(&Message::Ping(k).encode()).await.unwrap();
        assert!(
            recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(x) if *x == k))
                .await
                .is_some(),
            "still connected after {} reports",
            k + 1
        );
        assert_eq!(a.net.peers()[0].score, 0, "not penalized");
    }
    w.send(&Message::Headers(vec![newer(102)]).encode())
        .await
        .unwrap();
    assert!(closes_within(&mut r, 10).await, "disconnected at the third");
    wait_until("peer gone", 5, || a.net.stats().peers == 0).await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 1, "no penalty");
    assert_eq!(a.net.stats().banned, 0, "no ban");
    assert_eq!(a.chain.lock().unwrap().header_height(), 30);
}

/// Defect 2: a peer relaying headers of a block whose *body* we found invalid
/// (or of its descendants) is not banned: it cannot know without the body.
/// Before the fix every such relay scored 100 (an immediate ban), so one
/// invalid-body block could split honest nodes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relaying_headers_of_a_block_with_an_invalid_body_is_not_penalized() {
    let mut a = node(42, &[]).await;
    a.mine_n(2, 0);
    // A block with a valid header and an invalid body (the coinbase overpays).
    let bad = {
        let mut c = a.chain.lock().unwrap();
        let t = c.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: a.miner.address(SubaddressIndex::PRIMARY),
                amount: t.reward + 1,
            }],
            &a.miner.hedge_secret(),
            &mut a.rng,
        )
        .unwrap();
        let txs = vec![Transaction::Coinbase(cb)];
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
        assert!(
            c.submit_block(b.clone(), header.timestamp).is_err(),
            "body invalid"
        );
        b.header
    };
    // A child of the invalid block with a valid header.
    let child = {
        let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
        let c = a.chain.lock().unwrap();
        for h in 1..=2 {
            g.accept(c.block_at(h).unwrap().header, u64::MAX / 2)
                .unwrap();
        }
        let x = g.accept(bad, u64::MAX / 2).unwrap().id;
        let t = g.template_on(x).unwrap();
        BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: x,
            timestamp: t.min_timestamp.max(bad.timestamp + 120),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: 0,
        }
    };
    let nid = params().network_id;
    // Announced one by one, and as a solicited batch.
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(vec![bad, child]).encode())
        .await
        .unwrap();
    w.send(&Message::Headers(vec![bad]).encode()).await.unwrap();
    w.send(&Message::Headers(vec![child]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(9).encode()).await.unwrap();
    assert!(recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(9)))
        .await
        .is_some());
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 0);
    assert_eq!(a.net.peers().len(), 1, "still connected");
    assert_eq!(a.net.peers()[0].score, 0, "not penalized");
    assert_eq!(a.height(), 2, "the invalid branch is not followed");
    // A header that itself breaks the rules is still penalized.
    let mut broken = child;
    broken.prev_id = a.tip();
    broken.difficulty += 3;
    w.send(&Message::Headers(vec![broken]).encode())
        .await
        .unwrap();
    assert!(
        closes_within(&mut r, 5).await,
        "a rule-breaking header gets the peer banned"
    );
}

/// Defect 3: blocks we requested are not charged to the peer's byte budget.
/// With a byte budget far below the blocks' total size, a node still syncs
/// every block from an honest peer without penalizing it. Before the fix the
/// requested blocks beyond the budget were dropped (+1 each), timed out (+5
/// each) and re-requested.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requested_blocks_are_not_dropped_by_the_byte_limit() {
    let mut a = node(43, &[]).await;
    a.mine_n(48, 0);
    let total: usize = {
        let c = a.chain.lock().unwrap();
        (1..=48)
            .map(|h| c.block_at(h).unwrap().encode().len())
            .sum()
    };
    let mut cfg = fast_config(&[a.addr]);
    let burst = 1_500.0;
    cfg.peer_limits.bytes = blacksilk_p2p::limits::TokenBucket::new(50.0, burst);
    assert!(
        total as f64 > 2.0 * burst,
        "blocks ({total} B) exceed the byte budget"
    );
    let b = node_with(44, cfg).await;
    wait_until("b synced", 30, || b.height() == 48).await;
    assert_eq!(b.tip(), a.tip());
    let peers = b.net.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].score, 0, "the honest peer was not penalized");
    assert_eq!(b.net.stats().misbehaving_disconnects, 0);
}

/// Defect 4: verifying a header batch does not block the peer's read loop, so
/// pings are answered while the proof of work runs. Before the fix a batch
/// held the loop for its whole PoW (2000 x 0.45 s / threads at testnet
/// cost), longer than the 30 s pong timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pings_are_answered_while_a_header_batch_is_verified() {
    let mut cfg = fast_config(&[]);
    cfg.pow_threads = 1;
    // 300 headers x 20 ms (about 30 ms with Windows timer granularity): 6 to
    // 10 s of proof of work on one thread.
    let a = node_with_pow(45, cfg, Arc::new(SlowPow(20))).await;
    let nid = params().network_id;
    let batch = header_branch(300, 120, 0);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 300).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(batch).encode()).await.unwrap();
    let started = std::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(300)).await;
    w.send(&Message::Ping(77).encode()).await.unwrap();
    assert!(
        recv_until(&mut r, 1.0, |m| matches!(m, Message::Pong(77)))
            .await
            .is_some(),
        "pong while the batch is being verified"
    );
    assert!(
        a.chain.lock().unwrap().header_height() < 300,
        "the batch was still being verified when the pong came"
    );
    wait_until("batch verified", 120, || {
        a.chain.lock().unwrap().header_height() == 300
    })
    .await;
    assert!(started.elapsed() > Duration::from_secs(3));
    assert_eq!(a.net.peers()[0].score, 0);
}

/// A peer that disconnects before its batch is verified is still charged: the
/// verdict comes from the header worker after the peer has left. Its batch
/// waits behind another peer's (slow) batch; when its turn comes, the sender is
/// gone, so only the cheap pre-check runs: the rule violation is found and
/// charged, and none of its headers is hashed or stored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_leaves_before_its_bad_batch_is_verified_is_still_charged() {
    let mut cfg = fast_config(&[]);
    cfg.pow_threads = 1;
    let a = node_with_pow(46, cfg, Arc::new(SlowPow(20))).await;
    let nid = params().network_id;
    // An honest batch that keeps the header worker busy for 4 to 6 s (more
    // on a loaded machine).
    let (mut r1, mut w1) = raw_peer_at(a.addr, nid, true, 200).await;
    assert!(
        recv_until(&mut r1, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w1.send(&Message::Headers(header_branch(200, 120, 0)).encode())
        .await
        .unwrap();
    // 100 valid headers, then one that breaks a rule.
    let mut batch = header_branch(101, 120, 5);
    batch[100].difficulty += 5;
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 1000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(batch.clone()).encode())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    drop((r, w));
    wait_until("peer gone", 5, || a.net.stats().peers == 1).await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 0, "not yet verified");
    wait_until("charged after leaving", 120, || {
        a.net.stats().misbehaving_disconnects == 1
    })
    .await;
    let c = a.chain.lock().unwrap();
    assert!(
        c.header(&batch[0].id(nid)).is_none(),
        "nothing of a banned sender's batch is stored"
    );
    assert_eq!(c.header_height(), 200, "the honest batch is kept");
}

// ------------------------------------------ P2P hardening round 2 (review items)

fn hashed(pow: &CountingPow) -> usize {
    pow.0.load(std::sync::atomic::Ordering::SeqCst)
}

/// H1: the header queue is bounded per origin and in total, and batches of
/// senders that left are only pre-checked (never hashed). Junk peers
/// reconnecting from many source addresses while the worker is busy cannot
/// grow the queue past `2 x (max_inbound + max_outbound)`, and an honest
/// peer's batch is processed promptly after the busy batch. Before the fix
/// every departed sender's batch stayed queued and was fully verified
/// (here 2000 hashes each), starving honest header sync.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_header_queue_is_bounded_across_reconnects() {
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false; // per-IP limits apply to loopback
    cfg.max_inbound = 4;
    cfg.max_outbound = 4;
    cfg.pow_threads = 1;
    let cap = 2 * (cfg.max_inbound + cfg.max_outbound);
    let pow = Arc::new(SlowCountingPow(20, CountingPow::default()));
    let a = node_with_pow(47, cfg, pow.clone()).await;
    let nid = params().network_id;
    // A slow honest batch occupies the worker (300 x 20-30 ms).
    let (mut r0, mut w0) = raw_peer_from([127, 0, 0, 1], a.addr, nid, 300)
        .await
        .unwrap();
    assert!(
        recv_until(&mut r0, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w0.send(&Message::Headers(header_branch(300, 120, 0)).encode())
        .await
        .unwrap();
    // 40 junk peers from 20 source IPs (two each), each sending a full batch
    // that only the PoW would reject, then leaving.
    let junk = Message::Headers(header_branch(2000, 120, BAD_NONCE)).encode();
    let mut most = 0;
    for i in 0..40u8 {
        let src = [127, 0, 1, 1 + i / 2];
        let Some((mut r, mut w)) = raw_peer_from(src, a.addr, nid, 10_000).await else {
            continue;
        };
        if recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_none()
        {
            continue;
        }
        w.send(&junk).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop((r, w));
        most = most.max(a.net.header_queue_len());
    }
    assert!(most <= cap, "queue grew to {most} (cap {cap})");
    assert!(most >= 3, "the flood did queue batches ({most})");
    // An honest peer from another address, with more headers.
    let honest = header_branch(400, 120, 0);
    let (r, w) = raw_peer_from([127, 0, 0, 2], a.addr, nid, 400)
        .await
        .unwrap();
    serve_branch(r, w, honest);
    wait_until("the busy batch is verified", 120, || {
        a.chain.lock().unwrap().header_height() >= 300
    })
    .await;
    let t = std::time::Instant::now();
    wait_until("the honest batch is verified", 40, || {
        a.chain.lock().unwrap().header_height() == 400
    })
    .await;
    assert!(
        t.elapsed() < Duration::from_secs(30),
        "honest sync waited {:?}",
        t.elapsed()
    );
    assert_eq!(
        hashed(&pow.1),
        0,
        "no junk header of a departed sender was hashed"
    );
    wait_until("queue drained", 10, || a.net.header_queue_len() == 0).await;
}

/// H2: concurrent handshakes cannot bypass `max_per_ip` or `max_inbound`:
/// connections still in their handshake count against both limits at accept
/// time, and the limits are re-checked at registration. Before the fix only
/// registered peers were counted, so all these connections were accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_handshakes_respect_the_inbound_limits() {
    let nid = params().network_id;
    async fn flood(addr: SocketAddr, n: usize) -> usize {
        let nid = params().network_id;
        // All TCP connections first (accepted by the node), then all the
        // handshakes at once: none is registered when the others arrive.
        let mut streams = Vec::new();
        for _ in 0..n {
            streams.push(TcpStream::connect(addr).await.unwrap());
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let tasks: Vec<_> = streams
            .into_iter()
            .map(|s| tokio::spawn(try_raw_handshake(s, nid, true, 0)))
            .collect();
        let mut ok = Vec::new();
        for t in tasks {
            if let Some(p) = t.await.unwrap() {
                ok.push(p);
            }
        }
        let n = ok.len();
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(ok);
        n
    }
    // Per IP (loopback counts as one IP when `allow_private` is off).
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    cfg.max_per_ip = 2;
    cfg.max_inbound = 16;
    let a = node_with(48, cfg).await;
    let n = flood(a.addr, 10).await;
    assert!(n <= 2, "{n} handshakes completed from one IP");
    assert!(a.net.stats().peers <= 2);
    // In total.
    let mut cfg = fast_config(&[]);
    cfg.max_inbound = 3;
    let b = node_with(49, cfg).await;
    let n = flood(b.addr, 10).await;
    assert!(n <= 3, "{n} inbound handshakes completed (max 3)");
    wait_until("slots freed", 5, || b.net.stats().peers == 0).await;
    // Slots are released: new peers are accepted again.
    let _p = raw_peer(b.addr, nid, true).await;
    wait_until("accepted again", 5, || b.net.stats().peers == 1).await;
}

/// Accepts `headers` into the node's header chain directly (test setup).
fn give_headers(node: &TestNode, headers: &[BlockHeader]) {
    let mut c = node.chain.lock().unwrap();
    for part in headers.chunks(500) {
        c.accept_headers(part, u64::MAX / 2).unwrap();
    }
}

/// Item 3 (consensus review H2, R1-C1): headers whose claimed work stays
/// below the anti-DoS threshold (our best work minus that of our last 144
/// blocks) are not hashed or stored. After LWMA is driven to difficulty 1,
/// such headers cost an attacker nothing but ~0.45 s of RandomX each to
/// verify, and would be stored forever. Dropped without penalty; the peer is
/// not asked again every tick. Headers extending our best chain, and a
/// near-tip competitor, are still verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn low_work_header_branches_are_not_hashed() {
    let pow = Arc::new(CountingPow::default());
    let a = node_with_pow(50, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    // Our best chain: 300 fast blocks, so the difficulty rose above 1.
    let ours = header_branch(310, 1, 0);
    give_headers(&a, &ours[..300]);
    let (threshold, best, tip_difficulty) = {
        let c = a.chain.lock().unwrap();
        let hc = c.headers();
        let at = hc.main_id_at(300 - 144).unwrap();
        (hc.work(&at).unwrap(), hc.best_work(), hc.tip().difficulty)
    };
    // A difficulty-1 side branch from genesis, 2000 headers long (full
    // batch): work 2001, below the threshold, and less than half our work
    // per height.
    let cheap = header_branch(2000, 120, BAD_NONCE);
    assert!(cheap.iter().all(|h| h.difficulty == 1));
    assert!(2001 < threshold, "threshold {threshold}");
    assert!(2 * 2000 < best - 1 + 1700 * tip_difficulty as u128);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10_000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(cheap.clone()).encode())
        .await
        .unwrap();
    let asked_again = recv_until(&mut r, 2.0, |m| matches!(m, Message::GetHeaders { .. }))
        .await
        .is_some();
    assert!(
        !asked_again,
        "a peer whose branch is low-work is not re-asked"
    );
    assert_eq!(hashed(&pow), 0, "no RandomX hash for the cheap branch");
    {
        let c = a.chain.lock().unwrap();
        assert!(c.header(&cheap[0].id(nid)).is_none(), "nothing stored");
        assert_eq!(c.header_height(), 300);
    }
    let peers = a.net.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].score, 0, "no penalty for a low-work branch");
    // A tip announcement extending our chain is verified, and so is a
    // competing block at our height (its work is far above the threshold):
    // the node tracks near-tip forks.
    w.send(&Message::Headers(vec![ours[300]]).encode())
        .await
        .unwrap();
    wait_until("the extending header is stored", 5, || {
        a.chain.lock().unwrap().header_height() == 301
    })
    .await;
    let mut rival = ours[300];
    rival.nonce = 99;
    w.send(&Message::Headers(vec![rival]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(5).encode()).await.unwrap();
    assert!(recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(5)))
        .await
        .is_some());
    wait_until("the rival is stored", 5, || {
        a.chain.lock().unwrap().header(&rival.id(nid)).is_some()
    })
    .await;
    // An honest peer with a heavier chain still syncs.
    let (r2, w2) = raw_peer_at(a.addr, nid, true, 310).await;
    serve_branch(r2, w2, ours.clone());
    wait_until("honest headers synced", 10, || {
        a.chain.lock().unwrap().header_height() == 310
    })
    .await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 0);
}

/// Item 3 (cont.): a competing branch heavier than ours but forking more than
/// one batch (2000 headers) back still syncs. Its first full batch is below
/// the anti-DoS threshold, but has as much work per height as our chain, so
/// it is verified; the node then asks for more from the batch's last header
/// (not from its own best chain, which would return the same batch forever).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_heavier_fork_deeper_than_one_batch_syncs() {
    let a = node(51, &[]).await;
    let nid = params().network_id;
    give_headers(&a, &header_branch(2500, 120, 0));
    let theirs = header_branch(3000, 120, 7);
    let (r, w) = raw_peer_at(a.addr, nid, true, 3000).await;
    serve_branch(r, w, theirs.clone());
    wait_until("switched to the heavier branch", 240, || {
        a.chain.lock().unwrap().best_header_id() == theirs[2999].id(nid)
    })
    .await;
    assert_eq!(a.net.peers()[0].score, 0);
}

/// M3: a one-header tip announcement that arrives while our `GetHeaders` is
/// outstanding must not turn the real multi-header reply into an
/// "unrequested batch" (+10 and dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tip_announcement_racing_a_headers_reply_is_not_penalized() {
    let a = node(52, &[]).await;
    let nid = params().network_id;
    let branch = header_branch(10, 120, 0);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(vec![branch[0]]).encode())
        .await
        .unwrap();
    w.send(&Message::Headers(branch.clone()).encode())
        .await
        .unwrap();
    serve_branch(r, w, branch);
    wait_until("synced", 10, || {
        a.chain.lock().unwrap().header_height() == 10
    })
    .await;
    assert_eq!(a.net.peers()[0].score, 0, "the reply was not unsolicited");
}

/// M1: when the peer we asked for a transaction disconnects, the request
/// moves to the next announcer at once, not after the 30 s timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_request_moves_on_when_its_peer_leaves() {
    let a = node(53, &[]).await;
    let nid = params().network_id;
    let id = [0x77; 32];
    let (mut rx, mut wx) = raw_peer(a.addr, nid, true).await;
    wx.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    assert!(recv_until(
        &mut rx,
        5.0,
        |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
    )
    .await
    .is_some());
    let (mut ry, mut wy) = raw_peer(a.addr, nid, true).await;
    wy.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    wy.send(&Message::Ping(3).encode()).await.unwrap();
    assert!(recv_until(&mut ry, 5.0, |m| matches!(m, Message::Pong(3)))
        .await
        .is_some());
    drop((rx, wx));
    assert!(
        recv_until(
            &mut ry,
            3.0,
            |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
        )
        .await
        .is_some(),
        "the second announcer is asked when the first leaves"
    );
}

/// L1, L2: a peer that answers our `GetHeaders` with headers we already have
/// (a full batch), or with nothing, is not asked again in a loop. Before the
/// fix a known full batch triggered an immediate re-request, and a peer
/// claiming a higher chain was asked every tick.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_advancing_header_replies_do_not_cause_a_request_loop() {
    let a = node(54, &[]).await;
    let nid = params().network_id;
    let known = header_branch(2000, 120, 0);
    give_headers(&a, &known);
    for reply in [known, vec![]] {
        let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 1_000_000).await;
        let mut asked = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Some(_)) = tokio::time::timeout_at(
            deadline,
            recv_until(&mut r, 3.0, |m| matches!(m, Message::GetHeaders { .. })),
        )
        .await
        {
            asked += 1;
            w.send(&Message::Headers(reply.clone()).encode())
                .await
                .unwrap();
        }
        assert_eq!(asked, 1, "asked {asked} times ({} headers)", reply.len());
    }
    assert!(a.net.peers().iter().all(|p| p.score == 0));
}

/// L4, L5: banning an IP disconnects every live connection from it, and the
/// ban list is saved soon after it changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ban_disconnects_every_connection_from_the_ip_and_is_saved() {
    let dir = std::env::temp_dir().join(format!("bs-p2p-ban-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false; // loopback is banned like any address
    cfg.data_dir = Some(dir.clone());
    let a = node_with(55, cfg).await;
    let nid = params().network_id;
    let (mut r1, _w1) = raw_peer(a.addr, nid, true).await;
    let (mut r2, mut w2) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 2).await;
    let bad = BlockHeader {
        version: HEADER_VERSION,
        height: 1,
        prev_id: params().genesis_id(),
        timestamp: params().genesis.timestamp + 120,
        difficulty: 999_999,
        tx_root: [0; 32],
        nonce: 0,
    };
    w2.send(&Message::Headers(vec![bad]).encode())
        .await
        .unwrap();
    assert!(closes_within(&mut r2, 5).await, "the offender is cut off");
    assert!(
        closes_within(&mut r1, 5).await,
        "the other connection from the banned IP is cut off"
    );
    wait_until("no peers", 5, || a.net.stats().peers == 0).await;
    assert_eq!(a.net.stats().banned, 1);
    let path = dir.join("bans.json");
    wait_until("bans.json saved", 15, || {
        std::fs::read_to_string(&path).is_ok_and(|s| s.contains("127.0.0.1"))
    })
    .await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// M4 (privacy): a transaction created while the node has no stem peer (e.g.
/// right after startup) is held, not broadcast: inbound peers, possibly
/// spies, do not learn it from its origin. It enters the stem as soon as an
/// outbound peer exists. Before the fix it was fluffed at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_local_transaction_waits_for_a_stem_peer() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(60);
    let mut a = node_with(56, cfg).await;
    a.mine_n(80, 0);
    let b = node(57, &[]).await;
    {
        let ca = a.chain.lock().unwrap();
        let mut cb = b.chain.lock().unwrap();
        for h in 1..=ca.height() {
            let block = ca.block_at(h).unwrap();
            let now = block.header.timestamp;
            cb.submit_block(block, now).unwrap();
        }
    }
    let nid = params().network_id;
    let (mut spy, _spy_w) = raw_peer(a.addr, nid, true).await;
    wait_until("spy registered", 5, || a.net.stats().peers == 1).await;
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx).await.unwrap();
    assert!(a.net.stempool_contains(&id), "held in the stempool");
    assert!(
        recv_until(&mut spy, 1.5, |m| matches!(m, Message::InvTx(_)))
            .await
            .is_none(),
        "not announced to the inbound peer"
    );
    assert!(!a.mempool_has(&id), "not broadcast");
    // An outbound peer appears: the transaction goes into the stem.
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("B received it", 10, || {
        b.net.stempool_contains(&id) || b.mempool_has(&id)
    })
    .await;
}

// ------------------------------------ transaction relay hardening (tx review)

/// Sends `msgs`, then a ping, and waits for its pong: every message before it
/// has been handled.
async fn send_and_sync(r: &mut RawReader, w: &mut RawWriter, msgs: &[Vec<u8>], nonce: u64) {
    for m in msgs {
        w.send(m).await.unwrap();
    }
    w.send(&Message::Ping(nonce).encode()).await.unwrap();
    assert!(
        recv_until(r, 10.0, |m| matches!(m, Message::Pong(n) if *n == nonce))
            .await
            .is_some(),
        "pong {nonce}"
    );
}

fn as_transfer(tx: &Transaction) -> blacksilk_tx::types::Transfer {
    match tx {
        Transaction::Transfer(t) => (**t).clone(),
        _ => unreachable!(),
    }
}

/// tx review H1: a transfer with garbage CLSAGs over real, deeply buried ring
/// members fails only at the signature check, which used to count as
/// contextual: no penalty, no reject cache, re-sendable forever at ~3 ms of
/// CPU per input under the chain lock. A ring member 60 or more blocks deep
/// resolves to the same output on every plausible branch, so such a failure
/// is the sender's fault: penalized, remembered, never verified again. An
/// honest transaction still flows.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_signatures_over_buried_rings_are_penalized_once_verified() {
    let mut a = node(60, &[]).await;
    a.mine_n(80, 0);
    let tx1 = a.payment();
    let tx2 = a.payment();
    // Bury every ring member at least SIGNATURE_BURIAL (60) blocks deep.
    a.mine_n(61, 0);
    let mut bad = as_transfer(&tx1);
    bad.signatures = as_transfer(&tx2).signatures; // valid CLSAGs, wrong message
    let bad = Transaction::from(bad);
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&bad),
        Err(MempoolError::Invalid(TxError::InvalidSignature { .. }))
    ));
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let stem = Message::StemTx(bad.encode()).encode();
    send_and_sync(&mut r, &mut w, std::slice::from_ref(&stem), 1).await;
    assert_eq!(a.net.peers()[0].score, score::INVALID_TX);
    assert_eq!(a.net.stats().tx_verifications, 1);
    // Sent again: penalized again, without a second verification.
    send_and_sync(&mut r, &mut w, &[stem], 2).await;
    assert_eq!(a.net.peers()[0].score, 2 * score::INVALID_TX);
    assert_eq!(a.net.stats().tx_verifications, 1, "not verified again");
    // An honest peer's valid transaction is accepted.
    let (mut r2, mut w2) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r2,
        &mut w2,
        &[Message::StemTx(tx1.encode()).encode()],
        3,
    )
    .await;
    let id = tx1.hash();
    wait_until("the honest transaction is pooled", 10, || {
        a.mempool_has(&id)
    })
    .await;
    let scores: Vec<u32> = a.net.peers().iter().map(|p| p.score).collect();
    assert!(scores.contains(&0), "{scores:?}");
}

/// A transfer with one ring index changed to an output that does not exist
/// (on our chain): a contextual failure (C1).
fn unknown_ring_member(tx: &Transaction, k: u64) -> Transaction {
    let mut t = as_transfer(tx);
    let n = t.inputs[0].ring.len();
    t.inputs[0].ring[n - 1] = 1_000_000 + k;
    Transaction::from(t)
}

/// tx review H1 (b): a transaction that fails a contextual rule is not
/// penalized, but the same bytes are not verified again until our tip
/// changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn contextual_rejects_are_not_reverified_at_the_same_tip() {
    let mut a = node(61, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let bad = unknown_ring_member(&tx, 0);
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&bad),
        Err(MempoolError::Invalid(TxError::UnknownRingMember { .. }))
    ));
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let stem = Message::StemTx(bad.encode()).encode();
    send_and_sync(&mut r, &mut w, &[stem.clone(), stem.clone()], 1).await;
    assert_eq!(a.net.stats().tx_verifications, 1, "verified once");
    // Announced by inv: not even requested at this tip.
    w.send(&Message::InvTx(vec![bad.hash()]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(2).encode()).await.unwrap();
    let got = recv_until(&mut r, 5.0, |m| {
        matches!(m, Message::GetTx(_) | Message::Pong(2))
    })
    .await;
    assert!(matches!(got, Some(Message::Pong(2))), "{got:?}");
    // A new tip: verified again.
    a.mine(0);
    send_and_sync(&mut r, &mut w, &[stem], 3).await;
    assert_eq!(a.net.stats().tx_verifications, 2);
    assert_eq!(a.net.peers()[0].score, 0, "contextual: never penalized");
}

/// tx review H1 (a): the signature budget is charged per v1 input before any
/// verification; a peer over it is rate-limited, and its excess
/// transactions are not verified.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_signature_budget_is_charged_before_verification() {
    let mut cfg = fast_config(&[]);
    cfg.peer_limits.inputs = blacksilk_p2p::limits::TokenBucket::new(0.001, 2.0);
    let mut a = node_with(62, cfg).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let msgs: Vec<Vec<u8>> = (0..3)
        .map(|k| Message::StemTx(unknown_ring_member(&tx, k).encode()).encode())
        .collect();
    send_and_sync(&mut r, &mut w, &msgs, 1).await;
    assert_eq!(
        a.net.stats().tx_verifications,
        2,
        "the third was not verified"
    );
    assert_eq!(a.net.peers()[0].score, score::RATE);
}

/// A PX-only transaction with a random anchor: well formed, fails PX1 (a
/// cheap, contextual check).
fn junk_anchor_px(k: u32) -> Transaction {
    let fee = px_standard_fee();
    Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in: 0,
        bridge_out: fee,
        anchor: [k + 1, 7, 7, 7, 7, 7, 7, 7],
        nullifiers: [[k + 1, 1, 0, 0, 0, 0, 0, 0], [k + 1, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[0; 8]; 2],
        ciphertexts: [
            vec![0; blacksilk_px::delivery::CIPHERTEXT_BYTES],
            vec![0; blacksilk_px::delivery::CIPHERTEXT_BYTES],
        ],
        functions: vec![],
        pseudo_outs: vec![],
        range_proof: None,
        signatures: vec![],
        proof: vec![1, 2, 3],
    }))
}

/// tx review M2: the node-wide PX relay token is taken only after the cheap
/// checks. PX transactions with a random anchor from several peers, beyond
/// the node-wide burst (10), are rejected cheaply and leave the budget
/// intact for honest PX. Before the fix they drained it (the excess counted
/// as `px_global_drops`), censoring honest PX relay for free.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_anchor_px_floods_do_not_drain_the_px_relay_budget() {
    let a = node(63, &[]).await;
    let nid = params().network_id;
    let t = junk_anchor_px(0);
    let decoded = Transaction::decode(&t.encode()).expect("decodes");
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&decoded),
        Err(MempoolError::Invalid(TxError::PxUnknownAnchor))
    ));
    for peer in 0..6u32 {
        let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
        let msgs: Vec<Vec<u8>> = (0..4)
            .map(|i| Message::StemTx(junk_anchor_px(peer * 4 + i).encode()).encode())
            .collect();
        send_and_sync(&mut r, &mut w, &msgs, peer as u64).await;
        assert_eq!(a.net.peers().iter().map(|p| p.score).max(), Some(0));
        drop((r, w));
    }
    let st = a.net.stats();
    assert_eq!(st.px_global_drops, 0, "the node-wide PX budget is intact");
    assert_eq!(st.tx_verifications, 0, "rejected by the cheap checks");
}

/// R1-C1 (bodies): an unrequested block whose header we never accepted is
/// dropped before it is hashed or stored (a free low-work branch could
/// otherwise fill the disk, ~10 blocks per peer identity). Before the fix it
/// was penalized (10) but still submitted and connected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unrequested_block_of_an_unknown_header_is_not_stored() {
    let a = node(64, &[]).await;
    let mut other = node(65, &[]).await;
    let block = other.mine(0);
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r,
        &mut w,
        &[Message::Block(block.encode()).encode()],
        1,
    )
    .await;
    assert_eq!(a.net.peers()[0].score, score::UNSOLICITED);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let c = a.chain.lock().unwrap();
    assert_eq!(c.height(), 0);
    assert!(c.header(&block.id(nid)).is_none(), "not stored");
}

/// R8-7: a stem transaction that conflicts with one already in the stempool
/// (first seen wins) is dropped before any verification: valid double-spend
/// variants cost nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn conflicting_stem_transactions_are_not_verified() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(60);
    let mut a = node_with(66, cfg).await;
    a.mine_n(80, 0);
    // B stems back through its own outbound link, with a long embargo, so it
    // does not fluff the relayed transaction during the test.
    let mut bcfg = fast_config(&[a.addr]);
    bcfg.dandelion.embargo_base = Duration::from_secs(60);
    let b = node_with(67, bcfg).await;
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("A has an outbound stem peer", 10, || {
        a.net.stats().outbound >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let tx1 = a.payment();
    let tx2 = a.payment(); // the same output
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx1.encode()).encode()], 1).await;
    assert!(a.net.stempool_contains(&tx1.hash()), "stemmed, embargoed");
    assert_eq!(a.net.stats().tx_verifications, 1);
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx2.encode()).encode()], 2).await;
    assert_eq!(
        a.net.stats().tx_verifications,
        1,
        "the conflict is not verified"
    );
    assert!(!a.net.stempool_contains(&tx2.hash()));
    assert_eq!(a.net.peers().iter().map(|p| p.score).max(), Some(0));
}

/// I3-1: an `InvTx` for a transaction in our stempool gets the same answer
/// as one for an unknown transaction (a `GetTx`), and does not end the stem.
/// Before the fix the node sent no request and fluffed at once: a stempool
/// membership oracle that also let a spy end any stem at will.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announcing_a_stem_transaction_neither_reveals_nor_fluffs_it() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(60);
    let mut a = node_with(68, cfg).await;
    a.mine_n(80, 0);
    // B also stems through its own outbound link to A, with the same long
    // embargo: without a stem route B would fluff the relayed transaction at
    // once and announce it back, and A's honest request to B would race the
    // announcement under test (seen on Linux CI).
    let mut bcfg = fast_config(&[a.addr]);
    bcfg.dandelion.embargo_base = Duration::from_secs(60);
    let b = node_with(69, bcfg).await;
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("A has an outbound stem peer", 10, || {
        a.net.stats().outbound >= 1
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tx = a.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    assert!(a.net.stempool_contains(&id));
    let (mut rs, mut ws) = raw_peer(a.addr, nid, true).await;
    ws.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    assert!(
        recv_until(
            &mut rs,
            5.0,
            |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
        )
        .await
        .is_some(),
        "requested like any unknown transaction"
    );
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(a.net.stempool_contains(&id), "still in the stem");
    assert!(!a.mempool_has(&id), "not fluffed by an announcement");
}

/// I3-2: an onion public address is not advertised on a clearnet connection
/// (it would link the node's onion and IP identities).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_onion_address_is_not_advertised_over_clearnet() {
    let onion = "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:9999";
    let mut cfg = fast_config(&[]);
    cfg.public_address = Some(NetAddr::parse(onion).unwrap());
    let a = node_with(70, cfg).await;
    let nid = params().network_id;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    a.net.connect(NetAddr::Ip(l.local_addr().unwrap()));
    let (s, _) = l.accept().await.unwrap();
    let (mut r, _w) = handshake(
        s,
        false,
        nid,
        &params().genesis_id(),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let Message::Version(v) = Message::decode(&r.recv().await.unwrap()).unwrap() else {
        panic!("expected version");
    };
    assert_eq!(v.listen, None, "the onion address stays off clearnet");
}

/// SX2: replaying a transaction that is already in our mempool (from many
/// connections) costs no verification and no relay budget: it is dropped
/// before any of them. (A mined PX transaction replayed is rejected by the
/// cheap nullifier check before the node-wide PX token, see
/// `junk_anchor_px_floods_do_not_drain_the_px_relay_budget` for that order.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replaying_a_pooled_transaction_costs_no_verification() {
    let mut a = node(71, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    a.chain.lock().unwrap().submit_tx(tx.clone()).unwrap();
    let nid = params().network_id;
    let stem = Message::StemTx(tx.encode()).encode();
    for i in 0..5u64 {
        let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
        send_and_sync(&mut r, &mut w, &[stem.clone(), stem.clone()], i).await;
    }
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 0, "replays are not verified");
    assert!(a.net.peers().iter().all(|p| p.score == 0));
}

// ------------------------------------------------ P2P hardening, part 3 (A24)

/// Whether the chain lock can be taken, read on a blocking thread (the test
/// never waits for the chain lock on a runtime worker it shares with the node).
async fn height_of(chain: &SharedChain) -> u64 {
    let c = chain.clone();
    tokio::task::spawn_blocking(move || c.lock().unwrap().height())
        .await
        .unwrap()
}

/// Sends a ping and returns how long its pong took (`None`: none within `secs`).
async fn pong_latency(r: &mut RawReader, w: &mut RawWriter, nonce: u64, secs: f64) -> Option<f64> {
    let start = std::time::Instant::now();
    w.send(&Message::Ping(nonce).encode()).await.ok()?;
    recv_until(r, secs, |m| matches!(m, Message::Pong(n) if *n == nonce)).await?;
    Some(start.elapsed().as_secs_f64())
}

/// P0-7 (R8-1, R10-5): no runtime worker waits for the chain lock. While
/// another thread holds it for 3 s (as a long block connection or reorg
/// would), two peers' `GetHeaders` wait for it, and the maintenance loop
/// too, yet a third peer's ping is answered at once. Before the fix, with
/// two runtime workers, both were blocked inside `inner.chain()` and the pong
/// came after the lock was released.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pings_are_answered_while_the_chain_lock_is_held() {
    let a = node(90, &[]).await;
    let nid = params().network_id;
    let (mut r1, mut w1) = raw_peer(a.addr, nid, true).await;
    let (_r2, mut w2) = raw_peer(a.addr, nid, true).await;
    let (mut r3, mut w3) = raw_peer(a.addr, nid, true).await;
    assert!(pong_latency(&mut r3, &mut w3, 1, 5.0).await.is_some());

    let (held_tx, held_rx) = tokio::sync::oneshot::channel();
    let chain = a.chain.clone();
    let holder = std::thread::spawn(move || {
        let _guard = chain.lock().unwrap();
        held_tx.send(()).unwrap();
        std::thread::sleep(Duration::from_secs(3));
    });
    held_rx.await.unwrap();
    let get_headers = Message::GetHeaders {
        locator: vec![params().genesis_id()],
        stop: [0; 32],
    }
    .encode();
    w1.send(&get_headers).await.unwrap();
    w2.send(&get_headers).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    for n in 2..6 {
        let t = pong_latency(&mut r3, &mut w3, n, 2.5)
            .await
            .expect("pong while the chain lock is held");
        assert!(t < 1.0, "pong {n} took {t:.2} s");
    }
    assert!(!holder.is_finished(), "the lock was still held");
    holder.join().unwrap();
    assert!(
        recv_until(&mut r1, 5.0, |m| matches!(m, Message::Headers(_)))
            .await
            .is_some(),
        "the waiting request is answered once the lock is free"
    );
}

/// P0-7: a long batch of downloaded blocks connects in bounded steps, off the
/// read loops. A peer serves 120 bodies but withholds the first until it has
/// sent all the others; its arrival releases 119 waiting blocks at once.
/// Another peer's pings are answered promptly throughout, a thread taking the
/// chain lock repeatedly sees intermediate heights (the lock is released
/// between steps), and the node ends on the same tip without penalizing
/// anyone. Coinbase-only blocks connect fast (the drain takes a fraction of a
/// second here), so the lock-release check, not the pong latency, is what
/// fails if the batch is connected in one hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pings_are_answered_while_a_long_batch_of_blocks_connects() {
    const N: u64 = 120;
    let mut src = node(91, &[]).await;
    src.mine_n(N, 0);
    let (headers, bodies): (Vec<BlockHeader>, Vec<Block>) = {
        let c = src.chain.lock().unwrap();
        (1..=N)
            .map(|h| {
                let b = c.block_at(h).unwrap();
                (b.header, b)
            })
            .unzip()
    };
    let nid = params().network_id;
    let first = headers[0].id(nid);
    let by_id: std::collections::HashMap<Hash, Block> =
        bodies.into_iter().map(|b| (b.id(nid), b)).collect();

    let b = node(92, &[]).await;
    let (mut r, mut w) = raw_peer_at(b.addr, nid, true, N).await;
    let (released_tx, released_rx) = tokio::sync::oneshot::channel();
    let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let progress2 = progress.clone();
    // The serving peer: headers, bodies (the first one last), pongs.
    tokio::spawn(async move {
        let mut served = 0;
        let mut first_asked = false;
        let mut released = Some(released_tx);
        while let Ok(frame) = r.recv().await {
            let mut replies = Vec::new();
            match Message::decode(&frame) {
                Ok(Message::GetHeaders { locator, .. }) => {
                    replies.push(Message::Headers(serve_headers(&headers, &locator)))
                }
                Ok(Message::GetBlocks(ids)) => {
                    for id in ids {
                        if id == first {
                            first_asked = true;
                        } else {
                            served += 1;
                            progress2.store(served, std::sync::atomic::Ordering::SeqCst);
                            replies.push(Message::Block(by_id[&id].encode()));
                        }
                    }
                }
                Ok(Message::Ping(n)) => replies.push(Message::Pong(n)),
                _ => {}
            }
            if first_asked && served >= N - 1 {
                if let Some(tx) = released.take() {
                    replies.push(Message::Block(by_id[&first].encode()));
                    let _ = tx.send(());
                }
            }
            for m in replies {
                if w.send(&m.encode()).await.is_err() {
                    return;
                }
            }
        }
    });
    // Another peer pings the node throughout.
    let (mut pr, mut pw) = raw_peer(b.addr, nid, true).await;
    let chain_busy = |c: &SharedChain| c.try_lock().map(|c| c.height()).ok();
    // An observer takes the chain lock over and over while the batch
    // connects: it sees intermediate heights only if the lock is released
    // between steps (one hold for the whole batch shows 0, then 120).
    let observer = {
        let chain = b.chain.clone();
        std::thread::spawn(move || {
            let mut seen = std::collections::BTreeSet::new();
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            loop {
                let h = chain.lock().unwrap().height();
                seen.insert(h);
                if h == N || std::time::Instant::now() > deadline {
                    return seen;
                }
                std::thread::sleep(Duration::from_micros(200));
            }
        })
    };
    match tokio::time::timeout(Duration::from_secs(60), released_rx).await {
        Ok(r) => r.expect("the serving peer is alive"),
        Err(_) => panic!(
            "served {} bodies; height {:?}; peers {:?}",
            progress.load(std::sync::atomic::Ordering::SeqCst),
            chain_busy(&b.chain),
            b.net.peers()
        ),
    }
    let start = std::time::Instant::now();
    let mut worst: f64 = 0.0;
    let mut n = 100;
    while height_of(&b.chain).await < N {
        let Some(t) = pong_latency(&mut pr, &mut pw, n, 5.0).await else {
            panic!(
                "no pong {n} after {:?}: stats {:?}, peers {:?}, height {:?}",
                start.elapsed(),
                b.net.stats(),
                b.net.peers(),
                chain_busy(&b.chain)
            );
        };
        worst = worst.max(t);
        n += 1;
        // Within the 50 messages per second budget.
        tokio::time::sleep(Duration::from_millis(25)).await;
        assert!(start.elapsed() < Duration::from_secs(60), "sync stalled");
    }
    let connect = start.elapsed();
    println!(
        "{N} blocks connected in {:.2} s; worst pong latency {worst:.3} s over {} pings",
        connect.as_secs_f64(),
        n - 100
    );
    assert!(worst < 1.0, "worst pong latency {worst:.2} s");
    let seen = observer.join().unwrap();
    println!("intermediate heights seen by the observer: {seen:?}");
    // Every step connects exactly `SYNC_STEP_BLOCKS` (8) blocks here.
    let between: Vec<u64> = seen.iter().copied().filter(|&h| h > 0 && h < N).collect();
    assert!(
        !between.is_empty() && between.iter().all(|h| h % 8 == 0),
        "the lock was released between steps of 8 blocks: {seen:?}"
    );

    assert_eq!(b.tip(), src.tip());

    assert_eq!(b.net.peers().iter().map(|p| p.score).max(), Some(0));
}

/// P0-6 (R8-9): a peer is asked for at most `BLOCK_WINDOW_BYTES` worth of
/// blocks at a time (each charged `MAX_BLOCK_BYTES`: 3 blocks), even with 20
/// bodies missing and the count cap at 16. A body arriving frees its place.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blocks_in_flight_per_peer_are_bounded_by_bytes() {
    use blacksilk_chain::block::MAX_BLOCK_BYTES;
    use blacksilk_p2p::net::BLOCK_WINDOW_BYTES;
    let window = (BLOCK_WINDOW_BYTES / MAX_BLOCK_BYTES).max(1);
    assert_eq!(window, 3);
    let a = node(93, &[]).await;
    let nid = params().network_id;
    let branch = header_branch(20, 120, 0);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 20).await;
    let mut asked = std::collections::HashSet::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while tokio::time::Instant::now() < deadline {
        let Ok(Ok(frame)) = tokio::time::timeout_at(deadline, r.recv()).await else {
            break;
        };
        match Message::decode(&frame).unwrap() {
            Message::GetHeaders { locator, .. } => {
                let reply = Message::Headers(serve_headers(&branch, &locator));
                w.send(&reply.encode()).await.unwrap();
            }
            Message::GetBlocks(ids) => asked.extend(ids),
            Message::Ping(n) => w.send(&Message::Pong(n).encode()).await.unwrap(),
            _ => {}
        }
    }
    assert_eq!(asked.len(), window, "blocks requested and unanswered");
    // A `NotFound` frees the places: the next ones are requested.
    w.send(&Message::NotFound(asked.iter().copied().collect()).encode())
        .await
        .unwrap();
    let more = recv_until(&mut r, 5.0, |m| matches!(m, Message::GetBlocks(_)))
        .await
        .expect("more requested");
    let Message::GetBlocks(ids) = more else {
        unreachable!()
    };
    assert!(!ids.is_empty() && ids.len() <= window);
}

/// P0-8 (R8-14): a message of a type this version does not know (a later
/// protocol's) is ignored without penalty, but counts against the message
/// budget: a flood of them is still cut off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_message_types_are_ignored_but_charged() {
    let a = node(94, &[]).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let unknown: Vec<Vec<u8>> = vec![vec![15], vec![0xee, 1, 2, 3], vec![200; 5000]];
    send_and_sync(&mut r, &mut w, &unknown, 1).await;
    let peers = a.net.peers();
    assert_eq!(peers.len(), 1, "still connected");
    assert_eq!(peers[0].score, 0, "not penalized");
    // 700 unknown frames exceed the 500-message burst: 1 point per excess.
    let reader = tokio::spawn(async move { closes_within(&mut r, 10).await });
    for _ in 0..700 {
        if w.send(&[0x77, 0]).await.is_err() {
            break;
        }
    }
    assert!(reader.await.unwrap(), "flood of unknown messages cut off");
    wait_until("flooder counted", 5, || {
        a.net.stats().misbehaving_disconnects >= 1
    })
    .await;
}

/// P0-8: a `Version` with extension bytes after its known fields, and
/// messages of unknown types before `Verack` (feature negotiation of a later
/// protocol version), complete the handshake; the peer's protocol number is
/// recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_extended_version_and_unknown_handshake_messages_are_accepted() {
    let a = node(95, &[]).await;
    let nid = params().network_id;
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let mut v = Message::Version(Version {
        protocol: PROTOCOL_VERSION + 1,
        network: nid,
        nonce: 0x1234,
        height: 0,
        tip: [0; 32],
        listen: None,
        relay_txs: true,
    })
    .encode();
    v.extend_from_slice(&[0x05, 0xaa, 0xbb, 0xcc]);
    w.send(&v).await.unwrap();
    let Message::Version(theirs) = Message::decode(&r.recv().await.unwrap()).unwrap() else {
        panic!("expected version");
    };
    assert_eq!(theirs.protocol, PROTOCOL_VERSION);
    w.send(&[0x30, 1]).await.unwrap(); // e.g. a future "send compact blocks"
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Verack
    ));
    send_and_sync(&mut r, &mut w, &[], 7).await;
    wait_until("registered", 5, || a.net.peers().len() == 1).await;
    let p = &a.net.peers()[0];
    assert_eq!((p.protocol, p.score), (PROTOCOL_VERSION + 1, 0));
}

/// Mempool conflict query: a relayed transaction that conflicts with a pooled
/// one (the same output spent) is dropped before verification, and so
/// before the node-wide PX token for PX transactions (docs/p2p.md §10). It
/// is not penalized: it may be an honest double spend that lost a race.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_conflicting_with_the_pool_is_not_verified() {
    let mut a = node(96, &[]).await;
    a.mine_n(80, 0);
    let tx1 = a.payment();
    let tx2 = a.payment(); // the same output
    assert_ne!(tx1.hash(), tx2.hash());
    a.chain.lock().unwrap().submit_tx(tx1.clone()).unwrap();
    assert!(a.chain.lock().unwrap().mempool().conflicts(&tx2));
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx2.encode()).encode()], 1).await;
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 0, "the conflict is not verified");
    assert_eq!(st.px_global_drops, 0);
    assert!(!a.net.stempool_contains(&tx2.hash()));
    assert_eq!(a.net.peers()[0].score, 0);
    assert!(a.mempool_has(&tx1.hash()) && !a.mempool_has(&tx2.hash()));
}

// ------------------------------------------------ RTW1-1: the RT-1 work gate

/// Sends `headers` as one message and waits until the node's header worker
/// has verified it (the batch is queued before the pong is sent). Returns the
/// PoW evaluations it cost.
async fn headers_and_settle(
    node: &TestNode,
    pow: &CountAllPow,
    r: &mut RawReader,
    w: &mut RawWriter,
    headers: Vec<BlockHeader>,
    nonce: u64,
) -> usize {
    let hashes = || pow.0.load(std::sync::atomic::Ordering::SeqCst);
    let before = hashes();
    send_and_sync(r, w, &[Message::Headers(headers).encode()], nonce).await;
    wait_until("header batch verified", 10, || {
        node.net.header_queue_len() == 0
    })
    .await;
    hashes() - before
}

/// RTW1-1: an unknown-version header's claimed difficulty is never checked
/// (`check_rules` returns `UnknownUpgrade` before the difficulty rule), so the
/// anti-DoS gate charges it the difficulty this node requires at its position.
/// A header anchored at genesis (a deep, low-work fork) claiming `u64::MAX`
/// is dropped before any RandomX hash, like the same header with a known
/// version and its honest difficulty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deep_fork_unknown_version_header_claiming_max_difficulty_is_not_hashed() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(61, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    give_headers(&a, &header_branch(300, 1, 0));
    let g = params().genesis;
    let deep = |version, difficulty| BlockHeader {
        version,
        height: 1,
        prev_id: g.id(nid),
        timestamp: g.timestamp + 120,
        difficulty,
        tx_root: [0; 32],
        nonce: 77,
    };
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    let honest = deep(HEADER_VERSION, params().initial_difficulty);
    let known_low = headers_and_settle(&a, &pow, &mut r, &mut w, vec![honest], 1).await;
    let claimed = deep(HEADER_VERSION + 6, u64::MAX);
    let unknown_max = headers_and_settle(&a, &pow, &mut r, &mut w, vec![claimed], 2).await;
    assert_eq!(known_low, 0);
    assert_eq!(unknown_max, 0, "the claimed difficulty bought a hash");
    assert_eq!(a.net.peers()[0].score, 0);
    assert!(!a.net.upgrade_warned());
}

/// A raw peer the node dials: `a` connects to `l`, the raw side accepts.
async fn dialed_raw_peer(a: &TestNode, l: &tokio::net::TcpListener) -> (RawReader, RawWriter) {
    let outbound = a.net.stats().outbound;
    a.net.connect(NetAddr::Ip(l.local_addr().unwrap()));
    let (s, _) = l.accept().await.unwrap();
    let rw = try_raw_handshake_as(s, false, params().network_id, true, 0)
        .await
        .expect("handshake");
    wait_until("registered", 5, || a.net.stats().outbound == outbound + 1).await;
    rw
}

/// RTW1-1 (b): only outbound peers count toward the "node may need an
/// upgrade" warning, each once however often it reconnects. Inbound peers
/// from distinct addresses, even on a branch reaching our best work, never
/// trigger it; their headers are still hashed and not scored (RT-1). A second
/// distinct outbound reporter does.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_distinct_outbound_reporters_trigger_the_upgrade_warning() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(63, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let ours = header_branch(300, 1, 0);
    give_headers(&a, &ours);
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &ours {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let newer = |parent: Hash, nonce| {
        let t = g.template_on(parent).unwrap();
        let prev = g.header(&parent).unwrap();
        BlockHeader {
            version: HEADER_VERSION + 6,
            height: t.height,
            prev_id: parent,
            timestamp: t.min_timestamp.max(prev.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce,
        }
    };
    let tip = g.tip_id();
    // Within the anti-DoS window, below our best work.
    let fork = g.main_id_at(295).unwrap();

    for (k, last) in [2u8, 3, 4].into_iter().enumerate() {
        let k = k as u64;
        let (mut r, mut w) = raw_peer_from([127, 0, 0, last], a.addr, nid, 0)
            .await
            .expect("inbound peer");
        let on_tip =
            headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(tip, 10 + k)], 1).await;
        let on_fork =
            headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(fork, 20 + k)], 2).await;
        assert_eq!((on_tip, on_fork), (1, 1), "hashed");
    }
    assert!(!a.net.upgrade_warned(), "inbound reporters never warn");
    assert!(a.net.peers().iter().all(|p| p.score == 0));

    let l1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    for k in 0..2u64 {
        let (mut r, mut w) = dialed_raw_peer(&a, &l1).await;
        let cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(fork, 30 + k)], 3).await;
        assert_eq!(cost, 1);
        drop((r, w));
        wait_until("disconnected", 5, || a.net.stats().outbound == 0).await;
    }
    assert!(!a.net.upgrade_warned(), "a reconnect is the same reporter");

    let l2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut r, mut w) = dialed_raw_peer(&a, &l2).await;
    let cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(fork, 40)], 4).await;
    assert_eq!(cost, 1);
    assert!(a.net.upgrade_warned(), "two distinct outbound reporters");
}

/// RTW1-1 (c): an unknown-version header whose RandomX key is neither the
/// current nor the next key of our best chain is never hashed, so it cannot
/// make the node build (and evict) a RandomX cache. A pow call is where
/// `RandomXPow` builds a cache, so zero pow calls means no cache build. The
/// fork below is within the anti-DoS window (it passes the work gate at the
/// required difficulty) but its key is genesis, the previous epoch's; the same
/// header on the tip (the current key) is hashed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_old_epoch_unknown_version_header_triggers_no_cache_build() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(62, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let ours = header_branch(2200, 1, 0);
    give_headers(&a, &ours);
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &ours {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let p = params();
    let key = |height| seed_height(height, p.seed_epoch, p.seed_lag);
    assert_eq!(key(2201), 2048, "the current key");
    let newer = |parent: Hash| {
        let t = g.template_on(parent).unwrap();
        let prev = g.header(&parent).unwrap();
        BlockHeader {
            version: HEADER_VERSION + 6,
            height: t.height,
            prev_id: parent,
            timestamp: t.min_timestamp.max(prev.timestamp + 1),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce: 5,
        }
    };
    let old = newer(g.main_id_at(2099).unwrap());
    assert_eq!(key(old.height), 0, "the previous epoch's key");
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    let old_cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![old], 1).await;
    let tip = newer(g.tip_id());
    let tip_cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![tip], 2).await;
    assert_eq!(old_cost, 0, "an old-epoch key was hashed");
    assert_eq!(tip_cost, 1, "the current key is hashed");
    assert_eq!(a.net.peers()[0].score, 0);
}
