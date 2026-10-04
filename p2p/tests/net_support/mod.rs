//! Shared helpers of the multi-node tests (`network.rs`) and the privacy
//! regression suite (`privacy.rs`): test nodes over real TCP on localhost,
//! hand-driven raw peers, and the re-announcement observation helpers.
//! Moved here unchanged from `network.rs` (A-SUITE) so that both test
//! binaries use one copy.
#![allow(dead_code)]

use blacksilk_chain::actor::{self, ActorConfig};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{BlockHeader, ChainParams, Hash, PowFunction, HEADER_VERSION};
use blacksilk_crypto::keys::{SubaddressIndex, SubaddressTable, WalletKeys};
use blacksilk_p2p::dandelion::DandelionParams;
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
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

pub struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

pub fn params() -> ChainParams {
    ChainParams::regtest()
}

/// Test diagnostics: with `BLACKSILK_TEST_LOG` set, the network's debug log
/// (every penalty with its reason, `Inner::penalize`) goes to stderr,
/// prefixed with the milliseconds since the logger started. No new
/// dependency: `log` is the crate's own.
pub struct StderrLog(std::time::Instant);
impl log::Log for StderrLog {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.target().starts_with("blacksilk_p2p") && m.level() <= log::Level::Debug
    }
    fn log(&self, r: &log::Record) {
        if self.enabled(r.metadata()) {
            eprintln!(
                "[{:>7} ms {} {}] {}",
                self.0.elapsed().as_millis(),
                r.level(),
                r.target(),
                r.args()
            );
        }
    }
    fn flush(&self) {}
}

pub fn init_test_log() {
    static LOG: std::sync::OnceLock<StderrLog> = std::sync::OnceLock::new();
    if std::env::var_os("BLACKSILK_TEST_LOG").is_none() {
        return;
    }
    let l = LOG.get_or_init(|| StderrLog(std::time::Instant::now()));
    if log::set_logger(l).is_ok() {
        log::set_max_level(log::LevelFilter::Debug);
    }
}
pub struct TestNode {
    pub chain: SharedChain,
    pub net: Network,
    pub addr: SocketAddr,
    pub miner: WalletKeys,
    pub rng: ChaCha20Rng,
}

pub fn fast_config(connect: &[SocketAddr]) -> NetConfig {
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

pub async fn node_with(seed: u64, cfg: NetConfig) -> TestNode {
    node_with_pow(seed, cfg, Arc::new(ZeroPow)).await
}

pub async fn node_with_pow(seed: u64, cfg: NetConfig, pow: Arc<dyn PowFunction>) -> TestNode {
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

/// A node whose chain actor has the lane capacities and step budget of
/// `actor_cfg` (Stage 2 lane tests).
pub async fn node_with_actor(seed: u64, cfg: NetConfig, actor_cfg: ActorConfig) -> TestNode {
    node_with_actor_handle(seed, cfg, actor_cfg).await.0
}

/// [`node_with_actor`], also returning the chain actor's handle.
pub async fn node_with_actor_handle(
    seed: u64,
    cfg: NetConfig,
    actor_cfg: ActorConfig,
) -> (TestNode, actor::ChainHandle) {
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
    let (handle, _thread) = actor::spawn_shared(chain.clone(), actor_cfg);
    let net = Network::start_with(cfg, handle.clone()).await.unwrap();
    let addr = net.local_addr().unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let (miner, _) = WalletKeys::generate(&mut rng);
    let node = TestNode {
        chain,
        net,
        addr,
        miner,
        rng,
    };
    (node, handle)
}

pub async fn node(seed: u64, connect: &[SocketAddr]) -> TestNode {
    node_with(seed, fast_config(connect)).await
}

impl TestNode {
    pub fn height(&self) -> u64 {
        self.chain.lock().unwrap().height()
    }

    pub fn tip(&self) -> Hash {
        self.chain.lock().unwrap().tip_id()
    }

    pub fn mempool_has(&self, id: &Hash) -> bool {
        self.chain.lock().unwrap().mempool().contains(id)
    }

    /// Mines one block on the local tip (with mempool transactions).
    pub fn mine(&mut self, nonce: u64) -> Block {
        self.mine_with(nonce, true)
    }

    /// Mines one block on the local tip, with the mempool's transactions
    /// only if `with_pool`.
    pub fn mine_with(&mut self, nonce: u64, with_pool: bool) -> Block {
        self.mine_block(nonce, with_pool, None)
    }

    /// Mines `n` coinbase-only blocks, each `dt` seconds after its parent: a
    /// small `dt` makes LWMA raise the difficulty, so equal heights can carry
    /// unequal work.
    pub fn mine_spaced(&mut self, n: u64, dt: u64, nonce: u64) {
        for _ in 0..n {
            self.mine_block(nonce, false, Some(dt));
        }
    }

    /// The cumulative work of the connected tip.
    pub fn work(&self) -> u128 {
        let c = self.chain.lock().unwrap();
        c.headers().work(&c.tip_id()).unwrap()
    }

    /// Mines one block on the local tip; its timestamp is `spacing` seconds
    /// after its parent's, or 120 s per height after genesis if `None`.
    pub fn mine_block(&mut self, nonce: u64, with_pool: bool, spacing: Option<u64>) -> Block {
        let mut c = self.chain.lock().unwrap();
        let mut t = c.template();
        if !with_pool {
            t.txs.clear();
        }
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
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t.min_timestamp.max(match spacing {
                Some(dt) => c.tip_header().timestamp + dt,
                None => params().genesis.timestamp + 120 * t.height,
            }),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        let b = Block { header, txs };
        let now = b.header.timestamp;
        c.submit_block(b.clone(), now).unwrap();
        b
    }

    pub fn mine_n(&mut self, n: u64, nonce: u64) {
        for _ in 0..n {
            self.mine(nonce);
        }
    }

    /// A 1-input transfer from this node's miner wallet to a fresh wallet.
    pub fn payment(&mut self) -> Transaction {
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
    pub fn px_deposit(&mut self, amount: u64) -> Transaction {
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
                window: Default::default(),
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
    pub fn input_plan(&mut self, min_amount: u64) -> (InputPlan, TxRules) {
        self.input_plan_nth(min_amount, 0)
    }

    /// A 1-input transfer spending the `nth` mature, unspent miner output
    /// (distinct `nth`: transfers that do not conflict).
    pub fn payment_nth(&mut self, nth: usize) -> Transaction {
        let (plan, rules) = self.input_plan_nth(0, nth);
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

    /// [`Self::input_plan`] for the `nth` qualifying output (0: the first
    /// block's last, as before).
    pub fn input_plan_nth(&mut self, min_amount: u64, nth: usize) -> (InputPlan, TxRules) {
        let c = self.chain.lock().unwrap();
        let table = SubaddressTable::new(self.miner.view_keys(), 1, 2);
        let next = c.height() + 1;
        let mut owned = None;
        let mut seen = 0;
        for h in 1..=c.height() {
            let b = c.block_at(h).unwrap();
            let first = c.state().first_output_at(h).unwrap();
            let mut found = None;
            for o in scan_block(self.miner.view_keys(), &table, &b.txs, h, first).owned {
                if next >= o.height + COINBASE_MATURITY
                    && o.received.amount > min_amount
                    && !c.state().is_key_image_spent(&o.key_image(&self.miner))
                {
                    found = Some(o);
                }
            }
            if let Some(o) = found {
                if seen == nth {
                    owned = Some(o);
                    break;
                }
                seen += 1;
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

pub async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// RT2-TM2P2P diagnostics: [`wait_until`] that prints `diag()` on timeout.
pub async fn wait_until_d(
    what: &str,
    secs: u64,
    mut cond: impl FnMut() -> bool,
    diag: impl Fn() -> String,
) {
    log::info!(target: "blacksilk_p2p::rt2", "RT2DIAG wait {what} starts: {}", diag());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(secs);
    while !cond() {
        if tokio::time::Instant::now() > deadline {
            log::info!(target: "blacksilk_p2p::rt2", "RT2DIAG wait {what} timed out: {}", diag());
            eprintln!("RT2 DIAG ({what}): {}", diag());
            panic!("timed out waiting for: {what}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// The peers of `n` as (id, address, inbound, kind, height).
pub fn peer_list(n: &TestNode) -> String {
    format!(
        "self {} peers {:?}",
        n.addr,
        n.net
            .peers()
            .iter()
            .map(|p| (
                p.id,
                p.addr.to_string(),
                p.inbound,
                format!("{:?}", p.kind),
                p.height
            ))
            .collect::<Vec<_>>()
    )
}
// ---------------------------------------------------------------- raw peer

pub type RawReader = FrameReader<ReadHalf<TcpStream>>;
pub type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

/// A hand-driven peer for adversarial tests.
pub async fn raw_peer(
    addr: SocketAddr,
    network_id: u32,
    relay_txs: bool,
) -> (RawReader, RawWriter) {
    raw_peer_at(addr, network_id, relay_txs, 0).await
}

/// A raw peer claiming a chain of `height` blocks (so the node asks it for
/// headers).
pub async fn raw_peer_at(
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
pub async fn try_raw_handshake(
    s: TcpStream,
    network_id: u32,
    relay_txs: bool,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    try_raw_handshake_as(s, true, network_id, relay_txs, height).await
}

/// The raw peer's handshake, as the side that opened the connection
/// (`initiator`) or the side that accepted it.
pub async fn try_raw_handshake_as(
    s: TcpStream,
    initiator: bool,
    network_id: u32,
    relay_txs: bool,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    // A peer at height 0 names genesis as its tip, as an honest one does;
    // above it, a tip the node does not know (it asks for headers anyway).
    let tip = if height == 0 {
        params().genesis_id()
    } else {
        [0; 32]
    };
    try_raw_handshake_tip(s, initiator, network_id, relay_txs, height, tip).await
}

/// [`try_raw_handshake_as`] claiming the best header `tip` at `height`.
pub async fn try_raw_handshake_tip(
    s: TcpStream,
    initiator: bool,
    network_id: u32,
    relay_txs: bool,
    height: u64,
    tip: Hash,
) -> Option<(RawReader, RawWriter)> {
    let (mut r, mut w) = handshake(
        s,
        initiator,
        network_id,
        &params().genesis_id(),
        // A precondition, not a timing assertion: the node's own handshake
        // deadline (20 s) decides; a starved machine needs more than 5 s.
        Duration::from_secs(20),
    )
    .await
    .ok()?;
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: network_id,
        nonce: 0xdead_beef,
        height,
        tip,
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
pub async fn connect_from(src: [u8; 4], addr: SocketAddr) -> std::io::Result<TcpStream> {
    let sock = tokio::net::TcpSocket::new_v4()?;
    sock.bind(SocketAddr::from((src, 0)))?;
    sock.connect(addr).await
}

/// A raw peer connecting from the loopback address `src`.
pub async fn raw_peer_from(
    src: [u8; 4],
    addr: SocketAddr,
    network_id: u32,
    height: u64,
) -> Option<(RawReader, RawWriter)> {
    let s = connect_from(src, addr).await.ok()?;
    try_raw_handshake(s, network_id, true, height).await
}
/// Reads messages until one matches `want`; `None` if the connection closes or
/// `secs` pass first.
pub async fn recv_until(
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
/// A `GetTx` for an id no node has, derived from `nonce`, and whether `m` is
/// the node's answer to it (`NotFound`). A barrier through the peer's slow
/// lane: its answer comes after every earlier message of the peer has been
/// handled. A ping is no barrier: pings are answered on the read loop, ahead
/// of queued chain work (docs/p2p.md §10, F34-1).
pub fn lane_barrier(nonce: u64) -> (Vec<u8>, impl Fn(&Message) -> bool) {
    let mut id = [0xb7; 32];
    id[..8].copy_from_slice(&nonce.to_le_bytes());
    let answered = move |m: &Message| matches!(m, Message::NotFound(ids) if ids == &vec![id]);
    (Message::GetTx(vec![id]).encode(), answered)
}
/// A raw peer the node dials: `a` connects to `l`, the raw side accepts.
pub async fn dialed_raw_peer(a: &TestNode, l: &tokio::net::TcpListener) -> (RawReader, RawWriter) {
    let outbound = a.net.stats().outbound;
    a.net.connect(NetAddr::Ip(l.local_addr().unwrap()));
    let (s, _) = l.accept().await.unwrap();
    let rw = try_raw_handshake_as(s, false, params().network_id, true, 0)
        .await
        .expect("handshake");
    // Counts outbound peers: a caller's earlier outbound peer that leaves
    // meanwhile hides this one (mutation run E: a dropped first reporter in
    // the upgrade-threshold test, once taken for a slow registration).
    wait_until("registered", 30, || a.net.stats().outbound == outbound + 1).await;
    rw
}
/// A fresh, empty temporary data directory.
pub fn temp_data_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("bs-p2p-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// `a` restarted: a new node (seed `seed`) over a copy of `a`'s blocks, with
/// an empty mempool and stempool, whose data directory holds a copy of what
/// `a` saved in `a_dir` (persisted state survives a restart, memory does
/// not). `a` keeps running, but is no peer of the new node. Returns the new
/// node and its data directory.
pub async fn restarted(
    a: &TestNode,
    a_dir: &std::path::Path,
    seed: u64,
) -> (TestNode, std::path::PathBuf) {
    a.net.save();
    let dir = temp_data_dir(&format!("restart-{seed}"));
    for f in std::fs::read_dir(a_dir).unwrap() {
        let f = f.unwrap();
        if f.path().is_file() {
            std::fs::copy(f.path(), dir.join(f.file_name())).unwrap();
        }
    }
    let mut cfg = fast_config(&[]);
    cfg.data_dir = Some(dir.clone());
    let b = node_with(seed, cfg).await;
    {
        let ca = a.chain.lock().unwrap();
        let mut cb = b.chain.lock().unwrap();
        for h in 1..=ca.height() {
            let block = ca.block_at(h).unwrap();
            let now = block.header.timestamp;
            cb.submit_block(block, now).unwrap();
        }
    }
    (b, dir)
}
/// Gives `n` a block mined elsewhere (it may have it already from the
/// network) and waits until `n` is at its height.
pub async fn give_block(n: &TestNode, b: &Block) {
    let now = b.header.timestamp;
    let _ = n.chain.lock().unwrap().submit_block(b.clone(), now);
    let h = b.header.height;
    wait_until("block given", 30, || n.height() >= h).await;
}

/// Waits until `n`'s chain maintenance loop finished next height `next`
/// (pool re-announcement included) and its trickle queues are empty: every
/// announcement it decided is in an outbox (test hooks, no timing).
pub async fn settled(n: &TestNode, next: u64) {
    wait_until("maintenance saw the height", 30, || {
        n.net.maintenance_seen_height() >= next
    })
    .await;
    wait_until("announcements flushed", 30, || {
        n.net.queued_announcements() == 0
    })
    .await;
}

/// The messages a raw peer received before the answer to a ping sent now:
/// the node's outbox is FIFO, so whatever it queued for this peer before
/// it read the ping is among them.
pub async fn before_barrier(r: &mut RawReader, w: &mut RawWriter, nonce: u64) -> Vec<Message> {
    w.send(&Message::Ping(nonce).encode()).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let m = Message::decode(&r.recv().await.unwrap()).unwrap();
            if m == Message::Pong(nonce) {
                return;
            }
            got.push(m);
        }
    })
    .await
    .expect("pong");
    got
}

/// The next heights up to `to` at which each spy (`spies[i]`, a peer of
/// `nodes[i]`) first saw `id` announced: at the current height, then one
/// block mined on `nodes[0]` (and given to the others) per height. A spy
/// registered after the transaction was pooled has been told nothing about
/// it, so only a pool re-announcement reaches it. Deterministic: each node
/// has finished the height ([`settled`]) before its spy reads up to a
/// ping barrier.
pub async fn first_reannouncements(
    nodes: &mut [&mut TestNode],
    spies: &mut [(&mut RawReader, &mut RawWriter)],
    id: Hash,
    to: u64,
) -> Vec<Option<u64>> {
    let mut first = vec![None; spies.len()];
    let mut nonce = 0x7000;
    loop {
        let next = nodes[0].height() + 1;
        for (i, (r, w)) in spies.iter_mut().enumerate() {
            settled(nodes[i], next).await;
            nonce += 1;
            let seen = before_barrier(r, w, nonce)
                .await
                .iter()
                .any(|m| matches!(m, Message::InvTx(ids) if ids.contains(&id)));
            if first[i].is_none() && seen {
                first[i] = Some(next);
            }
        }
        if next >= to {
            return first;
        }
        let b = nodes[0].mine_with(0, false);
        for n in nodes[1..].iter() {
            give_block(n, &b).await;
        }
    }
}
