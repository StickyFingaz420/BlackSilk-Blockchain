//! Multi-node tests over real TCP on localhost: propagation, header-first sync,
//! Dandelion++ relay, reorganization across the network, peer discovery, and
//! defenses against misbehaving peers.

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
use blacksilk_tx::builder::{
    build_coinbase, build_transfer, standard_fee, Decoy, InputPlan, Payment, SpendableOutput,
};
use blacksilk_tx::decoy::select_ring;
use blacksilk_tx::params::{TxRules, COINBASE_MATURITY, SPENDABLE_AGE};
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
        let fees: u64 = t.txs.iter().map(|t| t.fee).sum();
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
        txs.extend(t.txs.iter().cloned().map(Transaction::from));
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
        let c = self.chain.lock().unwrap();
        let table = SubaddressTable::new(self.miner.view_keys(), 1, 2);
        let next = c.height() + 1;
        let mut owned = None;
        for h in 1..=c.height() {
            let b = c.block_at(h).unwrap();
            let first = c.state().first_output_at(h).unwrap();
            for o in scan_block(self.miner.view_keys(), &table, &b.txs, h, first).owned {
                if next >= o.height + COINBASE_MATURITY
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
        let (dest, _) = WalletKeys::generate(&mut self.rng);
        let tx = build_transfer(
            &self.miner,
            vec![InputPlan {
                real: SpendableOutput::from(&owned),
                decoys,
            }],
            &[Payment {
                address: dest.address(SubaddressIndex::PRIMARY),
                amount: 1_000,
            }],
            &self.miner.address(SubaddressIndex::PRIMARY),
            standard_fee(1, 2, c.rules()),
            c.rules(),
            &mut self.rng,
        )
        .unwrap();
        Transaction::from(tx)
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
    let s = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, network_id, Duration::from_secs(5))
        .await
        .unwrap();
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: network_id,
        nonce: 0xdead_beef,
        height: 0,
        tip: [0; 32],
        listen: None,
        relay_txs,
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
    let c_state_has = c.chain.lock().unwrap().height() == 81;
    assert!(c_state_has);
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
    // Undecodable message (valid encryption).
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    w.send(&[0xee, 1, 2, 3]).await.unwrap();
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
    wait_until("both gone", 5, || {
        a.net.stats().misbehaving_disconnects == 2
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn wrong_network_and_self_connections_are_refused() {
    let a = node(18, &[]).await;
    // Different network id: the first frame does not decrypt.
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, params().network_id + 1, Duration::from_secs(5))
        .await
        .unwrap();
    let _ = w.send(&Message::Verack.encode()).await;
    assert!(
        r.recv().await.is_err(),
        "no valid frame from a node of another network"
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
    // The next reply is the pong: the transaction was not served.
    loop {
        match Message::decode(&r.recv().await.unwrap()).unwrap() {
            Message::Pong(77) => break,
            Message::Tx(_) => panic!("served a transaction that was never announced to this peer"),
            _ => {}
        }
    }
}
