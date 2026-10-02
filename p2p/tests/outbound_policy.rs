//! Outbound and inbound connection policy over real TCP on localhost
//! (docs/p2p.md §9), the regressions of the RT-W3 red team:
//! - RTW3-2: a lost outbound peer is replaced, so the node keeps its full
//!   outbound target (a live connection counted once, not twice);
//! - RTW3-3: connections still in their handshake never make the node evict a
//!   registered inbound peer, and an honest newcomer is admitted;
//! - RTW3-4: stale-tip rotation evicts the outbound peer that brought the
//!   least (by its last validated new tip), never an established one for the
//!   newcomer that brought nothing, and waits while the worst is young;
//! - feelers run once the outbound slots are full, and move an answering
//!   address to *tried* without registering it.
//!
//! The rotation and feeler tests shorten the policy intervals through the
//! `NetConfig` knobs (`feeler_interval`, `stale_tip_after`,
//! `stale_check_interval`, `min_connect_time`).

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_p2p::addrman::AddrMan;
use blacksilk_p2p::connman::ConnKind;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, FrameReader, FrameWriter};
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;

type RawReader = FrameReader<ReadHalf<TcpStream>>;
type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

struct ZeroPow;
impl PowFunction for ZeroPow {
    fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
        [0; 32]
    }
}

fn params() -> ChainParams {
    ChainParams::regtest()
}

fn config(data_dir: Option<&Path>) -> NetConfig {
    let mut cfg = NetConfig::new(params().network_id);
    cfg.listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.allow_private = true;
    cfg.max_outbound = 4;
    cfg.tick = Duration::from_millis(50);
    cfg.pow_threads = 1;
    cfg.data_dir = data_dir.map(Path::to_path_buf);
    cfg
}

async fn start(seed: u8, cfg: NetConfig) -> (Network, SocketAddr) {
    let (net, addr, _) = start_chain(seed, cfg).await;
    (net, addr)
}

async fn start_chain(seed: u8, cfg: NetConfig) -> (Network, SocketAddr, SharedChain) {
    let p = params();
    let m = ChainManager::open(
        p.clone(),
        TxRules::for_chain(&p),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [seed; 32],
    )
    .unwrap();
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let net = Network::start(cfg, chain.clone()).await.unwrap();
    let addr = net.local_addr().unwrap();
    (net, addr, chain)
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

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bs-p2p-op-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A saved address table holding `addrs` (in *new*), all heard from one
/// source.
fn table_of(addrs: impl Iterator<Item = SocketAddr>, key: u8) -> AddrMan {
    let mut table = AddrMan::with_key([key; 32]);
    table.set_private_groups(true);
    let src = NetAddr::parse("127.0.0.9:1").unwrap();
    for a in addrs {
        assert!(table.add(NetAddr::Ip(a), &src, unix_now()), "{a} added");
    }
    table
}

/// The full-relay outbound peers (block-relay-only connections and seed
/// address fetches are not counted against `max_outbound`).
fn outbound(v: &Network) -> Vec<NetAddr> {
    v.peers()
        .into_iter()
        .filter(|p| p.kind == ConnKind::FullRelay)
        .map(|p| p.addr)
        .collect()
}

fn free_local_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

/// A node that advertises its own address (so a node that asks it for
/// addresses learns it).
async fn start_public(seed: u8) -> (Network, SocketAddr, SharedChain) {
    let a = free_local_addr();
    let mut cfg = config(None);
    cfg.listen = Some(a);
    cfg.public_address = Some(NetAddr::Ip(a));
    start_chain(seed, cfg).await
}

fn rand_nonce() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).unwrap();
    u64::from_le_bytes(b)
}

/// A peer the test controls, listening on `ip`: completes the handshake as
/// the responder, answers pings, and holds every connection until `close`
/// is notified.
async fn raw_listener(ip: &str, close: Arc<tokio::sync::Notify>) -> SocketAddr {
    let l = tokio::net::TcpListener::bind(format!("{ip}:0"))
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let close = close.clone();
            tokio::spawn(async move {
                let nid = params().network_id;
                let Ok((mut r, mut w)) = handshake(
                    s,
                    false,
                    nid,
                    &params().genesis_id(),
                    Duration::from_secs(5),
                )
                .await
                else {
                    return;
                };
                let v = Version {
                    protocol: PROTOCOL_VERSION,
                    network: nid,
                    nonce: rand_nonce(),
                    height: 0,
                    tip: params().genesis_id(),
                    listen: None,
                    relay_txs: true,
                };
                if w.send(&Message::Version(v).encode()).await.is_err()
                    || w.send(&Message::Verack.encode()).await.is_err()
                {
                    return;
                }
                loop {
                    tokio::select! {
                        _ = close.notified() => return,
                        f = r.recv() => match f {
                            Ok(f) => {
                                if let Ok(Message::Ping(n)) = Message::decode(&f) {
                                    let _ = w.send(&Message::Pong(n).encode()).await;
                                }
                            }
                            Err(_) => return,
                        },
                    }
                }
            });
        }
    });
    addr
}

/// A hand-driven inbound peer that completes its handshake, or the error.
async fn try_raw_peer(addr: SocketAddr) -> Result<(RawReader, RawWriter), String> {
    let nid = params().network_id;
    let s = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .map_err(|e| e.to_string())?;
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: rand_nonce(),
        height: 0,
        tip: params().genesis_id(),
        listen: None,
        relay_txs: true,
    };
    w.send(&Message::Version(v).encode())
        .await
        .map_err(|e| e.to_string())?;
    let m = r.recv().await.map_err(|e| e.to_string())?;
    if !matches!(Message::decode(&m), Ok(Message::Version(_))) {
        return Err("no version".into());
    }
    w.send(&Message::Verack.encode())
        .await
        .map_err(|e| e.to_string())?;
    let m = r.recv().await.map_err(|e| e.to_string())?;
    if !matches!(Message::decode(&m), Ok(Message::Verack)) {
        return Err("no verack".into());
    }
    Ok((r, w))
}

/// Whether the node closed the connection within `secs` (messages it sends
/// meanwhile are skipped).
async fn closed_within(r: &mut RawReader, secs: f64) -> bool {
    tokio::time::timeout(Duration::from_secs_f64(secs), async {
        while r.recv().await.is_ok() {}
    })
    .await
    .is_ok()
}

/// RTW3-2: `connecting` holds an outbound address for its whole session, and
/// the maintenance counted it on top of the registered peer, so a node
/// replaced a lost outbound peer only below half its target. Now two of four
/// outbound peers leave and both slots are refilled from the table.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_outbound_peers_are_replaced() {
    let mut peers = Vec::new();
    for _ in 0..8 {
        let close = Arc::new(tokio::sync::Notify::new());
        let addr = raw_listener("127.0.0.1", close.clone()).await;
        peers.push((addr, close));
    }
    let dir = temp_dir("lost");
    table_of(peers.iter().map(|(a, _)| *a), 6)
        .save(&dir.join("peers.json"))
        .unwrap();
    let mut cfg = config(Some(&dir));
    cfg.max_outbound = 4;
    let (v, _) = start(10, cfg).await;
    wait_until("the first round fills every slot", 10, || {
        outbound(&v).len() == 4
    })
    .await;
    let first = outbound(&v);
    // Two of them go away (for example two honest peers restart).
    for a in first.iter().take(2) {
        let (_, close) = peers.iter().find(|(p, _)| NetAddr::Ip(*p) == *a).unwrap();
        close.notify_waiters();
    }
    wait_until("the lost peers are gone", 10, || {
        !outbound(&v).contains(&first[0]) && !outbound(&v).contains(&first[1])
    })
    .await;
    // Four reachable table entries are not connected: both slots refill
    // within a few maintenance rounds (every 2 s).
    wait_until("both lost slots refilled", 20, || outbound(&v).len() == 4).await;
    // And it stays at the target: no dial beyond it.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(outbound(&v).len(), 4, "{:?}", outbound(&v));
    drop(v);
    let _ = std::fs::remove_dir_all(&dir);
}

/// RTW3-3: TCP connections that never send a byte (no key, no work) used to
/// count against `max_inbound`, were never eviction candidates themselves,
/// and made the node evict its registered inbound peers; honest newcomers
/// were then refused. Now they only compete among themselves (oldest
/// first, a quarter of `max_inbound`), no registered peer is evicted for
/// them, and an honest newcomer is admitted (evicting one unprotected
/// registered peer at its registration, W6).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_handshakes_do_not_evict_registered_peers() {
    let mut cfg = config(None);
    cfg.max_inbound = 12;
    let (a, a_addr) = start(3, cfg).await;
    let mut peers = Vec::new();
    for i in 0..12 {
        peers.push(try_raw_peer(a_addr).await.unwrap());
        wait_until("registered", 5, || a.stats().inbound == i + 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // The attacker: 12 TCP connections that send nothing.
    let mut silent = Vec::new();
    for _ in 0..12 {
        silent.push(TcpStream::connect(a_addr).await.unwrap());
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut closed = 0;
    for (r, _) in peers.iter_mut() {
        if closed_within(r, 0.2).await {
            closed += 1;
        }
    }
    assert_eq!(closed, 0, "registered peers evicted for silent connections");
    assert_eq!(a.stats().inbound, 12);
    // An honest newcomer is admitted while the silent connections are held.
    let (mut new_r, _new_w) = try_raw_peer(a_addr).await.expect("newcomer admitted");
    assert!(!closed_within(&mut new_r, 0.5).await, "the newcomer stays");
    wait_until("inbound back at the limit", 5, || a.stats().inbound == 12).await;
    assert_eq!(a.stats().banned, 0, "nothing is scored before Verack");
    drop(silent);
}

/// Mines `n` blocks on `chain`'s tip (coinbase only).
fn mine(chain: &SharedChain, n: u64) {
    use blacksilk_chain::block::Block;
    use blacksilk_consensus::merkle::tx_root;
    use blacksilk_consensus::{BlockHeader, HEADER_VERSION};
    use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
    use blacksilk_tx::builder::{build_coinbase, Payment};
    use blacksilk_tx::types::Transaction;
    use rand_chacha::rand_core::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
    let (miner, _) = WalletKeys::generate(&mut rng);
    let mut c = chain.lock().unwrap();
    for _ in 0..n {
        let t = c.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: miner.address(SubaddressIndex::PRIMARY),
                amount: t.reward,
            }],
            &miner.hedge_secret(),
            &mut rng,
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
        let now = header.timestamp;
        c.submit_block(Block { header, txs }, now).unwrap();
    }
}

/// Shortened policy intervals: the tip is stale after 4 s, a peer may be
/// rotated out after 3 s; one extra connection per stale episode. Only
/// full-relay connections (the rotation concerns them).
fn rotation_config(dir: &Path, seed: SocketAddr) -> NetConfig {
    let mut cfg = config(Some(dir));
    cfg.max_outbound = 2;
    cfg.block_relay_only = 0;
    cfg.seeds = vec![NetAddr::Ip(seed)];
    cfg.stale_tip_after = Some(Duration::from_secs(4));
    cfg.min_connect_time = Duration::from_secs(3);
    cfg.stale_check_interval = Duration::from_secs(600);
    cfg
}

/// V's table: H1 and H2 only, so they fill V's two slots, and the seed S is
/// asked for addresses only once the tip is stale. S answers with its own
/// address (it advertises itself), which V then dials as the extra peer.
fn anchored(name: &str, h1: SocketAddr, h2: SocketAddr) -> PathBuf {
    let dir = temp_dir(name);
    table_of([h1, h2].into_iter(), 5)
        .save(&dir.join("peers.json"))
        .unwrap();
    dir
}

/// RTW3-4: when the stale-tip extra peer registers and brought nothing
/// (every height 0), the rotation waits until it is `min_connect_time` old
/// and then evicts IT, never an established peer. Before, the established
/// peer with the lowest claimed height (ties: the youngest old enough) went
/// two seconds after the newcomer arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_tip_rotation_keeps_established_peers() {
    let (h1, h1_addr) = start(11, config(None)).await;
    let (h2, h2_addr) = start(12, config(None)).await;
    let (s, s_addr, _) = start_public(13).await;
    let dir = anchored("stale-keep", h1_addr, h2_addr);
    let (v, _) = start(10, rotation_config(&dir, s_addr)).await;
    let (h1n, h2n, sn) = (
        NetAddr::Ip(h1_addr),
        NetAddr::Ip(h2_addr),
        NetAddr::Ip(s_addr),
    );
    wait_until("V dialed H1 and H2", 10, || {
        let o = outbound(&v);
        o.contains(&h1n) && o.contains(&h2n)
    })
    .await;
    wait_until(
        "V learned S from the seed once the tip was stale and dialed it",
        15,
        || outbound(&v).contains(&sn),
    )
    .await;
    let dialed = std::time::Instant::now();
    // H1 and H2 stay throughout; S goes once it is old enough.
    wait_until("the newcomer rotated out", 15, || {
        let o = outbound(&v);
        assert!(o.contains(&h1n) && o.contains(&h2n), "{o:?}");
        !o.contains(&sn)
    })
    .await;
    let waited = dialed.elapsed();
    assert!(
        waited >= Duration::from_millis(2500),
        "evicted after {waited:?}, before min_connect_time"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(outbound(&v).len(), 2, "{:?}", outbound(&v));
    drop((v, h1, h2, s));
    let _ = std::fs::remove_dir_all(&dir);
}

/// RTW3-4: a newcomer that delivers a validated new tip stays, and an
/// established peer that brought none goes instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stale_tip_rotation_keeps_a_newcomer_that_brought_a_new_tip() {
    let (h1, h1_addr) = start(21, config(None)).await;
    let (h2, h2_addr) = start(22, config(None)).await;
    let (s, s_addr, s_chain) = start_public(23).await;
    mine(&s_chain, 3);
    let dir = anchored("stale-new-tip", h1_addr, h2_addr);
    let (v, _, v_chain) = start_chain(20, rotation_config(&dir, s_addr)).await;
    let (h1n, h2n, sn) = (
        NetAddr::Ip(h1_addr),
        NetAddr::Ip(h2_addr),
        NetAddr::Ip(s_addr),
    );
    wait_until(
        "V learned S from the seed once the tip was stale and dialed it",
        20,
        || outbound(&v).contains(&sn),
    )
    .await;
    wait_until("V synced S's chain", 15, || {
        v_chain.lock().unwrap().height() == 3
    })
    .await;
    wait_until(
        "an established peer that brought nothing rotated out",
        15,
        || {
            let o = outbound(&v);
            !(o.contains(&h1n) && o.contains(&h2n))
        },
    )
    .await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let o = outbound(&v);
    assert!(
        o.contains(&sn),
        "the newcomer that brought a new tip stays: {o:?}"
    );
    assert_eq!(o.len(), 2, "{o:?}");
    drop((v, h1, h2, s));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Feelers (W5; RTW3-2 made them reachable in practice): with the outbound
/// slots full, a short connection tests the remaining *new* address and
/// moves it to *tried*, without registering it as a peer. The three peers
/// listen on distinct loopback IPs (*tried* holds one entry per IP).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn feelers_move_an_answering_new_address_to_tried() {
    let close = Arc::new(tokio::sync::Notify::new());
    let mut addrs = Vec::new();
    for ip in ["127.0.0.2", "127.0.0.3", "127.0.0.4"] {
        addrs.push(raw_listener(ip, close.clone()).await);
    }
    let dir = temp_dir("feeler");
    table_of(addrs.iter().copied(), 8)
        .save(&dir.join("peers.json"))
        .unwrap();
    let mut cfg = config(Some(&dir));
    cfg.max_outbound = 2;
    cfg.block_relay_only = 0;
    cfg.feeler_interval = Duration::from_millis(500);
    let (v, _) = start(30, cfg).await;
    wait_until("both outbound slots filled", 10, || outbound(&v).len() == 2).await;
    let o = outbound(&v);
    let third = addrs
        .iter()
        .map(|a| NetAddr::Ip(*a))
        .find(|a| !o.contains(a))
        .unwrap();
    let mut registered_third = false;
    wait_until("the feeler moved the third address to tried", 20, || {
        registered_third |= outbound(&v).contains(&third);
        v.stats().known_addresses == (0, 3)
    })
    .await;
    assert!(!registered_third, "a feeler is never registered");
    let mut now = outbound(&v);
    let mut before = o.clone();
    now.sort_by_key(|a| a.to_string());
    before.sort_by_key(|a| a.to_string());
    assert_eq!(now, before, "the outbound peers are unchanged");
    drop(v);
    close.notify_waiters();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Only an outbound connection that completes its handshake marks its
/// address good (moves it to *tried*): an inbound connection from an address
/// already in *new* leaves it there, as Bitcoin Core does, so inbound
/// peers cannot place themselves in *tried* (mutation run E: the `!inbound`
/// of the rule had no test). The node dials nothing (`connect_only`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_inbound_connection_never_moves_its_address_to_tried() {
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let from = sock.local_addr().unwrap();
    let dir = temp_dir("inbound-not-tried");
    table_of(std::iter::once(from), 9)
        .save(&dir.join("peers.json"))
        .unwrap();
    let mut cfg = config(Some(&dir));
    cfg.connect_only = true;
    cfg.feeler_interval = Duration::from_secs(3600);
    let (v, v_addr) = start(30, cfg).await;
    wait_until("the table is loaded", 10, || {
        v.stats().known_addresses == (1, 0)
    })
    .await;
    let s = sock.connect(v_addr).await.unwrap();
    let nid = params().network_id;
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let ours = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: rand_nonce(),
        height: 0,
        tip: params().genesis_id(),
        listen: None,
        relay_txs: true,
    };
    w.send(&Message::Version(ours).encode()).await.unwrap();
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Version(_)
    ));
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Verack
    ));
    // Registered before the read loop answers this ping.
    w.send(&Message::Ping(5).encode()).await.unwrap();
    loop {
        if matches!(
            Message::decode(&r.recv().await.unwrap()).unwrap(),
            Message::Pong(5)
        ) {
            break;
        }
    }
    assert_eq!(v.stats().peers, 1);
    assert_eq!(v.stats().known_addresses, (1, 0), "still in new");
    drop((r, w, v));
    let _ = std::fs::remove_dir_all(&dir);
}
