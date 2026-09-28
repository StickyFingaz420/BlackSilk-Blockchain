//! Connection policy over real TCP on localhost (docs/p2p.md §9; dossier 32
//! W4, W6): anchors are saved at shutdown and dialed first at the next start;
//! a full inbound set makes room by evicting an unprotected peer.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
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
    let net = Network::start(cfg, chain).await.unwrap();
    let addr = net.local_addr().unwrap();
    (net, addr)
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

fn free_local_addr() -> SocketAddr {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap()
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("bs-p2p-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// W4: the outbound peers of a node that shuts down are written to
/// `anchors.json`, and a restarted node dials them first, even with an empty
/// address table. The file is deleted when read: a node that crashes later
/// does not re-anchor to an old file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchors_are_redialed_first_after_restart() {
    // A advertises itself to a hub H; B knows only H (a manual peer, never
    // an anchor), learns A from H's `GetAddr` answer and dials it.
    let (h, h_addr) = start(1, config(None)).await;
    let a_addr = free_local_addr();
    let mut cfg = config(None);
    cfg.listen = Some(a_addr);
    cfg.public_address = Some(NetAddr::Ip(a_addr));
    cfg.connect = vec![NetAddr::Ip(h_addr)];
    let (a, _) = start(4, cfg).await;
    wait_until("H learned A", 10, || {
        let (n, t) = h.stats().known_addresses;
        n + t >= 1
    })
    .await;
    let dir = temp_dir("anchors");
    let mut cfg = config(Some(&dir));
    cfg.connect = vec![NetAddr::Ip(h_addr)];
    let (b, _) = start(2, cfg).await;
    wait_until("B dialed A", 20, || {
        b.peers()
            .iter()
            .any(|p| !p.inbound && p.addr == NetAddr::Ip(a_addr))
    })
    .await;
    b.save();
    let anchors = dir.join("anchors.json");
    let saved = std::fs::read_to_string(&anchors).expect("anchors.json written at shutdown");
    assert!(saved.contains(&a_addr.to_string()), "{saved}");
    assert!(
        !saved.contains(&h_addr.to_string()),
        "a manual peer: {saved}"
    );
    drop(b);
    // Restart with no table, no seeds and no manual peers: only the anchor
    // can bring A back.
    std::fs::remove_file(dir.join("peers.json")).ok();
    let (b2, _) = start(2, config(Some(&dir))).await;
    wait_until("B redialed its anchor", 10, || {
        b2.peers()
            .iter()
            .any(|p| !p.inbound && p.addr == NetAddr::Ip(a_addr))
    })
    .await;
    assert!(!anchors.exists(), "anchors.json is deleted once read");
    drop((a, b2, h));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A hand-driven inbound peer that completed its handshake with `addr`.
async fn raw_peer(addr: SocketAddr) -> (RawReader, RawWriter) {
    let nid = params().network_id;
    let s = TcpStream::connect(addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: 0xdead_beef,
        height: 0,
        tip: [0; 32],
        listen: None,
        relay_txs: true,
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

/// Whether the node closed the connection within `secs` (messages it sends
/// meanwhile are skipped).
async fn closed_within(r: &mut RawReader, secs: f64) -> bool {
    tokio::time::timeout(Duration::from_secs_f64(secs), async {
        while r.recv().await.is_ok() {}
    })
    .await
    .is_ok()
}

/// W6: with inbound full, a new connection is accepted and one unprotected
/// peer is disconnected (not banned); the oldest peers are protected by
/// uptime or keyed group. Before, the new connection was dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn full_inbound_evicts_an_unprotected_peer() {
    let mut cfg = config(None);
    cfg.max_inbound = 12;
    let (a, a_addr) = start(3, cfg).await;
    let mut peers = Vec::new();
    for i in 0..12 {
        peers.push(raw_peer(a_addr).await);
        wait_until("registered", 5, || a.stats().inbound == i + 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (mut new_r, _new_w) = raw_peer(a_addr).await;
    let mut closed = Vec::new();
    for (i, (r, _)) in peers.iter_mut().enumerate() {
        if closed_within(r, 0.5).await {
            closed.push(i);
        }
    }
    assert_eq!(closed.len(), 1, "one peer evicted: {closed:?}");
    assert!(closed[0] >= 4, "an oldest peer was evicted: {closed:?}");
    assert!(!closed_within(&mut new_r, 0.5).await, "the newcomer stays");
    wait_until("inbound back at the limit", 5, || a.stats().inbound == 12).await;
    assert_eq!(a.stats().banned, 0);
}
