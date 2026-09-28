//! Address relay over real TCP on localhost (docs/p2p.md §9): unsolicited
//! batches, `GetAddr` from outbound peers, the `Version.listen` source check,
//! the per-peer address rate, and relay that does not reveal what the
//! address table holds.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_p2p::addr::AddrEntry;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, FrameReader, FrameWriter};
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
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

type RawReader = FrameReader<ReadHalf<TcpStream>>;
type RawWriter = FrameWriter<WriteHalf<TcpStream>>;

fn params() -> ChainParams {
    ChainParams::regtest()
}

async fn node(seed: u8) -> (Network, SocketAddr) {
    let mut cfg = NetConfig::new(params().network_id);
    cfg.listen = Some("127.0.0.1:0".parse().unwrap());
    cfg.allow_private = true;
    cfg.max_outbound = 4;
    cfg.tick = Duration::from_millis(50);
    cfg.pow_threads = 1;
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

/// The raw peer's side of the handshake, advertising `listen`.
async fn raw_handshake(
    s: TcpStream,
    initiator: bool,
    listen: Option<NetAddr>,
) -> (RawReader, RawWriter) {
    let nid = params().network_id;
    let (mut r, mut w) = handshake(
        s,
        initiator,
        nid,
        &params().genesis_id(),
        Duration::from_secs(5),
    )
    .await
    .expect("transport");
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: 0x5eed_0000 ^ u64::from(initiator),
        height: 0,
        tip: [0; 32],
        listen,
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

/// An inbound raw peer from the loopback address `src`.
async fn inbound_from(
    net: &Network,
    to: SocketAddr,
    src: [u8; 4],
    listen: Option<NetAddr>,
) -> (RawReader, RawWriter) {
    let before = net.stats().inbound;
    let sock = tokio::net::TcpSocket::new_v4().unwrap();
    sock.bind(SocketAddr::from((src, 0))).unwrap();
    let s = sock.connect(to).await.unwrap();
    let rw = raw_handshake(s, true, listen).await;
    wait_until("inbound registered", 5, || {
        net.stats().inbound == before + 1
    })
    .await;
    rw
}

/// A raw peer the node dialed (an outbound peer of the node).
async fn dialed(net: &Network) -> (RawReader, RawWriter) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let before = net.stats().outbound;
    net.connect(NetAddr::Ip(l.local_addr().unwrap()));
    let (s, _) = l.accept().await.unwrap();
    let rw = raw_handshake(s, false, None).await;
    wait_until("outbound registered", 5, || {
        net.stats().outbound == before + 1
    })
    .await;
    rw
}

/// Sends `msgs`, then a ping, and returns every message received up to the
/// pong: the node handled everything sent before the ping by then.
async fn send_and_sync(r: &mut RawReader, w: &mut RawWriter, msgs: &[Message]) -> Vec<Message> {
    for m in msgs {
        w.send(&m.encode()).await.unwrap();
    }
    let nonce = 0x1234_5678;
    w.send(&Message::Ping(nonce).encode()).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), async {
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

/// Messages received within `secs` (the node may send them after a delay).
async fn collect_for(r: &mut RawReader, secs: f64) -> Vec<Message> {
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs_f64(secs), async {
        while let Ok(f) = r.recv().await {
            got.push(Message::decode(&f).unwrap());
        }
    })
    .await;
    got
}

/// Distinct public addresses, each in its own /16 (so the address table's
/// per-group buckets never limit what a test stores).
fn public(i: u32) -> NetAddr {
    NetAddr::parse(&format!("{}.{}.7.1:29334", 20 + i / 200, i % 200)).unwrap()
}

fn known(net: &Network) -> usize {
    let (n, t) = net.stats().known_addresses;
    n + t
}

/// An `Addr` of `list`, every entry timed now (fresh).
fn addr(list: Vec<NetAddr>) -> Message {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    Message::Addr(list.into_iter().map(|a| AddrEntry::new(now, a)).collect())
}

/// W0 (F32-1, Heilman CM8): an `Addr` of more than 10 entries that the node
/// did not ask for is dropped and penalized, from an inbound peer even as its
/// first batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsolicited_large_addr_batch_is_penalized() {
    let (a, a_addr) = node(1).await;
    let (mut r, mut w) = inbound_from(&a, a_addr, [127, 0, 0, 2], None).await;
    send_and_sync(&mut r, &mut w, &[addr((0..11).map(public).collect())]).await;
    assert_eq!(known(&a), 0, "nothing stored");
    assert!(a.peers()[0].score >= 10, "penalized: {:?}", a.peers());
    // Ten entries are not a batch.
    let (mut r, mut w) = inbound_from(&a, a_addr, [127, 0, 0, 3], None).await;
    send_and_sync(&mut r, &mut w, &[addr((20..30).map(public).collect())]).await;
    let fresh = a
        .peers()
        .into_iter()
        .find(|p| p.addr.to_string().starts_with("127.0.0.3:"))
        .unwrap();
    assert_eq!(fresh.score, 0);
}

/// W0 (F32-4): `GetAddr` from a peer the node dialed is ignored, without a
/// penalty: answering it lets a peer fingerprint a node across sessions with
/// planted addresses (Biryukov and Pustogarov, 2015).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn getaddr_from_outbound_is_ignored() {
    let (a, _) = node(2).await;
    let (mut r, mut w) = dialed(&a).await;
    let got = send_and_sync(&mut r, &mut w, &[Message::GetAddr]).await;
    assert!(
        !got.iter().any(|m| matches!(m, Message::Addr(_))),
        "answered an outbound GetAddr: {got:?}"
    );
    assert_eq!(a.peers()[0].score, 0);
    // An inbound peer is answered.
    let (a, a_addr) = node(3).await;
    let (mut r, mut w) = inbound_from(&a, a_addr, [127, 0, 0, 4], None).await;
    let got = send_and_sync(&mut r, &mut w, &[Message::GetAddr]).await;
    assert!(got.iter().any(|m| matches!(m, Message::Addr(_))), "{got:?}");
}

/// W0 (F32-8): an inbound peer's `Version.listen` is stored only if its IP is
/// the connection's IP (or it is an onion address): a peer cannot plant a
/// third party's address with every handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_listen_must_match_the_connection_ip() {
    let (a, a_addr) = node(4).await;
    let _p = inbound_from(&a, a_addr, [127, 0, 0, 5], Some(public(1))).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(known(&a), 0, "a third party's address was stored");
    let own = NetAddr::parse("127.0.0.6:4444").unwrap();
    let _q = inbound_from(&a, a_addr, [127, 0, 0, 6], Some(own)).await;
    wait_until("own listen address stored", 5, || known(&a) == 1).await;
}

/// The answer to the node's own `GetAddr` (sent to every outbound peer) is
/// accepted whole, without a penalty.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_solicited_getaddr_answer_is_accepted() {
    let (a, _) = node(5).await;
    let (mut r, mut w) = dialed(&a).await;
    let got = collect_for(&mut r, 1.0).await;
    assert!(got.contains(&Message::GetAddr), "{got:?}");
    let before = known(&a);
    send_and_sync(&mut r, &mut w, &[addr((0..300).map(public).collect())]).await;
    // All 300 are admitted. One source's addresses share its 16 *new*
    // buckets (1024 slots), and an address whose slot is taken is dropped
    // (addrman v2, docs/p2p.md §9), so some collide.
    let stored = known(&a);
    assert!(
        stored > before + 200 && stored <= before + 300,
        "{before} -> {stored}"
    );
    assert_eq!(a.peers()[0].score, 0);
    // A second large batch is not an answer.
    send_and_sync(&mut r, &mut w, &[addr((300..400).map(public).collect())]).await;
    assert_eq!(known(&a), stored);
    assert!(a.peers()[0].score >= 10);
}

/// W3 (N-7): small unsolicited `Addr` messages are rate limited per peer
/// (0.1 address per second, starting with one token): the excess is dropped,
/// not penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsolicited_addresses_are_rate_limited_without_a_penalty() {
    let (a, a_addr) = node(6).await;
    let (mut r, mut w) = inbound_from(&a, a_addr, [127, 0, 0, 7], None).await;
    let msgs: Vec<Message> = (0..5).map(|i| addr(vec![public(i)])).collect();
    send_and_sync(&mut r, &mut w, &msgs).await;
    assert_eq!(known(&a), 1, "one token at the start");
    assert_eq!(a.peers()[0].score, 0);
}

/// W3 (F32-5): whether a fresh address is relayed does not depend on whether
/// the node already knew it, so a spy cannot probe the address table by
/// watching what the node relays.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn relay_does_not_reveal_whether_an_address_was_known() {
    let (a, a_addr) = node(7).await;
    // X becomes known to the node through its owner's handshake.
    let x = NetAddr::parse("127.0.0.8:4444").unwrap();
    let _owner = inbound_from(&a, a_addr, [127, 0, 0, 8], Some(x.clone())).await;
    wait_until("X known", 5, || known(&a) == 1).await;
    let (mut spy_r, _spy_w) = inbound_from(&a, a_addr, [127, 0, 0, 9], None).await;
    let (mut r, mut w) = inbound_from(&a, a_addr, [127, 0, 0, 10], None).await;
    send_and_sync(&mut r, &mut w, &[addr(vec![x.clone()])]).await;
    let got = collect_for(&mut spy_r, 1.0).await;
    assert!(
        got.iter()
            .any(|m| matches!(m, Message::Addr(v) if format!("{v:?}").contains("127.0.0.8"))),
        "a fresh address the node knew was not relayed: {got:?}"
    );
}
