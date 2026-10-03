//! Connection policy over real TCP on localhost (docs/p2p.md §9; dossier 32
//! W4, W6, W7): anchors (the block-relay-only peers) are saved at shutdown
//! and dialed first at the next start; block-relay-only connections carry no
//! addresses and no transactions; seeds are one-shot address fetches; a full
//! inbound set makes room by evicting an unprotected peer, never a low-ping
//! one; onion peers through the onion listener are a capped class, never
//! IP-banned.

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::{ChainParams, Hash, PowFunction};
use blacksilk_p2p::addr::AddrEntry;
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

/// W4: the block-relay-only peers of a node that shuts down are written to
/// `anchors.json`, and a restarted node dials them first, block-relay-only,
/// even with an empty address table. The file is deleted when read: a node
/// that crashes later does not re-anchor to an old file.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anchors_are_redialed_first_after_restart() {
    // A advertises itself to a hub H; B knows only H (a manual peer, never
    // an anchor, holding B's one full-relay slot), learns A from H's
    // `GetAddr` answer and dials it block-relay-only.
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
    cfg.max_outbound = 1;
    let (b, _) = start(2, cfg).await;
    wait_until("B dialed A block-relay-only", 20, || {
        b.peers()
            .iter()
            .any(|p| p.kind == ConnKind::BlockRelay && p.addr == NetAddr::Ip(a_addr))
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
            .any(|p| p.kind == ConnKind::BlockRelay && p.addr == NetAddr::Ip(a_addr))
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
        tip: params().genesis_id(),
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

// ---------------------------------------------------------------- W3-32c

fn unix_now() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32
}

/// What a scripted peer saw: the node's `Version`, the kinds of the
/// messages it sent, and the connections it opened and closed.
#[derive(Default)]
struct Seen {
    version: Option<Version>,
    kinds: Vec<&'static str>,
    connections: usize,
    closed: usize,
}

/// A peer the test controls, listening on `ip` for the node to dial it:
/// answers the handshake (without an address of its own), pings, and
/// `GetAddr` with `answer` (never, if `None`); sends whatever the test
/// injects.
struct Scripted {
    addr: SocketAddr,
    seen: Arc<Mutex<Seen>>,
    inject: tokio::sync::mpsc::UnboundedSender<Message>,
}

async fn scripted_listener(ip: &str, answer: Option<Vec<AddrEntry>>) -> Scripted {
    let l = tokio::net::TcpListener::bind(format!("{ip}:0"))
        .await
        .unwrap();
    let addr = l.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let (inject, rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let rx = Arc::new(tokio::sync::Mutex::new(rx));
    let s2 = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = l.accept().await else { return };
            let (seen, rx, answer) = (s2.clone(), rx.clone(), answer.clone());
            tokio::spawn(async move {
                seen.lock().unwrap().connections += 1;
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
                let Ok(Message::Version(theirs)) =
                    Message::decode(&r.recv().await.unwrap_or_default())
                else {
                    return;
                };
                seen.lock().unwrap().version = Some(theirs);
                let v = Version {
                    protocol: PROTOCOL_VERSION,
                    network: nid,
                    nonce: 0x5eed,
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
                let mut rx = rx.lock().await;
                loop {
                    tokio::select! {
                        m = rx.recv() => match m {
                            Some(m) => { let _ = w.send(&m.encode()).await; }
                            None => return,
                        },
                        f = r.recv() => match f {
                            Ok(f) => {
                                let Ok(m) = Message::decode(&f) else { continue };
                                seen.lock().unwrap().kinds.push(m.kind());
                                match m {
                                    Message::Ping(n) => {
                                        let _ = w.send(&Message::Pong(n).encode()).await;
                                    }
                                    Message::GetAddr => {
                                        if let Some(a) = &answer {
                                            let _ = w.send(&Message::Addr(a.clone()).encode()).await;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(_) => {
                                seen.lock().unwrap().closed += 1;
                                return;
                            }
                        },
                    }
                }
            });
        }
    });
    Scripted { addr, seen, inject }
}

/// A saved address table holding `addrs` in *new*.
fn save_table(dir: &Path, addrs: &[SocketAddr]) {
    let mut table = AddrMan::with_key([9; 32]);
    table.set_private_groups(true);
    let src = NetAddr::parse("127.0.0.9:1").unwrap();
    for a in addrs {
        assert!(table.add(NetAddr::Ip(*a), &src, u64::from(unix_now())));
    }
    table.save(&dir.join("peers.json")).unwrap();
}

/// W3-32c item 4 (dossier 32 W4): block-relay-only connections. With no
/// full-relay slot, the node dials its table's address block-relay-only:
/// `relay_txs = false` and no address of its own in `Version`; no `GetAddr`
/// and no `Addr` (not even its own address, which it advertises on
/// full-relay connections); an `Addr` from the peer is ignored; transaction
/// messages are a protocol violation, penalized until the peer is
/// disconnected. Before, the node opened no such connection (with
/// `max_outbound = 0` it dialed nothing), and always sent `relay_txs = true`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_relay_only_peers_get_no_addr_or_tx() {
    let peer = scripted_listener("127.0.0.1", None).await;
    let dir = temp_dir("block-relay");
    save_table(&dir, &[peer.addr]);
    let v_addr = free_local_addr();
    let mut cfg = config(Some(&dir));
    cfg.listen = Some(v_addr);
    cfg.public_address = Some(NetAddr::Ip(v_addr));
    cfg.max_outbound = 0;
    let (v, _) = start(40, cfg).await;
    wait_until("V dialed its block-relay-only peer", 10, || {
        peer.seen.lock().unwrap().version.is_some()
    })
    .await;
    let ver = peer.seen.lock().unwrap().version.clone().unwrap();
    assert!(!ver.relay_txs, "relay_txs = false");
    assert_eq!(ver.listen, None, "no address of ours on it");
    wait_until("registered", 5, || v.stats().block_relay == 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let kinds = peer.seen.lock().unwrap().kinds.clone();
    assert!(
        !kinds.contains(&"getaddr") && !kinds.contains(&"addr"),
        "{kinds:?}"
    );
    // An address from it is ignored.
    let before = v.stats().known_addresses;
    let planted = NetAddr::parse("127.0.0.77:1").unwrap();
    peer.inject
        .send(Message::Addr(vec![AddrEntry::new(unix_now(), planted)]))
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(v.stats().known_addresses, before, "the Addr was ignored");
    // Transaction relay there breaks the protocol.
    for i in 0..10u8 {
        peer.inject.send(Message::InvTx(vec![[i; 32]])).unwrap();
    }
    wait_until("disconnected for transaction messages", 5, || {
        peer.seen.lock().unwrap().closed >= 1
    })
    .await;
    assert!(v.stats().misbehaving_disconnects >= 1);
    drop(v);
    let _ = std::fs::remove_dir_all(&dir);
}

/// W3-32c item 6 (dossier 32 W7, F32-6): a seed is asked for addresses in a
/// one-shot connection: `GetAddr`, the answer is stored, the connection is
/// closed. The seed never becomes an outbound peer or a *tried* entry.
/// Before, the seed was kept as a full outbound peer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seed_is_disconnected_after_its_addr_answer() {
    let answer: Vec<AddrEntry> = ["127.0.0.50:1", "127.0.0.51:1"]
        .iter()
        .map(|s| AddrEntry::new(0, NetAddr::parse(s).unwrap()))
        .collect();
    let seed = scripted_listener("127.0.0.1", Some(answer)).await;
    let mut cfg = config(None);
    cfg.seeds = vec![NetAddr::Ip(seed.addr)];
    let (v, _) = start(41, cfg).await;
    wait_until("V asked the seed for addresses", 10, || {
        seed.seen.lock().unwrap().kinds.contains(&"getaddr")
    })
    .await;
    wait_until("V closed the seed connection after the answer", 5, || {
        seed.seen.lock().unwrap().closed >= 1
    })
    .await;
    let (new, tried) = v.stats().known_addresses;
    assert!(new >= 2, "the answer is stored: {new}");
    assert_eq!(tried, 0, "a seed is not promoted");
    let seed_addr = NetAddr::Ip(seed.addr);
    assert!(
        !v.peers().iter().any(|p| p.addr == seed_addr),
        "the seed is not a peer"
    );
    assert_eq!(seed.seen.lock().unwrap().connections, 1, "asked once");
}

/// P2P-FIX2 item 3: a seed whose answer is exactly one address is left as
/// soon as the answer arrives, not after the address-fetch timeout. The seed
/// (a real node, advertising itself) first sends its own address, a
/// one-entry `Addr` that is not the answer; its answer then holds the one
/// entry of its table. Before, the fetch closed only on an `Addr` of other
/// than one entry, so this seed was held for the whole timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_seed_answering_one_address_is_left_at_once() {
    // S advertises itself; P advertises itself to S, S's only table entry.
    let s_addr = free_local_addr();
    let mut cfg = config(None);
    cfg.listen = Some(s_addr);
    cfg.public_address = Some(NetAddr::Ip(s_addr));
    let (s, _) = start(45, cfg).await;
    let p_addr = free_local_addr();
    let mut cfg = config(None);
    cfg.listen = Some(p_addr);
    cfg.public_address = Some(NetAddr::Ip(p_addr));
    cfg.connect = vec![NetAddr::Ip(s_addr)];
    cfg.connect_only = true;
    let (_p, _) = start(46, cfg).await;
    wait_until("S learned P, its one entry", 10, || {
        s.stats().known_addresses == (1, 0)
    })
    .await;
    // V knows only S, as a seed; the timeout is far beyond the wait below.
    let mut cfg = config(None);
    cfg.seeds = vec![NetAddr::Ip(s_addr)];
    cfg.block_relay_only = 0;
    cfg.addr_fetch_timeout = Duration::from_secs(120);
    let (v, _) = start(47, cfg).await;
    // S's own address and its answer (P).
    wait_until("V stored S and the answer", 10, || {
        let (n, t) = v.stats().known_addresses;
        n + t >= 2
    })
    .await;
    wait_until("V closed the fetch on the one-address answer", 5, || {
        !v.peers().iter().any(|p| p.kind == ConnKind::AddrFetch)
    })
    .await;
}

/// W3-32c item 6: a seed that never answers is left after the address-fetch
/// timeout.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_seed_is_left_after_the_timeout() {
    let seed = scripted_listener("127.0.0.1", None).await;
    let mut cfg = config(None);
    cfg.seeds = vec![NetAddr::Ip(seed.addr)];
    cfg.addr_fetch_timeout = Duration::from_secs(1);
    let (v, _) = start(43, cfg).await;
    wait_until("V asked the seed", 10, || {
        seed.seen.lock().unwrap().kinds.contains(&"getaddr")
    })
    .await;
    wait_until("V left the silent seed", 5, || {
        seed.seen.lock().unwrap().closed >= 1
    })
    .await;
    drop(v);
}

/// A silent seed's address fetch is left once `addr_fetch_timeout` has passed
/// since the connection, not before: the seed has that long to answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_seed_has_the_whole_timeout_to_answer() {
    let seed = scripted_listener("127.0.0.1", None).await;
    let mut cfg = config(None);
    cfg.seeds = vec![NetAddr::Ip(seed.addr)];
    cfg.addr_fetch_timeout = Duration::from_secs(3);
    let (v, _) = start(45, cfg).await;
    wait_until("V asked the seed", 10, || {
        seed.seen.lock().unwrap().kinds.contains(&"getaddr")
    })
    .await;
    // The request comes after the handshake: the connection is older.
    let asked = std::time::Instant::now();
    wait_until("V left the silent seed", 10, || {
        seed.seen.lock().unwrap().closed >= 1
    })
    .await;
    let after = asked.elapsed();
    assert!(
        after >= Duration::from_millis(2_000),
        "left {after:?} after its request"
    );
    drop(v);
}

/// Outbound connections are maintained every 2 s (docs/p2p.md §9), not at
/// every tick: with one outbound slot and each dial failing at once (the
/// listener drops it), the node dials one address per round, at least 2 s
/// apart.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn outbound_connections_are_maintained_every_two_seconds() {
    let accepts = Arc::new(Mutex::new(Vec::new()));
    let mut addrs = Vec::new();
    for _ in 0..4 {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        addrs.push(l.local_addr().unwrap());
        let seen = accepts.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                seen.lock().unwrap().push(std::time::Instant::now());
                drop(s);
            }
        });
    }
    let dir = temp_dir("dial-rounds");
    save_table(&dir, &addrs);
    let mut cfg = config(Some(&dir));
    cfg.max_outbound = 1;
    cfg.block_relay_only = 0;
    cfg.feeler_interval = Duration::from_secs(1_000_000);
    let (v, _) = start(46, cfg).await;
    wait_until("three dials", 20, || accepts.lock().unwrap().len() >= 3).await;
    let at = accepts.lock().unwrap().clone();
    for w in at.windows(2) {
        let gap = w[1] - w[0];
        assert!(
            gap >= Duration::from_millis(1_800),
            "dials {gap:?} apart: {at:?}"
        );
    }
    drop(v);
    let _ = std::fs::remove_dir_all(&dir);
}

/// W3-32c item 6 (W7): seeds are asked once fewer than two full-relay
/// outbound peers were up for `seed_fallback_after`, not only when none is.
/// Before, one outbound peer (possibly the attacker's) suppressed the seeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn seeds_are_asked_when_fewer_than_two_outbound_peers_are_up() {
    let one = scripted_listener("127.0.0.1", None).await;
    let seed = scripted_listener("127.0.0.1", Some(vec![])).await;
    let dir = temp_dir("seed-fallback");
    save_table(&dir, &[one.addr]);
    let mut cfg = config(Some(&dir));
    cfg.seeds = vec![NetAddr::Ip(seed.addr)];
    cfg.block_relay_only = 0;
    cfg.seed_fallback_after = Duration::from_secs(1);
    let (v, _) = start(44, cfg).await;
    wait_until("V connected to its one known peer", 10, || {
        one.seen.lock().unwrap().version.is_some()
    })
    .await;
    wait_until("V asked the seed", 10, || {
        seed.seen.lock().unwrap().kinds.contains(&"getaddr")
    })
    .await;
    drop(v);
    let _ = std::fs::remove_dir_all(&dir);
}

/// W3-32c item 5 (N-6, dossier 32 W6): the onion listener. Its peers all
/// come from the Tor daemon's loopback address, yet more than two are
/// accepted (on the P2P listener a loopback IP gets `max_per_ip` = 2), the
/// class is capped at a quarter of `max_inbound` and makes room within
/// itself, and a misbehaving onion peer is disconnected without banning the
/// shared IP: the next onion peer is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn onion_inbound_is_capped_as_a_class_and_never_ip_banned() {
    let mut cfg = config(None);
    cfg.allow_private = false;
    cfg.max_inbound = 12;
    cfg.onion_listen = Some("127.0.0.1:0".parse().unwrap());
    let (a, a_addr) = start(42, cfg).await;
    let onion = a.onion_local_addr().expect("onion listener");
    let mut peers = Vec::new();
    for i in 0..3 {
        peers.push(raw_peer(onion).await);
        wait_until("registered", 5, || a.stats().inbound == i + 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(a.peers().iter().all(|p| p.kind == ConnKind::OnionInbound));
    // A fourth: the class is full (12 / 4 = 3), one of them gives way.
    let (mut r4, mut w4) = raw_peer(onion).await;
    assert!(!closed_within(&mut r4, 0.5).await, "the newcomer stays");
    wait_until("the class stays at its cap", 5, || a.stats().inbound == 3).await;
    // The P2P listener still takes clearnet peers besides them (a loopback
    // one here, not taken for Tor since the onion listener exists).
    let (_r5, _w5) = raw_peer(a_addr).await;
    wait_until("a clearnet peer too", 5, || a.stats().inbound == 4).await;
    // Misbehavior: a second Version (100 points) disconnects the onion peer;
    // the Tor daemon's IP is not banned.
    w4.send(
        &Message::Version(Version {
            protocol: PROTOCOL_VERSION,
            network: params().network_id,
            nonce: 1,
            height: 0,
            tip: params().genesis_id(),
            listen: None,
            relay_txs: true,
        })
        .encode(),
    )
    .await
    .unwrap();
    assert!(closed_within(&mut r4, 5.0).await, "disconnected");
    assert!(a.stats().misbehaving_disconnects >= 1);
    assert_eq!(a.stats().banned, 0, "the shared loopback IP is not banned");
    let (mut r6, _w6) = raw_peer(onion).await;
    assert!(
        !closed_within(&mut r6, 0.5).await,
        "the next onion peer is accepted"
    );
}

/// W3-32c item 3 (W6 remainder): the lowest-ping inbound peers are protected
/// from eviction. Six silent peers connect first (older), then eight that
/// answer pings; when a newcomer needs room, a silent one goes. Before, the
/// youngest unprotected peer went: one of the eight.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn low_ping_inbound_peers_survive_eviction() {
    let mut cfg = config(None);
    cfg.max_inbound = 14;
    cfg.ping_interval = Duration::from_millis(300);
    let (a, a_addr) = start(45, cfg).await;
    let mut silent = Vec::new();
    for i in 0..6 {
        silent.push(raw_peer(a_addr).await);
        wait_until("registered", 5, || a.stats().inbound == i + 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Pingers answer every ping and note when the node closes them.
    let gone = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    for i in 0..8 {
        let (mut r, mut w) = raw_peer(a_addr).await;
        let gone = gone.clone();
        tokio::spawn(async move {
            while let Ok(f) = r.recv().await {
                if let Ok(Message::Ping(n)) = Message::decode(&f) {
                    if w.send(&Message::Pong(n).encode()).await.is_err() {
                        break;
                    }
                }
            }
            gone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        });
        wait_until("registered", 5, || a.stats().inbound == 6 + i + 1).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    wait_until("the pingers' pings are measured", 10, || {
        a.peers().iter().filter(|p| p.min_ping.is_some()).count() == 8
    })
    .await;
    let (mut new_r, _new_w) = raw_peer(a_addr).await;
    assert!(!closed_within(&mut new_r, 0.5).await, "the newcomer stays");
    let mut closed = 0;
    for (r, _) in silent.iter_mut() {
        if closed_within(r, 0.3).await {
            closed += 1;
        }
    }
    assert_eq!(closed, 1, "one silent peer evicted");
    assert_eq!(
        gone.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "no low-ping peer evicted"
    );
}
