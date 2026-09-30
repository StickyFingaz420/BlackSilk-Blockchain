//! Adversarial tests of the encrypted transport and the handshake as the node
//! runs them (research dossier 30, W1 and W2; docs/p2p.md §3, §4).
//!
//! | Test | Rule |
//! |---|---|
//! | `a_pre_verack_frame_over_the_cap_closes_the_connection_without_a_ban` | W1: every frame before `Verack` is at most `MAX_HANDSHAKE_FRAME` |
//! | `handshake_frames_at_the_cap_still_complete_the_handshake` | W1: the P0-8 negotiation window keeps working at the cap |
//! | `a_drip_fed_handshake_is_closed_at_the_overall_deadline` | W1: one deadline from the connection to `Verack` |
//! | `an_unsolicited_message_before_verack_closes_the_connection` | W1: only handshake messages before `Verack` |
//! | `a_decrypt_failure_after_registration_disconnects_without_a_ban` | W2: an AEAD failure is not attributable, never scored |
//! | `a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set` | F48-1 (AT-1): the closed-network key stops an on-path relay |
//! | `only_nodes_with_the_network_psk_connect_and_others_are_not_banned` | F48-1: members only; outsiders are refused, unscored |
//!
//! Three of the W1/W2 tests failed on the base commit (1db5d1a): an
//! oversized `Version` was answered, a drip-fed handshake completed after
//! about 24 s, and a flipped bit banned 127.0.0.1 for 24 h.

mod common;

use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::store::MemoryStore;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::{handshake, NetworkPsk};
use blacksilk_p2p::{NetConfig, Network, SharedChain};
use blacksilk_tx::params::TxRules;
use common::{fast_config, params, RawReader, RawWriter, ZeroPow};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// The pre-`Verack` frame cap (`message::MAX_HANDSHAKE_FRAME`), restated so
/// that a change of the constant is a visible change of this test.
const CAP: usize = 4096;

struct Node {
    net: Network,
    addr: SocketAddr,
    _chain: SharedChain,
}

async fn node_with(seed: u64, cfg: NetConfig) -> Node {
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
    Node {
        net,
        addr,
        _chain: chain,
    }
}

/// A node that bans loopback addresses like any other (`allow_private` off),
/// so that a ban is observable.
async fn banning_node(seed: u64) -> Node {
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    node_with(seed, cfg).await
}

fn version(nonce: u64) -> Vec<u8> {
    Message::Version(Version {
        protocol: PROTOCOL_VERSION,
        network: params().network_id,
        nonce,
        height: 0,
        tip: params().genesis_id(),
        listen: None,
        relay_txs: true,
    })
    .encode()
}

/// The key exchange with the node at `addr`, nothing else.
async fn keyed(addr: SocketAddr) -> (RawReader, RawWriter) {
    let s = TcpStream::connect(addr).await.unwrap();
    handshake(
        s,
        true,
        params().network_id,
        &params().genesis_id(),
        Duration::from_secs(5),
    )
    .await
    .unwrap()
}

/// Sends `version` and reads the node's `Version`.
async fn exchange_versions(r: &mut RawReader, w: &mut RawWriter, version: &[u8]) {
    w.send(version).await.unwrap();
    let m = Message::decode(&r.recv().await.unwrap()).unwrap();
    assert!(matches!(m, Message::Version(_)), "the node's version first");
}

/// The next frame from the node within `secs`: `Some(Ok)` a frame,
/// `Some(Err)` the connection closed, `None` still open and silent.
async fn next_frame(r: &mut RawReader, secs: f64) -> Option<Result<Vec<u8>, ()>> {
    tokio::time::timeout(Duration::from_secs_f64(secs), r.recv())
        .await
        .ok()
        .map(|f| f.map_err(|_| ()))
}

/// Reads until a frame matches `want` (`true`) or the connection closes
/// (`false`), skipping other frames.
async fn reads_until(r: &mut RawReader, secs: f64, want: impl Fn(&Message) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs_f64(secs);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match next_frame(r, left.as_secs_f64()).await {
            Some(Ok(f)) => {
                if Message::decode(&f).is_ok_and(|m| want(&m)) {
                    return true;
                }
            }
            Some(Err(())) => return false,
            None => panic!("neither answered nor closed within {secs} s"),
        }
    }
}

/// Whether the node accepted our `Version`: it answers it with `Verack`.
async fn answers_verack(r: &mut RawReader, secs: f64) -> bool {
    reads_until(r, secs, |m| matches!(m, Message::Verack)).await
}

/// Whether the node registered the connection: a `Ping` sent now (after our
/// `Verack`) is answered. A node still in its handshake closes the
/// connection on a `Ping` instead.
async fn registered(r: &mut RawReader, w: &mut RawWriter, secs: f64) -> bool {
    if w.send(&Message::Ping(0x5eed).encode()).await.is_err() {
        return false;
    }
    reads_until(r, secs, |m| matches!(m, Message::Pong(0x5eed))).await
}

/// A full handshake from a fresh connection; `true` if the node registers it.
async fn can_connect(addr: SocketAddr, nonce: u64) -> bool {
    let (mut r, mut w) = keyed(addr).await;
    exchange_versions(&mut r, &mut w, &version(nonce)).await;
    w.send(&Message::Verack.encode()).await.unwrap();
    registered(&mut r, &mut w, 5.0).await
}

async fn wait_until(what: &str, secs: u64, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !cond() {
        assert!(Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// W1: a `Version` over the pre-`Verack` cap (here: a 4.1 KB extension area,
/// P0-8) closes the connection before the node answers `Verack`. The peer is
/// unregistered and unauthenticated, so nothing is scored or banned: a new
/// connection from the same address completes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_pre_verack_frame_over_the_cap_closes_the_connection_without_a_ban() {
    let a = banning_node(71).await;
    let (mut r, mut w) = keyed(a.addr).await;
    let mut v = version(1);
    v.resize(CAP + 1, 0xaa);
    w.send(&v).await.unwrap();
    // The node's own Version may come first; its Verack must not.
    assert!(
        !answers_verack(&mut r, 5.0).await,
        "oversized Version answered"
    );
    assert_eq!(a.net.stats().peers, 0);
    // An unknown negotiation frame over the cap, after a valid Version.
    let (mut r, mut w) = keyed(a.addr).await;
    exchange_versions(&mut r, &mut w, &version(2)).await;
    let mut unknown = vec![0x30];
    unknown.resize(CAP + 1, 0);
    w.send(&unknown).await.unwrap();
    let _ = w.send(&Message::Verack.encode()).await;
    assert!(
        !registered(&mut r, &mut w, 5.0).await,
        "oversized negotiation frame"
    );
    assert_eq!(a.net.stats().banned, 0, "nothing banned");
    assert!(can_connect(a.addr, 3).await, "the address is not banned");
}

/// W1 regression of P0-8: a `Version` and 8 unknown negotiation frames of
/// exactly the cap still complete the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_frames_at_the_cap_still_complete_the_handshake() {
    let a = banning_node(72).await;
    let (mut r, mut w) = keyed(a.addr).await;
    let mut v = version(4);
    v.resize(CAP, 0xaa);
    exchange_versions(&mut r, &mut w, &v).await;
    for _ in 0..8 {
        let mut unknown = vec![0x30];
        unknown.resize(CAP, 0);
        w.send(&unknown).await.unwrap();
    }
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(registered(&mut r, &mut w, 5.0).await);
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
}

/// W1: a peer that drip-feeds its negotiation frames, each well inside the
/// per-step timeout, is closed at the overall handshake deadline (20 s from
/// the connection), not after 8 more step timeouts. It sends `Verack` only
/// after the deadline: before the fix the handshake completed at about 24 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_drip_fed_handshake_is_closed_at_the_overall_deadline() {
    let a = banning_node(73).await;
    let start = Instant::now();
    let (mut r, mut w) = keyed(a.addr).await;
    exchange_versions(&mut r, &mut w, &version(5)).await;
    // The node's Verack follows its Version at once.
    let f = next_frame(&mut r, 5.0).await.unwrap().unwrap();
    assert!(matches!(Message::decode(&f), Ok(Message::Verack)));
    let reader = tokio::spawn(async move {
        let closed = matches!(next_frame(&mut r, 40.0).await, Some(Err(())));
        (closed, start.elapsed())
    });
    for _ in 0..8 {
        tokio::time::sleep(Duration::from_secs(3)).await;
        if w.send(&[0x30, 1]).await.is_err() {
            break;
        }
    }
    let _ = w.send(&Message::Verack.encode()).await;
    let (closed, at) = reader.await.unwrap();
    assert!(closed, "the connection was closed");
    assert!(
        at < Duration::from_secs(23),
        "closed at the 20 s deadline, not after {at:?}"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a.net.stats().peers, 0, "never registered");
    assert_eq!(a.net.stats().banned, 0);
}

/// W1: before `Verack`, a message other than the handshake's (here an
/// unsolicited `InvTx`) closes the connection, unscored. (This held before
/// W1 too; it is kept as a regression test.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsolicited_message_before_verack_closes_the_connection() {
    let a = banning_node(74).await;
    let (mut r, mut w) = keyed(a.addr).await;
    exchange_versions(&mut r, &mut w, &version(6)).await;
    w.send(&Message::InvTx(vec![[7; 32]]).encode())
        .await
        .unwrap();
    let _ = w.send(&Message::Verack.encode()).await;
    assert!(!registered(&mut r, &mut w, 5.0).await);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(a.net.stats().peers, 0);
    assert_eq!(a.net.stats().banned, 0);
}

/// A TCP relay to `node` that flips one bit of the next chunk it forwards
/// towards the node once `flip` is set: an on-path party that cannot read
/// the connection (docs/p2p.md §10).
async fn flipping_relay(node: SocketAddr) -> (SocketAddr, Arc<AtomicBool>) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let flip = Arc::new(AtomicBool::new(false));
    let f = flip.clone();
    tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let s = TcpStream::connect(node).await.unwrap();
        let (mut cr, mut cw) = c.into_split();
        let (mut sr, mut sw) = s.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut sr, &mut cw).await;
        });
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if f.swap(false, Ordering::SeqCst) {
                buf[n - 1] ^= 1;
            }
            if sw.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    (addr, flip)
}

/// W2: one bit flipped on the path after registration fails the AEAD at the
/// node. The node disconnects, but bans nothing and scores nothing: the
/// failure is not attributable to the peer (anyone on the path can cause
/// it), and a ban would let that party cut two honest nodes apart for 24 h.
/// The same address connects again at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decrypt_failure_after_registration_disconnects_without_a_ban() {
    let a = banning_node(75).await;
    let (relay, flip) = flipping_relay(a.addr).await;
    let (mut r, mut w) = keyed(relay).await;
    exchange_versions(&mut r, &mut w, &version(7)).await;
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(registered(&mut r, &mut w, 5.0).await);
    wait_until("registered", 5, || a.net.stats().peers == 1).await;
    flip.store(true, Ordering::SeqCst);
    w.send(&Message::Ping(1).encode()).await.unwrap();
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while r.recv().await.is_ok() {}
    })
    .await
    .is_ok();
    assert!(closed, "the connection is closed");
    wait_until("unregistered", 5, || a.net.stats().peers == 0).await;
    let st = a.net.stats();
    assert_eq!(st.banned, 0, "a decryption failure bans nothing");
    assert_eq!(st.misbehaving_disconnects, 0, "and is not misbehavior");
    assert_eq!(st.transport_failures, 1, "counted as a transport failure");
    assert!(can_connect(a.addr, 8).await, "the address connects again");
}

// ------------------------------------------------ closed-network key (F48-1)

fn test_psk(byte: u8) -> NetworkPsk {
    NetworkPsk::from_bytes([byte; 32]).unwrap()
}

/// AT-1 (F48-1): an on-path relay that runs the key exchange itself, as
/// node A's peer. Without a pre-shared key it reads A's first frame (its
/// `Version`) in the clear: the demonstration that the unauthenticated
/// transport does not stop a man in the middle. With a key on A, the relay's
/// session fails at that frame, and A records a transport failure, not
/// misbehavior.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_man_in_the_middle_reads_the_traffic_unless_a_psk_is_set() {
    for with_psk in [false, true] {
        let mitm = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = fast_config(&[mitm.local_addr().unwrap()]);
        cfg.network_psk = with_psk.then(|| test_psk(0x42));
        let a = node_with(80 + with_psk as u64, cfg).await;
        let (s, _) = tokio::time::timeout(Duration::from_secs(10), mitm.accept())
            .await
            .expect("A dials")
            .unwrap();
        // The relay's side towards A: A dialed it, so the relay responds.
        let (mut r, mut w) = handshake(
            s,
            false,
            params().network_id,
            &params().genesis_id(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        // The relay impersonates A's peer towards A.
        w.send(&version(10)).await.unwrap();
        let first = r.recv().await;
        if with_psk {
            assert!(first.is_err(), "the relay cannot read a PSK session");
            wait_until("failure counted", 5, || {
                a.net.stats().transport_failures >= 1
            })
            .await;
            let st = a.net.stats();
            assert_eq!((st.peers, st.misbehaving_disconnects), (0, 0));
        } else {
            let m = Message::decode(&first.expect("readable")).unwrap();
            assert!(matches!(m, Message::Version(_)), "read in the clear");
        }
    }
}

/// F48-1: two members sharing the key connect; a node without the key, or
/// with another one, never completes a session with a member, and the member
/// scores and bans nothing (the failure is not attributable).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_nodes_with_the_network_psk_connect_and_others_are_not_banned() {
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    // Every peer here comes from 127.0.0.1.
    cfg.max_per_ip = 8;
    cfg.network_psk = Some(test_psk(0x42));
    let a = node_with(83, cfg).await;
    let mut cfg = fast_config(&[a.addr]);
    cfg.network_psk = Some(test_psk(0x42));
    let b = node_with(84, cfg).await;
    wait_until("members connected", 10, || {
        a.net.stats().peers == 1 && b.net.stats().peers == 1
    })
    .await;
    let mut cfg = fast_config(&[a.addr]);
    cfg.network_psk = Some(test_psk(0x43));
    let other_key = node_with(85, cfg).await;
    let no_key = node_with(86, fast_config(&[a.addr])).await;
    // Both ends send `Version` at once; the one that reads first fails to
    // decrypt and closes, so the other may see only the close: each refused
    // connection is counted on at least one side.
    let failures = || {
        a.net.stats().transport_failures
            + other_key.net.stats().transport_failures
            + no_key.net.stats().transport_failures
    };
    wait_until("both refused", 10, || failures() >= 2).await;
    // A raw peer without the key fails the same way.
    let (mut r, mut w) = keyed(a.addr).await;
    let _ = w.send(&version(9)).await;
    assert!(r.recv().await.is_err(), "no readable frame without the key");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let st = a.net.stats();
    assert_eq!(st.peers, 1, "only the member");
    assert_eq!((st.banned, st.misbehaving_disconnects), (0, 0));
    assert_eq!(other_key.net.stats().peers, 0);
    assert_eq!(no_key.net.stats().peers, 0);
}
