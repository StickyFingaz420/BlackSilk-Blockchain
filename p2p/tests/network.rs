//! Multi-node tests over real TCP on localhost: propagation, header-first sync,
//! Dandelion++ relay, reorganization across the network, peer discovery, and
//! defenses against misbehaving peers.

use blacksilk_chain::actor::{self, ActorConfig};
use blacksilk_chain::block::Block;
use blacksilk_chain::manager::ChainManager;
use blacksilk_chain::mempool::MempoolError;
use blacksilk_chain::store::MemoryStore;
use blacksilk_consensus::merkle::tx_root;
use blacksilk_consensus::{
    seed_height, BlockHeader, Hash, HeaderChain, PowFunction, HEADER_VERSION,
};
use blacksilk_crypto::keys::{SubaddressIndex, WalletKeys};
use blacksilk_p2p::addr::AddrEntry;
use blacksilk_p2p::limits::score;
use blacksilk_p2p::message::{Message, Version, PROTOCOL_VERSION};
use blacksilk_p2p::transport::handshake;
use blacksilk_p2p::{NetAddr, NetConfig, Network, SharedChain};
use blacksilk_px::wallet::{self as pxw, Account};
use blacksilk_tx::builder::{build_coinbase, Payment};
use blacksilk_tx::params::TxRules;
use blacksilk_tx::px_builder::{build_px, px_standard_fee, PxPlan};
use blacksilk_tx::types::Transaction;
use blacksilk_tx::validate::ChainView;
use blacksilk_tx::TxError;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpStream;

mod net_support;
use net_support::*;

/// A PX record ciphertext that passes the ciphertext `R` rule: the base
/// point's encoding as `R`, then zeros (it opens for nobody).
fn px_ciphertext() -> Vec<u8> {
    let mut c = vec![0; blacksilk_px::delivery::CIPHERTEXT_BYTES];
    c[..32].copy_from_slice(&blacksilk_crypto::generators::G.compress().to_bytes());
    c
}

/// Every peer of `nodes` with a misbehavior score: (node index, peer
/// address, kind, score). The penalty reasons are in the debug log
/// (`BLACKSILK_TEST_LOG`).
fn penalized(nodes: &[&TestNode]) -> Vec<(usize, NetAddr, String, u32)> {
    nodes
        .iter()
        .enumerate()
        .flat_map(|(i, n)| {
            n.net
                .peers()
                .into_iter()
                .filter(|p| p.score != 0)
                .map(move |p| (i, p.addr, format!("{:?}", p.kind), p.score))
        })
        .collect()
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
fn serve_branch(r: RawReader, w: RawWriter, branch: Vec<BlockHeader>) {
    serve_branch_logged(r, w, branch);
}

/// [`serve_branch`], recording the first id of every locator it answers.
fn serve_branch_logged(
    mut r: RawReader,
    mut w: RawWriter,
    branch: Vec<BlockHeader>,
) -> Arc<Mutex<Vec<Hash>>> {
    let heads = Arc::new(Mutex::new(Vec::new()));
    let log = heads.clone();
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            let reply = match Message::decode(&frame) {
                Ok(Message::GetHeaders { locator, .. }) => {
                    log.lock().unwrap().push(locator[0]);
                    Message::Headers(serve_headers(&branch, &locator))
                }
                // Headers only: bodies are "not found" (no timeout penalty).
                Ok(Message::GetBlocks(ids)) => Message::NotFound(ids),
                // Alive: without pongs the node drops the peer 90 s in (a
                // 60 s ping interval plus the 30 s pong timeout), which
                // failed a slow `a_heavier_fork_deeper_than_one_batch_syncs`.
                Ok(Message::Ping(n)) => Message::Pong(n),
                _ => continue,
            };
            if w.send(&reply.encode()).await.is_err() {
                break;
            }
        }
    });
    heads
}

/// Answers the node's pings on `r`/`w` (and ignores everything else) until
/// the connection closes, as an honest peer does: without pongs the node
/// drops a peer 90 s in (a 60 s ping interval plus the 30 s pong timeout),
/// which a test of slow proof of work can reach on a loaded machine.
fn answer_pings(mut r: RawReader, mut w: RawWriter) {
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            if let Ok(Message::Ping(n)) = Message::decode(&frame) {
                if w.send(&Message::Pong(n).encode()).await.is_err() {
                    break;
                }
            }
        }
    });
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
            ..Default::default()
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
    fn pow_hash(&self, _: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        let nonce = u64::from_le_bytes(
            blob[blacksilk_consensus::POW_NONCE_OFFSET..blacksilk_consensus::POW_NONCE_OFFSET + 8]
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
    fn pow_hash(&self, key: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
        std::thread::sleep(Duration::from_millis(self.0));
        self.1.pow_hash(key, blob)
    }
}

/// A slow PoW function (every hash takes `ms` milliseconds; all pass).
struct SlowPow(u64);
impl PowFunction for SlowPow {
    fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
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

/// Whether the node closes the connection, waiting as long as its header
/// chain keeps growing: false only after `stall` seconds with neither a
/// close nor a new stored header. It bounds stalls, not the total time a
/// batch takes to verify: each PoW chunk spawns its hashing threads, and on
/// a loaded machine a new thread waits for the scheduler (INV-PEN: a
/// 31-header batch in 16 chunks took 5 ms idle, 1.0 to 2.4 s under 8
/// busy-loop processes, and over 10 s in a loaded suite run).
async fn closes_while_headers_grow(r: &mut RawReader, a: &TestNode, stall: u64) -> bool {
    let mut last = a.chain.lock().unwrap().header_height();
    loop {
        if closes_within(r, stall).await {
            return true;
        }
        let now = a.chain.lock().unwrap().header_height();
        if now == last {
            return false;
        }
        last = now;
    }
}

/// Waits until `a` stores at least `target` headers, as long as its header
/// chain keeps growing: panics only after `stall` seconds without a new
/// stored header ([`closes_while_headers_grow`] explains why the bound is on
/// stalls, not on the total).
async fn wait_while_headers_grow(what: &str, a: &TestNode, target: u64, stall: u64) {
    let height = || a.chain.lock().unwrap().header_height();
    let mut last = height();
    let mut since = tokio::time::Instant::now();
    while last < target {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let now = height();
        if now != last {
            (last, since) = (now, tokio::time::Instant::now());
        } else if since.elapsed() > Duration::from_secs(stall) {
            panic!("stalled at {last} headers waiting for: {what}");
        }
    }
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

/// Four connect-only nodes in labnet's topology (a ring with chords: node i
/// dials i+1 and i+2), each listening on its own loopback port, all of them
/// advertising that port (`--public-address`) if `public`.
async fn lab_mesh(seed: u64, public: bool) -> Vec<TestNode> {
    let addrs: Vec<SocketAddr> = (0..4).map(|_| free_local_addr()).collect();
    let mut nodes = Vec::new();
    for i in 0..4 {
        let mut cfg = fast_config(&[addrs[(i + 1) % 4], addrs[(i + 2) % 4]]);
        cfg.listen = Some(addrs[i]);
        cfg.connect_only = true;
        if public {
            cfg.public_address = Some(NetAddr::Ip(addrs[i]));
        }
        nodes.push(node_with(seed + i as u64, cfg).await);
    }
    for (i, n) in nodes.iter().enumerate() {
        wait_until(&format!("node {i} has its 4 links"), 30, || {
            n.net.stats().peers >= 4
        })
        .await;
    }
    nodes
}

/// Distinct lab nodes the joiner holds an outbound connection to.
fn outbound_lab_peers(joiner: &TestNode, lab: &[TestNode]) -> usize {
    let peers = joiner.net.peers();
    lab.iter()
        .filter(|n| {
            peers
                .iter()
                .any(|p| !p.inbound && p.addr == NetAddr::Ip(n.addr))
        })
        .count()
}

/// INV-PEERS (W4-RX labnet): a joiner that knows one peer, on a network whose
/// nodes advertise their addresses, reaches a second node through the
/// address it learns from that peer, all on one IP (127.0.0.1, one *tried*
/// entry per IP). Node 0's answer holds 1 entry of its 3 or 4; on 693dd95
/// that entry was node 0's own address (relayed back to it) in 7 of 32 runs,
/// and the joiner stayed with one peer (`a_node_does_not_store_its_own_address`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_with_one_peer_reaches_the_advertised_nodes() {
    let lab = lab_mesh(160, true).await;
    let known = lab[0].net.clone();
    wait_until("node 0 learned addresses", 20, || {
        let (n, t) = known.stats().known_addresses;
        n + t >= 2
    })
    .await;
    let joiner = node(170, &[lab[0].addr]).await;
    wait_until("the joiner reached a second lab node", 30, || {
        outbound_lab_peers(&joiner, &lab) >= 2
    })
    .await;
}

/// P2P-FIX2 item 1 (INV-PEERS small-network plateau): a joiner that knows
/// one seed fills its outbound target (4) on a network of four advertised
/// nodes, i.e. every one of them, the seed included once its address fetch
/// has closed. A `GetAddr` answer carries at least min(table, 8) addresses
/// (`addrman::GETADDR_MIN`): the seed's answer holds the other three nodes.
/// On the base (23 % of a 3-entry table: 1 address) the joiner filled its
/// target in 3 of 6 trial runs.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_joiner_with_one_seed_fills_its_outbound_target() {
    let lab = lab_mesh(230, true).await;
    for (i, n) in lab.iter().enumerate() {
        let net = n.net.clone();
        wait_until(&format!("node {i} learned the other three"), 20, || {
            let (n, t) = net.stats().known_addresses;
            n + t >= 3
        })
        .await;
    }
    let mut cfg = fast_config(&[]);
    cfg.seeds = vec![NetAddr::Ip(lab[0].addr)];
    cfg.block_relay_only = 0;
    let joiner = node_with(240, cfg).await;
    wait_until("the joiner filled its 4 outbound slots", 30, || {
        outbound_lab_peers(&joiner, &lab) >= 4
    })
    .await;
}

/// INV-PEERS: a node does not store its own address when a peer relays it
/// back. Its `GetAddr` answer holds at most 23 % of the table (1 entry of up
/// to 4), and on a small network that one entry could be the node's own
/// address, useless to the asker: a joiner that knew only that node then
/// learned nothing it could dial.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_does_not_store_its_own_address() {
    let a_addr = free_local_addr();
    let mut cfg = fast_config(&[]);
    cfg.listen = Some(a_addr);
    cfg.public_address = Some(NetAddr::Ip(a_addr));
    let a = node_with(220, cfg).await;
    let (_r, mut w) = raw_peer(a.addr, params().network_id, true).await;
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    // One entry per message, 10.5 s apart: an unsolicited `Addr` spends one
    // token per entry (one at the start, then 0.1 per second).
    let other = NetAddr::parse("127.0.0.1:9").unwrap();
    for e in [NetAddr::Ip(a_addr), other] {
        w.send(&Message::Addr(vec![AddrEntry::new(now, e)]).encode())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10_500)).await;
    }
    wait_until("the other address stored", 5, || {
        let (n, t) = a.net.stats().known_addresses;
        n + t >= 1
    })
    .await;
    assert_eq!(
        a.net.stats().known_addresses,
        (1, 0),
        "only the other address"
    );
}

/// INV-PEERS: nodes that do not advertise themselves are never learned,
/// by design (a private node is not revealed, docs/p2p.md §9): a joiner that
/// knows one of them stays with that one peer. This was the W4-RX labnet,
/// whose nodes ran without `--public-address`: node 0's table stayed empty,
/// so its `GetAddr` answer was empty.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nodes_that_do_not_advertise_are_not_discovered() {
    let lab = lab_mesh(180, false).await;
    let joiner = node(190, &[lab[0].addr]).await;
    wait_until("the joiner connected to node 0", 10, || {
        outbound_lab_peers(&joiner, &lab) == 1
    })
    .await;
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(lab[0].net.stats().known_addresses, (0, 0));
    assert_eq!(outbound_lab_peers(&joiner, &lab), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn invalid_header_gets_the_peer_disconnected() {
    let a = node(16, &[]).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
    // A header on genesis with a wrong difficulty.
    let bad = BlockHeader {
        version: HEADER_VERSION,
        height: 1,
        prev_id: params().genesis_id(),
        timestamp: params().genesis.timestamp + 120,
        difficulty: 999_999,
        tx_root: [0; 32],
        nonce: 0,
        ..Default::default()
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
    // The answer is NotFound, exactly as for a transaction the node never had: the
    // reply does not reveal the mempool content. (One handler sends any `Tx`
    // before the `NotFound`, so the `NotFound` ends the answer.)
    loop {
        match Message::decode(&r.recv().await.unwrap()).unwrap() {
            Message::NotFound(ids) => {
                assert_eq!(ids, vec![id]);
                break;
            }
            Message::Tx(_) => panic!("served a transaction that was never announced to this peer"),
            _ => {}
        }
    }
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

/// L8 (Stage 2, dossier 34 F34-5): with the chain actor's Tx lane full (here
/// of capacity 0, so always full), a requested, valid relayed transaction is
/// dropped before verification, counted, and its sender is not penalized;
/// a block the node requests from the same peer meanwhile is connected (the
/// Blocks lane is never refused).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn l8_a_full_tx_lane_drops_relayed_transactions_without_penalty() {
    let mut a = node_with_actor(
        0x28,
        fast_config(&[]),
        ActorConfig {
            capacity: [64, 256, 1024, 0],
            ..ActorConfig::default()
        },
    )
    .await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    loop {
        if let Message::GetTx(ids) = Message::decode(&r.recv().await.unwrap()).unwrap() {
            assert_eq!(ids, vec![id]);
            break;
        }
    }
    w.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
    let an = a.net.clone();
    wait_until("the transaction dropped at the Tx lane", 20, || {
        an.stats().tx_lane_drops == 1
    })
    .await;
    let stats = a.net.stats();
    assert_eq!(stats.tx_verifications, 0, "never verified");
    assert!(!a.mempool_has(&id), "not pooled");

    // A block announced by the same peer is requested and connected.
    let block = {
        let mut other = node(0x29, &[]).await;
        // The same chain as `a` (its blocks), then one block more.
        let mut c = other.chain.lock().unwrap();
        let ca = a.chain.lock().unwrap();
        for h in 1..=ca.height() {
            let b = ca.block_at(h).unwrap();
            let now = b.header.timestamp;
            c.submit_block(b, now).unwrap();
        }
        drop((c, ca));
        other.mine_with(7, false)
    };
    let height = a.height();
    w.send(&Message::Headers(vec![block.header]).encode())
        .await
        .unwrap();
    let requested = block.id(nid);
    loop {
        match Message::decode(&r.recv().await.unwrap()).unwrap() {
            Message::GetBlocks(ids) if ids.contains(&requested) => break,
            Message::Ping(n) => w.send(&Message::Pong(n).encode()).await.unwrap(),
            _ => {}
        }
    }
    w.send(&Message::Block(block.encode()).encode())
        .await
        .unwrap();
    let chain = a.chain.clone();
    wait_until("the requested block connected", 20, move || {
        chain.lock().unwrap().height() == height + 1
    })
    .await;
    let peers = a.net.peers();
    assert_eq!(peers.len(), 1, "still connected");
    assert_eq!(peers[0].score, 0, "no penalty for the dropped relay");
    println!("L8: {:?}", a.net.stats());
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
    init_test_log();
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
    let scored = penalized(&[&a, &b, &c]);
    assert!(
        scored.is_empty(),
        "penalized (node, peer, kind, score): {scored:?}"
    );
    let mut c = c;
    c.mine(0);
    wait_until("A and B confirm", 60, || {
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
    // peer exceeding its own share has its excess dropped, unpenalized
    // (RTW2A-4: an honest forwarder exceeds a rate without misbehaving; the
    // share itself is `limits::tests::relay_charges_are_all_or_nothing`).
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
    // Over its PX share (burst 4), within its byte burst (16 MB): the byte
    // rate stays a scored flood limit on the read loop, and is not what
    // this checks.
    let frame = Message::StemTx(bytes.clone()).encode().len();
    let sixth = (16_000_000 / frame).min(8);
    assert!(sixth > 4, "{sixth} stems of {frame} bytes");
    for _ in 0..sixth {
        w6.send(&Message::StemTx(bytes.clone()).encode())
            .await
            .unwrap();
    }
    // A slow-lane barrier after the stems: its answer means they were all
    // handled (a ping is no barrier: pongs overtake lane work since Stage 1).
    // Queued PX bytes never drop the barrier request.
    raws.push((r6, w6));
    for (i, (r, w)) in raws.iter_mut().enumerate() {
        send_and_sync(r, w, &[], 100 + i as u64).await;
    }
    let scores: Vec<u32> = b
        .net
        .peers()
        .iter()
        .filter(|p| !before.contains(&p.id))
        .map(|p| p.score)
        .collect();
    assert_eq!(scores, [0; 6], "no peer penalized, over its share or not");

    // A request behind a queued PX transaction (more than the lane's relay
    // byte bound) is answered and costs its sender nothing: the Stage 1
    // lane dropped it and charged it.
    assert!(bytes.len() > 2 * 1024 * 1024, "{} bytes", bytes.len());
    let (mut r7, mut w7) = raw_peer(b.addr, nid, true).await;
    w7.send(&Message::StemTx(bytes.clone()).encode())
        .await
        .unwrap();
    w7.send(
        &Message::GetHeaders {
            locator: vec![params().genesis_id()],
            stop: [0; 32],
        }
        .encode(),
    )
    .await
    .unwrap();
    assert!(
        recv_until(
            &mut r7,
            20.0,
            |m| matches!(m, Message::Headers(h) if h.len() == 81)
        )
        .await
        .is_some(),
        "the GetHeaders behind a PX StemTx is answered"
    );
    let newest = b
        .net
        .peers()
        .into_iter()
        .filter(|p| !before.contains(&p.id))
        .max_by_key(|p| p.id)
        .unwrap();
    assert_eq!(newest.score, 0, "the requester is not charged");
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
            window: Default::default(),
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
    // A deposit whose proof still decodes with the same shape, so that the
    // CLSAG over it (which covers the proof bytes) is what refuses it. The
    // prover's bytes vary with thread scheduling, so a fixed position (the
    // middle) sometimes broke the proof's structure instead and the decoder
    // refused it first, as PxProof (CI run 126); search from the middle for
    // a flip that keeps the proof decodable.
    let shape = |t: &blacksilk_tx::px::PxTx| {
        blacksilk_tx::validate::decode_px_proof(t)
            .ok()
            .map(|p| p.degree_bits)
    };
    let honest_shape = shape(dep.as_ref()).expect("the deposit's proof decodes");
    let bad_deposit = (dep.proof.len() / 2..dep.proof.len())
        .map(|i| {
            let mut t = (*dep).clone();
            t.proof[i] ^= 1;
            t
        })
        .find(|t| shape(t).as_ref() == Some(&honest_shape))
        .expect("some proof byte flip keeps the proof decodable");
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
        let (mut r, mut w) = raw_peer(a.addr, params().network_id, true).await;
        if penalized {
            w.send(&Message::StemTx(bad.encode()).encode())
                .await
                .unwrap();
            wait_until(what, 60, || {
                a.net.peers().iter().any(|p| p.score >= score::INVALID_TX)
            })
            .await;
        } else {
            // Handled once the lane barrier behind it is answered (within
            // the same 60 s as a penalty above); the peer stays unpenalized.
            // (Before INV-PEN: a fixed 3 s sleep, which passes unchecked if
            // the verdict comes later.)
            w.send(&Message::StemTx(bad.encode()).encode())
                .await
                .unwrap();
            let (barrier, answered) = lane_barrier(1);
            w.send(&barrier).await.unwrap();
            assert!(recv_until(&mut r, 60.0, answered).await.is_some(), "{what}");
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
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
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

/// A solicited batch whose headers are not a chain costs the sender
/// `UNCONNECTED_HEADERS` on the read loop, before any queueing or hash, for
/// a wrong parent alone and for a wrong height alone (mutation run E: the
/// existing tests broke both links at once).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_solicited_batch_that_is_not_a_chain_is_scored_on_arrival() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(46, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 5).await;
    let branch = header_branch(3, 120, 0);
    let mut height = branch.clone();
    height[2].height += 1; // its parent is right
    let mut parent = branch.clone();
    parent[2].prev_id = branch[0].id(nid); // its height is right
    for (k, batch) in [height, parent].into_iter().enumerate() {
        assert!(
            recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
                .await
                .is_some(),
            "asked for headers"
        );
        w.send(&Message::Headers(batch).encode()).await.unwrap();
        w.send(&Message::Ping(k as u64).encode()).await.unwrap();
        assert!(recv_until(
            &mut r,
            5.0,
            |m| matches!(m, Message::Pong(x) if *x == k as u64)
        )
        .await
        .is_some());
        assert_eq!(
            a.net.peers()[0].score,
            (k as u32 + 1) * score::UNCONNECTED_HEADERS,
            "batch {k}"
        );
    }
    assert_eq!(pow.0.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(a.chain.lock().unwrap().header_height(), 0);
}

/// A solicited batch whose first header connects to nothing we know costs
/// the sender `UNCONNECTED_HEADERS`; a single such header (a tip
/// announcement whose parent we lack) costs nothing and gets the sender
/// asked for headers (mutation run E: no test checked the batch-size rule).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unconnected_batch_is_scored_and_an_unconnected_announcement_is_not() {
    let a = node_with_pow(47, fast_config(&[]), Arc::new(ZeroPow)).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10).await;
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    let branch = header_branch(5, 120, 0);
    // Headers 2 and 3: the parent of the first is unknown.
    w.send(&Message::Headers(branch[1..3].to_vec()).encode())
        .await
        .unwrap();
    wait_until("scored", 10, || {
        a.net.peers()[0].score == score::UNCONNECTED_HEADERS
    })
    .await;
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    // Header 5 alone, unsolicited: asked for headers, not scored.
    w.send(&Message::Headers(vec![branch[4]]).encode())
        .await
        .unwrap();
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some(),
        "asked for headers"
    );
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    assert_eq!(a.net.peers()[0].score, score::UNCONNECTED_HEADERS);
}

/// Counts every PoW evaluation; fails headers carrying `BAD_NONCE` (as
/// `CountingPow`).
#[derive(Default)]
struct CountAllPow(std::sync::atomic::AtomicUsize);
impl PowFunction for CountAllPow {
    fn pow_hash(&self, seed: &Hash, blob: &blacksilk_consensus::PowBlob) -> Hash {
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
        ..Default::default()
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
        closes_while_headers_grow(&mut r, &a, 10).await,
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
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
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
        let (output_count, output_root) = t.outputs_after(&txs);
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
            output_count,
            output_root,
            px_root: t.px_root,
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
            ..Default::default()
        }
    };
    let nid = params().network_id;
    // Announced one by one, and as a solicited batch. Each is verified on
    // its own before the next is sent (`send_and_await_verdict`): before
    // INV-PEN the three went out back to back, so the two announcements
    // usually arrived while the batch was in flight and were dropped
    // unverified, and the rule-breaking header below was sent after a fixed
    // 500 ms, which the batch outlasted on a loaded machine (its announcement
    // was then dropped too, and the node's request for it went unanswered).
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    for (k, headers) in [vec![bad, child], vec![bad], vec![child]]
        .into_iter()
        .enumerate()
    {
        send_and_await_verdict(&a, &mut r, &mut w, headers, bad, k as u64).await;
        assert_eq!(a.net.stats().misbehaving_disconnects, 0);
        assert_eq!(a.net.peers().len(), 1, "still connected");
        assert_eq!(a.net.peers()[0].score, 0, "not penalized");
        // Its claimed height (10) is lowered to ours, so it is not asked
        // again every tick (mutation run E: the arm had no test).
        assert_eq!(
            a.net.peers()[0].height,
            a.chain.lock().unwrap().header_height(),
            "batch {k}"
        );
    }
    assert_eq!(a.height(), 2, "the invalid branch is not followed");
    // A header that itself breaks the rules is still penalized. No batch of
    // the peer is in flight now, so it is verified at once.
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

/// Holds the chain of `a` from another thread until [`HeldChain::release`]:
/// the header worker's first chain command for a batch waits behind it, so
/// the batch is in flight for as long as the test needs, whatever the load.
struct HeldChain {
    release: std::sync::mpsc::Sender<()>,
    thread: std::thread::JoinHandle<()>,
}

impl HeldChain {
    async fn hold(a: &TestNode) -> Self {
        let (held_tx, held_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = std::sync::mpsc::channel::<()>();
        let chain = a.chain.clone();
        let thread = std::thread::spawn(move || {
            let _guard = chain.lock().unwrap();
            held_tx.send(()).unwrap();
            let _ = release_rx.recv();
        });
        held_rx.await.unwrap();
        Self { release, thread }
    }

    async fn release(self) {
        self.release.send(()).unwrap();
        tokio::task::spawn_blocking(move || self.thread.join().unwrap())
            .await
            .unwrap();
    }
}

/// Sends `headers` and waits, by message order alone, until the node has
/// verified them: the chain is held while `headers` and then `poke` (one
/// header) arrive, so `poke` finds the batch in flight and is dropped, and
/// the node asks again (`GetHeaders`) once the batch's verdict is in
/// (docs/p2p.md §6, "At most one batch per peer"). That request is answered
/// as by a peer with nothing new: an empty batch. A ping answered before the
/// chain is released proves both messages were read while it was held.
/// Only for batches the peer is not penalized for (a penalty sends no
/// request).
async fn send_and_await_verdict(
    a: &TestNode,
    r: &mut RawReader,
    w: &mut RawWriter,
    headers: Vec<BlockHeader>,
    poke: BlockHeader,
    nonce: u64,
) {
    let held = HeldChain::hold(a).await;
    w.send(&Message::Headers(headers).encode()).await.unwrap();
    w.send(&Message::Headers(vec![poke]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(nonce).encode()).await.unwrap();
    assert!(
        recv_until(r, 10.0, |m| matches!(m, Message::Pong(n) if *n == nonce))
            .await
            .is_some(),
        "pong while the chain is held"
    );
    held.release().await;
    assert!(
        recv_until(r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some(),
        "asked again once the batch is verified"
    );
    w.send(&Message::Headers(Vec::new()).encode())
        .await
        .unwrap();
}

/// INV-PEN: a header announced while the sender's previous batch is still
/// being verified is not verified then (at most one batch per peer is in
/// flight), but it is not lost either: the node asks the peer again once the
/// batch is done, and what the peer answers is verified and scored as
/// usual. Here the announcement breaks a rule, and the peer, answering the
/// request with it, is banned. The batch is kept in flight by holding the
/// chain, not by timing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_header_announced_during_a_batch_is_asked_for_again_and_scored() {
    let a = node(142, &[]).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 10).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    let batch = header_branch(3, 120, 0);
    let mut broken = batch[0];
    broken.height = 5;
    let held = HeldChain::hold(&a).await;
    w.send(&Message::Headers(batch).encode()).await.unwrap();
    w.send(&Message::Headers(vec![broken]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(1).encode()).await.unwrap();
    assert!(recv_until(&mut r, 10.0, |m| matches!(m, Message::Pong(1)))
        .await
        .is_some());
    held.release().await;
    // The announcement was dropped unverified, not scored.
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some(),
        "the peer is asked again once its batch is verified"
    );
    assert_eq!(
        a.net.peers()[0].score,
        0,
        "the dropped header is not scored"
    );
    assert_eq!(a.chain.lock().unwrap().header_height(), 3);
    w.send(&Message::Headers(vec![broken]).encode())
        .await
        .unwrap();
    assert!(
        closes_within(&mut r, 5).await,
        "the rule-breaking reply gets the peer banned"
    );
    assert_eq!(a.net.stats().misbehaving_disconnects, 1);
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
    // 60 headers x 100 ms: 6 s of proof of work on one thread. With one PoW
    // thread every header is its own chunk, and each chunk costs two chain
    // commands and a hashing thread: thread hand-offs that a loaded machine
    // makes slow. Before INV-PEN the batch was 300 headers x 20 ms, the same
    // 6 s idle but 35 to 51 s with 8 busy-loop processes (60 x 100 ms: 10.5
    // to 11.5 s), and over 90 s in a loaded suite run, where the node then
    // dropped this raw peer for not answering its pings (60 s interval plus
    // 30 s pong timeout) and abandoned the batch: "batch verified" timed out.
    // The pong itself was answered in time in every run.
    let n = 60;
    let a = node_with_pow(45, cfg, Arc::new(SlowPow(100))).await;
    let nid = params().network_id;
    let batch = header_branch(n, 120, 0);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, n as u64).await;
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
        a.chain.lock().unwrap().header_height() < n as u64,
        "the batch was still being verified when the pong came"
    );
    wait_until("batch verified", 120, || {
        a.chain.lock().unwrap().header_height() == n as u64
    })
    .await;
    assert!(started.elapsed() > Duration::from_secs(3));
    assert_eq!(a.net.peers()[0].score, 0);
}

/// A peer that disconnects before its batch is verified is still charged: the
/// verdict comes from the header worker after the peer has left. Its batch
/// waits behind another peer's batch, held in flight by holding the chain;
/// when its turn comes, the sender is gone, so only the cheap pre-check runs:
/// the rule violation is found and charged, and none of its headers is
/// hashed or stored. (Before INV-PEN the honest batch was 200 headers of
/// slow proof of work, sent by a raw peer that never answers pings: on a
/// loaded machine the batch outlasted the 90 s pong timeout, the node
/// dropped that peer and abandoned its batch at 161 headers.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_leaves_before_its_bad_batch_is_verified_is_still_charged() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(46, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let (mut r1, mut w1) = raw_peer_at(a.addr, nid, true, 3).await;
    assert!(
        recv_until(&mut r1, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    // 100 valid headers, then one that breaks a rule.
    let mut batch = header_branch(101, 120, 5);
    batch[100].difficulty += 5;
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 1000).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    // The honest batch is taken up first and waits for the chain; the bad
    // one is queued behind it. Each pong proves its batch was read.
    let held = HeldChain::hold(&a).await;
    w1.send(&Message::Headers(header_branch(3, 120, 0)).encode())
        .await
        .unwrap();
    assert!(pong_latency(&mut r1, &mut w1, 1, 10.0).await.is_some());
    w.send(&Message::Headers(batch.clone()).encode())
        .await
        .unwrap();
    assert!(pong_latency(&mut r, &mut w, 2, 10.0).await.is_some());
    assert_eq!(a.net.header_queue_len(), 2, "both batches queued");
    drop((r, w));
    wait_until("peer gone", 10, || a.net.stats().peers == 1).await;
    assert_eq!(a.net.stats().misbehaving_disconnects, 0, "not yet verified");
    held.release().await;
    wait_until("charged after leaving", 30, || {
        a.net.stats().misbehaving_disconnects == 1
    })
    .await;
    let c = a.chain.lock().unwrap();
    assert!(
        c.header(&batch[0].id(nid)).is_none(),
        "nothing of a banned sender's batch is stored"
    );
    assert_eq!(c.header_height(), 3, "the honest batch is kept");
    assert_eq!(
        pow.0.load(std::sync::atomic::Ordering::SeqCst),
        3,
        "only the honest headers are hashed"
    );
}

/// A sender that leaves while its batch is hashed, chunk by chunk, stops
/// costing hashes at the next chunk (mutation run E: the check between
/// chunks had no test). One thread, so one header per chunk, 300 ms per
/// hash; the sender leaves after its second header is hashed, out of 40.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_departed_senders_batch_stops_at_the_next_chunk() {
    struct Slow(std::sync::atomic::AtomicUsize);
    impl PowFunction for Slow {
        fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
            std::thread::sleep(Duration::from_millis(300));
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            [0; 32]
        }
    }
    let pow = Arc::new(Slow(Default::default()));
    let hashes = || pow.0.load(std::sync::atomic::Ordering::SeqCst);
    let mut cfg = fast_config(&[]);
    cfg.pow_threads = 1;
    let a = node_with_pow(68, cfg, pow.clone()).await;
    let (mut r, mut w) = raw_peer_at(a.addr, params().network_id, true, 1000).await;
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(header_branch(40, 120, 0)).encode())
        .await
        .unwrap();
    wait_until("hashing", 30, || hashes() >= 2).await;
    drop((r, w));
    wait_until("peer gone", 10, || a.net.stats().peers == 0).await;
    wait_until("worker done", 30, || a.net.header_queue_len() == 0).await;
    let n = hashes();
    assert!(n < 40, "{n} of 40 hashed after the sender left");
    assert!(a.chain.lock().unwrap().header_height() < 40);
}

/// The proof of work of a header batch is hashed off the chain actor, chunk
/// after chunk: each chunk's jobs are computed while the previous chunk is
/// accepted, so the actor only looks the hashes up (docs/p2p.md §6;
/// mutation run E: the next chunk's index had no test, and with the
/// current chunk's jobs instead every later chunk was hashed on the actor).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn header_batches_are_hashed_off_the_chain_actor() {
    #[derive(Default)]
    struct Where {
        total: std::sync::atomic::AtomicUsize,
        on_actor: std::sync::atomic::AtomicUsize,
    }
    impl PowFunction for Where {
        fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
            use std::sync::atomic::Ordering::SeqCst;
            self.total.fetch_add(1, SeqCst);
            if std::thread::current().name() == Some("chain-actor") {
                self.on_actor.fetch_add(1, SeqCst);
            }
            [0; 32]
        }
    }
    let pow = Arc::new(Where::default());
    let mut cfg = fast_config(&[]);
    cfg.pow_threads = 2; // chunks of 2 headers
    let a = node_with_pow(69, cfg, pow.clone()).await;
    let (mut r, mut w) = raw_peer_at(a.addr, params().network_id, true, 1000).await;
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w.send(&Message::Headers(header_branch(10, 120, 0)).encode())
        .await
        .unwrap();
    wait_until("stored", 30, || {
        a.chain.lock().unwrap().header_height() == 10
    })
    .await;
    use std::sync::atomic::Ordering::SeqCst;
    assert_eq!(pow.total.load(SeqCst), 10, "each header hashed once");
    assert_eq!(pow.on_actor.load(SeqCst), 0, "none on the chain actor");
}

/// The clock monitor's samples come from live arrivals only: headers that
/// extend the best header chain above its height when their batch was
/// taken up, outside bulk sync, from at least three peers before an
/// estimate is reported. A header on a side branch, a tip sent again, a
/// heavier rival at the same height and a taller but lighter branch add
/// none (mutation run E: no network test read the clock monitor,
/// `Network::clock_estimate`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clock_samples_come_from_live_arrivals_only() {
    // Chunks of 64 headers: the 160-header branch below is hashed in three.
    let mut cfg = fast_config(&[]);
    cfg.pow_threads = 64;
    let a = node_with_pow(70, cfg, Arc::new(ZeroPow)).await;
    let nid = params().network_id;
    // Our chain: 150 fast headers (past the difficulty warm-up), then 5
    // announced, 1 000 s apart (each counted at the 6T solve-time cap).
    let base = header_branch(150, 1, 0);
    give_headers(&a, &base);
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &base {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let child = |g: &HeaderChain, parent: Hash, dt: u64, nonce: u64| {
        let t = g.template_on(parent).unwrap();
        BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: parent,
            timestamp: t
                .min_timestamp
                .max(g.header(&parent).unwrap().timestamp + dt),
            difficulty: t.difficulty,
            tx_root: [0; 32],
            nonce,
            ..Default::default()
        }
    };
    let fork = g.tip_id();
    let mut ours = Vec::new();
    let mut tip = fork;
    for _ in 0..5 {
        let h = child(&g, tip, 1_000, 0);
        tip = g.accept(h, u64::MAX / 2).unwrap().id;
        ours.push(h);
    }
    let mut peers = Vec::new();
    for _ in 0..3 {
        let (r, w) = raw_peer(a.addr, nid, true).await;
        peers.push((r, w));
    }
    wait_until("registered", 5, || a.net.stats().peers == 3).await;
    for (k, h) in ours.iter().enumerate() {
        let (_, w) = &mut peers[k % 3];
        w.send(&Message::Headers(vec![*h]).encode()).await.unwrap();
        wait_until("stored", 10, || {
            a.chain.lock().unwrap().header_height() == 151 + k as u64
        })
        .await;
        wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
        if k < 4 {
            assert!(a.net.clock_estimate().is_none(), "{} samples", k + 1);
        }
    }
    let e = a.net.clock_estimate().expect("5 samples from 3 peers");
    assert_eq!((e.samples, e.peers), (5, 3));
    // A side branch's header (new, not on the best chain) and the tip again.
    let side = child(&g, g.main_id_at(153).unwrap(), 1, 31);
    let (_, w) = &mut peers[0];
    w.send(&Message::Headers(vec![side]).encode())
        .await
        .unwrap();
    wait_until("the side header is stored", 10, || {
        a.chain.lock().unwrap().header(&side.id(nid)).is_some()
    })
    .await;
    let (_, w) = &mut peers[1];
    w.send(&Message::Headers(vec![ours[4]]).encode())
        .await
        .unwrap();
    // A rival of five headers from our fork point, 1 s apart: heavier at
    // the same height (the counted clock gives it the higher difficulty),
    // whose tip becomes our best header without rising above our height.
    let mut rival = Vec::new();
    let mut r_tip = fork;
    for _ in 0..5 {
        let h = child(&g, r_tip, 1, 9);
        r_tip = g.accept(h, u64::MAX / 2).unwrap().id;
        rival.push(h);
    }
    assert!(
        g.work(&r_tip).unwrap() > g.work(&tip).unwrap(),
        "the rival is heavier"
    );
    // As a solicited batch: the rival tip ends at our height (155).
    let (mut r4, mut w4) = raw_peer_at(a.addr, nid, true, 200).await;
    assert!(
        recv_until(&mut r4, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    w4.send(&Message::Headers(rival.clone()).encode())
        .await
        .unwrap();
    wait_until("the rival is stored", 10, || {
        a.chain.lock().unwrap().header(&r_tip).is_some()
    })
    .await;
    assert_eq!(a.chain.lock().unwrap().best_header_id(), r_tip);
    for (k, (r, w)) in peers.iter_mut().enumerate() {
        w.send(&Message::Ping(k as u64).encode()).await.unwrap();
        assert!(
            recv_until(r, 5.0, |m| matches!(m, Message::Pong(x) if *x == k as u64))
                .await
                .is_some()
        );
    }
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    // A taller, lighter branch from the genesis (difficulty 1 throughout),
    // as the reply to the handshake's request of a fourth peer.
    let theirs = header_branch(160, 120, 3);
    let mut t = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &theirs {
        t.accept(*h, u64::MAX / 2).unwrap();
    }
    let best = a.chain.lock().unwrap().headers().best_work();
    assert!(
        best > t.best_work(),
        "ours {best} against {}",
        t.best_work()
    );
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 160).await;
    let Some(Message::GetHeaders { locator, .. }) =
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. })).await
    else {
        panic!("no GetHeaders");
    };
    w.send(&Message::Headers(serve_headers(&theirs, &locator)).encode())
        .await
        .unwrap();
    let last = theirs[159].id(nid);

    wait_until("the lighter branch is stored as a side branch", 30, || {
        a.chain.lock().unwrap().header(&last).is_some()
    })
    .await;
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    assert_eq!(
        a.chain.lock().unwrap().best_header_id(),
        r_tip,
        "ours stays best"
    );
    let e = a.net.clock_estimate().unwrap();
    assert_eq!((e.samples, e.peers), (5, 3), "no sample from any of them");
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
    // On a loaded machine the batch outlasts the pong timeout (35 to 51 s
    // under 8 busy-loop processes for this shape, INV-PEN): without pongs
    // the node would drop the sender and abandon its batch.
    answer_pings(r0, w0);
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
    // An honest peer from another address, with 10 more headers. It was 100
    // before INV-PEN: 100 one-header chunks, each costing its proof of work
    // plus a thread spawn, which under load alone takes 75 to 130 ms
    // (INV-PEN: 300 cheap one-thread chunks took 22 to 40 s under 8
    // busy-loop processes), so the honest batch's own cost could reach the
    // 30 s bound below. A queued junk batch would cost 2000 hashes, 40 s or
    // more, each.
    let honest = header_branch(310, 120, 0);
    let (r, w) = raw_peer_from([127, 0, 0, 2], a.addr, nid, 310)
        .await
        .unwrap();
    serve_branch(r, w, honest);
    wait_while_headers_grow("the busy batch is verified", &a, 300, 30).await;
    let t = std::time::Instant::now();
    wait_until("the honest batch is verified", 40, || {
        a.chain.lock().unwrap().header_height() == 310
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

/// The per-IP limit is checked again at registration, counting every
/// registered peer of the IP, outbound ones too: an inbound connection
/// accepted while its IP had room is refused at registration if the IP's
/// peers reached `max_per_ip` meanwhile (here an outbound connection to the
/// same IP registered during its handshake), and accepted while they are one
/// below it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_per_ip_limit_is_rechecked_at_registration() {
    let nid = params().network_id;
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    cfg.max_per_ip = 2;
    cfg.max_inbound = 16;
    let a = node_with(51, cfg).await;
    // One inbound peer from 127.0.0.1, registered.
    let _first = raw_peer(a.addr, nid, true).await;
    wait_until("first registered", 20, || a.net.stats().inbound == 1).await;
    // A second one accepted (one peer of the IP, room for two) and holding
    // its key exchange done, before its `Version`.
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    // Meanwhile an outbound connection to the same IP registers: two peers.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _out = dialed_raw_peer(&a, &l).await;
    assert_eq!(a.net.stats().peers, 2);
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: 0x5151,
        height: 0,
        tip: params().genesis_id(),
        listen: None,
        relay_txs: true,
    };
    w.send(&Message::Version(v).encode()).await.unwrap();
    // Refused at registration (after the `Verack`s): closed, never
    // registered; until then it sends nothing but its handshake.
    let closed = tokio::time::timeout(Duration::from_secs(10), async {
        let mut kinds = Vec::new();
        loop {
            match r.recv().await {
                Err(_) => break kinds,
                Ok(m) => match Message::decode(&m) {
                    Ok(Message::Version(_)) => {
                        kinds.push("version");
                        let _ = w.send(&Message::Verack.encode()).await;
                    }
                    Ok(Message::Verack) => kinds.push("verack"),
                    _ => kinds.push("other"),
                },
            }
        }
    })
    .await;
    assert!(
        matches!(&closed, Ok(k) if !k.contains(&"other")),
        "a third peer of the IP registered: {closed:?}"
    );
    assert_eq!(a.net.stats().peers, 2);
    assert_eq!(a.net.stats().inbound, 1);
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
    init_test_log();
    let a = node(51, &[]).await;
    let nid = params().network_id;
    // Just deeper than one batch, and just heavier: 2100 against 2050
    // headers (it was 3000 against 2500). The deadline is for loaded
    // machines (a debug build verifies the first batch in 70 to 90 s).
    give_headers(&a, &header_branch(2050, 120, 0));
    let theirs = header_branch(2100, 120, 7);
    let (r, w) = raw_peer_at(a.addr, nid, true, 2100).await;
    let heads = serve_branch_logged(r, w, theirs.clone());
    wait_until("switched to the heavier branch", 600, || {
        a.chain.lock().unwrap().best_header_id() == theirs[2099].id(nid)
    })
    .await;
    assert_eq!(a.net.peers()[0].score, 0);
    // The second request starts at the full batch's last header, at once
    // (mutation run E: with the batch taken for not full, only the
    // maintenance tick asked again, from our own tip).
    let heads = heads.lock().unwrap().clone();
    assert!(heads.len() >= 2, "{} requests", heads.len());
    assert_eq!(heads[1], theirs[1999].id(nid));
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

/// P2P-FIX2 item 2, the root cause of the PX stem test's load flake: a
/// peer slow to answer (or a node slow to read its answer) is not penalized.
/// A one-header tip announcement takes the outstanding `GetHeaders`; the
/// node, now "not waiting", asks again before the first reply arrives, so
/// two replies are in flight. Before, the second reply was an "unrequested
/// header batch" (+10): the node forgot the first request when it sent the
/// second. Under CPU load this hit node C of
/// `px_transactions_travel_the_stem_and_confirm_everywhere` while it synced
/// from B, which was itself syncing and announcing every new tip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headers_reply_overtaken_by_a_second_request_is_not_penalized() {
    init_test_log();
    let a = node(250, &[]).await;
    let nid = params().network_id;
    let branch = header_branch(30, 120, 0);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 30).await;
    let Some(Message::GetHeaders { locator: first, .. }) =
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. })).await
    else {
        panic!("no first GetHeaders");
    };
    // The announcement; the node asks again once it has taken it.
    w.send(&Message::Headers(vec![branch[0]]).encode())
        .await
        .unwrap();
    let Some(Message::GetHeaders {
        locator: second, ..
    }) = recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. })).await
    else {
        panic!("no second GetHeaders");
    };
    // Only now the two (delayed) replies, in order.
    for locator in [first, second] {
        w.send(&Message::Headers(serve_headers(&branch, &locator)).encode())
            .await
            .unwrap();
    }
    serve_branch(r, w, branch.clone());
    wait_until("synced", 10, || {
        a.chain.lock().unwrap().header_height() == 30
    })
    .await;
    let scored = penalized(&[&a]);
    assert!(scored.is_empty(), "penalized: {scored:?}");
    // A third multi-header batch answers nothing: still unrequested.
    let (mut r2, mut w2) = raw_peer_at(a.addr, nid, true, 0).await;
    let _ = recv_until(&mut r2, 1.0, |_| false).await;
    w2.send(&Message::Headers(branch[..3].to_vec()).encode())
        .await
        .unwrap();
    wait_until("the unrequested batch is scored", 5, || {
        penalized(&[&a]).iter().any(|(_, _, _, s)| *s == 10)
    })
    .await;
}

/// P2P-FIX2 item 2 (same class): the answer to a `GetTx` that timed out
/// (30 s) and moved on is accepted from the peer we asked, unpenalized, as a
/// late block is. Before, it was an "unrequested transaction" (+10) and
/// dropped: a node or link slow for 30 s got honest peers penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_transaction_answer_is_not_penalized() {
    init_test_log();
    let mut a = node(260, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    assert!(recv_until(
        &mut r,
        5.0,
        |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
    )
    .await
    .is_some());
    let asked = std::time::Instant::now();
    // A second announcer (mutation run E: the request moves to it once
    // TX_TIMEOUT has passed, not before and not never).
    let (mut ry, mut wy) = raw_peer(a.addr, nid, true).await;
    wy.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    wy.send(&Message::Ping(5).encode()).await.unwrap();
    assert!(recv_until(&mut ry, 5.0, |m| matches!(m, Message::Pong(5)))
        .await
        .is_some());
    assert!(
        recv_until(
            &mut ry,
            45.0,
            |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
        )
        .await
        .is_some(),
        "the second announcer was never asked"
    );
    let moved = asked.elapsed();
    assert!(
        moved >= Duration::from_secs(25),
        "asked the next announcer {moved:?} after the first"
    );
    // The first peer's answer, past the 30 s request timeout.
    w.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
    wait_until("the late transaction is pooled", 10, || a.mempool_has(&id)).await;
    let scored = penalized(&[&a]);
    assert!(scored.is_empty(), "penalized: {scored:?}");
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
    // A third announcer (mutation run E: the departing peer's cleanup must
    // keep the other announcers queued, not drop them).
    let (mut rz, mut wz) = raw_peer(a.addr, nid, true).await;
    wz.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    wz.send(&Message::Ping(4).encode()).await.unwrap();
    assert!(recv_until(&mut rz, 5.0, |m| matches!(m, Message::Pong(4)))
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
    drop((ry, wy));
    assert!(
        recv_until(
            &mut rz,
            3.0,
            |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
        )
        .await
        .is_some(),
        "the third announcer is asked when the second leaves"
    );
}

/// When the peer a block body was asked from disconnects, its requests are
/// dropped at once and the body is asked from another peer that has it, not
/// after the 60 s block timeout (mutation run E: the departing peer's block
/// requests had no test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_request_moves_on_when_its_peer_leaves() {
    let a = node(78, &[]).await;
    let nid = params().network_id;
    let h1 = header_branch(1, 120, 0)[0];
    let id = h1.id(nid);
    let wants = |m: &Message| matches!(m, Message::GetBlocks(ids) if ids.contains(&id));
    let (mut rx, mut wx) = raw_peer_at(a.addr, nid, true, 1).await;
    wx.send(&Message::Headers(vec![h1]).encode()).await.unwrap();
    assert!(recv_until(&mut rx, 10.0, wants).await.is_some(), "asked X");
    let (mut ry, mut wy) = raw_peer_at(a.addr, nid, true, 1).await;
    wy.send(&Message::Headers(vec![h1]).encode()).await.unwrap();
    wy.send(&Message::Ping(6).encode()).await.unwrap();
    assert!(recv_until(&mut ry, 5.0, |m| matches!(m, Message::Pong(6)))
        .await
        .is_some());
    drop((rx, wx));
    assert!(
        recv_until(&mut ry, 10.0, wants).await.is_some(),
        "the body is asked from Y once X has left"
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
    wait_until("registered", 30, || a.net.stats().peers == 2).await;
    let bad = BlockHeader {
        version: HEADER_VERSION,
        height: 1,
        prev_id: params().genesis_id(),
        timestamp: params().genesis.timestamp + 120,
        difficulty: 999_999,
        tx_root: [0; 32],
        nonce: 0,
        ..Default::default()
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
    wait_until("spy registered", 30, || a.net.stats().peers == 1).await;
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

/// Sends `msgs`, then a slow-lane barrier ([`lane_barrier`]), and waits for
/// its answer: every message before it has been handled.
async fn send_and_sync(r: &mut RawReader, w: &mut RawWriter, msgs: &[Vec<u8>], nonce: u64) {
    for m in msgs {
        w.send(m).await.unwrap();
    }
    let (barrier, answered) = lane_barrier(nonce);
    w.send(&barrier).await.unwrap();
    assert!(
        recv_until(r, 10.0, answered).await.is_some(),
        "barrier {nonce}"
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

/// Two transfers whose CLSAGs are each other's (valid signatures, wrong
/// message), the index of the input that fails, and the height of the
/// youngest member of that input's ring.
fn swapped_signatures(
    a: &TestNode,
    tx1: &Transaction,
    tx2: &Transaction,
) -> [(Transaction, u64); 2] {
    [(tx1, tx2), (tx2, tx1)].map(|(x, y)| {
        let mut bad = as_transfer(x);
        bad.signatures = as_transfer(y).signatures;
        let bad = Transaction::from(bad);
        let c = a.chain.lock().unwrap();
        let Err(MempoolError::Invalid(TxError::InvalidSignature { input })) = c.check_tx(&bad)
        else {
            panic!("a signature failure")
        };
        let ring = &as_transfer(&bad).inputs[input].ring;
        let youngest = ring
            .iter()
            .map(|&i| c.state().output(i).expect("a ring member").height)
            .max()
            .unwrap();
        (bad, youngest)
    })
}

/// RT-MUTD: a signature failure is penalized only once every member of the
/// failing input's ring is `SIGNATURE_BURIAL` (60) blocks below the tip, at
/// that exact depth; over a younger ring it is contextual (a reorganization
/// could have changed the members' outputs), so an honest relayer is never
/// penalized. Contextual failures are cached per tip, two at a time too.
/// Mutation run D's admission oracle had only the buried case.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signature_failures_over_young_rings_are_not_penalized_and_the_burial_is_exact() {
    let mut a = node(66, &[]).await;
    a.mine_n(80, 0);
    let tx1 = a.payment();
    let tx2 = a.payment();
    let [(bad1, young1), (bad2, young2)] = swapped_signatures(&a, &tx1, &tx2);
    let youngest = young1.max(young2);
    println!(
        "youngest ring members: {young1}, {young2}; tip {}",
        a.height()
    );
    assert!(
        youngest + 59 >= a.height(),
        "no ring member one block short of the burial depth (another seed)"
    );
    // One block short of the burial depth for the youngest ring.
    a.mine_n(youngest + 59 - a.height(), 0);
    assert_eq!(a.height(), youngest + 59);
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let msgs: Vec<Vec<u8>> = [&bad1, &bad2, &bad1]
        .iter()
        .map(|t| Message::StemTx(t.encode()).encode())
        .collect();
    send_and_sync(&mut r, &mut w, &msgs, 1).await;
    let st = a.net.stats();
    assert_eq!(a.net.peers()[0].score, 0, "a young ring: contextual");
    assert_eq!(
        st.tx_verifications, 2,
        "both cached at this tip: the first is not verified again"
    );
    drop((r, w));
    wait_until("the first peer is gone", 10, || a.net.peers().is_empty()).await;
    // At the burial depth of the youngest of both rings: proven invalid.
    a.mine(0);
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let youngest_bad = if young1 >= young2 { &bad1 } else { &bad2 };
    send_and_sync(
        &mut r,
        &mut w,
        &[Message::StemTx(youngest_bad.encode()).encode()],
        2,
    )
    .await;
    assert_eq!(
        a.net.peers()[0].score,
        score::INVALID_TX,
        "buried: penalized"
    );
}

/// The first height of the second epoch of [`UPGRADE_LATE`]: late enough
/// that ring members of the first 80 blocks are buried when the grace window
/// opens (at 150).
const UPGRADE_LATE_AT: u64 = 210;

static UPGRADE_LATE: [blacksilk_consensus::schedule::Epoch; 2] = [
    blacksilk_consensus::schedule::Epoch {
        name: "v3",
        activation_height: 0,
        header_version: 1,
        branch_id: blacksilk_consensus::schedule::BRANCH_ID_V3,
        verifier_id: blacksilk_consensus::schedule::VERIFIER_PX_1,
    },
    blacksilk_consensus::schedule::Epoch {
        name: "noop",
        activation_height: UPGRADE_LATE_AT,
        header_version: 1,
        branch_id: 0x4253_7634,
        verifier_id: blacksilk_consensus::schedule::VERIFIER_PX_1,
    },
];

/// RT-MUTD: within `ACTIVATION_GRACE_BLOCKS` of an activation, a signature
/// failure over a buried ring is contextual (a signature made for the
/// neighbouring branch id fails honestly), judged at the next block's
/// height: at the first height of the window it is not penalized, one block
/// earlier it is. Mutation run D's admission oracle had no activation for
/// signatures (`proven_invalid`'s `near`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn signature_failures_in_the_activation_grace_window_are_not_penalized() {
    use blacksilk_tx::validate::ACTIVATION_GRACE_BLOCKS;
    let mut a = upgrading_node_with(67, &UPGRADE_LATE).await;
    a.mine_n(80, 0);
    let tx1 = a.payment();
    let tx2 = a.payment();
    let [(bad1, young1), (bad2, young2)] = swapped_signatures(&a, &tx1, &tx2);
    let window = UPGRADE_LATE_AT - ACTIVATION_GRACE_BLOCKS;
    // The next block is the last one before the window; both rings buried.
    a.mine_n(window - 2 - a.height(), 0);
    assert!(young1.max(young2) + 60 <= a.height(), "buried rings");
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r,
        &mut w,
        &[Message::StemTx(bad1.encode()).encode()],
        1,
    )
    .await;
    assert_eq!(
        a.net.peers()[0].score,
        score::INVALID_TX,
        "outside the window"
    );
    drop((r, w));
    wait_until("the first peer is gone", 10, || a.net.peers().is_empty()).await;
    // The next block is the first one inside the window.
    a.mine(0);
    assert_eq!(a.height() + 1, window);
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r,
        &mut w,
        &[Message::StemTx(bad2.encode()).encode()],
        2,
    )
    .await;
    assert_eq!(a.net.peers()[0].score, 0, "inside the window: contextual");
    assert_eq!(a.net.stats().tx_verifications, 2);
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
    let (barrier, answered) = lane_barrier(2);
    w.send(&barrier).await.unwrap();
    let got = recv_until(&mut r, 5.0, |m| {
        matches!(m, Message::GetTx(_)) || answered(m)
    })
    .await;
    assert!(got.as_ref().is_some_and(&answered), "{got:?}");
    // A new tip: verified again.
    a.mine(0);
    send_and_sync(&mut r, &mut w, &[stem], 3).await;
    assert_eq!(a.net.stats().tx_verifications, 2);
    assert_eq!(a.net.peers()[0].score, 0, "contextual: never penalized");
}

/// tx review H1 (a): the signature budget is charged per v1 input before any
/// verification; a peer over it is rate-limited: its excess transactions
/// are not verified, and (RTW2A-4) not penalized either, a relayed stem
/// included.
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
    assert_eq!(a.net.peers()[0].score, 0, "a rate excess is not penalized");
}

/// A PX-only transaction with a random anchor: well formed but for its proof
/// bytes, which do not decode (the stateless `PxProof`, checked first since
/// RTW1-2); with a decodable proof it would fail PX1 (a cheap, contextual
/// check).
fn junk_anchor_px(k: u32) -> Transaction {
    let fee = px_standard_fee();
    Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
        inputs: vec![],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in: 0,
        bridge_out: fee,
        window: Default::default(),
        anchor: [k + 1, 7, 7, 7, 7, 7, 7, 7],
        nullifiers: [[k + 1, 1, 0, 0, 0, 0, 0, 0], [k + 1, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[0; 8]; 2],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
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
///
/// Since RTW1-2 the proof is decoded in the cheap stage, so these junk
/// transactions (their proof bytes do not decode) are rejected as the
/// stateless `PxProof` and their senders penalized; the budget stays intact
/// either way. The contextual path (a decodable proof over a random anchor)
/// needs a real proof and is not exercised here: a proof is decoded only
/// after the structure and balance rules, and PX1 comes before the token in
/// the same cheap stage.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn junk_anchor_px_floods_do_not_drain_the_px_relay_budget() {
    let a = node(63, &[]).await;
    let nid = params().network_id;
    let t = junk_anchor_px(0);
    let decoded = Transaction::decode(&t.encode()).expect("decodes");
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&decoded),
        Err(MempoolError::Invalid(TxError::PxProof))
    ));
    for peer in 0..6u32 {
        let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
        let msgs: Vec<Vec<u8>> = (0..4)
            .map(|i| Message::StemTx(junk_anchor_px(peer * 4 + i).encode()).encode())
            .collect();
        send_and_sync(&mut r, &mut w, &msgs, peer as u64).await;
        assert_eq!(
            a.net.peers().iter().map(|p| p.score).max(),
            Some(4 * score::INVALID_TX),
            "a garbage proof is penalized"
        );
        drop((r, w));
    }
    let st = a.net.stats();
    assert_eq!(st.px_global_drops, 0, "the node-wide PX budget is intact");
    assert_eq!(st.tx_verifications, 0, "rejected by the cheap checks");
}

/// RTW1C-4: a PX transaction whose window ends fewer than
/// `PX_EXPIRING_SOON_BLOCKS` blocks after the next block is refused in the
/// cheap stage before its proof is decoded (these junk proofs would be the
/// penalized `PxProof` otherwise) and before the node-wide PX token: never
/// scored, never verified, no token taken, and not looked at again at this
/// tip. The same transaction with an unbounded window is decoded (and
/// penalized for its proof), showing the refusal came first.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expiring_soon_px_transaction_is_refused_before_the_px_token() {
    use blacksilk_tx::validate::PX_EXPIRING_SOON_BLOCKS;
    let a = node(64, &[]).await;
    let nid = params().network_id;
    // The next block is 1: a window ending at 1 + 3 - 1 expires soon.
    let expiring = |k: u32| {
        let Transaction::Px(mut t) = junk_anchor_px(k) else {
            unreachable!()
        };
        t.window.not_after = PX_EXPIRING_SOON_BLOCKS;
        Transaction::Px(t)
    };
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&expiring(0)),
        Err(MempoolError::ExpiringSoon)
    ));
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    // Within the peer's PX share (burst 4); one sent twice.
    let msgs: Vec<Vec<u8>> = [0, 1, 2, 2]
        .iter()
        .map(|&k| Message::StemTx(expiring(k).encode()).encode())
        .collect();
    send_and_sync(&mut r, &mut w, &msgs, 1).await;
    let st = a.net.stats();
    assert_eq!(a.net.peers()[0].score, 0, "never scored");
    assert_eq!(st.px_global_taken, 0, "no node-wide PX token taken");
    assert_eq!(st.px_global_drops, 0);
    assert_eq!(st.tx_verifications, 0, "never verified");
    assert!(!a.net.stempool_contains(&expiring(0).hash()), "not stemmed");

    // Control: the same junk with an unbounded window reaches the proof
    // decoding and is penalized for it.
    let msgs = vec![Message::StemTx(junk_anchor_px(9).encode()).encode()];
    let (mut r2, mut w2) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r2, &mut w2, &msgs, 2).await;
    assert!(
        a.net.peers().iter().any(|p| p.score == score::INVALID_TX),
        "a decodable window reaches the proof check"
    );
    assert_eq!(a.net.stats().px_global_taken, 0);
}

/// The expiring-soon refusal (RTW1C-4) is judged at the next block's
/// height, above genesis too (mutation run D: with release arithmetic, a
/// check at the tip's height minus one wrapped at genesis and passed the
/// test above). At height 10, a window ending at 10 + 3 expires soon for
/// the next block (11) but not for block 9: refused unscored, never
/// decoded.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expiring_soon_px_transaction_is_judged_at_the_next_blocks_height() {
    use blacksilk_tx::validate::PX_EXPIRING_SOON_BLOCKS;
    let mut a = node(65, &[]).await;
    a.mine_n(10, 0);
    let nid = params().network_id;
    let Transaction::Px(mut t) = junk_anchor_px(0) else {
        unreachable!()
    };
    t.window.not_after = a.height() + PX_EXPIRING_SOON_BLOCKS;
    let tx = Transaction::Px(t);
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&tx),
        Err(MempoolError::ExpiringSoon)
    ));
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    assert_eq!(a.net.peers()[0].score, 0, "never scored");
    assert_eq!(a.net.stats().tx_verifications, 0);
    assert_eq!(a.net.stats().px_global_taken, 0);
}

/// RTW1-2 (red team RT-W1): a PX transaction that passes every cheap
/// contextual check (a real ring, an unspent key image, the current anchor,
/// fresh nullifiers, a covered pool) but carries a garbage CLSAG and a
/// garbage proof. Its proof is decoded in admission's cheap stage: it is
/// rejected as the stateless `PxProof`, the relaying peer is penalized, and
/// it is never verified, so it takes no node-wide PX token and costs no ring
/// lookup, range proof or CLSAG. Before the fix it passed the cheap stage,
/// took the node-wide token, was verified (rings and CLSAG), and failed with
/// a contextual error that is never penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_garbage_px_proof_is_penalized_before_the_px_token_and_any_signature() {
    let mut a = node(97, &[]).await;
    a.mine_n(80, 0);
    let Transaction::Transfer(pay) = a.payment() else {
        panic!("a transfer")
    };
    let root = a.chain.lock().unwrap().state().px().root();
    let fee = px_standard_fee();
    let bridge_in = 1_000 * fee;
    let tx = Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
        inputs: vec![pay.inputs[0].clone()],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in,
        bridge_out: 0,
        window: Default::default(),
        anchor: root,
        nullifiers: [[9, 1, 0, 0, 0, 0, 0, 0], [9, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[0; 8]; 2],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
        functions: vec![],
        pseudo_outs: vec![blacksilk_crypto::Point::from_point(
            blacksilk_crypto::commitment::commit(bridge_in + fee, &blacksilk_crypto::Scalar::ZERO),
        )],
        range_proof: None,
        // Another message's signature: garbage here.
        signatures: vec![pay.signatures[0].clone()],
        proof: vec![0xA5; 4096],
    }));
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 0, "rejected by the cheap stage");
    assert_eq!(st.px_global_drops, 0);
    assert_eq!(a.net.peers()[0].score, score::INVALID_TX, "penalized");
    assert!(!a.net.stempool_contains(&tx.hash()));
    // The full check agrees: the proof is the reported fault.
    assert!(matches!(
        a.chain.lock().unwrap().check_tx(&tx),
        Err(MempoolError::Invalid(TxError::PxProof))
    ));
}

/// The encoding of a proof with one empty instance per entry of `bits`
/// (nothing opened, no FRI rounds) and those degree bits: it decodes under
/// the PX limits, so its degree bits reach the shape check, but it verifies
/// nothing (tx/tests/px_proof_wiring.rs has the layout). Each count and
/// degree bit is below 128 (one varint byte).
fn hollow_proof(bits: &[u8]) -> Vec<u8> {
    let mut b = vec![1]; // `blacksilk_zk::PROOF_VERSION`
    b.push(1); // the main commitment: one root
    b.extend([0; 32]);
    b.push(0); // no permutation commitment
    b.push(1); // the quotient commitment
    b.extend([0; 32]);
    b.push(0); // no random commitment
    b.push(bits.len() as u8);
    for _ in bits {
        b.extend([0; 8]); // an instance with nothing opened
    }
    b.extend([2, 0, 0]); // the hidden openings: two rounds, no matrices
    b.extend([0; 5]); // FRI: commitments, witnesses, input batches, openings, final polynomial
    b.extend([0; 4]); // the query grinding witness
    b.push(0); // no lookup terminals
    b.push(bits.len() as u8);
    b.extend(bits);
    b
}

/// A transfer statement's degree bits (13 tables): the shape a decodable PX
/// proof needs to pass admission's cheap stage. Checked against the shape rule
/// where used; tx/tests/px_proof_wiring.rs derives them from the statement.
const TRANSFER_BITS: [u8; 13] = [17, 13, 13, 14, 16, 16, 12, 15, 12, 12, 9, 9, 9];

/// A PX transaction spending `pay`'s first input into the pool, carrying
/// `proof`, that passes every cheap contextual check; `k` makes its
/// nullifiers (and so its id) unique. Its CLSAG is another message's.
fn px_with_proof(
    a: &TestNode,
    pay: &blacksilk_tx::types::Transfer,
    k: u32,
    proof: Vec<u8>,
) -> Transaction {
    let root = a.chain.lock().unwrap().state().px().root();
    let fee = px_standard_fee();
    let bridge_in = 1_000 * fee;
    Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
        inputs: vec![pay.inputs[0].clone()],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in,
        bridge_out: 0,
        window: Default::default(),
        anchor: root,
        nullifiers: [[8, k, 1, 0, 0, 0, 0, 0], [8, k, 2, 0, 0, 0, 0, 0]],
        commitments: [[0; 8]; 2],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
        functions: vec![],
        pseudo_outs: vec![blacksilk_crypto::Point::from_point(
            blacksilk_crypto::commitment::commit(bridge_in + fee, &blacksilk_crypto::Scalar::ZERO),
        )],
        range_proof: None,
        signatures: vec![pay.signatures[0].clone()],
        proof,
    }))
}

/// A decodable proof of the right shape passes admission's cheap stage
/// (decoded off the actor, its degree bits shape-checked in the command):
/// it takes a node-wide PX token and is verified, where it fails. Past the
/// node-wide burst (10) and its refill since the first send, further ones
/// are dropped unverified and counted (mutation run D: before, only proving
/// tests reached the token).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_px_transaction_past_the_cheap_stage_takes_a_node_wide_token() {
    let mut a = node(99, &[]).await;
    a.mine_n(80, 0);
    let Transaction::Transfer(pay) = a.payment() else {
        panic!("a transfer")
    };
    let mut tx = px_with_proof(&a, &pay, 0, hollow_proof(&TRANSFER_BITS));
    // Valid from the next block on (PX6): the cheap stage checks the
    // contextual rules at the next block's height.
    if let Transaction::Px(t) = &mut tx {
        t.window.not_before = a.height() + 1;
    }
    {
        let Transaction::Px(t) = &tx else {
            unreachable!()
        };
        let c = a.chain.lock().unwrap();
        let rules = c.next_rules();
        let bits: Vec<usize> = TRANSFER_BITS.iter().map(|&b| b.into()).collect();
        assert_eq!(
            blacksilk_tx::validate::check_px_proof_shape_bits(t, c.state(), &rules, &bits),
            Ok(()),
            "a transfer's shape (re-derive TRANSFER_BITS if the kernel changed)"
        );
    }
    let nid = params().network_id;
    // The node-wide bucket holds at most its burst (10) now; it refills
    // at 2 per second from here on (its exact burst and rate:
    // admission.rs `the_node_wide_px_bucket_has_burst_10_and_rate_2`).
    let first_send = std::time::Instant::now();
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 1, "past the cheap stage");
    assert_eq!(st.px_global_taken, 1, "one node-wide PX token");
    assert_eq!(st.px_global_drops, 0);
    assert!(
        !a.net.stempool_contains(&tx.hash()),
        "its verification fails"
    );
    drop((r, w));
    // Six more peers, four each (their PX share): past the burst, dropped.
    for peer in 1..=6u32 {
        let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
        let msgs: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let t = px_with_proof(&a, &pay, peer * 4 + i, hollow_proof(&TRANSFER_BITS));
                Message::StemTx(t.encode()).encode()
            })
            .collect();
        send_and_sync(&mut r, &mut w, &msgs, 10 + u64::from(peer)).await;
        drop((r, w));
    }
    let st = a.net.stats();
    assert_eq!(st.px_global_taken + st.px_global_drops, 25);
    assert!(st.px_global_taken >= 10, "{st:?}");
    // At most the burst plus the refill since the first send were taken;
    // the rest were dropped. Within about 7.5 s that leaves at least one
    // drop; on a slower run the bound alone is checked (RT-MUTD).
    let refill = (2.0 * first_send.elapsed().as_secs_f64()).ceil() as u64;
    assert!(st.px_global_taken <= 10 + refill, "{st:?}, refill {refill}");
    assert!(
        st.px_global_drops >= 25u64.saturating_sub(10 + refill),
        "{st:?}"
    );
    assert_eq!(
        st.tx_verifications, st.px_global_taken,
        "the dropped are not verified"
    );
}

/// A peer that relays a transaction which passes verification is marked as
/// a recent transaction relayer (`PeerInfo::last_tx`, which inbound eviction
/// protects, docs/p2p.md §9); one whose transaction fails is not (mutation
/// run D, RT-MUTD: `note_new_tx` had no test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_relaying_a_valid_transaction_is_marked_as_a_recent_relayer() {
    let mut a = node(102, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let answered = a.payment_nth(1);
    let nid = params().network_id;
    let (mut r1, mut w1) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r1,
        &mut w1,
        &[Message::StemTx(junk_anchor_px(0).encode()).encode()],
        1,
    )
    .await;
    let (mut r2, mut w2) = raw_peer(a.addr, nid, true).await;
    send_and_sync(
        &mut r2,
        &mut w2,
        &[Message::StemTx(tx.encode()).encode()],
        2,
    )
    .await;
    let peers = a.net.peers();
    assert_eq!(peers.len(), 2);
    assert_eq!(
        a.net.stats().tx_verifications,
        1,
        "the valid one was verified"
    );
    let (marked, unmarked): (Vec<_>, Vec<_>) = peers.iter().partition(|p| p.last_tx.is_some());
    assert_eq!((marked.len(), unmarked.len()), (1, 1));
    assert_eq!(marked[0].score, 0, "the valid relayer");
    assert_eq!(unmarked[0].score, score::INVALID_TX, "the invalid relayer");
    // The `Tx` path: announced, requested, answered, verified once, and its
    // relayer marked too.
    let id = answered.hash();
    let (mut r3, mut w3) = raw_peer(a.addr, nid, true).await;
    w3.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    assert!(recv_until(
        &mut r3,
        5.0,
        |m| matches!(m, Message::GetTx(ids) if ids == &vec![id])
    )
    .await
    .is_some());
    w3.send(&Message::Tx(answered.encode()).encode())
        .await
        .unwrap();
    wait_until("the answered transaction is pooled", 10, || {
        a.mempool_has(&id)
    })
    .await;
    assert_eq!(a.net.stats().tx_verifications, 2, "verified on the Tx path");
    assert_eq!(
        a.net.peers().iter().filter(|p| p.last_tx.is_some()).count(),
        2,
        "both valid relayers marked"
    );
}

/// The first height of the second epoch of [`UPGRADE`], an upgrade that
/// changes only the branch id (as chain/tests/activation.rs's).
const UPGRADE_AT: u64 = 150;

static UPGRADE: [blacksilk_consensus::schedule::Epoch; 2] = [
    blacksilk_consensus::schedule::Epoch {
        name: "v3",
        activation_height: 0,
        header_version: 1,
        branch_id: blacksilk_consensus::schedule::BRANCH_ID_V3,
        verifier_id: blacksilk_consensus::schedule::VERIFIER_PX_1,
    },
    blacksilk_consensus::schedule::Epoch {
        name: "noop",
        activation_height: UPGRADE_AT,
        header_version: 1,
        branch_id: 0x4253_7634,
        verifier_id: blacksilk_consensus::schedule::VERIFIER_PX_1,
    },
];

/// A node whose chain activates [`UPGRADE`] at [`UPGRADE_AT`].
async fn upgrading_node(seed: u64) -> TestNode {
    upgrading_node_with(seed, &UPGRADE).await
}

/// A node whose chain follows `epochs`.
async fn upgrading_node_with(
    seed: u64,
    epochs: &'static [blacksilk_consensus::schedule::Epoch],
) -> TestNode {
    let mut p = params();
    p.schedule = blacksilk_consensus::schedule::Schedule::new(epochs);
    // `TxRules::for_chain` refuses a multi-epoch schedule: the first
    // epoch's rules, the others derived per height.
    let m = ChainManager::open(
        p.clone(),
        TxRules::at_height(&p, 0),
        Arc::new(ZeroPow),
        Box::<MemoryStore>::default(),
        [seed as u8; 32],
    )
    .unwrap();
    let chain: SharedChain = Arc::new(Mutex::new(m));
    let net = Network::start(fast_config(&[]), chain.clone())
        .await
        .unwrap();
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

/// Within `ACTIVATION_GRACE_BLOCKS` of an activation a `PxProof` failure is
/// contextual (an honest proof made for the neighbouring rule set fails
/// honestly, `TxError::is_stateless_at`), and admission's cheap stage judges
/// it at the next block's height (mutation run D: no p2p test had an
/// activation). A wrong-shape proof is penalized while the next block is
/// outside the window, and only refused (never verified) once it is inside.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_px_proof_failure_is_not_penalized_in_the_activation_grace_window() {
    use blacksilk_tx::validate::ACTIVATION_GRACE_BLOCKS;
    let mut a = upgrading_node(101).await;
    let first_near = UPGRADE_AT - ACTIVATION_GRACE_BLOCKS;
    // The next block is the last one before the window.
    a.mine_n(first_near - 2, 0);
    let Transaction::Transfer(pay) = a.payment() else {
        panic!("a transfer")
    };
    let nid = params().network_id;
    // Mining an empty block leaves the PX anchor as it is.
    let [first, second] = [0, 1].map(|k| {
        let t = px_with_proof(&a, &pay, k, hollow_proof(&[10]));
        vec![Message::StemTx(t.encode()).encode()]
    });
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &first, 1).await;
    assert_eq!(
        a.net.peers()[0].score,
        score::INVALID_TX,
        "outside the window: stateless, penalized"
    );
    drop((r, w));
    wait_until("the first peer is gone", 10, || a.net.peers().is_empty()).await;
    // The next block is the first one inside the window.
    a.mine(0);
    assert_eq!(a.height() + 1, first_near);
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &second, 2).await;
    assert_eq!(a.net.peers()[0].score, 0, "inside the window: contextual");
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 0, "both refused in the cheap stage");
    assert_eq!(st.px_global_taken, 0);
}

/// The off-actor decoding hands its degree bits to the shape check
/// (RT-PXDOS F1; mutation run D): a PX transaction that passes every cheap
/// contextual check, with a proof that decodes but has another statement's
/// shape (one table), is refused in admission's cheap stage as the stateless
/// `PxProof`, penalized, never verified, and takes no node-wide PX token.
/// Before, only proving tests sent a decodable proof to admission.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_decodable_proof_of_the_wrong_shape_is_penalized_in_the_cheap_stage() {
    let mut a = node(98, &[]).await;
    a.mine_n(80, 0);
    let Transaction::Transfer(pay) = a.payment() else {
        panic!("a transfer")
    };
    let root = a.chain.lock().unwrap().state().px().root();
    let fee = px_standard_fee();
    let bridge_in = 1_000 * fee;
    let tx = Transaction::Px(Box::new(blacksilk_tx::px::PxTx {
        inputs: vec![pay.inputs[0].clone()],
        outputs: vec![],
        payouts: vec![],
        fee,
        bridge_in,
        bridge_out: 0,
        window: Default::default(),
        anchor: root,
        nullifiers: [[8, 1, 0, 0, 0, 0, 0, 0], [8, 2, 0, 0, 0, 0, 0, 0]],
        commitments: [[0; 8]; 2],
        ciphertexts: [px_ciphertext(), px_ciphertext()],
        functions: vec![],
        pseudo_outs: vec![blacksilk_crypto::Point::from_point(
            blacksilk_crypto::commitment::commit(bridge_in + fee, &blacksilk_crypto::Scalar::ZERO),
        )],
        range_proof: None,
        signatures: vec![pay.signatures[0].clone()],
        proof: hollow_proof(&[10]),
    }));
    let Transaction::Px(t) = &tx else {
        unreachable!()
    };
    let decoded = blacksilk_tx::validate::decode_px_proof(t).expect("the proof decodes");
    assert_eq!(decoded.degree_bits, [10]);
    {
        let c = a.chain.lock().unwrap();
        let rules = c.next_rules();
        assert_eq!(
            blacksilk_tx::validate::check_px_proof_shape_bits(t, c.state(), &rules, &[10]),
            Err(TxError::PxProof),
            "the shape check is what refuses it"
        );
        assert_eq!(
            blacksilk_tx::validate::revalidate_after_extension(&tx, c.state(), c.height() + 1),
            Ok(()),
            "every cheap contextual check passes"
        );
    }
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    let st = a.net.stats();
    assert_eq!(st.tx_verifications, 0, "refused by the cheap stage");
    assert_eq!(st.px_global_taken, 0, "no node-wide PX token");
    assert_eq!(a.net.peers()[0].score, score::INVALID_TX, "penalized");
    assert!(!a.net.stempool_contains(&tx.hash()));
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
    let onion = "2gzyxa5ihm7nsggfxnu52rck2vv4rvmdlkiu3zzui5du4xyclen53wid.onion:9999";
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
/// another thread holds it (as a long block connection or reorg
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

    // Held until released (before INV-PEN: for 3 s, and the test asserted
    // afterwards that the hold had outlasted its pings, which a loaded
    // machine need not do).
    let held = HeldChain::hold(&a).await;
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
    held.release().await;
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
/// Another peer's pings are answered promptly throughout, the chain actor
/// publishes intermediate heights (it connects the batch in steps and
/// publishes after each: the snapshot of every step, from the actor's
/// test-only log), and the node ends on the same tip without penalizing
/// anyone. Coinbase-only blocks connect fast (the drain takes a fraction of
/// a second here), so the step check, not the pong latency, is what fails if
/// the batch is connected in one step. (Before Stage 2 the observer took the
/// chain mutex between steps; the actor re-takes its private lock at once,
/// so the snapshot is the observable now. Before INV-PEN a thread polled the
/// snapshot every 200 us: on a loaded machine it was not scheduled during
/// the whole drain and saw only {0, 120}.)
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

    let (b, handle) = node_with_actor_handle(92, fast_config(&[]), ActorConfig::default()).await;
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
    // Every height the chain actor published, in order: the snapshot after
    // each command and each drain step (one step for the whole batch would
    // show only 0 and 120).
    let seen: std::collections::BTreeSet<u64> = handle
        .log_for_tests()
        .iter()
        .map(|e| match e {
            actor::LogEntry::Run { snapshot, .. }
            | actor::LogEntry::Submit { snapshot, .. }
            | actor::LogEntry::Step { snapshot, .. } => snapshot.height,
        })
        .collect();
    println!("heights published by the chain actor: {seen:?}");
    // Every step connects exactly `SYNC_STEP_BLOCKS` (8) blocks here.
    let between: Vec<u64> = seen.iter().copied().filter(|&h| h > 0 && h < N).collect();
    assert!(
        !between.is_empty() && between.iter().all(|h| h % 8 == 0),
        "the batch connected in steps of 8 blocks: {seen:?}"
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
        tip: params().genesis_id(),
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
    wait_until("registered", 30, || a.net.peers().len() == 1).await;
    let p = &a.net.peers()[0];
    assert_eq!((p.protocol, p.score), (PROTOCOL_VERSION + 1, 0));
}

/// Between `Version` and `Verack` at most 8 frames of unknown types are
/// skipped (`HANDSHAKE_UNKNOWN_FRAMES`, docs/p2p.md §4): with 8 the
/// handshake completes; a 9th closes the connection unregistered (mutation
/// run E: the bound had no test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn at_most_eight_unknown_frames_are_skipped_in_the_handshake() {
    let a = node(97, &[]).await;
    let nid = params().network_id;
    let mut kept = Vec::new();
    for (unknown, registered) in [(8u8, true), (9, false)] {
        let s = TcpStream::connect(a.addr).await.unwrap();
        let (mut r, mut w) =
            handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
                .await
                .unwrap();
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: nid,
            nonce: 0x5678 + u64::from(unknown),
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
        // The node may close at the 9th frame, before our later writes
        // reach it (a reset on Windows): those writes may fail.
        for k in 0..unknown {
            let sent = w.send(&[0x30, k]).await;
            assert!(sent.is_ok() || !registered, "{sent:?}");
        }
        let sent = w.send(&Message::Verack.encode()).await;
        assert!(sent.is_ok() || !registered, "{sent:?}");
        if registered {
            assert!(matches!(
                Message::decode(&r.recv().await.unwrap()).unwrap(),
                Message::Verack
            ));
            send_and_sync(&mut r, &mut w, &[], 7).await;
            wait_until("registered", 5, || a.net.peers().len() == 1).await;
            kept.push((r, w));
        } else {
            assert!(closes_within(&mut r, 10).await, "{unknown} unknown frames");
            assert_eq!(a.net.peers().len(), 1, "not registered");
        }
    }
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
        ..Default::default()
    };
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
    let honest = deep(HEADER_VERSION, params().initial_difficulty);
    let known_low = headers_and_settle(&a, &pow, &mut r, &mut w, vec![honest], 1).await;
    let claimed = deep(HEADER_VERSION + 6, u64::MAX);
    let unknown_max = headers_and_settle(&a, &pow, &mut r, &mut w, vec![claimed], 2).await;
    assert_eq!(known_low, 0);
    assert_eq!(unknown_max, 0, "the claimed difficulty bought a hash");
    assert_eq!(a.net.peers()[0].score, 0);
    assert!(!a.net.upgrade_warned());
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
            ..Default::default()
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

/// RTW1-1: one outbound reporter warns at once when its unknown-version
/// header, charged the difficulty this node requires, brings its branch to
/// our best chain's work (on our tip); on a lighter fork it does not
/// (mutation run E: `UpgradeWork::of`'s sum had no test).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_outbound_reporter_on_our_best_work_warns_at_once() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(64, fast_config(&[]), pow.clone()).await;
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
            ..Default::default()
        }
    };
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut r, mut w) = dialed_raw_peer(&a, &l).await;
    let fork = g.main_id_at(295).unwrap();
    let cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(fork, 50)], 1).await;
    assert_eq!(cost, 1, "hashed");
    assert!(!a.net.upgrade_warned(), "one reporter on a lighter fork");
    let cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(g.tip_id(), 51)], 2).await;
    assert_eq!(cost, 1, "hashed");
    assert!(a.net.upgrade_warned(), "our best chain's work: at once");
}

/// RTW1-1: the two upgrade-warning thresholds are inclusive (the boundary
/// pass of mutation run E). A branch reaching exactly the anti-DoS threshold
/// (a sibling of our block 156, 144 below the tip) counts toward the warning:
/// two such outbound reporters warn. A branch reaching exactly our best work
/// (a sibling of our tip) warns at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_upgrade_warning_thresholds_are_inclusive() {
    let ours = header_branch(300, 1, 0);
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
            ..Default::default()
        }
    };
    let at = |h: u64| g.main_id_at(h).unwrap();
    assert_eq!(
        blacksilk_chain::sync_policy::anti_dos_threshold(&g),
        g.work(&at(156)).unwrap()
    );
    // At the anti-DoS threshold: two distinct outbound reporters warn.
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(72, fast_config(&[]), pow.clone()).await;
    give_headers(&a, &ours);
    // The reporters stay connected: `dialed_raw_peer` counts outbound peers,
    // and a dropped first one leaving during the second dial hid the second.
    let mut kept = Vec::new();
    for (k, nonce) in [60u64, 61].into_iter().enumerate() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (mut r, mut w) = dialed_raw_peer(&a, &l).await;
        let cost =
            headers_and_settle(&a, &pow, &mut r, &mut w, vec![newer(at(155), nonce)], 1).await;
        assert_eq!(cost, 1, "hashed");
        assert_eq!(a.net.upgrade_warned(), k == 1, "after {} reporters", k + 1);
        kept.push((r, w, l));
    }
    // At our best work: one reporter warns at once.
    let pow = Arc::new(CountAllPow::default());
    let b = node_with_pow(73, fast_config(&[]), pow.clone()).await;
    give_headers(&b, &ours);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut r, mut w) = dialed_raw_peer(&b, &l).await;
    let cost = headers_and_settle(&b, &pow, &mut r, &mut w, vec![newer(at(299), 62)], 1).await;
    assert_eq!(cost, 1, "hashed");
    assert!(b.net.upgrade_warned(), "equal to our best work: at once");
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
            ..Default::default()
        }
    };
    let old = newer(g.main_id_at(2099).unwrap());
    assert_eq!(key(old.height), 0, "the previous epoch's key");
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 30, || a.net.stats().peers == 1).await;
    let old_cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![old], 1).await;
    let tip = newer(g.tip_id());
    let tip_cost = headers_and_settle(&a, &pow, &mut r, &mut w, vec![tip], 2).await;
    assert_eq!(old_cost, 0, "an old-epoch key was hashed");
    assert_eq!(tip_cost, 1, "the current key is hashed");
    assert_eq!(a.net.peers()[0].score, 0);
}

/// An unknown-version header whose RandomX key is the first header of its
/// own batch (a stored one: the batch repeats our blocks from the key block
/// 2 048 on) is keyed by that header, a live key, and hashed (mutation run
/// E: no test had the key inside the batch, `batch_seed`'s first branch).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unknown_version_header_keyed_by_its_own_batch_is_hashed() {
    let pow = Arc::new(CountAllPow::default());
    let a = node_with_pow(65, fast_config(&[]), pow.clone()).await;
    let nid = params().network_id;
    let ours = header_branch(2112, 1, 0);
    give_headers(&a, &ours);
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &ours {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let p = params();
    assert_eq!(seed_height(2113, p.seed_epoch, p.seed_lag), 2048);
    let t = g.template();
    let tip = g.header(&t.prev_id).unwrap();
    let newer = BlockHeader {
        version: HEADER_VERSION + 6,
        height: t.height,
        prev_id: t.prev_id,
        timestamp: t.min_timestamp.max(tip.timestamp + 1),
        difficulty: t.difficulty,
        tx_root: [0; 32],
        nonce: 5,
        ..Default::default()
    };
    let mut batch = ours[2047..].to_vec();
    assert_eq!(batch[0].height, 2048);
    batch.push(newer);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 3_000).await;
    assert!(
        recv_until(&mut r, 10.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    let before = pow.0.load(std::sync::atomic::Ordering::SeqCst);
    w.send(&Message::Headers(batch).encode()).await.unwrap();
    w.send(&Message::Ping(9).encode()).await.unwrap();
    assert!(recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(9)))
        .await
        .is_some());
    wait_until("header batch verified", 10, || {
        a.net.header_queue_len() == 0
    })
    .await;
    let cost = pow.0.load(std::sync::atomic::Ordering::SeqCst) - before;
    assert_eq!(
        cost, 1,
        "the unknown-version header is hashed under the live key"
    );
    assert_eq!(a.net.peers()[0].score, 0);
    // Nothing past it is usable: its claimed height (3 000) is lowered to
    // ours, so it is not asked again every tick.
    assert_eq!(a.net.peers()[0].height, 2112);
}

/// An unsolicited low-work header leaves the sender's claimed height alone
/// (only a solicited low-work reply lowers it): the peer may still hold a
/// heavier chain than the one it announced (mutation run E: the guard had no
/// test). The maintenance tick is a minute, so nothing asks it in between.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unsolicited_low_work_header_keeps_the_peers_claimed_height() {
    let pow = Arc::new(CountAllPow::default());
    let mut cfg = fast_config(&[]);
    cfg.tick = Duration::from_secs(60);
    let a = node_with_pow(66, cfg, pow.clone()).await;
    let nid = params().network_id;
    let ours = header_branch(300, 1, 0);
    give_headers(&a, &ours[..290]);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 400).await;
    assert!(
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    // The reply advances our chain: the peer's claim stands.
    w.send(&Message::Headers(ours[290..].to_vec()).encode())
        .await
        .unwrap();
    wait_until("the reply is stored", 10, || {
        a.chain.lock().unwrap().header_height() == 300
    })
    .await;
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    assert_eq!(a.net.peers()[0].height, 400);
    // An unsolicited header of a deep, low-work fork.
    let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
    for h in &ours {
        g.accept(*h, u64::MAX / 2).unwrap();
    }
    let parent = g.main_id_at(10).unwrap();
    let t = g.template_on(parent).unwrap();
    let fork = BlockHeader {
        version: HEADER_VERSION,
        height: t.height,
        prev_id: parent,
        timestamp: t
            .min_timestamp
            .max(g.header(&parent).unwrap().timestamp + 1),
        difficulty: t.difficulty,
        tx_root: [0; 32],
        nonce: 77,
        ..Default::default()
    };
    let before = pow.0.load(std::sync::atomic::Ordering::SeqCst);
    w.send(&Message::Headers(vec![fork]).encode())
        .await
        .unwrap();
    w.send(&Message::Ping(3).encode()).await.unwrap();
    assert!(recv_until(&mut r, 5.0, |m| matches!(m, Message::Pong(3)))
        .await
        .is_some());
    wait_until("worker done", 10, || a.net.header_queue_len() == 0).await;
    assert_eq!(
        pow.0.load(std::sync::atomic::Ordering::SeqCst),
        before,
        "low work: not hashed"
    );
    assert_eq!(a.net.peers()[0].height, 400, "the claim stands");
    assert_eq!(a.net.peers()[0].score, 0);
}

/// A panic in the header worker's proof-of-work jobs (off the chain actor)
/// stops the node as a panic in the actor does: exit status
/// `POISONED_EXIT_CODE` with the reason on stderr, never a worker that ends
/// silently while the node runs on (mutation run E: no test reached the
/// arm). The scenario runs in a child process (this test, re-run with an
/// environment variable), which exits 0 if it is still running after 20 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_panic_in_the_header_pow_jobs_stops_the_node() {
    const CHILD: &str = "BLACKSILK_TEST_PANIC_POW_CHILD";
    if std::env::var_os(CHILD).is_some() {
        struct PanicPow;
        impl PowFunction for PanicPow {
            fn pow_hash(&self, _: &Hash, _: &blacksilk_consensus::PowBlob) -> Hash {
                panic!("injected PoW panic");
            }
        }
        let a = node_with_pow(67, fast_config(&[]), Arc::new(PanicPow)).await;
        let (mut r, mut w) = raw_peer_at(a.addr, params().network_id, true, 10).await;
        assert!(
            recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
                .await
                .is_some()
        );
        w.send(&Message::Headers(header_branch(3, 120, 0)).encode())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(20)).await;
        std::process::exit(0);
    }
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "a_panic_in_the_header_pow_jobs_stops_the_node",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(blacksilk_p2p::POISONED_EXIT_CODE),
        "{stderr}"
    );
    assert!(stderr.contains("header task failed"), "{stderr}");
}

/// The key exchange's own timeout: 5 s on clearnet, 10 s over Tor (an
/// inbound loopback connection while no onion listener is configured and
/// private addresses are not allowed is taken for our hidden service). A
/// connection that sends nothing is closed after it: before 9 s on
/// clearnet, after 7.5 s over Tor (mutation run E: no test told the two
/// apart).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_connection_waits_five_seconds_on_clearnet_and_ten_over_tor() {
    use tokio::io::AsyncReadExt;
    async fn closed_after(addr: SocketAddr) -> Duration {
        let mut s = TcpStream::connect(addr).await.unwrap();
        let t = std::time::Instant::now();
        let mut buf = [0u8; 64];
        // The node writes its key-exchange message first; read until EOF.
        loop {
            match tokio::time::timeout(Duration::from_secs(30), s.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) => return t.elapsed(),
                Ok(Ok(_)) => continue,
                Err(_) => panic!("not closed within 30 s"),
            }
        }
    }
    let clearnet = node_with(74, fast_config(&[])).await;
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    let tor = node_with(75, cfg).await;
    let (c, t) = tokio::join!(closed_after(clearnet.addr), closed_after(tor.addr));
    // A timeout never fires early, so the lower bounds are exact (within the
    // time to connect); load only delays the observed close, so the upper
    // bound has a margin (a loaded run saw the clearnet close late).
    assert!(
        c >= Duration::from_millis(4_900) && c < Duration::from_millis(9_000),
        "clearnet: closed after {c:?}"
    );
    assert!(
        t >= Duration::from_millis(9_900),
        "over Tor: closed after {t:?}"
    );
}

/// Our address is advertised at the handshake only on connections that
/// relay addresses: not to an inbound peer that asked for no transaction
/// relay (a block-relay-only connection of its own; mutation run E: the
/// inbound side of the rule had no test). The advertisement is queued
/// before the answer to a ping sent after `Verack`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn our_address_is_advertised_only_where_addresses_are_relayed() {
    let mut cfg = fast_config(&[]);
    cfg.public_address = Some(NetAddr::parse("8.8.4.4:9999").unwrap());
    let a = node_with(76, cfg).await;
    let nid = params().network_id;
    for (relay_txs, advertised) in [(true, true), (false, false)] {
        let (mut r, mut w) = raw_peer(a.addr, nid, relay_txs).await;
        w.send(&Message::Ping(3).encode()).await.unwrap();
        let mut got = false;
        loop {
            match recv_until(&mut r, 10.0, |_| true).await.expect("a message") {
                Message::Addr(entries) => {
                    let ours = NetAddr::parse("8.8.4.4:9999").unwrap();
                    got |= entries.iter().any(|e| {
                        matches!(&e.addr, blacksilk_p2p::addr::EntryAddr::Known(x) if *x == ours)
                    })
                }
                Message::Pong(3) => break,
                _ => {}
            }
        }
        assert_eq!(got, advertised, "relay_txs {relay_txs}");
    }
}

/// A ban that comes in during a connection's handshake refuses the
/// connection at registration (the inbound limits are re-checked there,
/// under the lock of the insertion; mutation run E: no test banned an IP
/// mid-handshake). Without `allow_private`, loopback peers are IP-banned:
/// one registered peer breaks the protocol while a second connection from
/// the same IP waits before its `Verack`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_ban_during_the_handshake_refuses_the_connection_at_registration() {
    let mut cfg = fast_config(&[]);
    cfg.allow_private = false;
    let a = node_with(77, cfg).await;
    let nid = params().network_id;
    let (_rx, mut wx) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 10, || a.net.stats().peers == 1).await;
    // The second connection, up to the node's Verack.
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: 0x9abc,
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
    assert!(matches!(
        Message::decode(&r.recv().await.unwrap()).unwrap(),
        Message::Verack
    ));
    // The registered peer sends a malformed message: its IP is banned.
    wx.send(&[0x01, 0xff, 0xff]).await.unwrap();
    wait_until("banned", 10, || a.net.stats().banned == 1).await;
    wait_until("the first peer is gone", 10, || a.net.stats().peers == 0).await;
    // Its Verack completes the handshake; the registration refuses it.
    w.send(&Message::Verack.encode()).await.unwrap();
    assert!(closes_within(&mut r, 10).await, "refused at registration");
    assert_eq!(a.net.stats().peers, 0);
}

/// RTW1B-1: the recently-expired guard applies to local origination only.
/// A node that expired a transaction refuses it from its own wallet (`/tx`,
/// `Network::submit_tx`) for `RECENTLY_EXPIRED_BLOCKS`, but a peer stemming
/// it (the origin, whose own guard ended earlier because it admitted the
/// transaction earlier) is served like any valid transaction: the node
/// stems or fluffs it instead of dropping it, so the stem is no black hole
/// that makes the origin fluff its own transaction after the embargo.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_recently_expired_transaction_is_stemmed_for_a_peer_but_not_originated() {
    use blacksilk_chain::mempool::MEMPOOL_EXPIRY_BLOCKS;
    let mut b = node(72, &[]).await;
    b.mine_n(80, 0);
    let tx = b.payment();
    let id = tx.hash();
    // Pooled from a peer at next height 81, then expired 2 160 blocks later
    // (empty blocks: the transaction is never mined).
    b.chain.lock().unwrap().submit_tx(tx.clone()).unwrap();
    while b.height() + 1 < 81 + MEMPOOL_EXPIRY_BLOCKS {
        b.mine_with(0, false);
    }
    assert!(!b.mempool_has(&id), "expired");
    let next = b.height() + 1;
    assert!(b
        .chain
        .lock()
        .unwrap()
        .mempool()
        .recently_expired(&id, next));
    // Its own wallet cannot originate it again inside the window.
    let refused = b.net.submit_tx(tx.clone()).await.unwrap_err();
    assert!(refused.contains("Expired"), "{refused}");
    assert!(!b.net.stempool_contains(&id) && !b.mempool_has(&id));
    // A peer stems it: served, not dropped, and the peer is not penalized.
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(b.addr, nid, true).await;
    wait_until("peer registered", 30, || b.net.stats().peers == 1).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    wait_until("the stem peer relays it", 10, || {
        b.net.stempool_contains(&id) || b.mempool_has(&id)
    })
    .await;
    assert_eq!(b.net.peers()[0].score, 0);
}

// ------------------------- originated set and pool re-announcement (33 W2)

/// Whether a message is an announcement or a stem transaction (what an
/// origination shows a peer).
fn originates(m: &Message) -> bool {
    matches!(m, Message::StemTx(_) | Message::InvTx(_))
}

/// A node (data directory `dir`, 80 blocks) that originated one payment
/// through a raw stem peer and pooled it once its embargo fired, at next
/// height 81. Returns the node and the transaction.
async fn origin_with_a_pooled_payment(seed: u64, dir: &std::path::Path) -> (TestNode, Transaction) {
    let mut cfg = fast_config(&[]);
    cfg.data_dir = Some(dir.to_path_buf());
    let mut a = node_with(seed, cfg).await;
    a.mine_n(80, 0);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem, _w) = dialed_raw_peer(&a, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx.clone()).await.unwrap();
    assert!(
        recv_until(&mut stem, 5.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "originated into the stem"
    );
    // The raw stem peer relays nothing: the origin's embargo fluffs it.
    wait_until("pooled after the embargo", 15, || a.mempool_has(&id)).await;
    (a, tx)
}

/// Dossier 33 F33-1, W2 (privacy suite b): an origin restarted while the
/// network still pools its transaction (its own pool is empty after the
/// restart) does not originate it again when its wallet resubmits it: no
/// `StemTx` to its stem peer and no `InvTx` to anyone. The transaction is
/// held (pooled here without an announcement) and `/tx` accepts it. Before
/// the originated set the restarted node stemmed it to a peer that still
/// pooled it: an honest relay never stems a long-fluffed transaction, so the
/// peer learned the origin.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_origin_does_not_reoriginate_a_transaction_the_network_holds() {
    let dir = temp_data_dir("orig-held");
    let (a, tx) = origin_with_a_pooled_payment(80, &dir).await;
    let id = tx.hash();
    let (b, b_dir) = restarted(&a, &dir, 81).await;
    assert!(!b.mempool_has(&id), "the pool is not persisted");
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem, _w) = dialed_raw_peer(&b, &l).await;
    let nid = params().network_id;
    let (mut spy, _spy_w) = raw_peer(b.addr, nid, true).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    assert_eq!(b.net.submit_tx(tx.clone()).await, Ok(id), "accepted: held");
    assert!(
        recv_until(&mut stem, 5.0, originates).await.is_none(),
        "not re-originated to the stem peer"
    );
    assert!(
        recv_until(&mut spy, 1.0, originates).await.is_none(),
        "not announced"
    );
    assert!(!b.net.stempool_contains(&id));
    assert!(!b.mempool_has(&id), "held: accepted, but not pooled either");
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

/// Dossier 33 W2, FX-RTW1B follow-up (privacy suite a): a transaction the
/// origin expired from its pool is not originated again before
/// `relayed + MEMPOOL_EXPIRY_BLOCKS + RECENTLY_EXPIRED_BLOCKS`, also after a
/// restart inside the recently-expired window (the in-memory guard is gone
/// then; the originated set is persisted). After the window it is
/// originated once, through the stem.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_expired_local_transaction_is_not_reoriginated_inside_the_window_even_after_a_restart() {
    use blacksilk_chain::mempool::{MEMPOOL_EXPIRY_BLOCKS, RECENTLY_EXPIRED_BLOCKS};
    let dir = temp_data_dir("orig-expired");
    let (mut a, tx) = origin_with_a_pooled_payment(82, &dir).await;
    let id = tx.hash();
    while a.height() + 1 < 81 + MEMPOOL_EXPIRY_BLOCKS {
        a.mine_with(0, false);
    }
    assert!(!a.mempool_has(&id), "expired");
    let r = a.net.submit_tx(tx.clone()).await;
    assert!(matches!(&r, Err(e) if e.contains("Expired")), "{r:?}");
    let (mut b, b_dir) = restarted(&a, &dir, 83).await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem, _w) = dialed_raw_peer(&b, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let r = b.net.submit_tx(tx.clone()).await;
    assert!(
        matches!(&r, Err(e) if e.contains("Expired")),
        "refused inside the window after a restart: {r:?}"
    );
    assert!(
        recv_until(&mut stem, 5.0, originates).await.is_none(),
        "not re-originated inside the window"
    );
    while b.height() + 1 < 81 + MEMPOOL_EXPIRY_BLOCKS + RECENTLY_EXPIRED_BLOCKS - 1 {
        b.mine_with(0, false);
    }
    let r = b.net.submit_tx(tx.clone()).await;
    assert!(
        matches!(&r, Err(e) if e.contains("Expired")),
        "the window's last block: {r:?}"
    );
    b.mine_with(0, false);
    // Past the window the network has dropped it: originated once, as new.
    assert_eq!(b.net.submit_tx(tx.clone()).await, Ok(id));
    assert!(
        recv_until(&mut stem, 5.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "originated after the window"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

/// Dossier 33 W2 with RTW1B-1 (privacy suite d): the originated set applies
/// to local origination only. A peer stemming a transaction this node
/// originated (and holds back after a restart) is served like any valid
/// stem: the node relays it, and the peer is not penalized.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peers_stem_of_a_transaction_this_node_originated_is_relayed() {
    let dir = temp_data_dir("orig-peer");
    let (a, tx) = origin_with_a_pooled_payment(84, &dir).await;
    let id = tx.hash();
    let (b, b_dir) = restarted(&a, &dir, 85).await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem, _w) = dialed_raw_peer(&b, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(b.addr, nid, true).await;
    send_and_sync(&mut r, &mut w, &[Message::StemTx(tx.encode()).encode()], 1).await;
    assert!(
        recv_until(&mut stem, 5.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "relayed along the stem"
    );
    assert!(b.net.stempool_contains(&id) || b.mempool_has(&id));
    assert!(b.net.peers().iter().all(|p| p.score == 0));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

/// Dossier 38 §3.4 item 3 (W4n, pool re-announcement): every node
/// re-announces a pooled transaction that is still in its block template on
/// one fixed schedule of pool ages (10, 20, 40 … blocks), so a peer that
/// lost it (a restart) gets it back without its origin doing anything the
/// other nodes do not do. Only `InvTx`, never a `StemTx`; not before age 10,
/// and once per peer and schedule point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pooled_transactions_are_reannounced_on_the_common_schedule() {
    let mut a = node(86, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let id = tx.hash();
    // Pooled from a peer at next height 81 (never announced by this node).
    a.chain.lock().unwrap().submit_tx(tx).unwrap();
    let nid = params().network_id;
    let (mut spy, _w) = raw_peer(a.addr, nid, true).await;
    wait_until("spy registered", 30, || a.net.stats().peers == 1).await;
    for _ in 0..9 {
        a.mine_with(0, false);
    }
    // Age 9 (next height 90): not yet.
    assert!(
        recv_until(&mut spy, 1.5, originates).await.is_none(),
        "not before age 10"
    );
    a.mine_with(0, false);
    let got = recv_until(&mut spy, 5.0, originates).await;
    assert!(
        matches!(&got, Some(Message::InvTx(ids)) if ids == &vec![id]),
        "re-announced at age 10: {got:?}"
    );
    a.mine_with(0, false);
    assert!(
        recv_until(&mut spy, 1.5, originates).await.is_none(),
        "not again at age 11"
    );
}

// The TM2-P1 origin re-announcement tests (block during the stem,
// reorganization, restart) live in the privacy regression suite,
// `privacy.rs`, with the helpers they use in `net_support`.

/// TM2-17 (threat model round 2, network lens D4): a `GetTx` for more
/// transactions than a peer's control outbox holds (64 frames) is served in
/// full, and the requester stays connected. An honest node requests every
/// unknown id of one `InvTx` (up to 500) in one `GetTx` (`on_inv_tx`), and
/// a node announces a burst of transactions in one `InvTx` (a
/// re-announcement, a reconnect, a spam wave). The server queued one `Tx`
/// per id in a tight loop, and the first that found the outbox full
/// disconnected the requester as a slow reader: honest peers dropped each
/// other during a transaction burst. On a144d94 this test's requester was
/// disconnected after about 64 answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_gettx_for_more_transactions_than_an_outbox_is_served_in_full() {
    const N: usize = 100;
    let mut a = node(91, &[]).await;
    a.mine_n(N as u64 + 60, 0);
    let txs: Vec<Transaction> = (0..N).map(|n| a.payment_nth(n)).collect();
    {
        let mut c = a.chain.lock().unwrap();
        for t in &txs {
            c.submit_tx(t.clone()).unwrap();
        }
    }
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("requester registered", 30, || a.net.stats().peers == 1).await;
    // The pool's re-announcement at age 10 announces them all to the
    // requester (an announcement is what makes a transaction servable),
    // once the maintenance loop has seen the pool height (see
    // `a_repeated_id_in_one_gettx_is_answered_once`).
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        a.mine_with(0, false);
    }
    let mut announced = std::collections::HashSet::new();
    tokio::time::timeout(Duration::from_secs(10), async {
        while announced.len() < N {
            let m = Message::decode(&r.recv().await.unwrap()).unwrap();
            if let Message::InvTx(ids) = m {
                announced.extend(ids);
            }
        }
    })
    .await
    .expect("every transaction announced");
    // One request for all of them, as an honest node asks for one
    // announcement's ids.
    let ids: Vec<Hash> = announced.into_iter().collect();
    w.send(&Message::GetTx(ids.clone()).encode()).await.unwrap();
    // A requester that is slow to start reading is waited for.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut got = std::collections::HashSet::new();
    let served = tokio::time::timeout(Duration::from_secs(20), async {
        while got.len() < N {
            let Ok(frame) = r.recv().await else {
                return false; // disconnected
            };
            if let Ok(Message::Tx(bytes)) = Message::decode(&frame) {
                got.insert(Transaction::decode(&bytes).unwrap().hash());
            }
        }
        true
    })
    .await;
    assert_eq!(
        served,
        Ok(true),
        "served in full, not disconnected ({} of {N} received, {} slow disconnects)",
        got.len(),
        a.net.stats().slow_disconnects
    );
    assert!(ids.iter().all(|id| got.contains(id)));
    assert_eq!(a.net.stats().slow_disconnects, 0);
    assert_eq!(a.net.stats().peers, 1, "still connected");
    assert_eq!(a.net.peers()[0].score, 0);
}

/// TM2-17: an id named many times in one `GetTx` is answered once. A
/// requester could otherwise make the node encode and queue one large
/// transaction up to 500 times for a 16 KiB request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_repeated_id_in_one_gettx_is_answered_once() {
    let mut a = node(97, &[]).await;
    a.mine_n(80, 0);
    let tx = a.payment();
    let id = tx.hash();
    a.chain.lock().unwrap().submit_tx(tx).unwrap();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("requester registered", 30, || a.net.stats().peers == 1).await;
    // The maintenance loop sees the pool height before the blocks come (it
    // re-announces from the second height it sees; a busy machine can delay
    // its first look past them).
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        a.mine_with(0, false);
    }
    let got = recv_until(
        &mut r,
        5.0,
        |m| matches!(m, Message::InvTx(ids) if ids == &vec![id]),
    )
    .await;
    if got.is_none() {
        eprintln!(
            "RT2 DIAG (announced {:02x?}): height {} seen {} queued {} pooled {} admitted {:?} {} \
             stats {:?}",
            &id[..6],
            a.height(),
            a.net.maintenance_seen_height(),
            a.net.queued_announcements(),
            a.mempool_has(&id),
            a.chain.lock().unwrap().mempool().admitted_at(&id),
            peer_list(&a),
            a.net.stats()
        );
    }
    assert!(got.is_some(), "announced");
    let unknown = [0x55; 32];
    let mut ids = vec![id; 499];
    ids.push(unknown);
    w.send(&Message::GetTx(ids).encode()).await.unwrap();
    // The answer: one `Tx`, then the `NotFound` that ends it.
    let mut served = 0;
    loop {
        match Message::decode(&r.recv().await.unwrap()).unwrap() {
            Message::Tx(_) => served += 1,
            Message::NotFound(ids) => {
                assert_eq!(ids, vec![unknown]);
                break;
            }
            _ => {}
        }
    }
    assert_eq!(served, 1);
    assert_eq!(a.net.stats().slow_disconnects, 0);
}

/// TM2-17 between two honest nodes, and the cross-check's X3: a burst of
/// valid transactions announced in one `InvTx` does not cut the link, so
/// it does not churn the requester's Dandelion stem peers. The requester's
/// only outbound peer is the server, its stem peer; a disconnect made it
/// re-draw its stem peers mid-epoch (`Dandelion::maybe_new_epoch`), and an
/// attacker that can trigger such bursts gets extra chances to become a
/// victim's stem peer. On a144d94 the server disconnected the requester.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_transaction_burst_between_honest_nodes_keeps_the_link_and_the_stem() {
    const N: usize = 100;
    // A long inbound trickle: the whole re-announcement goes out as one
    // `InvTx`, and the requester asks for all of it in one `GetTx`.
    let mut cfg = fast_config(&[]);
    cfg.trickle_inbound = Duration::from_secs(1);
    let mut a = node_with(95, cfg).await;
    a.mine_n(N as u64 + 60, 0);
    let txs: Vec<Transaction> = (0..N).map(|n| a.payment_nth(n)).collect();
    {
        let mut c = a.chain.lock().unwrap();
        for t in &txs {
            c.submit_tx(t.clone()).unwrap();
        }
    }
    let b = node(96, &[a.addr]).await;
    for h in 1..=a.height() {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
    }
    wait_until("connected", 30, || {
        a.net.stats().peers == 1 && b.net.stats().outbound == 1
    })
    .await;
    wait_until("the server is the requester's stem peer", 5, || {
        b.net.stem_peers().len() == 1
    })
    .await;
    let stems = b.net.stem_peers();
    let link = b.net.peers()[0].id;
    assert_eq!(stems, vec![link]);
    // The pool's re-announcement at age 10: every transaction at once,
    // once the maintenance loop has seen the pool height (as above).
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        let blk = a.mine_with(0, false);
        give_block(&b, &blk).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let relayed = || txs.iter().filter(|t| b.mempool_has(&t.hash())).count();
    while relayed() < N && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(
        (relayed(), a.net.stats().slow_disconnects),
        (N, 0),
        "(transactions relayed, slow disconnects)"
    );
    assert_eq!(b.net.peers().len(), 1);
    assert_eq!(b.net.peers()[0].id, link, "the same connection");
    assert_eq!(b.net.stem_peers(), stems, "no stem peer change");
    assert!(a.net.peers().iter().all(|p| p.score == 0));
    assert!(b.net.peers().iter().all(|p| p.score == 0));
}

// ------------------------------------------------------------ RT-W2a fixes

/// RTW2A-4: a rate excess on a relayed `StemTx` is dropped without penalty.
/// An honest node forwarding many peers' valid stems exceeds a per-peer
/// rate without misbehaving; a penalty would get it banned. Here its `txs`
/// budget (burst 2) admits two of five valid stems: those are verified,
/// the other three are dropped unverified, not stemmed and not fluffed
/// (a forced fluff helps locate the origin), and the forwarder's score
/// stays 0. Invalid content is still penalized. On 47179f1 each excess
/// stem cost one point (`score::RATE`, "stem rate").
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_honest_stem_forwarder_over_its_rate_is_not_penalized() {
    let mut cfg = fast_config(&[]);
    cfg.peer_limits.txs = blacksilk_p2p::limits::TokenBucket::new(0.001, 2.0);
    let mut a = node_with(66, cfg).await;
    a.mine_n(80, 0);
    let txs: Vec<Transaction> = (0..5).map(|n| a.payment_nth(n)).collect();
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    let msgs: Vec<Vec<u8>> = txs
        .iter()
        .map(|t| Message::StemTx(t.encode()).encode())
        .collect();
    send_and_sync(&mut r, &mut w, &msgs, 1).await;
    assert_eq!(a.net.stats().tx_verifications, 2, "two within the rate");
    assert_eq!(a.net.peers()[0].score, 0, "the excess is not penalized");
    for t in &txs[2..] {
        let id = t.hash();
        assert!(
            !a.net.stempool_contains(&id) && !a.mempool_has(&id),
            "dropped: neither stemmed nor fluffed"
        );
    }
    // A stem that does not decode is invalid content: still penalized.
    send_and_sync(
        &mut r,
        &mut w,
        &[Message::StemTx(vec![1, 2, 3]).encode()],
        2,
    )
    .await;
    assert_eq!(a.net.peers()[0].score, score::INVALID_TX);
}

/// RTW2A-3: body downloads are scheduled during a drain while an embargo
/// fluff waits for the chain actor. During a drain a Tx-lane command runs
/// only after about `STARVATION_LIMIT` (16) steps
/// (`chain/tests/actor_order.rs`), and the chain-maintenance loop used to
/// await each fluff before `schedule_downloads`: here the drain has 30
/// steps of 250 ms and a local transaction's embargo expires at its start,
/// so a peer announcing the chain got its first `GetBlocks` only about 4 s
/// later. Now the loop schedules first and fluffs on a task of its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn downloads_are_scheduled_during_a_drain_while_a_fluff_waits() {
    const STEP: Duration = Duration::from_millis(250);
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_millis(300);
    cfg.dandelion.embargo_mean = Duration::from_millis(1);
    let (mut a, handle) = node_with_actor_handle(
        67,
        cfg,
        ActorConfig {
            step_budget: 1,
            ..ActorConfig::default()
        },
    )
    .await;
    a.mine_n(80, 0);
    // An extension of 40 blocks, mined elsewhere.
    let mut c = node(68, &[]).await;
    {
        let ca = a.chain.lock().unwrap();
        let mut cc = c.chain.lock().unwrap();
        for h in 1..=ca.height() {
            let b = ca.block_at(h).unwrap();
            let now = b.header.timestamp;
            cc.submit_block(b, now).unwrap();
        }
    }
    c.mine_n(40, 1);
    let ext: Vec<Block> = {
        let cc = c.chain.lock().unwrap();
        (81..=120).map(|h| cc.block_at(h).unwrap()).collect()
    };
    let now = ext.last().unwrap().header.timestamp;
    {
        // Headers 81-120 and bodies 82-110: body 81 releases a drain of 30
        // blocks; bodies 111-120 are missing.
        let mut ca = a.chain.lock().unwrap();
        let headers: Vec<BlockHeader> = ext.iter().map(|b| b.header).collect();
        ca.accept_headers(&headers, now).unwrap();
        for b in &ext[1..30] {
            ca.submit_block(b.clone(), now).unwrap();
        }
        ca.set_step_delay_for_tests(Some(STEP));
    }
    // A local transaction, held for lack of a stem peer; its embargo
    // expires during the drain.
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx).await.unwrap();
    assert!(a.net.stempool_contains(&id), "held");
    handle
        .submit_block(ext[0].clone(), now, false, |_| {})
        .unwrap();
    let t = std::time::Instant::now();
    while !handle.summary().sync_pending {
        assert!(t.elapsed() < Duration::from_secs(10), "the drain started");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    // The embargo (300 ms) expires and its fluff waits on the Tx lane. The
    // drain lasts 30 steps of 250 ms; the asserts below check it still runs.
    // (Before INV-PEN: a fixed 600 ms sleep, then an assert.)
    wait_until("the fluff is under way", 5, || {
        !a.net.stempool_contains(&id)
    })
    .await;
    let nid = params().network_id;
    let (mut r, _w) = raw_peer_at(a.addr, nid, true, 120).await;
    let start = std::time::Instant::now();
    let got = recv_until(&mut r, 2.0, |m| matches!(m, Message::GetBlocks(_))).await;
    let took = start.elapsed();
    let s = handle.summary();
    println!(
        "RTW2A-3: GetBlocks {:?} after {:.0} ms, drain at height {} (pending {})",
        got.is_some(),
        took.as_secs_f64() * 1000.0,
        s.height,
        s.sync_pending
    );
    assert!(got.is_some(), "no body request within 2 s during the drain");
    assert!(s.sync_pending, "requested while the drain runs");
    wait_until("the fluffed transaction is pooled", 30, || {
        a.mempool_has(&id)
    })
    .await;
}

// ------------------------------------------------ W4-SYNC (RT-LAB F1, F2)

/// Two unconnected nodes with branches of their own: `a` mines `a_blocks`
/// blocks `a_dt` seconds apart, `b` mines `b_blocks` blocks `b_dt` apart.
async fn two_branches(
    seed: u64,
    (a_blocks, a_dt): (u64, u64),
    (b_blocks, b_dt): (u64, u64),
) -> (TestNode, TestNode) {
    let mut a = node(seed, &[]).await;
    let mut b = node(seed + 1, &[]).await;
    a.mine_spaced(a_blocks, a_dt, 1);
    b.mine_spaced(b_blocks, b_dt, 2);
    assert_ne!(a.tip(), b.tip());
    (a, b)
}

/// RT-LAB F1 (labnet run 4): after a partition heals, two nodes on branches
/// of EQUAL height but unequal work must converge on the heavier branch
/// without waiting for a new block, whichever side dials. Before W4-SYNC the
/// handshake asked for headers only from a peer claiming a greater height,
/// and a tip was announced only to peers claiming a lower one, so neither
/// side asked or told the other anything until the next block (12.5 s in
/// the labnet).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn equal_height_branches_converge_on_the_heavier_without_a_new_block() {
    init_test_log();
    for heavier_dials in [false, true] {
        let seed = if heavier_dials { 612 } else { 610 };
        // `light`: 120 s apart (difficulty 1); `heavy`: 5 s apart (LWMA
        // raises the difficulty).
        let (light, heavy) = two_branches(seed, (10, 120), (10, 5)).await;
        assert_eq!(light.height(), heavy.height());
        assert!(heavy.work() > light.work(), "unequal work");
        let heavy_tip = heavy.tip();
        if heavier_dials {
            heavy.net.connect(NetAddr::Ip(light.addr));
        } else {
            light.net.connect(NetAddr::Ip(heavy.addr));
        }
        wait_until("the lighter node took the heavier branch", 20, || {
            light.tip() == heavy_tip
        })
        .await;
        assert_eq!(heavy.tip(), heavy_tip, "the heavier node stayed");
        assert_eq!(light.height(), 10, "no new block was needed");
        let scored = penalized(&[&light, &heavy]);
        assert!(scored.is_empty(), "penalized: {scored:?}");
    }
}

/// RT-LAB F1: a SHORTER but heavier branch wins over a longer, lighter one
/// across a connection, whichever side dials (most work, not most blocks).
/// Before W4-SYNC the longer node never asked the shorter one for headers.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_shorter_heavier_branch_wins_over_a_longer_lighter_one() {
    init_test_log();
    for heavier_dials in [false, true] {
        let seed = if heavier_dials { 616 } else { 614 };
        let (long, short) = two_branches(seed, (14, 120), (9, 5)).await;
        assert!(long.height() > short.height());
        assert!(short.work() > long.work(), "the shorter branch is heavier");
        let short_tip = short.tip();
        if heavier_dials {
            short.net.connect(NetAddr::Ip(long.addr));
        } else {
            long.net.connect(NetAddr::Ip(short.addr));
        }
        wait_until(
            "the longer node took the shorter, heavier branch",
            20,
            || long.tip() == short_tip,
        )
        .await;
        assert_eq!(long.height(), 9);
        let scored = penalized(&[&long, &short]);
        assert!(scored.is_empty(), "penalized: {scored:?}");
    }
}

/// RT-LAB F1, the announcement side: a new tip is announced to a peer whose
/// known branch is LONGER but lighter than ours (a near-tip competitor we
/// stored). Before W4-SYNC it went only to peers claiming a lower height,
/// so this peer stayed on its lighter branch.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_new_tip_is_announced_to_a_peer_on_a_longer_lighter_branch() {
    init_test_log();
    let mut a = node(618, &[]).await;
    let nid = params().network_id;
    a.mine_spaced(10, 5, 1);
    // The peer's branch: 12 headers from genesis, 120 s apart (work 13).
    let theirs = header_branch(12, 120, 3);
    let (mut r, mut w) = raw_peer_at(a.addr, nid, true, 12).await;
    let Some(Message::GetHeaders { locator, .. }) =
        recv_until(&mut r, 5.0, |m| matches!(m, Message::GetHeaders { .. })).await
    else {
        panic!("no GetHeaders");
    };
    w.send(&Message::Headers(serve_headers(&theirs, &locator)).encode())
        .await
        .unwrap();
    let last = theirs[11].id(nid);
    wait_until("the lighter branch is stored as a side branch", 10, || {
        a.chain.lock().unwrap().header(&last).is_some()
    })
    .await;
    assert!(a.work() > 13, "our 10 blocks are heavier than its 12");
    assert_eq!(a.height(), 10);
    a.mine_spaced(1, 5, 1);
    let tip = a.tip();
    let got = recv_until(
        &mut r,
        5.0,
        |m| matches!(m, Message::Headers(h) if h.len() == 1 && h[0].id(nid) == tip),
    )
    .await;
    assert!(got.is_some(), "our new, heavier tip was not announced");
    assert_eq!(a.net.peers()[0].score, 0);
}

/// RT-LAB F1, the DoS side: a peer naming a tip we do not know (a fake one)
/// in its `Version` is asked for headers once, at the handshake; an empty
/// answer ends it. It cannot make us fetch again, however long it stays,
/// and it is not penalized (an honest peer on a fork we lack looks the same
/// until it answers).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fake_version_tip_costs_one_header_request() {
    init_test_log();
    let mut a = node(620, &[]).await;
    let nid = params().network_id;
    a.mine_n(5, 0);
    for height in [0, 5, 3] {
        let s = TcpStream::connect(a.addr).await.unwrap();
        let (mut r, mut w) = try_raw_handshake_tip(s, true, nid, true, height, [0x77; 32])
            .await
            .expect("handshake");
        let mut asked = 0;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while let Ok(Some(_)) = tokio::time::timeout_at(
            deadline,
            recv_until(&mut r, 3.0, |m| matches!(m, Message::GetHeaders { .. })),
        )
        .await
        {
            asked += 1;
            w.send(&Message::Headers(vec![]).encode()).await.unwrap();
        }
        assert_eq!(
            asked, 1,
            "a fake tip at height {height}: asked {asked} times"
        );
    }
    assert!(a.net.peers().iter().all(|p| p.score == 0));
    assert_eq!(a.height(), 5);
}

/// RT-LAB F2: a new tip is announced when the chain publishes it, not at
/// the next maintenance tick. The tick is 5 s here, so a tick-driven
/// announcement would take 2.5 s on average; each must arrive within 1 s.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tip_announcements_do_not_wait_for_the_maintenance_tick() {
    init_test_log();
    let mut cfg = fast_config(&[]);
    cfg.tick = Duration::from_secs(5);
    let mut a = node_with(622, cfg).await;
    let nid = params().network_id;
    let (mut r, _w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 30, || a.net.peers().len() == 1).await;
    let mut took = Vec::new();
    for _ in 0..5 {
        a.mine(0);
        let start = std::time::Instant::now();
        let tip = a.tip();
        let got = recv_until(
            &mut r,
            6.0,
            |m| matches!(m, Message::Headers(h) if h.len() == 1 && h[0].id(nid) == tip),
        )
        .await;
        assert!(got.is_some(), "tip not announced");
        took.push(start.elapsed());
    }
    println!("W4-SYNC F2: announcement latencies with a 5 s tick: {took:?}");
    assert!(
        took.iter().all(|t| *t < Duration::from_secs(1)),
        "announcements waited for the tick: {took:?}"
    );
}

/// RT-LAB F2 measurement (run by hand, `--ignored --nocapture`): the time
/// from a block's connection to its announcement reaching a peer, with the
/// default tick, over 40 blocks spaced by a pseudo-random delay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement, run by hand"]
async fn announcement_latency_with_the_default_tick() {
    use rand_chacha::rand_core::RngCore;
    let tick = NetConfig::new(params().network_id).tick;
    let mut cfg = fast_config(&[]);
    cfg.tick = tick;
    let mut a = node_with(624, cfg).await;
    let nid = params().network_id;
    let (mut r, _w) = raw_peer(a.addr, nid, true).await;
    wait_until("registered", 30, || a.net.peers().len() == 1).await;
    let mut ms = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(624);
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50 + rng.next_u64() % 300)).await;
        a.mine(0);
        let start = std::time::Instant::now();
        let tip = a.tip();
        recv_until(
            &mut r,
            5.0,
            |m| matches!(m, Message::Headers(h) if h.len() == 1 && h[0].id(nid) == tip),
        )
        .await
        .expect("announced");
        ms.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    ms.sort_by(f64::total_cmp);
    let mean = ms.iter().sum::<f64>() / ms.len() as f64;
    println!(
        "W4-SYNC F2: tick {tick:?}, {} blocks: mean {mean:.1} ms, median {:.1} ms, p90 {:.1} ms, max {:.1} ms",
        ms.len(),
        ms[ms.len() / 2],
        ms[ms.len() * 9 / 10],
        ms[ms.len() - 1]
    );
}

// ------------------------------------------------ RT-SYNC (red team of W4-SYNC)

/// RT-SYNC 3: a line A - B - C where B and C share a lighter branch of equal
/// height and A holds a heavier one. When A dials B, C (two hops from the
/// heavier branch) converges without a new block, and without penalties.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_equal_height_heavier_branch_two_hops_away() {
    init_test_log();
    let mut a = node(700, &[]).await;
    let mut b = node(701, &[]).await;
    b.mine_spaced(12, 120, 2);
    let c = node(702, &[b.addr]).await;
    wait_until("C on B's branch", 20, || c.tip() == b.tip()).await;
    a.mine_spaced(12, 5, 1);
    assert_eq!(a.height(), c.height());
    assert!(a.work() > c.work());
    let heavy = a.tip();
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("C took the heavier branch two hops away", 20, || {
        c.tip() == heavy
    })
    .await;
    assert_eq!(b.tip(), heavy);
    assert_eq!(c.height(), 12);
    let scored = penalized(&[&a, &b, &c]);
    assert!(scored.is_empty(), "penalized: {scored:?}");
}

/// RT-SYNC 3: the same line with a SHORTER heavier branch; B dials A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_shorter_heavier_branch_two_hops_away() {
    init_test_log();
    let mut a = node(704, &[]).await;
    let mut b = node(705, &[]).await;
    b.mine_spaced(16, 120, 2);
    let c = node(706, &[b.addr]).await;
    wait_until("C on B's branch", 20, || c.tip() == b.tip()).await;
    a.mine_spaced(10, 5, 1);
    assert!(a.height() < c.height());
    assert!(a.work() > c.work(), "{} vs {}", a.work(), c.work());
    let heavy = a.tip();
    b.net.connect(NetAddr::Ip(a.addr));
    wait_until("C took the shorter heavier branch", 20, || c.tip() == heavy).await;
    assert_eq!(c.height(), 10);
    let scored = penalized(&[&a, &b, &c]);
    assert!(scored.is_empty(), "penalized: {scored:?}");
}

/// RT-SYNC 3: a long partition with LWMA difficulty drift: 400 light blocks
/// against 150 blocks at half the target spacing (heavier, shorter), fork at genesis,
/// deeper than ANTI_DOS_BLOCKS. Either side dialing converges on the heavier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_long_partition_with_lwma_drift_converges_on_the_heavier() {
    init_test_log();
    for heavier_dials in [false, true] {
        let seed = if heavier_dials { 710 } else { 708 };
        let mut long = node(seed, &[]).await;
        let mut short = node(seed + 1, &[]).await;
        long.mine_spaced(400, 120, 1);
        short.mine_spaced(150, 5, 2);
        println!(
            "RT-SYNC LWMA: long {} blocks work {}, short {} blocks work {}",
            long.height(),
            long.work(),
            short.height(),
            short.work()
        );
        assert!(short.work() > long.work());
        let heavy = short.tip();
        if heavier_dials {
            short.net.connect(NetAddr::Ip(long.addr));
        } else {
            long.net.connect(NetAddr::Ip(short.addr));
        }
        wait_until("the long node took the heavier branch", 60, || {
            long.tip() == heavy
        })
        .await;
        let scored = penalized(&[&long, &short]);
        assert!(scored.is_empty(), "penalized: {scored:?}");
    }
}

/// RT-SYNC 2: equal work, different tips (a tie). Each keeps its own tip
/// (ties keep), without penalties, and the next block settles it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_equal_work_tie_is_bounded_and_settles_on_the_next_block() {
    init_test_log();
    let mut a = node(712, &[]).await;
    let mut b = node(713, &[]).await;
    a.mine_spaced(6, 120, 1);
    b.mine_spaced(6, 120, 2);
    assert_eq!(a.work(), b.work());
    assert_ne!(a.tip(), b.tip());
    let (ta, tb) = (a.tip(), b.tip());
    a.net.connect(NetAddr::Ip(b.addr));
    wait_until("connected", 30, || a.net.peers().len() == 1).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!((a.tip(), b.tip()), (ta, tb), "a tie keeps both tips");
    a.mine_spaced(1, 120, 1);
    let t = a.tip();
    wait_until("B took A's next block", 20, || b.tip() == t).await;
    let scored = penalized(&[&a, &b]);
    assert!(scored.is_empty(), "penalized: {scored:?}");
}

/// RT-SYNC 2 (race): the node's tip changes between its `Version` (which
/// names the old tip) and the peer's registration. The announcement ran
/// while the peer was not registered, and the peer's `Version` tip is now
/// placeable (in our locator), so nobody asks and nobody tells: the peer
/// does not learn the new tip until the next one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_a_tip_found_during_the_handshake_is_announced() {
    init_test_log();
    let mut a = node(714, &[]).await;
    let nid = params().network_id;
    a.mine_n(5, 0);
    let (old_tip, h) = (a.tip(), a.height());
    let s = TcpStream::connect(a.addr).await.unwrap();
    let (mut r, mut w) = handshake(s, true, nid, &params().genesis_id(), Duration::from_secs(5))
        .await
        .unwrap();
    let v = Version {
        protocol: PROTOCOL_VERSION,
        network: nid,
        nonce: 0xdead_beef,
        height: h,
        tip: old_tip,
        listen: None,
        relay_txs: true,
    };
    w.send(&Message::Version(v).encode()).await.unwrap();
    let m = Message::decode(&r.recv().await.unwrap()).unwrap();
    assert!(matches!(m, Message::Version(ref v) if v.tip == old_tip));
    // The node finds a block before our Verack registers us.
    a.mine(0);
    let new_tip = a.tip();
    tokio::time::sleep(Duration::from_millis(400)).await;
    w.send(&Message::Verack.encode()).await.unwrap();
    let got = recv_until(&mut r, 4.0, |m| {
        matches!(m, Message::Headers(hs) if hs.iter().any(|x| x.id(nid) == new_tip))
            || matches!(m, Message::GetHeaders { .. })
    })
    .await;
    assert!(
        got.is_some(),
        "the peer was neither told of nor asked about the tip found during its handshake"
    );
}

/// RT-SYNC 1/2 (echo): a node that has the best header chain but is still
/// connecting bodies announces every intermediate tip to a peer that named
/// that best header in its `Version` (its work is recorded as 0), although
/// every one of them is an ancestor of the peer's tip. Before W4-SYNC the
/// peer's claimed height suppressed them. Counts the redundant announcements.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_a_draining_node_does_not_echo_tips_to_a_peer_ahead() {
    init_test_log();
    let nid = params().network_id;
    let mut a = node(716, &[]).await;
    a.mine_n(150, 0);
    let headers: Vec<BlockHeader> = {
        let c = a.chain.lock().unwrap();
        (1..=150).map(|h| c.block_at(h).unwrap().header).collect()
    };
    let best = headers[149].id(nid);
    let n = node(717, &[]).await;
    // X: serves the headers, not the bodies.
    let (xr, xw) = raw_peer_at(n.addr, nid, true, 150).await;
    serve_branch(xr, xw, headers.clone());
    // Generous deadlines: under full CPU load (other test processes) the
    // 150 headers took up to 18 s to verify in a release build.
    wait_until("N has the headers", 90, || {
        n.chain.lock().unwrap().header_height() == 150
    })
    .await;
    assert_eq!(n.height(), 0);
    // E: an honest peer at the same best header (it has all 150 blocks).
    let s = TcpStream::connect(n.addr).await.unwrap();
    let (mut er, mut ew) = try_raw_handshake_tip(s, true, nid, true, 150, best)
        .await
        .expect("handshake");
    wait_until("E registered", 30, || n.net.peers().len() == 2).await;
    // Counts until 1 s after the drain ended (W4-SYNC: a fixed 15 s window
    // missed late echoes, and the drain's 20 s deadline failed under load).
    let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);
    let counter = tokio::spawn(async move {
        let mut echoes = 0usize;
        let mut asked = 0usize;
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let frame = tokio::select! {
                f = tokio::time::timeout_at(deadline, er.recv()) => match f {
                    Ok(Ok(frame)) => frame,
                    _ => break,
                },
                _ = done_rx.changed() => {
                    deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                    continue;
                }
            };
            match Message::decode(&frame) {
                Ok(Message::Headers(h)) if h.len() == 1 => echoes += 1,
                Ok(Message::GetHeaders { .. }) => asked += 1,
                // A raw peer: bodies are "not found" (no timeout).
                Ok(Message::GetBlocks(ids)) => {
                    let _ = ew.send(&Message::NotFound(ids).encode()).await;
                }
                _ => {}
            }
        }
        (echoes, asked)
    });
    n.net.connect(NetAddr::Ip(a.addr));
    wait_until("N connected the bodies", 90, || n.height() == 150).await;
    done_tx.send(true).unwrap();
    let (echoes, asked) = counter.await.unwrap();
    println!("RT-SYNC echo: {echoes} single-header announcements to E, {asked} GetHeaders");
    assert_eq!(
        echoes, 0,
        "{echoes} ancestors of E's tip were announced to it"
    );
}

/// Whether the node asks a raw peer that handshakes claiming `height` and
/// the best header `tip` for headers within `secs` (the handshake's request:
/// with a long maintenance tick nothing else asks).
async fn handshake_asks(node: &TestNode, height: u64, tip: Hash, secs: f64) -> bool {
    let nid = params().network_id;
    let s = TcpStream::connect(node.addr).await.unwrap();
    let (mut r, _w) = try_raw_handshake_tip(s, true, nid, true, height, tip)
        .await
        .expect("handshake");
    recv_until(&mut r, secs, |m| matches!(m, Message::GetHeaders { .. }))
        .await
        .is_some()
}

/// The handshake's header request (W4-SYNC, `knows_tip`; mutation run D):
/// a peer is asked for headers if it claims more height than our best
/// header, or names a best header we cannot place: not if it claims no more
/// height and names a header we know, our connected tip included when our
/// best header chain has moved to another branch. The maintenance loop
/// (which also asks taller peers) is slowed to one tick a minute, so every
/// request seen comes from the handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_handshake_asks_for_headers_for_more_height_or_an_unknown_tip() {
    let nid = params().network_id;
    let mut cfg = fast_config(&[]);
    cfg.tick = Duration::from_secs(60);
    let mut a = node_with(730, cfg).await;
    a.mine_n(10, 0);
    let tip = a.tip();
    assert!(
        !handshake_asks(&a, 10, tip, 3.0).await,
        "same height, our tip"
    );
    assert!(
        !handshake_asks(&a, 5, params().genesis_id(), 3.0).await,
        "a lower height, a header of our locator"
    );
    assert!(handshake_asks(&a, 11, tip, 10.0).await, "more height");
    assert!(
        handshake_asks(&a, 10, [9; 32], 10.0).await,
        "an unknown tip"
    );
    // A heavier branch from genesis (12 blocks), headers only: our best
    // header chain moves to it, and our connected tip leaves it.
    let mut b = node(731, &[]).await;
    b.mine_n(12, 0);
    let branch: Vec<BlockHeader> = {
        let c = b.chain.lock().unwrap();
        (1..=12).map(|h| c.block_at(h).unwrap().header).collect()
    };
    let (xr, xw) = raw_peer_at(a.addr, nid, true, 12).await;
    serve_branch(xr, xw, branch);
    wait_until("A has the branch's headers", 60, || {
        a.chain.lock().unwrap().header_height() == 12
    })
    .await;
    assert_eq!(a.tip(), tip, "no bodies: the connected tip stays");
    assert!(!a.chain.lock().unwrap().summary().tip_on_best_chain);
    assert!(
        !handshake_asks(&a, 10, tip, 3.0).await,
        "our connected tip, off our best header chain"
    );
}

/// The headers a peer delivered count as known to it (W4-SYNC,
/// `Peer::has_header`, the work of `headers::end_of`; mutation run D), and
/// so does the best header it named in its `Version`: X names header 50,
/// answers two requests with headers 1..=50 and 51..=60 (the second batch
/// heavier), then announces a sibling of header 60 of equal work, which
/// does not replace it. While N connects the bodies (from A) it announces
/// none of its new tips to X, which has them all. Before, only a peer whose
/// `Version` named the best header was checked
/// (`rt_sync_a_draining_node_does_not_echo_tips_to_a_peer_ahead`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tips_are_not_echoed_to_the_peer_that_delivered_their_headers() {
    init_test_log();
    let nid = params().network_id;
    let mut a = node(732, &[]).await;
    a.mine_n(60, 0);
    let headers: Vec<BlockHeader> = {
        let c = a.chain.lock().unwrap();
        (1..=60).map(|h| c.block_at(h).unwrap().header).collect()
    };
    let mut sibling = headers[59];
    sibling.nonce += 1;
    let sibling_id = sibling.id(nid);
    let n = node(733, &[]).await;
    let s = TcpStream::connect(n.addr).await.unwrap();
    let (mut xr, mut xw) = try_raw_handshake_tip(s, true, nid, true, 60, headers[49].id(nid))
        .await
        .expect("handshake");
    let (sibling_tx, mut sibling_rx) = tokio::sync::oneshot::channel::<()>();
    let (done_tx, mut done_rx) = tokio::sync::watch::channel(false);
    let x = tokio::spawn(async move {
        let (mut requests, mut echoes) = (0usize, 0usize);
        let mut sibling_rx = Some(&mut sibling_rx);
        let mut deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        loop {
            let frame = tokio::select! {
                f = tokio::time::timeout_at(deadline, xr.recv()) => match f {
                    Ok(Ok(frame)) => frame,
                    _ => break,
                },
                _ = async { sibling_rx.as_mut().unwrap().await }, if sibling_rx.is_some() => {
                    sibling_rx = None;
                    let _ = xw.send(&Message::Headers(vec![sibling]).encode()).await;
                    continue;
                }
                _ = done_rx.changed() => {
                    deadline = tokio::time::Instant::now() + Duration::from_secs(1);
                    continue;
                }
            };
            let reply = match Message::decode(&frame) {
                Ok(Message::GetHeaders { locator, .. }) => {
                    requests += 1;
                    let mut h = serve_headers(&headers, &locator);
                    if requests == 1 {
                        h.truncate(50);
                    }
                    Message::Headers(h)
                }
                Ok(Message::Headers(h)) if h.len() == 1 => {
                    echoes += 1;
                    continue;
                }
                Ok(Message::GetBlocks(ids)) => Message::NotFound(ids),
                Ok(Message::Ping(n)) => Message::Pong(n),
                _ => continue,
            };
            if xw.send(&reply.encode()).await.is_err() {
                break;
            }
        }
        (requests, echoes)
    });
    wait_until("N has X's headers", 90, || {
        n.chain.lock().unwrap().header_height() == 60
    })
    .await;
    sibling_tx.send(()).unwrap();
    wait_until("N has the sibling", 30, || {
        n.chain
            .lock()
            .unwrap()
            .headers()
            .header(&sibling_id)
            .is_some()
    })
    .await;
    assert_eq!(n.height(), 0, "no bodies from X");
    n.net.connect(NetAddr::Ip(a.addr));
    wait_until("N connected the bodies", 90, || n.height() == 60).await;
    done_tx.send(true).unwrap();
    let (requests, echoes) = x.await.unwrap();
    println!("X: {requests} header requests, {echoes} single-header announcements");
    assert!(requests >= 2, "two batches");
    assert_eq!(echoes, 0, "{echoes} of N's tips were announced to X");
}

/// RT-SYNC 1 (DoS): peers reconnecting with an unplaceable tip, answering
/// the request with our own headers (a reply of stored headers), cost no
/// proof of work and are asked once per connection.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_fake_tip_churn_with_stored_headers_hashes_nothing() {
    init_test_log();
    let nid = params().network_id;
    let pow = Arc::new(CountAllPow::default());
    let mut a = node_with_pow(718, fast_config(&[]), pow.clone()).await;
    a.mine_n(40, 0);
    let ours: Vec<BlockHeader> = {
        let c = a.chain.lock().unwrap();
        (1..=40).map(|h| c.block_at(h).unwrap().header).collect()
    };
    let before = pow.0.load(std::sync::atomic::Ordering::SeqCst);
    let mut asked_total = 0;
    for i in 0..20u8 {
        let s = connect_from([127, 0, 0, 10 + i], a.addr).await.unwrap();
        let (mut r, mut w) = try_raw_handshake_tip(s, true, nid, true, 0, [0x55 ^ i; 32])
            .await
            .expect("handshake");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(700);
        while let Ok(Some(_)) = tokio::time::timeout_at(
            deadline,
            recv_until(&mut r, 1.0, |m| matches!(m, Message::GetHeaders { .. })),
        )
        .await
        {
            asked_total += 1;
            w.send(&Message::Headers(ours.clone()).encode())
                .await
                .unwrap();
        }
    }
    let after = pow.0.load(std::sync::atomic::Ordering::SeqCst);
    println!(
        "RT-SYNC churn: {asked_total} requests over 20 connections, {} hashes",
        after - before
    );
    assert_eq!(asked_total, 20);
    assert_eq!(after, before, "stored headers were hashed");
    assert!(a.net.peers().iter().all(|p| p.score == 0));
}

/// RT-SYNC 2 (stale record): a peer relayed headers of a branch (its last
/// header on our best header chain then, work W) whose first block's body
/// later proves invalid. Our best header chain falls back, and our next
/// honest tips (on the new best chain, work below W) are not announced to
/// the peer: `known_on_main` was recorded before the branch lost, and the
/// peer (which rejects the same invalid body) does not have them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_sync_tips_after_an_invalidated_branch_are_announced_to_its_relayer() {
    init_test_log();
    let mut a = node(720, &[]).await;
    a.mine_n(2, 0);
    let nid = params().network_id;
    // A block with a valid header and an invalid body (the coinbase
    // overpays), not submitted: the node learns the body later.
    let bad = {
        let c = a.chain.lock().unwrap();
        let t = c.template();
        let cb = build_coinbase(
            t.height,
            &[Payment {
                address: a.miner.address(SubaddressIndex::PRIMARY),
                amount: t.reward + 1,
            }],
            &a.miner.hedge_secret(),
            &mut ChaCha20Rng::seed_from_u64(1),
        )
        .unwrap();
        let txs = vec![Transaction::Coinbase(cb)];
        let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
        let (output_count, output_root) = t.outputs_after(&txs);
        let header = BlockHeader {
            version: HEADER_VERSION,
            height: t.height,
            prev_id: t.prev_id,
            timestamp: t
                .min_timestamp
                .max(params().genesis.timestamp + 120 * t.height),
            difficulty: t.difficulty,
            tx_root: tx_root(&ids),
            nonce: 7,
            output_count,
            output_root,
            px_root: t.px_root,
        };
        Block { header, txs }
    };
    // Two valid headers on it.
    let children = {
        let mut g = HeaderChain::new(params(), Arc::new(ZeroPow));
        let c = a.chain.lock().unwrap();
        for h in 1..=2 {
            g.accept(c.block_at(h).unwrap().header, u64::MAX / 2)
                .unwrap();
        }
        let mut x = g.accept(bad.header, u64::MAX / 2).unwrap().id;
        let mut out = Vec::new();
        for _ in 0..2 {
            let t = g.template_on(x).unwrap();
            let parent = *g.header(&x).unwrap();
            let h = BlockHeader {
                version: HEADER_VERSION,
                height: t.height,
                prev_id: x,
                timestamp: t.min_timestamp.max(parent.timestamp + 120),
                difficulty: t.difficulty,
                tx_root: [0; 32],
                nonce: 7,
                ..Default::default()
            };
            x = g.accept(h, u64::MAX / 2).unwrap().id;
            out.push(h);
        }
        out
    };
    let branch = vec![bad.header, children[0], children[1]];
    // P: an honest relayer of the headers (no bodies).
    let (mut pr, mut pw) = raw_peer_at(a.addr, nid, true, 5).await;
    assert!(
        recv_until(&mut pr, 5.0, |m| matches!(m, Message::GetHeaders { .. }))
            .await
            .is_some()
    );
    pw.send(&Message::Headers(branch.clone()).encode())
        .await
        .unwrap();
    wait_until("the branch's headers are stored", 10, || {
        a.chain.lock().unwrap().header_height() == 5
    })
    .await;
    // M: the source of the invalid body.
    let s = connect_from([127, 0, 0, 77], a.addr).await.unwrap();
    let (mr, mw) = try_raw_handshake(s, nid, true, 5).await.expect("handshake");
    {
        let (mut mr, mut mw, branch, bad) = (mr, mw, branch.clone(), bad.clone());
        tokio::spawn(async move {
            while let Ok(frame) = mr.recv().await {
                let reply = match Message::decode(&frame) {
                    Ok(Message::GetHeaders { locator, .. }) => {
                        Message::Headers(serve_headers(&branch, &locator))
                    }
                    Ok(Message::GetBlocks(ids)) if ids.contains(&bad.header.id(nid)) => {
                        Message::Block(bad.encode())
                    }
                    Ok(Message::GetBlocks(ids)) => Message::NotFound(ids),
                    _ => continue,
                };
                if mw.send(&reply.encode()).await.is_err() {
                    break;
                }
            }
        });
    }
    // P answers body requests with "not found".
    let (ptx, mut prx) = tokio::sync::mpsc::unbounded_channel::<Message>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                f = pr.recv() => {
                    let Ok(frame) = f else { break };
                    match Message::decode(&frame) {
                        Ok(Message::GetBlocks(ids)) => {
                            let _ = pw.send(&Message::NotFound(ids).encode()).await;
                        }
                        Ok(m) => { let _ = ptx.send(m); }
                        Err(_) => {}
                    }
                }
            }
        }
    });
    wait_until(
        "the invalid branch is dropped from the best header chain",
        20,
        || {
            let c = a.chain.lock().unwrap();
            c.best_header_id() == c.tip_id()
        },
    )
    .await;
    assert_eq!(a.height(), 2);
    // Our next honest block (work below the relayed branch's).
    a.mine(0);
    let tip = a.tip();
    let got = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(m) = prx.recv().await {
            if matches!(&m, Message::Headers(h) if h.iter().any(|x| x.id(nid) == tip)) {
                return true;
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(got, "our new tip was not announced to the branch's relayer");
}

// ------------------------------------------------------- RT-TM2P2P red team

impl TestNode {
    /// [`Self::px_deposit`] spending the `nth` mature miner output (distinct
    /// `nth`: PX deposits that do not conflict).
    fn px_deposit_nth(&mut self, amount: u64, nth: usize) -> Transaction {
        let fee = px_standard_fee();
        let (plan, rules) = self.input_plan_nth(amount + fee, nth);
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
}

/// A raw peer task that answers pings, never answers `GetTx`, and records
/// every id the node asked of it.
fn silent_announcer(
    mut r: RawReader,
    w: Arc<tokio::sync::Mutex<RawWriter>>,
) -> Arc<Mutex<Vec<Hash>>> {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let a2 = asked.clone();
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            match Message::decode(&frame) {
                Ok(Message::Ping(n)) => {
                    if w.lock()
                        .await
                        .send(&Message::Pong(n).encode())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(Message::GetTx(ids)) => a2.lock().unwrap().extend(ids),
                _ => {}
            }
        }
    });
    asked
}

/// RT-TM2P2P item 3 (privacy): a restarted origin whose wallet resubmits
/// its transaction behaves exactly as a restarted relay. Both answer an
/// `InvTx` probe with a `GetTx`, pool the transaction at the same height
/// when it arrives, and re-announce it at the same height. On 246ae4e the
/// origin pooled a held copy, so the probe told them apart (no `GetTx`
/// from the origin; RT's `rt_a_held_copy_answers_an_inv_probe_unlike_a_restarted_relay`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_a_restarted_origin_answers_an_inv_probe_like_a_restarted_relay() {
    let dir = temp_data_dir("rt-held-probe");
    let mut cfg = fast_config(&[]);
    cfg.data_dir = Some(dir.clone());
    cfg.max_outbound = 1;
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(211, cfg).await;
    a.mine_n(80, 0);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, mut stem_w) = dialed_raw_peer(&a, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx.clone()).await.unwrap();
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some()
    );
    stem_w
        .send(&Message::InvTx(vec![id]).encode())
        .await
        .unwrap();
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::GetTx(_)))
            .await
            .is_some()
    );
    stem_w
        .send(&Message::Tx(tx.encode()).encode())
        .await
        .unwrap();
    wait_until("pooled at the origin", 30, || a.mempool_has(&id)).await;
    // The origin restarts (its wallet resubmits: held), and so does a
    // relay (a node that had it pooled: same chain, empty pool).
    let (mut origin, o_dir) = restarted(&a, &dir, 212).await;
    assert_eq!(origin.net.submit_tx(tx.clone()).await, Ok(id), "held");
    assert!(!origin.mempool_has(&id), "not pooled");
    let relay_dir = temp_data_dir("rt-held-probe-relay");
    let (mut relay, r_dir) = restarted(&a, &relay_dir, 213).await;
    let nid = params().network_id;
    let mut asked = Vec::new();
    let mut probes = Vec::new();
    for n in [&origin, &relay] {
        let (mut r, mut w) = raw_peer(n.addr, nid, true).await;
        wait_until("spy registered", 30, || n.net.stats().peers == 1).await;
        w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
        let got = recv_until(
            &mut r,
            10.0,
            |m| matches!(m, Message::GetTx(ids) if ids.contains(&id)),
        )
        .await
        .is_some();
        asked.push(got);
        // The probe delivers it, as a re-announcing relay would.
        w.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
        wait_until("pooled", 30, || n.mempool_has(&id)).await;
        probes.push((r, w)); // kept open: the probe stays a peer
    }
    assert_eq!(asked, vec![true, true], "the probe cannot tell them apart");
    let at = |n: &TestNode| n.chain.lock().unwrap().mempool().admitted_at(&id);
    assert_eq!(at(&origin), at(&relay));
    let pooled = at(&origin).unwrap();
    // Fresh spies: both re-announce at the same height.
    let (mut so, mut wo) = raw_peer(origin.addr, nid, true).await;
    let (mut sr, mut wr) = raw_peer(relay.addr, nid, true).await;
    wait_until("spies registered", 30, || {
        origin.net.stats().peers == 2 && relay.net.stats().peers == 2
    })
    .await;
    let first = first_reannouncements(
        &mut [&mut origin, &mut relay],
        &mut [(&mut so, &mut wo), (&mut sr, &mut wr)],
        id,
        pooled + 11,
    )
    .await;
    assert_eq!(first[0], first[1], "(origin, relay)");
    assert_eq!(first[0], Some(pooled + 10));
    for d in [dir, o_dir, relay_dir, r_dir] {
        let _ = std::fs::remove_dir_all(&d);
    }
}

/// RT-TM2P2P liveness: a burst of PX transactions from one announcer. The
/// requester asks up to `TX_IN_FLIGHT` (16) at once, but the per-peer PX
/// relay share (burst 4) drops the answers past the fourth unpenalized,
/// after `on_tx` has ended their requests and forgotten their announcers:
/// they are never asked again, and the announcer never re-announces to a
/// peer it announced to. Fixed in f5f86cb; now a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PX proving (4-6 GB); run alone"]
async fn rt_a_px_burst_from_one_announcer_is_relayed_in_full() {
    const N: usize = 6;
    let mut a = node(214, &[]).await;
    a.mine_n(80, 0);
    let t0 = std::time::Instant::now();
    let txs: Vec<Transaction> = (0..N).map(|n| a.px_deposit_nth(5_000_000, n)).collect();
    eprintln!("RT: {N} PX built in {:?}", t0.elapsed());
    let b = node(215, &[]).await;
    for h in 1..=a.height() {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
    }
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(b.addr, nid, true).await;
    wait_until("announcer registered", 30, || b.net.stats().peers == 1).await;
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    w.send(&Message::InvTx(ids.clone()).encode()).await.unwrap();
    let mut requested = std::collections::HashSet::new();
    while requested.len() < N {
        match recv_until(&mut r, 5.0, |m| matches!(m, Message::GetTx(_))).await {
            Some(Message::GetTx(got)) => requested.extend(got),
            _ => break,
        }
    }
    eprintln!("RT: requested {} of {N} at once", requested.len());
    for t in &txs {
        if requested.contains(&t.hash()) {
            w.send(&Message::Tx(t.encode()).encode()).await.unwrap();
        }
    }
    // Every answer was delivered. Watch for 45 s (past the 30 s request
    // timeout) whether the requester asks again, and answer pings.
    let mut later = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    while tokio::time::Instant::now() < deadline {
        match recv_until(&mut r, 1.0, |m| {
            matches!(m, Message::GetTx(_) | Message::Ping(_))
        })
        .await
        {
            Some(Message::GetTx(got)) => {
                for id in &got {
                    if let Some(t) = txs.iter().find(|t| t.hash() == *id) {
                        w.send(&Message::Tx(t.encode()).encode()).await.unwrap();
                    }
                }
                later.extend(got);
            }
            Some(Message::Ping(n)) => {
                w.send(&Message::Pong(n).encode()).await.unwrap();
            }
            _ => {}
        }
    }
    let pooled = ids.iter().filter(|id| b.mempool_has(id)).count();
    let s = b.net.stats();
    eprintln!(
        "RT: pooled {pooled} of {N}; asked again {}; px_global_drops {} tx_lane_drops {} \
         tx_verifications {} scores {:?}",
        later.len(),
        s.px_global_drops,
        s.tx_lane_drops,
        s.tx_verifications,
        b.net.peers().iter().map(|p| p.score).collect::<Vec<_>>()
    );
    assert_eq!(
        pooled, N,
        "a PX burst from one announcer is relayed in full"
    );
}

/// RT-TM2P2P DoS: junk floods from other announcers (who also announce the
/// real id first and never answer) do not delay an honest announcer's
/// request: the in-flight caps and queues are per announcer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_a_junk_flood_does_not_delay_another_announcer() {
    let mut v = node(216, &[]).await;
    v.mine_n(80, 0);
    let tx = v.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let mut asked_junk = Vec::new();
    for k in 0..3u8 {
        let (r, mut w) = raw_peer_from([127, 0, 9, 10 + k], v.addr, nid, 0)
            .await
            .expect("junk");
        // 900 junk ids (90 inv tokens of a 100 burst), then the real id.
        for c in 0..3u32 {
            let ids: Vec<Hash> = (0..300u32)
                .map(|i| {
                    let mut h = [k; 32];
                    h[..4].copy_from_slice(&(c * 300 + i).to_le_bytes());
                    h[31] = 0xee;
                    h
                })
                .collect();
            w.send(&Message::InvTx(ids).encode()).await.unwrap();
        }
        w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
        asked_junk.push(silent_announcer(r, Arc::new(tokio::sync::Mutex::new(w))));
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    let asked_real_of_junk: usize = asked_junk
        .iter()
        .map(|a| a.lock().unwrap().iter().filter(|x| **x == id).count())
        .sum();
    let (mut hr, mut hw) = raw_peer_from([127, 0, 9, 50], v.addr, nid, 0)
        .await
        .expect("honest");
    let t0 = std::time::Instant::now();
    hw.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let got = recv_until(
        &mut hr,
        40.0,
        |m| matches!(m, Message::GetTx(ids) if ids.contains(&id)),
    )
    .await;
    let waited = t0.elapsed();
    eprintln!(
        "RT junk flood: real id asked of junk peers {asked_real_of_junk} times; honest asked \
         after {waited:?}; junk asks per peer {:?}",
        asked_junk
            .iter()
            .map(|a| a.lock().unwrap().len())
            .collect::<Vec<_>>()
    );
    assert!(got.is_some());
    // The honest announcer is inbound: since the request tracker (RT2) it is
    // asked 2 s after its announcement (`INBOUND_DELAY`, Core's
    // `NONPREF_PEER_TX_DELAY`), plus a maintenance tick; the junk does not
    // add to that (the junk peers' own requests fill their room first:
    // the tracker runs due timers before each event, so the order is the
    // order in time; once it ran the honest announcement's check before a
    // tick had sent the junk, asked a junk peer, and waited 30 s).
    assert!(waited < Duration::from_secs(4), "{waited:?}");
}

/// RT-TM2P2P (pre-existing, not introduced by TM2-17): eight announcers
/// that announce a transaction first and never answer fill its announcer
/// queue (8); an honest announcer after them is not recorded, is never
/// asked, and once the eight time out (8 x 30 s) the id is forgotten. An
/// honest node never announces it to us again (we are in its
/// `announced_to`). Fixed in f5f86cb; now a regression test. About 4.5 min.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt_eight_silent_first_announcers_do_not_suppress_an_honest_one() {
    let mut v = node(218, &[]).await;
    v.mine_n(80, 0);
    let tx = v.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let mut attackers = Vec::new();
    for k in 0..8u8 {
        let (r, mut w) = raw_peer_from([127, 0, 8, 10 + k], v.addr, nid, 0)
            .await
            .expect("attacker");
        w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
        attackers.push(silent_announcer(r, Arc::new(tokio::sync::Mutex::new(w))));
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (hr, mut hw) = raw_peer_from([127, 0, 8, 50], v.addr, nid, 0)
        .await
        .expect("honest");
    hw.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let hw = Arc::new(tokio::sync::Mutex::new(hw));
    let honest_asked = silent_announcer(hr, hw.clone());
    let t0 = std::time::Instant::now();
    let mut answered = false;
    while t0.elapsed() < Duration::from_secs(270) {
        if !answered && honest_asked.lock().unwrap().contains(&id) {
            hw.lock()
                .await
                .send(&Message::Tx(tx.encode()).encode())
                .await
                .unwrap();
            answered = true;
            eprintln!("RT: honest asked after {:?}", t0.elapsed());
        }
        if v.mempool_has(&id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let attacker_asks: Vec<usize> = attackers.iter().map(|a| a.lock().unwrap().len()).collect();
    eprintln!(
        "RT: after {:?}: pooled {}, honest asked {answered}, attacker asks {attacker_asks:?}",
        t0.elapsed(),
        v.mempool_has(&id),
    );
    assert!(
        v.mempool_has(&id),
        "an honest announcer is asked eventually"
    );
}

// ------------------------------------------------------ RT2-TM2P2P red team

/// A raw peer task that answers pings, records every id the node asked of
/// it, and answers a request for `tx` with it.
fn answering_announcer(
    mut r: RawReader,
    w: Arc<tokio::sync::Mutex<RawWriter>>,
    tx: Transaction,
) -> Arc<Mutex<Vec<Hash>>> {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let a2 = asked.clone();
    let id = tx.hash();
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            let reply = match Message::decode(&frame) {
                Ok(Message::Ping(n)) => Some(Message::Pong(n)),
                Ok(Message::GetTx(ids)) => {
                    let ours = ids.contains(&id);
                    a2.lock().unwrap().extend(ids);
                    ours.then(|| Message::Tx(tx.encode()))
                }
                _ => None,
            };
            if let Some(m) = reply {
                if w.lock().await.send(&m.encode()).await.is_err() {
                    break;
                }
            }
        }
    });
    asked
}

/// RT2-TM2P2P (censorship, pre-existing since TM2-17, made longer by the
/// retry-once of RT-TM2P2P): a request that times out moves to the next
/// announcer in arrival order; when that announcer has no free request slot
/// (its own silent junk holds all 16), the id is queued at the BACK of its
/// wanted queue (up to 2,000 ids) with no request outstanding and no
/// deadline. An honest announcer queued after it is not asked until that
/// queue drains: each junk id holds a slot 2 x 30 s (asked, then asked once
/// more), so 500 junk ids hold the real one for about 500 / 16 x 60 s = 31
/// minutes, 2,000 for about 2 hours. Two inbound peers suffice: X1
/// announces first and stays silent; X2 announces second. Fixed in f615965;
/// now a regression test (the honest announcer should be asked at the first
/// timeout, about 30 s).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt2_a_timed_out_request_is_not_parked_behind_a_junk_queue() {
    init_test_log();
    let mut v = node(230, &[]).await;
    v.mine_n(80, 0);
    let tx = v.payment();
    let id = tx.hash();
    let nid = params().network_id;
    // X2 first fills its own request slots and wanted queue with junk.
    let (r2, mut w2) = raw_peer_from([127, 0, 7, 12], v.addr, nid, 0)
        .await
        .expect("x2");
    let junk: Vec<Hash> = (0..500u32)
        .map(|i| {
            let mut h = [0x77; 32];
            h[..4].copy_from_slice(&i.to_le_bytes());
            h
        })
        .collect();
    w2.send(&Message::InvTx(junk).encode()).await.unwrap();
    let w2 = Arc::new(tokio::sync::Mutex::new(w2));
    let x2_asked = silent_announcer(r2, w2.clone());
    tokio::time::sleep(Duration::from_secs(1)).await;
    // X1 announces the real id first (asked, never answers), then X2, then
    // an honest announcer.
    let (r1, mut w1) = raw_peer_from([127, 0, 7, 11], v.addr, nid, 0)
        .await
        .expect("x1");
    w1.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let x1_asked = silent_announcer(r1, Arc::new(tokio::sync::Mutex::new(w1)));
    tokio::time::sleep(Duration::from_millis(300)).await;
    w2.lock()
        .await
        .send(&Message::InvTx(vec![id]).encode())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (hr, mut hw) = raw_peer_from([127, 0, 7, 50], v.addr, nid, 0)
        .await
        .expect("honest");
    hw.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let honest_asked = answering_announcer(hr, Arc::new(tokio::sync::Mutex::new(hw)), tx.clone());
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(75) && !v.mempool_has(&id) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let count = |a: &Arc<Mutex<Vec<Hash>>>| a.lock().unwrap().iter().filter(|x| **x == id).count();
    eprintln!(
        "RT2 parked: after {:?}: pooled {}, real id asked of x1 {}, x2 {}, honest {}; x2 asks {}",
        t0.elapsed(),
        v.mempool_has(&id),
        count(&x1_asked),
        count(&x2_asked),
        count(&honest_asked),
        x2_asked.lock().unwrap().len()
    );
    assert!(
        v.mempool_has(&id),
        "the honest announcer is asked at the first timeout"
    );
}

/// RT2-TM2P2P (censorship through Busy): an announcer can make this node
/// drop its answer for the node's own budgets at will. Before answering it
/// drains its own PX share (burst 4, 0.2 per second) with `StemTx` copies
/// of a PX transaction this node already pools: each is charged, then
/// dropped as known, never penalized. Its answer is then dropped as Busy,
/// the id goes back to the front of ITS wanted queue, it is paused 5 s and
/// asked again, indefinitely: no other announcer is asked, and no timeout
/// runs. Fixed in f615965; now a regression test. PX proving (two
/// transactions).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PX proving (4-6 GB); run alone"]
async fn rt2_an_announcer_kept_busy_does_not_hold_a_transaction() {
    init_test_log();
    let mut v = node(232, &[]).await;
    v.mine_n(80, 0);
    let pooled = v.px_deposit_nth(5_000_000, 1);
    let target = v.px_deposit_nth(5_000_000, 2);
    v.chain
        .lock()
        .unwrap()
        .submit_tx(pooled.clone())
        .expect("pooled");
    let id = target.hash();
    let nid = params().network_id;
    let (mut xr, xw) = raw_peer_from([127, 0, 6, 11], v.addr, nid, 0)
        .await
        .expect("x");
    let xw = Arc::new(tokio::sync::Mutex::new(xw));
    xw.lock()
        .await
        .send(&Message::InvTx(vec![id]).encode())
        .await
        .unwrap();
    // The busy announcer: drains its PX share before each answer.
    let x_asked = Arc::new(Mutex::new(0usize));
    {
        let (xw, x_asked, pooled, target) =
            (xw.clone(), x_asked.clone(), pooled.clone(), target.clone());
        tokio::spawn(async move {
            while let Ok(frame) = xr.recv().await {
                match Message::decode(&frame) {
                    Ok(Message::Ping(n)) => {
                        let _ = xw.lock().await.send(&Message::Pong(n).encode()).await;
                    }
                    Ok(Message::GetTx(ids)) if ids.contains(&target.hash()) => {
                        *x_asked.lock().unwrap() += 1;
                        for _ in 0..4 {
                            let m = Message::StemTx(pooled.encode()).encode();
                            let _ = xw.lock().await.send(&m).await;
                            tokio::time::sleep(Duration::from_millis(300)).await;
                        }
                        let m = Message::Tx(target.encode()).encode();
                        let _ = xw.lock().await.send(&m).await;
                    }
                    _ => {}
                }
            }
        });
    }
    // The first request is in flight; an honest announcer comes after.
    wait_until("x asked", 10, || *x_asked.lock().unwrap() >= 1).await;
    let (hr, mut hw) = raw_peer_from([127, 0, 6, 50], v.addr, nid, 0)
        .await
        .expect("honest");
    hw.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let honest_asked =
        answering_announcer(hr, Arc::new(tokio::sync::Mutex::new(hw)), target.clone());
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(60) && !v.mempool_has(&id) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let s = v.net.stats();
    eprintln!(
        "RT2 busy: after {:?}: pooled {}, x asked {} times, honest asked {}, scores {:?}, \
         px_global_drops {}",
        t0.elapsed(),
        v.mempool_has(&id),
        x_asked.lock().unwrap(),
        honest_asked
            .lock()
            .unwrap()
            .iter()
            .filter(|x| **x == id)
            .count(),
        v.net.peers().iter().map(|p| p.score).collect::<Vec<_>>(),
        s.px_global_drops
    );
    assert!(
        v.mempool_has(&id),
        "an announcer that keeps its answers Busy does not hold the transaction"
    );
}

// ------------------------------------------------------ RT3-TM2P2P red team

/// A raw peer task that answers pings and every `GetTx` for one of `txs`,
/// each answer `delay` after its request (in order), and records the ids
/// asked of it.
fn delayed_announcer(
    mut r: RawReader,
    w: Arc<tokio::sync::Mutex<RawWriter>>,
    txs: Vec<Transaction>,
    delay: Duration,
) -> Arc<Mutex<Vec<Hash>>> {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let a2 = asked.clone();
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            match Message::decode(&frame) {
                Ok(Message::Ping(n)) => {
                    let _ = w.lock().await.send(&Message::Pong(n).encode()).await;
                }
                Ok(Message::GetTx(ids)) => {
                    a2.lock().unwrap().extend(ids.iter().copied());
                    let answers: Vec<Vec<u8>> = ids
                        .iter()
                        .filter_map(|id| txs.iter().find(|t| t.hash() == *id))
                        .map(|t| Message::Tx(t.encode()).encode())
                        .collect();
                    let w = w.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        for m in answers {
                            let _ = w.lock().await.send(&m).await;
                        }
                    });
                }
                _ => {}
            }
        }
    });
    asked
}

/// The score of the live peer connected from `ip`, if any.
fn score_from(n: &TestNode, ip: [u8; 4]) -> Option<u32> {
    let ip = std::net::IpAddr::from(ip);
    n.net
        .peers()
        .into_iter()
        .find(|p| p.addr.ip() == Some(ip))
        .map(|p| p.score)
}

/// RT3-TM2P2P F1 (introduced by the RT2 tracker): after an id's first
/// timeout up to 4 announcers are asked in parallel, but the first answer
/// `forget`s every record of the id, so the other honest announcers'
/// answers, which this node requested, arrive as unrequested transactions
/// (+10 each, never decayed). Here 5 silent inbound peers announce 10
/// transactions first; two honest announcers (warmed up by one answer
/// each, so they have request room) announce them after. At the first
/// timeout both honest peers are asked for all 10; H1 answers at once, H2
/// 1 s later: H2 collects 10 x 10 = 100 points and is disconnected (and,
/// off loopback, banned for a day). Any id whose first request times out
/// does this, so an attacker needs only to announce first and stay silent
/// to have this node disconnect its honest peers. Fixed in 19f6690; now
/// a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt3_parallel_answers_of_honest_announcers_are_not_penalized() {
    init_test_log();
    const N: usize = 10;
    let mut v = node(240, &[]).await;
    v.mine_n(N as u64 + 2 + 65, 0);
    let txs: Vec<Transaction> = (0..N).map(|n| v.payment_nth(n)).collect();
    let warm: Vec<Transaction> = (N..N + 2).map(|n| v.payment_nth(n)).collect();
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let nid = params().network_id;
    // Five silent attackers, two ids each (two requests fit before a
    // peer's first answer).
    let mut silent = Vec::new();
    for k in 0..5u8 {
        let (r, mut w) = raw_peer_from([127, 0, 5, 10 + k], v.addr, nid, 0)
            .await
            .expect("attacker");
        let mine = ids[2 * k as usize..2 * k as usize + 2].to_vec();
        w.send(&Message::InvTx(mine).encode()).await.unwrap();
        silent.push(silent_announcer(r, Arc::new(tokio::sync::Mutex::new(w))));
    }
    wait_until("every id asked of an attacker", 10, || {
        silent
            .iter()
            .map(|a| a.lock().unwrap().len())
            .sum::<usize>()
            >= N
    })
    .await;
    // Two honest announcers, each warmed up with one answer.
    let mut honest = Vec::new();
    for (k, delay) in [(0u8, Duration::ZERO), (1, Duration::from_secs(1))] {
        let ip = [127, 0, 5, 50 + k];
        let (r, mut w) = raw_peer_from(ip, v.addr, nid, 0).await.expect("honest");
        let mut all = txs.clone();
        all.push(warm[k as usize].clone());
        w.send(&Message::InvTx(vec![warm[k as usize].hash()]).encode())
            .await
            .unwrap();
        let w = Arc::new(tokio::sync::Mutex::new(w));
        let asked = delayed_announcer(r, w.clone(), all, delay);
        let wid = warm[k as usize].hash();
        wait_until("warm-up pooled", 20, || v.mempool_has(&wid)).await;
        w.lock()
            .await
            .send(&Message::InvTx(ids.clone()).encode())
            .await
            .unwrap();
        honest.push((ip, asked));
    }
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(50) && !ids.iter().all(|id| v.mempool_has(id)) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // Let the slower honest answers arrive.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let pooled = ids.iter().filter(|id| v.mempool_has(id)).count();
    let asked: Vec<usize> = honest
        .iter()
        .map(|(_, a)| a.lock().unwrap().iter().filter(|x| ids.contains(x)).count())
        .collect();
    let scores: Vec<Option<u32>> = honest.iter().map(|(ip, _)| score_from(&v, *ip)).collect();
    eprintln!(
        "RT3 parallel: after {:?}: pooled {pooled} of {N}; honest asked {asked:?}; honest scores \
         {scores:?} (None: disconnected); misbehaving disconnects {}",
        t0.elapsed(),
        v.net.stats().misbehaving_disconnects
    );
    assert_eq!(pooled, N);
    assert_eq!(
        scores,
        vec![Some(0), Some(0)],
        "honest announcers that answered our requests are connected and unpenalized"
    );
}

/// RT3-TM2P2P F1b (the retry-once of RT2): a request that times out is
/// asked again of the same peer, which serves both. On a slow link (a PX
/// answer of 2.2 MB takes 34 s at 64 KiB/s) the second copy arrives after
/// the late-answer window (30 s after the first expiry), as an
/// unrequested transaction: +10 for an honest peer, for each such
/// transaction, on top of the doubled transfer. Simulated with a v1
/// transaction: the first answer 38 s after the first request, the second
/// 30 s later (a serial server on a slow link). Fixed in 19f6690; now
/// a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt3_a_slow_honest_announcer_is_not_penalized_for_the_retry() {
    init_test_log();
    let mut v = node(242, &[]).await;
    v.mine_n(80, 0);
    let tx = v.payment();
    let id = tx.hash();
    let nid = params().network_id;
    let ip = [127, 0, 4, 50];
    let (mut r, w) = raw_peer_from(ip, v.addr, nid, 0).await.expect("honest");
    let w = Arc::new(tokio::sync::Mutex::new(w));
    w.lock()
        .await
        .send(&Message::InvTx(vec![id]).encode())
        .await
        .unwrap();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let t0 = std::time::Instant::now();
    {
        let (w, asked, tx) = (w.clone(), asked.clone(), tx.clone());
        tokio::spawn(async move {
            let mut served = 0u32;
            while let Ok(frame) = r.recv().await {
                match Message::decode(&frame) {
                    Ok(Message::Ping(n)) => {
                        let _ = w.lock().await.send(&Message::Pong(n).encode()).await;
                    }
                    Ok(Message::GetTx(ids)) if ids.contains(&tx.hash()) => {
                        asked.lock().unwrap().push(t0.elapsed());
                        // The serial slow server: the first copy at 38 s,
                        // each further one 30 s later.
                        served += 1;
                        let at = Duration::from_secs(38) + Duration::from_secs(30) * (served - 1);
                        let (w, tx) = (w.clone(), tx.clone());
                        tokio::spawn(async move {
                            tokio::time::sleep(at.saturating_sub(t0.elapsed())).await;
                            let m = Message::Tx(tx.encode()).encode();
                            let _ = w.lock().await.send(&m).await;
                        });
                    }
                    _ => {}
                }
            }
        });
    }
    while t0.elapsed() < Duration::from_secs(75) {
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let score = score_from(&v, ip);
    eprintln!(
        "RT3 retry: asked at {:?}; pooled {}; score {score:?}",
        asked.lock().unwrap(),
        v.mempool_has(&id)
    );
    assert!(v.mempool_has(&id));
    assert_eq!(score, Some(0), "an honest slow announcer is not penalized");
}

/// Copies `r` to `w` at `rate` bytes per second (4 KiB chunks, paced).
async fn paced_pipe(
    mut r: impl tokio::io::AsyncRead + Unpin,
    mut w: impl tokio::io::AsyncWrite + Unpin,
    rate: usize,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 4096];
    let mut next = tokio::time::Instant::now();
    loop {
        let n = match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let now = tokio::time::Instant::now();
        if next < now {
            next = now;
        }
        next += Duration::from_secs_f64(n as f64 / rate as f64);
        tokio::time::sleep_until(next).await;
        if w.write_all(&buf[..n]).await.is_err() {
            break;
        }
    }
    let _ = w.shutdown().await;
}

/// A loopback TCP proxy to `target` carrying each direction at `rate`
/// bytes per second: a slow link (a Tor circuit, a home uplink).
async fn throttled_proxy(target: SocketAddr, rate: usize) -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((a, _)) = l.accept().await {
            let Ok(b) = TcpStream::connect(target).await else {
                continue;
            };
            let (ar, aw) = tokio::io::split(a);
            let (br, bw) = tokio::io::split(b);
            tokio::spawn(paced_pipe(ar, bw, rate));
            tokio::spawn(paced_pipe(br, aw, rate));
        }
    });
    addr
}

/// RT3-TM2P2P F3 (serving on slow links): two honest nodes over a 1 Mbit/s
/// link (125 kB/s, about twice `SLOW_RATE`, a common Tor circuit). The
/// server pools 3 PX transactions and re-announces them; the requester asks
/// for them (2, then 3 at a time: its expected answer size). Pings and
/// pongs queue behind the `Tx` answers in the same FIFO outbox, and
/// `PONG_TIMEOUT` is 30 s from when the ping was queued: 2 PX answers
/// (4.4 MB) take 35 s on this link, so the link is cut by a pong timeout
/// although the reader keeps well above `SLOW_RATE`. Each cut re-draws the
/// requester's Dandelion stem peers. Pings every 5 s here (60 s by
/// default: then a ping lands in such a transfer with probability about
/// transfer time / 60 s). Fixed in 19f6690; now a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PX proving (4-6 GB); run alone"]
async fn rt3_px_answers_over_a_1_mbit_link_keep_the_link() {
    init_test_log();
    const N: usize = 3;
    let mut cfg = fast_config(&[]);
    cfg.ping_interval = Duration::from_secs(5);
    cfg.trickle_inbound = Duration::from_secs(1);
    let mut a = node_with(250, cfg).await;
    a.mine_n(80, 0);
    let t0 = std::time::Instant::now();
    let txs: Vec<Transaction> = (0..N).map(|n| a.px_deposit_nth(5_000_000, n)).collect();
    eprintln!(
        "RT3 slow link: {N} PX built in {:?}, sizes {:?}",
        t0.elapsed(),
        txs.iter().map(|t| t.encode().len()).collect::<Vec<_>>()
    );
    {
        let mut c = a.chain.lock().unwrap();
        for t in &txs {
            c.submit_tx(t.clone()).unwrap();
        }
    }
    let proxy = throttled_proxy(a.addr, 125_000).await;
    let mut cfg = fast_config(&[proxy]);
    cfg.ping_interval = Duration::from_secs(5);
    let b = node_with(251, cfg).await;
    for h in 1..=a.height() {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
    }
    wait_until("connected", 60, || {
        a.net.stats().peers == 1 && b.net.stats().outbound == 1
    })
    .await;
    let link = b.net.peers()[0].id;
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        let blk = a.mine_with(0, false);
        give_block(&b, &blk).await;
    }
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let t0 = std::time::Instant::now();
    let mut links = vec![link];
    while t0.elapsed() < Duration::from_secs(150) && !ids.iter().all(|id| b.mempool_has(id)) {
        if let Some(p) = b.net.peers().first() {
            if !links.contains(&p.id) {
                links.push(p.id);
                eprintln!("RT3 slow link: new connection at {:?}", t0.elapsed());
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let pooled = ids.iter().filter(|id| b.mempool_has(id)).count();
    eprintln!(
        "RT3 slow link: after {:?}: pooled {pooled} of {N}; connections {}; a {:?}; b {:?}; \
         scores {:?}",
        t0.elapsed(),
        links.len(),
        a.net.stats(),
        b.net.stats(),
        penalized(&[&a, &b])
    );
    assert_eq!(pooled, N, "relayed over the slow link");
    assert_eq!(links, vec![link], "the same connection throughout");
    assert!(penalized(&[&a, &b]).is_empty());
}

/// RT3-TM2P2P F1 under a real burst: two honest announcers whose last
/// answer was a small v1 transaction (expected size 8 KiB: up to 16
/// requests at once) announce 4 PX transactions. The requester asks each
/// of them for its share at once; their answers (2.2 MB each) overflow the
/// requester's per-peer slow lane (two PX fit) and are dropped there; the
/// dropped requests time out, the parallel fallback asks both announcers,
/// and the first answer makes the other's (requested) answer unrequested:
/// +10. Fixed in 19f6690; now a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "PX proving (4-6 GB); run alone"]
async fn rt3_a_mixed_px_burst_from_two_honest_announcers_is_not_penalized() {
    init_test_log();
    const N: usize = 4;
    let mut a = node(252, &[]).await;
    a.mine_n(80, 0);
    let t0 = std::time::Instant::now();
    let txs: Vec<Transaction> = (0..N).map(|n| a.px_deposit_nth(5_000_000, n)).collect();
    eprintln!("RT3 mixed burst: {N} PX built in {:?}", t0.elapsed());
    let warm: Vec<Transaction> = (N..N + 2).map(|n| a.payment_nth(n)).collect();
    let v = node(253, &[]).await;
    for h in 1..=a.height() {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&v, &blk).await;
    }
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let nid = params().network_id;
    let mut honest = Vec::new();
    for (k, delay) in [(0u8, Duration::ZERO), (1, Duration::from_millis(500))] {
        let ip = [127, 0, 3, 50 + k];
        let (r, mut w) = raw_peer_from(ip, v.addr, nid, 0).await.expect("honest");
        let mut all = txs.clone();
        all.push(warm[k as usize].clone());
        w.send(&Message::InvTx(vec![warm[k as usize].hash()]).encode())
            .await
            .unwrap();
        let w = Arc::new(tokio::sync::Mutex::new(w));
        let asked = delayed_announcer(r, w.clone(), all, delay);
        let wid = warm[k as usize].hash();
        wait_until("warm-up pooled", 30, || v.mempool_has(&wid)).await;
        honest.push((ip, w, asked));
    }
    for (_, w, _) in &honest {
        w.lock()
            .await
            .send(&Message::InvTx(ids.clone()).encode())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(120) && !ids.iter().all(|id| v.mempool_has(id)) {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    tokio::time::sleep(Duration::from_secs(5)).await;
    let pooled = ids.iter().filter(|id| v.mempool_has(id)).count();
    let asked: Vec<usize> = honest
        .iter()
        .map(|(_, _, a)| a.lock().unwrap().iter().filter(|x| ids.contains(x)).count())
        .collect();
    let scores: Vec<Option<u32>> = honest
        .iter()
        .map(|(ip, _, _)| score_from(&v, *ip))
        .collect();
    eprintln!(
        "RT3 mixed burst: after {:?}: pooled {pooled} of {N}; asked {asked:?}; scores {scores:?}; \
         stats {:?}",
        t0.elapsed(),
        v.net.stats()
    );
    assert_eq!(pooled, N);
    assert_eq!(scores, vec![Some(0), Some(0)]);
}

// ------------------------------------------------------ RT4-TM2P2P red team

/// The ids of every `InvTx` read on `r` within `secs` (in order).
async fn inv_ids_for(r: &mut RawReader, secs: f64) -> Vec<Hash> {
    let mut ids = Vec::new();
    let end = tokio::time::Instant::now() + Duration::from_secs_f64(secs);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, r.recv()).await {
            Ok(Ok(f)) => {
                if let Ok(Message::InvTx(v)) = Message::decode(&f) {
                    ids.extend(v);
                }
            }
            _ => break,
        }
    }
    ids
}

/// One spy session from `ip` to `n`: connect, read the announcements for
/// `secs`, disconnect (and wait until `n` saw it go).
async fn spy_session(n: &TestNode, ip: [u8; 4], secs: f64) -> Vec<Hash> {
    let nid = params().network_id;
    let before = n.net.stats().peers;
    let (mut r, w) = raw_peer_from(ip, n.addr, nid, 0).await.expect("spy");
    wait_until("spy registered", 30, || n.net.stats().peers == before + 1).await;
    let ids = inv_ids_for(&mut r, secs).await;
    drop((r, w));
    wait_until("spy gone", 30, || n.net.stats().peers == before).await;
    ids
}

/// RT4-TM2P2P (privacy): the reconnect re-announcement (RT3 F3) tells any
/// peer that reconnects from the same host within 10 minutes the node's
/// whole pool (up to 5 000 ids), which a fresh connection is never told,
/// in the iteration order of the pool's `HashMap`: a random order fixed
/// per node (its hasher's seed), not per connection. Two sessions to the
/// same node, from two addresses (a clearnet and an onion identity of one
/// dual-homed node, or one node before and after an address change) read
/// the same permutation of the same pool; another node with the same pool
/// reads another. With 24 transactions a chance match is about 1 in 24!.
/// Every onion inbound peer has the same host (the Tor daemon's loopback),
/// so through the onion listener any connection made within 10 minutes of
/// any onion peer leaving is told the pool. Fixed in 4fb8536; now a regression
/// test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt4_a_reconnecting_spy_reads_the_pool_in_an_order_that_names_the_node() {
    init_test_log();
    const N: usize = 24;
    let mut a = node(270, &[]).await;
    a.mine_n(N as u64 + 66, 0);
    let txs: Vec<Transaction> = (0..N).map(|n| a.payment_nth(n)).collect();
    let b = node(271, &[]).await;
    for h in 1..=a.height() {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
    }
    for t in &txs {
        a.chain.lock().unwrap().submit_tx(t.clone()).unwrap();
        b.chain.lock().unwrap().submit_tx(t.clone()).unwrap();
    }
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let mut fresh = Vec::new();
    let mut again = Vec::new();
    for (n, ips) in [
        (&a, [[127, 0, 8, 1], [127, 0, 8, 2]]),
        (&b, [[127, 0, 8, 3], [127, 0, 8, 4]]),
    ] {
        for ip in ips {
            fresh.push(spy_session(n, ip, 2.0).await);
            again.push(spy_session(n, ip, 2.0).await);
        }
    }
    let told: Vec<usize> = again
        .iter()
        .map(|l| l.iter().filter(|i| ids.contains(i)).count())
        .collect();
    let same_node = again[0] == again[1];
    let other_node = again[0] != again[2] && again[2] == again[3];
    eprintln!(
        "RT4 reconnect: fresh sessions told {:?} ids; reconnects told {told:?} of {N}; node A \
         sessions in the same order: {same_node}; node B order differs and is its own: \
         {other_node}",
        fresh.iter().map(Vec::len).collect::<Vec<_>>()
    );
    assert!(
        fresh.iter().all(Vec::is_empty),
        "control: a fresh peer is told nothing"
    );
    assert!(
        !(told.iter().all(|&n| n == N) && same_node && other_node),
        "a reconnecting spy reads the whole pool in a per-node order"
    );
}

/// RT4-TM2P2P (privacy, control): the reconnect re-announcement does not
/// tell an origin from a relay. The origin holds its transaction in its
/// stempool (a stem peer that swallows it, a long embargo), a stem relay
/// holds the same transaction the same way; a reconnecting spy is told it
/// by neither. Once it diffuses back (an `InvTx` from the stem peer), both
/// pool it and both re-announce it to a reconnecting spy.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt4_the_reconnect_reannouncement_does_not_tell_an_origin_from_a_relay() {
    init_test_log();
    let mut cfg = fast_config(&[]);
    cfg.max_outbound = 1;
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut o = node_with(272, cfg.clone()).await;
    o.mine_n(80, 0);
    let r = node_with(273, cfg).await;
    for h in 1..=o.height() {
        let blk = o.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&r, &blk).await;
    }
    let lo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lr = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut o_stem_r, mut o_stem_w) = dialed_raw_peer(&o, &lo).await;
    let (mut r_stem_r, mut r_stem_w) = dialed_raw_peer(&r, &lr).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tx = o.payment();
    let id = tx.hash();
    o.net.submit_tx(tx.clone()).await.unwrap();
    assert!(
        recv_until(&mut o_stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "the origin stems it"
    );
    // The relay gets it as a stem hop from an inbound peer.
    let nid = params().network_id;
    let (_sr, mut sw) = raw_peer_from([127, 0, 8, 20], r.addr, nid, 0)
        .await
        .expect("stem sender");
    wait_until("stem sender registered", 30, || r.net.stats().peers == 2).await;
    sw.send(&Message::StemTx(tx.encode()).encode())
        .await
        .unwrap();
    assert!(
        recv_until(&mut r_stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "the relay stems it"
    );
    let mut stem_phase = Vec::new();
    for (n, ip) in [(&o, [127, 0, 8, 21]), (&r, [127, 0, 8, 22])] {
        let _ = spy_session(n, ip, 1.0).await;
        stem_phase.push(spy_session(n, ip, 2.0).await.contains(&id));
    }
    // It diffuses back: each stem peer announces it and serves it.
    for (n, sr, swr) in [
        (&o, &mut o_stem_r, &mut o_stem_w),
        (&r, &mut r_stem_r, &mut r_stem_w),
    ] {
        swr.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
        assert!(recv_until(
            sr,
            30.0,
            |m| matches!(m, Message::GetTx(ids) if ids.contains(&id))
        )
        .await
        .is_some());
        swr.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
        wait_until("pooled", 30, || n.mempool_has(&id)).await;
    }
    let mut pooled_phase = Vec::new();
    for (n, ip) in [(&o, [127, 0, 8, 21]), (&r, [127, 0, 8, 22])] {
        pooled_phase.push(spy_session(n, ip, 2.0).await.contains(&id));
    }
    eprintln!(
        "RT4 origin vs relay after a reconnect: told in the stem phase {stem_phase:?}; once \
         pooled {pooled_phase:?} (origin, relay)"
    );
    assert_eq!(stem_phase, vec![false, false]);
    // RT4 item 2: a reconnect is told only what its last connection was
    // owed, never the pool. The transaction was pooled while the spy was
    // away, so neither node owes it: neither tells (the same answer from
    // the origin and the relay, which is the property; before, both told
    // the whole pool).
    assert_eq!(pooled_phase, vec![false, false]);
}

/// A raw peer task that answers pings and every `GetTx` for one of `txs`
/// at once; counts the answers.
fn instant_answerer(
    mut r: RawReader,
    mut w: RawWriter,
    txs: std::collections::HashMap<Hash, Vec<u8>>,
    served: Arc<std::sync::atomic::AtomicUsize>,
) {
    tokio::spawn(async move {
        while let Ok(frame) = r.recv().await {
            match Message::decode(&frame) {
                Ok(Message::Ping(n)) => {
                    let _ = w.send(&Message::Pong(n).encode()).await;
                }
                Ok(Message::GetTx(ids)) => {
                    for id in ids {
                        if let Some(b) = txs.get(&id) {
                            if w.send(&Message::Tx(b.clone()).encode()).await.is_err() {
                                return;
                            }
                            served.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
                _ => {}
            }
        }
    });
}

/// RT4-TM2P2P (RT3 F1 reopened): the memory of requests whose answers stay
/// acceptable (`State::late_txs`) is one node-wide map of at most 10 000
/// (id, peer) pairs, and every answered request adds its own answerer to
/// it (`forget_tx`). A few inbound peers fill it in seconds, free: each
/// announces junk variants of a pooled transaction (its fee changed: same
/// key images, new id), the node asks for them, and each answer is a
/// conflict, dropped unpenalized (`Admit::Done`), whose request is
/// remembered. While the map is full nothing new is remembered, and RT3's
/// scenario is back: 5 silent announcers make the first requests time
/// out, two honest announcers are asked in parallel, and the second honest
/// answer is an unrequested `Tx` (+10 each: 10 transactions disconnect the
/// honest peer, and off loopback ban it for a day). Fixed in 4fb8536; now
/// a regression test.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt4_a_full_late_answer_memory_penalizes_parallel_honest_answers_again() {
    init_test_log();
    const N: usize = 10;
    const FILLERS: u8 = 23;
    const PER: u64 = 450;
    let mut v = node(274, &[]).await;
    v.mine_n(N as u64 + 3 + 65, 0);
    let txs: Vec<Transaction> = (0..N).map(|n| v.payment_nth(n)).collect();
    let warm: Vec<Transaction> = (N..N + 2).map(|n| v.payment_nth(n)).collect();
    let base = v.payment_nth(N + 2);
    v.chain.lock().unwrap().submit_tx(base.clone()).unwrap();
    let Transaction::Transfer(bt) = &base else {
        panic!("a transfer")
    };
    let nid = params().network_id;
    // Fill the late-answer memory.
    let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut fillers = Vec::new();
    for k in 0..FILLERS {
        let variants: std::collections::HashMap<Hash, Vec<u8>> = (0..PER)
            .map(|i| {
                let mut t = (**bt).clone();
                t.fee += 1 + u64::from(k) * PER + i;
                let t = Transaction::from(t);
                (t.hash(), t.encode())
            })
            .collect();
        let (r, mut w) = raw_peer_from([127, 0, 9, 10 + k], v.addr, nid, 0)
            .await
            .expect("filler");
        let ids: Vec<Hash> = variants.keys().copied().collect();
        w.send(&Message::InvTx(ids).encode()).await.unwrap();
        instant_answerer(r, w, variants, served.clone());
        fillers.push(k);
    }
    let t0 = std::time::Instant::now();
    let total = usize::from(FILLERS) * PER as usize;
    while t0.elapsed() < Duration::from_secs(120)
        && served.load(std::sync::atomic::Ordering::Relaxed) < total
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let filled = served.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!(
        "RT4 late memory: {filled} junk answers served in {:?}; misbehaving disconnects {}",
        t0.elapsed(),
        v.net.stats().misbehaving_disconnects
    );
    // RT3's scenario.
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    let mut silent = Vec::new();
    for k in 0..5u8 {
        let (r, mut w) = raw_peer_from([127, 0, 5, 10 + k], v.addr, nid, 0)
            .await
            .expect("attacker");
        let mine = ids[2 * k as usize..2 * k as usize + 2].to_vec();
        w.send(&Message::InvTx(mine).encode()).await.unwrap();
        silent.push(silent_announcer(r, Arc::new(tokio::sync::Mutex::new(w))));
    }
    wait_until("every id asked of an attacker", 10, || {
        silent
            .iter()
            .map(|a| a.lock().unwrap().len())
            .sum::<usize>()
            >= N
    })
    .await;
    let mut honest = Vec::new();
    for (k, delay) in [(0u8, Duration::ZERO), (1, Duration::from_secs(1))] {
        let ip = [127, 0, 5, 50 + k];
        let (r, mut w) = raw_peer_from(ip, v.addr, nid, 0).await.expect("honest");
        let mut all = txs.clone();
        all.push(warm[k as usize].clone());
        w.send(&Message::InvTx(vec![warm[k as usize].hash()]).encode())
            .await
            .unwrap();
        let w = Arc::new(tokio::sync::Mutex::new(w));
        let asked = delayed_announcer(r, w.clone(), all, delay);
        let wid = warm[k as usize].hash();
        wait_until("warm-up pooled", 20, || v.mempool_has(&wid)).await;
        w.lock()
            .await
            .send(&Message::InvTx(ids.clone()).encode())
            .await
            .unwrap();
        honest.push((ip, asked));
    }
    let t0 = std::time::Instant::now();
    while t0.elapsed() < Duration::from_secs(50) && !ids.iter().all(|id| v.mempool_has(id)) {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_secs(3)).await;
    let pooled = ids.iter().filter(|id| v.mempool_has(id)).count();
    let scores: Vec<Option<u32>> = honest.iter().map(|(ip, _)| score_from(&v, *ip)).collect();
    let filler_scores: Vec<Option<u32>> = fillers
        .iter()
        .map(|k| score_from(&v, [127, 0, 9, 10 + k]))
        .collect();
    eprintln!(
        "RT4 late memory: pooled {pooled} of {N}; honest scores {scores:?} (None: \
         disconnected); filler scores {filler_scores:?}"
    );
    assert_eq!(pooled, N);
    assert_eq!(
        scores,
        vec![Some(0), Some(0)],
        "honest announcers that answered our requests are unpenalized whatever others did"
    );
}

/// RT4-TM2P2P (liveness, measurement): a peer that stops reading but keeps
/// sending (so the 180 s idle timeout never fires) is cut by the pong
/// timeout, 192 s from when the ping was written since RT4 item 7 (128 s
/// after RT3; before RT3: 30 s from when it was queued). Pings every 2 s
/// here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt4_a_peer_that_never_reads_is_cut_by_the_pong_timeout() {
    init_test_log();
    let mut cfg = fast_config(&[]);
    cfg.ping_interval = Duration::from_secs(2);
    let v = node_with(275, cfg).await;
    let nid = params().network_id;
    let (r, mut w) = raw_peer_from([127, 0, 8, 30], v.addr, nid, 0)
        .await
        .expect("peer");
    wait_until("registered", 30, || v.net.stats().peers == 1).await;
    let t0 = std::time::Instant::now();
    let keep = tokio::spawn(async move {
        let mut n = 0u64;
        loop {
            tokio::time::sleep(Duration::from_secs(10)).await;
            n += 1;
            if w.send(&Message::Ping(n).encode()).await.is_err() {
                break;
            }
        }
    });
    while t0.elapsed() < Duration::from_secs(320) && v.net.stats().peers == 1 {
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let cut = t0.elapsed();
    keep.abort();
    drop(r);
    eprintln!("RT4 non-reading peer: cut after {cut:?} (ping interval 2 s)");
    // RT4 item 7: the timeout now also allows for 4 MiB buffered ahead of
    // the ping (192 s; RT4 measured the 128 s of RT3 here).
    assert!(
        cut >= Duration::from_secs(192) && cut < Duration::from_secs(204),
        "{cut:?}"
    );
}

/// RT4 item 2: a host that reconnects is told what its last connection was
/// owed (announced to it and not asked for), and nothing else; another
/// host is told nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_reconnecting_host_is_told_only_what_it_was_owed() {
    let mut a = node(276, &[]).await;
    a.mine_n(80, 0);
    let owed = a.payment_nth(0);
    let other = a.payment_nth(1);
    a.chain.lock().unwrap().submit_tx(owed.clone()).unwrap();
    let nid = params().network_id;
    let ip = [127, 0, 6, 70];
    let (mut r, w) = raw_peer_from(ip, a.addr, nid, 0).await.expect("spy");
    wait_until("spy registered", 30, || a.net.stats().peers == 1).await;
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        a.mine_with(0, false);
    }
    assert!(
        recv_until(
            &mut r,
            30.0,
            |m| matches!(m, Message::InvTx(ids) if ids.contains(&owed.hash()))
        )
        .await
        .is_some(),
        "announced (the pool's re-announcement at age 10)"
    );
    // Pooled after the spy was told: never owed to it.
    a.chain.lock().unwrap().submit_tx(other.clone()).unwrap();
    drop((r, w));
    wait_until("spy gone", 30, || a.net.stats().peers == 0).await;
    let again = spy_session(&a, ip, 3.0).await;
    let stranger = spy_session(&a, [127, 0, 6, 71], 3.0).await;
    assert_eq!(again, vec![owed.hash()], "only what it was owed");
    assert!(stranger.is_empty(), "another host: nothing");
}

// ------------------------------------------------------ RT5-TM2P2P red team

/// RT5-TM2P2P (privacy): the owed re-announcement with the transaction in
/// the owed set. RT4's control (`rt4_the_reconnect_reannouncement_does_not_
/// tell_an_origin_from_a_relay`) now asserts `[false, false]` because its
/// spy was away while the transaction was pooled, so the owed path never
/// carries it there. Here the spy stays connected while the origin and the
/// relay pool it (it diffuses back to both through their stem peers), is
/// told it (or has it queued), never asks, leaves and reconnects from the
/// same host: both must tell it again, alike.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rt5_an_owed_transaction_is_told_alike_by_the_origin_and_a_relay() {
    init_test_log();
    let mut cfg = fast_config(&[]);
    cfg.max_outbound = 1;
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut o = node_with(280, cfg.clone()).await;
    o.mine_n(80, 0);
    let r = node_with(281, cfg).await;
    for h in 1..=o.height() {
        let blk = o.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&r, &blk).await;
    }
    let lo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let lr = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut o_stem_r, mut o_stem_w) = dialed_raw_peer(&o, &lo).await;
    let (mut r_stem_r, mut r_stem_w) = dialed_raw_peer(&r, &lr).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let tx = o.payment();
    let id = tx.hash();
    o.net.submit_tx(tx.clone()).await.unwrap();
    assert!(
        recv_until(&mut o_stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "the origin stems it"
    );
    let nid = params().network_id;
    let (_sr, mut sw) = raw_peer_from([127, 0, 8, 40], r.addr, nid, 0)
        .await
        .expect("stem sender");
    wait_until("stem sender registered", 30, || r.net.stats().peers == 2).await;
    sw.send(&Message::StemTx(tx.encode()).encode())
        .await
        .unwrap();
    assert!(
        recv_until(&mut r_stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "the relay stems it"
    );
    // The spies connect now and stay while the transaction is pooled.
    let o_ip = [127, 0, 8, 41];
    let r_ip = [127, 0, 8, 42];
    let (mut o_spy_r, o_spy_w) = raw_peer_from(o_ip, o.addr, nid, 0).await.expect("spy");
    wait_until("spy at origin", 30, || o.net.stats().peers == 2).await;
    let (mut r_spy_r, r_spy_w) = raw_peer_from(r_ip, r.addr, nid, 0).await.expect("spy");
    wait_until("spy at relay", 30, || r.net.stats().peers == 3).await;
    for (n, sr, swr) in [
        (&o, &mut o_stem_r, &mut o_stem_w),
        (&r, &mut r_stem_r, &mut r_stem_w),
    ] {
        swr.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
        assert!(recv_until(
            sr,
            30.0,
            |m| matches!(m, Message::GetTx(ids) if ids.contains(&id))
        )
        .await
        .is_some());
        swr.send(&Message::Tx(tx.encode()).encode()).await.unwrap();
        wait_until("pooled", 30, || n.mempool_has(&id)).await;
    }
    // Told while connected (its trickle), never asked for.
    let told_live = vec![
        inv_ids_for(&mut o_spy_r, 4.0).await.contains(&id),
        inv_ids_for(&mut r_spy_r, 4.0).await.contains(&id),
    ];
    drop((o_spy_r, o_spy_w, r_spy_r, r_spy_w));
    wait_until("origin spy gone", 30, || o.net.stats().peers == 1).await;
    wait_until("relay spy gone", 30, || r.net.stats().peers == 2).await;
    let again = vec![
        spy_session(&o, o_ip, 3.0).await.contains(&id),
        spy_session(&r, r_ip, 3.0).await.contains(&id),
    ];
    eprintln!(
        "RT5 owed: told while connected {told_live:?}; told again on reconnect {again:?} \
         (origin, relay)"
    );
    assert_eq!(told_live, vec![true, true]);
    assert_eq!(
        again,
        vec![true, true],
        "owed alike by the origin and the relay"
    );
}
