//! Node liveness while the chain lock is held for a long time (research
//! dossier 34, Stage 0; findings F34-1 to F34-3).
//!
//! Every hold here is real: a [`common::stall::SlowStore`] stalls the append
//! of a block submitted through `submit_block_in_steps`, the path of the P2P
//! block worker and RPC `/block`, so the chain lock is held exactly where a
//! heavy block step, a reorganization or a slow disk would hold it. Nothing in
//! the node is instrumented.
//!
//! Test numbering (the Stage 0 assignment; the dossier's own numbers differ):
//!
//! | Here | Dossier | What stays live during a hold |
//! |---|---|---|
//! | L1 | L1 | a peer's own pongs while its `GetHeaders` waits for the chain |
//! | L2 | L3 | the maintenance loop (outbound dialing) |
//! | L3 | L4 | a new connection's handshake |
//! | L4, L5 | L5, L6 | RPC (`node/tests/rpc_liveness.rs`) |
//! | L6 | L2 | a peer's own pongs while its `InvTx` waits; per-peer order kept |
//!
//! L1, L2, L3 and L6 failed before Stage 1 (the per-peer slow lane, the
//! published chain summary and the chain-free maintenance loop) and run by
//! default since. Each prints what it measured (`-- --nocapture`).

mod common;

use blacksilk_p2p::message::Message;
use common::*;
use std::time::{Duration, Instant};

/// A hold past `PONG_TIMEOUT` (30 s), as a step of heavy blocks can take.
const LONG_HOLD: Duration = Duration::from_secs(40);
/// A hold past `HANDSHAKE_TIMEOUT` (10 s).
const HANDSHAKE_HOLD: Duration = Duration::from_secs(15);
/// A pong is "prompt" within this.
const PROMPT: f64 = 1.0;

/// Pings through `r`/`w` about once a second while `holder` holds the chain
/// lock; every pong must come within [`PROMPT`]. Returns the pings answered.
async fn pong_while_held(
    r: &mut RawReader,
    w: &mut RawWriter,
    holder: &common::stall::Holder,
    other: &mut Vec<Message>,
    what: &str,
) -> u64 {
    let mut n = 1000;
    let mut worst: f64 = 0.0;
    while holder.holding() {
        let t = pong_latency(r, w, n, 2.5, other).await.unwrap_or_else(|| {
            panic!(
                "{what}: no pong {n} within 2.5 s, {:.1} s into the hold",
                holder.started.elapsed().as_secs_f64()
            )
        });
        assert!(
            t < PROMPT,
            "{what}: pong {n} took {t:.2} s, {:.1} s into the hold",
            holder.started.elapsed().as_secs_f64()
        );
        worst = worst.max(t);
        n += 1;
        tokio::time::sleep(Duration::from_millis(900)).await;
    }
    println!(
        "{what}: {} pongs during a {:.1} s hold, worst {:.1} ms",
        n - 1000,
        holder.started.elapsed().as_secs_f64(),
        worst * 1000.0
    );
    n - 1000
}

/// Whether `m` is the reply to `get_headers_from_genesis` on a chain of at
/// least `height` blocks (a tip announcement carries one header).
fn headers_reply(m: &Message, height: u64) -> bool {
    matches!(m, Message::Headers(h) if h.len() as u64 >= height)
}

/// L1 (F34-1): a peer whose `GetHeaders` waits for the chain lock (held 40 s,
/// past `PONG_TIMEOUT`) still gets every one of its pings answered promptly,
/// and the `Headers` reply arrives once the hold ends. Before Stage 1 the read
/// loop was parked in the `GetHeaders` handler, so its pings sat unread.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l1_a_peers_own_pongs_flow_while_its_get_headers_waits() {
    let a = slow_node(0x11, fast_config(&[])).await;
    a.mine(3).await;
    let (mut r, mut w) = raw_peer(a.addr).await;
    let mut other = Vec::new();
    assert!(pong_latency(&mut r, &mut w, 1, 5.0, &mut other)
        .await
        .is_some());

    let holder = a.hold(LONG_HOLD).await;
    w.send(&get_headers_from_genesis()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pings = pong_while_held(&mut r, &mut w, &holder, &mut other, "L1").await;
    assert!(pings >= 20, "only {pings} pings during the hold");
    assert!(holder.join(), "the held block connects");

    let reply = other.iter().any(|m| headers_reply(m, 4))
        || recv_until(&mut r, 10.0, &mut other, |m| headers_reply(m, 4))
            .await
            .is_some();
    assert!(reply, "the waiting GetHeaders is answered after the hold");
    assert!(
        pong_latency(&mut r, &mut w, 1, 5.0, &mut other)
            .await
            .is_some(),
        "still connected"
    );
}

/// L6 (F34-1, dossier L2): the same with `InvTx`, and per-peer order is kept.
/// A peer sends `GetHeaders`, then `InvTx` for an unknown transaction, during
/// a 40 s hold. Its pings are answered promptly throughout; after the hold the
/// `Headers` reply comes first, then the `GetTx` request for the announced id.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l6_a_peers_own_pongs_flow_while_its_inv_tx_waits_and_order_is_kept() {
    let a = slow_node(0x16, fast_config(&[])).await;
    a.mine(3).await;
    let (mut r, mut w) = raw_peer(a.addr).await;
    let mut other = Vec::new();
    assert!(pong_latency(&mut r, &mut w, 1, 5.0, &mut other)
        .await
        .is_some());

    let id = [0x6b; 32];
    let holder = a.hold(LONG_HOLD).await;
    w.send(&get_headers_from_genesis()).await.unwrap();
    w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let pings = pong_while_held(&mut r, &mut w, &holder, &mut other, "L6").await;
    assert!(pings >= 20, "only {pings} pings during the hold");
    assert!(holder.join(), "the held block connects");

    let is_request = |m: &Message| matches!(m, Message::GetTx(ids) if ids == &vec![id]);
    if !other.iter().any(is_request) {
        let got = recv_until(&mut r, 10.0, &mut other, is_request).await;
        other.extend(got);
    }
    let reply = other.iter().position(|m| headers_reply(m, 4));
    let request = other.iter().position(is_request);
    assert!(request.is_some(), "the announced transaction is requested");
    assert!(reply.is_some(), "the GetHeaders is answered");
    assert!(
        reply < request,
        "per-peer order: Headers before GetTx; got {:?}",
        other.iter().map(Message::kind).collect::<Vec<_>>()
    );
}

/// L2 (F34-2, dossier L3): the maintenance loop keeps running during a hold.
/// The node keeps a manual peer connected; the "peer" is a listener that drops
/// every connection, so the node dials it again after its 10 s backoff. During
/// a 30 s hold the second dial still comes within 20 s of the first. Before Stage 1
/// the loop waited for the chain tip at every tick, so nothing was dialed (nor
/// pinged, timed out, fluffed or announced) until the hold ended.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l2_the_maintenance_loop_keeps_dialing_during_a_hold() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = slow_node(0x12, fast_config(&[listener.local_addr().unwrap()])).await;
    let (first, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .expect("the node dials its manual peer")
        .unwrap();
    let t0 = Instant::now();
    drop(first);

    let holder = a.hold(Duration::from_secs(30)).await;
    let again = tokio::time::timeout(
        Duration::from_secs(20).saturating_sub(t0.elapsed()),
        listener.accept(),
    )
    .await;
    let held = holder.holding();
    assert!(
        again.is_ok(),
        "no redial within 20 s of the first dial (hold still on: {held})"
    );
    println!(
        "L2: redialed {:.1} s after the first dial, during the hold",
        t0.elapsed().as_secs_f64()
    );
    assert!(held, "the redial happened during the hold");
    assert!(holder.release());
}

/// L3 (F34-3, dossier L4): a new peer completes its handshake within 1 s
/// during a hold longer than `HANDSHAKE_TIMEOUT`, and the node's `Version`
/// carries its header height from before or after the held block. Before
/// Stage 1 the node read the chain before sending `Version`, so no connection
/// completed during the hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn l3_a_handshake_completes_during_a_hold() {
    let a = slow_node(0x13, fast_config(&[])).await;
    a.mine(2).await;
    let (_, header_height) = a.heights().await;
    assert_eq!(header_height, 2);

    let holder = a.hold(HANDSHAKE_HOLD).await;
    let start = Instant::now();
    let done = raw_handshake(a.addr, 0, 1.0).await;
    let took = start.elapsed().as_secs_f64();
    let held = holder.holding();
    let (version, mut r, mut w) = done.unwrap_or_else(|| {
        panic!("no handshake within 1 s ({took:.2} s) of a hold (still on: {held})")
    });
    assert!(held, "the handshake completed during the hold");
    println!("L3: handshake in {:.1} ms during the hold", took * 1000.0);
    assert!(
        version.height == header_height || version.height == header_height + 1,
        "Version.height {} (header height {header_height})",
        version.height
    );
    assert!(holder.release());
    let mut other = Vec::new();
    assert!(
        pong_latency(&mut r, &mut w, 7, 5.0, &mut other)
            .await
            .is_some(),
        "the new peer stays connected"
    );
}

/// The fixture itself: a hold keeps the chain lock for its whole length,
/// connects its block when released, and an idle third peer (the P0-7
/// guarantee that holds today) is answered throughout.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_store_hold_keeps_the_chain_lock_and_idle_peers_stay_live() {
    let a = slow_node(0x10, fast_config(&[])).await;
    a.mine(1).await;
    let (mut r, mut w) = raw_peer(a.addr).await;
    let holder = a.hold(Duration::from_secs(20)).await;
    assert_eq!(holder.height, 2);
    let mut other = Vec::new();
    for n in 0..3 {
        let t = pong_latency(&mut r, &mut w, n, 2.5, &mut other)
            .await
            .expect("an idle peer's pong during the hold");
        assert!(t < PROMPT, "pong {n} took {t:.2} s");
        assert!(a.chain.try_lock().is_err(), "the chain lock is held");
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(holder.holding());
    assert!(holder.release(), "the held block connects");
    assert_eq!(a.heights().await, (2, 2));
    assert_eq!(a.ctl.stalls(), 1);
}

/// Control for L1, L3 and L6: without a hold, the same flows pass their
/// post-hold assertions (the reply shapes, the per-peer order and the
/// `Version` height), so a Stage 1 failure of those tests is about the hold.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_without_a_hold_the_replies_come_in_order() {
    let a = slow_node(0x17, fast_config(&[])).await;
    a.mine(4).await;
    let start = Instant::now();
    let (version, mut r, mut w) = raw_handshake(a.addr, 0, 1.0)
        .await
        .expect("a handshake within 1 s");
    assert!(start.elapsed() < Duration::from_secs(1));
    assert_eq!(version.height, 4);

    let id = [0x6c; 32];
    w.send(&get_headers_from_genesis()).await.unwrap();
    w.send(&Message::InvTx(vec![id]).encode()).await.unwrap();
    let mut other = Vec::new();
    let is_request = |m: &Message| matches!(m, Message::GetTx(ids) if ids == &vec![id]);
    let got = recv_until(&mut r, 5.0, &mut other, is_request).await;
    assert!(got.is_some(), "the announced transaction is requested");
    assert!(
        other.iter().any(|m| headers_reply(m, 4)),
        "Headers before GetTx; got {:?}",
        other.iter().map(Message::kind).collect::<Vec<_>>()
    );
    let t = pong_latency(&mut r, &mut w, 3, 2.5, &mut other)
        .await
        .expect("pong");
    assert!(t < PROMPT);
}

/// Control for L2: without a hold, the node dials its dropped manual peer
/// again within 20 s of the first dial (the 10 s backoff).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn control_without_a_hold_a_dropped_manual_peer_is_redialed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _a = slow_node(0x18, fast_config(&[listener.local_addr().unwrap()])).await;
    let (first, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .expect("the node dials its manual peer")
        .unwrap();
    let t0 = Instant::now();
    drop(first);
    let again = tokio::time::timeout(Duration::from_secs(20), listener.accept()).await;
    assert!(again.is_ok(), "no redial within 20 s");
    println!("redialed after {:.1} s", t0.elapsed().as_secs_f64());
}
