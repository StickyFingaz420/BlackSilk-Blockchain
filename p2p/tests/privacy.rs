//! The privacy regression suite (dossier 33 W1; threat model round 2,
//! TM2-P10 and cross-check G9; RES-FREEZE decision 4, "the privacy regression
//! suite as a gate"). Every change to transaction relay, Dandelion++, the
//! trickle, address relay or the transaction request tracker must keep these
//! tests passing (docs/p2p.md §8.2).
//!
//! Each test names the property it guards and the decision or finding it
//! comes from. Tests marked `#[ignore = "open: ..."]` describe a property the
//! code does NOT have yet: they fail when run with `--ignored`, which shows
//! that they detect the leak, and they are un-ignored by the change that
//! fixes it. No other assertion depends on timing: every wait is a generous
//! precondition (30 s), not a measurement. Everything else is deterministic
//! except three statistical tests: `inv_batches_list_ids_in_a_uniformly_random_order`
//! (false-failure probability about 1e-6 per run), and the trickle tests,
//! which compare receipt instants against a 250 ms bound
//! (`clearnet_and_onion_trickle_timers_are_independent`: about 3e-6 per run;
//! `inbound_peers_of_one_network_share_one_trickle_timer` fails only if one
//! maintenance pass's sends reach the spies more than 250 ms apart).
//!
//! Run: `cargo test -p blacksilk-p2p --test privacy` (and `-- --ignored`
//! for the open properties).

mod net_support;

use blacksilk_chain::actor::ActorConfig;
use blacksilk_consensus::Hash;
use blacksilk_p2p::addr::AddrEntry;
use blacksilk_p2p::message::Message;
use blacksilk_p2p::NetAddr;
use blacksilk_tx::types::Transaction;
use net_support::*;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::time::{Duration, Instant};

/// Answers pings and discards everything else on a raw connection until it
/// closes (a raw stem peer that must stay connected, and whose outbox must
/// never fill, while the test looks elsewhere).
fn drain(mut r: RawReader, mut w: RawWriter) {
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

/// Asserts that `r`'s connection is still open (a ping is answered
/// within 30 s) and that nothing received before the pong announces or
/// stems `id`: a "never announced" window passes vacuously if the node
/// dropped the spy (RT-ASUITE L1).
async fn connected_and_silent(r: &mut RawReader, w: &mut RawWriter, nonce: u64, id: &Hash) {
    w.send(&Message::Ping(nonce).encode()).await.unwrap();
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            let frame = r.recv().await.expect("the spy is still connected");
            let m = Message::decode(&frame).unwrap();
            if m == Message::Pong(nonce) {
                return;
            }
            got.push(m);
        }
    })
    .await
    .expect("the spy's ping is answered");
    assert!(
        !got.iter().any(|m| announces(m, id)
            || matches!(m, Message::StemTx(b) if Transaction::decode(b).is_ok_and(|t| t.hash() == *id))),
        "the spy learned the transaction: {got:?}"
    );
}

/// Whether `m` announces `id`.
fn announces(m: &Message, id: &Hash) -> bool {
    matches!(m, Message::InvTx(ids) if ids.contains(id))
}

/// Copies `from`'s blocks to `to` (directly, not over the network).
fn copy_chain(from: &TestNode, to: &TestNode) {
    let ca = from.chain.lock().unwrap();
    let mut cb = to.chain.lock().unwrap();
    for h in (cb.height() + 1)..=ca.height() {
        let block = ca.block_at(h).unwrap();
        let now = block.header.timestamp;
        cb.submit_block(block, now).unwrap();
    }
}

// ------------------------------------------------------- origin and the stem

/// Property: a local transaction created while the node has no stem peer is
/// held, and never announced to anyone, until it enters the stem through an
/// outbound peer; and that stem hop is the only thing an inbound peer (a
/// possible spy) could learn from, which it does not. Source: M4 (privacy
/// review), dossier 33 W1 ("held local tx never announced"), cross-check G9.
/// Companion of `network.rs` `a_local_transaction_waits_for_a_stem_peer`,
/// here with a raw stem peer so nothing fluffs it back.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_held_local_transaction_is_never_announced() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(301, cfg).await;
    a.mine_n(80, 0);
    let nid = params().network_id;
    let (mut spy, mut spy_w) = raw_peer(a.addr, nid, true).await;
    wait_until("spy registered", 30, || a.net.stats().peers == 1).await;
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx).await.unwrap();
    assert!(a.net.stempool_contains(&id), "held in the stempool");
    assert!(
        recv_until(&mut spy, 3.0, |m| announces(m, &id)
            || matches!(m, Message::StemTx(_)))
        .await
        .is_none(),
        "a held local transaction reached an inbound peer"
    );
    connected_and_silent(&mut spy, &mut spy_w, 0x51, &id).await;
    assert!(
        !a.mempool_has(&id),
        "a held local transaction was broadcast"
    );
    // A stem peer appears: the transaction goes to it as a `StemTx`, and
    // still to nobody else.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, _stem_w) = dialed_raw_peer(&a, &l).await;
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "the held transaction entered the stem"
    );
    assert!(
        recv_until(&mut spy, 2.0, |m| announces(m, &id)
            || matches!(m, Message::StemTx(_)))
        .await
        .is_none(),
        "the inbound peer learned the transaction from its origin"
    );
    connected_and_silent(&mut spy, &mut spy_w, 0x52, &id).await;
    assert!(a.net.stempool_contains(&id) && !a.mempool_has(&id));
}

/// Property: a node that is a diffuser for the epoch (it fluffs its peers'
/// stem transactions) still stems its OWN transaction and never diffuses it
/// itself. Otherwise a spy that sees a diffuser originate a fluff would know
/// the transaction is local. Source: Dandelion++ (Fanti et al. 2018, the
/// origin always stems), `Dandelion::route`, dossier 33 W1 ("a diffuser
/// still stems its own tx"), cross-check G9.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_diffuser_still_stems_its_own_transaction() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.fluff_probability = 1.0; // a diffuser in every epoch
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(302, cfg).await;
    a.mine_n(82, 0);
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, _stem_w) = dialed_raw_peer(&a, &l).await;
    wait_until("a stem peer", 30, || a.net.stem_peers().len() == 1).await;
    let nid = params().network_id;
    let (mut spy, mut spy_w) = raw_peer(a.addr, nid, true).await;
    wait_until("spy registered", 30, || a.net.stats().peers == 2).await;

    // The node is a diffuser: a peer's stem transaction is fluffed at once.
    let theirs = a.payment_nth(1);
    let theirs_id = theirs.hash();
    spy_w
        .send(&Message::StemTx(theirs.encode()).encode())
        .await
        .unwrap();
    wait_until("a peer's stem diffused", 30, || a.mempool_has(&theirs_id)).await;

    // Its own transaction goes into the stem, never to the inbound peer.
    let ours = a.payment_nth(0);
    let id = ours.hash();
    a.net.submit_tx(ours).await.unwrap();
    let got = recv_until(
        &mut stem_r,
        30.0,
        |m| matches!(m, Message::StemTx(b) if Transaction::decode(b).is_ok_and(|t| t.hash() == id)),
    )
    .await;
    assert!(
        got.is_some(),
        "the diffuser did not stem its own transaction"
    );
    assert!(
        recv_until(&mut spy, 3.0, |m| announces(m, &id))
            .await
            .is_none(),
        "the diffuser announced its own transaction"
    );
    connected_and_silent(&mut spy, &mut spy_w, 0x53, &id).await;
    assert!(a.net.stempool_contains(&id) && !a.mempool_has(&id));
}

// ------------------------------------------------- TM2-P1: re-announcement

/// TM2-P1 (threat model round 2, privacy): the origin of a transaction
/// re-announces it at the same heights as every other node, also when a
/// block is found while the transaction is still in the stem. Every node
/// counts the pool age from the height it pooled the transaction for: a
/// relay pools it at the fluff, after that block. The origin counted from
/// its submission height (`min(relayed, admitted)`), one block earlier, so
/// it alone re-announced the transaction one block (about 2 minutes) before
/// every other node: a spy opening fresh connections learned the origin
/// with certainty for any transaction unmined 10 blocks after submission.
/// On a144d94 the origin's first re-announcement was at next height 91,
/// the relay's at 92. (Moved here from `network.rs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_block_found_during_the_stem_does_not_make_the_origin_reannounce_first() {
    // The origin: one outbound peer (the raw stem peer), and no embargo
    // fluff of its own within the test.
    let mut cfg = fast_config(&[]);
    cfg.max_outbound = 1;
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(87, cfg).await;
    a.mine_n(80, 0);
    // A relay, dialing the origin (an inbound peer there: never a stem).
    let mut b = node(88, &[a.addr]).await;
    for h in 1..=80 {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
    }
    wait_until_d(
        "relay connected",
        30,
        || a.net.stats().peers == 1,
        || peer_list(&a),
    )
    .await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, mut stem_w) = dialed_raw_peer(&a, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx.clone()).await.unwrap(); // relayed for next height 81
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some(),
        "originated into the stem"
    );
    // A block is found while the transaction is in the stem.
    let blk = a.mine_with(0, false);
    give_block(&b, &blk).await;
    // The stem ends beyond the raw stem peer: the fluff reaches the origin
    // as an announcement, then the relay.
    stem_w
        .send(&Message::InvTx(vec![id]).encode())
        .await
        .unwrap();
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::GetTx(_)))
            .await
            .is_some(),
        "the origin requests its own transaction like any node"
    );
    stem_w
        .send(&Message::Tx(tx.encode()).encode())
        .await
        .unwrap();
    wait_until("pooled everywhere", 30, || {
        a.mempool_has(&id) && b.mempool_has(&id)
    })
    .await;
    for n in [&a, &b] {
        assert_eq!(n.chain.lock().unwrap().mempool().admitted_at(&id), Some(82));
    }
    // Fresh spy connections (a spy may reconnect at will).
    let nid = params().network_id;
    let (mut spy_a, mut wa) = raw_peer(a.addr, nid, true).await;
    let (mut spy_b, mut wb) = raw_peer(b.addr, nid, true).await;
    wait_until("spies registered", 30, || {
        a.net.stats().peers == 3 && b.net.stats().peers == 2
    })
    .await;
    let first = first_reannouncements(
        &mut [&mut a, &mut b],
        &mut [(&mut spy_a, &mut wa), (&mut spy_b, &mut wb)],
        id,
        93,
    )
    .await;
    assert_eq!(
        first[0], first[1],
        "the origin re-announces exactly when the relay does (origin, relay)"
    );
    assert_eq!(first[1], Some(92), "pool age 10 from the fluff at 82");
}

/// TM2-P1, reorganization variant (cross-check X6): a transaction returned
/// by a reorganization is readmitted at the reorganization's height on
/// every node, and every node, the origin included, re-announces it on the
/// schedule from there. The origin counted from `min(relayed, admitted)`,
/// its relay height for about 2,190 blocks: after a reorganization 10 or
/// more blocks past the relay height it re-announced at once, and no other
/// node did (a majority-hash attacker can cause that at will). Here the
/// branch of 11 blocks reorganizes at its second block, so both nodes
/// readmit the transaction for 83 and are due at 93; on a144d94 the origin
/// re-announced during the reorganization, at 91 (seen at next height 92),
/// a block before the relay. (Moved here from `network.rs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn after_a_reorganization_the_origin_reannounces_with_everyone() {
    let mut cfg = fast_config(&[]);
    cfg.max_outbound = 1;
    let mut a = node_with(92, cfg).await;
    a.mine_n(80, 0);
    let mut b = node(93, &[a.addr]).await;
    // A competing branch from height 80, mined elsewhere: 11 blocks.
    let mut c = node(94, &[]).await;
    for h in 1..=80 {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&b, &blk).await;
        give_block(&c, &blk).await;
    }
    c.mine_n(11, 1);
    wait_until_d(
        "relay connected",
        30,
        || a.net.stats().peers == 1,
        || peer_list(&a),
    )
    .await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, mut stem_w) = dialed_raw_peer(&a, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx.clone()).await.unwrap(); // relayed for next height 81
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
    wait_until("pooled everywhere", 30, || {
        a.mempool_has(&id) && b.mempool_has(&id)
    })
    .await;
    // Mined at 81, then the branch of 11 blocks reorganizes it out (at
    // its second block, the first with more work).
    let blk = a.mine(0);
    assert!(blk.txs.iter().any(|t| t.hash() == id), "mined");
    give_block(&b, &blk).await;
    let nid = params().network_id;
    let (mut spy_a, mut wa) = raw_peer(a.addr, nid, true).await;
    let (mut spy_b, mut wb) = raw_peer(b.addr, nid, true).await;
    wait_until("spies registered", 30, || {
        a.net.stats().peers == 3 && b.net.stats().peers == 2
    })
    .await;
    // Both maintenance loops saw 82 (re-announcement counts from the
    // second height a loop sees).
    settled(&a, 82).await;
    settled(&b, 82).await;
    for h in 81..=91 {
        let blk = c.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&a, &blk).await;
        give_block(&b, &blk).await;
    }
    wait_until("readmitted everywhere", 30, || {
        a.mempool_has(&id) && b.mempool_has(&id)
    })
    .await;
    for n in [&a, &b] {
        assert_eq!(n.tip(), c.tip());
        assert_eq!(n.chain.lock().unwrap().mempool().admitted_at(&id), Some(83));
    }
    let first = first_reannouncements(
        &mut [&mut a, &mut b],
        &mut [(&mut spy_a, &mut wa), (&mut spy_b, &mut wb)],
        id,
        94,
    )
    .await;
    assert_eq!(
        first[0], first[1],
        "the origin re-announces exactly when the relay does (origin, relay)"
    );
    assert_eq!(first[1], Some(93), "pool age 10 from the readmission at 83");
}

/// TM2-P1, after a restart (Lead decisions, privacy first): a restarted
/// origin whose wallet resubmits its transaction accepts it but neither
/// stems, announces nor pools it (RT-TM2P2P item 3), so it never
/// re-announces it, while a relay that still pools it re-announces it on
/// the network's schedule. An origin re-announcing on schedule would show a
/// spy that saw it restart that it kept the transaction across the restart.
/// On a144d94 the restarted origin re-announced it at 91 (from its relay
/// height), a block before the relay; on 33a57af at 92, with the relay.
/// (Moved here from `network.rs`.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restarted_origin_never_reannounces_its_held_copy() {
    init_test_log();
    let dir = temp_data_dir("orig-anchor");
    let mut cfg = fast_config(&[]);
    cfg.data_dir = Some(dir.clone());
    cfg.max_outbound = 1;
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(89, cfg).await;
    a.mine_n(80, 0);
    // A relay, dialing the origin (an inbound peer there: never a stem).
    let relay = node(98, &[a.addr]).await;
    for h in 1..=80 {
        let blk = a.chain.lock().unwrap().block_at(h).unwrap();
        give_block(&relay, &blk).await;
    }
    wait_until_d(
        "relay connected",
        30,
        || a.net.stats().peers == 1,
        || peer_list(&a),
    )
    .await;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut stem_r, mut stem_w) = dialed_raw_peer(&a, &l).await;
    tokio::time::sleep(Duration::from_millis(300)).await; // an epoch with a stem
    let tx = a.payment();
    let id = tx.hash();
    a.net.submit_tx(tx.clone()).await.unwrap(); // relayed for next height 81
    assert!(
        recv_until(&mut stem_r, 30.0, |m| matches!(m, Message::StemTx(_)))
            .await
            .is_some()
    );
    let blk = a.mine_with(0, false);
    give_block(&relay, &blk).await;
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
    wait_until("pooled at the fluff", 30, || {
        a.mempool_has(&id) && relay.mempool_has(&id)
    })
    .await;
    assert_eq!(
        relay.chain.lock().unwrap().mempool().admitted_at(&id),
        Some(82)
    );
    for _ in 0..2 {
        let blk = a.mine_with(0, false);
        give_block(&relay, &blk).await;
    }
    let (mut b, b_dir) = restarted(&a, &dir, 90).await;
    let nid = params().network_id;
    let (mut spy_b, mut wb) = raw_peer(b.addr, nid, true).await;
    let (mut spy_r, mut wr) = raw_peer(relay.addr, nid, true).await;
    wait_until_d(
        "spies registered",
        30,
        || b.net.stats().peers == 1 && relay.net.stats().peers == 2,
        || format!("b: {}; relay: {}", peer_list(&b), peer_list(&relay)),
    )
    .await;
    assert_eq!(b.net.submit_tx(tx.clone()).await, Ok(id), "held");
    assert!(!b.mempool_has(&id), "a held copy is not pooled");
    assert!(!b.net.stempool_contains(&id));
    let mut relay = relay;
    let first = first_reannouncements(
        &mut [&mut b, &mut relay],
        &mut [(&mut spy_b, &mut wb), (&mut spy_r, &mut wr)],
        id,
        95,
    )
    .await;
    assert_eq!(first[0], None, "the restarted origin stays silent");
    assert_eq!(
        first[1],
        Some(92),
        "the relay re-announces from the fluff at 82"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&b_dir);
}

// ------------------------------------------------------ InvTx batch order

/// Pearson's chi-square statistic of a table of observed counts against a
/// uniform expectation per row.
fn chi_square_uniform_rows(table: &[Vec<u64>]) -> f64 {
    table
        .iter()
        .map(|row| {
            let n: u64 = row.iter().sum();
            let e = n as f64 / row.len() as f64;
            row.iter().map(|&o| (o as f64 - e).powi(2) / e).sum::<f64>()
        })
        .sum()
}

/// Property: the order of the ids in an `InvTx` batch says nothing about
/// the node (each id is equally likely at every position), so a spy cannot
/// recognize a node, or link two of its identities, by the order it lists
/// a set of transactions in. Source: RT4-TM2P2P (a reconnecting spy read
/// the pool in the pool's fixed hash order, a per-node fingerprint),
/// R8-16 / dossier 33 W5 ("shuffled inv batches"), RES-FREEZE decision 4
/// (Bitcoin Core PR #33464: invs are not sent in arrival order), cross-check
/// G9 ("InvTx uniformity").
///
/// Measured on the owed re-announcement to a reconnecting host (RT4 item
/// 2), which repeats the same set of ids once per session: 40 sessions,
/// 4 ids, the sum of the four rows' chi-square statistics of the
/// id-by-position counts. Every row and column sums to 40, so under a
/// uniform shuffle the statistic is distributed as (4/3)·χ²₉ (mean 12).
/// The bound 60 is χ²₉ at 45: p ≈ 9.2e-7 per run (RT-ASUITE L3). A uniform
/// shuffle scored 10 to 29 in five runs; any fixed order (one permutation
/// every time) scores 480.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inv_batches_list_ids_in_a_uniformly_random_order() {
    const N: usize = 4;
    const SESSIONS: usize = 40;
    let mut a = node(303, &[]).await;
    a.mine_n(N as u64 + 80, 0); // 16 mature decoys plus N to spend
    let txs: Vec<Transaction> = (0..N).map(|n| a.payment_nth(n)).collect();
    let ids: Vec<Hash> = txs.iter().map(Transaction::hash).collect();
    {
        let mut c = a.chain.lock().unwrap();
        for t in &txs {
            c.submit_tx(t.clone()).unwrap();
        }
    }
    let nid = params().network_id;
    let ip = [127, 0, 9, 1];
    // The pool's re-announcement at age 10 tells the spy all of them once.
    let (mut r, w) = raw_peer_from(ip, a.addr, nid, 0).await.expect("spy");
    wait_until("spy registered", 30, || a.net.stats().peers == 1).await;
    settled(&a, a.height() + 1).await;
    for _ in 0..10 {
        a.mine_with(0, false);
    }
    let mut told = std::collections::HashSet::new();
    tokio::time::timeout(Duration::from_secs(30), async {
        while told.len() < N {
            if let Message::InvTx(got) = Message::decode(&r.recv().await.unwrap()).unwrap() {
                told.extend(got.into_iter().filter(|i| ids.contains(i)));
            }
        }
    })
    .await
    .expect("every transaction announced");
    drop((r, w));
    wait_until("spy gone", 30, || a.net.stats().peers == 0).await;

    // Each reconnection is told the same set again (never asked for).
    let mut table = vec![vec![0u64; N]; N]; // [id][position]
    for _ in 0..SESSIONS {
        let (mut r, w) = raw_peer_from(ip, a.addr, nid, 0).await.expect("spy");
        let mut order: Vec<Hash> = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), async {
            while order.len() < N {
                if let Message::InvTx(got) = Message::decode(&r.recv().await.unwrap()).unwrap() {
                    for i in got {
                        if ids.contains(&i) && !order.contains(&i) {
                            order.push(i);
                        }
                    }
                }
            }
        })
        .await
        .expect("the owed ids told again");
        for (pos, i) in order.iter().enumerate() {
            let k = ids.iter().position(|x| x == i).unwrap();
            table[k][pos] += 1;
        }
        drop((r, w));
        wait_until("spy gone", 30, || a.net.stats().peers == 0).await;
    }
    let chi2 = chi_square_uniform_rows(&table);
    println!("InvTx position counts {table:?}, chi-square {chi2:.1}");
    assert!(
        chi2 < 60.0,
        "InvTx batches list ids in a recognizable order: {table:?} (chi-square {chi2:.1})"
    );
}

// --------------------------------------------------------------- GetAddr

/// A distinct public address (its own /16).
fn public_addr(i: u32) -> NetAddr {
    NetAddr::parse(&format!("{}.{}.9.1:29334", 30 + i, i)).unwrap()
}

/// Sends `msgs`, then a ping, and returns every message received up to the
/// pong (`GetAddr`, `Addr` and `Ping` are all handled on the read loop, in
/// order, so by then the node handled everything sent before the ping).
async fn send_then_ping(r: &mut RawReader, w: &mut RawWriter, msgs: &[Message]) -> Vec<Message> {
    for m in msgs {
        w.send(&m.encode()).await.unwrap();
    }
    let nonce = 0x5a5a_0001;
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

/// Property: `GetAddr` is answered only on inbound connections, never on a
/// connection the node dialed, and without a penalty for asking. A peer the
/// node dials could otherwise read back addresses it planted earlier and so
/// recognize the node across sessions, IP changes and Tor circuits
/// (Biryukov and Pustogarov, S&P 2015). Current rule:
/// `p2p/src/net/addr_relay.rs` `on_get_addr` (inbound and address-relay
/// only). Source: F32-4 / F33-5 part 1, dossier 33 W1 and W6, cross-check
/// G9 ("GetAddr inbound-only"). The per-network answer cache (33 W6 second
/// half, RES-FREEZE decision 4) is not implemented yet and not tested here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn getaddr_is_answered_only_to_inbound_peers() {
    let a = node(304, &[]).await;
    let nid = params().network_id;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let planted: Vec<NetAddr> = (0..5).map(public_addr).collect();
    // An inbound peer plants addresses.
    let (mut r1, mut w1) = raw_peer_from([127, 0, 9, 2], a.addr, nid, 0)
        .await
        .expect("planter");
    send_then_ping(
        &mut r1,
        &mut w1,
        &[Message::Addr(
            planted
                .iter()
                .map(|p| AddrEntry::new(now, p.clone()))
                .collect(),
        )],
    )
    .await;
    wait_until("addresses stored", 30, || {
        let (n, t) = a.net.stats().known_addresses;
        n + t >= 1
    })
    .await;
    // A peer the node dialed asks: no answer, no penalty.
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut ro, mut wo) = dialed_raw_peer(&a, &l).await;
    let got = send_then_ping(&mut ro, &mut wo, &[Message::GetAddr]).await;
    assert!(
        !got.iter().any(|m| matches!(m, Message::Addr(_))),
        "answered a GetAddr on a connection the node dialed: {got:?}"
    );
    assert!(
        a.net.peers().iter().all(|p| p.score == 0),
        "asking is not penalized: {:?}",
        a.net.peers()
    );
    // An inbound peer asks: answered, with planted addresses among them
    // (so the outbound silence above is not an empty table).
    let (mut ri, mut wi) = raw_peer_from([127, 0, 9, 3], a.addr, nid, 0)
        .await
        .expect("asker");
    let got = send_then_ping(&mut ri, &mut wi, &[Message::GetAddr]).await;
    let planted_told = got
        .iter()
        .filter_map(|m| match m {
            Message::Addr(list) => Some(list.iter().filter_map(AddrEntry::known)),
            _ => None,
        })
        .flatten()
        .filter(|a| planted.contains(a))
        .count();
    assert!(
        planted_told >= 1,
        "an inbound GetAddr was not answered with the stored addresses: {got:?}"
    );
}

// ------------------------------------------------------ open properties

/// One slow-lane probe: `msg`, then a `GetTx` barrier through the same
/// peer's slow lane; returns the seconds until the barrier's answer.
async fn probe(r: &mut RawReader, w: &mut RawWriter, msg: &[u8], nonce: u64) -> f64 {
    let (barrier, answered) = lane_barrier(nonce);
    let start = Instant::now();
    w.send(msg).await.unwrap();
    w.send(&barrier).await.unwrap();
    assert!(
        recv_until(r, 30.0, answered).await.is_some(),
        "barrier {nonce}"
    );
    start.elapsed().as_secs_f64()
}

/// OPEN (TM2-P6, F33-2 residual; cross-check P13, dossier 33 W7; P1).
/// Property: how long a node takes to answer a peer's later message must not
/// depend on whether a transaction that peer just sent as `StemTx` is in the
/// node's stempool. Today `on_stem_tx` returns at once for a held
/// transaction but verifies an unknown one on the peer's own slow lane, so a
/// `StemTx(X)` followed by any slow-lane request (here a `GetTx` barrier)
/// answers faster when X is held: a stempool membership oracle that tells a
/// spy which nodes a stem passed through.
///
/// The test sends 24 pairs of probes in a seeded random order, one with a
/// transaction already in the stempool and one with a fresh valid one, and
/// counts the pairs in which the unknown transaction answered later. With no
/// oracle that is a fair coin (at most 20 of 24 except with probability
/// below 0.1 %); today it is nearly every pair. Fails until verification
/// leaves the per-peer lane (34 Stage 4 direction).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "open: TM2-P6 / X1, P1 (the slow-lane stempool timing oracle)"]
async fn stem_membership_does_not_change_reply_latency() {
    const PAIRS: usize = 24;
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(600);
    let mut a = node_with(305, cfg).await;
    a.mine_n(PAIRS as u64 + 70, 0);
    let held = a.payment_nth(0);
    let fresh: Vec<Transaction> = (1..=PAIRS).map(|n| a.payment_nth(n)).collect();
    // A stem peer, so relayed stems stay in the stempool (600 s embargo).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (stem_r, stem_w) = dialed_raw_peer(&a, &l).await;
    drain(stem_r, stem_w);
    wait_until("a stem peer", 30, || a.net.stem_peers().len() == 1).await;
    let nid = params().network_id;
    let (mut r, mut w) = raw_peer(a.addr, nid, true).await;
    wait_until("spy registered", 30, || a.net.stats().peers == 2).await;
    let held_msg = Message::StemTx(held.encode()).encode();
    probe(&mut r, &mut w, &held_msg, 1).await;
    wait_until("held in the stempool", 30, || {
        a.net.stempool_contains(&held.hash())
    })
    .await;

    let mut order = ChaCha20Rng::seed_from_u64(0x7a6);
    let (mut slower, mut t_held, mut t_fresh) = (0usize, Vec::new(), Vec::new());
    for (i, t) in fresh.iter().enumerate() {
        let fresh_msg = Message::StemTx(t.encode()).encode();
        let nonce = 100 + 2 * i as u64;
        let (h, f) = if order.next_u32() & 1 == 0 {
            let h = probe(&mut r, &mut w, &held_msg, nonce).await;
            (h, probe(&mut r, &mut w, &fresh_msg, nonce + 1).await)
        } else {
            let f = probe(&mut r, &mut w, &fresh_msg, nonce).await;
            (probe(&mut r, &mut w, &held_msg, nonce + 1).await, f)
        };
        // The fresh transaction must have been verified and stemmed, but only
        // eventually: after the off-lane fix verification may finish after the
        // barrier, and this test measures the latency, not that ordering
        // (RT-ASUITE M1). Residual: even with verification off the lane, the held
        // path returns at the stempool check while the fresh one goes on to
        // hand off its checks (a microsecond-scale bias); re-check it against
        // the bound when un-ignoring.
        let fresh_id = t.hash();
        wait_until("the fresh transaction verified", 30, || {
            a.net.stempool_contains(&fresh_id)
        })
        .await;
        slower += usize::from(f > h);
        t_held.push(h);
        t_fresh.push(f);
    }
    let median = |v: &mut Vec<f64>| {
        v.sort_by(f64::total_cmp);
        v[v.len() / 2] * 1e3
    };
    println!(
        "TM2-P6: unknown slower in {slower}/{PAIRS} pairs; median held {:.2} ms, unknown {:.2} ms",
        median(&mut t_held),
        median(&mut t_fresh)
    );
    assert!(
        slower <= 20,
        "stempool membership shows in the reply latency: the unknown transaction \
         answered later in {slower} of {PAIRS} pairs"
    );
}

/// OPEN (X1, cross-check §1.2 and P3; TM2-P4; dossier 33 W3; RES-FREEZE
/// decision 4 "local re-stem"; P1, P0 for any public-testnet privacy claim).
/// Property: when the origin's first stem hop black-holes its transaction,
/// the origin is not the first node to announce it: it sends the
/// transaction once through its other stem peer before any fluff of its
/// own. Here the black hole is the X1 lever: a relay whose chain actor's Tx
/// lane is full (capacity 0) drops every relayed transaction unverified and
/// unscored (`verify_on_tx_lane`), so the stem dies at the first hop. Today
/// the origin's embargo fires and it fluffs to every peer, its other stem
/// peer receiving an `InvTx`, never a `StemTx`: the origin names itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "open: TM2-P6 / X1, P1 (the stem black hole through a full Tx lane)"]
async fn a_black_holed_local_transaction_is_restemmed_before_the_origin_fluffs() {
    let mut cfg = fast_config(&[]);
    cfg.dandelion.embargo_base = Duration::from_secs(8);
    cfg.dandelion.embargo_mean = Duration::from_secs(1);
    let mut o = node_with(306, cfg).await;
    o.mine_n(80, 0);
    // The black-holing first hop: a full Tx lane.
    let hole = node_with_actor(
        307,
        fast_config(&[]),
        ActorConfig {
            capacity: [64, 256, 1024, 0],
            ..ActorConfig::default()
        },
    )
    .await;
    copy_chain(&o, &hole);
    let nid = params().network_id;
    let (mut spy, _spy_w) = raw_peer(o.addr, nid, true).await;
    wait_until("spy registered", 30, || o.net.stats().peers == 1).await;
    o.net.connect(NetAddr::Ip(hole.addr));
    wait_until("the hole is the only stem peer", 30, || {
        o.net.stem_peers().len() == 1
    })
    .await;
    let tx = o.payment();
    let id = tx.hash();
    let submitted = Instant::now();
    o.net.submit_tx(tx).await.unwrap();
    wait_until("the first hop dropped it at its Tx lane", 30, || {
        hole.net.stats().tx_lane_drops >= 1
    })
    .await;
    // A second, honest stem peer (the route of the origin's own source
    // stays on the hole for the epoch).
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut other, _other_w) = dialed_raw_peer(&o, &l).await;
    wait_until("two stem peers", 30, || o.net.stem_peers().len() == 2).await;
    assert!(
        o.net.stempool_contains(&id),
        "precondition: still in the stem {:?} after submission (machine too slow?)",
        submitted.elapsed()
    );
    let spy_task = tokio::spawn(async move {
        recv_until(&mut spy, 60.0, |m| announces(m, &id))
            .await
            .map(|_| Instant::now())
    });
    let restem = recv_until(
        &mut other,
        60.0,
        |m| matches!(m, Message::StemTx(b) if Transaction::decode(b).is_ok_and(|t| t.hash() == id)),
    )
    .await
    .map(|_| Instant::now());
    let spy_at = spy_task.await.unwrap();
    assert!(
        restem.is_some(),
        "the origin never re-stemmed through its other stem peer (the spy saw it announced: {})",
        spy_at.is_some()
    );
    if let (Some(s), Some(r)) = (spy_at, restem) {
        assert!(r <= s, "the origin announced before it re-stemmed");
    }
}

// ---------------------------------------------------------------- Trickle

/// Two receipts closer than this were released by the same maintenance
/// pass: the release is one pass (one 50 ms tick), the rest is loopback
/// delivery and task scheduling, a few milliseconds.
const SAME_RELEASE: Duration = Duration::from_millis(250);

/// Pools payment `nth` of `a` and has `a` announce it to every peer at
/// once (its pool re-announcement at age 10, `relay::reannounce_pool`);
/// returns when each spy received the announcement, in `spies` order.
async fn release_instants(
    a: &mut TestNode,
    nth: usize,
    spies: &mut Vec<RawReader>,
) -> Vec<Instant> {
    let tx = a.payment_nth(nth);
    let id = tx.hash();
    settled(a, a.height() + 1).await;
    a.chain.lock().unwrap().submit_tx(tx).unwrap();
    let tasks: Vec<_> = spies
        .drain(..)
        .map(|mut r| {
            tokio::spawn(async move {
                let at = tokio::time::timeout(Duration::from_secs(60), async {
                    loop {
                        let frame = r.recv().await.expect("the spy is still connected");
                        if matches!(Message::decode(&frame), Ok(m) if announces(&m, &id)) {
                            return Instant::now();
                        }
                    }
                })
                .await
                .expect("announced within 60 s");
                (r, at)
            })
        })
        .collect();
    for _ in 0..10 {
        a.mine_with(0, false);
    }
    let mut at = Vec::new();
    for t in tasks {
        let (r, t) = t.await.unwrap();
        spies.push(r);
        at.push(t);
    }
    at
}

/// The time between the first and the last of `at`.
fn spread(at: &[Instant]) -> Duration {
    let (min, max) = (at.iter().min().unwrap(), at.iter().max().unwrap());
    max.duration_since(*min)
}

/// Property: inbound peers that reach the node through one network share ONE
/// release timer, so a spy gains nothing from opening more inbound
/// connections: its k connections see one release instant per transaction,
/// not k independent exponential delays whose earliest estimates when the
/// node first had it (timing-based origin inference). Source: R1 in
/// decisions.md "Decoy and relay plan (2026-10-04)", RES-FREEZE §4.5(2) and
/// §8.6-4a, dossier 33 W5; Bitcoin Core PR #33464 (one inbound timer per
/// network key).
///
/// Four inbound spies, mean 2 s, three transactions: every transaction
/// reaches the four within one release. With independent per-peer timers
/// the four receipts of one transaction lie within 250 ms with probability
/// (1 - e^(-0.125))^3 ≈ 1.6e-3, so the three rounds fail them (the code
/// before R1 did).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn inbound_peers_of_one_network_share_one_trickle_timer() {
    const SPIES: u8 = 4;
    const ROUNDS: usize = 3;
    let mut cfg = fast_config(&[]);
    cfg.trickle_inbound = Duration::from_secs(2);
    cfg.ping_interval = Duration::from_secs(3600); // the spies never answer
    let mut a = node_with(308, cfg).await;
    a.mine_n(80 + ROUNDS as u64, 0);
    let nid = params().network_id;
    let mut spies = Vec::new();
    let mut writers = Vec::new();
    for i in 1..=SPIES {
        let (r, w) = raw_peer_from([127, 0, 9, i], a.addr, nid, 0)
            .await
            .expect("spy");
        spies.push(r);
        writers.push(w);
    }
    wait_until("spies registered", 30, || {
        a.net.stats().peers == SPIES as usize
    })
    .await;
    for n in 0..ROUNDS {
        let at = release_instants(&mut a, n, &mut spies).await;
        assert!(
            spread(&at) < SAME_RELEASE,
            "round {n}: the inbound spies were told {:?} apart",
            spread(&at)
        );
    }
}

/// Property: the node's network identities do not share a release timer:
/// its clearnet inbound peers and its onion service's peers are released
/// by independent timers, so a spy connected to an onion address and to an
/// IP address cannot confirm that they are one node by seeing every
/// transaction released on both at the same instant (the reason Bitcoin
/// Core PR #33464 replaced its single inbound timer). Each class still
/// shares one timer within itself. Source: as above; docs/p2p.md §7.
///
/// Two clearnet and two onion spies (our onion listener), mean 3 s, five
/// transactions. Within a class the receipts lie within one release; across
/// the classes at least one transaction is released more than 250 ms
/// apart. Independent timers are within 250 ms of each other with
/// probability 1 - e^(-1/12) ≈ 0.08 per transaction, all five ≈ 3e-6; one
/// node-wide inbound timer releases all five together.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn clearnet_and_onion_trickle_timers_are_independent() {
    const ROUNDS: usize = 5;
    let mut cfg = fast_config(&[]);
    cfg.trickle_inbound = Duration::from_secs(3);
    cfg.ping_interval = Duration::from_secs(3600);
    cfg.onion_listen = Some("127.0.0.1:0".parse().unwrap());
    let mut a = node_with(309, cfg).await;
    a.mine_n(80 + ROUNDS as u64, 0);
    let nid = params().network_id;
    let onion = a.net.onion_local_addr().expect("onion listener");
    let mut spies = Vec::new();
    let mut writers = Vec::new();
    for to in [a.addr, a.addr, onion, onion] {
        let (r, w) = raw_peer(to, nid, true).await;
        spies.push(r);
        writers.push(w);
    }
    wait_until("spies registered", 30, || a.net.stats().peers == 4).await;
    let onion_peers = a
        .net
        .peers()
        .iter()
        .filter(|p| p.kind == blacksilk_p2p::connman::ConnKind::OnionInbound)
        .count();
    assert_eq!(onion_peers, 2, "two spies through the onion listener");
    let mut apart = 0;
    for n in 0..ROUNDS {
        let at = release_instants(&mut a, n, &mut spies).await;
        let (clear, tor) = at.split_at(2);
        assert!(
            spread(clear) < SAME_RELEASE && spread(tor) < SAME_RELEASE,
            "round {n}: one class was told at different instants: {at:?}"
        );
        let gap = if clear[0] > tor[0] {
            clear[0].duration_since(tor[0])
        } else {
            tor[0].duration_since(clear[0])
        };
        println!("round {n}: clearnet and onion released {gap:?} apart");
        if gap > SAME_RELEASE {
            apart += 1;
        }
    }
    assert!(
        apart > 0,
        "clearnet and onion peers were told every transaction at the same instant"
    );
}
