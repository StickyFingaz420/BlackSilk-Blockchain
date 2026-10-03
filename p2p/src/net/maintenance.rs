//! The maintenance loops (docs/p2p.md §10):
//! - [`announce_loop`] announces each new tip as soon as the chain publishes
//!   it (RT-LAB F2), at most once per [`ANNOUNCE_MIN_GAP`];
//! - [`maintenance_loop`] never waits for the chain lock: Dandelion epochs,
//!   held local transactions, tip announcements (the fallback of
//!   [`announce_loop`], from the published chain summary), trickle flush,
//!   pings, timeouts, header re-requests, outbound dialing and saving keep
//!   their schedule during any long chain command (F34-2);
//! - [`chain_maintenance_loop`] does the work that needs the chain: download
//!   scheduling (from the published snapshot, first), embargo fluffs (each
//!   a mempool submission on the actor's Tx lane, run on its own task: the
//!   loop never waits for one, RTW2A-3) and pool re-announcement (a Query
//!   command). A long command delays only the re-announcement, by at most
//!   its length.

use super::blocks::{release_block_slot, schedule_downloads, BLOCK_TIMEOUT};
use super::headers::{add_grace, HEADERS_TIMEOUT};
use super::peers::maintain_outbound;
use super::relay::{reannounce_pool, remember, retry_tx, TX_TIMEOUT};
use super::state::{short, unix_now, Inner, State, StemEntry, LATE_TXS_MAX};
use super::stem::{fluff_entry, send_held_local_txs, take_stem};
use crate::connman::ConnKind;
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use rand_chacha::rand_core::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PONG_TIMEOUT: Duration = Duration::from_secs(30);

/// The shortest time between two announcements by [`announce_loop`]: while
/// the tip changes faster (a body drain, initial sync), the tips in between
/// are skipped, so a peer gets at most 1 / `ANNOUNCE_MIN_GAP` of them per
/// second, plus one per maintenance tick from the fallback (about 14 per
/// second with the default 250 ms tick; 4 before, from the tick alone). A
/// single new block is announced at once.
pub(super) const ANNOUNCE_MIN_GAP: Duration = Duration::from_millis(100);

/// Announces the connected tip of the published summary with a `Headers`
/// message holding its header, once per peer and tip: to every peer not yet
/// considered for this tip (`Peer::announced`, per peer, so a peer registered
/// after the tip changed is still considered, RT-SYNC F-B) and not known to
/// have it (`Peer::wants_tip`; docs/p2p.md §6). Takes the state lock once;
/// never waits for the chain.
pub(super) fn announce_tip(inner: &Inner) {
    let s = inner.summary.load();
    let mut st = inner.state();
    let mut peers = Vec::new();
    for (id, p) in st.peers.iter_mut() {
        if p.announced == s.tip_id {
            continue;
        }
        p.announced = s.tip_id;
        if p.wants_tip(&s.tip_id, &s.best_header_id, s.tip_on_best_chain) {
            peers.push(*id);
        }
    }
    for p in peers {
        inner.send(&mut st, p, Message::Headers(vec![s.tip_header]));
    }
}

/// Announces each new tip when the chain publishes it (RT-LAB F2): woken by
/// the summary cell's tip listener (`Inner::tip_published`), not by the
/// maintenance tick, which added half a tick (125 ms by default) per hop on
/// average. Wake-ups during [`ANNOUNCE_MIN_GAP`] coalesce into one, so a
/// burst of tips costs at most one announcement per gap.
pub(super) async fn announce_loop(inner: Arc<Inner>) {
    loop {
        inner.tip_published.notified().await;
        announce_tip(&inner);
        tokio::time::sleep(ANNOUNCE_MIN_GAP).await;
    }
}

/// Address table and bans are saved at most this often, and only when changed
/// (a crash loses at most this much discovery state).
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------- maintenance
pub(super) async fn maintenance_loop(inner: Arc<Inner>) {
    // Save soon after the first change.
    let mut last_save = Instant::now() - SAVE_INTERVAL + Duration::from_secs(5);
    let mut saved_fingerprint = (0, 0);
    let mut last_outbound = Instant::now() - Duration::from_secs(60);
    loop {
        tokio::time::sleep(inner.cfg.tick).await;
        let now = Instant::now();

        // Dandelion epoch; held local transactions.
        {
            let mut st = inner.state();
            let outbound: Vec<PeerId> = st
                .peers
                .iter()
                .filter(|(_, p)| !p.inbound && p.relay_txs)
                .map(|(id, _)| *id)
                .collect();
            let State { dandelion, rng, .. } = &mut *st;
            dandelion.maybe_new_epoch(now, &outbound, rng);
            send_held_local_txs(&inner, &mut st);
        }

        // Announce a new tip that `announce_loop` has not (a fallback: a
        // block connected by any path is announced within a tick, even
        // during a hold).
        announce_tip(&inner);
        let header_height_now = inner.summary.load().header_height;

        // Trickled announcements, pings, timeouts.
        let mut timed_out = Vec::new();
        {
            let mut st = inner.state();
            let ids: Vec<PeerId> = st.peers.keys().copied().collect();
            for pid in ids {
                let nonce = st.rng.next_u64();
                let p = st.peers.get_mut(&pid).expect("listed");
                if !p.inv_queue.is_empty() && now >= p.next_inv {
                    let queue = std::mem::take(&mut p.inv_queue);
                    remember(&mut p.announced_to, queue.iter().copied());
                    for chunk in queue.chunks(500) {
                        let _ = p.out.try_send(Message::InvTx(chunk.to_vec()));
                    }
                }
                // A seed's address fetch that got no answer in time.
                if p.kind == ConnKind::AddrFetch
                    && now.duration_since(p.connected_at) > inner.cfg.addr_fetch_timeout
                {
                    p.kill.notify_one();
                }
                if let Some((_, sent)) = p.ping {
                    if now.duration_since(sent) > PONG_TIMEOUT {
                        p.kill.notify_one();
                    }
                } else if now.duration_since(p.last_ping) > inner.cfg.ping_interval {
                    p.ping = Some((nonce, now));
                    p.last_ping = now;
                    let _ = p.out.try_send(Message::Ping(nonce));
                }
                if p.headers_requested
                    .is_some_and(|t| now.duration_since(t) > HEADERS_TIMEOUT)
                {
                    p.headers_requested = None;
                    // Its reply is still accepted, unpenalized, for another
                    // HEADERS_TIMEOUT (a busy honest peer, R8-9).
                    add_grace(&mut p.headers_grace, now);
                    timed_out.push((pid, "headers"));
                    // Not asked again every tick; asked again when it
                    // announces a new tip.
                    p.height = p.height.min(header_height_now);
                }
            }
            let stale_blocks: Vec<(Hash, PeerId)> = st
                .block_requests
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) > BLOCK_TIMEOUT)
                .map(|(id, (p, _))| (*id, *p))
                .collect();
            for (id, p) in stale_blocks {
                st.block_requests.remove(&id);
                release_block_slot(&mut st, p);
                st.late_blocks.insert(id, (p, now));
                timed_out.push((p, "block"));
            }
            st.late_blocks
                .retain(|_, (_, t)| now.duration_since(*t) <= BLOCK_TIMEOUT);
            let stale_txs: Vec<(Hash, PeerId)> = st
                .tx_requests
                .iter()
                .filter(|(_, (_, t))| now.duration_since(*t) > TX_TIMEOUT)
                .map(|(id, (p, _))| (*id, *p))
                .collect();
            // Transaction relay is best effort: a slow answer is retried with the
            // next announcer but not penalized (peers answer `NotFound` when they
            // no longer have the transaction). The late answer is still
            // accepted from the peer asked (`late_txs`).
            st.late_txs
                .retain(|_, t| now.duration_since(*t) <= TX_TIMEOUT);
            for (id, p) in stale_txs {
                if st.late_txs.len() < LATE_TXS_MAX {
                    st.late_txs.insert((id, p), now);
                }
                retry_tx(&inner, &mut st, id, p, now);
            }
        }
        // A timeout is not misbehavior: a large block on a slow link, or a
        // busy honest peer, times out too (R8-9). The request moves to another
        // peer; the late answer is still accepted without penalty.
        for (p, what) in timed_out {
            log::debug!("peer {p}: {what} request timed out");
        }

        // Keep syncing from peers that are ahead, and ask again peers whose
        // headers were dropped while the queue was full, once it has room.
        let header_height = header_height_now;
        let behind: Vec<PeerId> = {
            let st = inner.state();
            st.peers
                .iter()
                .filter(|(_, p)| {
                    p.kind != ConnKind::AddrFetch
                        && (p.height > header_height || p.headers_pending)
                        && p.headers_requested.is_none()
                        && !p.headers_busy
                        && inner.header_queue_room(&st, &p.addr, p.proxied)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for p in behind {
            inner.request_headers(p).await;
        }

        // Outbound connections.
        if now.duration_since(last_outbound) > Duration::from_secs(2) {
            last_outbound = now;
            maintain_outbound(&inner);
        }
        // The address table is saved when its size changed; the ban list
        // whenever a ban was added (a new ban does not always change the
        // count: it may replace an expired one).
        let (fingerprint, bans_dirty) = {
            let st = inner.state();
            (st.addrman.len(), st.bans_dirty)
        };
        if (fingerprint != saved_fingerprint || bans_dirty)
            && now.duration_since(last_save) > SAVE_INTERVAL
        {
            last_save = now;
            saved_fingerprint = fingerprint;
            let mut st = inner.state();
            st.bans.prune(unix_now());
            st.bans_dirty = false;
            drop(st);
            inner.save();
        }
    }
}

/// The chain-side maintenance, every tick, on its own task so that a long
/// chain command never stops [`maintenance_loop`]: missing bodies are
/// requested, embargoes that expired are fluffed (the transaction enters the
/// mempool: a chain write, on a task of its own), pooled transactions are
/// re-announced once per new height, and originated-set entries whose
/// window ended are dropped.
pub(super) async fn chain_maintenance_loop(inner: Arc<Inner>) {
    // The next block's height at the previous tick (0: not seen yet).
    let mut last_next = 0u64;
    loop {
        tokio::time::sleep(inner.cfg.tick).await;
        let now = Instant::now();

        // Body downloads first: they read only the published snapshot, so a
        // busy chain never delays them (RTW2A-3).
        schedule_downloads(&inner).await;

        // Embargoes, detected at the tick after expiry. Each fluff is a
        // command on the chain actor's Tx lane, which during a drain runs
        // only after about `STARVATION_LIMIT` steps: it runs on its own task,
        // so the loop never waits for it (RTW2A-3). The entry leaves the
        // stempool here, so a later tick does not fluff it again.
        let expired: Vec<(Hash, StemEntry)> = {
            let mut st = inner.state();
            let ids: Vec<Hash> = st
                .stempool
                .iter()
                .filter(|(_, e)| now >= e.embargo)
                .map(|(id, _)| *id)
                .collect();
            ids.into_iter()
                .filter_map(|id| take_stem(&mut st, &id).map(|e| (id, e)))
                .collect()
        };
        for (id, entry) in expired {
            log::debug!("embargo expired for {}", short(&id));
            let inner = inner.clone();
            tokio::spawn(async move { fluff_entry(&inner, id, entry, None).await });
        }

        // Once per new height: pool re-announcement (docs/p2p.md §7), and
        // originated-set entries whose window ended are dropped (§8.1).
        let next = inner.summary.load().height + 1;
        if next != last_next {
            if last_next != 0 {
                reannounce_pool(&inner, last_next, next).await;
            }
            last_next = next;
            if inner.state().originated.prune(next) > 0 {
                inner.save_originated().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! The maintenance loop's own rules (mutation run E): the trickle delay,
    //! the ping, pong, request and idle timeouts, the late requests, the
    //! announcement chunks and the address table's saves, on an idle node
    //! with raw loopback peers (some with request ages set in the state).
    use super::*;
    use crate::addr::NetAddr;
    use crate::message::{Version, PROTOCOL_VERSION};
    use blacksilk_chain::manager::ChainManager;

    struct ZeroPow;
    impl blacksilk_consensus::PowFunction for ZeroPow {
        fn pow_hash(&self, _: &Hash, _: &[u8]) -> Hash {
            [0; 32]
        }
    }

    async fn idle_network(edit: impl FnOnce(&mut crate::NetConfig)) -> crate::Network {
        let p = blacksilk_consensus::ChainParams::regtest();
        let m = ChainManager::open(
            p.clone(),
            blacksilk_tx::params::TxRules::for_chain(&p),
            Arc::new(ZeroPow),
            Box::<blacksilk_chain::store::MemoryStore>::default(),
            [2; 32],
        )
        .unwrap();
        let mut cfg = crate::NetConfig::new(p.network_id);
        cfg.listen = Some("127.0.0.1:0".parse().unwrap());
        cfg.allow_private = true;
        cfg.tick = Duration::from_millis(50);
        edit(&mut cfg);
        crate::Network::start(cfg, Arc::new(std::sync::Mutex::new(m)))
            .await
            .unwrap()
    }

    /// A raw loopback peer of `net`, registered: its handshake done.
    async fn raw_peer(
        net: &crate::Network,
    ) -> (
        crate::transport::FrameReader<tokio::io::ReadHalf<tokio::net::TcpStream>>,
        crate::transport::FrameWriter<tokio::io::WriteHalf<tokio::net::TcpStream>>,
    ) {
        let inner = &net.inner;
        let before = inner.state().peers.len();
        let stream = tokio::net::TcpStream::connect(net.local_addr().unwrap())
            .await
            .unwrap();
        let (mut r, mut w) = crate::transport::handshake(
            stream,
            true,
            inner.cfg.network_id,
            &inner.genesis_id,
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let v = Version {
            protocol: PROTOCOL_VERSION,
            network: inner.cfg.network_id,
            nonce: 0x2468,
            height: 0,
            tip: inner.genesis_id,
            listen: None,
            relay_txs: true,
        };
        w.send(&Message::Version(v).encode()).await.unwrap();
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Version(_)));
        w.send(&Message::Verack.encode()).await.unwrap();
        assert!(matches!(recv(r.recv().await.unwrap()), Message::Verack));
        while inner.state().peers.len() == before {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        (r, w)
    }

    /// A queued transaction announcement waits for the peer's trickle delay
    /// (exponential, mean `trickle_inbound`): with a mean of 10^6 s nothing is
    /// sent in the next half second of ticks, whatever is queued (a delay
    /// below it has probability about 5·10^-7).
    #[tokio::test]
    async fn an_announcement_waits_for_its_trickle_delay() {
        let net = idle_network(|c| c.trickle_inbound = Duration::from_secs(1_000_000)).await;
        let inner = net.inner.clone();
        let (mut r, mut w) = raw_peer(&net).await;
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        inner.announce_tx([9; 32], None);
        assert_eq!(
            inner.state().peers.values().next().unwrap().inv_queue,
            [[9; 32]]
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
        w.send(&Message::Ping(8).encode()).await.unwrap();
        loop {
            match recv(r.recv().await.unwrap()) {
                Message::Pong(8) => break,
                Message::InvTx(ids) => panic!("announced before its delay: {ids:?}"),
                _ => {}
            }
        }
        assert_eq!(
            inner.state().peers.values().next().unwrap().inv_queue.len(),
            1
        );
    }

    /// The address table is first saved 5 s after the start at the earliest
    /// ("save soon after the first change": `last_save` starts 55 s in the
    /// past of the 60 s interval), not at the first tick after a change.
    #[tokio::test]
    async fn the_first_save_of_the_address_table_comes_5_s_after_the_start() {
        // "Saved within a minute of changing" (docs/p2p.md §9, Persistence).
        assert_eq!(SAVE_INTERVAL, Duration::from_secs(60));
        let dir = std::env::temp_dir().join(format!("bs-p2p-maint-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let t0 = Instant::now();
        let net = idle_network(|c| c.data_dir = Some(dir.clone())).await;
        let now = unix_now();
        let added = net.inner.state().addrman.add(
            NetAddr::parse("8.8.8.8:8333").unwrap(),
            &NetAddr::parse("9.9.9.9:1").unwrap(),
            now,
        );
        assert!(added);
        let saved = loop {
            if dir.join("peers.json").exists() {
                break t0.elapsed();
            }
            assert!(t0.elapsed() < Duration::from_secs(60), "never saved");
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert!(
            saved >= Duration::from_millis(4_500),
            "saved after {saved:?}"
        );
        drop(net);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A peer is pinged once per `ping_interval`, counted from its last ping,
    /// not at every tick once the interval is past or before it is: an
    /// answering peer gets two to four pings in 3.5 s at a 1 s interval
    /// (ticks of 50 ms), the first after the interval from its registration.
    #[tokio::test]
    async fn an_answering_peer_is_pinged_once_per_interval() {
        let net = idle_network(|c| c.ping_interval = Duration::from_secs(1)).await;
        let (mut r, mut w) = raw_peer(&net).await;
        let start = Instant::now();
        let mut pings = Vec::new();
        while let Ok(m) =
            tokio::time::timeout_at((start + Duration::from_millis(3_500)).into(), r.recv()).await
        {
            if let Message::Ping(n) = Message::decode(&m.unwrap()).unwrap() {
                pings.push(start.elapsed());
                w.send(&Message::Pong(n).encode()).await.unwrap();
            }
        }
        assert!((2..=4).contains(&pings.len()), "pings at {pings:?}");
        assert!(pings[0] >= Duration::from_millis(800), "pings at {pings:?}");
    }

    /// A peer that does not answer a ping is disconnected once `PONG_TIMEOUT`
    /// (30 s) has passed since the ping, and not before.
    #[tokio::test]
    async fn a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout() {
        assert_eq!(PONG_TIMEOUT, Duration::from_secs(30));
        let net = idle_network(|c| c.ping_interval = Duration::from_secs(1)).await;
        let (mut r, _w) = raw_peer(&net).await;
        let mut first_ping = None;
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(60), r.recv()).await {
                Err(_) => panic!("still connected 60 s after the last frame"),
                Ok(Err(_)) => break Instant::now(),
                Ok(Ok(m)) => {
                    if let Ok(Message::Ping(_)) = Message::decode(&m) {
                        first_ping.get_or_insert_with(Instant::now);
                    }
                }
            }
        };
        let after = closed.duration_since(first_ping.expect("pinged"));
        assert!(
            after >= Duration::from_millis(29_500) && after < Duration::from_secs(45),
            "left {after:?} after the ping"
        );
        assert!(net.inner.state().peers.is_empty());
    }

    /// Waits up to 10 s for `done` on the state (a few ticks).
    async fn until(net: &crate::Network, done: impl Fn(&State) -> bool) {
        let t = Instant::now();
        while !done(&net.inner.state()) {
            assert!(t.elapsed() < Duration::from_secs(10), "not within 10 s");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Block and transaction requests time out once their timeouts have
    /// passed (`BLOCK_TIMEOUT` 60 s, `TX_TIMEOUT` 30 s), not before: an
    /// expired request moves to the late requests, where its answer is still
    /// accepted for another timeout, then forgotten. The ages are set in the
    /// state directly; nothing is missing, so nothing is asked again.
    #[tokio::test]
    async fn requests_time_out_after_their_timeouts_and_late_ones_are_kept_as_long() {
        assert_eq!(BLOCK_TIMEOUT, Duration::from_secs(60));
        assert_eq!(TX_TIMEOUT, Duration::from_secs(30));
        let net = idle_network(|_| {}).await;
        let _peer = raw_peer(&net).await;
        let ago = |d: Duration| Instant::now().checked_sub(d).expect("uptime");
        let margin = Duration::from_secs(10);
        let pid = {
            let mut st = net.inner.state();
            let pid = *st.peers.keys().next().unwrap();
            st.peers.get_mut(&pid).unwrap().blocks_in_flight = 2;
            st.block_requests
                .insert([1; 32], (pid, ago(BLOCK_TIMEOUT - margin)));
            st.block_requests
                .insert([2; 32], (pid, ago(BLOCK_TIMEOUT + margin)));
            st.late_blocks
                .insert([3; 32], (pid, ago(BLOCK_TIMEOUT - margin)));
            st.late_blocks
                .insert([4; 32], (pid, ago(BLOCK_TIMEOUT + margin)));
            st.tx_requests
                .insert([5; 32], (pid, ago(TX_TIMEOUT - margin)));
            st.tx_requests
                .insert([6; 32], (pid, ago(TX_TIMEOUT + margin)));
            st.late_txs.insert(([7; 32], pid), ago(TX_TIMEOUT - margin));
            st.late_txs.insert(([8; 32], pid), ago(TX_TIMEOUT + margin));
            pid
        };
        until(&net, |st| {
            !st.block_requests.contains_key(&[2; 32]) && !st.tx_requests.contains_key(&[6; 32])
        })
        .await;
        // Some ticks later (a late request just moved is not forgotten).
        tokio::time::sleep(Duration::from_millis(300)).await;
        let st = net.inner.state();
        let keys = |m: Vec<Hash>| {
            let mut m = m;
            m.sort();
            m
        };
        assert_eq!(keys(st.block_requests.keys().copied().collect()), [[1; 32]]);
        assert_eq!(
            keys(st.late_blocks.keys().copied().collect()),
            [[2; 32], [3; 32]]
        );
        assert!(st.late_blocks.values().all(|(p, _)| *p == pid));
        assert_eq!(st.peers[&pid].blocks_in_flight, 1);
        assert_eq!(keys(st.tx_requests.keys().copied().collect()), [[5; 32]]);
        assert_eq!(
            keys(st.late_txs.keys().map(|(h, _)| *h).collect()),
            [[6; 32], [7; 32]]
        );
    }

    /// At most `LATE_TXS_MAX` timed-out transaction requests are remembered:
    /// with room for one, of two that time out one is kept.
    #[tokio::test]
    async fn late_transaction_requests_are_capped() {
        assert_eq!(LATE_TXS_MAX, 10_000);
        let net = idle_network(|_| {}).await;
        let _peer = raw_peer(&net).await;
        let old = Instant::now()
            .checked_sub(TX_TIMEOUT + Duration::from_secs(10))
            .expect("uptime");
        {
            let mut st = net.inner.state();
            let pid = *st.peers.keys().next().unwrap();
            let now = Instant::now();
            for i in 0..LATE_TXS_MAX as u32 - 1 {
                let mut h = [0xee; 32];
                h[..4].copy_from_slice(&i.to_le_bytes());
                st.late_txs.insert((h, pid), now);
            }
            st.tx_requests.insert([5; 32], (pid, old));
            st.tx_requests.insert([6; 32], (pid, old));
        }
        until(&net, |st| st.tx_requests.is_empty()).await;
        let st = net.inner.state();
        assert_eq!(st.late_txs.len(), LATE_TXS_MAX);
        assert_eq!(
            st.late_txs
                .keys()
                .filter(|(h, _)| *h == [5; 32] || *h == [6; 32])
                .count(),
            1
        );
    }

    /// A header request times out once `HEADERS_TIMEOUT` (60 s) has passed,
    /// not before: the peer gets a grace entry (its late reply is accepted)
    /// and is not asked again at once.
    #[tokio::test]
    async fn a_header_request_times_out_after_the_headers_timeout() {
        assert_eq!(HEADERS_TIMEOUT, Duration::from_secs(60));
        let net = idle_network(|_| {}).await;
        let _one = raw_peer(&net).await;
        let _two = raw_peer(&net).await;
        let ago = |d: Duration| Instant::now().checked_sub(d).expect("uptime");
        let margin = Duration::from_secs(10);
        let (fresh, old) = {
            let mut st = net.inner.state();
            let mut ids: Vec<PeerId> = st.peers.keys().copied().collect();
            ids.sort();
            let (fresh, old) = (ids[0], ids[1]);
            st.peers.get_mut(&fresh).unwrap().headers_requested =
                Some(ago(HEADERS_TIMEOUT - margin));
            st.peers.get_mut(&old).unwrap().headers_requested = Some(ago(HEADERS_TIMEOUT + margin));
            (fresh, old)
        };
        until(&net, |st| st.peers[&old].headers_requested.is_none()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        let st = net.inner.state();
        assert!(st.peers[&fresh].headers_requested.is_some());
        assert!(st.peers[&fresh].headers_grace.is_empty());
        assert!(st.peers[&old].headers_requested.is_none());
        assert_eq!(st.peers[&old].headers_grace.len(), 1);
    }

    /// A registered peer that sends nothing is disconnected 180 s after its
    /// last frame (docs/p2p.md "Liveness"; `conn::IDLE_TIMEOUT`), not before.
    /// Pings are off (a 1000 s interval), so no pong timeout comes first.
    #[tokio::test]
    async fn a_silent_registered_peer_is_left_after_the_idle_timeout() {
        let net = idle_network(|c| c.ping_interval = Duration::from_secs(1000)).await;
        let (mut r, _w) = raw_peer(&net).await;
        let last_sent = Instant::now();
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(240), r.recv()).await {
                Err(_) => panic!("still connected 240 s after the last frame"),
                Ok(Err(_)) => break last_sent.elapsed(),
                Ok(Ok(_)) => {}
            }
        };
        assert!(
            closed >= Duration::from_millis(179_500) && closed < Duration::from_secs(200),
            "left {closed:?} after its last frame"
        );
        assert!(net.inner.state().peers.is_empty());
    }

    /// Queued announcements go out in `InvTx` messages of at most `MAX_INV`
    /// (500) ids, the most a peer decodes: 501 queued ids are sent as 500
    /// and 1.
    #[tokio::test]
    async fn queued_announcements_go_out_in_messages_of_at_most_500_ids() {
        assert_eq!(crate::message::MAX_INV, 500);
        let net = idle_network(|_| {}).await;
        let (mut r, _w) = raw_peer(&net).await;
        {
            let mut st = net.inner.state();
            let p = st.peers.values_mut().next().unwrap();
            p.inv_queue = (0..501u32)
                .map(|i| {
                    let mut h = [0x55; 32];
                    h[..4].copy_from_slice(&i.to_le_bytes());
                    h
                })
                .collect();
            p.next_inv = Instant::now();
        }
        let mut sizes = Vec::new();
        while sizes.iter().sum::<usize>() < 501 {
            let m = tokio::time::timeout(Duration::from_secs(10), r.recv())
                .await
                .expect("announced within 10 s")
                .unwrap();
            if let Message::InvTx(ids) = Message::decode(&m).expect("a valid message") {
                sizes.push(ids.len());
            }
        }
        assert_eq!(sizes, [500, 1]);
    }
}
