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
use super::dispatch::MAX_RELAY_FRAME;
use super::headers::{add_grace, HEADERS_TIMEOUT};
use super::peers::maintain_outbound;
use super::relay::{reannounce_pool, remember};
use super::serve_tx::SLOW_RATE;
use super::state::{short, shuffle, unix_now, Inner, State, StemEntry, OWED_IDS};
use super::stem::{fluff_entry, send_held_local_txs, take_stem};
use super::tx_requests::Actions;
use crate::connman::ConnKind;
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Bytes that may sit in buffers ahead of a written ping: our kernel's
/// send buffer (autotuned up to about 4 MiB) and a Tor circuit's window.
/// The writer hands the ping to the socket, not to the peer.
const SEND_BUFFER_ALLOWANCE: usize = 4 * 1024 * 1024;

/// A pong must arrive this long after our ping was WRITTEN (RT3 F3, RT4).
/// Ahead of the ping there may still be [`SEND_BUFFER_ALLOWANCE`] of
/// buffered data, and the peer writes its pong after the frame it is
/// writing to us, which may be a transaction of `MAX_RELAY_FRAME` bytes: at
/// the slowest rate the serving side keeps (`serve_tx::SLOW_RATE`,
/// 64 KiB/s) that is `(4 MiB + MAX_RELAY_FRAME) / SLOW_RATE` (about 132 s);
/// plus a minute for the round trip and a busy peer. Bitcoin Core waits 20
/// minutes. The cost: a dead peer that still sends (so the 180 s idle
/// timeout never fires) holds its slot about 3 minutes, against 30 s
/// before RT3 (dead links that send nothing are cut by the idle timeout).
const PONG_TIMEOUT: Duration =
    Duration::from_secs(((SEND_BUFFER_ALLOWANCE + MAX_RELAY_FRAME) / SLOW_RATE) as u64 + 60);

/// A ping not yet written (the writer is busy with a frame) times out only
/// after the time that frame takes at `SLOW_RATE` and the pong timeout.
const PING_WRITE_GRACE: Duration = Duration::from_secs((MAX_RELAY_FRAME / SLOW_RATE) as u64);

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

/// A changed address table is first saved this long after the start ("soon
/// after the first change"), then at most every [`SAVE_INTERVAL`].
const FIRST_SAVE_DELAY: Duration = Duration::from_secs(5);

/// Outbound connections are maintained (`maintain_outbound`) at most this
/// often (docs/p2p.md §9: every 2 s).
const OUTBOUND_ROUND: Duration = Duration::from_secs(2);

// ---------------------------------------------------------------- maintenance
pub(super) async fn maintenance_loop(inner: Arc<Inner>) {
    // Save soon after the first change.
    let mut last_save = Instant::now() - SAVE_INTERVAL + FIRST_SAVE_DELAY;
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
        let mut too_slow = Vec::new();
        {
            let mut st = inner.state();
            // The inbound identities whose shared timer fired: all their
            // peers are released in this pass (`trickle`).
            let fired = {
                let State {
                    peers,
                    inbound_trickle,
                    rng,
                    ..
                } = &mut *st;
                let live = peers.values().filter_map(|p| p.trickle);
                inbound_trickle.fire(live, now, inner.cfg.trickle_inbound, rng)
            };
            let ids: Vec<PeerId> = st.peers.keys().copied().collect();
            for pid in ids {
                let nonce = st.rng.next_u64();
                let mut rng = ChaCha20Rng::seed_from_u64(st.rng.next_u64());
                let p = st.peers.get_mut(&pid).expect("listed");
                let due = match &p.trickle {
                    Some(key) => fired.contains(key),
                    None => now >= p.next_inv,
                };
                if !p.inv_queue.is_empty() && due {
                    let mut queue = std::mem::take(&mut p.inv_queue);
                    // Every flush in a fresh random order (RT4): the order
                    // ids were queued in says nothing to the peer.
                    shuffle(&mut queue, &mut rng);
                    remember(&mut p.announced_to, queue.iter().copied());
                    for h in &queue {
                        p.recent_inv.push_back((*h, now));
                    }
                    while p.recent_inv.len() > OWED_IDS {
                        p.recent_inv.pop_front();
                    }
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
                // A reader too slow for the serving budget it holds
                // (`serve_tx`, RT2 F3): disconnected, not banned.
                if p.replies
                    .too_slow(now, inner.serve_budget.contended(!p.inbound))
                {
                    p.kill.notify_one();
                    too_slow.push(p.addr.clone());
                }
                if let Some((n, queued)) = p.ping {
                    // Counted from when the ping was written (RT3 F3).
                    let written = p
                        .ping_written
                        .lock()
                        .ok()
                        .and_then(|w| *w)
                        .filter(|(x, _)| *x == n)
                        .map(|(_, at)| at);
                    let late = match written {
                        Some(at) => now.duration_since(at) > PONG_TIMEOUT,
                        None => now.duration_since(queued) > PING_WRITE_GRACE + PONG_TIMEOUT,
                    };
                    if late {
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
            // Transaction requests: timers due now (timeouts, delayed and
            // paused candidates, deadlines; `tx_requests`). Transaction
            // relay is best effort: a slow answer is asked of other
            // announcers but not penalized (peers answer `NotFound` when
            // they no longer have the transaction). The late answer is
            // still accepted from the peer asked (`TxTracker::take_late`).
            let mut out = Actions::default();
            st.tx_tracker.poll(now, &mut out);
            inner.apply_tx_actions(&mut st, out, now);
        }
        // A timeout is not misbehavior: a large block on a slow link, or a
        // busy honest peer, times out too (R8-9). The request moves to another
        // peer; the late answer is still accepted without penalty.
        for (p, what) in timed_out {
            log::debug!("peer {p}: {what} request timed out");
        }
        if !too_slow.is_empty() {
            inner.state().slow_disconnects += too_slow.len() as u64;
        }
        for addr in too_slow {
            log::debug!("peer {addr} reads too slowly for the answers it holds; disconnecting");
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
        if now.duration_since(last_outbound) > OUTBOUND_ROUND {
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
            inner
                .maintenance_seen
                .store(next, std::sync::atomic::Ordering::Release);
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

    /// A queued transaction announcement waits for the trickle (an inbound
    /// peer: its network's shared timer, exponential intervals of mean
    /// `trickle_inbound`, `trickle`): with a mean of 10^6 s nothing is
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

    /// The loop's delays by value: the first save 5 s after the start, an
    /// outbound round every 2 s (docs/p2p.md §9). Their behavior tests bound
    /// them exactly only from below (a delay never ends early); a second more
    /// passes them under load (run E's E44, now named and pinned: RT-MUTE).
    #[test]
    fn the_first_save_delay_and_the_outbound_round_are_the_specified_ones() {
        assert_eq!(FIRST_SAVE_DELAY, Duration::from_secs(5));
        assert_eq!(OUTBOUND_ROUND, Duration::from_secs(2));
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
    /// (192 s) has passed since the ping, and not before. The peer sends
    /// its own pings every 20 s, so the 180 s idle timeout never comes first.
    #[tokio::test]
    async fn a_peer_that_never_answers_a_ping_is_left_after_the_pong_timeout() {
        assert_eq!(PONG_TIMEOUT, Duration::from_secs(192));
        let net = idle_network(|c| c.ping_interval = Duration::from_secs(1)).await;
        let (mut r, mut w) = raw_peer(&net).await;
        let keepalive = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                if w.send(&Message::Ping(7).encode()).await.is_err() {
                    break;
                }
            }
        });
        let mut first_ping = None;
        let closed = loop {
            match tokio::time::timeout(Duration::from_secs(240), r.recv()).await {
                Err(_) => panic!("still connected 240 s after the last frame"),
                Ok(Err(_)) => break Instant::now(),
                Ok(Ok(m)) => {
                    if let Ok(Message::Ping(_)) = Message::decode(&m) {
                        first_ping.get_or_insert_with(Instant::now);
                    }
                }
            }
        };
        keepalive.abort();
        let after = closed.duration_since(first_ping.expect("pinged"));
        assert!(
            after >= Duration::from_millis(191_500) && after < Duration::from_secs(207),
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

    /// Block requests time out once `BLOCK_TIMEOUT` (60 s) has passed, not
    /// before: an expired request moves to the late requests, where its
    /// answer is still accepted for another timeout, then forgotten. The ages
    /// are set in the state directly; nothing is missing, so nothing is asked
    /// again. (Transaction requests are the tracker's: `tx_requests` tests.)
    #[tokio::test]
    async fn block_requests_time_out_after_their_timeout_and_late_ones_are_kept_as_long() {
        assert_eq!(BLOCK_TIMEOUT, Duration::from_secs(60));
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
            pid
        };
        until(&net, |st| !st.block_requests.contains_key(&[2; 32])).await;
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
        // An inbound peer: released by the shared inbound timer (mean 50 ms).
        let net = idle_network(|c| c.trickle_inbound = Duration::from_millis(50)).await;
        let (mut r, _w) = raw_peer(&net).await;
        {
            let mut st = net.inner.state();
            let p = st.peers.values_mut().next().unwrap();
            assert!(p.inbound && p.trickle.is_some());
            p.inv_queue = (0..501u32)
                .map(|i| {
                    let mut h = [0x55; 32];
                    h[..4].copy_from_slice(&i.to_le_bytes());
                    h
                })
                .collect();
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

    /// The interval and address-fetch limits are strict: an elapsed time
    /// equal to the limit does not trigger them (RT-MUTE, against E43's
    /// "no test can arrange the equality"). With both limits zero and the
    /// recorded instants not in the past, `duration_since` saturates to zero,
    /// so the elapsed time equals the limit at every tick: the peer is
    /// neither pinged nor left as a silent seed (the mutants `>` -> `>=` of
    /// the ping interval and the address-fetch timeout ping it and leave
    /// it). Control: with the instants in the past, both limits trigger.
    #[tokio::test]
    async fn an_elapsed_time_equal_to_a_zero_limit_does_not_trigger_it() {
        let net = idle_network(|c| {
            c.ping_interval = Duration::ZERO;
            c.addr_fetch_timeout = Duration::ZERO;
        })
        .await;
        let recv = |m: Vec<u8>| Message::decode(&m).unwrap();
        let (mut r, mut w) = raw_peer(&net).await;
        let later = Instant::now() + Duration::from_secs(3600);
        {
            let mut st = net.inner.state();
            let p = st.peers.values_mut().next().unwrap();
            p.ping = None;
            p.last_ping = later;
            p.kind = ConnKind::AddrFetch;
            p.connected_at = later;
        }
        // Everything queued before the edit comes before this pong.
        w.send(&Message::Ping(8).encode()).await.unwrap();
        loop {
            if let Message::Pong(8) = recv(r.recv().await.unwrap()) {
                break;
            }
        }
        // Ten ticks with the elapsed times equal to the limits.
        tokio::time::sleep(Duration::from_millis(500)).await;
        w.send(&Message::Ping(9).encode()).await.unwrap();
        loop {
            match recv(r.recv().await.expect("still connected")) {
                Message::Pong(9) => break,
                Message::Ping(n) => panic!("pinged ({n}) at an elapsed time equal to the interval"),
                _ => {}
            }
        }
        assert_eq!(net.inner.state().peers.len(), 1, "left as a silent seed");

        // Control: the same zero limits with the instants in the past.
        net.inner
            .state()
            .peers
            .values_mut()
            .next()
            .unwrap()
            .last_ping = Instant::now();
        let pinged = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Message::Ping(_) = recv(r.recv().await.unwrap()) {
                    break;
                }
            }
        })
        .await;
        assert!(pinged.is_ok(), "not pinged once the interval had passed");
        net.inner
            .state()
            .peers
            .values_mut()
            .next()
            .unwrap()
            .connected_at = Instant::now();
        let left = tokio::time::timeout(Duration::from_secs(10), async {
            while r.recv().await.is_ok() {}
        })
        .await;
        assert!(left.is_ok(), "a seed past its zero timeout was not left");
    }

    /// RT3 F3, RT4: the pong timeout covers buffered data ahead of the
    /// ping and the largest frame the peer may be writing to us, at the
    /// slowest rate the serving side keeps, plus a margin (docs/p2p.md §10
    /// states 68 s and 192 s).
    #[test]
    fn the_pong_timeout_covers_a_largest_frame_at_the_slowest_rate() {
        let frame = Duration::from_secs_f64(
            (SEND_BUFFER_ALLOWANCE + MAX_RELAY_FRAME) as f64 / SLOW_RATE as f64,
        );
        assert!(PONG_TIMEOUT >= frame + Duration::from_secs(30));
        assert_eq!(PING_WRITE_GRACE.as_secs(), 68);
        assert_eq!(PONG_TIMEOUT.as_secs(), 192);
    }
}
