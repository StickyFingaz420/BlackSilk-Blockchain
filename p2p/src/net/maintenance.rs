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
        let mut too_slow = Vec::new();
        {
            let mut st = inner.state();
            let ids: Vec<PeerId> = st.peers.keys().copied().collect();
            for pid in ids {
                let nonce = st.rng.next_u64();
                let mut rng = ChaCha20Rng::seed_from_u64(st.rng.next_u64());
                let p = st.peers.get_mut(&pid).expect("listed");
                if !p.inv_queue.is_empty() && now >= p.next_inv {
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
            // still accepted from the peer asked (`TxTracker::is_late`).
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
            inner
                .maintenance_seen
                .store(next, std::sync::atomic::Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
