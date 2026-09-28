//! The maintenance loop: Dandelion epochs and embargo, tip announcements,
//! pool re-announcement, trickle flush, pings, timeouts, re-requests,
//! downloads, outbound, saving.

use super::blocks::{release_block_slot, schedule_downloads, BLOCK_TIMEOUT};
use super::headers::HEADERS_TIMEOUT;
use super::peers::maintain_outbound;
use super::relay::{reannounce_pool, remember, retry_tx, TX_TIMEOUT};
use super::state::{short, unix_now, Inner, State};
use super::stem::{fluff, send_held_local_txs};
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use rand_chacha::rand_core::RngCore;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PING_INTERVAL: Duration = Duration::from_secs(60);

const PONG_TIMEOUT: Duration = Duration::from_secs(30);

/// Address table and bans are saved at most this often, and only when changed
/// (a crash loses at most this much discovery state).
const SAVE_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------- maintenance
pub(super) async fn maintenance_loop(inner: Arc<Inner>) {
    // Save soon after the first change.
    let mut last_save = Instant::now() - SAVE_INTERVAL + Duration::from_secs(5);
    let mut saved_fingerprint = (0, 0);
    let mut last_outbound = Instant::now() - Duration::from_secs(60);
    // The next block's height at the previous tick (0: not seen yet).
    let mut last_next = 0u64;
    loop {
        tokio::time::sleep(inner.cfg.tick).await;
        let now = Instant::now();

        // Dandelion epoch and embargoes.
        let expired: Vec<Hash> = {
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
            st.stempool
                .iter()
                .filter(|(_, e)| now >= e.embargo)
                .map(|(id, _)| *id)
                .collect()
        };
        for id in expired {
            log::debug!("embargo expired for {}", short(&id));
            fluff(&inner, id, None).await;
        }

        // Announce a new tip.
        let (tip, header_height_now) = inner
            .with_chain(|c| ((c.tip_id(), *c.tip_header()), c.header_height()))
            .await;
        // Once per new height: pool re-announcement (docs/p2p.md §7), and
        // originated-set entries whose window ended are dropped (§8.1).
        let next = tip.1.height + 1;
        if next != last_next {
            if last_next != 0 {
                reannounce_pool(&inner, last_next, next).await;
            }
            last_next = next;
            if inner.state().originated.prune(next) > 0 {
                inner.save_originated().await;
            }
        }
        {
            let mut st = inner.state();
            if st.announced_tip != tip.0 {
                st.announced_tip = tip.0;
                let peers: Vec<PeerId> = st
                    .peers
                    .iter()
                    .filter(|(_, p)| p.height < tip.1.height)
                    .map(|(id, _)| *id)
                    .collect();
                for p in peers {
                    inner.send(&mut st, p, Message::Headers(vec![tip.1]));
                }
            }
        }

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
                if let Some((_, sent)) = p.ping {
                    if now.duration_since(sent) > PONG_TIMEOUT {
                        p.kill.notify_one();
                    }
                } else if now.duration_since(p.last_ping) > PING_INTERVAL {
                    p.ping = Some((nonce, now));
                    p.last_ping = now;
                    let _ = p.out.try_send(Message::Ping(nonce));
                }
                if p.headers_requested
                    .is_some_and(|t| now.duration_since(t) > HEADERS_TIMEOUT)
                {
                    p.headers_requested = None;
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
            // no longer have the transaction).
            for (id, p) in stale_txs {
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
                    (p.height > header_height || p.headers_pending)
                        && p.headers_requested.is_none()
                        && !p.headers_busy
                        && inner.header_queue_room(&st, &p.addr)
                })
                .map(|(id, _)| *id)
                .collect()
        };
        for p in behind {
            inner.request_headers(p).await;
        }
        schedule_downloads(&inner).await;

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
