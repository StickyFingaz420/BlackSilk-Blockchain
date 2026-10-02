//! Transaction relay: inventory announcements, requests and retries.

use super::admission::ctx_rejected;
use super::dispatch::SLOW_LANE_RELAY;
use super::state::{Inner, State};
use crate::dandelion::{exponential, PeerId};
use crate::limits::score;
use crate::message::Message;
use blacksilk_chain::mempool::MEMPOOL_EXPIRY_BLOCKS;
use blacksilk_consensus::Hash;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

pub(super) const TX_TIMEOUT: Duration = Duration::from_secs(30);

/// Transactions requested from one peer at a time (TM2-17). Its answers
/// wait in its slow lane, where relay beyond `SLOW_LANE_RELAY` messages is
/// dropped: a request for a whole burst lost most of the answers there, to
/// a timeout and the next re-announcement. The ids it announced beyond
/// this wait in `Peer::tx_wanted` and are asked as its requests end
/// ([`request_wanted`]), as Bitcoin Core limits the transactions in flight
/// per peer.
pub(super) const TX_IN_FLIGHT: usize = SLOW_LANE_RELAY / 2;

/// Most ids waiting in one peer's `tx_wanted` (32 bytes each); an id over
/// it is still asked of another announcer, or at a later announcement.
pub(super) const TX_WANTED_CAP: usize = 2_000;

/// Transaction replies (`Tx` frames answering a peer's `GetTx`) queued in
/// one peer's control outbox or being written: at most this many frames...
pub(super) const SERVE_TX_FRAMES: usize = 32;
/// ...and this many bytes, unless it is the only one (a transaction of any
/// size is served). It is also the most a `GetTx` answer encodes at once.
pub(super) const SERVE_TX_BYTES: usize = 4 * 1024 * 1024;
/// A peer that lets no queued reply be written for this long while more
/// wait is disconnected as a slow reader (no ban), as when its outbox
/// overflows.
pub(super) const SERVE_TX_STALL: Duration = Duration::from_secs(60);

/// The transaction replies queued for one peer (TM2-17, docs/p2p.md §7):
/// counted by [`on_get_tx`] as it queues each, and by the writer once it
/// has written each (only [`on_get_tx`] sends `Tx`). Replies wait for room
/// here instead of overflowing the control outbox, whose overflow
/// disconnects the peer.
#[derive(Default)]
pub(super) struct ReplyQueue {
    frames: AtomicUsize,
    bytes: AtomicUsize,
    /// Woken when a reply was written, and when the peer disconnected.
    room: Notify,
}

impl ReplyQueue {
    /// Whether a reply of `len` bytes may be queued now.
    fn fits(&self, len: usize) -> bool {
        let frames = self.frames.load(Ordering::Acquire);
        frames == 0
            || (frames < SERVE_TX_FRAMES
                && self.bytes.load(Ordering::Acquire).saturating_add(len) <= SERVE_TX_BYTES)
    }

    fn queued(&self, len: usize) {
        self.bytes.fetch_add(len, Ordering::AcqRel);
        self.frames.fetch_add(1, Ordering::AcqRel);
    }

    /// A reply of `len` bytes was written (the writer). Saturating: a
    /// miscount must never wrap into a queue that is full forever.
    pub(super) fn written(&self, len: usize) {
        let sub = |n: usize| move |v: usize| Some(v.saturating_sub(n));
        let _ = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, sub(len));
        let _ = self
            .frames
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, sub(1));
        self.room.notify_one();
    }

    /// The peer disconnected: a waiting [`on_get_tx`] stops.
    pub(super) fn closed(&self) {
        self.room.notify_one();
    }
}

const ANNOUNCED_CAP: usize = 50_000;

/// Remembers transaction ids in a per-peer set, clearing it when it grows past
/// `ANNOUNCED_CAP` (the set only saves redundant announcements; forgetting is
/// harmless, growing without bound is not).
pub(super) fn remember(set: &mut HashSet<Hash>, ids: impl IntoIterator<Item = Hash>) {
    if set.len() > ANNOUNCED_CAP {
        set.clear();
    }
    set.extend(ids);
}

impl Inner {
    /// Queues an `InvTx` announcement to every transaction-relaying peer except
    /// `except` and peers that already know it (docs/p2p.md §7).
    pub(super) fn announce_tx(&self, id: Hash, except: Option<PeerId>) {
        let mut st = self.state();
        let now = Instant::now();
        let (out_mean, in_mean) = (self.cfg.trickle_outbound, self.cfg.trickle_inbound);
        let ids: Vec<PeerId> = st.peers.keys().copied().collect();
        for pid in ids {
            if Some(pid) == except {
                continue;
            }
            let delay = {
                let inbound = st.peers[&pid].inbound;
                exponential(if inbound { in_mean } else { out_mean }, &mut st.rng)
            };
            let p = st.peers.get_mut(&pid).expect("listed");
            if !p.relay_txs || p.known_txs.contains(&id) || p.announced_to.contains(&id) {
                continue;
            }
            if p.inv_queue.is_empty() {
                p.next_inv = now + delay;
            }
            p.inv_queue.push(id);
        }
    }
}

/// Pool re-announcement (docs/p2p.md §7; dossier 38 §3.4 item 3): the first
/// pool age at which a pooled transaction is announced again, in blocks...
const REANNOUNCE_FIRST: u64 = 10;
/// ...the largest gap between two re-announcements (the gap doubles from
/// `REANNOUNCE_FIRST` up to this)...
const REANNOUNCE_MAX_GAP: u64 = 360;
/// ...and the age after which it is never re-announced: half the pool
/// expiry.
const REANNOUNCE_STOP: u64 = MEMPOOL_EXPIRY_BLOCKS / 2;

/// Whether a re-announcement point of the schedule (pool ages 10, 20, 40,
/// 80, 160, 320, 640, 1000) lies in `(from, to]`. A range, not one age: the
/// tip can advance by several blocks between two maintenance ticks.
pub(super) fn reannounce_due(from: u64, to: u64) -> bool {
    let (mut at, mut gap) = (REANNOUNCE_FIRST, REANNOUNCE_FIRST);
    while at <= REANNOUNCE_STOP && at <= to {
        if at > from {
            return true;
        }
        at += gap;
        gap = (gap * 2).min(REANNOUNCE_MAX_GAP);
    }
    false
}

/// Announces again the pooled transactions whose pool age crossed a point of
/// the schedule ([`reannounce_due`]) as the next block's height moved from
/// `prev` to `next`, if they are in the next block template (they should
/// have been mined, so other pools may lack them). The age counts from the
/// height the transaction was pooled for: at or after its fluff, or its
/// readmission after a reorganization. Honest nodes pool it within seconds
/// of each other, so they re-announce it at the same heights, and the
/// origin counts exactly as they do (TM2-P1): never from its relay height,
/// which a block found during the stem, or a reorganization, puts before
/// everyone else's anchor. Only a held copy of a transaction originated
/// here (pooled late, `Originated::anchor`) counts from the height the
/// origin pooled it for before (docs/p2p.md §7, §8.1). Only `InvTx`,
/// through the usual trickle, to peers not known to have it; never a
/// `StemTx`.
pub(super) async fn reannounce_pool(inner: &Arc<Inner>, prev: u64, next: u64) {
    if next <= prev {
        return; // a reorganization to a lower (or the same) height
    }
    let held: Vec<Hash> = inner
        .state()
        .originated
        .held()
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    // Each held copy with its current pool height, if still pooled.
    type HeldNow = Vec<(Hash, Option<u64>)>;
    let (pooled, held_now): (Vec<(Hash, u64)>, HeldNow) = inner
        .with_chain(move |c| {
            let held_now = held
                .into_iter()
                .map(|id| (id, c.mempool().admitted_at(&id)))
                .collect();
            if c.mempool().is_empty() {
                return (Vec::new(), held_now);
            }
            let pooled = c
                .template()
                .txs
                .iter()
                .filter_map(|tx| {
                    let id = tx.hash();
                    c.mempool().admitted_at(&id).map(|a| (id, a))
                })
                .collect();
            (pooled, held_now)
        })
        .await;
    let (due, changed) = {
        let mut st = inner.state();
        st.originated.refresh_held(&held_now);
        let mut changed = false;
        let mut due = Vec::new();
        for (id, admitted) in pooled {
            // A transaction originated here, pooled as every node pools it
            // (a reorganization readmitted it, say): the anchor a held copy
            // would use after a restart follows.
            changed |= st.originated.note_pooled(&id, admitted);
            let Some(anchor) = st.originated.anchor(&id, admitted) else {
                continue;
            };
            if reannounce_due(prev.saturating_sub(anchor), next.saturating_sub(anchor)) {
                due.push(id);
            }
        }
        (due, changed)
    };
    if changed {
        inner.save_originated().await;
    }
    for id in due {
        inner.announce_tx(id, None);
    }
}

pub(super) async fn on_inv_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let (ids, known, tip): (Vec<Hash>, Vec<bool>, Hash) = inner
        .with_chain(move |c| {
            let known = ids.iter().map(|id| c.mempool().contains(id)).collect();
            (ids, known, c.tip_id())
        })
        .await;
    let mut request = Vec::new();
    let mut changed = false;
    {
        let mut st = inner.state();
        let now = Instant::now();
        let Some(p) = st.peers.get_mut(&peer) else {
            return;
        };
        if !p.limits.txs.take(ids.len() as f64 * 0.1, now) {
            drop(st);
            inner.misbehave(peer, score::RATE, "inv rate");
            return;
        }
        remember(&mut p.known_txs, ids.iter().copied());
        let next = inner.summary.load().height + 1;
        let mut room = TX_IN_FLIGHT.saturating_sub(in_flight(&st, peer));
        for (id, in_mempool) in ids.into_iter().zip(known) {
            if in_mempool {
                // A held copy of our own transaction, pooled without a pool
                // height (a restart before its fluff): a relay that lost it
                // pools it on this announcement, so it anchors here.
                changed |= st.originated.held_announced(&id, next);
                continue;
            }
            if st.recent_rejects_set.contains(&id) || ctx_rejected(&st, &id, &tip) {
                continue;
            }
            // A transaction in our stempool is treated like an unknown one:
            // requested, never fluffed because of an announcement. Answering
            // differently would tell a spy what is in our stempool, and let
            // it end the stem at will (I3-1). If it is really in fluff, the
            // transaction arrives and is pooled, which ends the embargo
            // (`on_tx`).
            //
            // Asked now, kept for later (`tx_wanted`, at `TX_IN_FLIGHT`), or
            // a fallback announcer if asked of another one already. With no
            // room for any of these the announcement is dropped, and leaves
            // no state behind (an id comes back with a later announcement).
            let asked = st.tx_requests.contains_key(&id);
            let keep = if asked || room > 0 {
                true
            } else {
                st.peers
                    .get(&peer)
                    .is_some_and(|p| p.tx_wanted.len() < TX_WANTED_CAP)
            };
            if !keep {
                continue;
            }
            let q = st.tx_announcers.entry(id).or_default();
            if !q.contains(&peer) && q.len() < 8 {
                q.push_back(peer);
            }
            if asked {
                continue;
            }
            if room > 0 {
                room -= 1;
                st.tx_requests.insert(id, (peer, now));
                request.push(id);
            } else if let Some(p) = st.peers.get_mut(&peer) {
                p.tx_wanted.push_back(id);
            }
        }
        if !request.is_empty() {
            inner.send(&mut st, peer, Message::GetTx(request));
        }
    }
    if changed {
        inner.save_originated().await;
    }
}

/// Answers a `GetTx` (docs/p2p.md §7). Serves only what we announced to this
/// peer and still have. Everything else gets the same `NotFound` answer, so
/// the reply reveals nothing about the stempool or mempool, and an honest
/// requester can move on immediately.
///
/// One `GetTx` may name up to `MAX_INV` (500) ids, far more than the
/// control outbox holds (64 frames), and an honest node asks for all the
/// unknown ids of one announcement at once (`on_inv_tx`). So the answers
/// are paced (TM2-17): encoded [`SERVE_TX_BYTES`] at a time, and each
/// queued only once the [`ReplyQueue`] has room, which leaves the rest of
/// the outbox to pongs and announcements. Meanwhile this peer's slow lane
/// waits, as Bitcoin Core stops processing a peer's messages while its send
/// buffer is full. Queueing them all at once overflowed the outbox and
/// disconnected honest requesters during any burst. An id named twice is
/// answered once. A requester that reads nothing for [`SERVE_TX_STALL`] is
/// disconnected as a slow reader, as before; one that disconnects stops
/// the answer.
pub(super) async fn on_get_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let (mut wanted, replies): (VecDeque<(Hash, bool)>, Arc<ReplyQueue>) = {
        let st = inner.state();
        let Some(p) = st.peers.get(&peer) else { return };
        let mut seen = HashSet::new();
        let wanted = ids
            .into_iter()
            .filter(|id| seen.insert(*id))
            .map(|id| (id, p.announced_to.contains(&id)))
            .collect();
        (wanted, p.replies.clone())
    };
    let mut missing = Vec::new();
    while !wanted.is_empty() {
        let (txs, miss, rest) = inner
            .with_chain(move |c| {
                let (mut txs, mut missing, mut bytes) = (Vec::new(), Vec::new(), 0usize);
                while bytes < SERVE_TX_BYTES {
                    let Some((id, ok)) = wanted.pop_front() else {
                        break;
                    };
                    match c.mempool().get(&id).filter(|_| ok) {
                        Some(t) => {
                            let t = t.encode();
                            bytes += t.len();
                            txs.push(t);
                        }
                        None => missing.push(id),
                    }
                }
                (txs, missing, wanted)
            })
            .await;
        wanted = rest;
        missing.extend(miss);
        for t in txs {
            let len = t.len();
            if !reply_room(inner, peer, &replies, len).await {
                return;
            }
            replies.queued(len);
            inner.send_now(peer, Message::Tx(t));
        }
    }
    // Last, so it still ends the answer.
    if !missing.is_empty() {
        inner.send_now(peer, Message::NotFound(missing));
    }
}

/// Waits until `replies` has room for a reply of `len` bytes. `false`: the
/// peer is gone, or it let nothing be written for [`SERVE_TX_STALL`] and is
/// disconnected now as a slow reader.
async fn reply_room(inner: &Inner, peer: PeerId, replies: &ReplyQueue, len: usize) -> bool {
    loop {
        // Registered before the checks, so a write in between still wakes
        // it.
        let room = replies.room.notified();
        tokio::pin!(room);
        room.as_mut().enable();
        if !inner.state().peers.contains_key(&peer) {
            return false;
        }
        if replies.fits(len) {
            return true;
        }
        if tokio::time::timeout(SERVE_TX_STALL, room).await.is_err() {
            let mut st = inner.state();
            if let Some(p) = st.peers.get(&peer) {
                log::debug!(
                    "peer {} reads no transaction replies; disconnecting",
                    p.addr
                );
                p.kill.notify_one();
                st.slow_disconnects += 1;
            }
            return false;
        }
    }
}

/// Transaction requests outstanding to `peer`.
fn in_flight(st: &State, peer: PeerId) -> usize {
    st.tx_requests.values().filter(|(p, _)| *p == peer).count()
}

/// Asks `peer` for the ids waiting in its `tx_wanted` while it has fewer
/// than [`TX_IN_FLIGHT`] requests outstanding: after one of its requests
/// ended. An id is asked only if still wanted from it: announced by it
/// (still in its announcer queue, which receipt or a final failure
/// removes) and asked of no one.
pub(super) fn request_wanted(inner: &Inner, st: &mut State, peer: PeerId, now: Instant) {
    let mut room = TX_IN_FLIGHT.saturating_sub(in_flight(st, peer));
    let mut ask = Vec::new();
    while room > 0 {
        let Some(id) = st
            .peers
            .get_mut(&peer)
            .and_then(|p| p.tx_wanted.pop_front())
        else {
            break;
        };
        let announced = st.tx_announcers.get(&id).is_some_and(|q| q.contains(&peer));
        if !announced || st.tx_requests.contains_key(&id) {
            continue;
        }
        st.tx_requests.insert(id, (peer, now));
        ask.push(id);
        room -= 1;
    }
    if !ask.is_empty() {
        inner.send(st, peer, Message::GetTx(ask));
    }
}

/// Drops a transaction request that `failed` could not answer and asks the next
/// announcer, if any (or queues it there, at [`TX_IN_FLIGHT`]); `failed`
/// may then be asked for what waits for it.
pub(super) fn retry_tx(inner: &Inner, st: &mut State, id: Hash, failed: PeerId, now: Instant) {
    st.tx_requests.remove(&id);
    let next = st.tx_announcers.get_mut(&id).and_then(|q| {
        q.retain(|x| *x != failed);
        q.front().copied()
    });
    match next {
        Some(n) if in_flight(st, n) < TX_IN_FLIGHT => {
            st.tx_requests.insert(id, (n, now));
            inner.send(st, n, Message::GetTx(vec![id]));
        }
        Some(n) => {
            // Kept for when `n` has room; with none there either, dropped
            // with its announcers (it comes back with a later
            // announcement), so no announcer entry outlives every request.
            let kept = st.peers.get_mut(&n).is_some_and(|p| {
                let room = p.tx_wanted.len() < TX_WANTED_CAP;
                if room {
                    p.tx_wanted.push_back(id);
                }
                room
            });
            if !kept {
                st.tx_announcers.remove(&id);
            }
        }
        None => {
            st.tx_announcers.remove(&id);
        }
    }
    request_wanted(inner, st, failed, now);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dossier 38 §3.4 item 3: the re-announcement points are the pool ages
    /// 10, 20, 40, 80, 160, 320, 640 and 1000 (the gap doubles from 10, capped
    /// at 360, and nothing after half the expiry); each is due exactly once
    /// however the heights advance.
    #[test]
    fn reannouncement_follows_the_backoff_schedule() {
        let points: Vec<u64> = (0..=MEMPOOL_EXPIRY_BLOCKS)
            .filter(|&a| reannounce_due(a.saturating_sub(1), a) && a > 0)
            .collect();
        assert_eq!(points, [10, 20, 40, 80, 160, 320, 640, 1000]);
        assert!(!reannounce_due(0, 9));
        assert!(reannounce_due(0, 10));
        assert!(!reannounce_due(10, 19));
        assert!(reannounce_due(15, 45), "a jump over a point");
        assert!(!reannounce_due(1000, MEMPOOL_EXPIRY_BLOCKS * 2), "stopped");
        assert!(!reannounce_due(20, 20), "an empty range");
    }

    /// TM2-17: the reply queue takes up to `SERVE_TX_FRAMES` frames and
    /// `SERVE_TX_BYTES` bytes, any one reply when empty, and room returns
    /// as replies are written.
    #[test]
    fn the_reply_queue_is_bounded_in_frames_and_bytes() {
        let q = ReplyQueue::default();
        assert!(q.fits(usize::MAX), "a lone reply of any size");
        q.queued(SERVE_TX_BYTES * 2);
        assert!(!q.fits(1), "over the bytes");
        q.written(SERVE_TX_BYTES * 2);
        for _ in 0..SERVE_TX_FRAMES {
            assert!(q.fits(100));
            q.queued(100);
        }
        assert!(!q.fits(100), "over the frames");
        q.written(100);
        assert!(q.fits(100));
        assert!(!q.fits(SERVE_TX_BYTES), "over the bytes with others queued");
        const { assert!(SERVE_TX_FRAMES < 64) };
    }

    /// M2: the per-peer id sets (`known_txs`, `announced_to`) stay bounded.
    #[test]
    fn remembered_ids_are_capped() {
        let mut set = HashSet::new();
        for i in 0..(3 * ANNOUNCED_CAP as u64) {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&i.to_le_bytes());
            remember(&mut set, [id]);
            assert!(set.len() <= ANNOUNCED_CAP + 1);
        }
    }
}
