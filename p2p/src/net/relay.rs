//! Transaction relay: inventory announcements, requests and retries.

use super::admission::ctx_rejected;
use super::dispatch::MAX_RELAY_FRAME;
use super::state::Inner;
use super::tx_requests::{add_announcer, room, TX_WANTED_CAP};
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

/// Transaction replies (`Tx` frames answering a peer's `GetTx`) queued in
/// one peer's control outbox or being written: at most this many frames...
pub(super) const SERVE_TX_FRAMES: usize = 32;
/// ...and this many bytes, unless it is the only one. It is also the most
/// one answer encodes at once (at least any one transaction).
pub(super) const SERVE_TX_BYTES: usize = MAX_RELAY_FRAME;
/// Node-wide: bytes of `GetTx` answers encoded and not yet written, over
/// all peers ([`ServeBudget`]).
pub(super) const SERVE_TX_TOTAL: usize = 64 * 1024 * 1024;
/// A peer that lets no queued reply be written for this long while more
/// wait is disconnected as a slow reader (no ban), as when its outbox
/// overflows. A `GetTx` answer that finds no node-wide room for this long
/// ends with `NotFound` for the rest (the requester asks elsewhere).
pub(super) const SERVE_TX_STALL: Duration = Duration::from_secs(60);

const _: () = assert!(SERVE_TX_TOTAL >= 2 * SERVE_TX_BYTES);

/// The node-wide byte budget of `GetTx` answers (RT-TM2P2P item 6): an
/// answer reserves [`SERVE_TX_BYTES`] before it encodes, keeps what it
/// encoded, and each byte is released when its frame is written, or when
/// its peer disconnects. At most [`SERVE_TX_TOTAL`] in all, whatever the
/// number of peers.
#[derive(Default)]
pub(super) struct ServeBudget {
    bytes: AtomicUsize,
    /// Woken (all waiters) whenever bytes are released.
    room: Notify,
}

impl ServeBudget {
    fn try_reserve(&self, n: usize) -> bool {
        self.bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                (v.saturating_add(n) <= SERVE_TX_TOTAL).then_some(v + n)
            })
            .is_ok()
    }

    fn release(&self, n: usize) {
        if n == 0 {
            return;
        }
        let _ = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(n))
            });
        self.room.notify_waiters();
    }

    /// Bytes reserved or queued now.
    pub(super) fn used(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

/// Bytes of the [`ServeBudget`] one answer holds and has not handed to its
/// peer's [`ReplyQueue`]; released when dropped.
struct Reservation {
    budget: Arc<ServeBudget>,
    left: usize,
}

impl Reservation {
    /// Keeps only `n` bytes.
    fn shrink_to(&mut self, n: usize) {
        if n < self.left {
            self.budget.release(self.left - n);
            self.left = n;
        }
    }

    /// `n` bytes move to a reply queue (still counted node-wide).
    fn hand_over(&mut self, n: usize) {
        self.left = self.left.saturating_sub(n);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.release(self.left);
    }
}

/// The transaction replies queued for one peer (TM2-17, docs/p2p.md §7):
/// counted by [`on_get_tx`] as it queues each (under the state lock, with
/// the peer registered), and by the writer once it has written each (only
/// [`on_get_tx`] sends `Tx`). Replies wait for room here instead of
/// overflowing the control outbox, whose overflow disconnects the peer.
/// Their bytes are part of the node-wide [`ServeBudget`].
pub(super) struct ReplyQueue {
    frames: AtomicUsize,
    bytes: AtomicUsize,
    /// Woken when a reply was written, and when the peer disconnected.
    room: Notify,
    budget: Arc<ServeBudget>,
}

impl ReplyQueue {
    pub(super) fn new(budget: Arc<ServeBudget>) -> Self {
        Self {
            frames: AtomicUsize::new(0),
            bytes: AtomicUsize::new(0),
            room: Notify::new(),
            budget,
        }
    }

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

    /// A reply of `len` bytes was written (the writer). Saturating, and the
    /// node-wide budget gets back only what this queue still held: a reply
    /// written after [`Self::closed`] is not released twice.
    pub(super) fn written(&self, len: usize) {
        let prev = self
            .bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(len))
            })
            .unwrap_or(0);
        let _ = self
            .frames
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                Some(v.saturating_sub(1))
            });
        self.budget.release(prev.min(len));
        self.room.notify_one();
    }

    /// The peer disconnected (called under the state lock, after it was
    /// removed): what it never got returns to the node-wide budget, and a
    /// waiting [`on_get_tx`] stops.
    pub(super) fn closed(&self) {
        let b = self.bytes.swap(0, Ordering::AcqRel);
        self.frames.store(0, Ordering::Release);
        self.budget.release(b);
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
/// everyone else's anchor. A restarted origin does not pool its own
/// transaction when its wallet resubmits it (docs/p2p.md §8.1): it learns
/// it back as a relay does. Only `InvTx`, through the usual trickle, to
/// peers not known to have it; never a `StemTx`.
pub(super) async fn reannounce_pool(inner: &Arc<Inner>, prev: u64, next: u64) {
    if next <= prev {
        return; // a reorganization to a lower (or the same) height
    }
    let pooled: Vec<(Hash, u64)> = inner
        .with_chain(|c| {
            if c.mempool().is_empty() {
                return Vec::new();
            }
            c.template()
                .txs
                .iter()
                .filter_map(|tx| {
                    let id = tx.hash();
                    c.mempool().admitted_at(&id).map(|a| (id, a))
                })
                .collect()
        })
        .await;
    let due: Vec<Hash> = pooled
        .into_iter()
        .filter(|(_, admitted)| {
            reannounce_due(
                prev.saturating_sub(*admitted),
                next.saturating_sub(*admitted),
            )
        })
        .map(|(id, _)| id)
        .collect();
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
        let mut room = room(&st, peer, now);
        for (id, in_mempool) in ids.into_iter().zip(known) {
            if in_mempool || st.recent_rejects_set.contains(&id) || ctx_rejected(&st, &id, &tip) {
                continue;
            }
            // A transaction in our stempool is treated like an unknown one:
            // requested, never fluffed because of an announcement. Answering
            // differently would tell a spy what is in our stempool, and let
            // it end the stem at will (I3-1). If it is really in fluff, the
            // transaction arrives and is pooled, which ends the embargo
            // (`on_tx`).
            //
            // Asked now, kept for later (`tx_wanted`, at its in-flight cap),
            // or a fallback announcer if asked of another one already
            // (`tx_requests` module). With no room for any of these the
            // announcement leaves no state behind, except its `known_txs`
            // entry (an id comes back with a later announcement).
            let asked = st.tx_requests.contains_key(&id);
            let wanted_room = st
                .peers
                .get(&peer)
                .is_some_and(|p| p.tx_wanted.len() < TX_WANTED_CAP);
            if !asked && room == 0 && !wanted_room {
                continue;
            }
            let in_queue = add_announcer(&mut st, id, peer);
            if asked {
                continue;
            }
            if room > 0 {
                room -= 1;
                st.tx_requests.insert(id, (peer, now));
                request.push(id);
            } else if in_queue {
                if let Some(p) = st.peers.get_mut(&peer) {
                    p.tx_wanted.push_back(id);
                }
            }
        }
        if !request.is_empty() {
            inner.send(&mut st, peer, Message::GetTx(request));
        }
    }
}

/// Answers a `GetTx` (docs/p2p.md §7). Serves only what we announced to this
/// peer and still have. Everything else gets the same `NotFound` answer, so
/// the reply reveals nothing about the stempool or mempool, and an honest
/// requester can move on immediately.
///
/// One `GetTx` may name up to `MAX_INV` (500) ids, far more than the
/// control outbox holds (64 frames). So the answers are paced (TM2-17):
/// encoded [`SERVE_TX_BYTES`] at a time from a node-wide reservation
/// ([`ServeBudget`]), and each queued only once the [`ReplyQueue`] has
/// room, which leaves the rest of the outbox to pongs and announcements.
/// Meanwhile this peer's slow lane waits, as Bitcoin Core stops processing
/// a peer's messages while its send buffer is full. Queueing them all at
/// once overflowed the outbox and disconnected honest requesters during
/// any burst. An id named twice is answered once. A requester that reads
/// nothing for [`SERVE_TX_STALL`] is disconnected as a slow reader, as
/// before; one that disconnects stops the answer.
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
        let Some(mut resv) = reserve(inner, peer).await else {
            if inner.state().peers.contains_key(&peer) {
                // No node-wide room for a long time: the rest is not
                // served now, and the requester asks another announcer.
                missing.extend(wanted.drain(..).map(|(id, _)| id));
                break;
            }
            return;
        };
        let (txs, miss, rest) = inner
            .with_chain(move |c| {
                let (mut txs, mut missing, mut bytes) = (Vec::new(), Vec::new(), 0usize);
                while let Some((id, ok)) = wanted.pop_front() {
                    match c.mempool().get(&id).filter(|_| ok) {
                        Some(t) => {
                            let t = t.encode();
                            if !txs.is_empty() && bytes + t.len() > SERVE_TX_BYTES {
                                wanted.push_front((id, ok));
                                break;
                            }
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
        resv.shrink_to(txs.iter().map(Vec::len).sum());
        for t in txs {
            let len = t.len();
            if !reply_room(inner, peer, &replies, len).await {
                return;
            }
            let mut st = inner.state();
            if !st.peers.contains_key(&peer) {
                return;
            }
            replies.queued(len);
            resv.hand_over(len);
            inner.send(&mut st, peer, Message::Tx(t));
        }
    }
    // Last, so it still ends the answer.
    if !missing.is_empty() {
        inner.send_now(peer, Message::NotFound(missing));
    }
}

/// Reserves [`SERVE_TX_BYTES`] of the node-wide [`ServeBudget`], waiting
/// for room. `None`: the peer is gone, or no room came for
/// [`SERVE_TX_STALL`] (other peers hold the budget).
async fn reserve(inner: &Inner, peer: PeerId) -> Option<Reservation> {
    let budget = inner.serve_budget.clone();
    let deadline = tokio::time::Instant::now() + SERVE_TX_STALL;
    loop {
        let room = budget.room.notified();
        tokio::pin!(room);
        room.as_mut().enable();
        if !inner.state().peers.contains_key(&peer) {
            return None;
        }
        if budget.try_reserve(SERVE_TX_BYTES) {
            return Some(Reservation {
                budget: budget.clone(),
                left: SERVE_TX_BYTES,
            });
        }
        if tokio::time::timeout_at(deadline, room).await.is_err() {
            log::debug!("peer {peer}: no node-wide room for transaction answers");
            return None;
        }
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
        let q = ReplyQueue::new(Arc::new(ServeBudget::default()));
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

    /// RT-TM2P2P item 6: the node-wide budget never holds more than
    /// `SERVE_TX_TOTAL`; a reservation returns what it did not hand over,
    /// a written reply returns its bytes once, and a disconnect returns what
    /// its queue held, never twice.
    #[test]
    fn the_node_wide_serving_budget_is_exact() {
        let budget = Arc::new(ServeBudget::default());
        let n = SERVE_TX_TOTAL / SERVE_TX_BYTES;
        let held: Vec<Reservation> = (0..n)
            .map(|_| {
                assert!(budget.try_reserve(SERVE_TX_BYTES));
                Reservation {
                    budget: budget.clone(),
                    left: SERVE_TX_BYTES,
                }
            })
            .collect();
        assert!(!budget.try_reserve(SERVE_TX_BYTES), "full");
        drop(held);
        assert_eq!(budget.used(), 0);

        let q = ReplyQueue::new(budget.clone());
        assert!(budget.try_reserve(SERVE_TX_BYTES));
        let mut r = Reservation {
            budget: budget.clone(),
            left: SERVE_TX_BYTES,
        };
        r.shrink_to(300);
        assert_eq!(budget.used(), 300);
        q.queued(100);
        r.hand_over(100);
        q.queued(100);
        r.hand_over(100);
        drop(r); // 100 never encoded into a reply
        assert_eq!(budget.used(), 200);
        q.written(100);
        assert_eq!(budget.used(), 100);
        q.closed();
        assert_eq!(budget.used(), 0);
        q.written(100); // the writer finishing after the disconnect
        assert_eq!(budget.used(), 0);
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
