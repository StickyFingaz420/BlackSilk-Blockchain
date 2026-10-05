//! Serving `GetTx` (docs/p2p.md §7, "Serving"): paced answers, a per-peer
//! reply queue, and a node-wide byte budget with fair waiting (TM2-17,
//! RT-TM2P2P item 6, RT2-TM2P2P F3).

use super::dispatch::MAX_RELAY_FRAME;
use super::state::Inner;
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

/// `Tx` answers queued in one peer's answers outbox (`ANSWERS_OUTBOX` in
/// `conn.rs`, twice this) or being written: at most this many frames; the
/// rest of that outbox holds their `NotFound`s. Answers no longer share the
/// control outbox, so pongs and announcements never wait behind them.
pub(super) const SERVE_TX_FRAMES: usize = 32;
/// The most one answer step encodes at once (at least one transaction).
pub(super) const SERVE_TX_BYTES: usize = MAX_RELAY_FRAME;
/// Node-wide: bytes of `GetTx` answers encoded and not yet written.
pub(super) const SERVE_TX_TOTAL: usize = 64 * 1024 * 1024;
/// Of it, the slice only outbound peers use (inbound peers cannot crowd
/// out the peers this node chose).
pub(super) const SERVE_TX_OUTBOUND: usize = SERVE_TX_TOTAL / 4;
/// What one peer may hold of it.
pub(super) const SERVE_TX_PEER: usize = SERVE_TX_TOTAL / 8;
/// A peer whose queued answers make no progress for this long while more
/// wait is disconnected as a slow reader (no ban), as an outbox overflow is.
/// An answer that finds no room for this long ends with `NotFound` for the
/// rest (the requester asks another announcer).
pub(super) const SERVE_TX_STALL: Duration = Duration::from_secs(60);
/// The least write rate a peer holding more than [`SLOW_SHARE`] must keep:
/// its oldest queued answer must be written within [`SLOW_BASE`] plus its
/// size at this rate, or it is disconnected (no ban).
pub(super) const SLOW_RATE: usize = 64 * 1024;
pub(super) const SLOW_BASE: Duration = Duration::from_secs(10);
pub(super) const SLOW_SHARE: usize = SERVE_TX_TOTAL / 16;
/// The holding above which the rule applies while other answers wait for
/// room in the peer's pool (RT3 F5: a holder of up to `SLOW_SHARE` was never
/// flagged however slowly it read).
pub(super) const SLOW_SHARE_CONTENDED: usize = 1024 * 1024;

/// Budget units: KiB (semaphore permits are `u32`).
const UNIT: usize = 1024;

fn units(bytes: usize) -> u32 {
    bytes.div_ceil(UNIT).max(1) as u32
}

const _: () = assert!(SERVE_TX_PEER >= SERVE_TX_BYTES);
const _: () = assert!(SERVE_TX_OUTBOUND >= SERVE_TX_BYTES);
const _: () = assert!(SERVE_TX_TOTAL - SERVE_TX_OUTBOUND >= SERVE_TX_BYTES);

/// The node-wide byte budget of `GetTx` answers. Two fair (FIFO) pools: a
/// slice for outbound peers and the rest for inbound ones. An answer holds
/// exactly its transactions' sizes, from before it encodes them until each
/// frame is written or its peer disconnects.
pub(super) struct ServeBudget {
    outbound: Arc<Semaphore>,
    shared: Arc<Semaphore>,
    /// Answers waiting for room, per pool (inbound, outbound).
    waiting: [AtomicUsize; 2],
}

impl Default for ServeBudget {
    fn default() -> Self {
        Self {
            outbound: Arc::new(Semaphore::new(SERVE_TX_OUTBOUND / UNIT)),
            shared: Arc::new(Semaphore::new((SERVE_TX_TOTAL - SERVE_TX_OUTBOUND) / UNIT)),
            waiting: [AtomicUsize::new(0), AtomicUsize::new(0)],
        }
    }
}

/// Counts an answer waiting for room in a pool while it lives.
struct Waiting<'a>(&'a AtomicUsize);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl ServeBudget {
    /// Whether answers wait for room in this pool: then the slow-reader
    /// rule applies from [`SLOW_SHARE_CONTENDED`] (RT3 F5).
    pub(super) fn contended(&self, outbound: bool) -> bool {
        self.waiting[usize::from(outbound)].load(Ordering::Acquire) > 0
    }

    fn wait(&self, outbound: bool) -> Waiting<'_> {
        let w = &self.waiting[usize::from(outbound)];
        w.fetch_add(1, Ordering::AcqRel);
        Waiting(w)
    }

    /// Bytes held now (rounded to KiB; the unit tests' probe).
    #[cfg(test)]
    pub(super) fn used(&self) -> usize {
        let free = self.outbound.available_permits() + self.shared.available_permits();
        SERVE_TX_TOTAL - free * UNIT
    }

    fn pool(&self, outbound: bool) -> Arc<Semaphore> {
        if outbound {
            self.outbound.clone()
        } else {
            self.shared.clone()
        }
    }
}

/// One queued answer: its size, when it reached the front of the queue
/// (RT3 F3: the slow-reader rule times the frame being written, not the
/// wait behind earlier ones), and its share of the budgets (released when
/// it is written).
struct Queued {
    len: usize,
    at: Instant,
    _peer: OwnedSemaphorePermit,
    _pool: OwnedSemaphorePermit,
}

/// The answers queued for one peer (only [`on_get_tx`] sends `Tx`, so the
/// writer's `Tx` frames are these, in order).
pub(super) struct ReplyQueue {
    queue: Mutex<VecDeque<Queued>>,
    /// The peer's own share of the node-wide budget ([`SERVE_TX_PEER`]).
    share: Arc<Semaphore>,
    /// Woken when an answer was written, and when the peer disconnected.
    room: Notify,
}

impl Default for ReplyQueue {
    fn default() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            share: Arc::new(Semaphore::new(SERVE_TX_PEER / UNIT)),
            room: Notify::new(),
        }
    }
}

impl ReplyQueue {
    fn frames(&self) -> usize {
        self.queue.lock().map(|q| q.len()).unwrap_or(0)
    }

    /// Bytes queued.
    #[cfg(test)]
    fn bytes(&self) -> usize {
        self.queue
            .lock()
            .map(|q| q.iter().map(|x| x.len).sum())
            .unwrap_or(0)
    }

    /// An answer was written (the writer): its budget is released.
    pub(super) fn written(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.pop_front();
            if let Some(front) = q.front_mut() {
                front.at = Instant::now();
            }
        }
        self.room.notify_one();
    }

    /// Queues an answer; it is timed from when it reaches the front.
    fn push(&self, mut item: Queued) {
        if let Ok(mut q) = self.queue.lock() {
            item.at = Instant::now();
            q.push_back(item);
        }
    }

    /// The peer disconnected: everything it held is released, and a
    /// waiting [`on_get_tx`] stops.
    pub(super) fn closed(&self) {
        if let Ok(mut q) = self.queue.lock() {
            q.clear();
        }
        self.share.close();
        self.room.notify_one();
    }

    /// Whether this peer holds more than [`SLOW_SHARE`] and its oldest
    /// answer waits longer than [`SLOW_BASE`] plus its size at
    /// [`SLOW_RATE`]: a reader too slow for what it holds.
    pub(super) fn too_slow(&self, now: Instant, contended: bool) -> bool {
        let share = if contended {
            SLOW_SHARE_CONTENDED
        } else {
            SLOW_SHARE
        };
        let Ok(q) = self.queue.lock() else {
            return false;
        };
        let held: usize = q.iter().map(|x| x.len).sum();
        let Some(front) = q.front() else {
            return false;
        };
        let allowed = SLOW_BASE + Duration::from_secs_f64(front.len as f64 / SLOW_RATE as f64);
        held > share && now.duration_since(front.at) > allowed
    }
}

/// Answers a `GetTx` (docs/p2p.md §7). Serves only what we announced to this
/// peer and still have. Everything else gets the same `NotFound` answer, so
/// the reply reveals nothing about the stempool or mempool, and an honest
/// requester can move on immediately.
///
/// One `GetTx` may name up to `MAX_INV` (500) ids, far more than the
/// control outbox holds (64 frames). So the answer is paced: at most
/// [`SERVE_TX_BYTES`] at a time, each step holding exactly its
/// transactions' sizes of the peer's share and of the node-wide budget
/// (FIFO waiting, an outbound slice), and each `Tx` queued only while fewer
/// than [`SERVE_TX_FRAMES`] wait. Meanwhile this peer's slow lane waits, as
/// Bitcoin Core stops processing a peer's messages while its send buffer is
/// full. An id named twice is answered once.
pub(super) async fn on_get_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    let (mut wanted, replies, outbound): (VecDeque<(Hash, bool)>, Arc<ReplyQueue>, bool) = {
        let st = inner.state();
        let Some(p) = st.peers.get(&peer) else { return };
        let mut seen = HashSet::new();
        let wanted = ids
            .into_iter()
            .filter(|id| seen.insert(*id))
            .map(|id| (id, p.announced_to.contains(&id)))
            .collect();
        (wanted, p.replies.clone(), !p.inbound)
    };
    let pool = inner.serve_budget.pool(outbound);
    let mut missing = Vec::new();
    while !wanted.is_empty() {
        // The next step's transactions and their sizes (encoded in the
        // command and dropped there: nothing is held before the budget).
        let (step, miss, rest) = inner
            .with_chain(move |c| {
                let (mut step, mut missing, mut bytes) = (Vec::new(), Vec::new(), 0usize);
                while let Some((id, ok)) = wanted.pop_front() {
                    match c.mempool().get(&id).filter(|_| ok) {
                        Some(t) => {
                            let len = t.encode().len();
                            if !step.is_empty() && bytes + len > SERVE_TX_BYTES {
                                wanted.push_front((id, ok));
                                break;
                            }
                            bytes += len;
                            step.push((id, len));
                        }
                        None => missing.push(id),
                    }
                }
                (step, missing, wanted)
            })
            .await;
        wanted = rest;
        missing.extend(miss);
        if step.is_empty() {
            continue;
        }
        let need: u32 = step.iter().map(|(_, l)| units(*l)).sum();
        let waiting = inner.serve_budget.wait(outbound);
        let got = acquire(&replies, &pool, need).await;
        drop(waiting);
        let Some((mut mine, mut pooled)) = got else {
            // Gone, or no room for a long time: the rest is not served now.
            missing.extend(step.into_iter().map(|(id, _)| id));
            missing.extend(wanted.drain(..).map(|(id, _)| id));
            break;
        };
        let ids: Vec<Hash> = step.iter().map(|(id, _)| *id).collect();
        let txs: Vec<(Hash, Option<Vec<u8>>)> = inner
            .with_chain(move |c| {
                ids.into_iter()
                    .map(|id| (id, c.mempool().get(&id).map(|t| t.encode())))
                    .collect()
            })
            .await;
        for (id, t) in txs {
            let Some(t) = t else {
                missing.push(id);
                continue;
            };
            let len = t.len();
            if !frame_room(inner, peer, &replies).await {
                return;
            }
            // A transaction's size may differ from the step's measure only
            // if it left the pool and came back: never more than held.
            let n = (units(len) as usize).min(mine.num_permits());
            let peer_part = mine.split(n);
            let pool_part = pooled.split(n);
            let (Some(peer_part), Some(pool_part)) = (peer_part, pool_part) else {
                missing.push(id);
                continue;
            };
            let mut st = inner.state();
            if !st.peers.contains_key(&peer) {
                return;
            }
            // Asked for and answered: no longer owed to a reconnect (RT4).
            if let Some(p) = st.peers.get_mut(&peer) {
                p.recent_inv.retain(|(h, _)| *h != id);
            }
            replies.push(Queued {
                len,
                at: Instant::now(),
                _peer: peer_part,
                _pool: pool_part,
            });
            inner.send_answer(&mut st, peer, Message::Tx(t));
        }
        // Units not used (a transaction left the pool meanwhile) are
        // released here, with `mine` and `pooled`.
    }
    // Last, so it still ends the answer.
    if !missing.is_empty() {
        inner.send_answer(&mut inner.state(), peer, Message::NotFound(missing));
    }
}

/// Takes `n` units of the peer's share, then of its pool, waiting in FIFO
/// order for at most [`SERVE_TX_STALL`]. `None`: the peer is gone, or no
/// room came in time.
async fn acquire(
    replies: &ReplyQueue,
    pool: &Arc<Semaphore>,
    n: u32,
) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
    let take = async {
        let mine = replies.share.clone().acquire_many_owned(n).await.ok()?;
        let pooled = pool.clone().acquire_many_owned(n).await.ok()?;
        Some((mine, pooled))
    };
    tokio::time::timeout(SERVE_TX_STALL, take)
        .await
        .ok()
        .flatten()
}

/// Waits until fewer than [`SERVE_TX_FRAMES`] answers are queued for
/// `peer`. `false`: the peer is gone, or nothing was written for
/// [`SERVE_TX_STALL`] and it is disconnected now as a slow reader.
async fn frame_room(inner: &Inner, peer: PeerId, replies: &ReplyQueue) -> bool {
    loop {
        // Registered before the checks, so a write in between still wakes
        // it.
        let room = replies.room.notified();
        tokio::pin!(room);
        room.as_mut().enable();
        if !inner.state().peers.contains_key(&peer) {
            return false;
        }
        if replies.frames() < SERVE_TX_FRAMES {
            return true;
        }
        if tokio::time::timeout(SERVE_TX_STALL, room).await.is_err() {
            let addr = {
                let mut st = inner.state();
                let addr = st.peers.get(&peer).map(|p| {
                    p.kill.notify_one();
                    p.addr.clone()
                });
                if addr.is_some() {
                    st.slow_disconnects += 1;
                }
                addr
            };
            if let Some(addr) = addr {
                log::debug!("peer {addr} reads no transaction answers; disconnecting");
            }
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RT2 F3: a step holds exactly its size of the peer's share and of its
    /// pool; a peer cannot hold more than its share; outbound and inbound
    /// pools are apart; written and disconnected answers release exactly
    /// what they held.
    #[tokio::test]
    async fn the_serving_budget_is_exact_fair_and_shared() {
        let budget = ServeBudget::default();
        let q = ReplyQueue::default();
        let inbound = budget.pool(false);
        let (mut mine, mut pooled) = acquire(&q, &inbound, units(3_000)).await.unwrap();
        assert_eq!(budget.used(), 3 * UNIT);
        let peer_part = mine.split(3).unwrap();
        let pool_part = pooled.split(3).unwrap();
        q.queue.lock().unwrap().push_back(Queued {
            len: 3_000,
            at: Instant::now(),
            _peer: peer_part,
            _pool: pool_part,
        });
        assert_eq!(q.bytes(), 3_000);
        q.written();
        assert_eq!(budget.used(), 0);
        // A peer's share caps it.
        let held = acquire(&q, &inbound, units(SERVE_TX_PEER)).await.unwrap();
        let more = tokio::time::timeout(Duration::from_millis(50), acquire(&q, &inbound, 1));
        assert!(more.await.is_err(), "over its share: waits");
        drop(held);
        // The outbound slice is apart from the inbound pool.
        let fill: Vec<_> = (0..(SERVE_TX_TOTAL - SERVE_TX_OUTBOUND) / SERVE_TX_PEER)
            .map(|_| ReplyQueue::default())
            .collect();
        let mut holds = Vec::new();
        for f in &fill {
            holds.push(acquire(f, &inbound, units(SERVE_TX_PEER)).await.unwrap());
        }
        let other = ReplyQueue::default();
        let blocked = tokio::time::timeout(Duration::from_millis(50), acquire(&other, &inbound, 1));
        assert!(blocked.await.is_err(), "the inbound pool is full");
        assert!(acquire(&other, &budget.pool(true), 1).await.is_some());
        // A disconnect releases what the queue held.
        drop(holds);
        let (mut mine, mut pooled) = acquire(&q, &inbound, 2).await.unwrap();
        q.queue.lock().unwrap().push_back(Queued {
            len: 2 * UNIT,
            at: Instant::now(),
            _peer: mine.split(2).unwrap(),
            _pool: pooled.split(2).unwrap(),
        });
        q.closed();
        assert_eq!(budget.used(), 0);
    }

    /// The throughput rule: only a peer holding over `SLOW_SHARE`, and
    /// only once its oldest answer waited past `SLOW_BASE` plus its size at
    /// `SLOW_RATE`.
    #[tokio::test]
    async fn a_slow_reader_holding_much_is_found() {
        let q = ReplyQueue::default();
        let pool = Arc::new(Semaphore::new(SERVE_TX_TOTAL / UNIT));
        let t0 = Instant::now();
        for _ in 0..3 {
            let (mut mine, mut pooled) = acquire(&q, &pool, units(2 * 1024 * 1024)).await.unwrap();
            let n = mine.num_permits();
            q.queue.lock().unwrap().push_back(Queued {
                len: 2 * 1024 * 1024,
                at: t0,
                _peer: mine.split(n).unwrap(),
                _pool: pooled.split(n).unwrap(),
            });
        }
        assert!(q.bytes() > SLOW_SHARE);
        assert!(!q.too_slow(t0 + SLOW_BASE, false));
        assert!(q.too_slow(t0 + SLOW_BASE + Duration::from_secs(33), false));
        q.written();
        q.written();
        // The front is timed from when it got there (RT3 F3).
        let later = Instant::now();
        assert!(!q.too_slow(later + SLOW_BASE, true));
        // 2 MiB held: under the share, flagged only while the pool is
        // contended (RT3 F5).
        assert!(!q.too_slow(later + Duration::from_secs(3_600), false));
        assert!(q.too_slow(later + Duration::from_secs(3_600), true));
        let budget = ServeBudget::default();
        assert!(!budget.contended(false));
        let w = budget.wait(false);
        assert!(budget.contended(false) && !budget.contended(true));
        drop(w);
        assert!(!budget.contended(false));
    }
}
