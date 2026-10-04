//! Transaction relay: inventory announcements and pool re-announcement.
//! Requests are in `tx_requests`, serving `GetTx` in `serve_tx`.

use super::admission::ctx_rejected;
use super::state::{Inner, State};
use super::tx_requests::Actions;
use crate::dandelion::{exponential, PeerId};
use crate::limits::score;
use blacksilk_chain::mempool::MEMPOOL_EXPIRY_BLOCKS;
use blacksilk_consensus::Hash;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

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
    /// Queues announcements of `ids` to `peer` only, through its trickle,
    /// skipping what it knows or was told (a reconnecting peer, RT3 F3).
    pub(super) fn announce_to(&self, peer: PeerId, ids: Vec<Hash>) {
        let mut st = self.state();
        self.queue_inv(&mut st, peer, ids);
    }

    /// Queues an `InvTx` announcement to every transaction-relaying peer except
    /// `except` and peers that already know it (docs/p2p.md §7).
    pub(super) fn announce_tx(&self, id: Hash, except: Option<PeerId>) {
        let mut st = self.state();
        let ids: Vec<PeerId> = st.peers.keys().copied().collect();
        for pid in ids {
            if Some(pid) != except {
                self.queue_inv(&mut st, pid, vec![id]);
            }
        }
    }

    /// Queues `ids` for `peer` if it relays transactions, skipping what it
    /// knows or was told. An outbound peer's queue is released by its own
    /// timer, started (Exp(`trickle_outbound`)) when the queue was empty; an
    /// inbound peer's by its network identity's shared timer, which ticks
    /// whatever is queued (`trickle::trickle_loop`, woken here).
    fn queue_inv(&self, st: &mut State, peer: PeerId, ids: Vec<Hash>) {
        let State {
            peers,
            rng,
            inbound_trickle,
            ..
        } = st;
        let Some(p) = peers.get_mut(&peer).filter(|p| p.relay_txs) else {
            return;
        };
        let was_empty = p.inv_queue.is_empty();
        for id in ids {
            if p.known_txs.contains(&id) || p.announced_to.contains(&id) {
                continue;
            }
            if p.inv_queue.is_empty() && p.trickle.is_none() {
                p.next_inv = Instant::now() + exponential(self.cfg.trickle_outbound, rng);
            }
            p.inv_queue.push(id);
        }
        if was_empty && !p.inv_queue.is_empty() {
            inbound_trickle.wake();
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
    let preferred = !p.inbound;
    let mut out = Actions::default();
    for (id, in_mempool) in ids.into_iter().zip(known) {
        if in_mempool || st.recent_rejects_set.contains(&id) || ctx_rejected(&st, &id, &tip) {
            continue;
        }
        // A transaction in our stempool is treated like an unknown one:
        // requested, never fluffed because of an announcement. Answering
        // differently would tell a spy what is in our stempool, and let it
        // end the stem at will (I3-1). If it is really in fluff, the
        // transaction arrives and is pooled, which ends the embargo
        // (`on_tx`). Who is asked, and when: the tracker (`tx_requests`).
        st.tx_tracker.announce(id, peer, preferred, now, &mut out);
    }
    inner.apply_tx_actions(&mut st, out, now);
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
