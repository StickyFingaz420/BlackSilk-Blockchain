//! Transaction relay: inventory announcements, requests and retries.

use super::admission::ctx_rejected;
use super::state::{Inner, State};
use crate::dandelion::{exponential, PeerId};
use crate::limits::score;
use crate::message::Message;
use blacksilk_consensus::Hash;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(super) const TX_TIMEOUT: Duration = Duration::from_secs(30);

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
            let q = st.tx_announcers.entry(id).or_default();
            if !q.contains(&peer) && q.len() < 8 {
                q.push_back(peer);
            }
            if let std::collections::hash_map::Entry::Vacant(e) = st.tx_requests.entry(id) {
                e.insert((peer, now));
                request.push(id);
            }
        }
        if !request.is_empty() {
            inner.send(&mut st, peer, Message::GetTx(request));
        }
    }
}

pub(super) async fn on_get_tx(inner: &Arc<Inner>, peer: PeerId, ids: Vec<Hash>) {
    // Serve only what we announced to this peer and still have. Everything else
    // gets the same `NotFound` answer, so the reply reveals nothing about the
    // stempool or mempool, and an honest requester can move on immediately.
    let announced: Vec<(Hash, bool)> = {
        let st = inner.state();
        let Some(p) = st.peers.get(&peer) else { return };
        ids.into_iter()
            .map(|id| (id, p.announced_to.contains(&id)))
            .collect()
    };
    let (txs, missing) = inner
        .with_chain(move |c| {
            let mut txs = Vec::new();
            let mut missing = Vec::new();
            for (id, ok) in announced {
                match c.mempool().get(&id).filter(|_| ok) {
                    Some(t) => txs.push(t.encode()),
                    None => missing.push(id),
                }
            }
            (txs, missing)
        })
        .await;

    let mut st = inner.state();
    for t in txs {
        inner.send(&mut st, peer, Message::Tx(t));
    }
    if !missing.is_empty() {
        inner.send(&mut st, peer, Message::NotFound(missing));
    }
}

/// Drops a transaction request that `failed` could not answer and asks the next
/// announcer, if any.
pub(super) fn retry_tx(inner: &Inner, st: &mut State, id: Hash, failed: PeerId, now: Instant) {
    st.tx_requests.remove(&id);
    let next = st.tx_announcers.get_mut(&id).and_then(|q| {
        q.retain(|x| *x != failed);
        q.front().copied()
    });
    match next {
        Some(n) => {
            st.tx_requests.insert(id, (n, now));
            inner.send(st, n, Message::GetTx(vec![id]));
        }
        None => {
            st.tx_announcers.remove(&id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
