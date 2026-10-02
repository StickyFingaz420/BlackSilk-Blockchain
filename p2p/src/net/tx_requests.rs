//! Transaction requests (docs/p2p.md §7): who announced what, what is asked
//! of whom, and what happens when an answer is lost, refused or late.
//!
//! - **In flight per peer.** At most [`TX_IN_FLIGHT`] requests are
//!   outstanding to one peer, and one while its last answer was large
//!   (over `SMALL_RELAY_BYTES`, a PX transaction): its answers wait in its
//!   slow lane, which holds about two PX transactions, and relay over its
//!   bounds is dropped there. Further ids it announced wait in
//!   `Peer::tx_wanted`, oldest first, and are asked as its requests end
//!   ([`request_wanted`]), as Bitcoin Core limits the transactions in
//!   flight per peer (TM2-17).
//! - **Announcers.** At most [`ANNOUNCERS_CAP`] per id, in arrival order;
//!   an outbound announcer takes the place of an inbound one when the
//!   queue is full. An announcer refused a place is not forgotten: the id
//!   is marked (`State::tx_overflow`), and when its queue runs out, the
//!   peers that announced it (`Peer::known_txs`) and have not failed it are
//!   asked (RT-TM2P2P: eight silent first announcers suppressed an honest
//!   ninth).
//! - **Lost and refused answers.** An answer dropped for this node's own
//!   budgets (the peer's relay share, the node-wide PX share, a full Tx
//!   lane) goes back to the front of the peer's wanted queue, and the peer
//!   is asked again after [`TX_BUSY_BACKOFF`]. A request that times out
//!   moves to the next announcer; with none left, the same peer is asked
//!   once more before the id is forgotten. An answer dropped by the slow
//!   lane is such a timeout. (RT-TM2P2P: a PX burst from one announcer was
//!   lost for good.)

use super::dispatch::SLOW_LANE_RELAY;
use super::state::{Inner, State};
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use std::time::{Duration, Instant};

/// Requests outstanding to one peer whose last answer was small.
pub(super) const TX_IN_FLIGHT: usize = SLOW_LANE_RELAY / 2;

/// Requests outstanding to one peer whose last answer was large.
pub(super) const TX_IN_FLIGHT_LARGE: usize = 1;

/// Most ids waiting in one peer's `tx_wanted` (32 bytes each); an id over
/// it is asked of another announcer, or at a later announcement.
pub(super) const TX_WANTED_CAP: usize = 2_000;

/// Announcers remembered per id.
pub(super) const ANNOUNCERS_CAP: usize = 8;

/// Ids marked in `State::tx_overflow` (an announcer was refused a place).
pub(super) const TX_OVERFLOW_CAP: usize = 10_000;

/// `(id, peer)` pairs asked a second time after a timeout
/// (`State::tx_retried`); cleared when full.
pub(super) const TX_RETRIED_CAP: usize = 10_000;

/// How long a peer whose answer this node dropped for its own budgets is
/// not asked again: about one token of the per-peer PX share (0.2 per
/// second).
pub(super) const TX_BUSY_BACKOFF: Duration = Duration::from_secs(5);

/// Why a request ended without the transaction (`retry_tx`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// `NotFound`: the peer does not have it.
    NotFound,
    /// No answer within `TX_TIMEOUT` (or the answer was dropped by the
    /// peer's slow lane).
    Timeout,
    /// The peer disconnected.
    Gone,
}

/// Transaction requests outstanding to `peer`.
pub(super) fn in_flight(st: &State, peer: PeerId) -> usize {
    st.tx_requests.values().filter(|(p, _)| *p == peer).count()
}

/// How many more requests `peer` may have outstanding now (0 while it is
/// paused after a dropped answer).
pub(super) fn room(st: &State, peer: PeerId, now: Instant) -> usize {
    let Some(p) = st.peers.get(&peer) else {
        return 0;
    };
    if p.tx_paused_until.is_some_and(|t| now < t) {
        return 0;
    }
    let cap = if p.tx_large {
        TX_IN_FLIGHT_LARGE
    } else {
        TX_IN_FLIGHT
    };
    cap.saturating_sub(in_flight(st, peer))
}

/// Records `peer` as an announcer of `id`. Returns whether it is in the
/// queue now. A full queue takes an outbound announcer in the place of an
/// inbound one (not the one asked now); every announcer refused a place,
/// or displaced, marks the id ([`TX_OVERFLOW_CAP`]).
pub(super) fn add_announcer(st: &mut State, id: Hash, peer: PeerId) -> bool {
    let inbound = st.peers.get(&peer).is_none_or(|p| p.inbound);
    let asked = st.tx_requests.get(&id).map(|(p, _)| *p);
    let q = st.tx_announcers.entry(id).or_default();
    if q.contains(&peer) {
        return true;
    }
    if q.len() < ANNOUNCERS_CAP {
        q.push_back(peer);
        return true;
    }
    let mut added = false;
    if !inbound {
        let peers = &st.peers;
        let displaced = q
            .iter()
            .rposition(|x| Some(*x) != asked && peers.get(x).is_none_or(|p| p.inbound));
        if let Some(i) = displaced {
            q.remove(i);
            q.push_back(peer);
            added = true;
        }
    }
    if st.tx_overflow.len() < TX_OVERFLOW_CAP || st.tx_overflow.contains_key(&id) {
        st.tx_overflow.entry(id).or_default();
    }
    added
}

/// Asks `peer` for the ids waiting in its `tx_wanted` while it has
/// [`room`]. An id is asked only if still wanted from it: announced by it
/// (still in its announcer queue, which receipt or a final failure
/// removes) and asked of no one.
pub(super) fn request_wanted(inner: &Inner, st: &mut State, peer: PeerId, now: Instant) {
    let mut room = room(st, peer, now);
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

/// Asks `peer` for `id` now if it has room, else queues it at the front
/// (`front`) or back of its wanted queue. `false`: neither (its queue is
/// full, or it is gone).
fn ask_or_queue(
    inner: &Inner,
    st: &mut State,
    id: Hash,
    peer: PeerId,
    now: Instant,
    front: bool,
) -> bool {
    if room(st, peer, now) > 0 {
        st.tx_requests.insert(id, (peer, now));
        inner.send(st, peer, Message::GetTx(vec![id]));
        return true;
    }
    let Some(p) = st.peers.get_mut(&peer) else {
        return false;
    };
    if p.tx_wanted.len() >= TX_WANTED_CAP {
        return false;
    }
    if front {
        p.tx_wanted.push_front(id);
    } else {
        p.tx_wanted.push_back(id);
    }
    true
}

/// The request for `id` ended at `failed` without the transaction: asks
/// the next announcer (or queues it there); with none left, an id whose
/// announcers overflowed is asked of the other peers that announced it,
/// and after a timeout the same peer is asked once more; only then is the
/// id forgotten. `failed` may then be asked for what waits for it.
pub(super) fn retry_tx(
    inner: &Inner,
    st: &mut State,
    id: Hash,
    failed: PeerId,
    why: Failure,
    now: Instant,
) {
    st.tx_requests.remove(&id);
    if let Some(q) = st.tx_announcers.get_mut(&id) {
        q.retain(|x| *x != failed);
    }
    if let Some(f) = st.tx_overflow.get_mut(&id) {
        if !f.contains(&failed) {
            f.push(failed);
        }
    }
    if st.tx_announcers.get(&id).is_none_or(|q| q.is_empty()) {
        refill_announcers(st, id, failed);
    }
    loop {
        let next = st.tx_announcers.get(&id).and_then(|q| q.front().copied());
        let Some(n) = next else { break };
        if ask_or_queue(inner, st, id, n, now, false) {
            request_wanted(inner, st, failed, now);
            return;
        }
        if let Some(q) = st.tx_announcers.get_mut(&id) {
            q.pop_front();
        }
    }
    let retried = why == Failure::Timeout
        && st.peers.contains_key(&failed)
        && st.tx_retried.insert((id, failed));
    if retried {
        if st.tx_retried.len() > TX_RETRIED_CAP {
            st.tx_retried.clear();
            st.tx_retried.insert((id, failed));
        }
        st.tx_announcers.entry(id).or_default().push_back(failed);
        if ask_or_queue(inner, st, id, failed, now, true) {
            return;
        }
    }
    forget(st, &id);
    request_wanted(inner, st, failed, now);
}

/// For an id whose announcers overflowed: the peers that announced it
/// (`known_txs`), relay transactions, and have not failed it, outbound
/// first, up to [`ANNOUNCERS_CAP`].
fn refill_announcers(st: &mut State, id: Hash, failed: PeerId) {
    let Some(tried) = st.tx_overflow.get(&id) else {
        return;
    };
    let mut cands: Vec<(bool, PeerId)> = st
        .peers
        .iter()
        .filter(|(pid, p)| {
            **pid != failed && !tried.contains(pid) && p.relay_txs && p.known_txs.contains(&id)
        })
        .map(|(pid, p)| (p.inbound, *pid))
        .collect();
    cands.sort();
    cands.truncate(ANNOUNCERS_CAP);
    if !cands.is_empty() {
        st.tx_announcers
            .entry(id)
            .or_default()
            .extend(cands.into_iter().map(|(_, p)| p));
    }
}

/// Forgets every request state of `id` (received, or no one left to ask).
pub(super) fn forget(st: &mut State, id: &Hash) {
    st.tx_requests.remove(id);
    st.tx_announcers.remove(id);
    st.tx_overflow.remove(id);
}

/// `peer` answered our request for `id`, but this node dropped the answer
/// for its own budgets: the id goes back to the front of the peer's wanted
/// queue, and the peer is not asked again for [`TX_BUSY_BACKOFF`] (the
/// maintenance loop asks it then). It stays an announcer.
pub(super) fn answer_dropped(st: &mut State, id: Hash, peer: PeerId, now: Instant) {
    if st.tx_requests.get(&id).is_some_and(|(p, _)| *p == peer) {
        st.tx_requests.remove(&id);
    }
    let in_queue = st.tx_announcers.get(&id).is_some_and(|q| q.contains(&peer));
    if !in_queue {
        st.tx_announcers.entry(id).or_default().push_front(peer);
    }
    if let Some(p) = st.peers.get_mut(&peer) {
        p.tx_paused_until = Some(now + TX_BUSY_BACKOFF);
        if p.tx_wanted.len() < TX_WANTED_CAP {
            p.tx_wanted.push_front(id);
        }
    }
}

/// The maintenance loop's share: peers with ids waiting and room again
/// (a pause ended) are asked.
pub(super) fn resume_requests(inner: &Inner, st: &mut State, now: Instant) {
    let ready: Vec<PeerId> = st
        .peers
        .iter()
        .filter(|(_, p)| !p.tx_wanted.is_empty() && p.tx_paused_until.is_none_or(|t| now >= t))
        .map(|(id, _)| *id)
        .collect();
    for peer in ready {
        if let Some(p) = st.peers.get_mut(&peer) {
            p.tx_paused_until = None;
        }
        request_wanted(inner, st, peer, now);
    }
}
