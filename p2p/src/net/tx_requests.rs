//! The transaction request tracker (docs/p2p.md §7, "Requesting"; RT2-TM2P2P
//! redesign). Prior art: Bitcoin Core's `TxRequestTracker` (txrequest.cpp).
//!
//! One record per (transaction id, announcing peer) and one per id. Every
//! tracked id has a timer (the earliest of its deadline, its requests'
//! expiries, its candidates' ready times and its pause), so no id waits
//! without a request and a timer. The tracker is plain data: it decides,
//! and returns what to send ([`Actions`]); the caller sends it.

use super::dispatch::SLOW_LANE_BYTES;
use super::state::{Inner, State, LATE_TXS_MAX};
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::hash::BuildHasher;
use std::time::{Duration, Instant};

/// A request not answered in this time has timed out.
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// An inbound (non-preferred) announcer is asked no sooner than this after
/// its announcement (Core's `NONPREF_PEER_TX_DELAY`).
pub(super) const INBOUND_DELAY: Duration = Duration::from_secs(2);
/// Requests outstanding for one id once one of its requests timed out.
pub(super) const PARALLEL: usize = 4;
/// An id is dropped, with all its records, this long after its first
/// announcement.
pub(super) const DEADLINE: Duration = Duration::from_secs(20 * 60);
/// Ids one peer may have tracked (its announcements beyond are ignored).
pub(super) const PEER_TRACKED: usize = 2_000;
/// Requests in flight to one peer.
pub(super) const PEER_IN_FLIGHT: usize = 16;
/// Expected answer bytes in flight to one peer: what its slow lane holds.
pub(super) const PEER_IN_FLIGHT_BYTES: usize = SLOW_LANE_BYTES;
/// The least an answer is expected to weigh.
pub(super) const MIN_ANSWER: usize = 8 * 1024;
/// An answer dropped for the peer's own budgets: that announcer is asked
/// again no sooner than this (others are asked at once)...
pub(super) const BUSY_BACKOFF: Duration = Duration::from_secs(5);
/// ...and at most this many times per (id, peer).
pub(super) const BUSY_MAX: u8 = 2;
/// An answer dropped for the node-wide PX share pauses its id this long.
pub(super) const GLOBAL_PAUSE: Duration = Duration::from_secs(1);
/// A ready candidate whose peer has no room is looked at again after this.
pub(super) const BLOCKED_RETRY: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnnState {
    /// May be asked from `ready` on.
    Candidate { ready: Instant },
    /// Asked; times out at `expiry`.
    Requested { expiry: Instant },
    /// Answered without the transaction, timed out, or refused.
    Done,
}

#[derive(Clone, Debug)]
struct Ann {
    peer: PeerId,
    preferred: bool,
    state: AnnState,
    busy: u8,
    /// It timed out once and was put back as a last resort.
    retried: bool,
    /// Per-node random priority of (id, peer): lower first.
    prio: u64,
}

#[derive(Clone, Debug)]
struct TxEntry {
    deadline: Instant,
    timeouts: u32,
    paused_until: Option<Instant>,
    anns: Vec<Ann>,
    /// Its key in `timers`.
    timer: Instant,
}

#[derive(Clone, Debug, Default)]
struct PeerLoad {
    tracked: HashSet<Hash>,
    in_flight: usize,
    /// The size of its last answer (0: none yet).
    answer_size: usize,
}

impl PeerLoad {
    /// What each request to this peer is expected to weigh: its last
    /// answer's size; before its first answer, half its in-flight bytes
    /// (two requests, so a burst of large answers fits its slow lane).
    fn expected(&self) -> usize {
        if self.answer_size == 0 {
            PEER_IN_FLIGHT_BYTES / 2
        } else {
            self.answer_size.max(MIN_ANSWER)
        }
    }

    fn has_room(&self) -> bool {
        self.in_flight < PEER_IN_FLIGHT
            && (self.in_flight + 1) * self.expected() <= PEER_IN_FLIGHT_BYTES.max(self.expected())
    }
}

/// What the caller sends and records after a tracker call.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Actions {
    /// `GetTx` per peer.
    pub(super) requests: Vec<(PeerId, Vec<Hash>)>,
    /// Requests that timed out now: their late answers stay acceptable
    /// (`State::late_txs`).
    pub(super) expired: Vec<(Hash, PeerId)>,
}

impl Actions {
    fn ask(&mut self, peer: PeerId, id: Hash) {
        match self.requests.iter_mut().find(|(p, _)| *p == peer) {
            Some((_, ids)) => ids.push(id),
            None => self.requests.push((peer, vec![id])),
        }
    }
}

impl Inner {
    /// Sends a tracker call's `GetTx`s and remembers its timed-out requests
    /// (their late answers stay acceptable for `TX_TIMEOUT`, P2P-FIX2).
    pub(super) fn apply_tx_actions(&self, st: &mut State, out: Actions, now: Instant) {
        for (id, peer) in out.expired {
            if st.late_txs.len() < LATE_TXS_MAX {
                st.late_txs.insert((id, peer), now);
            }
        }
        for (peer, ids) in out.requests {
            self.send(st, peer, Message::GetTx(ids));
        }
    }
}

/// The tracker.
pub(super) struct TxTracker {
    txs: HashMap<Hash, TxEntry>,
    peers: HashMap<PeerId, PeerLoad>,
    timers: BTreeSet<(Instant, Hash)>,
    salt: RandomState,
}

impl Default for TxTracker {
    fn default() -> Self {
        Self {
            txs: HashMap::new(),
            peers: HashMap::new(),
            timers: BTreeSet::new(),
            salt: RandomState::new(),
        }
    }
}

impl TxTracker {
    /// Ids tracked.
    pub(super) fn len(&self) -> usize {
        self.txs.len()
    }

    /// Requests outstanding, over all ids.
    pub(super) fn requests(&self) -> usize {
        self.peers.values().map(|p| p.in_flight).sum()
    }

    /// Whether `peer` has an outstanding request for `id`.
    pub(super) fn is_requested(&self, id: &Hash, peer: PeerId) -> bool {
        self.txs.get(id).is_some_and(|e| {
            e.anns
                .iter()
                .any(|a| a.peer == peer && matches!(a.state, AnnState::Requested { .. }))
        })
    }

    /// `peer` announced `id`. Ignored if it announced it already, or has
    /// [`PEER_TRACKED`] ids tracked. Asks at once whoever is ready.
    pub(super) fn announce(
        &mut self,
        id: Hash,
        peer: PeerId,
        preferred: bool,
        now: Instant,
        out: &mut Actions,
    ) {
        // Timers due before this event run first: what happens is decided
        // in time order, never by when the maintenance tick comes.
        self.poll(now, out);
        let load = self.peers.entry(peer).or_default();
        if load.tracked.contains(&id) || load.tracked.len() >= PEER_TRACKED {
            return;
        }
        load.tracked.insert(id);
        let prio = self.salt.hash_one((id, peer));
        let ready = if preferred { now } else { now + INBOUND_DELAY };
        let e = self.txs.entry(id).or_insert_with(|| TxEntry {
            deadline: now + DEADLINE,
            timeouts: 0,
            paused_until: None,
            anns: Vec::new(),
            timer: now,
        });
        e.anns.push(Ann {
            peer,
            preferred,
            state: AnnState::Candidate { ready },
            busy: 0,
            retried: false,
            prio,
        });
        self.eval(id, now, out);
    }

    /// The size of `peer`'s latest answer (or of an answer its slow lane
    /// dropped): what each request to it is expected to weigh.
    pub(super) fn answer_size(&mut self, peer: PeerId, bytes: usize) {
        if let Some(l) = self.peers.get_mut(&peer) {
            l.answer_size = bytes;
        }
    }

    /// `id` arrived, or is known otherwise: forgotten, with all its records.
    pub(super) fn forget(&mut self, id: &Hash) {
        self.remove(id);
    }

    /// `peer` answered `NotFound` for `id`.
    pub(super) fn not_found(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        if self.end_request(&id, peer, |a| a.state = AnnState::Done) {
            self.eval(id, now, out);
        }
    }

    /// `peer`'s answer for `id` was dropped for its own budgets (its relay
    /// share, a full transaction lane): the next candidate is asked now,
    /// this one again after [`BUSY_BACKOFF`], at most [`BUSY_MAX`] times.
    pub(super) fn busy(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let ended = self.end_request(&id, peer, |a| {
            a.busy += 1;
            a.state = if a.busy > BUSY_MAX {
                AnnState::Done
            } else {
                AnnState::Candidate {
                    ready: now + BUSY_BACKOFF,
                }
            };
        });
        if ended {
            self.eval(id, now, out);
        }
    }

    /// `peer`'s answer for `id` was dropped for the node-wide PX share: the
    /// id (not the peer) pauses for [`GLOBAL_PAUSE`], and the same record
    /// is asked again after it.
    pub(super) fn pause(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        if self.end_request(&id, peer, |a| a.state = AnnState::Candidate { ready: now }) {
            if let Some(e) = self.txs.get_mut(&id) {
                e.paused_until = Some(now + GLOBAL_PAUSE);
            }
            self.eval(id, now, out);
        }
    }

    /// `peer` disconnected: its records go, and the ids it held are
    /// looked at again now.
    pub(super) fn peer_gone(&mut self, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let Some(load) = self.peers.remove(&peer) else {
            return;
        };
        for id in load.tracked {
            if let Some(e) = self.txs.get_mut(&id) {
                e.anns.retain(|a| a.peer != peer);
                self.eval(id, now, out);
            }
        }
    }

    /// The timers due by `now`: requests time out, paused or delayed
    /// candidates are asked, deadlines drop ids. In time order, each at its
    /// own time: an id whose timer came first is looked at as of that time,
    /// so a candidate that became ready later cannot jump ahead of what
    /// happened in between (another id filling that candidate's peer, say).
    pub(super) fn poll(&mut self, now: Instant, out: &mut Actions) {
        while let Some(&(t, id)) = self.timers.first() {
            if t > now {
                break;
            }
            self.timers.remove(&(t, id));
            self.eval(id, t, out);
        }
    }

    /// Ends `peer`'s request for `id` with `f` (on its record). `false` if
    /// there was none.
    fn end_request(&mut self, id: &Hash, peer: PeerId, f: impl FnOnce(&mut Ann)) -> bool {
        let Some(e) = self.txs.get_mut(id) else {
            return false;
        };
        let Some(a) = e
            .anns
            .iter_mut()
            .find(|a| a.peer == peer && matches!(a.state, AnnState::Requested { .. }))
        else {
            return false;
        };
        f(a);
        if let Some(l) = self.peers.get_mut(&peer) {
            l.in_flight = l.in_flight.saturating_sub(1);
        }
        true
    }

    /// Removes `id` with all its records.
    fn remove(&mut self, id: &Hash) {
        let Some(e) = self.txs.remove(id) else {
            return;
        };
        self.timers.remove(&(e.timer, *id));
        for a in e.anns {
            if let Some(l) = self.peers.get_mut(&a.peer) {
                l.tracked.remove(id);
                if matches!(a.state, AnnState::Requested { .. }) {
                    l.in_flight = l.in_flight.saturating_sub(1);
                }
            }
        }
    }

    /// Looks at `id` now: drops it at its deadline or when no record is
    /// left to ask, times out requests, asks ready candidates up to its
    /// concurrency, and sets its timer.
    fn eval(&mut self, id: Hash, now: Instant, out: &mut Actions) {
        let Some(e) = self.txs.get_mut(&id) else {
            return;
        };
        self.timers.remove(&(e.timer, id));
        if now >= e.deadline {
            self.remove(&id);
            return;
        }
        for a in e.anns.iter_mut() {
            if let AnnState::Requested { expiry } = a.state {
                if expiry <= now {
                    // Asked once more as a last resort (after every fresh
                    // candidate): its answer may have been dropped by our
                    // own slow lane. Never a third time.
                    a.state = if a.retried {
                        AnnState::Done
                    } else {
                        AnnState::Candidate { ready: now }
                    };
                    a.retried = true;
                    e.timeouts += 1;
                    out.expired.push((id, a.peer));
                    if let Some(l) = self.peers.get_mut(&a.peer) {
                        l.in_flight = l.in_flight.saturating_sub(1);
                    }
                }
            }
        }
        if e.paused_until.is_some_and(|t| t <= now) {
            e.paused_until = None;
        }
        let mut blocked = false;
        if e.paused_until.is_none() {
            let allowed = if e.timeouts == 0 { 1 } else { PARALLEL };
            let mut outstanding = e
                .anns
                .iter()
                .filter(|a| matches!(a.state, AnnState::Requested { .. }))
                .count();
            while outstanding < allowed {
                let peers = &self.peers;
                let mut best: Option<usize> = None;
                for (i, a) in e.anns.iter().enumerate() {
                    let AnnState::Candidate { ready } = a.state else {
                        continue;
                    };
                    if ready > now {
                        continue;
                    }
                    if !peers.get(&a.peer).is_some_and(PeerLoad::has_room) {
                        blocked = true;
                        continue;
                    }
                    let key = |a: &Ann| (a.busy + u8::from(a.retried), !a.preferred, a.prio);
                    if best.is_none_or(|b| key(a) < key(&e.anns[b])) {
                        best = Some(i);
                    }
                }
                let Some(i) = best else { break };
                let a = &mut e.anns[i];
                a.state = AnnState::Requested {
                    expiry: now + REQUEST_TIMEOUT,
                };
                if let Some(l) = self.peers.get_mut(&a.peer) {
                    l.in_flight += 1;
                }
                out.ask(a.peer, id);
                outstanding += 1;
            }
        }
        let live = e.anns.iter().any(|a| !matches!(a.state, AnnState::Done));
        if !live {
            self.remove(&id);
            return;
        }
        let mut timer = e.deadline;
        for a in &e.anns {
            match a.state {
                AnnState::Requested { expiry } => timer = timer.min(expiry),
                AnnState::Candidate { ready } if ready > now => timer = timer.min(ready),
                _ => {}
            }
        }
        if let Some(t) = e.paused_until {
            timer = timer.min(t);
        }
        if blocked {
            timer = timer.min(now + BLOCKED_RETRY);
        }
        e.timer = timer;
        self.timers.insert((timer, id));
    }

    /// Checks the invariants (tests): every id has a timer at or before its
    /// deadline and a live record; no cap is exceeded; at most one request
    /// per id before its first timeout, [`PARALLEL`] after.
    #[cfg(test)]
    fn check(&self) {
        for (id, e) in &self.txs {
            assert!(
                self.timers.contains(&(e.timer, *id)),
                "an id without a timer"
            );
            assert!(e.timer <= e.deadline);
            assert!(e.anns.iter().any(|a| a.state != AnnState::Done));
            let req = e
                .anns
                .iter()
                .filter(|a| matches!(a.state, AnnState::Requested { .. }))
                .count();
            assert!(req <= if e.timeouts == 0 { 1 } else { PARALLEL });
        }
        assert_eq!(self.timers.len(), self.txs.len());
        for (peer, l) in &self.peers {
            assert!(l.tracked.len() <= PEER_TRACKED);
            assert!(l.in_flight <= PEER_IN_FLIGHT);
            let real = self
                .txs
                .values()
                .flat_map(|e| e.anns.iter())
                .filter(|a| a.peer == *peer && matches!(a.state, AnnState::Requested { .. }))
                .count();
            assert_eq!(real, l.in_flight);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn id(n: u64) -> Hash {
        let mut h = [0u8; 32];
        h[..8].copy_from_slice(&n.to_le_bytes());
        h
    }

    fn asked(out: &Actions, peer: PeerId, id: Hash) -> bool {
        out.requests
            .iter()
            .any(|(p, ids)| *p == peer && ids.contains(&id))
    }

    /// Preferred announcers are asked at once, inbound ones after 2 s; one
    /// request until the first timeout, then up to 4 in parallel.
    #[test]
    fn preferred_first_inbound_delayed_then_parallel_fallback() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(1), 10, false, t0, &mut out);
        assert!(out.requests.is_empty(), "inbound: delayed");
        t.announce(id(1), 11, true, t0, &mut out);
        assert!(asked(&out, 11, id(1)), "preferred: at once");
        for p in 12..20 {
            t.announce(id(1), p, false, t0, &mut out);
        }
        let mut out = Actions::default();
        t.poll(t0 + INBOUND_DELAY, &mut out);
        assert!(out.requests.is_empty(), "one at a time");
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT, &mut out);
        assert_eq!(out.expired, vec![(id(1), 11)]);
        let n: usize = out.requests.iter().map(|(_, v)| v.len()).sum();
        assert_eq!(n, PARALLEL, "4 at once after the first timeout");
        t.check();
    }

    /// RT2 F1: junk from one peer uses only its own room; an honest
    /// candidate is asked as soon as the request before it ends.
    #[test]
    fn junk_from_one_peer_does_not_hold_another_peers_candidate() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for n in 0..500 {
            t.announce(id(1000 + n), 2, true, t0, &mut out);
        }
        assert!(!t.peers[&2].has_room(), "its own junk fills its room");
        t.announce(id(1), 1, true, t0, &mut out);
        assert!(asked(&out, 1, id(1)));
        t.announce(id(1), 2, true, t0, &mut out);
        t.announce(id(1), 3, false, t0, &mut out);
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT, &mut out);
        assert!(
            asked(&out, 3, id(1)),
            "the honest one, not parked behind 2's junk"
        );
        t.check();
    }

    /// RT2 F2: an answer dropped as Busy asks the next candidate now, and
    /// the busy one at most `BUSY_MAX` more times.
    #[test]
    fn busy_rotates_and_is_capped() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(1), 1, true, t0, &mut out);
        t.announce(id(1), 2, true, t0, &mut out);
        let first = out.requests[0].0;
        let other = if first == 1 { 2 } else { 1 };
        let mut out = Actions::default();
        t.busy(id(1), first, t0, &mut out);
        assert!(asked(&out, other, id(1)), "rotated at once");
        let mut out = Actions::default();
        t.not_found(id(1), other, t0, &mut out);
        assert!(out.requests.is_empty(), "the busy one waits its backoff");
        let mut now = t0;
        for _ in 0..BUSY_MAX {
            now += BUSY_BACKOFF;
            let mut out = Actions::default();
            t.poll(now, &mut out);
            assert!(asked(&out, first, id(1)));
            t.busy(id(1), first, now, &mut out);
        }
        assert_eq!(t.len(), 0, "dropped after the busy cap");
        t.check();
    }

    /// A request that timed out is asked once more of the same peer, as a
    /// last resort after every fresh candidate; never a third time. Before
    /// a peer's first answer, two requests are in flight to it.
    #[test]
    fn a_timed_out_request_is_retried_once_as_a_last_resort() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for n in 1..=3 {
            t.announce(id(n), 1, true, t0, &mut out);
        }
        assert_eq!(t.requests(), 2, "two before its first answer");
        t.answer_size(1, 1_000);
        let mut out = Actions::default();
        t.poll(t0 + BLOCKED_RETRY, &mut out);
        assert!(asked(&out, 1, id(3)), "room once its answers are small");
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT, &mut out);
        assert_eq!(out.expired.len(), 2);
        assert!(
            asked(&out, 1, id(1)) && asked(&out, 1, id(2)),
            "asked once more"
        );
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT * 3, &mut out);
        assert_eq!(t.len(), 0, "never a third time");
        t.check();
    }

    /// The node-wide share pauses the id, not the peer.
    #[test]
    fn a_global_pause_delays_the_id_only() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(1), 1, true, t0, &mut out);
        t.announce(id(2), 1, true, t0, &mut out);
        let mut out = Actions::default();
        t.pause(id(1), 1, t0, &mut out);
        assert!(out.requests.is_empty());
        let mut out = Actions::default();
        t.poll(t0 + GLOBAL_PAUSE, &mut out);
        assert!(asked(&out, 1, id(1)), "asked again after the pause");
        t.check();
    }

    /// The deadline drops an id and its records; a disconnect drops a
    /// peer's records; a peer's tracked ids are capped.
    #[test]
    fn deadlines_disconnects_and_caps() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for n in 0..(PEER_TRACKED as u64 + 10) {
            t.announce(id(n), 1, false, t0, &mut out);
        }
        assert_eq!(t.peers[&1].tracked.len(), PEER_TRACKED);
        t.check();
        let mut out = Actions::default();
        t.poll(t0 + DEADLINE, &mut out);
        assert_eq!(t.len(), 0);
        assert_eq!(t.requests(), 0);
        let mut out = Actions::default();
        t.announce(id(5), 1, true, t0 + DEADLINE, &mut out);
        t.peer_gone(1, t0 + DEADLINE, &mut out);
        assert_eq!(t.len(), 0);
        t.check();
    }

    /// Property test: random sequences of announcements, answers,
    /// `NotFound`s, Busy and global drops, timeouts and disconnects keep
    /// the invariants (`check`), and an honest announcer among `k` silent
    /// ones is asked within the bound of docs/p2p.md §7.
    #[test]
    fn random_sequences_keep_the_invariants_and_the_bound() {
        for seed in 0..60u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let t0 = Instant::now();
            let mut now = t0;
            let mut t = TxTracker::default();
            let honest: PeerId = 1000;
            let k = 1 + (rng.next_u64() % 40) as usize;
            let target = id(7);
            let mut honest_announced: Option<Instant> = None;
            let mut honest_asked: Option<Instant> = None;
            let mut outstanding: Vec<(Hash, PeerId)> = Vec::new();
            let note = |out: &Actions,
                        outstanding: &mut Vec<(Hash, PeerId)>,
                        at: Instant,
                        asked_at: &mut Option<Instant>| {
                for (p, ids) in &out.requests {
                    for i in ids {
                        outstanding.push((*i, *p));
                        if *p == honest && *i == target && asked_at.is_none() {
                            *asked_at = Some(at);
                        }
                    }
                }
                outstanding.retain(|x| !out.expired.contains(x));
            };
            // The silent attackers announce the target first, then junk.
            for a in 0..k as PeerId {
                let mut out = Actions::default();
                t.announce(target, a, rng.next_u64() % 4 == 0, now, &mut out);
                note(&out, &mut outstanding, now, &mut honest_asked);
            }
            for step in 0..3_000u32 {
                now += Duration::from_millis(rng.next_u64() % 400);
                let mut out = Actions::default();
                match rng.next_u64() % 10 {
                    0..=2 => {
                        let p = (rng.next_u64() % (k as u64 + 3)) as PeerId;
                        let n = 100 + rng.next_u64() % 300;
                        t.announce(id(n), p, rng.next_u64() % 2 == 0, now, &mut out);
                    }
                    3 if !outstanding.is_empty() => {
                        // An answer for a junk id (never for the target
                        // from an attacker): forgotten as received.
                        let i = (rng.next_u64() as usize) % outstanding.len();
                        let (tx, p) = outstanding[i];
                        if tx != target {
                            outstanding.remove(i);
                            if t.is_requested(&tx, p) {
                                t.forget(&tx);
                                outstanding.retain(|x| x.0 != tx);
                            }
                        }
                    }
                    4 if !outstanding.is_empty() => {
                        let i = (rng.next_u64() as usize) % outstanding.len();
                        let (tx, p) = outstanding.remove(i);
                        if tx != target {
                            match rng.next_u64() % 3 {
                                0 => t.not_found(tx, p, now, &mut out),
                                1 => t.busy(tx, p, now, &mut out),
                                _ => t.pause(tx, p, now, &mut out),
                            }
                        }
                    }
                    5 if step % 50 == 0 => {
                        // A junk peer leaves (never the target's announcers).
                        let p = k as PeerId + (rng.next_u64() % 3) as PeerId;
                        t.peer_gone(p, now, &mut out);
                        outstanding.retain(|x| x.1 != p);
                    }
                    6 if honest_announced.is_none() && step > 20 => {
                        honest_announced = Some(now);
                        t.announce(target, honest, false, now, &mut out);
                    }
                    _ => {}
                }
                note(&out, &mut outstanding, now, &mut honest_asked);
                let mut out = Actions::default();
                t.poll(now, &mut out);
                note(&out, &mut outstanding, now, &mut honest_asked);
                t.check();
                if honest_asked.is_some() {
                    break;
                }
            }
            if let Some(at) = honest_announced {
                // Finish the clock until it is asked.
                while honest_asked.is_none() && now < at + DEADLINE {
                    now += Duration::from_millis(250);
                    let mut out = Actions::default();
                    t.poll(now, &mut out);
                    note(&out, &mut outstanding, now, &mut honest_asked);
                    t.check();
                }
                let bound = INBOUND_DELAY
                    + REQUEST_TIMEOUT * (1 + k.div_ceil(PARALLEL) as u32)
                    + Duration::from_millis(500);
                let waited = honest_asked.expect("the honest announcer is asked") - at;
                assert!(
                    waited <= bound,
                    "seed {seed}, k {k}: {waited:?} > {bound:?}"
                );
            }
        }
    }
}
