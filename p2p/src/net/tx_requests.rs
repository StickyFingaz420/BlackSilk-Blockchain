//! The transaction request tracker (docs/p2p.md §7, "Requesting"; RT2-TM2P2P
//! redesign, RT3-TM2P2P fixes). Prior art: Bitcoin Core's
//! `TxRequestTracker` (txrequest.cpp).
//!
//! One record per (transaction id, announcing peer) and one per id. Every
//! tracked id has a timer (the earliest of its deadline, its requests'
//! expiries, its candidates' ready times, its pause and the end of its
//! first request period), so no id waits without a request and a timer. A
//! candidate whose peer has no room also waits on that peer: it is looked
//! at again as soon as the peer has room. The tracker is plain data: it
//! decides, and returns what to send ([`Actions`]); the caller sends it.
//!
//! Each network class (clearnet; through Tor) has its own records and
//! per-id state (RT3 F6, RT4): the timing of requests on one interface no
//! longer depends on the other's. The mempool is shared, so whether the
//! node already holds a transaction still links the two (docs/p2p.md §7).

use super::dispatch::SLOW_LANE_BYTES;
use super::state::{Inner, State};
use crate::dandelion::PeerId;
use crate::message::Message;
use blacksilk_consensus::Hash;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::hash::BuildHasher;
use std::time::{Duration, Instant};

/// A request for a small answer not answered in this time has timed out
/// (a peer whose answers are large gets [`REQUEST_RATE`] more, below).
pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// The slowest answer rate a request's timeout allows for (the serving
/// side's `SLOW_RATE`): a peer whose last answers were `n` bytes gets
/// `n / REQUEST_RATE` seconds more.
pub(super) const REQUEST_RATE: usize = 64 * 1024;
/// An inbound (non-preferred) announcer is asked no sooner than this after
/// its announcement (Core's `NONPREF_PEER_TX_DELAY`).
pub(super) const INBOUND_DELAY: Duration = Duration::from_secs(2);
/// Requests outstanding for one id from [`REQUEST_TIMEOUT`] after its
/// first request on (however the earlier requests ended).
pub(super) const PARALLEL: usize = 4;
/// Requests outstanding for one id at once, young or old, that leave a
/// non-preferred (inbound) announcer room to be asked: its [`PARALLEL`]
/// slots plus as many older requests still waiting out a size-aware
/// timeout (RT5 F2: counting only young requests allowed up to 12 copies
/// of one slow large transaction in flight, 4 before RT4).
pub(super) const OUTSTANDING_MAX: usize = 2 * PARALLEL;
/// Places beyond [`OUTSTANDING_MAX`] only a preferred (outbound) announcer
/// may take: inbound attackers that fill the 8 places cannot make an
/// outbound announcer wait for one of them to expire (RT-ART5: 68 s, not
/// 32 s). At most `OUTSTANDING_MAX + PREFERRED_RESERVE` (9) copies of one
/// id are requested at once.
pub(super) const PREFERRED_RESERVE: usize = 1;
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
/// again no sooner than this (others are asked at once), doubling...
pub(super) const BUSY_BACKOFF: Duration = Duration::from_secs(5);
/// ...and after this many such drops its record is done, unless it is the
/// id's last live record (then it keeps waiting its backoff, up to
/// [`REQUEST_TIMEOUT`]; the deadline bounds it).
pub(super) const BUSY_MAX: u8 = 2;
/// An answer dropped for a node-wide reason (the node-wide PX share, a full
/// transaction lane) pauses its id this long, doubling at each further
/// such drop...
pub(super) const GLOBAL_PAUSE: Duration = Duration::from_secs(1);
/// ...up to this.
pub(super) const GLOBAL_PAUSE_MAX: Duration = Duration::from_secs(30);

/// How long any copy of an id a peer was asked for is accepted from it
/// after its request ended (timed out, cut by the deadline, or another
/// announcer's answer came first): a slow honest link delivers well within
/// it (RT3 F1b; a PX transaction takes about 35 s at 64 KiB/s).
pub(super) const LATE_TX_WINDOW: Duration = Duration::from_secs(5 * 60);

/// Ended requests remembered per peer: a bound, not a guess (RT5 F1). An
/// entry outlives its answer only if its request held one of the peer's
/// [`PEER_IN_FLIGHT`] slots to its expiry, at least [`REQUEST_TIMEOUT`]
/// after it was asked: a request ended early (another announcer's answer,
/// the deadline) keeps its slot until its answer, its `NotFound` or its
/// expiry, and the answer consumes the entry. Entries whose slot was
/// released within the last [`LATE_TX_WINDOW`] each held a slot through
/// the 30 s before that release, at most 16 at once, so there are at most
/// 16 x (300 s + 30 s) / 30 s = 176 of them, plus at most 16 still holding
/// a slot. Before RT5 F1 an early ending freed the slot at once, a burst of
/// such endings pushed earlier entries out of a 160-entry memory, and
/// their honest late answers were penalized as unrequested
/// (`rt5_fast_endings_push_a_peers_late_answers_out`). Each peer has its
/// own: one peer's entries never crowd out another's (RT4: one node-wide
/// map was filled for free with junk answers, and honest answers were
/// penalized again).
pub(super) const LATE_PER_PEER: usize =
    PEER_IN_FLIGHT * (LATE_TX_WINDOW.as_secs() / REQUEST_TIMEOUT.as_secs() + 2) as usize;

/// A peer's network class: clearnet, or onion (an onion address, or an
/// inbound connection through our hidden service).
pub(super) type NetClass = u8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnnState {
    /// May be asked from `ready` on.
    Candidate { ready: Instant },
    /// Asked at `asked`; times out at `expiry`.
    Requested { asked: Instant, expiry: Instant },
    /// Answered without the transaction, timed out, or refused.
    Done,
}

#[derive(Clone, Debug)]
struct Ann {
    peer: PeerId,
    preferred: bool,
    state: AnnState,
    busy: u8,
    /// It timed out once after its answer was dropped by this node's own
    /// slow lane, and was put back.
    retried: bool,
    /// The request period (of [`REQUEST_TIMEOUT`], from the id's first
    /// announcement) it was announced in: a later period ranks after
    /// (re-announcements by reconnecting peers, RT3 F2).
    epoch: u32,
    /// Per-node random priority of (id, peer): lower first.
    prio: u64,
}

impl Ann {
    /// Lower is asked first.
    fn key(&self) -> (u8, bool, u32, u64) {
        (
            self.busy.saturating_add(u8::from(self.retried)),
            !self.preferred,
            self.epoch,
            self.prio,
        )
    }
}

#[derive(Clone, Debug)]
struct TxEntry {
    created: Instant,
    deadline: Instant,
    timeouts: u32,
    /// When its first request was sent: [`PARALLEL`] from 30 s after.
    first_asked: Option<Instant>,
    /// Node-wide drops so far (the pause doubles).
    stalls: u32,
    paused_until: Option<Instant>,
    anns: Vec<Ann>,
    /// Its key in `timers`.
    timer: Instant,
}

impl TxEntry {
    fn allowed(&self, now: Instant) -> usize {
        let parallel =
            self.timeouts > 0 || self.first_asked.is_some_and(|f| now >= f + REQUEST_TIMEOUT);
        if parallel {
            PARALLEL
        } else {
            1
        }
    }
}

#[derive(Clone, Debug, Default)]
struct PeerLoad {
    class: NetClass,
    tracked: HashSet<Hash>,
    in_flight: usize,
    /// A decaying maximum of its answers' sizes (0: none yet).
    answer_size: usize,
    /// When its slow lane last dropped a large answer from it.
    lane_drop: Option<Instant>,
    /// Ids with a ready candidate of this peer that found no room: looked
    /// at again when it has room.
    waiting: VecDeque<Hash>,
    waiting_set: HashSet<Hash>,
    /// Its ended requests whose answers stay acceptable, one copy each,
    /// oldest first.
    late: VecDeque<Late>,
    /// Entries [`LATE_PER_PEER`] pushed out (tests: the bound says none).
    #[cfg(test)]
    evicted: usize,
}

/// An ended request of a peer whose answer stays acceptable (once).
#[derive(Clone, Copy, Debug)]
struct Late {
    id: Hash,
    /// When it timed out, or (`hold`) when it will: a copy is accepted
    /// until [`LATE_TX_WINDOW`] after.
    at: Instant,
    /// Ended before its expiry (another announcer's answer, the deadline):
    /// the peer is still answering it, so it holds one of the peer's
    /// in-flight slots until its answer, its `NotFound` or `at`. Its key in
    /// `TxTracker::holds`.
    hold: Option<u64>,
}

impl PeerLoad {
    /// Remembers an ended request for `id`, accepted until
    /// [`LATE_TX_WINDOW`] after `at` (entries out of their window go first;
    /// the bound of [`LATE_PER_PEER`] says nothing is pushed out).
    fn remember_late(&mut self, id: Hash, at: Instant, hold: Option<u64>, now: Instant) {
        self.late
            .retain(|l| l.hold.is_some() || now.saturating_duration_since(l.at) <= LATE_TX_WINDOW);
        self.late.push_back(Late { id, at, hold });
        while self.late.len() > LATE_PER_PEER {
            // Never one that holds a slot (at most `PEER_IN_FLIGHT`).
            let Some(i) = self.late.iter().position(|l| l.hold.is_none()) else {
                break;
            };
            self.late.remove(i);
            #[cfg(test)]
            {
                self.evicted += 1;
            }
        }
    }

    /// Removes and returns an acceptable entry for `id` (one holding a
    /// slot first).
    fn take_late(&mut self, id: &Hash, now: Instant) -> Option<Late> {
        let ok = |l: &Late| l.id == *id && now.saturating_duration_since(l.at) <= LATE_TX_WINDOW;
        let i = self
            .late
            .iter()
            .position(|l| ok(l) && l.hold.is_some())
            .or_else(|| self.late.iter().position(ok))?;
        self.late.remove(i)
    }
}

impl PeerLoad {
    /// What each request to this peer is expected to weigh: the decaying
    /// maximum of its answers; before its first answer, half its in-flight
    /// bytes (two requests, so a burst of large answers fits its slow lane).
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

    /// A request's timeout: [`REQUEST_TIMEOUT`] plus the time its known
    /// answer size takes at [`REQUEST_RATE`].
    fn timeout(&self) -> Duration {
        REQUEST_TIMEOUT + Duration::from_secs((self.answer_size / REQUEST_RATE) as u64)
    }
}

/// Whether `a` is a request younger than [`REQUEST_TIMEOUT`] at `now`.
fn young(a: &Ann, now: Instant) -> bool {
    matches!(a.state, AnnState::Requested { asked, .. } if now < asked + REQUEST_TIMEOUT)
}

/// What the caller sends and records after a tracker call.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Actions {
    /// `GetTx` per peer.
    pub(super) requests: Vec<(PeerId, Vec<Hash>)>,
    /// Requests that timed out now: their late answers stay acceptable
    /// (`TxTracker::remember_late`).
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
    /// Sends a tracker call's `GetTx`s (its ended requests are remembered
    /// by the tracker itself, per peer: their late answers stay
    /// acceptable, P2P-FIX2).
    pub(super) fn apply_tx_actions(&self, st: &mut State, out: Actions, _now: Instant) {
        for (peer, ids) in out.requests {
            self.send(st, peer, Message::GetTx(ids));
        }
    }

    /// Forgets `id` in the tracker (it arrived, or is known otherwise). The
    /// answers of its other outstanding requests stay acceptable: those
    /// peers did what was asked (RT3 F1: they were penalized as
    /// unrequested), and each holds its slot until it answers (RT5 F1).
    /// `taken`: the peer whose answer was just taken; it is not remembered
    /// (RT4).
    pub(super) fn forget_tx(st: &mut State, id: &Hash, taken: Option<PeerId>) {
        st.tx_tracker.forget_requested(id, taken, Instant::now());
    }
}

type Key = (NetClass, Hash);

/// The tracker.
pub(super) struct TxTracker {
    txs: HashMap<Key, TxEntry>,
    peers: HashMap<PeerId, PeerLoad>,
    timers: BTreeSet<(Instant, Key)>,
    /// Slots held by requests ended before their expiry, by expiry
    /// ([`Late::hold`]): freed then if not answered before.
    holds: BTreeSet<(Instant, u64, PeerId)>,
    /// The last [`Late::hold`] key.
    seq: u64,
    salt: RandomState,
    /// Peers that got room during a call: their waiting ids are looked at
    /// before it returns.
    freed: Vec<PeerId>,
    /// The latest time a call saw (the invariant check's clock).
    now: Instant,
}

impl Default for TxTracker {
    fn default() -> Self {
        Self {
            txs: HashMap::new(),
            peers: HashMap::new(),
            timers: BTreeSet::new(),
            holds: BTreeSet::new(),
            seq: 0,
            salt: RandomState::new(),
            freed: Vec::new(),
            now: Instant::now(),
        }
    }
}

impl TxTracker {
    /// Ids tracked (per network class).
    pub(super) fn len(&self) -> usize {
        self.txs.len()
    }

    /// Requests outstanding, over all ids.
    pub(super) fn requests(&self) -> usize {
        self.peers.values().map(|p| p.in_flight).sum()
    }

    /// Records `peer`'s network class (at registration; clearnet unless
    /// set).
    pub(super) fn register_peer(&mut self, peer: PeerId, class: NetClass) {
        self.peers.entry(peer).or_default().class = class;
    }

    fn class(&self, peer: PeerId) -> NetClass {
        self.peers.get(&peer).map_or(0, |l| l.class)
    }

    /// `peer`'s request for `id`, expiring at `expiry`, ended before its
    /// answer (another announcer's answer came first, or the deadline cut
    /// it): its answer stays acceptable, and it keeps its slot until that
    /// answer, a `NotFound` or `expiry` (RT5 F1). Past its expiry it is a
    /// timeout: the slot is freed now.
    fn end_unanswered(&mut self, id: Hash, peer: PeerId, expiry: Instant, now: Instant) {
        let Some(l) = self.peers.get_mut(&peer) else {
            return;
        };
        if expiry <= now {
            l.remember_late(id, now, None, now);
            l.in_flight = l.in_flight.saturating_sub(1);
            self.freed.push(peer);
            return;
        }
        self.seq += 1;
        l.remember_late(id, expiry, Some(self.seq), now);
        self.holds.insert((expiry, self.seq, peer));
    }

    /// Frees the slot of `peer` that `late` held, if it held one.
    fn release(&mut self, peer: PeerId, late: Late) {
        let Some(seq) = late.hold else {
            return;
        };
        self.holds.remove(&(late.at, seq, peer));
        if let Some(l) = self.peers.get_mut(&peer) {
            l.in_flight = l.in_flight.saturating_sub(1);
            self.freed.push(peer);
        }
    }

    /// Takes the record of a late answer: whether a copy of `id` from
    /// `peer` answers one of our ended requests, one copy per request,
    /// within [`LATE_TX_WINDOW`] of its end. Taking it frees the slot the
    /// request still held (used at the next call that wakes, as a `poll`).
    pub(super) fn take_late(&mut self, id: &Hash, peer: PeerId, now: Instant) -> bool {
        let Some(late) = self.peers.get_mut(&peer).and_then(|l| l.take_late(id, now)) else {
            return false;
        };
        self.release(peer, late);
        true
    }

    /// Whether `peer` has an outstanding request for `id`.
    pub(super) fn is_requested(&self, id: &Hash, peer: PeerId) -> bool {
        self.txs.get(&(self.class(peer), *id)).is_some_and(|e| {
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
        let key = (load.class, id);
        let prio = self.salt.hash_one((id, peer));
        let ready = if preferred { now } else { now + INBOUND_DELAY };
        let e = self.txs.entry(key).or_insert_with(|| TxEntry {
            created: now,
            deadline: now + DEADLINE,
            timeouts: 0,
            first_asked: None,
            stalls: 0,
            paused_until: None,
            anns: Vec::new(),
            timer: now,
        });
        let epoch =
            (now.saturating_duration_since(e.created).as_secs() / REQUEST_TIMEOUT.as_secs()) as u32;
        e.anns.push(Ann {
            peer,
            preferred,
            state: AnnState::Candidate { ready },
            busy: 0,
            retried: false,
            epoch,
            prio,
        });
        self.eval(key, now, out);
        self.wake(now, out);
    }

    /// The size of `peer`'s latest answer: a decaying maximum of them (each
    /// answer, or 7/8 of the previous figure, whichever is larger) is what
    /// each request to it is expected to weigh. One small answer after a
    /// large one does not open 16 requests at once (RT3 F3).
    pub(super) fn answer_size(
        &mut self,
        peer: PeerId,
        bytes: usize,
        now: Instant,
        out: &mut Actions,
    ) {
        if let Some(l) = self.peers.get_mut(&peer) {
            l.answer_size = bytes.max(l.answer_size / 8 * 7);
            self.freed.push(peer);
        }
        self.wake(now, out);
    }

    /// `peer`'s slow lane dropped a large `Tx` frame: its requests that
    /// time out are asked once more. The frame was never decoded, so its
    /// size says nothing (RT4: it inflated the peer's request timeouts for
    /// free); only decoded answers set the expected size
    /// ([`Self::answer_size`]).
    pub(super) fn lane_dropped(&mut self, peer: PeerId, _bytes: usize, now: Instant) {
        if let Some(l) = self.peers.get_mut(&peer) {
            l.lane_drop = Some(now);
        }
    }

    /// Forgets `id` (in both network classes), returning the peers whose
    /// requests for it were still outstanding, but `taken` (the peer whose
    /// answer was just taken: its slot is freed). Their answers stay
    /// acceptable, and each holds its slot until it comes (RT5 F1).
    pub(super) fn forget_requested(
        &mut self,
        id: &Hash,
        taken: Option<PeerId>,
        now: Instant,
    ) -> Vec<PeerId> {
        let mut asked = Vec::new();
        for class in [0, 1] {
            asked.extend(self.remove(&(class, *id), taken, now));
        }
        asked
    }

    /// `peer` answered `NotFound` for `id`: its request ends; or, if it had
    /// ended already, the slot it still held is freed.
    pub(super) fn not_found(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let key = (self.class(peer), id);
        if self.end_request(&key, peer, |a| a.state = AnnState::Done) {
            self.eval(key, now, out);
        } else if let Some(late) = self
            .peers
            .get_mut(&peer)
            .and_then(|l| l.take_late(&id, now))
        {
            self.release(peer, late);
        }
        self.wake(now, out);
    }

    /// `peer`'s answer for `id` was dropped for its own budgets (its relay
    /// share): the next candidate is asked now, this one again after
    /// [`BUSY_BACKOFF`] (doubling), and after [`BUSY_MAX`] such drops it
    /// is done unless it is the id's last live record.
    pub(super) fn busy(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let key = (self.class(peer), id);
        let others_live = self.txs.get(&key).is_some_and(|e| {
            e.anns
                .iter()
                .any(|a| a.peer != peer && a.state != AnnState::Done)
        });
        let ended = self.end_request(&key, peer, |a| {
            a.busy = a.busy.saturating_add(1);
            let backoff = BUSY_BACKOFF
                .saturating_mul(1 << (a.busy - 1).min(4))
                .min(REQUEST_TIMEOUT);
            a.state = if a.busy >= BUSY_MAX && others_live {
                AnnState::Done
            } else {
                AnnState::Candidate {
                    ready: now + backoff,
                }
            };
        });
        if ended {
            self.eval(key, now, out);
        }
        self.wake(now, out);
    }

    /// `peer`'s answer for `id` was dropped for a node-wide reason (the
    /// node-wide PX share, a full transaction lane): the id (not the peer)
    /// pauses for [`GLOBAL_PAUSE`], doubling up to [`GLOBAL_PAUSE_MAX`],
    /// and the same record is asked again after it (RT3 F4).
    pub(super) fn pause(&mut self, id: Hash, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let key = (self.class(peer), id);
        if self.end_request(&key, peer, |a| a.state = AnnState::Candidate { ready: now }) {
            if let Some(e) = self.txs.get_mut(&key) {
                let pause = GLOBAL_PAUSE
                    .saturating_mul(1 << e.stalls.min(5))
                    .min(GLOBAL_PAUSE_MAX);
                e.stalls += 1;
                e.paused_until = Some(now + pause);
            }
            self.eval(key, now, out);
        }
        self.wake(now, out);
    }

    /// `peer` disconnected: its records go, and the ids it held are
    /// looked at again now.
    pub(super) fn peer_gone(&mut self, peer: PeerId, now: Instant, out: &mut Actions) {
        self.poll(now, out);
        let Some(load) = self.peers.remove(&peer) else {
            return;
        };
        for l in &load.late {
            if let Some(seq) = l.hold {
                self.holds.remove(&(l.at, seq, peer));
            }
        }
        for id in load.tracked {
            let key = (load.class, id);
            if let Some(e) = self.txs.get_mut(&key) {
                e.anns.retain(|a| a.peer != peer);
                self.eval(key, now, out);
            }
        }
        self.wake(now, out);
    }

    /// The timers due by `now`: requests time out, paused or delayed
    /// candidates are asked, a first request period ends, deadlines drop
    /// ids. In time order, each at its own time: an id whose timer came
    /// first is looked at as of that time, so a candidate that became ready
    /// later cannot jump ahead of what happened in between (another id
    /// filling that candidate's peer, say).
    pub(super) fn poll(&mut self, now: Instant, out: &mut Actions) {
        self.now = self.now.max(now);
        loop {
            let timer = self.timers.first().copied().filter(|(t, _)| *t <= now);
            let hold = self.holds.first().copied().filter(|(t, ..)| *t <= now);
            match (timer, hold) {
                // A slot held by a request ended early whose expiry came
                // unanswered: freed (its answer stays acceptable, as a
                // timed-out one's).
                (_, Some((t, seq, peer))) if timer.is_none_or(|(tt, _)| t <= tt) => {
                    self.holds.remove(&(t, seq, peer));
                    if let Some(l) = self.peers.get_mut(&peer) {
                        if let Some(x) = l.late.iter_mut().find(|x| x.hold == Some(seq)) {
                            x.hold = None;
                        }
                        l.in_flight = l.in_flight.saturating_sub(1);
                        self.freed.push(peer);
                    }
                    self.wake(t, out);
                }
                (Some((t, key)), _) => {
                    self.timers.remove(&(t, key));
                    self.eval(key, t, out);
                    self.wake(t, out);
                }
                (None, _) => break,
            }
        }
        // Room freed outside a call that wakes (a forget, RT4).
        self.wake(now, out);
    }

    /// Looks again at the ids waiting on peers that got room, while they
    /// have room.
    fn wake(&mut self, now: Instant, out: &mut Actions) {
        while let Some(peer) = self.freed.pop() {
            let mut budget = self.peers.get(&peer).map_or(0, |l| l.waiting.len());
            while budget > 0 && self.peers.get(&peer).is_some_and(PeerLoad::has_room) {
                budget -= 1;
                let Some(l) = self.peers.get_mut(&peer) else {
                    break;
                };
                let Some(id) = l.waiting.pop_front() else {
                    break;
                };
                l.waiting_set.remove(&id);
                let key = (l.class, id);
                self.eval(key, now, out);
            }
        }
    }

    /// Ends `peer`'s request for `key` with `f` (on its record). `false` if
    /// there was none.
    fn end_request(&mut self, key: &Key, peer: PeerId, f: impl FnOnce(&mut Ann)) -> bool {
        let Some(e) = self.txs.get_mut(key) else {
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
            self.freed.push(peer);
        }
        true
    }

    /// Removes `key` with all its records. Its outstanding requests but
    /// `taken`'s (freed: its answer came) stay acceptable and keep their
    /// slots until answered ([`Self::end_unanswered`]); their peers are
    /// returned.
    fn remove(&mut self, key: &Key, taken: Option<PeerId>, now: Instant) -> Vec<PeerId> {
        let Some(e) = self.txs.remove(key) else {
            return Vec::new();
        };
        self.timers.remove(&(e.timer, *key));
        let mut ended = Vec::new();
        for a in e.anns {
            let Some(l) = self.peers.get_mut(&a.peer) else {
                continue;
            };
            l.tracked.remove(&key.1);
            if let AnnState::Requested { expiry, .. } = a.state {
                if Some(a.peer) == taken {
                    l.in_flight = l.in_flight.saturating_sub(1);
                    self.freed.push(a.peer);
                } else {
                    self.end_unanswered(key.1, a.peer, expiry, now);
                    ended.push(a.peer);
                }
            }
        }
        ended
    }

    /// Looks at `key` as of `now`: drops it at its deadline or when no
    /// record is left to ask, times out requests (a request whose answer
    /// our own slow lane dropped is asked once more), asks ready candidates
    /// up to its concurrency, and sets its timer.
    fn eval(&mut self, key: Key, now: Instant, out: &mut Actions) {
        let Some(e) = self.txs.get_mut(&key) else {
            return;
        };
        self.timers.remove(&(e.timer, key));
        if now >= e.deadline {
            // Requests cut by the deadline stay acceptable (RT4), and keep
            // their slots until answered (RT5 F1).
            for p in self.remove(&key, None, now) {
                out.expired.push((key.1, p));
            }
            return;
        }
        for a in e.anns.iter_mut() {
            if let AnnState::Requested { asked, expiry } = a.state {
                if expiry <= now {
                    e.timeouts += 1;
                    out.expired.push((key.1, a.peer));
                    let mut load = self.peers.get_mut(&a.peer);
                    if let Some(l) = load.as_mut() {
                        l.remember_late(key.1, now, None, now);
                    }
                    let dropped = load
                        .as_ref()
                        .is_some_and(|l| l.lane_drop.is_some_and(|d| d >= asked));
                    a.state = if dropped && !a.retried {
                        a.retried = true;
                        AnnState::Candidate { ready: now }
                    } else {
                        AnnState::Done
                    };
                    if let Some(l) = load {
                        l.in_flight = l.in_flight.saturating_sub(1);
                        self.freed.push(a.peer);
                    }
                }
            }
        }
        if e.paused_until.is_some_and(|t| t <= now) {
            e.paused_until = None;
        }
        let mut blocked: Vec<PeerId> = Vec::new();
        if e.paused_until.is_none() {
            let allowed = e.allowed(now);
            // Only requests younger than `REQUEST_TIMEOUT` hold one of the
            // id's slots; an older one (a long, size-aware timeout) stays
            // acceptable without holding it (RT4), but at most
            // `OUTSTANDING_MAX` are outstanding at once, one more for a
            // preferred announcer (RT5 F2, RT-ART5).
            let mut outstanding = e.anns.iter().filter(|a| young(a, now)).count();
            let mut total = e
                .anns
                .iter()
                .filter(|a| matches!(a.state, AnnState::Requested { .. }))
                .count();
            while outstanding < allowed && total < OUTSTANDING_MAX + PREFERRED_RESERVE {
                let peers = &self.peers;
                let mut best: Option<usize> = None;
                for (i, a) in e.anns.iter().enumerate() {
                    let AnnState::Candidate { ready } = a.state else {
                        continue;
                    };
                    if ready > now {
                        continue;
                    }
                    // The reserved place is for preferred announcers only;
                    // the others wait for an expiry (its timer is set).
                    if !a.preferred && total >= OUTSTANDING_MAX {
                        continue;
                    }
                    if !peers.get(&a.peer).is_some_and(PeerLoad::has_room) {
                        if !blocked.contains(&a.peer) {
                            blocked.push(a.peer);
                        }
                        continue;
                    }
                    if best.is_none_or(|b| a.key() < e.anns[b].key()) {
                        best = Some(i);
                    }
                }
                let Some(i) = best else { break };
                let a = &mut e.anns[i];
                let timeout = self
                    .peers
                    .get(&a.peer)
                    .map_or(REQUEST_TIMEOUT, PeerLoad::timeout);
                a.state = AnnState::Requested {
                    asked: now,
                    expiry: now + timeout,
                };
                if let Some(l) = self.peers.get_mut(&a.peer) {
                    l.in_flight += 1;
                }
                out.ask(a.peer, key.1);
                e.first_asked.get_or_insert(now);
                outstanding += 1;
                total += 1;
            }
        }
        let live = e.anns.iter().any(|a| a.state != AnnState::Done);
        if !live {
            // No request is outstanding: nothing to remember.
            self.remove(&key, None, now);
            return;
        }
        let mut timer = e.deadline;
        for a in &e.anns {
            match a.state {
                AnnState::Requested { expiry, asked } => {
                    timer = timer.min(expiry);
                    if asked + REQUEST_TIMEOUT > now {
                        timer = timer.min(asked + REQUEST_TIMEOUT);
                    }
                }
                AnnState::Candidate { ready } if ready > now => timer = timer.min(ready),
                _ => {}
            }
        }
        if let Some(t) = e.paused_until {
            timer = timer.min(t);
        }
        if let Some(f) = e.first_asked {
            if e.timeouts == 0 && f + REQUEST_TIMEOUT > now {
                timer = timer.min(f + REQUEST_TIMEOUT);
            }
        }
        e.timer = timer;
        self.timers.insert((timer, key));
        // Blocked candidates wait on their peers (no rescan timer: RT3).
        for p in blocked {
            if let Some(l) = self.peers.get_mut(&p) {
                if l.waiting_set.insert(key.1) {
                    l.waiting.push_back(key.1);
                }
            }
        }
    }

    /// Checks the invariants (tests): every id has a timer at or before its
    /// deadline and a live record; no cap is exceeded; at most
    /// [`PARALLEL`] requests per id; a peer's in-flight count matches its
    /// records; a ready candidate is never left without room nor a wait.
    #[cfg(test)]
    fn check(&self) {
        for (key, e) in &self.txs {
            assert!(
                self.timers.contains(&(e.timer, *key)),
                "an id without a timer"
            );
            assert!(e.timer <= e.deadline);
            assert!(e.anns.iter().any(|a| a.state != AnnState::Done));
            // Young requests hold the id's slots (older ones only stay
            // acceptable): at most `PARALLEL`, one before the first request
            // period ends.
            let young_now = e.anns.iter().filter(|a| young(a, self.now)).count();
            assert!(young_now <= PARALLEL);
            let total = e
                .anns
                .iter()
                .filter(|a| matches!(a.state, AnnState::Requested { .. }))
                .count();
            assert!(
                total <= OUTSTANDING_MAX + PREFERRED_RESERVE,
                "{total} outstanding for one id"
            );
            let inbound = e
                .anns
                .iter()
                .filter(|a| !a.preferred && matches!(a.state, AnnState::Requested { .. }))
                .count();
            assert!(
                inbound <= OUTSTANDING_MAX,
                "{inbound} non-preferred outstanding"
            );
            if e.timeouts == 0 && e.first_asked.is_none_or(|f| self.now < f + REQUEST_TIMEOUT) {
                assert!(young_now <= 1);
            }
        }
        assert_eq!(self.timers.len(), self.txs.len());
        let mut holding = 0;
        for (peer, l) in &self.peers {
            assert!(l.tracked.len() <= PEER_TRACKED);
            assert!(l.in_flight <= PEER_IN_FLIGHT);
            let real = self
                .txs
                .values()
                .flat_map(|e| e.anns.iter())
                .filter(|a| a.peer == *peer && matches!(a.state, AnnState::Requested { .. }))
                .count();
            // Requests ended before their answer hold their slots (RT5 F1).
            let held = l.late.iter().filter(|x| x.hold.is_some()).count();
            for x in &l.late {
                if let Some(seq) = x.hold {
                    assert!(self.holds.contains(&(x.at, seq, *peer)));
                }
            }
            holding += held;
            assert_eq!(real + held, l.in_flight);
            assert!(l.late.len() <= LATE_PER_PEER);
            assert_eq!(l.evicted, 0, "the late-answer memory is a bound (RT5 F1)");
        }
        assert_eq!(holding, self.holds.len());
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
        t.announce(id(1), 3, true, t0, &mut out);
        let first = out.requests[0].0;
        let mut out = Actions::default();
        t.busy(id(1), first, t0, &mut out);
        let second = out.requests[0].0;
        assert_ne!(first, second, "rotated at once");
        // `BUSY_MAX` (2) drops: the record is done while others live.
        let mut out = Actions::default();
        t.not_found(id(1), second, t0, &mut out);
        let third = out.requests[0].0;
        let mut now = t0 + BUSY_BACKOFF;
        let mut out = Actions::default();
        t.not_found(id(1), third, now, &mut out);
        t.poll(now, &mut out);
        assert!(asked(&out, first, id(1)), "the busy one, after its backoff");
        // Its second drop, as the last live record: kept, with a doubled
        // backoff (the deadline bounds it).
        t.busy(id(1), first, now, &mut out);
        assert_eq!(t.len(), 1, "the last live record is not dropped for Busy");
        now += BUSY_BACKOFF * 2;
        let mut out = Actions::default();
        t.poll(now, &mut out);
        assert!(asked(&out, first, id(1)));
        t.check();
        // With other live records, the second drop ends the busy one.
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for p in 1..=3 {
            t.announce(id(2), p, true, t0, &mut out);
        }
        let mut now = t0;
        while now < t0 + Duration::from_secs(40) {
            let mut out = Actions::default();
            t.poll(now, &mut out);
            if t.is_requested(&id(2), 1) {
                t.busy(id(2), 1, now, &mut out);
            }
            now += Duration::from_secs(1);
        }
        assert!(t.txs.values().all(|e| e
            .anns
            .iter()
            .any(|a| a.peer == 1 && a.state == AnnState::Done)));
        t.check();
    }

    /// A request that timed out is asked once more of the same peer only
    /// if this node's own slow lane dropped a large answer from that peer
    /// since it was asked (RT3 F1b: otherwise a slow honest peer's second
    /// copy was penalized); never a third time. Before a peer's first
    /// answer, two requests are in flight to it; a small answer opens room
    /// at once (the waiting ids are looked at again), and the decaying size
    /// keeps a large answer's weight for a while.
    #[test]
    fn a_timed_out_request_is_retried_only_after_a_lane_drop() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for n in 1..=3 {
            t.announce(id(n), 1, true, t0, &mut out);
        }
        assert_eq!(t.requests(), 2, "two before its first answer");
        let mut out = Actions::default();
        t.answer_size(1, 1_000, t0, &mut out);
        assert!(asked(&out, 1, id(3)), "room once its answers are small");
        t.lane_dropped(1, 2_000_000, t0 + Duration::from_secs(1));
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT, &mut out);
        assert_eq!(out.expired.len(), 3);
        assert!(
            asked(&out, 1, id(1)) || asked(&out, 1, id(2)),
            "asked once more after a lane drop"
        );
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT * 10, &mut out);
        assert_eq!(t.len(), 0, "never a third time");
        t.check();
        // Without a lane drop: no second request.
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(9), 1, true, t0, &mut out);
        let mut out = Actions::default();
        t.poll(t0 + REQUEST_TIMEOUT, &mut out);
        assert_eq!(out.expired, vec![(id(9), 1)]);
        assert!(out.requests.is_empty());
        assert_eq!(t.len(), 0);
        // The expected size decays: 7/8 per answer.
        let mut t = TxTracker::default();
        t.register_peer(1, 0);
        let mut out = Actions::default();
        t.answer_size(1, 2_000_000, t0, &mut out);
        t.answer_size(1, 1_000, t0, &mut out);
        assert_eq!(t.peers[&1].answer_size, 2_000_000 / 8 * 7);
    }

    /// Network classes keep apart (RT3 F6): the same id announced on the
    /// clearnet and the onion side is asked on both at once.
    #[test]
    fn network_classes_have_their_own_records() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        t.register_peer(1, 0);
        t.register_peer(2, 1);
        let mut out = Actions::default();
        t.announce(id(1), 1, true, t0, &mut out);
        t.announce(id(1), 2, true, t0, &mut out);
        assert!(asked(&out, 1, id(1)) && asked(&out, 2, id(1)));
        assert_eq!(t.len(), 2);
        assert_eq!(t.forget_requested(&id(1), None, t0).len(), 2);
        assert_eq!(t.len(), 0);
        t.check();
    }

    /// A ready candidate whose peer has no room waits on that peer and is
    /// asked as soon as the peer has room, without a rescan timer.
    #[test]
    fn a_blocked_candidate_is_woken_by_room() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(1), 1, true, t0, &mut out);
        t.announce(id(2), 1, true, t0, &mut out);
        t.announce(id(3), 1, true, t0, &mut out);
        assert_eq!(t.requests(), 2);
        let mut out = Actions::default();
        t.not_found(id(1), 1, t0, &mut out);
        assert!(asked(&out, 1, id(3)), "woken when room came");
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
        // The requests the deadline cut keep their slots until answered or
        // expired (RT5 F1).
        // (Two at a time, asked at 2 s + 30 s x 39 = 1 172 s.)
        assert_eq!(t.requests(), 2);
        t.check();
        let mut out = Actions::default();
        t.poll(t0 + DEADLINE + REQUEST_TIMEOUT, &mut out);
        assert_eq!(t.requests(), 0);
        t.check();
        let mut out = Actions::default();
        t.announce(id(5), 1, true, t0 + DEADLINE, &mut out);
        t.peer_gone(1, t0 + DEADLINE, &mut out);
        assert_eq!(t.len(), 0);
        t.check();
    }

    /// Property test: random sequences of announcements, answers,
    /// `NotFound`s, Busy and global drops, timeouts, disconnects, and late
    /// answers and `NotFound`s to requests another answer ended keep the
    /// invariants (`check`); every late answer within its window is
    /// accepted (RT5 F1); and an honest announcer among `k` attackers is
    /// asked within the bound of docs/p2p.md §7.
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
            // Requests ended early by another answer: (id, peer, when).
            let mut ended: Vec<(Hash, PeerId, Instant)> = Vec::new();
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
            // The attackers announce the target first, then junk. They
            // stay silent, answer `NotFound`, get their answers dropped as
            // Busy, or reconnect and announce again (RT3: adversarial).
            let mut attackers: Vec<PeerId> = (0..k as PeerId).collect();
            let mut next_peer: PeerId = 5_000;
            for a in 0..k as PeerId {
                let mut out = Actions::default();
                t.announce(target, a, rng.next_u64() % 4 == 0, now, &mut out);
                // Some inflate their expected answer size first (a decoded
                // answer of the largest size, RT4): they keep the bound.
                if rng.next_u64() % 3 == 0 {
                    t.answer_size(a, super::super::dispatch::MAX_RELAY_FRAME, now, &mut out);
                }
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
                                // The other requests for it end early:
                                // their answers are still to come (RT5 F1).
                                for q in t.forget_requested(&tx, Some(p), now) {
                                    ended.push((tx, q, now));
                                }
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
                        } else if p != honest {
                            // An attacker's answer for the target.
                            match rng.next_u64() % 2 {
                                0 => t.not_found(tx, p, now, &mut out),
                                _ => t.busy(tx, p, now, &mut out),
                            }
                        }
                    }
                    7 => {
                        // An attacker reconnects (a new peer id) and
                        // announces the target again.
                        let i = (rng.next_u64() as usize) % attackers.len();
                        let old = attackers[i];
                        t.peer_gone(old, now, &mut out);
                        outstanding.retain(|x| x.1 != old);
                        ended.retain(|x| x.1 != old);
                        attackers[i] = next_peer;
                        t.announce(target, next_peer, false, now, &mut out);
                        next_peer += 1;
                    }
                    5 if step % 50 == 0 => {
                        // A junk peer leaves (never the target's announcers).
                        let p = k as PeerId + (rng.next_u64() % 3) as PeerId;
                        t.peer_gone(p, now, &mut out);
                        outstanding.retain(|x| x.1 != p);
                        ended.retain(|x| x.1 != p);
                    }
                    8 if !ended.is_empty() => {
                        // A late answer (or `NotFound`) to a request ended
                        // early: accepted once, within its window, and its
                        // slot is freed (RT5 F1).
                        let i = (rng.next_u64() as usize) % ended.len();
                        let (tx, p, at) = ended.swap_remove(i);
                        if rng.next_u64() % 4 == 0 {
                            t.not_found(tx, p, now, &mut out);
                        } else if now <= at + LATE_TX_WINDOW {
                            assert!(
                                t.take_late(&tx, p, now),
                                "seed {seed}: a late answer refused"
                            );
                        }
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
                // Some attackers inflated: the stated bound with the
                // longest timeout (RT5 F2).
                let bound = stated_bound(k, longest_timeout()) + Duration::from_millis(500);
                let waited = honest_asked.expect("the honest announcer is asked") - at;
                assert!(
                    waited <= bound,
                    "seed {seed}, k {k}: {waited:?} > {bound:?}"
                );
            }
        }
    }

    /// The longest request timeout an attacker can get: after a decoded
    /// answer of the largest size (about 98 s).
    fn longest_timeout() -> Duration {
        REQUEST_TIMEOUT
            + Duration::from_secs((super::super::dispatch::MAX_RELAY_FRAME / REQUEST_RATE) as u64)
    }

    /// The stated bound of docs/p2p.md §7 (RT5 F2): an inbound honest
    /// announcer behind `k` attackers whose longest request timeout is
    /// `longest` is asked within `2 s + max(30 s x (1 + ceil(k / 4)),
    /// longest x ceil(k / 8))`: the 4 slots turn over every 30 s, the 8
    /// outstanding places at least every `longest`, and each attacker is
    /// asked at most once ahead of it.
    fn stated_bound(k: usize, longest: Duration) -> Duration {
        let slots = REQUEST_TIMEOUT * (1 + k.div_ceil(PARALLEL) as u32);
        let places = longest * k.div_ceil(OUTSTANDING_MAX) as u32;
        INBOUND_DELAY + slots.max(places)
    }

    // ------------------------------------------------ RT3-TM2P2P red team

    /// What an attacker does with a request for the target.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Strategy {
        /// Never answers (the model of the bound in docs/p2p.md §7).
        Silent,
        /// Answers `NotFound` just before its request would time out.
        SlowNotFound,
        /// Its answer is dropped as Busy just before the timeout (it
        /// drained its own relay share first, as in RT2 F2).
        SlowBusy,
        /// Disconnects just before the timeout, reconnects (a new peer id)
        /// and announces the target again.
        Recycle,
    }

    const STEP: Duration = Duration::from_millis(100);

    /// `strategies.len()` inbound attackers announce the target at t0, an
    /// honest announcer (inbound unless `honest_preferred`) 100 ms later.
    /// Runs in 100 ms steps, each attacker acting 100 ms before its
    /// request would time out. How long the honest one waited for its
    /// request; `None` if the id was dropped first (deadline, or every
    /// record done).
    fn honest_wait(strategies: &[Strategy], honest_preferred: bool) -> Option<Duration> {
        honest_wait_at(strategies, honest_preferred, STEP)
    }

    /// [`honest_wait`] with the honest announcement `after` the attackers'.
    fn honest_wait_at(
        strategies: &[Strategy],
        honest_preferred: bool,
        after: Duration,
    ) -> Option<Duration> {
        let t0 = Instant::now();
        let target = id(7);
        let honest: PeerId = 1_000_000;
        let mut next_peer = strategies.len() as PeerId;
        let mut who: HashMap<PeerId, Strategy> = HashMap::new();
        let mut asked: Vec<(PeerId, Instant)> = Vec::new();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for (p, s) in strategies.iter().enumerate() {
            who.insert(p as PeerId, *s);
            t.announce(target, p as PeerId, false, t0, &mut out);
        }
        let at = t0 + after;
        let mut now = t0;
        let mut announced = false;
        loop {
            asked.retain(|(p, _)| !out.expired.contains(&(target, *p)));
            for (p, ids) in &out.requests {
                if ids.contains(&target) {
                    if *p == honest {
                        return Some(now - at);
                    }
                    asked.push((*p, now));
                }
            }
            t.check();
            if (announced && t.len() == 0) || now > t0 + DEADLINE + STEP {
                return None;
            }
            now += STEP;
            out = Actions::default();
            if !announced && now >= at {
                t.announce(target, honest, honest_preferred, now, &mut out);
                announced = true;
            }
            let due: Vec<PeerId> = asked
                .iter()
                .filter(|(p, s)| now + STEP >= *s + REQUEST_TIMEOUT && who[p] != Strategy::Silent)
                .map(|(p, _)| *p)
                .collect();
            for p in due {
                asked.retain(|x| x.0 != p);
                match who[&p] {
                    Strategy::Silent => {}
                    Strategy::SlowNotFound => t.not_found(target, p, now, &mut out),
                    Strategy::SlowBusy => t.busy(target, p, now, &mut out),
                    Strategy::Recycle => {
                        t.peer_gone(p, now, &mut out);
                        let q = next_peer;
                        next_peer += 1;
                        who.insert(q, Strategy::Recycle);
                        t.announce(target, q, false, now, &mut out);
                    }
                }
            }
            t.poll(now, &mut out);
        }
    }

    /// The bound against attackers that do not inflate their timeouts
    /// (each `REQUEST_TIMEOUT`): `2 s + 30 s x (1 + ceil(k / 4))`.
    fn bound(k: usize) -> Duration {
        stated_bound(k, REQUEST_TIMEOUT) + STEP * 2
    }

    /// The bound against any attackers, some inflated to the largest
    /// answer (RT5 F2).
    fn bound_any(k: usize) -> Duration {
        stated_bound(k, longest_timeout()) + STEP * 2
    }

    /// Runs `trials` simulations; the worst wait (`None`: dropped).
    fn worst_wait(strategies: &[Strategy], preferred: bool, trials: usize) -> Option<Duration> {
        let mut worst = Some(Duration::ZERO);
        for _ in 0..trials {
            let w = honest_wait(strategies, preferred);
            worst = match (worst, w) {
                (Some(a), Some(b)) => Some(a.max(b)),
                _ => None,
            };
        }
        worst
    }

    /// The bound's own model: silent attackers. Holds (control).
    #[test]
    fn rt3_the_bound_holds_against_silent_announcers() {
        let k = 8;
        let w = worst_wait(&[Strategy::Silent; 8], false, 20);
        eprintln!("RT3 silent x{k}: worst {w:?}, bound {:?}", bound(k));
        assert!(w.is_some_and(|w| w <= bound(k)));
    }

    /// RT3-TM2P2P F2: the parallel fallback counts only timeouts. Attackers
    /// that answer `NotFound` (or get their answer dropped as Busy) just
    /// before the timeout never trigger it: the requests stay one at a
    /// time, 30 s per attacker, and an honest inbound announcer waits up to
    /// k x 30 s, not 2 s + 30 s x (1 + ceil(k / 4)). Expected to FAIL
    /// while the gap exists.
    #[test]
    fn rt3_slow_notfound_announcers_keep_the_bound() {
        let k = 8;
        let nf = worst_wait(&[Strategy::SlowNotFound; 8], false, 20);
        let busy = worst_wait(&[Strategy::SlowBusy; 8], false, 20);
        eprintln!(
            "RT3 slow NotFound x{k}: worst {nf:?}; slow Busy x{k}: worst {busy:?}; bound {:?}",
            bound(k)
        );
        assert!(nf.is_some_and(|w| w <= bound(k)), "slow NotFound: {nf:?}");
        assert!(busy.is_some_and(|w| w <= bound(k)), "slow Busy: {busy:?}");
    }

    /// RT3-TM2P2P F2: an attacker that disconnects just before its
    /// timeout, reconnects and announces again is a fresh candidate each
    /// time, with a fresh random priority, and no timeout ever runs: k
    /// such connections ask the honest inbound announcer to win a
    /// 1-in-(k + 1) draw every 30 s, and the 20-minute deadline drops the
    /// id first in a large share of the trials. Expected to FAIL while the
    /// gap exists.
    #[test]
    fn rt3_recycling_announcers_keep_the_bound() {
        let k = 8;
        let mut dropped = 0;
        let mut worst = Duration::ZERO;
        for _ in 0..20 {
            match honest_wait(&[Strategy::Recycle; 8], false) {
                Some(w) => worst = worst.max(w),
                None => dropped += 1,
            }
        }
        let many = (0..10)
            .filter(|_| honest_wait(&[Strategy::Recycle; 40], false).is_none())
            .count();
        eprintln!(
            "RT3 recycle x{k}: worst {worst:?}, dropped {dropped} of 20; x40: dropped {many} of \
             10; bound {:?}",
            bound(k)
        );
        assert!(
            dropped == 0 && worst <= bound(k),
            "{worst:?}, {dropped} dropped"
        );
    }

    /// An outbound (preferred) honest announcer is asked within 32 s
    /// whatever inbound attackers do (control: preferred ones rank first).
    #[test]
    fn rt3_a_preferred_announcer_is_asked_within_32_s_against_every_strategy() {
        for s in [
            Strategy::Silent,
            Strategy::SlowNotFound,
            Strategy::SlowBusy,
            Strategy::Recycle,
        ] {
            // Announced after an attacker was asked (inbound: at 2 s).
            let mut w = Some(Duration::ZERO);
            for _ in 0..10 {
                let one = honest_wait_at(&[s; 20], true, Duration::from_secs(3));
                w = w.zip(one).map(|(a, b)| a.max(b));
            }
            eprintln!("RT3 preferred honest (3 s after) vs 20 x {s:?}: worst {w:?}");
            assert!(
                w.is_some_and(|w| w <= REQUEST_TIMEOUT + INBOUND_DELAY + STEP * 2),
                "{s:?}: {w:?}"
            );
        }
    }

    /// RT3-TM2P2P: the adversarial counterpart of the property test above
    /// (which has only silent attackers): random mixes of the strategies,
    /// k from 1 to 40, an inbound honest announcer. Expected to FAIL while
    /// the gap exists.
    #[test]
    fn rt3_adversarial_strategies_keep_the_bound() {
        let all = [
            Strategy::Silent,
            Strategy::SlowNotFound,
            Strategy::SlowBusy,
            Strategy::Recycle,
        ];
        let mut failures = Vec::new();
        for seed in 0..30u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let k = 1 + (rng.next_u64() % 40) as usize;
            let mix: Vec<Strategy> = (0..k)
                .map(|_| all[(rng.next_u64() % all.len() as u64) as usize])
                .collect();
            let w = honest_wait(&mix, false);
            if !w.is_some_and(|w| w <= bound(k)) {
                failures.push((seed, k, w, bound(k)));
            }
        }
        eprintln!(
            "RT3 adversarial mixes: {} of 30 over the bound: {failures:?}",
            failures.len()
        );
        assert!(failures.is_empty());
    }

    /// RT3-TM2P2P F4: a full chain Tx lane is a node-wide condition (the
    /// actor is busy with blocks, say), but `on_tx` reports it as the
    /// answering peer's Busy, which is capped per (id, peer). About 10 s
    /// of a full lane make every honest record done and drop the id: it is
    /// not asked again until a later announcement (an honest node announces
    /// a transaction to a peer once, then only at the pool's
    /// re-announcement ages, 10 blocks and more). Expected to FAIL while
    /// the gap exists.
    #[test]
    fn rt3_a_node_wide_lane_stall_does_not_drop_an_honest_id() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        t.announce(id(1), 1, true, t0, &mut out);
        t.announce(id(1), 2, true, t0, &mut out);
        let mut now = t0;
        // Every answer arrives 50 ms after its request and finds the lane
        // full.
        let mut pending: Vec<(PeerId, Instant)> =
            out.requests.iter().map(|(p, _)| (*p, now)).collect();
        while now < t0 + Duration::from_secs(15) && t.len() > 0 {
            now += Duration::from_millis(50);
            let mut out = Actions::default();
            for (p, _) in std::mem::take(&mut pending) {
                t.busy(id(1), p, now, &mut out);
            }
            t.poll(now, &mut out);
            pending.extend(out.requests.iter().map(|(p, _)| (*p, now)));
            t.check();
        }
        eprintln!("RT3 lane stall: tracked after {:?}: {}", now - t0, t.len());
        assert_eq!(t.len(), 1, "dropped after {:?} of a full lane", now - t0);
    }

    /// RT3-TM2P2P (cost, informational): 64 junk peers with `PEER_TRACKED`
    /// ids each. A capped peer's ready candidates are "blocked" and looked
    /// at again every `BLOCKED_RETRY` (2 s) until the 20-minute deadline,
    /// all under the node's state lock (the maintenance tick polls the
    /// tracker). Prints the wall time of one simulated minute of polls.
    #[test]
    fn rt3_the_cost_of_blocked_junk_candidates() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for p in 0..64u64 {
            for n in 0..PEER_TRACKED as u64 {
                t.announce(id((p << 32) | n), p, false, t0, &mut out);
            }
        }
        let wall = Instant::now();
        let mut now = t0;
        let mut ticks = 0u32;
        while now < t0 + Duration::from_secs(60) {
            now += Duration::from_millis(250);
            let mut out = Actions::default();
            t.poll(now, &mut out);
            ticks += 1;
        }
        let spent = wall.elapsed();
        eprintln!(
            "RT3 junk cost: {} ids tracked; 60 s of polls ({ticks} ticks) took {spent:?} of wall \
             time ({:?} per tick)",
            t.len(),
            spent / ticks
        );
        // Since RT3 F1b a request that timed out is not asked again
        // without a lane drop: each junk peer's first two requests end, and
        // their ids, which no one else announced, are dropped.
        assert_eq!(t.len(), 64 * (PEER_TRACKED - 2));
    }

    // ------------------------------------------------ RT4-TM2P2P red team

    use super::super::dispatch::MAX_RELAY_FRAME;

    /// RT4-TM2P2P: an id whose entry is kept alive to its deadline (two
    /// attacker connections that each disconnect just before their request
    /// times out and announce again from a new connection: the entry always
    /// has a live record, so it keeps its first deadline). An honest
    /// (outbound) announcer announces 10 s before the deadline and is asked
    /// at once; its answer takes 15 s. At the deadline `eval` removes the
    /// entry with `remove`, which, unlike a timeout or `forget_requested`,
    /// reports no outstanding request: the honest request is not
    /// remembered in `State::late_txs`, so its answer arrives as an
    /// unrequested `Tx` (+10, dropped). An attacker who releases its own
    /// transaction to an honest peer at the right time frames that peer;
    /// ten times bans it. Expected to FAIL while the gap exists.
    #[test]
    fn rt4_a_request_cut_by_the_deadline_stays_acceptable() {
        let t0 = Instant::now();
        let target = id(7);
        let honest: PeerId = 1_000_000;
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        let mut next: PeerId = 0;
        for _ in 0..2 {
            t.announce(target, next, false, t0, &mut out);
            next += 1;
        }
        let mut asked_at: HashMap<PeerId, Instant> = HashMap::new();
        let mut honest_asked: Option<Instant> = None;
        let mut honest_expired = false;
        let mut alive_before = false;
        let mut now = t0;
        while now < t0 + DEADLINE + Duration::from_secs(30) {
            for (p, ids) in &out.requests {
                if ids.contains(&target) {
                    if *p == honest {
                        honest_asked.get_or_insert(now);
                    } else {
                        asked_at.insert(*p, now);
                    }
                }
            }
            honest_expired |= out.expired.contains(&(target, honest));
            t.check();
            now += STEP;
            out = Actions::default();
            if honest_asked.is_none() && now >= t0 + DEADLINE - Duration::from_secs(10) {
                alive_before |= t.len() == 1;
                t.announce(target, honest, true, now, &mut out);
            }
            let due: Vec<PeerId> = asked_at
                .iter()
                .filter(|(_, s)| now + STEP >= **s + REQUEST_TIMEOUT)
                .map(|(p, _)| *p)
                .collect();
            for p in due {
                asked_at.remove(&p);
                t.peer_gone(p, now, &mut out);
                t.announce(target, next, false, now, &mut out);
                next += 1;
            }
            t.poll(now, &mut out);
        }
        let asked = honest_asked.expect("the honest announcer is asked");
        eprintln!(
            "RT4 deadline cut: entry alive 10 s before the deadline: {alive_before}; honest asked \
             {:?} before the deadline; remembered as late: {honest_expired}; {} attacker \
             connections used",
            (t0 + DEADLINE).saturating_duration_since(asked),
            next
        );
        assert!(alive_before, "two recycling connections keep the id alive");
        assert!(
            honest_expired,
            "the honest request cut by the deadline is reported (late answer acceptable)"
        );
    }

    /// RT4-TM2P2P: room that a `forget_requested` frees (an id arriving
    /// another way: a fluffed stem transaction, a copy from another
    /// announcer) wakes nobody: `forget_requested` takes no `Actions`, and
    /// `poll` drained the freed peers only when a timer was due. A
    /// candidate waiting on that peer (its id's only timer is its
    /// 20-minute deadline) waited for an unrelated tracker event. Since RT5
    /// F1 a request ended by another announcer's answer keeps its slot until
    /// its own answer comes (or its `NotFound`, or its expiry): the room
    /// comes then, and is used at the next poll.
    #[test]
    fn rt4_room_freed_by_a_forget_is_used_at_the_next_poll() {
        // `answered`: how the room comes: 0 the peer's own answer was the
        // one taken, 1 its late answers, 2 its `NotFound`s, 3 nothing (the
        // requests' expiry).
        for answered in 0..4 {
            let t0 = Instant::now();
            let mut t = TxTracker::default();
            let mut out = Actions::default();
            for n in 1..=3 {
                t.announce(id(n), 1, true, t0, &mut out);
            }
            assert_eq!(t.requests(), 2, "two before the first answer; id 3 waits");
            let taken = (answered == 0).then_some(1);
            let ended = if taken.is_some() { vec![] } else { vec![1] };
            assert_eq!(t.forget_requested(&id(1), taken, t0), ended);
            assert_eq!(t.forget_requested(&id(2), taken, t0), ended);
            // The answers come 5 s later.
            let at = t0 + Duration::from_secs(5);
            let mut now = t0;
            let mut first = None;
            let mut answers_due = answered == 1 || answered == 2;
            while now < t0 + Duration::from_secs(120) && first.is_none() {
                now += Duration::from_millis(250);
                let mut out = Actions::default();
                if answers_due && now >= at {
                    answers_due = false;
                    if answered == 1 {
                        assert!(t.take_late(&id(1), 1, now) && t.take_late(&id(2), 1, now));
                        assert!(!t.take_late(&id(1), 1, now), "one copy per request");
                    } else {
                        t.not_found(id(1), 1, now, &mut out);
                        t.not_found(id(2), 1, now, &mut out);
                    }
                }
                t.poll(now, &mut out);
                if asked(&out, 1, id(3)) {
                    first = Some(now - t0);
                }
                t.check();
            }
            eprintln!("RT4 lost wakeup ({answered}): id 3 asked after {first:?}");
            // The next poll after the room came: the forget (the peer's
            // own answer taken), its answers, or the requests' expiry (no
            // answer: 30 s).
            let room = match answered {
                0 => Duration::ZERO,
                1 | 2 => at - t0,
                _ => REQUEST_TIMEOUT,
            };
            assert!(
                first.is_some_and(|d| d >= room && d <= room + Duration::from_millis(250)),
                "{answered}: {first:?}"
            );
            if answered == 3 {
                assert!(t.take_late(&id(1), 1, now), "acceptable after its expiry");
            }
        }
    }

    /// RT4 strategies of size-inflating attackers. Each makes its expected
    /// answer size the largest frame first: one large `Tx` frame its own
    /// full slow lane drops unread (`conn.rs`, `lane_dropped`; relay drops
    /// are never charged, and the frame is never decoded, so it costs no
    /// points and need not be a transaction at all).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum S4 {
        /// Then stays silent.
        Silent,
        /// Then drops a large frame again after each request, so its timed
        /// out request is asked once more (`retried`).
        Retry,
        /// Then answers `NotFound` just before its (inflated) timeout.
        LateNotFound,
    }

    /// `k` size-inflated inbound attackers announce the target at t0, an
    /// inbound honest one 100 ms later. The honest wait; `None` if the
    /// deadline dropped the id first.
    fn honest_wait_inflated(s: S4, k: usize, after: Duration) -> Option<Duration> {
        let t0 = Instant::now();
        let target = id(7);
        let honest: PeerId = 1_000_000;
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for p in 0..k as PeerId {
            t.announce(target, p, false, t0, &mut out);
            t.lane_dropped(p, MAX_RELAY_FRAME, t0);
            // Since RT4 a dropped frame no longer inflates the expected
            // size; a decoded answer of the largest size does (the costly
            // way): every attacker inflates so.
            t.answer_size(p, MAX_RELAY_FRAME, t0, &mut out);
        }
        let at = t0 + after;
        let mut now = t0;
        let mut announced = false;
        let mut asked: Vec<(PeerId, Instant)> = Vec::new();
        loop {
            asked.retain(|(p, _)| !out.expired.contains(&(target, *p)));
            for (p, ids) in &out.requests {
                if ids.contains(&target) {
                    if *p == honest {
                        return Some(now - at);
                    }
                    asked.push((*p, now));
                    if s == S4::Retry {
                        t.lane_dropped(*p, MAX_RELAY_FRAME, now);
                    }
                }
            }
            t.check();
            if (announced && t.len() == 0) || now > t0 + DEADLINE + STEP {
                return None;
            }
            now += STEP;
            out = Actions::default();
            if !announced && now >= at {
                t.announce(target, honest, false, now, &mut out);
                announced = true;
            }
            if s == S4::LateNotFound {
                let due: Vec<PeerId> = asked
                    .iter()
                    .filter(|(p, a)| {
                        let to = t.peers.get(p).map_or(REQUEST_TIMEOUT, PeerLoad::timeout);
                        now + STEP >= *a + to
                    })
                    .map(|(p, _)| *p)
                    .collect();
                for p in due {
                    asked.retain(|x| x.0 != p);
                    t.not_found(target, p, now, &mut out);
                }
            }
            t.poll(now, &mut out);
        }
    }

    /// The stated bound against size-inflating attackers (docs/p2p.md §7):
    /// `2 s + 30 s + (30 s + MAX_RELAY_FRAME / 64 KiB/s) x ceil(k / 4)`.
    fn inflated_bound(k: usize) -> Duration {
        let slot = REQUEST_TIMEOUT + Duration::from_secs((MAX_RELAY_FRAME / REQUEST_RATE) as u64);
        INBOUND_DELAY + REQUEST_TIMEOUT + slot * k.div_ceil(PARALLEL) as u32 + STEP * 2
    }

    /// RT4-TM2P2P (claim check): the size-inflation bound holds up to k =
    /// 44 for every inflating strategy. Since the RT4 fixes (only requests
    /// younger than `REQUEST_TIMEOUT` hold the id's slots, and only decoded
    /// answers set the expected size) inflaters keep the silent bound, and
    /// the deadline no longer drops the id within the 64 inbound slots:
    /// the assertion that it did (written against RT3) is replaced by the
    /// stronger one that it does not.
    #[test]
    fn rt4_size_inflaters_keep_the_stated_bound_up_to_44() {
        // The worst case: the honest announcement comes in the id's second
        // request period, so every attacker (first period) ranks ahead of
        // it. The wait is counted from the attackers' announcement.
        let late = REQUEST_TIMEOUT + STEP;
        for s in [S4::Silent, S4::Retry, S4::LateNotFound] {
            for k in [1, 4, 8, 20, 44] {
                let w = honest_wait_inflated(s, k, late).map(|w| w + late);
                eprintln!(
                    "RT4 inflated {s:?} x{k}: {w:?} after the attackers, stated bound {:?}",
                    inflated_bound(k)
                );
                assert!(
                    w.is_some_and(|w| w <= inflated_bound(k)),
                    "{s:?} x{k}: {w:?}"
                );
                assert!(
                    w.is_some_and(|w| w <= bound_any(k)),
                    "the single bound: {s:?} x{k}: {w:?}"
                );
            }
            // Beyond 44, within the 64 inbound slots: the single bound
            // (RT5 F2) holds and the deadline drops nothing.
            for k in [45, 52, 64] {
                let w = honest_wait_inflated(s, k, late).map(|w| w + late);
                eprintln!(
                    "RT4 inflated {s:?} x{k}: {w:?}, single bound {:?}",
                    bound_any(k)
                );
                assert!(w.is_some_and(|w| w <= bound_any(k)), "{s:?} x{k}: {w:?}");
            }
        }
    }

    // ------------------------------------------------ RT5-TM2P2P red team

    /// RT5 attacker strategies: RT3's and RT4's, plus reconnecting at a
    /// timeout, a Busy at the end of the 30 s slot of an inflated request,
    /// and a lane drop after every request (a retry each time).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum S5 {
        Silent,
        /// `NotFound` just before its own (possibly inflated) timeout.
        SlowNotFound,
        /// Busy just before its own (possibly inflated) timeout.
        SlowBusy,
        /// Busy just before the end of its 30 s slot (an inflated request
        /// would otherwise stay outstanding, unslotted, until ~98 s).
        SlotBusy,
        /// Disconnects just before its own timeout, reconnects, announces
        /// again.
        Recycle,
        /// Lets its request time out, then reconnects and announces again
        /// (a fresh record, in the period of the reconnect).
        ReconnectOnExpiry,
        /// A large frame dropped by its slow lane after each request: the
        /// timed-out request is asked once more.
        Retry,
    }

    const S5_ALL: [S5; 7] = [
        S5::Silent,
        S5::SlowNotFound,
        S5::SlowBusy,
        S5::SlotBusy,
        S5::Recycle,
        S5::ReconnectOnExpiry,
        S5::Retry,
    ];

    /// `strats.len()` inbound attackers (each inflated if its flag is set:
    /// a decoded answer of the largest size first) announce the target at
    /// t0; an inbound (or preferred) honest announcer `after` it. The
    /// honest wait from its own announcement; `None`: the id was dropped.
    fn rt5_wait(strats: &[(S5, bool)], after: Duration, honest_pref: bool) -> Option<Duration> {
        let t0 = Instant::now();
        let target = id(7);
        let honest: PeerId = 1_000_000;
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        let mut who: HashMap<PeerId, (S5, bool)> = HashMap::new();
        for (p, s) in strats.iter().enumerate() {
            let p = p as PeerId;
            who.insert(p, *s);
            t.announce(target, p, false, t0, &mut out);
            if s.1 {
                t.answer_size(p, MAX_RELAY_FRAME, t0, &mut out);
            }
        }
        let mut next_peer = strats.len() as PeerId;
        let at = t0 + after;
        let mut now = t0;
        let mut announced = false;
        let mut asked: Vec<(PeerId, Instant)> = Vec::new();
        loop {
            let mut reconnect: Vec<PeerId> = Vec::new();
            for (h, p) in &out.expired {
                if *h == target && who.get(p).is_some_and(|s| s.0 == S5::ReconnectOnExpiry) {
                    reconnect.push(*p);
                }
            }
            asked.retain(|(p, _)| !out.expired.contains(&(target, *p)));
            for (p, ids) in &out.requests {
                if ids.contains(&target) {
                    if *p == honest {
                        return Some(now - at);
                    }
                    asked.retain(|x| x.0 != *p);
                    asked.push((*p, now));
                    if who[p].0 == S5::Retry {
                        t.lane_dropped(*p, MAX_RELAY_FRAME, now);
                    }
                }
            }
            t.check();
            if (announced && t.len() == 0) || now > t0 + DEADLINE + STEP {
                return None;
            }
            now += STEP;
            out = Actions::default();
            if !announced && now >= at {
                t.announce(target, honest, honest_pref, now, &mut out);
                announced = true;
            }
            let mut fresh = |t: &mut TxTracker,
                             old: PeerId,
                             now: Instant,
                             out: &mut Actions,
                             who: &mut HashMap<PeerId, (S5, bool)>| {
                t.peer_gone(old, now, out);
                let s = who[&old];
                let q = next_peer;
                next_peer += 1;
                who.insert(q, s);
                t.announce(target, q, false, now, out);
                if s.1 {
                    t.answer_size(q, MAX_RELAY_FRAME, now, out);
                }
            };
            for p in reconnect {
                asked.retain(|x| x.0 != p);
                fresh(&mut t, p, now, &mut out, &mut who);
            }
            let due: Vec<(PeerId, S5)> = asked
                .iter()
                .filter_map(|(p, s)| {
                    let to = t.peers.get(p).map_or(REQUEST_TIMEOUT, PeerLoad::timeout);
                    let st = who[p].0;
                    let when = match st {
                        S5::SlotBusy => *s + REQUEST_TIMEOUT,
                        S5::SlowNotFound | S5::SlowBusy | S5::Recycle => *s + to,
                        _ => return None,
                    };
                    (now + STEP >= when).then_some((*p, st))
                })
                .collect();
            for (p, st) in due {
                asked.retain(|x| x.0 != p);
                match st {
                    S5::SlowNotFound => t.not_found(target, p, now, &mut out),
                    S5::SlowBusy | S5::SlotBusy => t.busy(target, p, now, &mut out),
                    S5::Recycle => fresh(&mut t, p, now, &mut out, &mut who),
                    _ => {}
                }
            }
            t.poll(now, &mut out);
        }
    }

    /// RT5-TM2P2P: the single stated bound (docs/p2p.md §7) against random
    /// mixes of every strategy, with and without inflation, k up to the 64
    /// inbound slots, and the honest announcement at a random time in the
    /// first 3 minutes (a later request period: reconnects in its period
    /// tie with it). Reports every case over the bound.
    #[test]
    fn rt5_every_strategy_mix_keeps_the_single_bound() {
        let mut over = Vec::new();
        let mut worst_ratio = 0f64;
        for seed in 0..200u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(0x5_0000 + seed);
            let k = 1 + (rng.next_u64() % 64) as usize;
            let mix: Vec<(S5, bool)> = (0..k)
                .map(|_| {
                    (
                        S5_ALL[(rng.next_u64() % S5_ALL.len() as u64) as usize],
                        rng.next_u64() % 2 == 0,
                    )
                })
                .collect();
            let after = Duration::from_millis(100 + rng.next_u64() % 180_000);
            let w = rt5_wait(&mix, after, false);
            let b = if mix.iter().any(|s| s.1) {
                bound_any(k)
            } else {
                bound(k)
            };
            if let Some(w) = w {
                worst_ratio = worst_ratio.max(w.as_secs_f64() / b.as_secs_f64());
            }
            if !w.is_some_and(|w| w <= b) {
                over.push((seed, k, after, w, b));
            }
        }
        eprintln!(
            "RT5 mixes: {} of 200 over the bound (worst wait / bound {worst_ratio:.2}): {over:?}",
            over.len()
        );
        assert!(over.is_empty());
    }

    /// RT5-TM2P2P: one strategy at a time, k = 8, 32, 64, the honest
    /// announcement right after the attackers' or at the start of a later
    /// request period (the worst case for reconnects that tie with it).
    #[test]
    fn rt5_each_strategy_at_each_period_offset_keeps_the_bound() {
        let mut rows = Vec::new();
        let mut over = Vec::new();
        for s in S5_ALL {
            for inflate in [false, true] {
                for k in [8usize, 32, 64] {
                    for after in [
                        STEP,
                        REQUEST_TIMEOUT + STEP,
                        REQUEST_TIMEOUT * 2 + STEP,
                        REQUEST_TIMEOUT * 3 - STEP,
                    ] {
                        let mut worst = Some(Duration::ZERO);
                        for _ in 0..4 {
                            let w = rt5_wait(&vec![(s, inflate); k], after, false);
                            worst = worst.zip(w).map(|(a, b)| a.max(b));
                        }
                        let b = if inflate { bound_any(k) } else { bound(k) };
                        if !worst.is_some_and(|w| w <= b) {
                            over.push((s, inflate, k, after, worst, b));
                        }
                        rows.push((s, inflate, k, after.as_secs(), worst.map(|w| w.as_secs())));
                    }
                }
            }
        }
        eprintln!("RT5 per strategy (s, inflated, k, after s, worst s): {rows:?}");
        eprintln!("RT5 over the bound: {over:?}");
        assert!(over.is_empty());
    }

    /// RT5 F2, RT-ART5: inflated inbound attackers can fill the 8 places
    /// non-preferred announcers may take, but not the place reserved for
    /// preferred (outbound) ones (`PREFERRED_RESERVE`). An outbound honest
    /// announcer, which ranks first, waits only for a young slot: it is
    /// asked within `2 s + 30 s`, as before RT5 F2 (with the 8-place cap
    /// alone, up to 68 s: RT-ART5 reproduced 67.9 s).
    #[test]
    fn rt5_a_preferred_announcer_against_inflated_attackers() {
        let limit = INBOUND_DELAY + REQUEST_TIMEOUT + STEP * 2;
        let mut worst = Duration::ZERO;
        let mut over = Vec::new();
        for s in S5_ALL {
            for k in [8usize, 16, 64] {
                // Every second of the first 200 (the first request
                // periods and the turnover of the places).
                for after in (1..=200).map(Duration::from_secs) {
                    let w = rt5_wait(&vec![(s, true); k], after, true);
                    if let Some(w) = w {
                        worst = worst.max(w);
                    }
                    if !w.is_some_and(|w| w <= limit) {
                        over.push((s, k, after, w));
                    }
                }
            }
        }
        eprintln!(
            "RT5 F2 preferred honest vs inflated: worst {worst:?}, limit {limit:?}; over: {over:?}"
        );
        assert!(over.is_empty());
    }

    /// RT-ART5 (the reviewer's worst shape for the 8-place cap alone): `k`
    /// inflated inbound attackers; the one asked first answers `NotFound`
    /// at 61.9 s, at the edge of its slot, so that 4 old and 4 young
    /// requests are outstanding when an honest preferred announcer comes at
    /// 62.1 s. It was asked after 67.9 s (the oldest place's expiry); with
    /// the reserved place, within 32 s (here: at once).
    #[test]
    fn rt5_the_worst_shape_for_an_outbound_announcer_keeps_32_s() {
        for k in [8u64, 16, 64] {
            let t0 = Instant::now();
            let target = id(7);
            let honest: PeerId = 1_000_000;
            let at = t0 + Duration::from_millis(62_100);
            let mut t = TxTracker::default();
            let mut out = Actions::default();
            for p in 0..k {
                t.announce(target, p, false, t0, &mut out);
                t.answer_size(p, MAX_RELAY_FRAME, t0, &mut out);
            }
            let mut first: Option<PeerId> = None;
            let mut now = t0;
            let mut got = None;
            let mut announced = false;
            let mut before = 0;
            while now < t0 + Duration::from_secs(400) && got.is_none() {
                for (p, ids) in &out.requests {
                    if ids.contains(&target) {
                        if *p == honest {
                            got = Some(now - at);
                        }
                        first.get_or_insert(*p);
                    }
                }
                t.check();
                now += STEP;
                out = Actions::default();
                if now >= t0 + Duration::from_millis(61_900)
                    && now < t0 + Duration::from_millis(62_000)
                {
                    t.not_found(target, first.expect("an attacker was asked"), now, &mut out);
                }
                if !announced && now >= at {
                    before = t.requests();
                    t.announce(target, honest, true, now, &mut out);
                    announced = true;
                }
                t.poll(now, &mut out);
            }
            eprintln!(
                "RT-ART5 worst shape, k = {k}: {before} outstanding at the honest announcement; \
                 asked after {got:?}"
            );
            if k >= 16 {
                assert_eq!(before, OUTSTANDING_MAX, "the shape: 4 old and 4 young");
            }
            assert!(
                got.is_some_and(|w| w <= REQUEST_TIMEOUT + INBOUND_DELAY),
                "k = {k}: {got:?}"
            );
        }
    }

    /// 16 inflated inbound attackers announce the target at t0; the one
    /// asked first answers `NotFound` at 61.9 s (the worst shape above);
    /// `outbound` inflated, silent outbound attackers announce at
    /// `outbound_at`, and an outbound honest announcer at `after`. Its
    /// wait, and whether every outbound attacker had been asked before it
    /// announced; `None`: the id was dropped.
    fn outbound_attackers_wait(
        outbound: u64,
        outbound_at: Duration,
        after: Duration,
    ) -> Option<(Duration, bool)> {
        let inbound = 16;
        let t0 = Instant::now();
        let target = id(7);
        let honest: PeerId = 1_000_000;
        let at = t0 + after;
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        for p in 0..inbound {
            t.announce(target, p, false, t0, &mut out);
            t.answer_size(p, MAX_RELAY_FRAME, t0, &mut out);
        }
        let attackers: Vec<PeerId> = (inbound..inbound + outbound).collect();
        let mut first: Option<PeerId> = None;
        let mut now = t0;
        let (mut joined, mut announced, mut all_asked) = (false, false, false);
        while now <= t0 + DEADLINE {
            for (p, ids) in &out.requests {
                if ids.contains(&target) {
                    if *p == honest {
                        return Some((now - at, all_asked));
                    }
                    first.get_or_insert(*p);
                }
            }
            t.check();
            if announced && t.len() == 0 {
                return None;
            }
            now += STEP;
            out = Actions::default();
            if now >= t0 + Duration::from_millis(61_900) && now < t0 + Duration::from_millis(62_000)
            {
                if let Some(f) = first {
                    t.not_found(target, f, now, &mut out);
                }
            }
            if !joined && now >= t0 + outbound_at {
                for p in &attackers {
                    t.announce(target, *p, true, now, &mut out);
                    t.answer_size(*p, MAX_RELAY_FRAME, now, &mut out);
                }
                joined = true;
            }
            if !announced && now >= at {
                all_asked = joined && attackers.iter().all(|p| t.is_requested(&target, *p));
                t.announce(target, honest, true, now, &mut out);
                announced = true;
            }
            t.poll(now, &mut out);
        }
        None
    }

    /// RT-ART5: the reserved place is for any preferred announcer, so an
    /// outbound peer that is itself an inflated attacker can hold it. An
    /// outbound honest announcer then waits, as with the 8-place cap alone,
    /// until a young slot and a place are both free: at most 4 of the 9
    /// outstanding requests are young, so the oldest expires within
    /// `T - 30 s`, and a young slot frees within 30 s. With every outbound
    /// attacker already asked, it is asked within `2 s + max(30 s, T - 30
    /// s)` (70 s at the largest answer); each of `m` outbound attackers not
    /// yet asked that ranks ahead of it adds at most `max(30 s, T - 30 s)`.
    /// Measured with 1, 2 and 4 outbound attackers: at most 67.5 s (an
    /// attacker still waiting for a young slot takes the reserved place
    /// just before the honest announcer comes), 37.5 s once all of them
    /// were asked. Outbound peers are the ones this node chose: the attacker must be
    /// among its outbound connections.
    #[test]
    fn rt5_outbound_attackers_can_hold_the_reserved_place() {
        let gap = REQUEST_TIMEOUT.max(longest_timeout() - REQUEST_TIMEOUT);
        let asked_limit = INBOUND_DELAY + gap + STEP * 2;
        let mut rows = Vec::new();
        let mut over = Vec::new();
        for m in [1u64, 2, 4] {
            let limit = INBOUND_DELAY + gap * (m as u32 + 1) + STEP * 2;
            for outbound_at in [1u64, 31, 62, 63, 92, 120].map(Duration::from_secs) {
                let (mut worst, mut worst_asked) = (Duration::ZERO, Duration::ZERO);
                // Every half second for 200 s from the attackers' arrival.
                for half in 1..=400u64 {
                    let after = outbound_at + Duration::from_millis(500 * half);
                    let w = outbound_attackers_wait(m, outbound_at, after);
                    match w {
                        Some((w, all_asked)) => {
                            worst = worst.max(w);
                            if all_asked {
                                worst_asked = worst_asked.max(w);
                                if w > asked_limit {
                                    over.push((m, outbound_at, after, w, asked_limit));
                                }
                            }
                            if w > limit {
                                over.push((m, outbound_at, after, w, limit));
                            }
                        }
                        None => over.push((m, outbound_at, after, Duration::MAX, limit)),
                    }
                }
                // Measured, not proven for m > 1: the fallback stays
                // within 2 s + max(30 s, T - 30 s) (67.5 s at most here).
                if worst > asked_limit {
                    over.push((m, outbound_at, Duration::ZERO, worst, asked_limit));
                }
                rows.push((m, outbound_at.as_secs(), worst, worst_asked));
            }
        }
        eprintln!(
            "RT-ART5 outbound attackers (m, attackers at s, worst, worst once all were asked): \
             {rows:?}; limits {asked_limit:?} once asked, 2 s + (m + 1) x {gap:?}; over: {over:?}"
        );
        assert!(over.is_empty());
    }

    /// RT5-TM2P2P F1: a peer's late-answer memory was a FIFO of 160, sized
    /// as if its requests ended no faster than one per slot per 30 s
    /// (16 x 300 s / 30 s). A request ended by another announcer's answer
    /// (`forget_tx`) freed its slot at once, so with the peer's room
    /// refilled from its waiting ids, 161 such endings in one instant
    /// pushed out the first, and that peer's answer to it (still on its
    /// way) was an unrequested `Tx` (+10). Now an early ending keeps its
    /// slot until the peer's answer (which takes the entry) or the
    /// request's expiry, so the memory is a bound ([`LATE_PER_PEER`]):
    /// every request to an honest peer ends at once, for ten minutes, its
    /// answers coming 1 s or 200 s later, and every answer is accepted,
    /// with nothing pushed out (`check`).
    #[test]
    fn rt5_fast_endings_push_a_peers_late_answers_out() {
        for delay in [Duration::from_secs(1), Duration::from_secs(200)] {
            let t0 = Instant::now();
            let mut t = TxTracker::default();
            let h: PeerId = 1;
            t.register_peer(h, 0);
            let mut out = Actions::default();
            t.answer_size(h, 1_000, t0, &mut out);
            let mut next = 0u64;
            let mut now = t0;
            let mut answers: VecDeque<(Instant, Hash)> = VecDeque::new();
            let (mut ended, mut accepted, mut most_in_one_instant) = (0usize, 0usize, 0usize);
            while now < t0 + Duration::from_secs(600) {
                let mut out = Actions::default();
                // The peer keeps announcing (up to its tracked ids).
                for _ in 0..50 {
                    t.announce(id(next), h, true, now, &mut out);
                    next += 1;
                }
                // Its answers that are due arrive: each one accepted.
                while answers.front().is_some_and(|(at, _)| *at <= now) {
                    let Some((_, x)) = answers.pop_front() else {
                        break;
                    };
                    assert!(
                        t.take_late(&x, h, now),
                        "{delay:?}: an honest late answer refused"
                    );
                    accepted += 1;
                }
                t.poll(now, &mut out);
                // Each id asked of it arrives from someone else at once.
                let asked: Vec<Hash> = out
                    .requests
                    .iter()
                    .filter(|(p, _)| *p == h)
                    .flat_map(|(_, ids)| ids.iter().copied())
                    .collect();
                most_in_one_instant = most_in_one_instant.max(asked.len());
                for x in asked {
                    assert_eq!(t.forget_requested(&x, None, now), vec![h]);
                    answers.push_back((now + delay, x));
                    ended += 1;
                }
                t.check();
                now += Duration::from_millis(250);
            }
            eprintln!(
                "RT5 late memory ({delay:?} answers): {ended} requests to one peer ended early in \
                 10 min, at most {most_in_one_instant} in one instant; {accepted} answers, all \
                 accepted; memory {} of {LATE_PER_PEER}",
                t.peers[&h].late.len()
            );
            assert!(ended > LATE_PER_PEER, "{ended}");
            assert!(most_in_one_instant <= PEER_IN_FLIGHT);
            assert!(accepted + answers.len() == ended);
        }
    }

    /// RT5-TM2P2P F2: since only young requests hold the id's slots, a
    /// large transaction whose honest announcers' answers are slow (a
    /// congested or Tor link; their expected size a PX answer) was asked of
    /// up to 4 more announcers every 30 s while the older requests stayed
    /// outstanding: 12 copies in flight at once for one id (4 before RT4).
    /// Now at most `OUTSTANDING_MAX` (8) are outstanding at once.
    #[test]
    fn rt5_copies_in_flight_for_one_slow_large_id() {
        let t0 = Instant::now();
        let mut t = TxTracker::default();
        let mut out = Actions::default();
        let px = 2_200_000;
        for p in 0..20 as PeerId {
            t.register_peer(p, 0);
            t.answer_size(p, px, t0, &mut out);
        }
        for p in 0..20 as PeerId {
            t.announce(id(1), p, p < 4, t0, &mut out);
        }
        let mut now = t0;
        let mut most = 0;
        let mut at = Vec::new();
        let mut total = 0;
        while now < t0 + Duration::from_secs(150) {
            let mut out = Actions::default();
            t.poll(now, &mut out);
            total += out.requests.iter().map(|(_, v)| v.len()).sum::<usize>();
            let n = t.requests();
            if n > most {
                most = n;
                at.push(((now - t0).as_secs(), n));
            }
            now += STEP;
        }
        eprintln!(
            "RT5 slow PX id: at most {most} requests outstanding at once, {total} sent in 150 s \
             (timeout {:?}); growth (s, n): {at:?}",
            t.peers[&0].timeout()
        );
        // RT5 F2: at most `OUTSTANDING_MAX` (8) at once for the inbound
        // announcers, one more for an outbound one; 12 before.
        assert!(most <= OUTSTANDING_MAX + PREFERRED_RESERVE, "{most}");
    }

    /// RT-ART5: peak copies of one slow PX-sized id with `npref` slow
    /// outbound and 20 slow inbound announcers, all at once or the outbound
    /// ones coming one by one: never more than 9.
    #[test]
    fn rt5_copies_in_flight_never_exceed_nine() {
        let mut rows = Vec::new();
        for npref in [0u64, 1, 4, 8, 9, 12] {
            for staggered in [false, true] {
                let t0 = Instant::now();
                let mut t = TxTracker::default();
                let mut out = Actions::default();
                let n = 20 + npref;
                for p in 0..n {
                    t.register_peer(p, 0);
                    t.answer_size(p, 2_200_000, t0, &mut out);
                }
                for p in 0..20 {
                    t.announce(id(1), p, false, t0, &mut out);
                }
                let mut next = 20;
                let mut now = t0;
                let mut most = 0;
                while now < t0 + Duration::from_secs(300) {
                    let mut out = Actions::default();
                    while next < n
                        && (!staggered || now >= t0 + Duration::from_secs(10 * (next - 20)))
                    {
                        t.announce(id(1), next, true, now, &mut out);
                        next += 1;
                    }
                    t.poll(now, &mut out);
                    most = most.max(t.requests());
                    t.check();
                    now += STEP;
                }
                rows.push((npref, staggered, most));
                assert!(
                    most <= OUTSTANDING_MAX + PREFERRED_RESERVE,
                    "{npref}: {most}"
                );
            }
        }
        eprintln!("RT-ART5 copies (outbound, staggered, peak): {rows:?}");
    }
}
