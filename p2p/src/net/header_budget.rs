//! Header proof-of-work scheduling and budgets (docs/p2p.md §6, "Header
//! proof-of-work budget"; R8-8, RT-HDRDOS).
//!
//! One RandomX light-mode hash costs this node about 0.5 s of CPU, while a
//! header with junk proof of work costs its sender nothing. Bans are per IP
//! (an IPv6 /64), and onion inbound peers cannot be banned at all, so a
//! sender rotating identities could keep the single header worker hashing
//! junk. Two measures bound that, without any consensus change:
//!
//! 1. **Three tiers** ([`HeaderScheduler`]): outbound peers' batches (we
//!    chose them) are always verified first; then batches of inbound peers
//!    that delivered a *live* new tip with valid proof of work
//!    (`Peer::pow_proven`); then every other inbound batch. The untrusted
//!    batches wait per network class (IPv4, IPv6, onion); the classes take
//!    turns, and within a class the next batch is drawn at random among the
//!    waiting ones, so an honest peer's batch is not stuck behind a queue of
//!    junk that is always refilled.
//! 2. **A budget per class** ([`PowBudget`]): an untrusted batch is taken up
//!    only while its class's token bucket holds a token. Each header hashed
//!    for it is charged one token, and refunded once its proof of work turns
//!    out valid, so only *failed* hashes stay charged: honest peers spend
//!    nothing. A class can cause at most `burst + rate × t` failed hashes
//!    (plus one chunk of overdraft), however many identities send them.
//!    There is no node-wide bucket: one class's flood (onion identities are
//!    free) never spends another class's share. Waiting batches are kept,
//!    not dropped, and taken up when a token frees.
//!
//! Bitcoin Core checks a header's proof of work before anything else
//! because its PoW is one SHA-256d; its anti-DoS work threshold protects
//! memory, not CPU (PR #25717). Monero verifies announced blocks on receipt
//! without a rate limit and relies on IP bans, which do not reach anonymous
//! inbound peers. Neither pays ~0.5 s per verification; hence this module.

use super::state::{HeaderBatch, Peer};
use super::trickle::NetClass;
use crate::limits::TokenBucket;
use rand_chacha::rand_core::RngCore;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Which queue a header batch waits in, and which budget pays for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeaderLane {
    /// An outbound peer: first, never budgeted.
    Outbound,
    /// An inbound peer that delivered a live new tip with valid proof of
    /// work (`Peer::pow_proven`): after outbound peers, never budgeted.
    Proven,
    /// Any other inbound peer, by the network it reached us through.
    Inbound(NetClass),
}

impl HeaderLane {
    /// The lane of `p`'s batches. An inbound peer always has its trickle
    /// key; without one it would count as onion, the strictest class.
    pub(super) fn of(p: &Peer) -> Self {
        if !p.inbound {
            HeaderLane::Outbound
        } else if p.pow_proven {
            HeaderLane::Proven
        } else {
            HeaderLane::Inbound(p.trickle.map_or(NetClass::Onion, |k| k.class()))
        }
    }

    pub(super) fn untrusted(self) -> bool {
        matches!(self, HeaderLane::Inbound(_))
    }
}

const CLASSES: usize = 3;

fn class_index(c: NetClass) -> usize {
    match c {
        NetClass::Ipv4 => 0,
        NetClass::Ipv6 => 1,
        NetClass::Onion => 2,
    }
}

/// The budget of proof-of-work hashes for untrusted inbound senders, per
/// network class (`NetConfig::header_pow_budget`). The rate is in hashes
/// per second.
#[derive(Clone, Debug, PartialEq)]
pub struct HeaderPowBudget {
    /// At most `class_burst` failed hashes at once per class, refilled at
    /// `class_rate`.
    pub class_burst: f64,
    pub class_rate: f64,
}

impl Default for HeaderPowBudget {
    /// Per class: 3 hashes, one more every 45 s. With three classes, junk
    /// headers cost this node at most 9 hashes at once and one every 15 s in
    /// the long run (~3.5 % of one core at ~0.5 s per light-mode hash),
    /// however many identities send them.
    fn default() -> Self {
        Self {
            class_burst: 3.0,
            class_rate: 1.0 / 45.0,
        }
    }
}

impl HeaderPowBudget {
    /// No limit (tests that measure the unbudgeted cost).
    pub fn unlimited() -> Self {
        Self {
            class_burst: f64::MAX,
            class_rate: 0.0,
        }
    }

    /// The bound on failed hashes one class can cause over `t`: `burst +
    /// rate × t`, plus one chunk of overdraft. The node-wide bound is three
    /// times this.
    pub fn class_bound(&self, t: Duration, chunk: usize) -> f64 {
        self.class_burst + self.class_rate * t.as_secs_f64() + chunk as f64
    }
}

/// The token buckets of [`HeaderPowBudget`], and counters for `NetStats`.
#[derive(Debug)]
pub(super) struct PowBudget {
    classes: [TokenBucket; CLASSES],
    /// Hashes charged and not refunded (failed proof of work).
    pub(super) failed: u64,
    /// Untrusted batches that had to wait for a token, or were cut off
    /// between two chunks.
    pub(super) throttled: u64,
}

impl PowBudget {
    pub(super) fn new(cfg: &HeaderPowBudget) -> Self {
        let class = || TokenBucket::new(cfg.class_rate, cfg.class_burst);
        Self {
            classes: [class(), class(), class()],
            failed: 0,
            throttled: 0,
        }
    }

    /// Whether an untrusted batch of class `c` may be taken up now.
    fn ready(&mut self, c: usize, now: Instant) -> bool {
        self.classes[c].has(1.0, now)
    }

    /// Charges `n` hashes to `lane` (nothing for a trusted lane): allowed if
    /// its class's bucket holds at least one token. The whole `n` is then
    /// taken, possibly into debt (a chunk's size is known only when it is
    /// hashed). `false`: nothing is taken, and the rest of the batch is not
    /// hashed now.
    pub(super) fn charge(&mut self, lane: HeaderLane, n: usize, now: Instant) -> bool {
        let HeaderLane::Inbound(c) = lane else {
            return true;
        };
        let class = &mut self.classes[class_index(c)];
        if !class.has(1.0, now) {
            self.throttled += 1;
            return false;
        }
        class.debit(n as f64, now);
        self.failed += n as u64;
        true
    }

    /// Refunds `n` hashes charged to `lane` whose proof of work was valid.
    pub(super) fn refund(&mut self, lane: HeaderLane, n: usize, now: Instant) {
        let HeaderLane::Inbound(c) = lane else {
            return;
        };
        self.classes[class_index(c)].credit(n as f64, now);
        self.failed = self.failed.saturating_sub(n as u64);
    }
}

/// The header worker's queues ([`HeaderLane`]): outbound, then proven, then
/// the untrusted classes in turn, each only while it has a token.
#[derive(Default)]
pub(super) struct HeaderScheduler {
    outbound: VecDeque<HeaderBatch>,
    proven: VecDeque<HeaderBatch>,
    /// Untrusted batches whose senders left while they waited: only
    /// pre-checked (no hash, so no token), so that a rule-breaking sender is
    /// still banned (`verify_headers`).
    departed: VecDeque<HeaderBatch>,
    /// Untrusted batches waiting, per class (taken in random order).
    inbound: [Vec<HeaderBatch>; CLASSES],
    /// The class whose turn is next.
    next: usize,
}

impl HeaderScheduler {
    /// Queues `b`; an untrusted batch whose class has no token now is
    /// counted as throttled (it waits).
    pub(super) fn push(&mut self, b: HeaderBatch, budget: &mut PowBudget, now: Instant) {
        match b.lane {
            HeaderLane::Outbound => self.outbound.push_back(b),
            HeaderLane::Proven => self.proven.push_back(b),
            HeaderLane::Inbound(c) => {
                let i = class_index(c);
                if !budget.ready(i, now) {
                    budget.throttled += 1;
                }
                self.inbound[i].push(b);
            }
        }
    }

    /// The next batch to verify: outbound first, then proven, then an
    /// untrusted class with a token (in turn), a random batch of it.
    pub(super) fn pop(
        &mut self,
        budget: &mut PowBudget,
        now: Instant,
        rng: &mut impl RngCore,
    ) -> Option<HeaderBatch> {
        if let Some(b) = self.outbound.pop_front() {
            return Some(b);
        }
        if let Some(b) = self.proven.pop_front() {
            return Some(b);
        }
        if let Some(b) = self.departed.pop_front() {
            return Some(b);
        }
        for k in 0..CLASSES {
            let i = (self.next + k) % CLASSES;
            let waiting = &mut self.inbound[i];
            if !waiting.is_empty() && budget.ready(i, now) {
                self.next = (i + 1) % CLASSES;
                let pick = (rng.next_u64() % waiting.len() as u64) as usize;
                return Some(waiting.swap_remove(pick));
            }
        }
        None
    }

    /// How long until an untrusted batch waiting now may be taken up
    /// (`None`: nothing waits, or nothing ever will be).
    pub(super) fn next_ready(&self, budget: &mut PowBudget, now: Instant) -> Option<Duration> {
        (0..CLASSES)
            .filter(|&i| !self.inbound[i].is_empty())
            .filter_map(|i| budget.classes[i].wait_for(1.0, now))
            .min()
    }

    /// Moves the waiting untrusted batches for which `gone` holds (their
    /// senders left) to the departed queue: they are only pre-checked, need
    /// no token, and go right after the trusted ones.
    pub(super) fn release_departed(&mut self, mut gone: impl FnMut(&HeaderBatch) -> bool) {
        for waiting in &mut self.inbound {
            let mut i = 0;
            while i < waiting.len() {
                if gone(&waiting[i]) {
                    self.departed.push_back(waiting.swap_remove(i));
                } else {
                    i += 1;
                }
            }
        }
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.outbound.is_empty()
            && self.proven.is_empty()
            && self.departed.is_empty()
            && self.inbound.iter().all(Vec::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn batch(peer: u64, lane: HeaderLane) -> HeaderBatch {
        HeaderBatch {
            peer,
            addr: NetAddr::parse("1.2.3.4:5").unwrap(),
            proxied: false,
            solicited: false,
            lane,
            headers: Vec::new(),
        }
    }

    const ONION: HeaderLane = HeaderLane::Inbound(NetClass::Onion);
    const V4: HeaderLane = HeaderLane::Inbound(NetClass::Ipv4);
    const V6: HeaderLane = HeaderLane::Inbound(NetClass::Ipv6);

    fn plenty() -> PowBudget {
        PowBudget::new(&HeaderPowBudget::unlimited())
    }

    /// Outbound batches go first, then proven ones, then the untrusted
    /// classes in turn; a proven backlog never delays an outbound batch.
    #[test]
    fn outbound_then_proven_then_classes_in_turn() {
        let (mut s, mut b, now) = (HeaderScheduler::default(), plenty(), Instant::now());
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        for p in 1..=3 {
            s.push(batch(p, ONION), &mut b, now);
        }
        s.push(batch(10, V4), &mut b, now);
        for p in 40..=44 {
            s.push(batch(p, HeaderLane::Proven), &mut b, now);
        }
        s.push(batch(20, HeaderLane::Outbound), &mut b, now);
        let order: Vec<u64> = std::iter::from_fn(|| s.pop(&mut b, now, &mut rng))
            .map(|b| b.peer)
            .collect();
        assert_eq!(&order[..6], [20, 40, 41, 42, 43, 44]);
        assert_eq!(order[6], 10, "IPv4's turn first");
        let mut onion: Vec<u64> = order[7..].to_vec();
        onion.sort();
        assert_eq!(onion, [1, 2, 3]);
        assert!(s.is_empty());
        // Stockpiled proven identities: an outbound batch arriving behind
        // them is next.
        for p in 50..=99 {
            s.push(batch(p, HeaderLane::Proven), &mut b, now);
        }
        assert_eq!(s.pop(&mut b, now, &mut rng).unwrap().peer, 50);
        s.push(batch(30, HeaderLane::Outbound), &mut b, now);
        assert_eq!(s.pop(&mut b, now, &mut rng).unwrap().peer, 30);
    }

    /// Within a class the next batch is random among the waiting ones: an
    /// honest batch among 9 junk ones is drawn first about 1 time in 10, not
    /// last every time as in a FIFO the junk refills.
    #[test]
    fn a_class_draws_its_waiting_batches_at_random() {
        let now = Instant::now();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let mut first = 0;
        for _ in 0..2000 {
            let (mut s, mut b) = (HeaderScheduler::default(), plenty());
            for p in 1..=9 {
                s.push(batch(p, V4), &mut b, now);
            }
            s.push(batch(100, V4), &mut b, now);
            if s.pop(&mut b, now, &mut rng).unwrap().peer == 100 {
                first += 1;
            }
        }
        assert!((150..250).contains(&first), "{first} of 2000");
    }

    /// An untrusted class without a token waits (kept, not dropped) and is
    /// taken up once its bucket refills; another class is not held back.
    #[test]
    fn a_class_without_a_token_waits_and_others_go_on() {
        let cfg = HeaderPowBudget {
            class_burst: 1.0,
            class_rate: 1.0,
        };
        let t0 = Instant::now();
        let mut b = PowBudget::new(&cfg);
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut s = HeaderScheduler::default();
        assert!(b.charge(ONION, 1, t0), "the onion token is spent");
        s.push(batch(1, ONION), &mut b, t0);
        s.push(batch(2, V6), &mut b, t0);
        assert_eq!(b.throttled, 1, "the onion batch waits");
        assert_eq!(s.pop(&mut b, t0, &mut rng).unwrap().peer, 2);
        assert!(s.pop(&mut b, t0, &mut rng).is_none(), "onion has no token");
        let wait = s.next_ready(&mut b, t0).unwrap();
        assert!(wait > Duration::from_millis(900) && wait <= Duration::from_secs(1));
        assert_eq!(s.pop(&mut b, t0 + wait, &mut rng).unwrap().peer, 1);
        assert!(s.next_ready(&mut b, t0).is_none(), "nothing waits");
    }

    /// Failed hashes stay charged; valid ones are refunded. An empty class
    /// refuses (and takes nothing); classes are independent; trusted lanes
    /// are never charged. A chunk may overdraw once.
    #[test]
    fn the_budget_charges_failures_only_per_class() {
        let cfg = HeaderPowBudget {
            class_burst: 2.0,
            class_rate: 0.0,
        };
        let now = Instant::now();
        let mut b = PowBudget::new(&cfg);
        for _ in 0..100 {
            assert!(b.charge(ONION, 1, now));
            b.refund(ONION, 1, now);
        }
        assert_eq!(b.failed, 0);
        assert!(b.charge(ONION, 1, now));
        assert!(b.charge(ONION, 1, now));
        assert!(!b.charge(ONION, 1, now), "onion class empty");
        assert_eq!((b.failed, b.throttled), (2, 1));
        // Other classes keep their whole share (no node-wide bucket).
        assert!(b.charge(V4, 1, now) && b.charge(V4, 1, now));
        assert!(b.charge(V6, 1, now) && b.charge(V6, 1, now));
        assert!(b.charge(HeaderLane::Outbound, 64, now));
        assert!(b.charge(HeaderLane::Proven, 64, now));
        assert_eq!(b.failed, 6);
        let mut b = PowBudget::new(&cfg);
        assert!(b.charge(V6, 8, now));
        assert!(!b.charge(V6, 1, now), "in debt");
        b.refund(V6, 8, now);
        assert!(b.charge(V6, 1, now), "refunded");
    }

    #[test]
    fn the_budget_refills_and_bounds() {
        let cfg = HeaderPowBudget {
            class_burst: 1.0,
            class_rate: 1.0,
        };
        let t0 = Instant::now();
        let mut b = PowBudget::new(&cfg);
        assert!(b.charge(ONION, 1, t0));
        assert!(!b.charge(ONION, 1, t0 + Duration::from_millis(500)));
        assert!(b.charge(ONION, 1, t0 + Duration::from_millis(1001)));
        let d = HeaderPowBudget::default();
        assert!((d.class_bound(Duration::from_secs(450), 1) - 14.0).abs() < 1e-9);
    }

    /// Batches of senders that left while they waited are released without
    /// a token (they are only pre-checked), after the trusted ones.
    #[test]
    fn departed_untrusted_batches_are_released_without_a_token() {
        let cfg = HeaderPowBudget {
            class_burst: 1.0,
            class_rate: 0.0,
        };
        let now = Instant::now();
        let mut b = PowBudget::new(&cfg);
        assert!(
            b.charge(V4, 1, now) && b.charge(ONION, 1, now),
            "no tokens left"
        );
        let mut s = HeaderScheduler::default();
        for p in 1..=6 {
            s.push(batch(p, if p % 2 == 0 { V4 } else { ONION }), &mut b, now);
        }
        s.push(batch(9, HeaderLane::Outbound), &mut b, now);
        s.release_departed(|b| b.peer > 3);
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        assert_eq!(s.pop(&mut b, now, &mut rng).unwrap().peer, 9);
        let mut gone: Vec<u64> = std::iter::from_fn(|| s.pop(&mut b, now, &mut rng))
            .map(|b| b.peer)
            .collect();
        gone.sort();
        assert_eq!(gone, [4, 5, 6], "the others still wait for a token");
        assert!(!s.is_empty());
    }
}
