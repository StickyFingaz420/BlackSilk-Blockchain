//! Header proof-of-work scheduling and budgets (docs/p2p.md §6, "Header
//! proof-of-work budget"; R8-8).
//!
//! One RandomX light-mode hash costs this node about 0.5 s of CPU, while a
//! header with junk proof of work costs its sender nothing. Bans are per IP
//! (an IPv6 /64), and onion inbound peers cannot be banned at all, so a
//! sender rotating identities could keep the single header worker hashing
//! junk. Two measures bound that, without any consensus change:
//!
//! 1. **Priority** ([`HeaderScheduler`]): batches of *trusted* senders,
//!    outbound peers (we chose them) and inbound peers that already
//!    delivered new headers with valid proof of work (`Peer::pow_proven`),
//!    are always verified before any other batch. Other inbound batches take
//!    turns by network class (IPv4, IPv6, onion), FIFO within a class, so a
//!    flood through one class does not delay another class's batches more
//!    than one batch at a time.
//! 2. **Budget** ([`PowBudget`]): a header hashed for an untrusted inbound
//!    sender is charged one token to its class's bucket and one to the
//!    node-wide bucket of untrusted hashing, and refunded once its proof of
//!    work turns out valid. Only *failed* hashes stay charged, so honest
//!    peers spend nothing, and the hashing an attacker can cause for free
//!    is at most `burst + rate × t` hashes node-wide (plus one chunk of
//!    overdraft), however many identities it uses. While a bucket is empty,
//!    untrusted batches that would need hashing are dropped unhashed and
//!    unpenalized (`HeaderOutcome::Throttled`); the same headers still come
//!    from trusted peers.
//!
//! Bitcoin Core checks a header's proof of work before anything else
//! because its PoW is one SHA-256d; its anti-DoS work threshold protects
//! memory, not CPU (PR #25717). Monero verifies announced blocks on receipt
//! without a rate limit and relies on IP bans, which do not reach anonymous
//! inbound peers. Neither pays ~0.5 s per verification; hence this module.

use super::state::HeaderBatch;
use super::trickle::NetClass;
use crate::limits::TokenBucket;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Which queue a header batch waits in, and which budget pays for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum HeaderLane {
    /// An outbound peer, or an inbound peer that already delivered new
    /// headers with valid proof of work: first in line, never budgeted.
    Trusted,
    /// Any other inbound peer, by the network it reached us through.
    Inbound(NetClass),
}

const CLASSES: [NetClass; 3] = [NetClass::Ipv4, NetClass::Ipv6, NetClass::Onion];

fn class_index(c: NetClass) -> usize {
    match c {
        NetClass::Ipv4 => 0,
        NetClass::Ipv6 => 1,
        NetClass::Onion => 2,
    }
}

/// The budget of proof-of-work hashes for untrusted inbound senders
/// (`NetConfig::header_pow_budget`). Rates are in hashes per second.
#[derive(Clone, Debug, PartialEq)]
pub struct HeaderPowBudget {
    /// Per network class (IPv4, IPv6, onion): at most `class_burst` failed
    /// hashes at once, refilled at `class_rate`.
    pub class_burst: f64,
    pub class_rate: f64,
    /// For all untrusted inbound senders together.
    pub global_burst: f64,
    pub global_rate: f64,
}

impl Default for HeaderPowBudget {
    /// Per class: 4 hashes, one more every 30 s; node-wide: 8 hashes, one
    /// more every 15 s. At ~0.5 s per light-mode hash, junk headers cost
    /// this node at most ~3.5 % of one core in the long run (plus a burst of
    /// 8 hashes), however many identities send them.
    fn default() -> Self {
        Self {
            class_burst: 4.0,
            class_rate: 1.0 / 30.0,
            global_burst: 8.0,
            global_rate: 1.0 / 15.0,
        }
    }
}

impl HeaderPowBudget {
    /// No limit (tests that measure the unbudgeted cost).
    pub fn unlimited() -> Self {
        Self {
            class_burst: f64::MAX,
            class_rate: 0.0,
            global_burst: f64::MAX,
            global_rate: 0.0,
        }
    }

    /// The long-run bound on budgeted hashes over `t`: what the global
    /// bucket allows (`burst + rate × t`), plus one chunk of overdraft.
    pub fn bound(&self, t: Duration, chunk: usize) -> f64 {
        self.global_burst + self.global_rate * t.as_secs_f64() + chunk as f64
    }
}

/// The token buckets of [`HeaderPowBudget`], and counters for `NetStats`.
#[derive(Debug)]
pub(super) struct PowBudget {
    classes: [TokenBucket; 3],
    global: TokenBucket,
    /// Hashes charged and not refunded (failed proof of work).
    pub(super) failed: u64,
    /// Batches dropped unhashed because a bucket was empty.
    pub(super) throttled: u64,
}

impl PowBudget {
    pub(super) fn new(cfg: &HeaderPowBudget) -> Self {
        let class = || TokenBucket::new(cfg.class_rate, cfg.class_burst);
        Self {
            classes: [class(), class(), class()],
            global: TokenBucket::new(cfg.global_rate, cfg.global_burst),
            failed: 0,
            throttled: 0,
        }
    }

    /// Charges `n` hashes to `lane` (nothing for a trusted lane): allowed if
    /// both its class's bucket and the node-wide one hold at least one token.
    /// The whole `n` is then taken from both, possibly into debt (a chunk's
    /// size is known only when it is hashed). `false`: nothing is taken, and
    /// the batch is to be dropped unhashed.
    pub(super) fn charge(&mut self, lane: HeaderLane, n: usize, now: Instant) -> bool {
        let HeaderLane::Inbound(c) = lane else {
            return true;
        };
        let class = &mut self.classes[class_index(c)];
        if !(class.has(1.0, now) && self.global.has(1.0, now)) {
            self.throttled += 1;
            return false;
        }
        class.debit(n as f64, now);
        self.global.debit(n as f64, now);
        self.failed += n as u64;
        true
    }

    /// Refunds `n` hashes charged to `lane` whose proof of work was valid.
    pub(super) fn refund(&mut self, lane: HeaderLane, n: usize, now: Instant) {
        let HeaderLane::Inbound(c) = lane else {
            return;
        };
        self.classes[class_index(c)].credit(n as f64, now);
        self.global.credit(n as f64, now);
        self.failed = self.failed.saturating_sub(n as u64);
    }
}

/// The header worker's queues ([`HeaderLane`]): trusted batches first, then
/// the untrusted classes in turn.
#[derive(Default)]
pub(super) struct HeaderScheduler {
    trusted: VecDeque<HeaderBatch>,
    inbound: [VecDeque<HeaderBatch>; 3],
    /// The class whose turn is next.
    next: usize,
}

impl HeaderScheduler {
    pub(super) fn push(&mut self, b: HeaderBatch) {
        match b.lane {
            HeaderLane::Trusted => self.trusted.push_back(b),
            HeaderLane::Inbound(c) => self.inbound[class_index(c)].push_back(b),
        }
    }

    /// The next batch to verify.
    pub(super) fn pop(&mut self) -> Option<HeaderBatch> {
        if let Some(b) = self.trusted.pop_front() {
            return Some(b);
        }
        for k in 0..CLASSES.len() {
            let i = (self.next + k) % CLASSES.len();
            if let Some(b) = self.inbound[i].pop_front() {
                self.next = (i + 1) % CLASSES.len();
                return Some(b);
            }
        }
        None
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.trusted.is_empty() && self.inbound.iter().all(VecDeque::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;

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

    /// Trusted batches go first; untrusted classes take turns, FIFO within
    /// a class: a flood in one class waits behind one batch of each other.
    #[test]
    fn trusted_first_then_classes_in_turn() {
        let mut s = HeaderScheduler::default();
        let onion = HeaderLane::Inbound(NetClass::Onion);
        let v4 = HeaderLane::Inbound(NetClass::Ipv4);
        for p in 1..=5 {
            s.push(batch(p, onion));
        }
        s.push(batch(10, v4));
        s.push(batch(11, v4));
        s.push(batch(20, HeaderLane::Trusted));
        let order: Vec<u64> = std::iter::from_fn(|| s.pop()).map(|b| b.peer).collect();
        assert_eq!(order, [20, 10, 1, 11, 2, 3, 4, 5]);
        assert!(s.is_empty());
        // A trusted batch arriving behind a flood is next.
        for p in 1..=3 {
            s.push(batch(p, onion));
        }
        assert_eq!(s.pop().unwrap().peer, 1);
        s.push(batch(30, HeaderLane::Trusted));
        assert_eq!(s.pop().unwrap().peer, 30);
    }

    /// Failed hashes stay charged; valid ones are refunded. An empty class
    /// or global bucket refuses (and takes nothing); trusted lanes are never
    /// charged. A chunk may overdraw once.
    #[test]
    fn the_budget_charges_failures_only() {
        let cfg = HeaderPowBudget {
            class_burst: 2.0,
            class_rate: 0.0,
            global_burst: 3.0,
            global_rate: 0.0,
        };
        let now = Instant::now();
        let mut b = PowBudget::new(&cfg);
        let (onion, v4, v6) = (
            HeaderLane::Inbound(NetClass::Onion),
            HeaderLane::Inbound(NetClass::Ipv4),
            HeaderLane::Inbound(NetClass::Ipv6),
        );
        // Honest: charged and refunded, any number of times.
        for _ in 0..100 {
            assert!(b.charge(onion, 1, now));
            b.refund(onion, 1, now);
        }
        assert_eq!(b.failed, 0);
        // Junk: the class bucket (2) runs out first.
        assert!(b.charge(onion, 1, now));
        assert!(b.charge(onion, 1, now));
        assert!(!b.charge(onion, 1, now), "onion class empty");
        assert_eq!((b.failed, b.throttled), (2, 1));
        // Another class still has its own, until the global bucket (3) is
        // empty: one more hash.
        assert!(b.charge(v4, 1, now));
        assert!(!b.charge(v4, 1, now), "global empty");
        assert!(!b.charge(v6, 1, now), "global empty");
        assert!(b.charge(HeaderLane::Trusted, 64, now), "never charged");
        assert_eq!(b.failed, 3);
        // An overdraft: a chunk of 8 on one token leaves a debt of 7.
        let mut b = PowBudget::new(&cfg);
        assert!(b.charge(v6, 8, now));
        assert!(!b.charge(v6, 1, now));
        assert!(!b.charge(v4, 1, now), "the global bucket is in debt too");
        b.refund(v6, 8, now);
        assert!(b.charge(v4, 1, now), "refunded");
    }

    /// The bucket refills at its rate.
    #[test]
    fn the_budget_refills() {
        let cfg = HeaderPowBudget {
            class_burst: 1.0,
            class_rate: 1.0,
            global_burst: 1.0,
            global_rate: 1.0,
        };
        let t0 = Instant::now();
        let mut b = PowBudget::new(&cfg);
        let onion = HeaderLane::Inbound(NetClass::Onion);
        assert!(b.charge(onion, 1, t0));
        assert!(!b.charge(onion, 1, t0 + Duration::from_millis(500)));
        assert!(b.charge(onion, 1, t0 + Duration::from_millis(1001)));
        let d = HeaderPowBudget::default();
        assert!((d.bound(Duration::from_secs(150), 1) - 19.0).abs() < 1e-9);
    }
}
