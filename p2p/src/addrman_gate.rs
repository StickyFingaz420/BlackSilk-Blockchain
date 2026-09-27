//! Per-peer admission of received addresses (docs/p2p.md §9): what a peer may
//! put into the address table, and which received addresses are fresh
//! enough to relay. Pure policy (no I/O, time passed in), used by the network
//! and by the eclipse simulator (`p2p/tests/eclipse_sim.rs`).
//!
//! - **Solicited answers.** After the node sends `GetAddr`, the peer may
//!   answer with up to [`MAX_ADDRS`] addresses in total, within
//!   [`ANSWER_WINDOW`]; the answer ends with its first message of more than
//!   [`MAX_UNSOLICITED`] entries. Answers are stored, never relayed.
//! - **Unsolicited batches** of more than [`MAX_UNSOLICITED`] entries are
//!   dropped whole and the sender is penalized (Heilman et al., "Eclipse
//!   Attacks on Bitcoin's Peer-to-Peer Network", countermeasure 8).
//! - **Unsolicited small messages** are rate limited per address: a token
//!   bucket of [`ADDR_RATE`] per second, at most [`ADDR_BURST`], starting with
//!   one token (Bitcoin Core PR #22387). Excess addresses are dropped, not
//!   penalized: an honest relayer cannot know how much its peer accepts.

use crate::message::MAX_ADDRS;
use std::time::{Duration, Instant};

/// The most entries an unsolicited `Addr` may have.
pub const MAX_UNSOLICITED: usize = 10;
/// Unsolicited addresses a peer may have admitted per second.
pub const ADDR_RATE: f64 = 0.1;
/// The most unsolicited addresses a peer can save up.
pub const ADDR_BURST: f64 = 1000.0;
/// How long after our `GetAddr` its answer is accepted.
pub const ANSWER_WINDOW: Duration = Duration::from_secs(60);
/// A received address is relayed only if its time is at most this old (or
/// this far in the future).
pub const FRESH_SECS: u64 = 600;
/// An entry time further than this in the future, or before 1973, is replaced
/// by "5 days ago" (not fresh).
pub const FUTURE_SLACK_SECS: u64 = 600;
const STALE_SECS: u64 = 5 * 24 * 3600;

/// What to do with one received `Addr` message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Part of the answer to our `GetAddr`: store every entry, relay none.
    Answer,
    /// Unsolicited and small: store (and possibly relay) the first `admit`
    /// entries; drop the rest unpenalized.
    Limited { admit: usize },
    /// An unsolicited batch: drop it and penalize the sender.
    Unsolicited,
}

/// The per-peer state.
#[derive(Clone, Debug)]
pub struct AddrGate {
    tokens: f64,
    last: Instant,
    /// Our outstanding `GetAddr`: its deadline and the addresses its answer
    /// may still carry.
    answer: Option<(Instant, usize)>,
}

impl AddrGate {
    pub fn new(now: Instant) -> Self {
        Self {
            tokens: 1.0,
            last: now,
            answer: None,
        }
    }

    /// Our `GetAddr` was sent to this peer.
    pub fn getaddr_sent(&mut self, now: Instant) {
        self.answer = Some((now + ANSWER_WINDOW, MAX_ADDRS as usize));
    }

    /// Whether an answer to our `GetAddr` is still expected.
    pub fn awaiting_answer(&self, now: Instant) -> bool {
        self.answer.is_some_and(|(deadline, _)| now <= deadline)
    }

    /// Classifies a received `Addr` of `len` entries and charges it.
    pub fn check(&mut self, len: usize, now: Instant) -> Verdict {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * ADDR_RATE).min(ADDR_BURST);
        if let Some((deadline, credit)) = self.answer.take() {
            if now <= deadline && len <= credit {
                if len <= MAX_UNSOLICITED {
                    self.answer = Some((deadline, credit - len));
                }
                return Verdict::Answer;
            }
        }
        if len > MAX_UNSOLICITED {
            return Verdict::Unsolicited;
        }
        let admit = len.min(self.tokens as usize);
        self.tokens -= admit as f64;
        Verdict::Limited { admit }
    }
}

/// A received entry time as the receiver uses it: times in the future beyond
/// [`FUTURE_SLACK_SECS`], and times before 1973 (0 = unknown), become "5 days
/// ago". Only [`is_fresh`] reads the result.
pub fn clamp_time(time: u32, now: u64) -> u64 {
    let t = u64::from(time);
    if t < 100_000_000 || t > now + FUTURE_SLACK_SECS {
        now.saturating_sub(STALE_SECS)
    } else {
        t
    }
}

/// Whether a received entry time is recent enough to relay the address.
pub fn is_fresh(time: u32, now: u64) -> bool {
    clamp_time(time, now) + FRESH_SECS >= now
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsolicited_batches_and_the_rate() {
        let t0 = Instant::now();
        let mut g = AddrGate::new(t0);
        assert_eq!(g.check(11, t0), Verdict::Unsolicited);
        assert_eq!(g.check(5, t0), Verdict::Limited { admit: 1 });
        assert_eq!(g.check(1, t0), Verdict::Limited { admit: 0 });
        // 0.1 per second: one more after 10 s.
        let t = t0 + Duration::from_secs(10);
        assert_eq!(g.check(3, t), Verdict::Limited { admit: 1 });
        // The bucket holds at most ADDR_BURST.
        let t = t + Duration::from_secs(1_000_000);
        assert_eq!(g.check(10, t), Verdict::Limited { admit: 10 });
        assert!(g.tokens <= ADDR_BURST);
    }

    #[test]
    fn the_answer_to_our_getaddr() {
        let t0 = Instant::now();
        let mut g = AddrGate::new(t0);
        g.getaddr_sent(t0);
        assert!(g.awaiting_answer(t0));
        // A small message (say the peer's self-advertisement) first: part
        // of the credit, the answer is still expected.
        assert_eq!(g.check(1, t0), Verdict::Answer);
        assert_eq!(g.check(999, t0), Verdict::Answer);
        assert!(!g.awaiting_answer(t0));
        assert_eq!(g.check(500, t0), Verdict::Unsolicited);
        // Too late.
        g.getaddr_sent(t0);
        let late = t0 + ANSWER_WINDOW + Duration::from_secs(1);
        assert_eq!(g.check(100, late), Verdict::Unsolicited);
        // More than the credit is not an answer.
        g.getaddr_sent(t0);
        assert_eq!(g.check(10, t0), Verdict::Answer);
        assert_eq!(g.check(995, t0), Verdict::Unsolicited);
    }

    #[test]
    fn freshness() {
        let now = 1_900_000_000u64;
        let n = now as u32;
        assert!(is_fresh(n, now));
        assert!(is_fresh(n - 600, now));
        assert!(!is_fresh(n - 601, now));
        assert!(is_fresh(n + 600, now));
        assert!(!is_fresh(n + 601, now), "far future");
        assert!(!is_fresh(0, now), "unknown");
        assert_eq!(clamp_time(0, now), now - STALE_SECS);
    }
}
