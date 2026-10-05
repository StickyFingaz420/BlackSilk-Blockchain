//! Rate limits and misbehavior scores (docs/p2p.md §10).

use std::time::{Duration, Instant};

/// Misbehavior score at which a peer is disconnected and banned.
pub const BAN_THRESHOLD: u32 = 100;
/// Ban duration.
pub const BAN_SECS: u64 = 24 * 3600;

/// Scores for violations.
pub mod score {
    pub const PROTOCOL: u32 = 100;
    pub const INVALID_HEADER: u32 = 100;
    pub const INVALID_BLOCK: u32 = 100;
    pub const UNCONNECTED_HEADERS: u32 = 20;
    pub const INVALID_TX: u32 = 20;
    pub const UNSOLICITED: u32 = 10;
    pub const RATE: u32 = 1;
}

/// Token bucket: `rate` tokens per second, at most `burst` stored.
#[derive(Clone, Debug)]
pub struct TokenBucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate: f64, burst: f64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
    }

    /// Whether `cost` tokens are available at `now`, taking none: several
    /// buckets can then be charged all or nothing (a `take` at the same
    /// `now` right after succeeds).
    pub fn has(&mut self, cost: f64, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= cost
    }

    /// Takes `cost` tokens unconditionally: the balance may go negative,
    /// and the debt is repaid by the refill before [`Self::has`] holds
    /// again. For work whose cost is known only in steps (a header chunk):
    /// the caller checks `has(1.0)` first.
    pub fn debit(&mut self, cost: f64, now: Instant) {
        self.refill(now);
        self.tokens -= cost;
    }

    /// How long until [`Self::has`]`(cost)` holds (zero if it does now;
    /// `None` if it never will: no refill and too few tokens).
    pub fn wait_for(&mut self, cost: f64, now: Instant) -> Option<Duration> {
        self.refill(now);
        if self.tokens >= cost {
            return Some(Duration::ZERO);
        }
        if self.rate <= 0.0 || cost > self.burst {
            return None;
        }
        Duration::try_from_secs_f64((cost - self.tokens) / self.rate).ok()
    }

    /// Returns `cost` tokens (work that turned out to be paid for, such as
    /// a header whose proof of work was valid), never above `burst`.
    pub fn credit(&mut self, cost: f64, now: Instant) {
        self.refill(now);
        self.tokens = (self.tokens + cost).min(self.burst);
    }

    /// Takes `cost` tokens if available.
    pub fn take(&mut self, cost: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }
}

/// Per-peer limits.
#[derive(Clone, Debug)]
pub struct PeerLimits {
    pub messages: TokenBucket,
    pub bytes: TokenBucket,
    pub txs: TokenBucket,
    /// Ring signatures to verify: one token per v1 input of a relayed
    /// transaction (`Tx` or `StemTx`), each a CLSAG verification. A 64-input
    /// transaction costs 64 tokens, not one.
    pub inputs: TokenBucket,
    /// PX and deploy transactions: each costs ~0.2 s to verify
    /// (docs/px.md §11.5), so their relay is limited separately.
    pub px: TokenBucket,
}

impl PeerLimits {
    /// Charges one relayed transaction, all or nothing: one `txs` token if
    /// it is a `StemTx` (`stem`), one `px` token if it is a PX or deploy
    /// transaction (`px`), and one `inputs` token per v1 input (at least
    /// one). Over any of them nothing is taken and the exhausted budget is
    /// named. The caller charges only after the checks that drop a
    /// transaction for free (dedupe, known invalid): an honest forwarder's
    /// duplicates never cost it budget (RTW2A-4).
    pub fn charge_relay(
        &mut self,
        stem: bool,
        px: bool,
        inputs: usize,
        now: Instant,
    ) -> Result<(), &'static str> {
        let inputs = inputs.max(1) as f64;
        if stem && !self.txs.has(1.0, now) {
            return Err("stem rate");
        }
        if px && !self.px.has(1.0, now) {
            return Err("PX share");
        }
        if !self.inputs.has(inputs, now) {
            return Err("input rate");
        }
        if stem {
            self.txs.take(1.0, now);
        }
        if px {
            self.px.take(1.0, now);
        }
        self.inputs.take(inputs, now);
        Ok(())
    }
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            messages: TokenBucket::new(50.0, 500.0),
            bytes: TokenBucket::new(4_000_000.0, 16_000_000.0),
            txs: TokenBucket::new(20.0, 100.0),
            inputs: TokenBucket::new(50.0, 500.0),
            px: TokenBucket::new(0.2, 4.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_refills_and_caps() {
        let t0 = Instant::now();
        let mut b = TokenBucket::new(10.0, 20.0);
        b.last = t0;
        for _ in 0..20 {
            assert!(b.take(1.0, t0));
        }
        assert!(!b.take(1.0, t0), "burst exhausted");
        assert!(
            b.take(5.0, t0 + Duration::from_millis(500)),
            "refilled 5 in 0.5 s"
        );
        assert!(!b.take(1.0, t0 + Duration::from_millis(500)));
        // Cannot accumulate beyond the burst.
        assert!(!b.take(21.0, t0 + Duration::from_secs(100)));
        assert!(b.take(20.0, t0 + Duration::from_secs(100)));
    }

    /// RTW2A-4: a relayed transaction is charged all or nothing. The PX
    /// share (burst 4) admits four PX stems, then refuses without taking a
    /// `txs` or `inputs` token; a v1 stem still passes.
    #[test]
    fn relay_charges_are_all_or_nothing() {
        let t0 = Instant::now();
        let mut l = PeerLimits::default();
        for b in [&mut l.txs, &mut l.inputs, &mut l.px] {
            b.last = t0;
        }
        for _ in 0..4 {
            assert_eq!(l.charge_relay(true, true, 1, t0), Ok(()));
        }
        let (txs, inputs) = (l.txs.tokens, l.inputs.tokens);
        assert_eq!(l.charge_relay(true, true, 1, t0), Err("PX share"));
        assert_eq!(
            (l.txs.tokens, l.inputs.tokens),
            (txs, inputs),
            "nothing taken"
        );
        assert_eq!(l.charge_relay(true, false, 1, t0), Ok(()));
        assert_eq!(l.charge_relay(false, false, 10_000, t0), Err("input rate"));
        assert_eq!(l.txs.tokens, txs - 1.0);
    }
}
