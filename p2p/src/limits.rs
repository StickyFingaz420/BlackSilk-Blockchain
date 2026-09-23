//! Rate limits and misbehavior scores (docs/p2p.md §10).

use std::time::Instant;

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
    pub const TIMEOUT: u32 = 5;
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

    /// Takes `cost` tokens if available.
    pub fn take(&mut self, cost: f64, now: Instant) -> bool {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.burst);
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
}

impl Default for PeerLimits {
    fn default() -> Self {
        Self {
            messages: TokenBucket::new(50.0, 500.0),
            bytes: TokenBucket::new(4_000_000.0, 16_000_000.0),
            txs: TokenBucket::new(20.0, 100.0),
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
}
