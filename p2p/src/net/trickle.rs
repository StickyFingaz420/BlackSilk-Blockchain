//! When queued transaction announcements are released: the trickle
//! (docs/p2p.md §7, "Announcing").
//!
//! An outbound peer has its own timer (`Peer::next_inv`, an exponential
//! delay of mean `trickle_outbound` from its first queued id): we chose it,
//! so a spy cannot multiply it.
//!
//! Inbound peers share ONE timer per network identity of this node
//! ([`TrickleKey`]): a Poisson process of mean `trickle_inbound` that releases
//! the queues of every inbound peer of that identity at the same instant.
//! A spy that opens k inbound connections then sees one release instant per
//! transaction, not k independent ones whose earliest estimates when we first
//! had it (timing-based origin inference; RES-FREEZE §4.5(2), §8.6-4a,
//! dossier 33 W5). The identities are kept apart (IPv4, IPv6, onion, and
//! each local endpoint): one timer for all of them would release at the same
//! instant on, say, our onion service and our IPv4 address, and so tell a
//! spy connected to both that they are one node. Bitcoin Core PR #33464
//! (merged 2025-10-03) has the same two properties: one inbound timer per
//! "network key" (the peer's network class, onion for its onion service,
//! plus the local bind address and port), outbound timers per peer.

use crate::addr::NetAddr;
use crate::dandelion::exponential;
use rand_chacha::rand_core::RngCore;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// The network an inbound peer reached us through.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum NetClass {
    Ipv4,
    Ipv6,
    /// Through Tor: our onion service's listener, or the legacy setup
    /// forwarding the onion service to the P2P port (`loopback_is_tor`).
    Onion,
}

/// One network identity of this node: inbound peers with the same key share
/// one release timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct TrickleKey {
    class: NetClass,
    /// The local endpoint the connection was accepted on (canonical), when
    /// known: a host with several addresses of one family behind one
    /// wildcard listener has one timer per address.
    local: Option<SocketAddr>,
}

impl TrickleKey {
    /// The key of an inbound connection from `addr` (canonical), accepted on
    /// `local`; `via_tor` when it came through Tor.
    pub(super) fn inbound(addr: &NetAddr, via_tor: bool, local: Option<SocketAddr>) -> Self {
        let class = match addr.ip() {
            _ if via_tor || addr.is_onion() => NetClass::Onion,
            Some(ip) if ip.to_canonical().is_ipv4() => NetClass::Ipv4,
            Some(_) => NetClass::Ipv6,
            None => NetClass::Onion,
        };
        let local = local.map(|l| SocketAddr::new(l.ip().to_canonical(), l.port()));
        Self { class, local }
    }
}

/// The shared inbound timers, one per [`TrickleKey`] in use.
#[derive(Default)]
pub(super) struct InboundTrickle {
    timers: HashMap<TrickleKey, Instant>,
}

impl InboundTrickle {
    /// The keys whose timer fired by `now`, each then drawn again (`now` +
    /// Exp(`mean`)). A key first seen gets a fresh timer (not fired); keys
    /// not in `live` (no inbound peer left) are forgotten, so the map holds
    /// only the node's own current identities.
    pub(super) fn fire(
        &mut self,
        live: impl IntoIterator<Item = TrickleKey>,
        now: Instant,
        mean: Duration,
        rng: &mut impl RngCore,
    ) -> HashSet<TrickleKey> {
        let live: HashSet<TrickleKey> = live.into_iter().collect();
        self.timers.retain(|k, _| live.contains(k));
        let mut fired = HashSet::new();
        for key in live {
            let timer = self
                .timers
                .entry(key)
                .or_insert_with(|| now + exponential(mean, rng));
            if *timer <= now {
                *timer = now + exponential(mean, rng);
                fired.insert(key);
            }
        }
        fired
    }

    /// When `key`'s timer fires next (tests).
    #[cfg(test)]
    fn next(&self, key: &TrickleKey) -> Option<Instant> {
        self.timers.get(key).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn key(class: NetClass) -> TrickleKey {
        TrickleKey { class, local: None }
    }

    /// Runs `key`'s timer alone for `n` fires, jumping to each firing
    /// instant (no tick rounding): the intervals between fires.
    fn intervals(seed: u64, mean: Duration, n: usize) -> Vec<f64> {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut t = InboundTrickle::default();
        let k = key(NetClass::Ipv4);
        let mut now = Instant::now();
        assert!(t.fire([k], now, mean, &mut rng).is_empty(), "a new key");
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let next = t.next(&k).unwrap();
            out.push(next.duration_since(now).as_secs_f64());
            now = next;
            assert_eq!(t.fire([k], now, mean, &mut rng), HashSet::from([k]));
        }
        out
    }

    /// The intervals between releases are exponential with the configured
    /// mean: sample mean and standard deviation both within 3 % of it
    /// (20 000 samples: one standard error is 0.7 %), and the median at
    /// mean·ln 2.
    #[test]
    fn release_intervals_are_exponential_with_the_configured_mean() {
        let xs = intervals(7, Duration::from_secs(5), 20_000);
        let n = xs.len() as f64;
        let m = xs.iter().sum::<f64>() / n;
        let sd = (xs.iter().map(|x| (x - m).powi(2)).sum::<f64>() / n).sqrt();
        assert!((m - 5.0).abs() < 0.15, "mean {m}");
        assert!((sd - 5.0).abs() < 0.15, "standard deviation {sd}");
        let mut s = xs.clone();
        s.sort_by(f64::total_cmp);
        let median = s[s.len() / 2];
        assert!((median - 5.0 * 2f64.ln()).abs() < 0.15, "median {median}");
    }

    /// Memorylessness, the property the shared timer relies on: a
    /// transaction queued at an arbitrary instant waits Exp(mean) for the
    /// next release, however long the timer has already run. Measured two
    /// ways on 20 000 intervals: P(X > s + t | X > s) = P(X > t) for s = t =
    /// the mean (both e^-1), and the wait from uniformly random arrival
    /// instants to the next release has the full mean (not half of it, as
    /// with a periodic timer).
    #[test]
    fn a_release_timer_is_memoryless() {
        let xs = intervals(11, Duration::from_secs(2), 20_000);
        let over = |a: f64| xs.iter().filter(|&&x| x > a).count() as f64;
        let p_t = over(2.0) / xs.len() as f64;
        let p_cond = over(4.0) / over(2.0);
        let e1 = (-1f64).exp();
        assert!((p_t - e1).abs() < 0.02, "P(X > t) {p_t}");
        assert!((p_cond - e1).abs() < 0.03, "P(X > s + t | X > s) {p_cond}");
        // Arrivals at uniform instants over the whole run.
        let mut ends = Vec::with_capacity(xs.len());
        let mut t = 0.0;
        for x in &xs {
            t += x;
            ends.push(t);
        }
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let waits: Vec<f64> = (0..20_000)
            .map(|_| {
                let u = (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64;
                let at = u * t;
                let i = ends.partition_point(|&e| e <= at);
                ends[i.min(ends.len() - 1)] - at
            })
            .collect();
        let m = waits.iter().sum::<f64>() / waits.len() as f64;
        assert!((m - 2.0).abs() < 0.1, "mean wait from a random instant {m}");
    }

    /// One timer per key: every peer of a key is released by the same fire;
    /// keys never fire together by construction (independent draws), and a
    /// key with no inbound peer left is forgotten.
    #[test]
    fn each_key_has_one_timer_and_keys_are_independent() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let mut t = InboundTrickle::default();
        let (v4, v6, onion) = (
            key(NetClass::Ipv4),
            key(NetClass::Ipv6),
            key(NetClass::Onion),
        );
        let mean = Duration::from_secs(5);
        let start = Instant::now();
        // Many peers, three keys: three timers.
        let live = [v4, v4, v4, v6, onion, onion];
        assert!(t.fire(live, start, mean, &mut rng).is_empty());
        assert_eq!(t.timers.len(), 3);
        let at = [t.next(&v4), t.next(&v6), t.next(&onion)].map(Option::unwrap);
        assert!(at[0] != at[1] && at[1] != at[2] && at[0] != at[2]);
        // At v4's instant only v4 fires (the draws are continuous, so ties
        // have probability 0), and its peers fire together.
        let first = *at.iter().min().unwrap();
        let fired = t.fire(live, first, mean, &mut rng);
        assert_eq!(fired.len(), 1);
        // Redrawn from the firing instant; the others kept theirs.
        let k = *fired.iter().next().unwrap();
        assert!(t.next(&k).unwrap() > first);
        // The onion peers leave: their timer is forgotten.
        t.fire([v4, v6], first, mean, &mut rng);
        assert!(t.next(&onion).is_none() && t.timers.len() == 2);
    }

    /// The network class of an inbound connection, and its local endpoint.
    #[test]
    fn inbound_keys_follow_network_and_local_endpoint() {
        let v4 = NetAddr::parse("1.2.3.4:5").unwrap();
        let v6 = NetAddr::parse("[2001:db8::1]:5").unwrap();
        let mapped = NetAddr::Ip("[::ffff:1.2.3.4]:5".parse().unwrap());
        let local: SocketAddr = "[::ffff:10.0.0.1]:29334".parse().unwrap();
        assert_eq!(TrickleKey::inbound(&v4, false, None).class, NetClass::Ipv4);
        assert_eq!(
            TrickleKey::inbound(&mapped, false, None).class,
            NetClass::Ipv4
        );
        assert_eq!(TrickleKey::inbound(&v6, false, None).class, NetClass::Ipv6);
        assert_eq!(TrickleKey::inbound(&v4, true, None).class, NetClass::Onion);
        assert_eq!(
            TrickleKey::inbound(&v4, false, Some(local)).local,
            Some("10.0.0.1:29334".parse().unwrap()),
            "canonical"
        );
        assert_ne!(
            TrickleKey::inbound(&v4, false, Some("10.0.0.1:1".parse().unwrap())),
            TrickleKey::inbound(&v4, false, Some("10.0.0.2:1".parse().unwrap())),
            "two local addresses, two timers"
        );
    }
}
