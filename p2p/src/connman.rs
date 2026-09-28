//! Connection policy (docs/p2p.md §9; dossier 32 W4–W7): which inbound peer
//! gives way when inbound is full, which outbound peers are anchors across a
//! restart, when a feeler is due, and when the tip is stale. Pure decisions
//! (no I/O except the anchors file, time passed in), used by the network and
//! unit-tested here.

use crate::addr::NetAddr;
use crate::dandelion::PeerId;
use blacksilk_consensus::Hash;
use rand_core::RngCore;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Outbound peers saved at shutdown and dialed first at the next start
/// (Bitcoin Core: 2 block-relay-only anchors; Monero: 2).
pub const MAX_ANCHORS: usize = 2;
/// The anchors file in the data directory.
pub const ANCHORS_FILE: &str = "anchors.json";
/// Mean time between feeler connections (Bitcoin Core: 2 minutes).
pub const FEELER_INTERVAL: Duration = Duration::from_secs(120);
/// The tip is stale after `3 × T × STALE_TIP_FACTOR` without a new block.
/// Bitcoin Core uses 3 × T; the factor 2 keeps honest block-time variance
/// (P(no block in 6 T) ≈ e^-6 ≈ 0.25 %) from triggering it.
pub const STALE_TIP_FACTOR: u64 = 2;
/// While the tip is stale, one extra outbound connection at most this often
/// (Bitcoin Core's `STALE_CHECK_INTERVAL`).
pub const STALE_CHECK_INTERVAL: Duration = Duration::from_secs(600);
/// An outbound peer younger than this is never evicted as the extra one.
pub const MIN_CONNECT_TIME: Duration = Duration::from_secs(30);
/// Inbound peers protected by keyed network group, one per group.
pub const PROTECT_BY_GROUP: usize = 4;

// ---------------------------------------------------------------- inbound eviction

/// An inbound peer considered for eviction.
#[derive(Clone, Debug)]
pub struct EvictionCandidate {
    pub id: PeerId,
    /// `AddrMan::keyed_group` of the peer's group: unpredictable to peers.
    pub keyed_group: u64,
    pub connected: Instant,
    /// A network whose peers are scarce and would lose out on the other
    /// criteria: onion peers, arriving through our hidden service from
    /// loopback.
    pub disadvantaged: bool,
}

/// The inbound peer to disconnect so that a new inbound connection can be
/// accepted, or `None` (the new connection is refused), after Bitcoin Core's
/// `SelectNodeToEvict`. Protected, in order:
/// 1. one peer (the oldest) of each of the [`PROTECT_BY_GROUP`] groups with
///    the highest keyed group hash: an attacker cannot know which groups;
/// 2. up to a quarter of all candidates from disadvantaged networks, oldest
///    first;
/// 3. half of the rest, by uptime (oldest first): long-lived connections are
///    costly to take over.
///
/// From the rest, the youngest peer of the group with the most connections
/// (ties: the group whose youngest peer is youngest) is evicted.
///
/// Bitcoin Core also protects the peers with the lowest ping and those that
/// recently relayed transactions or blocks; BlackSilk does not measure them
/// yet (docs/p2p.md §9).
pub fn select_inbound_to_evict(candidates: &[EvictionCandidate]) -> Option<PeerId> {
    let total = candidates.len();
    let mut c: Vec<&EvictionCandidate> = candidates.iter().collect();
    // 1. Keyed groups.
    c.sort_by(|a, b| {
        b.keyed_group
            .cmp(&a.keyed_group)
            .then(a.connected.cmp(&b.connected))
            .then(a.id.cmp(&b.id))
    });
    let mut groups = Vec::new();
    c.retain(|p| {
        if groups.len() < PROTECT_BY_GROUP && !groups.contains(&p.keyed_group) {
            groups.push(p.keyed_group);
            return false;
        }
        true
    });
    // 2. Disadvantaged networks.
    c.sort_by(|a, b| a.connected.cmp(&b.connected).then(a.id.cmp(&b.id)));
    let mut quota = total / 4;
    c.retain(|p| {
        if p.disadvantaged && quota > 0 {
            quota -= 1;
            return false;
        }
        true
    });
    // 3. Uptime.
    let keep = c.len() / 2;
    let c = &c[keep..];
    if c.is_empty() {
        return None;
    }
    let mut by_group: HashMap<u64, Vec<&EvictionCandidate>> = HashMap::new();
    for p in c {
        by_group.entry(p.keyed_group).or_default().push(p);
    }
    let youngest = |v: &[&EvictionCandidate]| {
        v.iter()
            .map(|p| (p.connected, p.id))
            .max()
            .expect("non-empty")
    };
    let group = by_group
        .values()
        .max_by(|a, b| a.len().cmp(&b.len()).then(youngest(a).cmp(&youngest(b))))
        .expect("non-empty");
    Some(youngest(group).1)
}

// ---------------------------------------------------------------- outbound rotation

/// An outbound (not manual) peer considered for eviction when the node has
/// more outbound peers than its target (the extra stale-tip connection).
#[derive(Clone, Debug)]
pub struct OutboundCandidate {
    pub id: PeerId,
    /// When the peer last delivered a validated new tip: a header batch
    /// that stored new headers on our best header chain, or a block that
    /// joined our best chain (`None`: never). Never the height the peer
    /// claimed in its `Version`, which costs nothing to inflate (RTW3-4).
    pub last_new_tip: Option<Instant>,
    pub connected: Instant,
    /// Blocks requested from the peer are still outstanding.
    pub blocks_in_flight: bool,
}

/// The outbound peer to disconnect, after Bitcoin Core's
/// `EvictExtraOutboundPeers`: the worst of ALL candidates is the one whose
/// last validated new tip is oldest (never: worst), ties broken by the
/// youngest connection. If that peer is younger than `min_connect_time`, or
/// blocks it was asked for are outstanding, nothing is evicted now: the
/// rotation waits for it rather than evicting a better peer (RTW3-4). So a
/// newcomer that brought nothing goes once it is old enough, and one that
/// brought a new tip stays while an established peer that brought none goes.
pub fn select_outbound_to_evict(
    candidates: &[OutboundCandidate],
    now: Instant,
    min_connect_time: Duration,
) -> Option<PeerId> {
    let worst = candidates.iter().min_by(|a, b| {
        a.last_new_tip
            .cmp(&b.last_new_tip)
            .then(b.connected.cmp(&a.connected))
            .then(b.id.cmp(&a.id))
    })?;
    let old_enough = now.saturating_duration_since(worst.connected) >= min_connect_time;
    (old_enough && !worst.blocks_in_flight).then_some(worst.id)
}

// ---------------------------------------------------------------- stale tip

/// The stale-tip threshold for a chain with target block time
/// `target_secs`: `3 × T × STALE_TIP_FACTOR`.
pub fn stale_threshold(target_secs: u64) -> Duration {
    Duration::from_secs(3 * target_secs.max(1) * STALE_TIP_FACTOR)
}

/// Watches the connected tip: stale once it has not changed for the
/// threshold ([`stale_threshold`] by default).
#[derive(Clone, Debug)]
pub struct StaleTip {
    tip: Hash,
    since: Instant,
    threshold: Duration,
    check_interval: Duration,
    last_extra: Option<Instant>,
}

impl StaleTip {
    /// Stale after `threshold` without a new tip; one extra connection at
    /// most every `check_interval` ([`STALE_CHECK_INTERVAL`] by default).
    pub fn new(tip: Hash, now: Instant, threshold: Duration, check_interval: Duration) -> Self {
        Self {
            tip,
            since: now,
            threshold,
            check_interval,
            last_extra: None,
        }
    }

    /// Records the tip seen now; returns whether it is stale.
    pub fn observe(&mut self, tip: Hash, now: Instant) -> bool {
        if tip != self.tip {
            self.tip = tip;
            self.since = now;
            self.last_extra = None;
        }
        now.saturating_duration_since(self.since) >= self.threshold
    }

    /// Whether an extra outbound connection is due (the tip is stale, and
    /// none was made in the last check interval).
    pub fn extra_due(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.since) >= self.threshold
            && self
                .last_extra
                .is_none_or(|t| now.saturating_duration_since(t) >= self.check_interval)
    }

    /// An extra connection was started now.
    pub fn extra_started(&mut self, now: Instant) {
        self.last_extra = Some(now);
    }
}

// ---------------------------------------------------------------- feelers

/// When the next feeler is due: exponentially distributed with mean `mean`
/// ([`FEELER_INTERVAL`] by default; a Poisson process: the schedule tells a
/// peer nothing), capped at 10 means.
pub fn next_feeler(now: Instant, mean: Duration, rng: &mut impl RngCore) -> Instant {
    let u = ((rng.next_u64() >> 11) as f64 + 1.0) / (1u64 << 53) as f64;
    let secs = (-u.ln() * mean.as_secs_f64()).min(10.0 * mean.as_secs_f64());
    now + Duration::from_secs_f64(secs)
}

// ---------------------------------------------------------------- anchors

/// Writes the anchors (at most [`MAX_ANCHORS`]); an empty list removes the
/// file. Written to a temporary file and renamed.
pub fn save_anchors(dir: &Path, anchors: &[NetAddr]) -> std::io::Result<()> {
    let path = dir.join(ANCHORS_FILE);
    if anchors.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let list = &anchors[..anchors.len().min(MAX_ANCHORS)];
    let tmp = path.with_extension("tmp");
    std::fs::write(
        &tmp,
        serde_json::to_vec(list).map_err(std::io::Error::other)?,
    )?;
    std::fs::rename(tmp, path)
}

/// Reads and deletes the anchors file (a node that crashes later does not
/// re-anchor to an old file): at most [`MAX_ANCHORS`] canonical addresses;
/// empty if missing or unreadable.
pub fn take_anchors(dir: &Path) -> Vec<NetAddr> {
    let path = dir.join(ANCHORS_FILE);
    let Ok(bytes) = std::fs::read(&path) else {
        return Vec::new();
    };
    if let Err(e) = std::fs::remove_file(&path) {
        log::warn!("{}: cannot delete ({e})", path.display());
    }
    let list: Vec<NetAddr> = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        log::warn!("{}: cannot parse ({e}); no anchors", path.display());
        Vec::new()
    });
    let mut out: Vec<NetAddr> = Vec::new();
    for a in list.into_iter().map(NetAddr::canonical) {
        if out.len() < MAX_ANCHORS && !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

// ---------------------------------------------------------------- state

/// The network's connection-policy state (behind the network lock).
#[derive(Default)]
pub struct ConnState {
    /// Anchors still to dial; `None` until the anchors file was read.
    pub anchors: Option<Vec<NetAddr>>,
    /// The feeler connection in progress, if any.
    pub feeler: Option<NetAddr>,
    /// When the next feeler is due (`None`: not scheduled yet).
    pub next_feeler: Option<Instant>,
    /// The stale-tip watch (`None` until the first maintenance round).
    pub stale: Option<StaleTip>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn cand(id: PeerId, group: u64, age_secs: u64, t0: Instant) -> EvictionCandidate {
        EvictionCandidate {
            id,
            keyed_group: group,
            connected: t0 - Duration::from_secs(age_secs),
            disadvantaged: false,
        }
    }

    /// W6: a full inbound set evicts from the group with the most
    /// connections, its youngest peer.
    #[test]
    fn full_inbound_evicts_from_the_largest_netgroup() {
        let t0 = Instant::now() + Duration::from_secs(100_000);
        let mut c = Vec::new();
        // Honest peers in 12 groups, old connections.
        for i in 0..12u64 {
            c.push(cand(i, 1000 + i, 10_000 + i * 10, t0));
        }
        // An attacker's 20 connections from group 7, young.
        for i in 0..20u64 {
            c.push(cand(100 + i, 7, 10 + i, t0));
        }
        let v = select_inbound_to_evict(&c).unwrap();
        assert_eq!(v, 100, "the youngest peer of the attacker's group");
        // Repeated evictions take only attacker peers until its group is no
        // longer the largest.
        let mut left = c.clone();
        for _ in 0..15 {
            let v = select_inbound_to_evict(&left).unwrap();
            assert!(v >= 100, "evicted honest peer {v}");
            left.retain(|p| p.id != v);
        }
    }

    /// W6: protected peers survive: the oldest of the top keyed groups, the
    /// disadvantaged quota and the older half.
    #[test]
    fn protected_peers_survive_eviction() {
        let t0 = Instant::now() + Duration::from_secs(100_000);
        // Few candidates: all protected, nothing is evicted.
        let c: Vec<_> = (0..4).map(|i| cand(i, i, 100, t0)).collect();
        assert_eq!(select_inbound_to_evict(&c), None);
        assert_eq!(select_inbound_to_evict(&[]), None);
        // One onion peer (loopback, one group with 7 others), young: kept.
        let mut c: Vec<_> = (0..8).map(|i| cand(i, 5, 1000 + i, t0)).collect();
        c.push(EvictionCandidate {
            disadvantaged: true,
            ..cand(50, 5, 1, t0)
        });
        // The quota is a quarter of the candidates: while there are 4.
        let mut left = c.clone();
        while left.len() >= 4 {
            let v = select_inbound_to_evict(&left).unwrap();
            assert_ne!(v, 50, "the disadvantaged peer is protected");
            left.retain(|p| p.id != v);
        }
        // The oldest peers are protected by uptime.
        assert!(left.iter().any(|p| p.id == 7), "oldest kept");
    }

    /// RTW3-4: the worst outbound peer is the one whose last validated new
    /// tip is oldest (never: worst; ties: the youngest), over all candidates.
    /// A young worst peer is waited for, never replaced by an older, better
    /// one; so is one with blocks in flight.
    #[test]
    fn outbound_rotation_evicts_the_peer_that_brought_the_least() {
        let now = Instant::now() + Duration::from_secs(1000);
        let min = MIN_CONNECT_TIME;
        let o = |id, tip_ago: Option<u64>, age| OutboundCandidate {
            id,
            last_new_tip: tip_ago.map(|s| now - Duration::from_secs(s)),
            connected: now - Duration::from_secs(age),
            blocks_in_flight: false,
        };
        // 2 brought its last tip long ago, 1 and 3 recently.
        let c = [
            o(1, Some(10), 500),
            o(2, Some(400), 450),
            o(3, Some(20), 300),
        ];
        assert_eq!(select_outbound_to_evict(&c, now, min), Some(2));
        // A young newcomer that brought a new tip stays; the stale one goes.
        let mut c2 = c.to_vec();
        c2.push(o(4, Some(1), 5));
        assert_eq!(select_outbound_to_evict(&c2, now, min), Some(2));
        // Nobody brought anything: the youngest is worst; while it is younger
        // than the minimum the rotation waits (it never evicts an older one).
        let quiet = [o(1, None, 500), o(2, None, 400), o(3, None, 5)];
        assert_eq!(select_outbound_to_evict(&quiet, now, min), None);
        let later = now + min;
        assert_eq!(select_outbound_to_evict(&quiet, later, min), Some(3));
        // Never delivered is worse than delivered long ago, whatever the age.
        let c3 = [o(1, Some(900), 950), o(2, None, 600)];
        assert_eq!(select_outbound_to_evict(&c3, now, min), Some(2));
        // Blocks in flight: wait.
        let mut busy = c3.to_vec();
        busy[1].blocks_in_flight = true;
        assert_eq!(select_outbound_to_evict(&busy, now, min), None);
        assert_eq!(select_outbound_to_evict(&[], now, min), None);
    }

    /// W7: the tip is stale after 3 × T × factor without change; one extra
    /// connection per stale check interval.
    #[test]
    fn stale_tip_asks_for_an_extra_outbound() {
        let t0 = Instant::now();
        let stale_after = stale_threshold(120);
        assert_eq!(stale_after, Duration::from_secs(3 * 120 * STALE_TIP_FACTOR));
        let mut s = StaleTip::new([1; 32], t0, stale_after, STALE_CHECK_INTERVAL);
        assert!(!s.observe([1; 32], t0 + stale_after - Duration::from_secs(1)));
        assert!(!s.extra_due(t0 + stale_after - Duration::from_secs(1)));
        let t = t0 + stale_after;
        assert!(s.observe([1; 32], t));
        assert!(s.extra_due(t));
        s.extra_started(t);
        assert!(!s.extra_due(t + Duration::from_secs(1)));
        assert!(s.extra_due(t + STALE_CHECK_INTERVAL));
        // A new tip resets it.
        assert!(!s.observe([2; 32], t + STALE_CHECK_INTERVAL));
        assert!(!s.extra_due(t + STALE_CHECK_INTERVAL));
    }

    #[test]
    fn feelers_are_poisson_with_the_mean_interval() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let t0 = Instant::now();
        let n = 20_000;
        let total: f64 = (0..n)
            .map(|_| {
                next_feeler(t0, FEELER_INTERVAL, &mut rng)
                    .duration_since(t0)
                    .as_secs_f64()
            })
            .sum();
        let mean = total / n as f64;
        assert!((mean - 120.0).abs() < 5.0, "{mean}");
    }

    #[test]
    fn anchors_file_is_deleted_after_load() {
        let dir = tempfile::tempdir().unwrap();
        let a = NetAddr::parse("8.8.8.8:1").unwrap();
        let b = NetAddr::parse("9.9.9.9:2").unwrap();
        let c = NetAddr::parse("7.7.7.7:3").unwrap();
        save_anchors(dir.path(), &[a.clone(), b.clone(), c]).unwrap();
        assert_eq!(take_anchors(dir.path()), vec![a, b], "at most two");
        assert!(!dir.path().join(ANCHORS_FILE).exists());
        assert!(take_anchors(dir.path()).is_empty());
        std::fs::write(dir.path().join(ANCHORS_FILE), b"junk").unwrap();
        assert!(take_anchors(dir.path()).is_empty());
        assert!(!dir.path().join(ANCHORS_FILE).exists());
        save_anchors(dir.path(), &[]).unwrap();
    }
}
