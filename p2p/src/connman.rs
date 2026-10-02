//! Connection policy (docs/p2p.md §9; dossier 32 W4–W7): the kinds of
//! connection, which inbound peer gives way when inbound is full, which
//! outbound peers are anchors across a restart, when a feeler is due, and
//! when the tip is stale. Pure decisions (no I/O except the anchors file,
//! time passed in), used by the network and unit-tested here.

use crate::addr::NetAddr;
use crate::dandelion::PeerId;
use blacksilk_consensus::Hash;
use rand_core::RngCore;
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Block-relay-only peers saved at shutdown and dialed first at the next start
/// (Bitcoin Core: 2 block-relay-only anchors; Monero: 2).
pub const MAX_ANCHORS: usize = 2;
/// Block-relay-only outbound connections kept besides the full-relay ones
/// (Bitcoin Core: 2). They carry headers and blocks only: no transactions and
/// no addresses, so transaction and address relay reveal nothing about them
/// (TxProbe, Delgado-Segura et al., FC 2019), and they are the anchors.
pub const BLOCK_RELAY_ONLY: usize = 2;
/// A seed's address fetch is closed after this long if the seed has not
/// answered by then (Bitcoin Core closes an addr-fetch connection after its
/// answer, or at the next check).
pub const ADDR_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Seeds are asked for addresses when fewer than this many full-relay
/// outbound peers are up...
pub const SEED_FALLBACK_OUTBOUND: usize = 2;
/// ...for this long (or at once when the address table is empty, and while
/// the tip is stale).
pub const SEED_FALLBACK_AFTER: Duration = Duration::from_secs(60);
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
/// Inbound peers protected by the lowest minimum ping time.
pub const PROTECT_BY_PING: usize = 8;
/// Inbound peers protected by the most recent new valid transaction.
pub const PROTECT_BY_TX: usize = 4;
/// Block-relay-only inbound peers protected by the most recent new block.
pub const PROTECT_BLOCK_RELAY_BY_BLOCK: usize = 8;
/// Inbound peers protected by the most recent new block.
pub const PROTECT_BY_BLOCK: usize = 4;

// ---------------------------------------------------------------- connection kinds

/// What a connection is for (docs/p2p.md §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConnKind {
    /// Accepted on the P2P listener.
    Inbound,
    /// Accepted on the onion listener (`NetConfig::onion_listen`): a peer
    /// reaching our hidden service. Its IP is the Tor daemon's, so it is
    /// never IP-banned or counted per IP; the class is capped instead
    /// ([`onion_inbound_cap`]).
    OnionInbound,
    /// Outbound, relaying blocks, transactions and addresses. Manual peers
    /// are full-relay.
    FullRelay,
    /// Outbound, relaying headers and blocks only ([`BLOCK_RELAY_ONLY`]):
    /// `Version.relay_txs = false`, no `GetAddr`, no `Addr` either way, never
    /// a Dandelion stem.
    BlockRelay,
    /// Outbound to a seed, one-shot: `GetAddr`, then closed on the answer or
    /// after [`ADDR_FETCH_TIMEOUT`]. Never promoted in the address table,
    /// never a stem or an anchor, not counted as an outbound peer.
    AddrFetch,
}

impl ConnKind {
    pub fn is_inbound(self) -> bool {
        matches!(self, ConnKind::Inbound | ConnKind::OnionInbound)
    }

    /// Whether transactions are relayed (announced, stemmed) on it by this
    /// node.
    pub fn relays_txs(self) -> bool {
        matches!(
            self,
            ConnKind::Inbound | ConnKind::OnionInbound | ConnKind::FullRelay
        )
    }

    /// Whether addresses are exchanged on it (our `GetAddr` or theirs, our
    /// own address, relayed addresses).
    pub fn relays_addrs(self) -> bool {
        self != ConnKind::BlockRelay
    }
}

/// Onion inbound peers at most: a quarter of `max_inbound` (at least one).
/// They share `max_inbound` with the clearnet inbound peers.
pub fn onion_inbound_cap(max_inbound: usize) -> usize {
    (max_inbound / 4).max(1)
}

// ---------------------------------------------------------------- inbound eviction

/// An inbound peer considered for eviction.
#[derive(Clone, Debug)]
pub struct EvictionCandidate {
    pub id: PeerId,
    /// `AddrMan::keyed_group` of the peer's group: unpredictable to peers.
    pub keyed_group: u64,
    pub connected: Instant,
    /// A network whose peers are scarce and would lose out on the other
    /// criteria: onion peers, arriving through our hidden service.
    pub disadvantaged: bool,
    /// The lowest ping round trip measured (`None`: not measured yet). A
    /// peer cannot make it lower than its real distance: the nonce it must
    /// echo is sent only then.
    pub min_ping: Option<Duration>,
    /// When the peer last delivered a new transaction that passed
    /// verification (`None`: never).
    pub last_tx: Option<Instant>,
    /// When the peer last delivered a new block that joined our best chain
    /// (`None`: never).
    pub last_block: Option<Instant>,
    /// The peer asked for transaction relay (`Version.relay_txs`); `false`:
    /// a block-relay-only connection of the peer's.
    pub relay_txs: bool,
}

/// Removes from `c` up to `k` candidates for which `key` is `Some`, those
/// with the greatest key (ties: the oldest connection, then the lowest id):
/// they are protected.
fn protect_best<K: Ord>(
    c: &mut Vec<&EvictionCandidate>,
    k: usize,
    key: impl Fn(&EvictionCandidate) -> Option<K>,
) {
    let mut ranked: Vec<(K, Instant, PeerId)> = c
        .iter()
        .filter_map(|p| key(p).map(|x| (x, p.connected, p.id)))
        .collect();
    ranked.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)).then(a.2.cmp(&b.2)));
    let keep: Vec<PeerId> = ranked.into_iter().take(k).map(|x| x.2).collect();
    c.retain(|p| !keep.contains(&p.id));
}

/// The inbound peer to disconnect so that a new inbound connection can be
/// accepted, or `None` (the new connection is refused), after Bitcoin Core's
/// `SelectNodeToEvict`. Protected, in order:
/// 1. one peer (the oldest) of each of the [`PROTECT_BY_GROUP`] groups with
///    the highest keyed group hash: an attacker cannot know which groups;
/// 2. the [`PROTECT_BY_PING`] peers with the lowest measured minimum ping
///    (an attacker must be close to the node, in the network, to win);
/// 3. the [`PROTECT_BY_TX`] peers that most recently delivered a new valid
///    transaction;
/// 4. the [`PROTECT_BLOCK_RELAY_BY_BLOCK`] block-relay-only peers that most
///    recently delivered a new block;
/// 5. the [`PROTECT_BY_BLOCK`] peers that most recently delivered a new
///    block;
/// 6. up to a quarter of all candidates from disadvantaged networks, oldest
///    first;
/// 7. half of the rest, by uptime (oldest first): long-lived connections are
///    costly to take over.
///
/// Classes 2 to 5 protect only peers that earned it (a measured ping, a
/// delivery). From the rest, the youngest peer of the group with the most
/// connections (ties: the group whose youngest peer is youngest) is
/// evicted.
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
    // 2. Lowest ping (greatest key: the reversed ping).
    protect_best(&mut c, PROTECT_BY_PING, |p| {
        p.min_ping.map(std::cmp::Reverse)
    });
    // 3. Recent transactions.
    protect_best(&mut c, PROTECT_BY_TX, |p| p.last_tx);
    // 4. Block-relay-only peers by recent blocks.
    protect_best(&mut c, PROTECT_BLOCK_RELAY_BY_BLOCK, |p| {
        p.last_block.filter(|_| !p.relay_txs)
    });
    // 5. Recent blocks.
    protect_best(&mut c, PROTECT_BY_BLOCK, |p| p.last_block);
    // 6. Disadvantaged networks.
    c.sort_by(|a, b| a.connected.cmp(&b.connected).then(a.id.cmp(&b.id)));
    let mut quota = total / 4;
    c.retain(|p| {
        if p.disadvantaged && quota > 0 {
            quota -= 1;
            return false;
        }
        true
    });
    // 7. Uptime.
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
    // Owner-only: stable contacts that recognize this node.
    crate::private_file::write_atomic(
        &path,
        &serde_json::to_vec(list).map_err(std::io::Error::other)?,
    )
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
    /// Anchors still to dial (as block-relay-only connections); `None` until
    /// the anchors file was read.
    pub anchors: Option<Vec<NetAddr>>,
    /// Since when fewer than [`SEED_FALLBACK_OUTBOUND`] full-relay outbound
    /// peers are up (`None`: enough are).
    pub low_outbound_since: Option<Instant>,
    /// When each seed was last asked for addresses (at most every
    /// `SEED_RETRY`).
    pub seed_fetches: HashMap<NetAddr, Instant>,
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
            min_ping: None,
            last_tx: None,
            last_block: None,
            relay_txs: true,
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

    /// W3-32c item 3 (W6 remainder): peers that recently delivered a new
    /// valid transaction or block, and the lowest-ping peers, survive
    /// eviction; a peer that delivered nothing, however old, does not
    /// outlast them. All candidates share one group and are young (no group
    /// or uptime advantage) except where stated.
    #[test]
    fn recent_relayers_and_low_ping_peers_survive_eviction() {
        let t0 = Instant::now() + Duration::from_secs(100_000);
        let recent = |secs| Some(t0 - Duration::from_secs(secs));
        let mut c: Vec<EvictionCandidate> = (0..40).map(|i| cand(i, 7, 10 + i, t0)).collect();
        // 8 fast peers, 4 transaction relayers, 4 block relayers and 8
        // block-relay-only peers that delivered blocks; the rest delivered
        // nothing and have no ping measured.
        for p in &mut c[0..8] {
            p.min_ping = Some(Duration::from_millis(5 + p.id));
        }
        for p in &mut c[8..12] {
            p.last_tx = recent(p.id);
        }
        for p in &mut c[12..16] {
            p.last_block = recent(p.id);
        }
        for p in &mut c[16..24] {
            p.last_block = recent(1000 + p.id);
            p.relay_txs = false;
        }
        // Slower peers than the 8 fast ones, and staler relayers: not
        // protected by those classes.
        for p in &mut c[24..28] {
            p.min_ping = Some(Duration::from_millis(500));
        }
        let protected: Vec<PeerId> = (0..24).collect();
        let mut left = c.clone();
        while let Some(v) = select_inbound_to_evict(&left) {
            assert!(!protected.contains(&v), "evicted protected peer {v}");
            left.retain(|p| p.id != v);
        }
        for id in &protected {
            assert!(left.iter().any(|p| p.id == *id), "{id} evicted");
        }
        // Protection is earned: without the measurements the same peers are
        // evicted like any other.
        let plain: Vec<EvictionCandidate> = (0..40).map(|i| cand(i, 7, 10 + i, t0)).collect();
        let mut left = plain;
        let mut evicted = Vec::new();
        while let Some(v) = select_inbound_to_evict(&left) {
            evicted.push(v);
            left.retain(|p| p.id != v);
        }
        assert!(evicted.iter().any(|v| *v < 24), "{evicted:?}");
    }

    /// Connection kinds: what each relays.
    #[test]
    fn connection_kinds() {
        use ConnKind::*;
        for k in [Inbound, OnionInbound] {
            assert!(k.is_inbound() && k.relays_txs() && k.relays_addrs());
        }
        assert!(!FullRelay.is_inbound() && FullRelay.relays_txs() && FullRelay.relays_addrs());
        assert!(!BlockRelay.relays_txs() && !BlockRelay.relays_addrs());
        assert!(!AddrFetch.relays_txs() && AddrFetch.relays_addrs());
        assert_eq!(onion_inbound_cap(64), 16);
        assert_eq!(onion_inbound_cap(3), 1);
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
