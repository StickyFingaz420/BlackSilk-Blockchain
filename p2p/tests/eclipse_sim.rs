//! Eclipse simulator (docs/p2p.md §9; dossier 32 W8, the regression metric
//! for the address manager): a deterministic, network-free model of one
//! victim node's address table under a Sybil address flood, measuring the
//! attacker's share of the table and of the node's outbound slots.
//!
//! The model drives the real [`AddrMan`] (bucketing, collisions, selection),
//! the real [`NetAddr`] rules (groups, routability) and, for the current
//! policy, the real per-peer admission ([`AddrGate`]). Three policies are
//! compared:
//! - `2a69556`: the admission before W2-32 ([`admitted_2a69556`]) and the
//!   address manager before v2 ([`V1`]);
//! - `w2`: today's admission ([`AddrGate`]) and the address manager before
//!   v2: the baseline of addrman v2 (W3-32);
//! - `v2`: today's admission and [`AddrMan`] v2, with its *tried* bias
//!   [`TRIED_BIAS`] (`v2 0.5`: with Bitcoin Core's 0.5, for comparison).
//!
//! Scenario: `honest` reachable honest nodes are in the victim's table
//! (`honest_tried` of them in *tried*). The attacker holds `sources` IPs in
//! distinct /16s, keeps `max_per_ip` = 2 inbound connections from each, and
//! reconnects every `reconnect_secs` during `flood_secs`, announcing
//! addresses of its own spread over as many groups as possible (valid onion
//! names for an onion-only victim). Then the victim restarts: all 8 outbound
//! slots are drawn afresh as `maintain_outbound` draws them (one per group,
//! routable only). Each scenario is run on several tables (seeds) with many
//! restarts each.
//!
//! Columns: `new-att%` is the attacker's share of *new* entries, `bkt-att%`
//! its share of the non-empty *new* buckets, `bkt/src` the most *new* buckets
//! one attacker source reached, `slot-att%` its share of outbound slots,
//! `P(all8)` the probability that all 8 are the attacker's.
//!
//! This is a model, not a measurement of a live network: the attacker's
//! addresses count as attacker-controlled whether or not they accept
//! connections, and honest churn, feelers and anchors are not modelled (an
//! anchor that was honest before the restart keeps one slot honest).
//! Run with `--nocapture` for the table.
//!
//! A second model ([`eclipse_simulation_with_feelers_rederives_the_tried_bias`],
//! RTW3-10) adds feelers after the flood: attacker addresses that accept
//! connections (its own IPs, or up to 128 in distinct groups) reach *tried*,
//! one per IP, and so do honest *new* addresses; the restart draws are then
//! compared for *tried* biases 0.5 to 0.9. Regular outbound connections
//! promoting what they reach, honest address inflow after the flood and
//! anchors are not modelled there.
//!
//! W3-32c adds two: the onion rows of the feeler model under each onion
//! *tried* cap ([`eclipse_simulation_onion_tried_cap`]), and a realistic
//! model ([`eclipse_simulation_realistic_model`]): a week after the flood
//! with feelers, regular redials that promote what answers, honest address
//! inflow and continued flooding, comparing W3-32's policy with the
//! source-group *tried* cap and the rich-*tried* bias. Honest churn and an
//! attacker laundering addresses through honest relays are not modelled.

use blacksilk_crypto::hash::{h32, tags};
use blacksilk_p2p::addrman::{
    AddrMan, Table, TriedCaps, BUCKET_SIZE, NEW_BUCKETS_PER_SOURCE_GROUP, TRIED_BIAS,
    TRIED_PER_ONION_GROUP,
};
use blacksilk_p2p::addrman_gate::{AddrGate, Verdict, ADDR_RATE};
use blacksilk_p2p::NetAddr;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

const OUTBOUND: usize = 8;
const MAX_PER_IP: u64 = 2;
/// Addresses the attacker gets admitted per scenario at most: beyond the
/// *new* table's 16 384 slots, more only churns it (and costs run time).
const FLOOD_CAP: u64 = 24_000;
const SEEDS: u64 = 3;
const RESTARTS: usize = 2_000;
const NOW: u64 = 1_900_000_000;

#[derive(Clone, Copy, PartialEq)]
enum Policy {
    /// `rebuild/core` 2a69556: old admission, old table.
    Base,
    /// [`AddrGate`], old table (the addrman v2 baseline).
    W2,
    /// [`AddrGate`], [`AddrMan`] v2 with a *tried* bias.
    V2(f64),
}

impl Policy {
    fn name(self) -> String {
        match self {
            Policy::Base => "2a69556".into(),
            Policy::W2 => "w2".into(),
            Policy::V2(b) if b == TRIED_BIAS => "v2".into(),
            Policy::V2(b) => format!("v2 {b}"),
        }
    }
}

#[derive(Clone, Copy)]
struct Scenario {
    name: &'static str,
    honest: usize,
    honest_tried: usize,
    sources: u64,
    flood_secs: u64,
    reconnect_secs: u64,
    /// The victim is onion-only (every address an onion; Tor proxy).
    onion: bool,
}

/// Addresses one attacker connection of `secs` seconds gets into the table
/// under the node's `Addr` policy at `rebuild/core` 2a69556
/// (`p2p/src/net/addr_relay.rs`, `conn.rs`, `limits.rs` there):
/// - one batch of up to 1000 (`MAX_ADDRS`) addresses per connection, even
///   unsolicited and from an inbound peer;
/// - any number of messages of at most 10 addresses, limited only by the
///   message budget (`PeerLimits::messages`: 50 per second, burst 500);
/// - one address of the peer's choosing in `Version.listen`.
fn admitted_2a69556(secs: u64) -> u64 {
    1000 + 10 * (500 + 50 * secs) + 1
}

/// The same attacker connection under [`AddrGate`]: it opens with a
/// 1000-address batch, then sends a 10-address message every second (as
/// fast as the message budget allows is no better: the gate counts
/// addresses). `Version.listen` must be the connection's own address
/// (F32-8), so it adds no Sybil address.
fn admitted_current(secs: u64) -> u64 {
    let t0 = Instant::now();
    let mut g = AddrGate::new(t0);
    let mut n = 0;
    if let Verdict::Limited { admit } = g.check(1000, t0) {
        n += admit as u64;
    }
    for s in 0..secs {
        if let Verdict::Limited { admit } = g.check(10, t0 + Duration::from_secs(s)) {
            n += admit as u64;
        }
    }
    n
}

// ---------------------------------------------------------------- the v1 table

/// The address manager before v2 (`p2p/src/addrman.rs` at bff3a62), kept
/// as the baseline: one-stage bucket `H(secret ‖ table ‖ group(addr) ‖
/// group(src)) mod N`, append or evict a random entry (one that failed 3
/// times first) when the bucket is full, and selection 50/50 from *tried*
/// and *new*, uniform over entries.
struct V1 {
    secret: [u8; 32],
    new: Vec<Vec<(NetAddr, Vec<u8>)>>,
    tried: Vec<Vec<NetAddr>>,
}

impl V1 {
    fn new(rng: &mut impl RngCore) -> Self {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        Self {
            secret,
            new: vec![Vec::new(); 256],
            tried: vec![Vec::new(); 64],
        }
    }

    fn bucket(&self, table: u8, addr: &NetAddr, source_group: &[u8], n: usize) -> usize {
        let h = h32(
            tags::P2P_ADDRMAN,
            &[&self.secret, &[table], &addr.group(), source_group],
        );
        (u64::from_le_bytes(h[..8].try_into().unwrap()) % n as u64) as usize
    }

    fn contains(&self, a: &NetAddr) -> bool {
        self.new.iter().flatten().any(|(x, _)| x == a)
            || self.tried.iter().flatten().any(|x| x == a)
    }

    fn add(&mut self, addr: NetAddr, source: &NetAddr, rng: &mut impl RngCore) -> Option<usize> {
        let sg = source.group();
        let b = self.bucket(0, &addr, &sg, 256);
        let bucket = &mut self.new[b];
        if bucket.len() >= BUCKET_SIZE {
            let i = (rng.next_u32() as usize) % bucket.len();
            bucket[i] = (addr, sg);
        } else {
            bucket.push((addr, sg));
        }
        Some(b)
    }

    fn mark_good(&mut self, addr: &NetAddr) {
        for b in &mut self.new {
            b.retain(|(x, _)| x != addr);
        }
        let tb = self.bucket(1, addr, &addr.group(), 64);
        if self.tried[tb].len() < BUCKET_SIZE {
            self.tried[tb].push(addr.clone());
        }
    }

    fn len(&self) -> (usize, usize) {
        (
            self.new.iter().map(Vec::len).sum(),
            self.tried.iter().map(Vec::len).sum(),
        )
    }

    fn select(&self, rng: &mut impl RngCore, skip: impl Fn(&NetAddr) -> bool) -> Option<NetAddr> {
        let (n_new, n_tried) = self.len();
        for _ in 0..64 {
            let use_tried = n_tried > 0 && (n_new == 0 || rng.next_u32().is_multiple_of(2));
            let total = if use_tried { n_tried } else { n_new };
            if total == 0 {
                return None;
            }
            let mut k = (rng.next_u64() % total as u64) as usize;
            let lens: Vec<usize> = if use_tried {
                self.tried.iter().map(Vec::len).collect()
            } else {
                self.new.iter().map(Vec::len).collect()
            };
            for (b, len) in lens.into_iter().enumerate() {
                if k < len {
                    let e = if use_tried {
                        &self.tried[b][k]
                    } else {
                        &self.new[b][k].0
                    };
                    if !skip(e) {
                        return Some(e.clone());
                    }
                    break;
                }
                k -= len;
            }
        }
        None
    }
}

/// The table under test.
enum Table2 {
    V1(V1),
    V2(Box<AddrMan>, f64),
}

impl Table2 {
    /// Adds `a` heard from `src`; the *new* bucket it went to, if added.
    fn add(&mut self, a: NetAddr, src: &NetAddr, rng: &mut ChaCha20Rng) -> Option<usize> {
        match self {
            Table2::V1(m) => m.add(a, src, rng),
            Table2::V2(m, _) => {
                let added = m.add(a.clone(), src, NOW);
                added.then(|| m.position(&a).unwrap().1)
            }
        }
    }

    fn good(&mut self, a: &NetAddr) {
        match self {
            Table2::V1(m) => m.mark_good(a),
            Table2::V2(m, _) => {
                m.good(a, NOW);
            }
        }
    }

    fn select(&self, rng: &mut ChaCha20Rng, skip: impl Fn(&NetAddr) -> bool) -> Option<NetAddr> {
        match self {
            Table2::V1(m) => m.select(rng, skip),
            Table2::V2(m, bias) => m.select_biased(rng, NOW, false, *bias, skip),
        }
    }

    /// Every *new* entry with its bucket.
    fn new_entries(&self) -> Vec<(NetAddr, usize)> {
        match self {
            Table2::V1(m) => m
                .new
                .iter()
                .enumerate()
                .flat_map(|(b, v)| v.iter().map(move |(a, _)| (a.clone(), b)))
                .collect(),
            Table2::V2(m, _) => m
                .addresses()
                .into_iter()
                .filter(|(_, t)| *t == Table::New)
                .map(|(a, _)| {
                    let b = m.position(&a).unwrap().1;
                    (a, b)
                })
                .collect(),
        }
    }

    fn contains(&self, a: &NetAddr) -> bool {
        match self {
            Table2::V1(m) => m.contains(a),
            Table2::V2(m, _) => m.contains(a),
        }
    }
}

// ---------------------------------------------------------------- the model

fn public_v4(rng: &mut ChaCha20Rng, used: &mut HashSet<[u8; 2]>) -> NetAddr {
    loop {
        let b = rng.next_u32().to_le_bytes();
        let a = NetAddr::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])),
            1024 + (rng.next_u32() % 60_000) as u16,
        ));
        if a.is_routable() && used.insert([b[0], b[1]]) {
            return a;
        }
        // Fewer than 60 000 /16s are routable: start over well before.
        if used.len() > 40_000 {
            used.clear();
        }
    }
}

/// A valid onion address with a random key (onion names are free).
fn onion(rng: &mut ChaCha20Rng) -> NetAddr {
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    NetAddr::from_onion_key(&key, 29334)
}

#[derive(Default)]
struct Tally {
    attacker: u64,
    honest: u64,
    all_attacker: u64,
    none_honest: u64,
    restarts: u64,
    new_attacker: u64,
    new_total: u64,
    buckets_attacker: u64,
    buckets_total: u64,
    admitted: u64,
    budget: u64,
    /// The most *new* buckets one attacker source reached.
    max_buckets_per_source: u64,
    /// The most *new* entries one scenario's attacker held.
    max_new_attacker: u64,
}

fn run(s: Scenario, policy: Policy, seed: u64, t: &mut Tally) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut m = match policy {
        Policy::Base | Policy::W2 => Table2::V1(V1::new(&mut rng)),
        Policy::V2(bias) => Table2::V2(Box::new(AddrMan::new(&mut rng)), bias),
    };
    let mut used = HashSet::new();
    let mut fresh = |rng: &mut ChaCha20Rng| {
        if s.onion {
            onion(rng)
        } else {
            public_v4(rng, &mut used)
        }
    };
    let honest: Vec<NetAddr> = (0..s.honest).map(|_| fresh(&mut rng)).collect();
    for (i, h) in honest.iter().enumerate() {
        let src = &honest[(i + 1) % honest.len()];
        m.add(h.clone(), src, &mut rng);
        if i < s.honest_tried {
            m.good(h);
        }
    }
    let honest: HashSet<NetAddr> = honest.into_iter().filter(|h| m.contains(h)).collect();
    // The flood.
    let conns = MAX_PER_IP * s.flood_secs.div_ceil(s.reconnect_secs);
    let per_conn = match policy {
        Policy::Base => admitted_2a69556(s.reconnect_secs),
        Policy::W2 | Policy::V2(_) => admitted_current(s.reconnect_secs),
    };
    let budget = conns * per_conn;
    t.budget += budget * s.sources;
    let per_source = budget.min(FLOOD_CAP / s.sources);
    let sources: Vec<NetAddr> = (0..s.sources)
        .map(|_| public_v4(&mut rng, &mut HashSet::new()))
        .collect();
    for src in &sources {
        let mut reached = HashSet::new();
        for _ in 0..per_source {
            let a = fresh(&mut rng);
            if let Some(b) = m.add(a, src, &mut rng) {
                reached.insert(b);
            }
        }
        t.admitted += per_source;
        t.max_buckets_per_source = t.max_buckets_per_source.max(reached.len() as u64);
    }
    // Attacker entries: everything that is not honest (never in *tried*).
    let entries = m.new_entries();
    let mut buckets: HashMap<usize, bool> = HashMap::new();
    let mut attacker_entries = 0;
    for (a, b) in &entries {
        let bad = !honest.contains(a);
        attacker_entries += bad as u64;
        *buckets.entry(*b).or_default() |= bad;
    }
    t.new_total += entries.len() as u64;
    t.new_attacker += attacker_entries;
    t.max_new_attacker = t.max_new_attacker.max(attacker_entries);
    t.buckets_total += buckets.len() as u64;
    t.buckets_attacker += buckets.values().filter(|&&bad| bad).count() as u64;
    // Restarts: 8 fresh outbound picks each.
    for _ in 0..RESTARTS {
        let mut groups = HashSet::new();
        let mut picked: Vec<NetAddr> = Vec::new();
        for _ in 0..OUTBOUND {
            let pick = m.select(&mut rng, |a| {
                !a.is_routable()
                    || groups.contains(&a.group())
                    || picked.contains(a)
                    || a.is_onion() != s.onion
            });
            if let Some(a) = pick {
                groups.insert(a.group());
                picked.push(a);
            }
        }
        let bad = picked.iter().filter(|a| !honest.contains(*a)).count();
        t.attacker += bad as u64;
        t.honest += (picked.len() - bad) as u64;
        t.restarts += 1;
        if bad == OUTBOUND {
            t.all_attacker += 1;
        }
        if bad == picked.len() {
            t.none_honest += 1;
        }
    }
}

struct Row {
    slot_share: f64,
    p_all8: f64,
    max_buckets_per_source: u64,
    max_new_attacker: u64,
}

#[test]
fn eclipse_simulation_attacker_share_of_outbound_slots() {
    let ipv4 = |name, honest_tried, sources, reconnect_secs| Scenario {
        name,
        honest: 50,
        honest_tried,
        sources,
        flood_secs: 600,
        reconnect_secs,
        onion: false,
    };
    let scenarios = [
        ipv4("ipv4 g=1 10min", 16, 1, 60),
        ipv4("ipv4 g=4 10min", 16, 4, 60),
        ipv4("ipv4 g=4 empty-tried", 0, 4, 60),
        // Reconnecting every second: each new connection starts with one
        // token, so connection churn is the residual flood rate.
        ipv4("ipv4 g=4 churn-1s", 16, 4, 1),
        ipv4("ipv4 g=4 churn empty", 0, 4, 1),
        Scenario {
            name: "onion g=1 10min",
            honest: 20,
            honest_tried: 8,
            sources: 1,
            flood_secs: 600,
            reconnect_secs: 60,
            onion: true,
        },
    ];
    let policies = [
        Policy::Base,
        Policy::W2,
        Policy::V2(TRIED_BIAS),
        Policy::V2(0.5),
    ];
    println!(
        "{:<22} {:<8} {:>9} {:>9} {:>6} {:>9} {:>9} {:>7} {:>10} {:>8} {:>8}",
        "scenario",
        "policy",
        "budget",
        "admitted",
        "new",
        "new-att%",
        "bkt-att%",
        "bkt/src",
        "slot-att%",
        "P(all8)",
        "P(0 hon)"
    );
    let mut rows: HashMap<(&str, String), Row> = HashMap::new();
    for s in scenarios {
        for policy in policies {
            let mut t = Tally::default();
            for seed in 0..SEEDS {
                run(s, policy, 1000 + seed, &mut t);
            }
            let filled = (t.attacker + t.honest).max(1);
            let share = t.attacker as f64 / filled as f64;
            let p_all8 = t.all_attacker as f64 / t.restarts as f64;
            println!(
                "{:<22} {:<8} {:>9} {:>9} {:>6} {:>8.1}% {:>8.1}% {:>7} {:>9.1}% {:>8.4} {:>8.4}",
                s.name,
                policy.name(),
                t.budget / SEEDS,
                t.admitted / SEEDS,
                t.new_total / SEEDS,
                100.0 * t.new_attacker as f64 / t.new_total.max(1) as f64,
                100.0 * t.buckets_attacker as f64 / t.buckets_total.max(1) as f64,
                t.max_buckets_per_source,
                100.0 * share,
                p_all8,
                t.none_honest as f64 / t.restarts as f64,
            );
            assert!((0.0..=1.0).contains(&share));
            assert_eq!(t.restarts, SEEDS * RESTARTS as u64);
            rows.insert(
                (s.name, policy.name()),
                Row {
                    slot_share: share,
                    p_all8,
                    max_buckets_per_source: t.max_buckets_per_source,
                    max_new_attacker: t.max_new_attacker,
                },
            );
        }
    }
    for s in scenarios {
        let w2 = &rows[&(s.name, Policy::W2.name())];
        let v2 = &rows[&(s.name, Policy::V2(TRIED_BIAS).name())];
        // W1: one attacker source reaches at most 16 *new* buckets, so at
        // most 16 × 64 entries; before v2 it reached them all.
        assert!(
            v2.max_buckets_per_source <= NEW_BUCKETS_PER_SOURCE_GROUP,
            "{}: {}",
            s.name,
            v2.max_buckets_per_source
        );
        assert!(
            v2.max_new_attacker <= s.sources * NEW_BUCKETS_PER_SOURCE_GROUP * BUCKET_SIZE as u64
        );
        // Never worse than the baseline.
        assert!(
            v2.slot_share <= w2.slot_share && v2.p_all8 <= w2.p_all8,
            "{}: v2 {:.3}/{:.4} vs w2 {:.3}/{:.4}",
            s.name,
            v2.slot_share,
            v2.p_all8,
            w2.slot_share,
            w2.p_all8
        );
        if s.onion {
            // Onion groups are 16 (the first 4 key bits): one attacker
            // source group reaches at most 16 *new* buckets with them.
            assert!(w2.max_new_attacker <= 16 * BUCKET_SIZE as u64);
        }
    }
    // The acceptance bar (W3-32): a large improvement where the attacker has
    // one or four sources and the node a *tried* table.
    for name in ["ipv4 g=1 10min", "ipv4 g=4 10min"] {
        let w2 = &rows[&(name, Policy::W2.name())];
        let v2 = &rows[&(name, Policy::V2(TRIED_BIAS).name())];
        assert!(
            v2.slot_share <= w2.slot_share / 2.0,
            "{name}: v2 {:.3} vs w2 {:.3}",
            v2.slot_share,
            w2.slot_share
        );
    }
    // The admission bound: per connection of `secs` seconds, one address to
    // start with plus ADDR_RATE per second, and no unsolicited batch.
    for secs in [1u64, 60, 600, 3600] {
        let bound = 1 + (secs as f64 * ADDR_RATE) as u64;
        assert!(admitted_current(secs) <= bound, "{secs} s");
    }
}

// ---------------------------------------------------------------- feelers (RTW3-10)

/// Feelers after the flood, one every [`FEELER_SECS`] (their mean
/// interval): the *tried* table the restart draws from is no longer only
/// the honest addresses the node connected to before the attack.
const FEELER_SECS: u64 = 120;
/// Feeler horizons: none, one day, one week.
const FEELER_HORIZONS: [u64; 3] = [0, 720, 5040];
/// The *tried* biases compared.
const BIASES: [f64; 5] = [0.5, 0.6, 0.7, 0.8, 0.9];
const FEELER_RESTARTS: usize = 1_000;

/// A flood scenario plus `answering` attacker addresses that accept
/// connections (so a feeler promotes them to *tried*).
#[derive(Clone, Copy)]
struct FeelerScenario {
    base: Scenario,
    /// Attacker addresses that answer. `None`: the attacker's own source
    /// IPs (the connections it floods from); `Some(n)`: `n` addresses in
    /// distinct groups (IPv4 /16s, or free onion names), announced first.
    answering: Option<u64>,
}

/// Per (scenario, horizon, bias): outbound slot tallies; per (scenario,
/// horizon): the *tried* table's make-up.
#[derive(Default, Clone)]
struct FeelerTally {
    attacker: u64,
    honest: u64,
    all_attacker: u64,
    restarts: u64,
}

#[derive(Default, Clone)]
struct TriedTally {
    honest_tried: u64,
    attacker_tried: u64,
    answering: u64,
    runs: u64,
}

/// `n` outbound draws after a restart under `bias`, as `maintain_outbound`
/// makes them (routable, one per group).
#[allow(clippy::too_many_arguments)]
fn restart_draws(
    m: &AddrMan,
    s: &Scenario,
    honest: &HashSet<NetAddr>,
    bias: Option<f64>,
    now: u64,
    rng: &mut ChaCha20Rng,
    t: &mut FeelerTally,
    n: usize,
) {
    for _ in 0..n {
        let mut groups = HashSet::new();
        let mut picked: Vec<NetAddr> = Vec::new();
        for _ in 0..OUTBOUND {
            let pick = draw(m, rng, now, bias, |a| {
                !a.is_routable()
                    || groups.contains(&a.group())
                    || picked.contains(a)
                    || a.is_onion() != s.onion
            });
            if let Some(a) = pick {
                groups.insert(a.group());
                picked.push(a);
            }
        }
        let bad = picked.iter().filter(|a| !honest.contains(*a)).count();
        t.attacker += bad as u64;
        t.honest += (picked.len() - bad) as u64;
        t.restarts += 1;
        if bad == OUTBOUND {
            t.all_attacker += 1;
        }
    }
}

/// One scenario on one table (seed): the flood as in [`run`] (the current
/// admission, addrman v2), the answering addresses announced first; then
/// feelers as `maintain_outbound` makes them since RTW3-2 and RTW3-9 (the
/// slots are full, so one is due every [`FEELER_SECS`]): a waiting *tried*
/// collision's occupant is tested first, whatever its group or last attempt,
/// else a routable *new* address. An address that answers (honest, or
/// attacker-answering) moves to *tried*; one that does not is charged an
/// attempt. At each horizon the restart draws are measured for every bias.
fn run_feelers(
    fs: FeelerScenario,
    caps: TriedCaps,
    seed: u64,
    slots: &mut HashMap<(u64, u64), FeelerTally>,
    tried: &mut HashMap<u64, TriedTally>,
) {
    let s = fs.base;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut m = AddrMan::new(&mut rng);
    m.set_tried_caps(caps);
    let mut used = HashSet::new();
    let mut fresh = |rng: &mut ChaCha20Rng| {
        if s.onion {
            onion(rng)
        } else {
            public_v4(rng, &mut used)
        }
    };
    let honest: Vec<NetAddr> = (0..s.honest).map(|_| fresh(&mut rng)).collect();
    for (i, h) in honest.iter().enumerate() {
        let src = &honest[(i + 1) % honest.len()];
        m.add(h.clone(), src, NOW);
        if i < s.honest_tried {
            m.good(h, NOW);
        }
    }
    let honest: HashSet<NetAddr> = honest.into_iter().filter(|h| m.contains(h)).collect();
    let sources: Vec<NetAddr> = (0..s.sources)
        .map(|_| public_v4(&mut rng, &mut HashSet::new()))
        .collect();
    // The answering addresses, announced first (each costs one admitted
    // address of its source's budget).
    let answering: Vec<NetAddr> = match fs.answering {
        None => sources.clone(),
        Some(n) => (0..n).map(|_| fresh(&mut rng)).collect(),
    };
    let conns = MAX_PER_IP * s.flood_secs.div_ceil(s.reconnect_secs);
    let per_source = (conns * admitted_current(s.reconnect_secs)).min(FLOOD_CAP / s.sources);
    let mut left: Vec<u64> = vec![per_source; sources.len()];
    for (i, a) in answering.iter().enumerate() {
        let k = i % sources.len();
        if left[k] > 0 {
            // A source announcing its own address is a relayed `Addr`
            // entry, not `Version.listen` (F32-8): it takes the same path.
            m.add(a.clone(), &sources[(k + 1) % sources.len()], NOW);
            left[k] -= 1;
        }
    }
    for (src, n) in sources.iter().zip(left) {
        for _ in 0..n {
            let a = fresh(&mut rng);
            m.add(a, src, NOW);
        }
    }
    let answers: HashSet<NetAddr> = answering.iter().cloned().collect();
    let mut done = 0;
    for horizon in FEELER_HORIZONS {
        while done < horizon {
            done += 1;
            let now = NOW + s.flood_secs + done * FEELER_SECS;
            m.resolve_collisions(now);
            let pick = m.select_tried_collision(&mut rng).or_else(|| {
                m.select(&mut rng, now, true, |a| {
                    !a.is_routable() || a.is_onion() != s.onion
                })
            });
            if let Some(a) = pick {
                m.attempt(&a, now);
                if honest.contains(&a) || answers.contains(&a) {
                    m.good(&a, now);
                }
            }
        }
        let now = NOW + s.flood_secs + horizon * FEELER_SECS + 1;
        let in_tried: Vec<NetAddr> = m
            .addresses()
            .into_iter()
            .filter(|(_, t)| *t == Table::Tried)
            .map(|(a, _)| a)
            .collect();
        let tt = tried.entry(horizon).or_default();
        let attacker_tried = in_tried.iter().filter(|a| !honest.contains(*a)).count() as u64;
        tt.attacker_tried += attacker_tried;
        tt.honest_tried += in_tried.len() as u64 - attacker_tried;
        tt.answering += answering.len() as u64;
        tt.runs += 1;
        // One *tried* entry per IP, and only answering addresses get there.
        assert!(in_tried
            .iter()
            .all(|a| honest.contains(a) || answers.contains(a)));
        assert!(attacker_tried <= answering.len() as u64);
        for (i, bias) in BIASES.iter().enumerate() {
            let t = slots.entry((horizon, i as u64)).or_default();
            restart_draws(
                &m,
                &s,
                &honest,
                Some(*bias),
                now,
                &mut rng,
                t,
                FEELER_RESTARTS,
            );
        }
    }
    m.check().unwrap();
}

/// RTW3-10: the *tried* bias re-derived with feelers modelled (after RTW3-2
/// they actually run, and RTW3-9 lets them test collisions whatever the
/// group). Attacker addresses that answer reach *tried* through feelers,
/// one per IP; honest *new* addresses do too. The table prints, per
/// scenario and horizon, the *tried* make-up and the attacker's outbound
/// share and P(all 8) for each bias. Run with `--nocapture`.
#[test]
fn eclipse_simulation_with_feelers_rederives_the_tried_bias() {
    let ipv4 = |name, honest_tried, sources| Scenario {
        name,
        honest: 50,
        honest_tried,
        sources,
        flood_secs: 600,
        reconnect_secs: 60,
        onion: false,
    };
    let onion_s = Scenario {
        name: "onion g=1",
        honest: 20,
        honest_tried: 8,
        sources: 1,
        flood_secs: 600,
        reconnect_secs: 60,
        onion: true,
    };
    let mut scenarios = Vec::new();
    for base in [
        ipv4("ipv4 g=1", 16, 1),
        ipv4("ipv4 g=4", 16, 4),
        ipv4("ipv4 g=4 empty-tried", 0, 4),
    ] {
        for answering in [None, Some(32), Some(128)] {
            scenarios.push(FeelerScenario { base, answering });
        }
    }
    for answering in [Some(32), Some(128)] {
        scenarios.push(FeelerScenario {
            base: onion_s,
            answering,
        });
    }
    print!(
        "{:<22} {:>5} {:>7} {:>8} {:>8}",
        "scenario", "ans", "feelers", "hon-tr", "att-tr"
    );
    for b in BIASES {
        print!(" {:>13}", format!("slot%/all8@{b}"));
    }
    println!();
    for fs in scenarios {
        let mut slots = HashMap::new();
        let mut tried = HashMap::new();
        for seed in 0..SEEDS {
            run_feelers(
                fs,
                TriedCaps::default(),
                2000 + seed,
                &mut slots,
                &mut tried,
            );
        }
        for horizon in FEELER_HORIZONS {
            let tt = &tried[&horizon];
            print!(
                "{:<22} {:>5} {:>7} {:>8.1} {:>8.1}",
                fs.base.name,
                tt.answering / tt.runs,
                horizon,
                tt.honest_tried as f64 / tt.runs as f64,
                tt.attacker_tried as f64 / tt.runs as f64,
            );
            let share_at = |i: usize| {
                let t: &FeelerTally = &slots[&(horizon, i as u64)];
                t.attacker as f64 / (t.attacker + t.honest).max(1) as f64
            };
            // The chosen bias is never worse than Bitcoin Core's 0.5 (one
            // point of sampling noise allowed).
            let ours = BIASES.iter().position(|b| *b == TRIED_BIAS).unwrap();
            assert!(
                share_at(ours) <= share_at(0) + 0.01,
                "{} ans {} feelers {horizon}: {:.3} vs {:.3}",
                fs.base.name,
                tt.answering / tt.runs,
                share_at(ours),
                share_at(0)
            );
            for i in 0..BIASES.len() {
                let t = &slots[&(horizon, i as u64)];
                let share = share_at(i);
                assert!((0.0..=1.0).contains(&share));
                print!(
                    " {:>13}",
                    format!(
                        "{:.1}/{:.3}",
                        100.0 * share,
                        t.all_attacker as f64 / t.restarts as f64
                    )
                );
            }
            println!();
        }
    }
}

// ---------------------------------------------------------------- onion tried cap (W3-32c)

/// Onion *tried* caps compared (`usize::MAX`: no cap, before W3-32c).
const ONION_CAPS: [usize; 5] = [usize::MAX, 1, 2, 4, 8];

fn cap_name(c: usize) -> String {
    if c == usize::MAX {
        "none".into()
    } else {
        c.to_string()
    }
}

/// W3-32c item 1: the onion rows of the feeler model under each onion
/// *tried* cap. Before the cap an onion attacker had no per-entry cost: every
/// answering onion it announced could reach *tried*. The cap bounds its
/// *tried* entries to 16 × cap whatever it announces; the honest-only rows
/// show what the cap costs an onion node whose honest peers outnumber it.
/// Run with `--nocapture` for the table.
#[test]
fn eclipse_simulation_onion_tried_cap() {
    let onion = |name, honest, honest_tried| Scenario {
        name,
        honest,
        honest_tried,
        sources: 1,
        flood_secs: 600,
        reconnect_secs: 60,
        onion: true,
    };
    let scenarios = [
        FeelerScenario {
            base: onion("onion g=1", 20, 8),
            answering: Some(32),
        },
        FeelerScenario {
            base: onion("onion g=1", 20, 8),
            answering: Some(128),
        },
        FeelerScenario {
            base: onion("onion honest-only", 100, 8),
            answering: Some(0),
        },
    ];
    let ours = BIASES.iter().position(|b| *b == TRIED_BIAS).unwrap();
    println!(
        "{:<18} {:>4} {:>5} {:>7} {:>8} {:>8} {:>14}",
        "scenario", "cap", "ans", "feelers", "hon-tr", "att-tr", "slot%/all8"
    );
    // (scenario, cap) -> (share, P(all 8), attacker tried, honest tried)
    // after a week of feelers.
    let mut week: HashMap<(usize, usize), (f64, f64, f64, f64)> = HashMap::new();
    for (k, fs) in scenarios.iter().enumerate() {
        for cap in ONION_CAPS {
            let caps = TriedCaps {
                onion_group: cap,
                source_group: usize::MAX,
            };
            let mut slots = HashMap::new();
            let mut tried = HashMap::new();
            for seed in 0..SEEDS {
                run_feelers(*fs, caps, 2000 + seed, &mut slots, &mut tried);
            }
            for horizon in FEELER_HORIZONS {
                let tt = &tried[&horizon];
                let t = &slots[&(horizon, ours as u64)];
                let share = t.attacker as f64 / (t.attacker + t.honest).max(1) as f64;
                let all8 = t.all_attacker as f64 / t.restarts as f64;
                let att = tt.attacker_tried as f64 / tt.runs as f64;
                let hon = tt.honest_tried as f64 / tt.runs as f64;
                println!(
                    "{:<18} {:>4} {:>5} {:>7} {:>8.1} {:>8.1} {:>14}",
                    fs.base.name,
                    cap_name(cap),
                    tt.answering / tt.runs,
                    horizon,
                    hon,
                    att,
                    format!("{:.1}/{:.3}", 100.0 * share, all8)
                );
                if cap != usize::MAX {
                    assert!(
                        att <= 16.0 * cap as f64,
                        "{} cap {cap}: {att}",
                        fs.base.name
                    );
                }
                if horizon == *FEELER_HORIZONS.last().unwrap() {
                    week.insert((k, cap), (share, all8, att, hon));
                }
            }
        }
    }
    let chosen = TRIED_PER_ONION_GROUP;
    for k in 0..2 {
        let (none, capped) = (week[&(k, usize::MAX)], week[&(k, chosen)]);
        // The cap bounds the attacker's *tried* entries, and at least a
        // third of its outbound share goes.
        assert!(capped.2 <= 16.0 * chosen as f64 && capped.2 < none.2);
        assert!(
            capped.0 <= none.0 * 2.0 / 3.0 && capped.1 <= none.1,
            "scenario {k}: {:.3}/{:.3} vs {:.3}/{:.3}",
            capped.0,
            capped.1,
            none.0,
            none.1
        );
    }
    // With no answering attacker address the cap costs little: the
    // attacker's share of the slots rises by at most 5 points.
    let (none, capped) = (week[&(2, usize::MAX)], week[&(2, chosen)]);
    assert!(
        capped.0 <= none.0 + 0.05,
        "{:.3} vs {:.3}",
        capped.0,
        none.0
    );
}

// ---------------------------------------------------------------- the realistic model (W3-32c item 2)

/// One step of the realistic model is one feeler (their mean interval).
const STEP_SECS: u64 = 120;
/// One outbound slot is redrawn about this often (honest peers restarting,
/// attacker peers leaving to force a redraw, stale-tip rotation): a slot
/// lasts about 4 hours.
const DIAL_SECS: u64 = 1800;
/// A new honest node's address reaches the victim this often, relayed by an
/// honest peer (honest address inflow: nodes joining).
const JOIN_SECS: u64 = 3600;
/// Every honest node's address is heard again about once a day (its own
/// re-advertisement, relayed; Bitcoin Core re-advertises every 24 hours).
const READVERTISE_SECS: u64 = 24 * 3600;
/// Attacker addresses admitted per source per hour after the flood: it keeps
/// flooding within the admission limits (a fraction of what they allow), so
/// its addresses that fail and turn terrible are replaced.
const FLOOD_PER_HOUR: u64 = 100;
/// The honest peers the victim learned its honest addresses from (its
/// outbound peers' `GetAddr` answers): the source groups of those entries.
const HONEST_SOURCES: usize = 8;
/// Days after the flood at which the table and the slots are measured.
const REAL_DAYS: [u64; 3] = [0, 1, 7];
const REAL_RESTARTS: usize = 500;
const REAL_SEEDS: u64 = 5;

/// A policy variant: *tried* caps and bias (`None`: the node's own,
/// `AddrMan::tried_bias`).
#[derive(Clone, Copy)]
struct Mitigation {
    name: &'static str,
    caps: TriedCaps,
    bias: Option<f64>,
}

/// One draw as `maintain_outbound` makes it, under `bias` (`None`: the
/// node's own).
fn draw(
    m: &AddrMan,
    rng: &mut ChaCha20Rng,
    now: u64,
    bias: Option<f64>,
    skip: impl Fn(&NetAddr) -> bool,
) -> Option<NetAddr> {
    match bias {
        Some(b) => m.select_biased(rng, now, false, b, skip),
        None => m.select(rng, now, false, skip),
    }
}

#[derive(Default, Clone)]
struct RealTally {
    new_honest: u64,
    new_total: u64,
    tried_honest: u64,
    tried_attacker: u64,
    /// The victim's live outbound slots, sampled every hour since the
    /// previous measurement.
    live_attacker: u64,
    live_total: u64,
    restart: FeelerTally,
    runs: u64,
}

impl RealTally {
    fn live_share(&self) -> f64 {
        self.live_attacker as f64 / self.live_total.max(1) as f64
    }

    fn restart_share(&self) -> f64 {
        let r = &self.restart;
        r.attacker as f64 / (r.attacker + r.honest).max(1) as f64
    }

    fn all8(&self) -> f64 {
        self.restart.all_attacker as f64 / self.restart.restarts.max(1) as f64
    }

    fn new_honest_share(&self) -> f64 {
        self.new_honest as f64 / self.new_total.max(1) as f64
    }
}

/// Whether `a` accepts connections: honest, or an answering attacker address.
fn answers(a: &NetAddr, honest: &HashSet<NetAddr>, answering: &HashSet<NetAddr>) -> bool {
    honest.contains(a) || answering.contains(a)
}

/// A regular outbound dial as `maintain_outbound` makes it: routable, one
/// per group, not connected; an address that answers is connected and
/// promoted (`AddrMan::good`), one that does not is charged an attempt and
/// the next one is drawn.
#[allow(clippy::too_many_arguments)]
fn dial(
    m: &mut AddrMan,
    out: &mut Vec<NetAddr>,
    onion: bool,
    bias: Option<f64>,
    now: u64,
    rng: &mut ChaCha20Rng,
    honest: &HashSet<NetAddr>,
    answering: &HashSet<NetAddr>,
) {
    for _ in 0..32 {
        let groups: HashSet<Vec<u8>> = out.iter().map(NetAddr::group).collect();
        let pick = draw(m, rng, now, bias, |a| {
            !a.is_routable()
                || groups.contains(&a.group())
                || out.contains(a)
                || a.is_onion() != onion
        });
        let Some(a) = pick else { return };
        m.attempt(&a, now);
        if answers(&a, honest, answering) {
            m.good(&a, now);
            out.push(a);
            return;
        }
    }
}

/// The realistic model: the flood of [`run_feelers`], then a week in steps
/// of [`STEP_SECS`]. Every step one feeler runs (a waiting collision's
/// occupant first, else a *new* address outside the outbound groups) and
/// the outbound peers keep their entries fresh (`AddrMan::connected`).
/// Every [`DIAL_SECS`] one outbound slot is redrawn by a regular dial,
/// which promotes what answers. Honest address inflow: a new honest node
/// every [`JOIN_SECS`], and every honest address heard again every
/// [`READVERTISE_SECS`], each from a random honest node. The attacker keeps
/// flooding [`FLOOD_PER_HOUR`] addresses per source. The honest addresses
/// known before the flood come from [`HONEST_SOURCES`] peers. At each of
/// [`REAL_DAYS`]: the make-up of both tables, the attacker's share of the
/// live outbound slots (sampled hourly over the period) and of the slots
/// after a restart.
fn run_realistic(
    fs: FeelerScenario,
    mit: Mitigation,
    seed: u64,
    tally: &mut HashMap<u64, RealTally>,
) {
    let s = fs.base;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut m = AddrMan::new(&mut rng);
    m.set_tried_caps(mit.caps);
    let mut used = HashSet::new();
    let mut fresh = |rng: &mut ChaCha20Rng| {
        if s.onion {
            onion(rng)
        } else {
            public_v4(rng, &mut used)
        }
    };
    let mut honest_list: Vec<NetAddr> = (0..s.honest).map(|_| fresh(&mut rng)).collect();
    for (i, h) in honest_list.iter().enumerate() {
        let src = &honest_list[i % HONEST_SOURCES];
        m.add(h.clone(), src, NOW);
        if i < s.honest_tried {
            m.good(h, NOW);
        }
    }
    let mut honest: HashSet<NetAddr> = honest_list.iter().cloned().collect();
    let sources: Vec<NetAddr> = (0..s.sources)
        .map(|_| public_v4(&mut rng, &mut HashSet::new()))
        .collect();
    let answering_list: Vec<NetAddr> = match fs.answering {
        None => sources.clone(),
        Some(n) => (0..n).map(|_| fresh(&mut rng)).collect(),
    };
    let conns = MAX_PER_IP * s.flood_secs.div_ceil(s.reconnect_secs);
    let per_source = (conns * admitted_current(s.reconnect_secs)).min(FLOOD_CAP / s.sources);
    let mut left: Vec<u64> = vec![per_source; sources.len()];
    for (i, a) in answering_list.iter().enumerate() {
        let k = i % sources.len();
        if left[k] > 0 {
            m.add(a.clone(), &sources[(k + 1) % sources.len()], NOW);
            left[k] -= 1;
        }
    }
    for (src, n) in sources.iter().zip(left) {
        for _ in 0..n {
            let a = fresh(&mut rng);
            m.add(a, src, NOW);
        }
    }
    let answering: HashSet<NetAddr> = answering_list.iter().cloned().collect();
    let t0 = NOW + s.flood_secs;
    // The outbound peers right after the flood: drawn as after a restart.
    let mut out: Vec<NetAddr> = Vec::new();
    while out.len() < OUTBOUND {
        let before = out.len();
        dial(
            &mut m, &mut out, s.onion, mit.bias, t0, &mut rng, &honest, &answering,
        );
        if out.len() == before {
            break;
        }
    }
    let per_hour = 3600 / STEP_SECS;
    let readvertise_every = READVERTISE_SECS / STEP_SECS;
    let mut step = 0;
    let (mut live_attacker, mut live_total) = (0u64, 0u64);
    for day in REAL_DAYS {
        while step < day * 24 * per_hour {
            step += 1;
            let now = t0 + step * STEP_SECS;
            for a in &out {
                m.connected(a, now);
            }
            m.resolve_collisions(now);
            // The feeler.
            let groups: HashSet<Vec<u8>> = out.iter().map(NetAddr::group).collect();
            let pick = m.select_tried_collision(&mut rng).or_else(|| {
                m.select(&mut rng, now, true, |a| {
                    !a.is_routable()
                        || groups.contains(&a.group())
                        || out.contains(a)
                        || a.is_onion() != s.onion
                })
            });
            if let Some(a) = pick {
                m.attempt(&a, now);
                if answers(&a, &honest, &answering) {
                    m.good(&a, now);
                }
            }
            // A regular dial replaces one outbound peer.
            if step % (DIAL_SECS / STEP_SECS) == 0 && !out.is_empty() {
                let i = (rng.next_u64() % out.len() as u64) as usize;
                out.swap_remove(i);
                dial(
                    &mut m, &mut out, s.onion, mit.bias, now, &mut rng, &honest, &answering,
                );
            }
            // Honest inflow: a node joins; addresses are heard again.
            if step % (JOIN_SECS / STEP_SECS) == 0 {
                let h = fresh(&mut rng);
                let src = honest_list[(rng.next_u64() % honest_list.len() as u64) as usize].clone();
                m.add(h.clone(), &src, now);
                honest.insert(h.clone());
                honest_list.push(h);
            }
            for (j, h) in honest_list.iter().enumerate() {
                if j as u64 % readvertise_every == step % readvertise_every {
                    let src = &honest_list[(rng.next_u64() % honest_list.len() as u64) as usize];
                    m.add(h.clone(), src, now);
                }
            }
            // The attacker keeps flooding; the live slots are sampled.
            if step % per_hour == 0 {
                for src in &sources {
                    for _ in 0..FLOOD_PER_HOUR {
                        let a = fresh(&mut rng);
                        m.add(a, src, now);
                    }
                }
                live_attacker += out.iter().filter(|a| !honest.contains(*a)).count() as u64;
                live_total += OUTBOUND as u64;
            }
        }
        let now = t0 + step * STEP_SECS + 1;
        let t = tally.entry(day).or_default();
        for (a, table) in m.addresses() {
            let h = honest.contains(&a);
            match table {
                Table::New => {
                    t.new_total += 1;
                    t.new_honest += h as u64;
                }
                Table::Tried => {
                    t.tried_honest += h as u64;
                    t.tried_attacker += !h as u64;
                }
            }
        }
        t.live_attacker += live_attacker;
        t.live_total += live_total;
        (live_attacker, live_total) = (0, 0);
        restart_draws(
            &m,
            &s,
            &honest,
            mit.bias,
            now,
            &mut rng,
            &mut t.restart,
            REAL_RESTARTS,
        );
        t.runs += 1;
    }
    m.check().unwrap();
}

/// W3-32c item 2: the realistic model's table, per scenario, policy
/// variant and day: the honest share of *new*, the *tried* make-up, the
/// attacker's share of the live outbound slots over the period and of the
/// slots after a restart (and P(all 8)). Run with `--nocapture`.
#[test]
fn eclipse_simulation_realistic_model() {
    let scen = |name, honest, honest_tried, sources, onion, answering| FeelerScenario {
        base: Scenario {
            name,
            honest,
            honest_tried,
            sources,
            flood_secs: 600,
            reconnect_secs: 60,
            onion,
        },
        answering,
    };
    let scenarios = [
        scen("ipv4 g=1", 50, 16, 1, false, None),
        scen("ipv4 g=4", 50, 16, 4, false, None),
        scen("ipv4 g=4", 50, 16, 4, false, Some(32)),
        scen("ipv4 g=4", 50, 16, 4, false, Some(128)),
        scen("ipv4 g=4 empty-tried", 50, 0, 4, false, Some(32)),
        scen("ipv4 honest-200 g=1", 200, 16, 1, false, None),
        scen("onion g=1", 20, 8, 1, true, Some(128)),
    ];
    let caps = |source_group| TriedCaps {
        source_group,
        ..TriedCaps::default()
    };
    // W3-32 (before W3-32c) with the onion cap, each change alone, and the
    // chosen defaults.
    let before = Mitigation {
        name: "w3-32",
        caps: caps(usize::MAX),
        bias: Some(0.7),
    };
    let chosen = Mitigation {
        name: "chosen",
        caps: TriedCaps::default(),
        bias: None,
    };
    let mitigations = [
        before,
        Mitigation {
            name: "src 8",
            caps: caps(8),
            bias: Some(0.7),
        },
        Mitigation {
            name: "src 16",
            caps: caps(16),
            bias: Some(0.7),
        },
        Mitigation {
            name: "src 32",
            caps: caps(32),
            bias: Some(0.7),
        },
        Mitigation {
            name: "bias 0.9",
            caps: caps(usize::MAX),
            bias: Some(0.9),
        },
        chosen,
    ];
    println!(
        "{:<22} {:>4} {:<9} {:>3} {:>8} {:>7} {:>7} {:>9} {:>14}",
        "scenario",
        "ans",
        "policy",
        "day",
        "new-hon%",
        "hon-tr",
        "att-tr",
        "live-att%",
        "restart%/all8"
    );
    let week = *REAL_DAYS.last().unwrap();
    let mut rows: HashMap<(usize, &str), RealTally> = HashMap::new();
    for (k, fs) in scenarios.iter().copied().enumerate() {
        for mit in mitigations {
            let mut tally = HashMap::new();
            for seed in 0..REAL_SEEDS {
                run_realistic(fs, mit, 3000 + seed, &mut tally);
            }
            for day in REAL_DAYS {
                let t = &tally[&day];
                let runs = t.runs.max(1) as f64;
                println!(
                    "{:<22} {:>4} {:<11} {:>3} {:>7.1}% {:>7.1} {:>7.1} {:>8.1}% {:>14}",
                    fs.base.name,
                    fs.answering.map_or("own".to_string(), |n| n.to_string()),
                    mit.name,
                    day,
                    100.0 * t.new_honest_share(),
                    t.tried_honest as f64 / runs,
                    t.tried_attacker as f64 / runs,
                    100.0 * t.live_share(),
                    format!("{:.1}/{:.3}", 100.0 * t.restart_share(), t.all8()),
                );
            }
            rows.insert((k, mit.name), tally[&week].clone());
        }
    }
    // The drain: after a week of feelers, *new* holds almost no honest
    // address in every IPv4 flood scenario under W3-32's policy.
    assert!(rows[&(0, before.name)].new_honest_share() < 0.05);
    // The chosen policy lowers the attacker's share of the slots after a
    // restart in every scenario (up to two points of sampling noise), and
    // never raises P(all 8) (up to 0.002).
    for (k, fs) in scenarios.iter().enumerate() {
        let (b, c) = (&rows[&(k, before.name)], &rows[&(k, chosen.name)]);
        assert!(
            c.restart_share() <= b.restart_share() + 0.02 && c.all8() <= b.all8() + 0.002,
            "{} {:?}: {:.3}/{:.4} vs {:.3}/{:.4}",
            fs.base.name,
            fs.answering,
            c.restart_share(),
            c.all8(),
            b.restart_share(),
            b.all8()
        );
    }
    // Where the attacker's addresses answer from its own IPs, the share
    // falls by at least a third.
    for k in [0, 1] {
        let (b, c) = (&rows[&(k, before.name)], &rows[&(k, chosen.name)]);
        assert!(c.restart_share() <= b.restart_share() * 2.0 / 3.0);
    }
}
