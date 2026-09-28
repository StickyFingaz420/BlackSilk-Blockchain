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
//! anchors are still not modelled.

use blacksilk_crypto::hash::{h32, tags};
use blacksilk_p2p::addrman::{
    AddrMan, Table, BUCKET_SIZE, NEW_BUCKETS_PER_SOURCE_GROUP, TRIED_BIAS,
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
        if used.len() > 60_000 {
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

/// One outbound draw after a restart under `bias`, as `maintain_outbound`
/// makes it (routable, one per group).
fn restart_draws(
    m: &AddrMan,
    s: &Scenario,
    honest: &HashSet<NetAddr>,
    bias: f64,
    now: u64,
    rng: &mut ChaCha20Rng,
    t: &mut FeelerTally,
) {
    for _ in 0..FEELER_RESTARTS {
        let mut groups = HashSet::new();
        let mut picked: Vec<NetAddr> = Vec::new();
        for _ in 0..OUTBOUND {
            let pick = m.select_biased(rng, now, false, bias, |a| {
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
    seed: u64,
    slots: &mut HashMap<(u64, u64), FeelerTally>,
    tried: &mut HashMap<u64, TriedTally>,
) {
    let s = fs.base;
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut m = AddrMan::new(&mut rng);
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
            restart_draws(&m, &s, &honest, *bias, now, &mut rng, t);
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
            run_feelers(fs, 2000 + seed, &mut slots, &mut tried);
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
