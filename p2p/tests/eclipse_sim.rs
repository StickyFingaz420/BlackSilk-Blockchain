//! Eclipse simulator (docs/p2p.md §9; dossier 32 W8): a deterministic,
//! network-free model of one victim node's address table under a Sybil
//! address flood, measuring the attacker's share of the node's outbound
//! slots.
//!
//! The model drives the real [`AddrMan`] (bucketing, eviction, selection) and
//! the real [`NetAddr`] rules (groups, routability). What a peer can get into
//! the table per connection is the node's `Addr` admission policy; the policy
//! of the code under test is modelled in [`admitted`], with the numbers taken
//! from the source (named there).
//!
//! Scenario: `honest` reachable honest nodes are in the victim's table
//! (`honest_tried` of them in *tried*). The attacker holds `sources` IPs in
//! distinct /16s, keeps `max_per_ip` = 2 inbound connections from each, and
//! reconnects every `reconnect_secs` during `flood_secs`, announcing
//! addresses of its own spread over as many groups as possible. Then the
//! victim restarts: all 8 outbound slots are drawn afresh as
//! `maintain_outbound` draws them (one per group, routable only). Each
//! scenario is run on several tables (seeds) with many restarts each.
//!
//! This is a model, not a measurement of a live network: the attacker's
//! addresses count as attacker-controlled whether or not they accept
//! connections, and honest churn, feelers and anchors are not modelled.
//! Run with `--nocapture` for the table.

use blacksilk_p2p::addrman::AddrMan;
use blacksilk_p2p::NetAddr;
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const OUTBOUND: usize = 8;
const MAX_PER_IP: u64 = 2;
/// Addresses the attacker gets admitted per scenario at most: beyond the
/// *new* table's 16 384 slots, more only churns it (and costs run time).
const FLOOD_CAP: u64 = 24_000;
const SEEDS: u64 = 3;
const RESTARTS: usize = 2_000;

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
/// (`p2p/src/net/addr_relay.rs`, `conn.rs`, `limits.rs`):
/// - one batch of up to 1000 (`MAX_ADDRS`) addresses per connection, even
///   unsolicited and from an inbound peer;
/// - any number of messages of at most 10 addresses, limited only by the
///   message budget (`PeerLimits::messages`: 50 per second, burst 500);
/// - one address of the peer's choosing in `Version.listen`.
fn admitted(secs: u64) -> u64 {
    1000 + 10 * (500 + 50 * secs) + 1
}

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

/// An onion address with random (not necessarily valid v3) name: the model
/// needs only its group, which depends on the name's first character.
fn onion(rng: &mut ChaCha20Rng) -> NetAddr {
    const B32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let host: String = (0..56)
        .map(|_| B32[(rng.next_u32() % 32) as usize] as char)
        .collect();
    NetAddr::Onion { host, port: 29334 }
}

#[derive(Default)]
struct Tally {
    attacker: u64,
    honest: u64,
    empty: u64,
    all_attacker: u64,
    none_honest: u64,
    restarts: u64,
    new_attacker: u64,
    new_total: u64,
    admitted: u64,
    budget: u64,
}

fn run(s: Scenario, seed: u64, t: &mut Tally) {
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
        m.add(h.clone(), src, &mut rng);
        if i < s.honest_tried {
            m.mark_good(h, 1);
        }
    }
    let honest: HashSet<NetAddr> = honest.into_iter().collect();
    // The flood.
    let conns = MAX_PER_IP * s.flood_secs.div_ceil(s.reconnect_secs);
    let budget = conns * admitted(s.reconnect_secs);
    t.budget += budget * s.sources;
    let per_source = budget.min(FLOOD_CAP / s.sources);
    let sources: Vec<NetAddr> = (0..s.sources)
        .map(|_| public_v4(&mut rng, &mut HashSet::new()))
        .collect();
    for src in &sources {
        for _ in 0..per_source {
            let a = fresh(&mut rng);
            m.add(a, src, &mut rng);
        }
        t.admitted += per_source;
    }
    let (n_new, _) = m.len();
    t.new_total += n_new as u64;
    // Attacker entries in *new*: everything that is not honest.
    let mut sample_rng = ChaCha20Rng::seed_from_u64(seed ^ 0xabcd);
    let all = m.sample(usize::MAX, &mut sample_rng);
    t.new_attacker += all
        .iter()
        .filter(|a| !honest.contains(a))
        .count()
        .min(n_new) as u64;
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
            match pick {
                Some(a) => {
                    groups.insert(a.group());
                    picked.push(a);
                }
                None => t.empty += 1,
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

#[test]
fn eclipse_simulation_attacker_share_of_outbound_slots() {
    let scenarios = [
        Scenario {
            name: "ipv4 g=1 10min",
            honest: 50,
            honest_tried: 16,
            sources: 1,
            flood_secs: 600,
            reconnect_secs: 60,
            onion: false,
        },
        Scenario {
            name: "ipv4 g=4 10min",
            honest: 50,
            honest_tried: 16,
            sources: 4,
            flood_secs: 600,
            reconnect_secs: 60,
            onion: false,
        },
        Scenario {
            name: "ipv4 g=4 empty-tried",
            honest: 50,
            honest_tried: 0,
            sources: 4,
            flood_secs: 600,
            reconnect_secs: 60,
            onion: false,
        },
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
    println!(
        "{:<22} {:>9} {:>9} {:>8} {:>10} {:>10} {:>9} {:>9}",
        "scenario", "budget", "admitted", "new", "new-att%", "slot-att%", "P(all8)", "P(0 hon)"
    );
    for s in scenarios {
        let mut t = Tally::default();
        for seed in 0..SEEDS {
            run(s, 1000 + seed, &mut t);
        }
        let filled = (t.attacker + t.honest).max(1);
        let share = t.attacker as f64 / filled as f64;
        println!(
            "{:<22} {:>9} {:>9} {:>8} {:>9.1}% {:>9.1}% {:>9.4} {:>9.4}",
            s.name,
            t.budget / SEEDS,
            t.admitted / SEEDS,
            t.new_total / SEEDS,
            100.0 * t.new_attacker as f64 / t.new_total.max(1) as f64,
            100.0 * share,
            t.all_attacker as f64 / t.restarts as f64,
            t.none_honest as f64 / t.restarts as f64,
        );
        assert!((0.0..=1.0).contains(&share));
        assert_eq!(t.restarts, SEEDS * RESTARTS as u64);
        let _ = t.empty;
    }
}
