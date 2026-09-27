//! Rollout trace (RT-DAA): which candidate stamp the rollout controller (H = 76, honest
//! base) chooses on the rule under attack, by solve time and counted-clock offset, and
//! a trace of blocks 1000..1080. Seed 1000, 3000 blocks.
//!
//! `cargo run --release -p blacksilk-daa-sim --example rollout_trace`

use blacksilk_daa_sim::redteam::*;
use blacksilk_daa_sim::rng::Rng;
use blacksilk_daa_sim::sim::{Branch, DEQ, RATE};
use std::collections::BTreeMap;

fn main() {
    let s = Subject::recommended();
    let p = Policy::Rollout {
        horizon: 76,
        base: Box::new(Policy::Honest),
    };
    let mut rng = Rng::new(1000);
    let mut b = Branch::steady(121, DEQ);
    let mut now = b.tip_time() as f64;
    for _ in 0..200 {
        let d = s.required(&b);
        now += rng.exp() * d as f64 / RATE;
        b.push(b.honest_stamp(now), d, now);
    }
    // (dt bin, e bin) -> counts per candidate
    let mut hist: BTreeMap<(i64, i64), [usize; 15]> = BTreeMap::new();
    let mut totals = [0usize; 15];
    let mut trace = Vec::new();
    for k in 0..3000 {
        let d = s.required(&b);
        let dt = rng.exp() * d as f64 / RATE;
        now += dt;
        let cands: Vec<u64> = CANDIDATES.iter().map(|a| a.resolve(&b, now, &s)).collect();
        let clk = s.clock(&b) as i64;
        let t = p.stamp(k, &mut b, now, d, &s);
        let idx = cands.iter().position(|&c| c == t).unwrap_or(14);
        totals[idx] += 1;
        let dtb = ((dt / 60.0) as i64).min(12);
        let eb = ((clk - now as i64) / 120).clamp(-10, 3);
        hist.entry((dtb, eb)).or_insert([0; 15])[idx] += 1;
        if (1000..1080).contains(&k) {
            trace.push(format!(
                "k{k} dt {:.0} D/DEQ {:.3} clk-now {} stamp-now {} ({}) prev-now {} mtp-now {}",
                dt,
                d as f64 / DEQ as f64,
                clk - now as i64,
                t as i64 - now as i64,
                if idx < 14 {
                    CANDIDATES[idx].label()
                } else {
                    "?".into()
                },
                b.tip_time() as i64 - now as i64,
                b.mtp() as i64 - now as i64
            ));
        }
        b.push(t, d, now);
    }
    println!("totals:");
    for (i, c) in totals.iter().enumerate() {
        if i < 14 {
            println!("  {:>10} {c}", CANDIDATES[i].label());
        }
    }
    println!("by (dt/60 bin, (clk-now)/120 bin): counts per candidate");
    for (k, v) in &hist {
        println!("  {:?} {:?}", k, v);
    }
    for l in trace {
        println!("{l}");
    }
}
