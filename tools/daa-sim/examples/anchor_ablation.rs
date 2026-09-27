//! Anchor ablation (RT-DAA): the rollout controller's emission gain against the rule
//! under attack and against variants whose counted clock is warmed over 1, 11 or 75
//! blocks before the window, plus the honest bias of each.
//!
//! `cargo run --release -p blacksilk-daa-sim --example anchor_ablation -- [blocks] [skip] [horizon] [seeds] [subjects]`
//! where `subjects` is a string of r (rule under attack), o (warm 1), a (warm 11),
//! w (warm 75) and c (current consensus rule). Defaults: 3000 1000 76 6 rawc.
//! Seeds are 1000..1000+seeds.

use blacksilk_daa_sim::redteam::*;
use blacksilk_daa_sim::sim::{par_map, TARGET};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let blocks: usize = args.get(1).map_or(3000, |x| x.parse().unwrap());
    let skip: usize = args.get(2).map_or(1000, |x| x.parse().unwrap());
    let h: usize = args.get(3).map_or(76, |x| x.parse().unwrap());
    let nseeds: u64 = args.get(4).map_or(6, |x| x.parse().unwrap());
    let which: String = args.get(5).cloned().unwrap_or("rawc".into());
    let mut subs = Vec::new();
    for c in which.chars() {
        subs.push(match c {
            'r' => Subject::recommended(),
            'a' => Subject::anchored("warm 11", 11),
            'w' => Subject::anchored("warm 75", 75),
            'o' => Subject::anchored("warm 1", 1),
            'c' => Subject::current(),
            _ => panic!(),
        });
    }
    for s in subs {
        let seeds: Vec<u64> = (0..nseeds).collect();
        let p = Policy::Rollout {
            horizon: h,
            base: Box::new(Policy::Honest),
        };
        let r = par_map(&seeds, 6, |&c| {
            (
                sto_gain(&s, &p, blocks, 1000 + c, 1.0),
                sto_gain_from(&s, &p, blocks, skip, 1000 + c),
                sto_time(&s, &Policy::Honest, blocks, 1000 + c, 1.0),
            )
        });
        let m = |i: usize| {
            let x: Vec<f64> = r
                .iter()
                .map(|t| match i {
                    0 => t.0,
                    1 => t.1,
                    _ => t.2 / blocks as f64 / TARGET as f64 - 1.0,
                })
                .collect();
            let mean = x.iter().sum::<f64>() / x.len() as f64;
            let sd =
                (x.iter().map(|y| (y - mean).powi(2)).sum::<f64>() / (x.len() as f64 - 1.0)).sqrt();
            format!(
                "mean {:+.4} sd {:.4} min {:+.4}",
                mean,
                sd,
                x.iter().cloned().fold(1.0, f64::min)
            )
        };
        println!(
            "{}: rollout H={h} total {} | sustained {} | honest bias {}",
            s.name,
            m(0),
            m(1),
            m(2)
        );
    }
}
