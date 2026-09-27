//! Forward-stamping hoppers (RT-DAA): the hopper's excess over its fair share when it
//! stamps its own blocks `x` seconds ahead of its clock, for x = 0 (honest) up to the
//! FTL (360 s). Smaller x shows what a smaller FTL would leave. 3 seeds x 20 000 blocks.
//!
//! `cargo run --release -p blacksilk-daa-sim --example hop_ahead`

use blacksilk_daa_sim::redteam::{hop_run, Hop, HopMode, HopStamp, Subject};
use blacksilk_daa_sim::rng::derive;
use blacksilk_daa_sim::sim::par_map;

fn main() {
    let configs = [
        (100.0, HopMode::Abs, 1.2, 1.7),
        (10.0, HopMode::Abs, 1.2, 1.7),
        (10.0, HopMode::Abs, 1.2, 2.0),
        (30.0, HopMode::Rel, 0.9, 1.1),
    ];
    let aheads = [0u64, 60, 120, 180, 240, 360];
    for s in [
        Subject::recommended(),
        Subject::anchored("Candidate fix (warm 11)", 11),
        Subject::current(),
    ] {
        println!("{}", s.name);
        for &(big, mode, on, off) in &configs {
            let jobs: Vec<(u64, u64)> = aheads
                .iter()
                .flat_map(|&x| (0..3u64).map(move |c| (x, c)))
                .collect();
            let r = par_map(&jobs, 6, |&(x, c)| {
                let h = Hop {
                    big,
                    mode,
                    on,
                    off,
                    stamp: if x == 0 {
                        HopStamp::Honest
                    } else {
                        HopStamp::Ahead(x)
                    },
                };
                let (sh, fair) = hop_run(&s, &h, 20_000, derive(0x40B, &[c]));
                100.0 * (sh - fair)
            });
            let cells: Vec<String> = aheads
                .iter()
                .map(|&x| {
                    let v: Vec<f64> = jobs
                        .iter()
                        .zip(&r)
                        .filter(|((xx, _), _)| *xx == x)
                        .map(|(_, e)| *e)
                        .collect();
                    format!("{x}s {:+.2}", v.iter().sum::<f64>() / v.len() as f64)
                })
                .collect();
            let label = Hop {
                big,
                mode,
                on,
                off,
                stamp: HopStamp::Honest,
            }
            .label()
            .replace(", honest", "");
            println!("  {label}: {}", cells.join(" | "));
        }
    }
}
