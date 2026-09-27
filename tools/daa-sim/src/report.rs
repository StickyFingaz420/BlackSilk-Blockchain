//! Runs every scenario for every candidate rule and renders the Markdown report.

use crate::rng::{derive, Rng};
use crate::rules::DifficultyRule;
use crate::scenarios::{
    fixed_strategies, genesis_fork_trial, genesis_gap, honest_bias, hopper, lowering_run, race,
    random_patterns, startup, step, Follow, ForkOutcome, Gap, Hopper, Rate, Stamping, Strategy,
};
use crate::sim::{par_map, DEQ, TARGET};
use std::fmt::Write;

/// Scenario sizes and seeds.
#[derive(Clone, Debug)]
pub struct Config {
    pub seed: u64,
    pub threads: usize,
    pub race_trials: usize,
    pub race_qs: Vec<f64>,
    pub race_zs: Vec<usize>,
    /// `(q, chain age in blocks, trials)`.
    pub forks: Vec<(f64, usize, usize)>,
    pub fork_horizon_days: f64,
    pub bias_seeds: usize,
    pub bias_blocks: usize,
    pub median_seeds: usize,
    pub hopper_seeds: usize,
    pub hopper_blocks: usize,
    pub lowering_seeds: usize,
    pub lowering_blocks: usize,
    pub patterns: usize,
    pub pattern_blocks: usize,
}

impl Config {
    pub fn full(seed: u64, threads: usize) -> Self {
        Self {
            seed,
            threads,
            race_trials: 2_000,
            race_qs: vec![0.2, 0.3, 0.35, 0.4, 0.45],
            race_zs: vec![6, 20, 100],
            forks: vec![
                (0.1, 720, 1_000),
                (0.2, 720, 1_000),
                (0.3, 720, 1_000),
                (0.2, 7_200, 300),
            ],
            fork_horizon_days: 10.0,
            bias_seeds: 4,
            bias_blocks: 50_000,
            median_seeds: 101,
            hopper_seeds: 3,
            hopper_blocks: 20_000,
            lowering_seeds: 3,
            lowering_blocks: 3_000,
            patterns: 120,
            pattern_blocks: 1_500,
        }
    }

    pub fn quick(seed: u64, threads: usize) -> Self {
        Self {
            race_trials: 200,
            forks: vec![(0.2, 720, 100)],
            bias_seeds: 2,
            bias_blocks: 10_000,
            median_seeds: 21,
            hopper_seeds: 1,
            hopper_blocks: 5_000,
            lowering_seeds: 1,
            lowering_blocks: 1_000,
            patterns: 10,
            pattern_blocks: 500,
            ..Self::full(seed, threads)
        }
    }
}

/// Trials per parallel job.
const RACE_CHUNK: usize = 100;
const FORK_CHUNK: usize = 25;
/// Blocks simulated before a follow scenario is reported as not converged.
const MAX_FOLLOW: usize = 3_000;

// Seed tags (one per scenario).
const TAG_RACE: u64 = 1;
const TAG_FORK: u64 = 2;
const TAG_BIAS: u64 = 3;
const TAG_STEP: u64 = 4;
const TAG_STARTUP: u64 = 5;
const TAG_GAP: u64 = 6;
const TAG_HOPPER: u64 = 7;
const TAG_LOWER: u64 = 8;
const TAG_PATTERN: u64 = 9;

#[derive(Clone, Debug)]
pub struct RaceCell {
    pub q: f64,
    pub z: usize,
    pub honest: Rate,
    pub compressed: Rate,
}

impl RaceCell {
    pub fn excess(&self) -> f64 {
        self.compressed.p() - self.honest.p()
    }
    /// The excess plus three standard errors of the difference.
    pub fn excess_upper(&self) -> f64 {
        self.excess() + 3.0 * (self.compressed.se().powi(2) + self.honest.se().powi(2)).sqrt()
    }
}

#[derive(Clone, Debug)]
pub struct ForkCell {
    pub q: f64,
    pub age: usize,
    pub honest: Rate,
    pub compressed: Rate,
    pub capped: u64,
}

#[derive(Clone, Debug)]
pub struct StartupRow {
    pub factor: f64,
    pub first_block_s: f64,
    pub det: Follow,
    pub median: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct Lowering {
    /// Per family: (best label, gain in blocks per hour over honest, in %).
    pub families: Vec<(String, String, f64)>,
    pub best: (String, f64),
    /// The best random pattern re-run on fresh seeds (removes the selection bias).
    pub pattern_rerun: f64,
}

#[derive(Clone, Debug)]
pub struct RuleResults {
    pub name: String,
    pub race: Vec<RaceCell>,
    pub forks: Vec<ForkCell>,
    pub bias: f64,
    pub bias_se: f64,
    pub up_det: Follow,
    pub down_det: Follow,
    pub up_median: Option<usize>,
    pub down_median: Option<usize>,
    pub startup: Vec<StartupRow>,
    pub gap: Gap,
    pub gap_d100: Gap,
    pub gap_median: Option<usize>,
    pub gap_extra_median: i64,
    pub hopper: Hopper,
    pub lowering: Lowering,
}

/// The acceptance criteria of decisions.md (Agent 03).
#[derive(Clone, Debug)]
pub struct Verdict {
    /// Largest race excess over the honest baseline at q <= 0.4, z = 100.
    pub race_excess: f64,
    pub race_excess_upper: f64,
    pub race_ok: bool,
    pub bias_ok: bool,
    pub up_ok: bool,
    pub startup_ok: bool,
}

impl Verdict {
    pub fn all(&self) -> bool {
        self.race_ok && self.bias_ok && self.up_ok && self.startup_ok
    }

    /// Every criterion except the bias one (the bias is inherited from LWMA-60,
    /// and its 99/100 correction is a separate P3 decision).
    pub fn all_but_bias(&self) -> bool {
        self.race_ok && self.up_ok && self.startup_ok
    }
}

impl RuleResults {
    pub fn verdict(&self) -> Verdict {
        let cells = self.race.iter().filter(|c| c.q <= 0.4 + 1e-9 && c.z == 100);
        let (mut ex, mut up) = (f64::MIN, f64::MIN);
        for c in cells {
            ex = ex.max(c.excess());
            up = up.max(c.excess_upper());
        }
        let half = self
            .startup
            .iter()
            .find(|r| (r.factor - 0.5).abs() < 1e-9)
            .and_then(|r| r.det.blocks);
        Verdict {
            race_excess: ex,
            race_excess_upper: up,
            race_ok: ex <= 0.02,
            bias_ok: self.bias.abs() <= 0.01,
            up_ok: self.up_det.blocks.is_some_and(|b| b <= 150),
            startup_ok: half.is_some_and(|b| b <= 40),
        }
    }
}

fn median_of(mut v: Vec<Option<usize>>) -> Option<usize> {
    v.sort_by_key(|x| x.unwrap_or(usize::MAX));
    v[v.len() / 2]
}

fn q_tag(q: f64) -> u64 {
    (q * 1_000.0).round() as u64
}

/// Runs every scenario for every rule.
pub fn run(cfg: &Config, rules: &[Box<dyn DifficultyRule>]) -> Vec<RuleResults> {
    let th = cfg.threads;
    let seed = cfg.seed;

    // Race: (rule, q, z, stamping, chunk). The seed omits the rule and the
    // stamping, so rules and strategies are compared on common random numbers.
    let mut race_jobs = Vec::new();
    for r in 0..rules.len() {
        for &q in &cfg.race_qs {
            for &z in &cfg.race_zs {
                for s in [Stamping::Honest, Stamping::Compressed] {
                    for chunk in 0..cfg.race_trials.div_ceil(RACE_CHUNK) {
                        let n = RACE_CHUNK.min(cfg.race_trials - chunk * RACE_CHUNK);
                        race_jobs.push((r, q, z, s, n, chunk as u64));
                    }
                }
            }
        }
    }
    let race_out = par_map(&race_jobs, th, |&(r, q, z, s, n, chunk)| {
        let sd = derive(seed, &[TAG_RACE, q_tag(q), z as u64, chunk]);
        race(rules[r].as_ref(), q, z, s, n, sd)
    });

    // Genesis fork.
    let mut fork_jobs = Vec::new();
    for r in 0..rules.len() {
        for (i, &(q, age, trials)) in cfg.forks.iter().enumerate() {
            for s in [Stamping::Honest, Stamping::Compressed] {
                for chunk in 0..trials.div_ceil(FORK_CHUNK) {
                    let n = FORK_CHUNK.min(trials - chunk * FORK_CHUNK);
                    fork_jobs.push((r, i, q, age, s, n, chunk as u64));
                }
            }
        }
    }
    let horizon = cfg.fork_horizon_days * 86_400.0;
    let fork_out = par_map(&fork_jobs, th, |&(r, _, q, age, s, n, chunk)| {
        let mut rng = Rng::new(derive(seed, &[TAG_FORK, q_tag(q), age as u64, chunk]));
        let mut out = (0u64, 0u64);
        for _ in 0..n {
            match genesis_fork_trial(rules[r].as_ref(), q, age, s, horizon, &mut rng) {
                ForkOutcome::Win => out.0 += 1,
                ForkOutcome::Capped => out.1 += 1,
                ForkOutcome::Loss => {}
            }
        }
        out
    });

    // Honest bias, hopper.
    let bias_jobs: Vec<(usize, u64)> = (0..rules.len())
        .flat_map(|r| (0..cfg.bias_seeds as u64).map(move |s| (r, s)))
        .collect();
    let bias_out = par_map(&bias_jobs, th, |&(r, s)| {
        let mut rng = Rng::new(derive(seed, &[TAG_BIAS, s]));
        honest_bias(rules[r].as_ref(), cfg.bias_blocks, &mut rng)
    });
    let hop_jobs: Vec<(usize, u64)> = (0..rules.len())
        .flat_map(|r| (0..cfg.hopper_seeds as u64).map(move |s| (r, s)))
        .collect();
    let hop_out = par_map(&hop_jobs, th, |&(r, s)| {
        let mut rng = Rng::new(derive(seed, &[TAG_HOPPER, s]));
        hopper(rules[r].as_ref(), cfg.hopper_blocks, &mut rng)
    });

    // Follow scenarios: deterministic (expected solve times) and stochastic medians.
    let factors = [0.01, 0.1, 0.5, 2.0, 10.0];
    let follow_out = par_map(&(0..rules.len()).collect::<Vec<_>>(), th, |&r| {
        let rule = rules[r].as_ref();
        let up_det = step(rule, 10.0, None, MAX_FOLLOW);
        let down_det = step(rule, 0.1, None, MAX_FOLLOW);
        let med = |f: f64, tag: u64| {
            median_of(
                (0..cfg.median_seeds as u64)
                    .map(|s| {
                        let mut rng = Rng::new(derive(seed, &[TAG_STEP, tag, s]));
                        step(rule, f, Some(&mut rng), MAX_FOLLOW).blocks
                    })
                    .collect(),
            )
        };
        let up_median = med(10.0, 1);
        let down_median = med(0.1, 2);
        let startup_rows = factors
            .iter()
            .enumerate()
            .map(|(i, &f)| {
                let (first, det) = startup(rule, f, None, MAX_FOLLOW);
                let median = median_of(
                    (0..cfg.median_seeds as u64)
                        .map(|s| {
                            let mut rng = Rng::new(derive(seed, &[TAG_STARTUP, i as u64, s]));
                            startup(rule, f, Some(&mut rng), MAX_FOLLOW).1.blocks
                        })
                        .collect(),
                );
                StartupRow {
                    factor: f,
                    first_block_s: first,
                    det,
                    median,
                }
            })
            .collect();
        let gap = genesis_gap(rule, DEQ, 7_200, None, MAX_FOLLOW);
        let gap_d100 = genesis_gap(rule, 100, 7_200, None, MAX_FOLLOW);
        let gaps: Vec<Gap> = (0..cfg.median_seeds as u64)
            .map(|s| {
                let mut rng = Rng::new(derive(seed, &[TAG_GAP, s]));
                genesis_gap(rule, DEQ, 7_200, Some(&mut rng), MAX_FOLLOW)
            })
            .collect();
        let gap_median = median_of(gaps.iter().map(|g| g.recovered_at).collect());
        let mut extra: Vec<i64> = gaps.iter().map(|g| g.extra_blocks_6h).collect();
        extra.sort_unstable();
        (
            up_det,
            down_det,
            up_median,
            down_median,
            startup_rows,
            gap,
            gap_d100,
            gap_median,
            extra[extra.len() / 2],
        )
    });

    // Timestamp lowering: fixed families on every seed; random patterns selected on
    // one set of seeds and re-run on fresh ones.
    let fixed = fixed_strategies();
    let mut prng = Rng::new(derive(seed, &[TAG_PATTERN]));
    let patterns = random_patterns(cfg.patterns, &mut prng);
    let lower_seed = |s: u64| derive(seed, &[TAG_LOWER, s]);
    let mut low_jobs = Vec::new();
    for r in 0..rules.len() {
        for s in 0..cfg.lowering_seeds as u64 {
            low_jobs.push((r, Strategy::Honest, cfg.lowering_blocks, lower_seed(s)));
            for st in &fixed {
                low_jobs.push((r, st.clone(), cfg.lowering_blocks, lower_seed(s)));
            }
        }
        for p in &patterns {
            low_jobs.push((r, Strategy::Honest, cfg.pattern_blocks, lower_seed(1_000)));
            low_jobs.push((r, p.clone(), cfg.pattern_blocks, lower_seed(1_000)));
        }
    }
    let low_out = par_map(&low_jobs, th, |(r, st, blocks, sd)| {
        lowering_run(rules[*r].as_ref(), st, *blocks, *sd)
    });
    // The best pattern per rule, re-run on fresh seeds.
    let mut rerun_jobs = Vec::new();
    for r in 0..rules.len() {
        let mut best = (f64::MIN, 0);
        for (j, _) in patterns.iter().enumerate() {
            let idx = low_jobs
                .iter()
                .position(|(rr, st, b, _)| {
                    *rr == r && *b == cfg.pattern_blocks && *st == patterns[j]
                })
                .expect("pattern job");
            let gain = low_out[idx - 1] / low_out[idx] - 1.0;
            if gain > best.0 {
                best = (gain, j);
            }
        }
        for s in 0..cfg.lowering_seeds as u64 {
            let sd = lower_seed(2_000 + s);
            rerun_jobs.push((r, Strategy::Honest, sd));
            rerun_jobs.push((r, patterns[best.1].clone(), sd));
        }
    }
    let rerun_out = par_map(&rerun_jobs, th, |(r, st, sd)| {
        lowering_run(rules[*r].as_ref(), st, cfg.lowering_blocks, *sd)
    });

    // Aggregate.
    let mut results = Vec::new();
    for (r, rule) in rules.iter().enumerate() {
        let mut race = Vec::new();
        for &q in &cfg.race_qs {
            for &z in &cfg.race_zs {
                let mut honest = Rate::default();
                let mut compressed = Rate::default();
                for (job, out) in race_jobs.iter().zip(&race_out) {
                    if job.0 == r && job.1 == q && job.2 == z {
                        match job.3 {
                            Stamping::Honest => honest.add(*out),
                            Stamping::Compressed => compressed.add(*out),
                        }
                    }
                }
                race.push(RaceCell {
                    q,
                    z,
                    honest,
                    compressed,
                });
            }
        }
        let mut forks = Vec::new();
        for (i, &(q, age, _)) in cfg.forks.iter().enumerate() {
            let mut cell = ForkCell {
                q,
                age,
                honest: Rate::default(),
                compressed: Rate::default(),
                capped: 0,
            };
            for (job, out) in fork_jobs.iter().zip(&fork_out) {
                if job.0 == r && job.1 == i {
                    let rate = Rate {
                        hits: out.0,
                        trials: job.5 as u64,
                    };
                    cell.capped += out.1;
                    match job.4 {
                        Stamping::Honest => cell.honest.add(rate),
                        Stamping::Compressed => cell.compressed.add(rate),
                    }
                }
            }
            forks.push(cell);
        }
        let per_seed: Vec<f64> = bias_jobs
            .iter()
            .zip(&bias_out)
            .filter(|(j, _)| j.0 == r)
            .map(|(_, &(sum, n))| sum / n as f64 / TARGET as f64 - 1.0)
            .collect();
        let bias = per_seed.iter().sum::<f64>() / per_seed.len() as f64;
        let var = per_seed.iter().map(|b| (b - bias).powi(2)).sum::<f64>()
            / (per_seed.len().max(2) - 1) as f64;
        let bias_se = (var / per_seed.len() as f64).sqrt();
        let hops: Vec<Hopper> = hop_jobs
            .iter()
            .zip(&hop_out)
            .filter(|(j, _)| j.0 == r)
            .map(|(_, h)| *h)
            .collect();
        let n = hops.len() as f64;
        let hopper = Hopper {
            share: hops.iter().map(|h| h.share).sum::<f64>() / n,
            mean_st: hops.iter().map(|h| h.mean_st).sum::<f64>() / n,
            slow: hops.iter().map(|h| h.slow).sum::<f64>() / n,
        };

        // Lowering: sum the totals over seeds per strategy.
        let total = |st: &Strategy| -> f64 {
            low_jobs
                .iter()
                .zip(&low_out)
                .filter(|((rr, s, b, _), _)| *rr == r && s == st && *b == cfg.lowering_blocks)
                .map(|(_, t)| *t)
                .sum()
        };
        let honest_total = total(&Strategy::Honest);
        let mut families: Vec<(String, String, f64)> = Vec::new();
        for st in &fixed {
            let gain = 100.0 * (honest_total / total(st) - 1.0);
            match families.iter_mut().find(|f| f.0 == st.family()) {
                Some(f) if gain > f.2 => {
                    f.1 = st.label();
                    f.2 = gain;
                }
                Some(_) => {}
                None => families.push((st.family().into(), st.label(), gain)),
            }
        }
        let (mut h, mut p) = (0.0, 0.0);
        let mut label = String::new();
        for (job, out) in rerun_jobs.iter().zip(&rerun_out) {
            if job.0 == r {
                match &job.1 {
                    Strategy::Honest => h += out,
                    s => {
                        p += out;
                        label = s.label();
                    }
                }
            }
        }
        let pattern_rerun = 100.0 * (h / p - 1.0);
        families.push(("random periodic patterns".into(), label, pattern_rerun));
        let best = families
            .iter()
            .max_by(|a, b| a.2.total_cmp(&b.2))
            .map(|f| (format!("{} ({})", f.0, f.1), f.2))
            .expect("families");

        let f = follow_out[r].clone();
        results.push(RuleResults {
            name: rule.name(),
            race,
            forks,
            bias,
            bias_se,
            up_det: f.0,
            down_det: f.1,
            up_median: f.2,
            down_median: f.3,
            startup: f.4,
            gap: f.5,
            gap_d100: f.6,
            gap_median: f.7,
            gap_extra_median: f.8,
            hopper,
            lowering: Lowering {
                families,
                best,
                pattern_rerun,
            },
        });
    }
    results
}

fn blocks(b: Option<usize>) -> String {
    match b {
        Some(b) => b.to_string(),
        None => format!("> {MAX_FOLLOW}"),
    }
}

fn pct(x: f64) -> String {
    format!("{:+.2}%", 100.0 * x)
}

fn p3(r: &Rate) -> String {
    format!("{:.3}", r.p())
}

/// The recommended candidate: the simplest rule that meets every criterion. Rise
/// caps are simpler than ASERT (one line on the reviewed LWMA); among passing caps
/// the largest `R` is preferred (fastest honest response), provided its race excess
/// still passes at +3 standard errors; otherwise the largest point-estimate pass.
pub fn recommend(results: &[RuleResults]) -> Option<&RuleResults> {
    let pct_of = |r: &RuleResults| -> f64 {
        r.name
            .rsplit("<= ")
            .next()
            .and_then(|s| s.trim_end_matches('%').parse().ok())
            .unwrap_or(0.0)
    };
    let pick = |ok: &dyn Fn(&Verdict) -> bool| -> Option<&RuleResults> {
        let caps: Vec<&RuleResults> = results
            .iter()
            .filter(|r| r.name.contains("rise") && ok(&r.verdict()))
            .collect();
        caps.iter()
            .filter(|r| r.verdict().race_excess_upper <= 0.02)
            .max_by(|a, b| pct_of(a).total_cmp(&pct_of(b)))
            .or_else(|| caps.iter().max_by(|a, b| pct_of(a).total_cmp(&pct_of(b))))
            .copied()
            .or_else(|| {
                results
                    .iter()
                    .find(|r| r.name.contains("ASERT") && ok(&r.verdict()))
            })
    };
    pick(&|v| v.all()).or_else(|| pick(&|v| v.all_but_bias()))
}

/// The Markdown report.
pub fn render(cfg: &Config, results: &[RuleResults], header: &str) -> String {
    let mut s = String::new();
    let w = &mut s;
    let _ = writeln!(w, "{header}");
    let _ = writeln!(w, "## Configuration\n");
    let _ = writeln!(
        w,
        "- Base seed: `{:#x}`. Every job derives its own seed from the base seed and its \
         scenario coordinates (`rng::derive`), so results do not depend on the thread count ({} threads used).",
        cfg.seed, cfg.threads
    );
    let _ = writeln!(
        w,
        "- T = {TARGET} s, FTL = {} s, MTP window {}, equilibrium difficulty DEQ = {DEQ} \
         (reference hash rate DEQ/T). Solve times are exponential with mean D/H.",
        crate::sim::FTL,
        crate::sim::MTP_WINDOW
    );
    let _ = writeln!(
        w,
        "- Race: {} trials per (rule, q, z, stamping) cell; q in {:?}; z in {:?}; horizon 12z + 240 block times; \
         the private branch starts from a 121-block equilibrium chain.",
        cfg.race_trials, cfg.race_qs, cfg.race_zs
    );
    let _ = writeln!(
        w,
        "- Genesis fork: (q, chain age, trials) = {:?}; horizon {} days after the fork.",
        cfg.forks, cfg.fork_horizon_days
    );
    let _ = writeln!(
        w,
        "- Honest bias: {} seeds x {} blocks (after 1 000 burn-in). Hopper: {} seeds x {} blocks. \
         Stochastic medians: {} seeds. Lowering: {} seeds x {} blocks per strategy; {} random patterns \
         selected on {} blocks and the best re-run on {} fresh seeds.",
        cfg.bias_seeds,
        cfg.bias_blocks,
        cfg.hopper_seeds,
        cfg.hopper_blocks,
        cfg.median_seeds,
        cfg.lowering_seeds,
        cfg.lowering_blocks,
        cfg.patterns,
        cfg.pattern_blocks,
        cfg.lowering_seeds
    );

    let _ = writeln!(w, "\n## Summary\n");
    let _ = writeln!(
        w,
        "| Rule | Race q=0.4 z=100: compressed / honest | Max excess q<=0.4 z=100 (+3 se) | Honest bias | \
         10x up: blocks (h) | 10x down: blocks (h) | From 0.5xD0: blocks | 2 h gap: recovery blocks | \
         Genesis fork q=0.2 age 720 | Hopper share | Best lowering gain |"
    );
    let _ = writeln!(w, "|---|---|---|---|---|---|---|---|---|---|---|");
    for r in results {
        let v = r.verdict();
        let c = r
            .race
            .iter()
            .find(|c| (c.q - 0.4).abs() < 1e-9 && c.z == 100);
        let fork = r
            .forks
            .iter()
            .find(|f| (f.q - 0.2).abs() < 1e-9 && f.age == 720);
        let half = r.startup.iter().find(|x| (x.factor - 0.5).abs() < 1e-9);
        let _ =
            writeln!(
            w,
            "| {} | {} | {} ({}) | {} | {} ({:.1}) | {} ({:.1}) | {} | {} | {} | {:.3} | {:+.2}% |",
            r.name,
            c.map_or("-".into(), |c| format!("{} / {}", p3(&c.compressed), p3(&c.honest))),
            pct(v.race_excess),
            pct(v.race_excess_upper),
            pct(r.bias),
            blocks(r.up_det.blocks),
            r.up_det.hours,
            blocks(r.down_det.blocks),
            r.down_det.hours,
            half.map_or("-".into(), |h| blocks(h.det.blocks)),
            blocks(r.gap.recovered_at),
            fork.map_or("-".into(), |f| format!(
                "{} (honest {})",
                p3(&f.compressed),
                p3(&f.honest)
            )),
            r.hopper.share,
            r.lowering.best.1,
        );
    }

    let _ = writeln!(w, "\n## Acceptance criteria (decisions.md, Agent 03)\n");
    let _ = writeln!(
        w,
        "Race excess <= +2% at q <= 0.4, z = 100 (point estimate); |honest bias| <= 1%; \
         10x up in <= 150 blocks; from 0.5xD0 in <= 40 blocks (deterministic runs).\n"
    );
    let _ = writeln!(
        w,
        "| Rule | Race | Bias | 10x up | 0.5xD0 | All | All but bias | Race also passes at +3 se |"
    );
    let _ = writeln!(w, "|---|---|---|---|---|---|---|---|");
    let yn = |b: bool| if b { "pass" } else { "FAIL" };
    for r in results {
        let v = r.verdict();
        let _ = writeln!(
            w,
            "| {} | {} ({}) | {} ({}) | {} | {} | **{}** | {} | {} |",
            r.name,
            yn(v.race_ok),
            pct(v.race_excess),
            yn(v.bias_ok),
            pct(r.bias),
            yn(v.up_ok),
            yn(v.startup_ok),
            yn(v.all()),
            yn(v.all_but_bias()),
            if v.race_excess_upper <= 0.02 {
                "yes"
            } else {
                "no"
            }
        );
    }

    let _ = writeln!(w, "\n## Difficulty-raising race (P(attacker wins))\n");
    let _ = writeln!(
        w,
        "Each cell: compressed-stamp attacker / honest-stamp attacker (baseline). \
         Standard error at p = 0.02 and {} trials: {:.3}.\n",
        cfg.race_trials,
        (0.02f64 * 0.98 / cfg.race_trials as f64).sqrt()
    );
    for &z in &cfg.race_zs {
        let _ = writeln!(w, "### z = {z} confirmations\n");
        let mut head = String::from("| Rule |");
        let mut sep = String::from("|---|");
        for q in &cfg.race_qs {
            let _ = write!(head, " q = {q} |");
            sep.push_str("---|");
        }
        let _ = writeln!(w, "{head}\n{sep}");
        for r in results {
            let mut row = format!("| {} |", r.name);
            for c in r.race.iter().filter(|c| c.z == z) {
                let _ = write!(row, " {} / {} |", p3(&c.compressed), p3(&c.honest));
            }
            let _ = writeln!(w, "{row}");
        }
        let _ = writeln!(w);
    }

    let _ = writeln!(
        w,
        "## Genesis-fork rewrite (P(private branch from genesis overtakes))\n"
    );
    let _ = writeln!(
        w,
        "The chain runs `age` blocks at the full hash rate; then a miner with share q mines a \
         branch from genesis for {} days. Cells: compressed / honest stamps (trials; capped trials count as losses).\n",
        cfg.fork_horizon_days
    );
    let mut head = String::from("| Rule |");
    let mut sep = String::from("|---|");
    for (q, age, t) in &cfg.forks {
        let _ = write!(head, " q = {q}, age {age} ({t}) |");
        sep.push_str("---|");
    }
    let _ = writeln!(w, "{head}\n{sep}");
    for r in results {
        let mut row = format!("| {} |", r.name);
        for f in &r.forks {
            let capped = if f.capped > 0 {
                format!(", {} capped", f.capped)
            } else {
                String::new()
            };
            let _ = write!(row, " {} / {}{capped} |", p3(&f.compressed), p3(&f.honest));
        }
        let _ = writeln!(w, "{row}");
    }

    let _ = writeln!(w, "\n## Honest operation\n");
    let _ = writeln!(
        w,
        "| Rule | Mean solve time / T - 1 (se) | 10x up: det blocks (h) / median | 10x down: det blocks (h) / median |"
    );
    let _ = writeln!(w, "|---|---|---|---|");
    for r in results {
        let _ = writeln!(
            w,
            "| {} | {} ({:.2}%) | {} ({:.1}) / {} | {} ({:.1}) / {} |",
            r.name,
            pct(r.bias),
            100.0 * r.bias_se,
            blocks(r.up_det.blocks),
            r.up_det.hours,
            blocks(r.up_median),
            blocks(r.down_det.blocks),
            r.down_det.hours,
            blocks(r.down_median),
        );
    }
    let _ = writeln!(
        w,
        "\n\"Blocks\" counts blocks after the change until a block's difficulty is within +/-10% of the \
         new equilibrium; \"det\" uses expected solve times, \"median\" is over {} stochastic seeds.",
        cfg.median_seeds
    );

    let _ = writeln!(w, "\n## Start-up from a mis-set D0\n");
    let _ = writeln!(
        w,
        "Cells: first height whose difficulty is within +/-10% of equilibrium, deterministic / \
         stochastic median; and the expected time to block 1.\n"
    );
    let mut head = String::from("| Rule |");
    let mut sep = String::from("|---|");
    if let Some(r) = results.first() {
        for row in &r.startup {
            let _ = write!(head, " D0 = {}x |", row.factor);
            sep.push_str("---|");
        }
    }
    let _ = writeln!(w, "{head}\n{sep}");
    for r in results {
        let mut row = format!("| {} |", r.name);
        for x in &r.startup {
            let _ = write!(
                row,
                " {} / {} (block 1: {:.0} s) |",
                blocks(x.det.blocks),
                blocks(x.median),
                x.first_block_s
            );
        }
        let _ = writeln!(w, "{row}");
    }

    let _ = writeln!(w, "\n## Genesis-to-launch gap (2 h)\n");
    let _ = writeln!(
        w,
        "Genesis stamped 2 h before mining starts, D0 correct. Minimum difficulty reached (x equilibrium), \
         first height back at >= 90%, and extra blocks in the first 6 h of mining (180 expected). \
         The D0 = 100 column repeats the deterministic run at the current testnet placeholder, where \
         integer rounding matters.\n"
    );
    let _ = writeln!(
        w,
        "| Rule | Min ratio | Recovery: det / median | Extra blocks in 6 h: det / median | D0 = 100: min, recovery |"
    );
    let _ = writeln!(w, "|---|---|---|---|---|");
    for r in results {
        let _ = writeln!(
            w,
            "| {} | {:.3} | {} / {} | {} / {} | {:.2}, {} |",
            r.name,
            r.gap.min_ratio,
            blocks(r.gap.recovered_at),
            blocks(r.gap_median),
            r.gap.extra_blocks_6h,
            r.gap_extra_median,
            r.gap_d100.min_ratio,
            blocks(r.gap_d100.recovered_at),
        );
    }

    let _ = writeln!(w, "\n## Hop-in/hop-out mining\n");
    let _ = writeln!(
        w,
        "A hopper with 10x the dedicated hash rate mines while D < 1.2 DEQ and leaves above 2 DEQ.\n"
    );
    let _ = writeln!(
        w,
        "| Rule | Hopper share of blocks | Mean solve time / T | Blocks slower than 6T |"
    );
    let _ = writeln!(w, "|---|---|---|---|");
    for r in results {
        let _ = writeln!(
            w,
            "| {} | {:.3} | {:.3} | {:.2}% |",
            r.name,
            r.hopper.share,
            r.hopper.mean_st,
            100.0 * r.hopper.slow
        );
    }

    let _ = writeln!(
        w,
        "\n## Timestamp lowering by a 100% miner (dossier 04's families)\n"
    );
    let _ = writeln!(
        w,
        "Gain in blocks per hour over honest stamping on the same solve-time draws (positive = the \
         strategy lowers the difficulty). Best member of each family.\n"
    );
    let mut head = String::from("| Rule |");
    let mut sep = String::from("|---|");
    if let Some(r) = results.first() {
        for f in &r.lowering.families {
            let _ = write!(head, " {} |", f.0);
            sep.push_str("---|");
        }
    }
    let _ = writeln!(w, "{head}\n{sep}");
    for r in results {
        let mut row = format!("| {} |", r.name);
        for f in &r.lowering.families {
            let _ = write!(row, " {:+.2}% ({}) |", f.2, f.1);
        }
        let _ = writeln!(w, "{row}");
    }

    let _ = writeln!(w, "\n## Automated verdict\n");
    let passing: Vec<&str> = results
        .iter()
        .filter(|r| r.verdict().all())
        .map(|r| r.name.as_str())
        .collect();
    let but_bias: Vec<&str> = results
        .iter()
        .filter(|r| r.verdict().all_but_bias())
        .map(|r| r.name.as_str())
        .collect();
    let list = |v: &[&str]| {
        if v.is_empty() {
            "none".to_string()
        } else {
            v.join(", ")
        }
    };
    let _ = writeln!(
        w,
        "- Candidates meeting every criterion: {}.",
        list(&passing)
    );
    let _ = writeln!(
        w,
        "- Candidates meeting every criterion except the honest-bias one: {}.",
        list(&but_bias)
    );
    match recommend(results) {
        Some(r) => {
            let _ = writeln!(
                w,
                "- Automated pick (the simplest rule passing every criterion, else every criterion \
                 but the bias; among rise caps the largest R whose race excess passes at +3 se, \
                 else the largest passing R): **{}**.",
                r.name
            );
        }
        None => {
            let _ = writeln!(
                w,
                "- No candidate meets every criterion (nor every criterion but the bias)."
            );
        }
    }
    s
}
