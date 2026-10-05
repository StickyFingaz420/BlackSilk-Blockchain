//! The W0-03b selection study: every candidate against the coordinator's revised
//! acceptance criteria (decisions.md, "DAA update"), with adaptive attackers.

use crate::adaptive::{self, Attack, HopFair, HOPPERS};
use crate::rng::{derive, Rng};
use crate::rules::DifficultyRule;
use crate::scenarios::{
    fixed_strategies, genesis_fork_trial, genesis_gap, honest_bias, lowering_run, random_patterns,
    startup, step, ForkOutcome, Stamping, Strategy,
};
use crate::sim::{par_map, DEQ, TARGET};
use std::fmt::Write;

#[derive(Clone, Debug)]
pub struct SelConfig {
    pub seed: u64,
    pub threads: usize,
    pub qs: Vec<f64>,
    pub z: usize,
    /// Trials per (rule, q, policy) in the screening pass (seed set A).
    pub screen_trials: usize,
    /// Trials per (rule, q, policy) in the confirmation pass (seed set B).
    pub confirm_trials: usize,
    pub bias_seeds: usize,
    pub bias_blocks: usize,
    pub median_seeds: usize,
    pub hopper_seeds: usize,
    pub hopper_blocks: usize,
    pub lowering_seeds: usize,
    pub lowering_blocks: usize,
    pub patterns: usize,
    pub pattern_blocks: usize,
    pub fork_trials: usize,
}

impl SelConfig {
    pub fn full(seed: u64, threads: usize) -> Self {
        Self {
            seed,
            threads,
            qs: vec![0.3, 0.35, 0.4],
            z: 100,
            screen_trials: 1_000,
            confirm_trials: 4_000,
            bias_seeds: 4,
            bias_blocks: 50_000,
            median_seeds: 101,
            hopper_seeds: 3,
            hopper_blocks: 20_000,
            lowering_seeds: 3,
            lowering_blocks: 3_000,
            patterns: 120,
            pattern_blocks: 1_500,
            fork_trials: 300,
        }
    }

    pub fn quick(seed: u64, threads: usize) -> Self {
        Self {
            screen_trials: 100,
            confirm_trials: 300,
            bias_seeds: 2,
            bias_blocks: 10_000,
            median_seeds: 21,
            hopper_seeds: 1,
            hopper_blocks: 5_000,
            lowering_seeds: 1,
            lowering_blocks: 1_000,
            patterns: 10,
            pattern_blocks: 500,
            fork_trials: 50,
            ..Self::full(seed, threads)
        }
    }
}

const CHUNK: usize = 50;

/// Screening tallies `(policy, hits)` and the selected adaptive policy.
type Screened = (Vec<(Attack, u64)>, Attack);
const MAX_FOLLOW: usize = 3_000;
const TAG_SCREEN: u64 = 101;
const TAG_CONFIRM: u64 = 102;
const TAG_BIAS: u64 = 103;
const TAG_HOP: u64 = 104;
const TAG_STEP: u64 = 105;
const TAG_START: u64 = 106;
const TAG_GAP: u64 = 107;
const TAG_LOWER: u64 = 108;
const TAG_PATTERN: u64 = 109;
const TAG_FORK: u64 = 110;

#[derive(Clone, Debug)]
pub struct RaceQ {
    pub q: f64,
    /// Screening: (policy, hits) on seed set A.
    pub screen: Vec<(Attack, u64)>,
    pub best: Attack,
    pub honest: u64,
    pub compressed: u64,
    pub best_hits: u64,
    pub trials: u64,
}

impl RaceQ {
    pub fn p(&self, h: u64) -> f64 {
        h as f64 / self.trials as f64
    }
    /// Worst confirmed attacker (compressed or the selected adaptive policy) minus
    /// the honest-stamp baseline, all on seed set B.
    pub fn excess(&self) -> f64 {
        self.p(self.compressed.max(self.best_hits)) - self.p(self.honest)
    }
}

#[derive(Clone, Debug)]
pub struct SelResult {
    pub name: String,
    pub race: Vec<RaceQ>,
    pub emission_best: (String, f64),
    pub emission_families: Vec<(String, String, f64)>,
    pub hop: Vec<HopFair>,
    pub bias: f64,
    pub up_det: Option<usize>,
    pub up_med: Option<usize>,
    pub down_det: Option<usize>,
    pub down_med: Option<usize>,
    pub down_hours: f64,
    pub drop100: (Option<usize>, f64),
    pub half_det: Option<usize>,
    pub half_med: Option<usize>,
    pub gap_det: Option<usize>,
    pub gap_med: Option<usize>,
    pub gap_extra_med: i64,
    pub gap_d100: Option<usize>,
    pub fork: (u64, u64),
}

/// Pass/fail per criterion.
#[derive(Clone, Debug)]
pub struct Checks {
    pub race40: bool,
    pub race35: bool,
    pub emission: bool,
    pub hopper: bool,
    pub bias: bool,
    pub up: bool,
    pub down: bool,
    pub half: bool,
    pub gap: bool,
}

impl Checks {
    pub fn list(&self) -> [bool; 9] {
        [
            self.race40,
            self.race35,
            self.emission,
            self.hopper,
            self.bias,
            self.up,
            self.down,
            self.half,
            self.gap,
        ]
    }
    pub fn fails(&self) -> usize {
        self.list().iter().filter(|x| !**x).count()
    }
}

fn worse(a: Option<usize>, b: Option<usize>) -> Option<usize> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        _ => None,
    }
}

impl SelResult {
    pub fn race_at(&self, q: f64) -> Option<&RaceQ> {
        self.race.iter().find(|r| (r.q - q).abs() < 1e-9)
    }
    pub fn hop_excess(&self) -> f64 {
        self.hop
            .iter()
            .map(|h| h.excess_points())
            .fold(0.0, |a: f64, b| if b.abs() > a.abs() { b } else { a })
    }
    pub fn checks(&self) -> Checks {
        let r40 = self.race_at(0.4).map_or(1.0, |r| r.excess());
        let r35 = self
            .race
            .iter()
            .filter(|r| r.q <= 0.35 + 1e-9)
            .map(|r| r.excess())
            .fold(f64::MIN, f64::max);
        let le = |b: Option<usize>, x| b.is_some_and(|b| b <= x);
        Checks {
            race40: r40 <= 0.05,
            race35: r35 <= 0.01,
            emission: self.emission_best.1 <= 1.0,
            hopper: self.hop_excess().abs() <= 3.0,
            bias: self.bias.abs() <= 0.015,
            // Follow criteria: the slower of the deterministic run and the median.
            up: le(worse(self.up_det, self.up_med), 150),
            down: le(worse(self.down_det, self.down_med), 150),
            half: le(self.half_med, 60),
            gap: le(self.gap_med, 120),
        }
    }
}

fn median_of(mut v: Vec<Option<usize>>) -> Option<usize> {
    v.sort_by_key(|x| x.unwrap_or(usize::MAX));
    v[v.len() / 2]
}

fn qt(q: f64) -> u64 {
    (q * 1_000.0).round() as u64
}

pub fn run(cfg: &SelConfig, rules: &[Box<dyn DifficultyRule>]) -> Vec<SelResult> {
    let th = cfg.threads;
    let seed = cfg.seed;
    let mut policies = vec![Attack::Compressed];
    policies.extend(Attack::adaptive());

    // Race, screening (seed set A; common random numbers across rules and policies).
    let mut jobs = Vec::new();
    for r in 0..rules.len() {
        for &q in &cfg.qs {
            for (pi, &a) in policies.iter().enumerate() {
                for c in 0..cfg.screen_trials.div_ceil(CHUNK) {
                    let n = CHUNK.min(cfg.screen_trials - c * CHUNK);
                    jobs.push((r, q, pi, a, n, c as u64));
                }
            }
        }
    }
    let screen = par_map(&jobs, th, |&(r, q, _, a, n, c)| {
        adaptive::race(
            rules[r].as_ref(),
            q,
            cfg.z,
            a,
            n,
            derive(seed, &[TAG_SCREEN, qt(q), c]),
        )
    });
    let mut best: Vec<Vec<Screened>> = Vec::new();
    for r in 0..rules.len() {
        let mut per_q = Vec::new();
        for &q in &cfg.qs {
            let tally: Vec<(Attack, u64)> = policies
                .iter()
                .enumerate()
                .map(|(pi, &a)| {
                    let hits = jobs
                        .iter()
                        .zip(&screen)
                        .filter(|(j, _)| j.0 == r && j.1 == q && j.2 == pi)
                        .map(|(_, h)| *h)
                        .sum();
                    (a, hits)
                })
                .collect();
            let b = tally[1..]
                .iter()
                .max_by_key(|x| x.1)
                .map(|x| x.0)
                .expect("adaptive policies");
            per_q.push((tally, b));
        }
        best.push(per_q);
    }
    // Confirmation (seed set B): honest, compressed and the selected adaptive policy.
    let mut cjobs = Vec::new();
    for (r, per_q) in best.iter().enumerate() {
        for (qi, &q) in cfg.qs.iter().enumerate() {
            for (k, a) in [Attack::Honest, Attack::Compressed, per_q[qi].1]
                .into_iter()
                .enumerate()
            {
                for c in 0..cfg.confirm_trials.div_ceil(CHUNK) {
                    let n = CHUNK.min(cfg.confirm_trials - c * CHUNK);
                    cjobs.push((r, qi, k, a, q, n, c as u64));
                }
            }
        }
    }
    let confirm = par_map(&cjobs, th, |&(r, _, _, a, q, n, c)| {
        adaptive::race(
            rules[r].as_ref(),
            q,
            cfg.z,
            a,
            n,
            derive(seed, &[TAG_CONFIRM, qt(q), c]),
        )
    });

    // Honest bias and hoppers.
    let bias_jobs: Vec<(usize, u64)> = (0..rules.len())
        .flat_map(|r| (0..cfg.bias_seeds as u64).map(move |s| (r, s)))
        .collect();
    let bias_out = par_map(&bias_jobs, th, |&(r, s)| {
        let mut rng = Rng::new(derive(seed, &[TAG_BIAS, s]));
        honest_bias(rules[r].as_ref(), cfg.bias_blocks, &mut rng)
    });
    let hop_jobs: Vec<(usize, usize, u64)> = (0..rules.len())
        .flat_map(|r| {
            (0..HOPPERS.len())
                .flat_map(move |h| (0..cfg.hopper_seeds as u64).map(move |s| (r, h, s)))
        })
        .collect();
    let hop_out = par_map(&hop_jobs, th, |&(r, h, s)| {
        let (on, off, big) = HOPPERS[h];
        let mut rng = Rng::new(derive(seed, &[TAG_HOP, h as u64, s]));
        adaptive::hopper(rules[r].as_ref(), cfg.hopper_blocks, on, off, big, &mut rng)
    });

    // Follow scenarios and the genesis fork.
    let follow = par_map(&(0..rules.len()).collect::<Vec<_>>(), th, |&r| {
        let rule = rules[r].as_ref();
        let med_step = |f: f64, tag: u64| {
            median_of(
                (0..cfg.median_seeds as u64)
                    .map(|s| {
                        let mut rng = Rng::new(derive(seed, &[TAG_STEP, tag, s]));
                        step(rule, f, Some(&mut rng), MAX_FOLLOW).blocks
                    })
                    .collect(),
            )
        };
        let up = step(rule, 10.0, None, MAX_FOLLOW);
        let down = step(rule, 0.1, None, MAX_FOLLOW);
        let drop100 = adaptive::drop_hours(rule, 0.01, MAX_FOLLOW);
        let half_det = startup(rule, 0.5, None, MAX_FOLLOW).1.blocks;
        let half_med = median_of(
            (0..cfg.median_seeds as u64)
                .map(|s| {
                    let mut rng = Rng::new(derive(seed, &[TAG_START, s]));
                    startup(rule, 0.5, Some(&mut rng), MAX_FOLLOW).1.blocks
                })
                .collect(),
        );
        let gap_det = genesis_gap(rule, DEQ, 7_200, None, MAX_FOLLOW);
        let gaps: Vec<_> = (0..cfg.median_seeds as u64)
            .map(|s| {
                let mut rng = Rng::new(derive(seed, &[TAG_GAP, s]));
                genesis_gap(rule, DEQ, 7_200, Some(&mut rng), MAX_FOLLOW)
            })
            .collect();
        let mut extra: Vec<i64> = gaps.iter().map(|g| g.extra_blocks_6h).collect();
        extra.sort_unstable();
        let gap_d100 = genesis_gap(rule, 100, 7_200, None, MAX_FOLLOW).recovered_at;
        (
            up.blocks,
            med_step(10.0, 1),
            down.blocks,
            med_step(0.1, 2),
            down.hours,
            drop100,
            half_det,
            half_med,
            gap_det.recovered_at,
            median_of(gaps.iter().map(|g| g.recovered_at).collect()),
            extra[extra.len() / 2],
            gap_d100,
        )
    });
    let fork_jobs: Vec<(usize, u64)> = (0..rules.len())
        .flat_map(|r| (0..cfg.fork_trials.div_ceil(25) as u64).map(move |c| (r, c)))
        .collect();
    let fork_out = par_map(&fork_jobs, th, |&(r, c)| {
        let n = 25.min(cfg.fork_trials - c as usize * 25);
        let mut rng = Rng::new(derive(seed, &[TAG_FORK, c]));
        let mut w = 0u64;
        for _ in 0..n {
            if genesis_fork_trial(
                rules[r].as_ref(),
                0.2,
                720,
                Stamping::Compressed,
                864_000.0,
                &mut rng,
            ) == ForkOutcome::Win
            {
                w += 1;
            }
        }
        (w, n as u64)
    });

    // Timestamp lowering by a 100% miner: dossier 04's families on every rule.
    let fixed = fixed_strategies();
    let mut prng = Rng::new(derive(seed, &[TAG_PATTERN]));
    let patterns = random_patterns(cfg.patterns, &mut prng);
    let lseed = |s: u64| derive(seed, &[TAG_LOWER, s]);
    let mut low_jobs = Vec::new();
    for r in 0..rules.len() {
        for s in 0..cfg.lowering_seeds as u64 {
            low_jobs.push((r, Strategy::Honest, cfg.lowering_blocks, lseed(s)));
            for st in &fixed {
                low_jobs.push((r, st.clone(), cfg.lowering_blocks, lseed(s)));
            }
        }
        low_jobs.push((r, Strategy::Honest, cfg.pattern_blocks, lseed(1_000)));
        for p in &patterns {
            low_jobs.push((r, p.clone(), cfg.pattern_blocks, lseed(1_000)));
        }
    }
    let low_out = par_map(&low_jobs, th, |(r, st, b, sd)| {
        lowering_run(rules[*r].as_ref(), st, *b, *sd)
    });
    let mut rerun_jobs = Vec::new();
    for r in 0..rules.len() {
        let honest = low_jobs
            .iter()
            .zip(&low_out)
            .find(|(j, _)| j.0 == r && j.2 == cfg.pattern_blocks && j.1 == Strategy::Honest)
            .map(|(_, t)| *t)
            .expect("honest pattern baseline");
        let mut bestp = (f64::MIN, 0usize);
        for (j, p) in patterns.iter().enumerate() {
            let t = low_jobs
                .iter()
                .zip(&low_out)
                .find(|(jj, _)| jj.0 == r && jj.2 == cfg.pattern_blocks && jj.1 == *p)
                .map(|(_, t)| *t)
                .expect("pattern");
            if honest / t - 1.0 > bestp.0 {
                bestp = (honest / t - 1.0, j);
            }
        }
        for s in 0..cfg.lowering_seeds as u64 {
            rerun_jobs.push((r, Strategy::Honest, lseed(2_000 + s)));
            rerun_jobs.push((r, patterns[bestp.1].clone(), lseed(2_000 + s)));
        }
    }
    let rerun_out = par_map(&rerun_jobs, th, |(r, st, sd)| {
        lowering_run(rules[*r].as_ref(), st, cfg.lowering_blocks, *sd)
    });

    // Aggregate.
    let mut out = Vec::new();
    for (r, rule) in rules.iter().enumerate() {
        let race = cfg
            .qs
            .iter()
            .enumerate()
            .map(|(qi, &q)| {
                let sum = |k: usize| -> u64 {
                    cjobs
                        .iter()
                        .zip(&confirm)
                        .filter(|(j, _)| j.0 == r && j.1 == qi && j.2 == k)
                        .map(|(_, h)| *h)
                        .sum()
                };
                RaceQ {
                    q,
                    screen: best[r][qi].0.clone(),
                    best: best[r][qi].1,
                    honest: sum(0),
                    compressed: sum(1),
                    best_hits: sum(2),
                    trials: cfg.confirm_trials as u64,
                }
            })
            .collect();
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
        let (mut h, mut p, mut label) = (0.0, 0.0, String::new());
        for (j, o) in rerun_jobs.iter().zip(&rerun_out) {
            if j.0 == r {
                if j.1 == Strategy::Honest {
                    h += o;
                } else {
                    p += o;
                    label = j.1.label();
                }
            }
        }
        families.push((
            "random periodic patterns".into(),
            label,
            100.0 * (h / p - 1.0),
        ));
        let emission_best = families
            .iter()
            .max_by(|a, b| a.2.total_cmp(&b.2))
            .map(|f| (f.1.clone(), f.2))
            .expect("families");
        let per_seed: Vec<f64> = bias_jobs
            .iter()
            .zip(&bias_out)
            .filter(|(j, _)| j.0 == r)
            .map(|(_, &(s, n))| s / n as f64 / TARGET as f64 - 1.0)
            .collect();
        let hop = (0..HOPPERS.len())
            .map(|hc| {
                let v: Vec<HopFair> = hop_jobs
                    .iter()
                    .zip(&hop_out)
                    .filter(|(j, _)| j.0 == r && j.1 == hc)
                    .map(|(_, x)| *x)
                    .collect();
                let n = v.len() as f64;
                HopFair {
                    share: v.iter().map(|x| x.share).sum::<f64>() / n,
                    fair: v.iter().map(|x| x.fair).sum::<f64>() / n,
                }
            })
            .collect();
        let fork = fork_jobs
            .iter()
            .zip(&fork_out)
            .filter(|(j, _)| j.0 == r)
            .fold((0, 0), |a, (_, o)| (a.0 + o.0, a.1 + o.1));
        let f = follow[r];
        out.push(SelResult {
            name: rule.name(),
            race,
            emission_best,
            emission_families: families,
            hop,
            bias: per_seed.iter().sum::<f64>() / per_seed.len() as f64,
            up_det: f.0,
            up_med: f.1,
            down_det: f.2,
            down_med: f.3,
            down_hours: f.4,
            drop100: f.5,
            half_det: f.6,
            half_med: f.7,
            gap_det: f.8,
            gap_med: f.9,
            gap_extra_med: f.10,
            gap_d100: f.11,
            fork,
        });
    }
    out
}

fn b(x: Option<usize>) -> String {
    x.map_or(format!("> {MAX_FOLLOW}"), |v| v.to_string())
}

fn mark(ok: bool) -> &'static str {
    if ok {
        "pass"
    } else {
        "**FAIL**"
    }
}

pub fn render(cfg: &SelConfig, res: &[SelResult], header: &str) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{header}");
    let _ = writeln!(s, "## Configuration\n");
    let _ = writeln!(
        s,
        "- Base seed `{:#x}`; every job derives its seed from the base seed and its scenario coordinates, not from the rule, so all rules and policies run on common random numbers. {} threads.",
        cfg.seed, cfg.threads
    );
    let _ = writeln!(
        s,
        "- Race: z = {}, q in {:?}. Screening: {} trials per (rule, q, policy) on seed set A over the policies compressed + {}. Confirmation: {} trials each of honest, compressed and the screened-best adaptive policy on the disjoint seed set B. Excess = max(compressed, best adaptive) - honest, all on B.",
        cfg.z,
        cfg.qs,
        cfg.screen_trials,
        Attack::adaptive().iter().map(|a| a.label()).collect::<Vec<_>>().join(", "),
        cfg.confirm_trials
    );
    let _ = writeln!(
        s,
        "- Lowering (100% miner): dossier 04's fixed families on {} seeds x {} blocks, {} random patterns selected on {} blocks and the best re-run on {} fresh seeds. Emission gain = blocks/h over honest stamping on the same draws.",
        cfg.lowering_seeds, cfg.lowering_blocks, cfg.patterns, cfg.pattern_blocks, cfg.lowering_seeds
    );
    let _ = writeln!(
        s,
        "- Hopper: configurations (on < x DEQ, off > y DEQ, hash multiple) {:?}, {} seeds x {} blocks each; reported: the largest |share - fair share| in points, where fair share = the hopper's share of hashes spent.",
        HOPPERS, cfg.hopper_seeds, cfg.hopper_blocks
    );
    let _ = writeln!(
        s,
        "- Bias: {} seeds x {} blocks. Medians: {} seeds. Follow criteria use the slower of the deterministic run and the stochastic median; 0.5xD0 and the gap use the stochastic median. Genesis fork (informational): q = 0.2, age 720, compressed, {} trials.\n",
        cfg.bias_seeds, cfg.bias_blocks, cfg.median_seeds, cfg.fork_trials
    );

    let _ = writeln!(s, "## Every candidate against every criterion\n");
    let _ = writeln!(s, "| # | Rule | Race q=0.4 (<= +5%) | Race q<=0.35 (<= +1%) | Emission gain (<= +1%) | Hopper vs fair (+-3 pts) | Bias (+-1.5%) | 10x up (<= 150) | 10x down (<= 150) | 0.5xD0 median (<= 60) | Gap median (<= 120) | Fails |");
    let _ = writeln!(s, "|---|---|---|---|---|---|---|---|---|---|---|---|");
    for (i, r) in res.iter().enumerate() {
        let c = r.checks();
        let r40 = r.race_at(0.4).map_or(f64::NAN, |x| x.excess());
        let r35 = r
            .race
            .iter()
            .filter(|x| x.q <= 0.35 + 1e-9)
            .map(|x| x.excess())
            .fold(f64::MIN, f64::max);
        let _ = writeln!(
            s,
            "| {} | {} | {} {:+.1}% | {} {:+.2}% | {} {:+.2}% | {} {:+.1} | {} {:+.2}% | {} {}/{} | {} {}/{} | {} {} | {} {} | {} |",
            i + 1,
            r.name,
            mark(c.race40),
            100.0 * r40,
            mark(c.race35),
            100.0 * r35,
            mark(c.emission),
            r.emission_best.1,
            mark(c.hopper),
            r.hop_excess(),
            mark(c.bias),
            100.0 * r.bias,
            mark(c.up),
            b(r.up_det),
            b(r.up_med),
            mark(c.down),
            b(r.down_det),
            b(r.down_med),
            mark(c.half),
            b(r.half_med),
            mark(c.gap),
            b(r.gap_med),
            c.fails()
        );
    }
    let _ = writeln!(s, "\nFollow cells: deterministic / median blocks. All rules are exact integer arithmetic (criterion 8); see the rule definitions.\n");

    let _ = writeln!(
        s,
        "## Race detail (z = {}, confirmation pass, {} trials per cell)\n",
        cfg.z, cfg.confirm_trials
    );
    let _ = writeln!(s, "Cells: honest / compressed / best adaptive (policy) -> excess. Standard error of a difference near p = 0.05: about 0.007.\n");
    let _ = write!(s, "| Rule |");
    for q in &cfg.qs {
        let _ = write!(s, " q = {q} |");
    }
    let _ = writeln!(s, "\n|---|{}", "---|".repeat(cfg.qs.len()));
    for r in res {
        let _ = write!(s, "| {} |", r.name);
        for x in &r.race {
            let _ = write!(
                s,
                " {:.3} / {:.3} / {:.3} ({}) -> {:+.1}% |",
                x.p(x.honest),
                x.p(x.compressed),
                x.p(x.best_hits),
                x.best.label(),
                100.0 * x.excess()
            );
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(
        s,
        "\n### Screening pass at q = 0.4 (seed set A, {} trials per policy; hits)\n",
        cfg.screen_trials
    );
    let pol: Vec<String> = res[0]
        .race_at(0.4)
        .map_or(vec![], |x| x.screen.iter().map(|p| p.0.label()).collect());
    let _ = writeln!(s, "| Rule | {} |", pol.join(" | "));
    let _ = writeln!(s, "|---|{}", "---|".repeat(pol.len()));
    for r in res {
        if let Some(x) = r.race_at(0.4) {
            let _ = writeln!(
                s,
                "| {} | {} |",
                r.name,
                x.screen
                    .iter()
                    .map(|p| p.1.to_string())
                    .collect::<Vec<_>>()
                    .join(" | ")
            );
        }
    }

    let _ = writeln!(
        s,
        "\n## Timestamp lowering by a 100% miner (best member per family, blocks/h gain)\n"
    );
    let fams: Vec<String> = res[0]
        .emission_families
        .iter()
        .map(|f| f.0.clone())
        .collect();
    let _ = writeln!(s, "| Rule | {} |", fams.join(" | "));
    let _ = writeln!(s, "|---|{}", "---|".repeat(fams.len()));
    for r in res {
        let _ = writeln!(
            s,
            "| {} | {} |",
            r.name,
            r.emission_families
                .iter()
                .map(|f| format!("{:+.2}% ({})", f.2, f.1))
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }

    let _ = writeln!(s, "\n## Hoppers (share / fair share of blocks)\n");
    let _ = writeln!(
        s,
        "| Rule | {} |",
        HOPPERS
            .iter()
            .map(|(a, b, c)| format!("on<{a} off>{b} x{c}"))
            .collect::<Vec<_>>()
            .join(" | ")
    );
    let _ = writeln!(s, "|---|{}", "---|".repeat(HOPPERS.len()));
    for r in res {
        let _ = writeln!(
            s,
            "| {} | {} |",
            r.name,
            r.hop
                .iter()
                .map(|h| format!("{:.3} / {:.3} ({:+.1})", h.share, h.fair, h.excess_points()))
                .collect::<Vec<_>>()
                .join(" | ")
        );
    }

    let _ = writeln!(
        s,
        "\n## Liveness and start-up (informational columns included)\n"
    );
    let _ = writeln!(s, "| Rule | 10x down: hours (det) | 100x drop: blocks, hours (det) | 0.5xD0 det | Gap det | Gap: extra blocks in first 6 h (median) | Gap at D0 = 100 (det) | Genesis fork q=0.2 age 720 (compressed) |");
    let _ = writeln!(s, "|---|---|---|---|---|---|---|---|");
    for r in res {
        let _ = writeln!(
            s,
            "| {} | {:.1} | {}, {:.1} | {} | {} | {:+} | {} | {}/{} |",
            r.name,
            r.down_hours,
            b(r.drop100.0),
            r.drop100.1,
            b(r.half_det),
            b(r.gap_det),
            r.gap_extra_med,
            b(r.gap_d100),
            r.fork.0,
            r.fork.1
        );
    }
    let passing: Vec<&str> = res
        .iter()
        .filter(|r| r.checks().fails() == 0)
        .map(|r| r.name.as_str())
        .collect();
    let _ = writeln!(s, "\n## Automated verdict\n");
    if passing.is_empty() {
        let _ = writeln!(s, "- No candidate meets every criterion.");
    } else {
        let _ = writeln!(
            s,
            "- Candidates meeting every criterion: {}.",
            passing.join("; ")
        );
    }
    let mut ranked: Vec<(usize, &SelResult)> =
        res.iter().map(|r| (r.checks().fails(), r)).collect();
    ranked.sort_by_key(|x| x.0);
    for (f, r) in ranked.iter().filter(|x| x.0 == 1) {
        let c = r.checks();
        let names = [
            "race q=0.4",
            "race q<=0.35",
            "emission",
            "hopper",
            "bias",
            "10x up",
            "10x down",
            "0.5xD0",
            "gap",
        ];
        let which: Vec<&str> = c
            .list()
            .iter()
            .zip(names)
            .filter(|x| !*x.0)
            .map(|x| x.1)
            .collect();
        let _ = writeln!(s, "- {} fails {f}: {}.", r.name, which.join(", "));
    }
    s
}
