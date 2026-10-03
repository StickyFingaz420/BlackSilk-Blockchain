//! Statistical tests of the wallet decoy picker (`tx/src/decoy.rs`) as it is
//! (item A-STATS: dossier 38 D4 and the F38-4/M4 guess-newest measurement,
//! decision D7 part (a), tm2-crosscheck X7; decisions "Decoy and relay plan
//! (2026-10-04)").
//!
//! The reference is an **independent model** of the picker's age draw, written
//! here from the specification (docs/transactions.md §11.3.1), not from the
//! code: on a chain with `k` outputs in every block, a draw lands on the block
//! `d` deep with
//!
//! ```text
//! p(d) = [d − 10 < 15] · F(ln 10T) / 15  +  F(ln (d+1)T) − F(ln dT),   d ≥ 10
//! ```
//!
//! where `F` is the CDF of Gamma(shape 19.28, rate 1.61) over log-seconds and
//! `T` the block time, renormalised over the depths the chain has. (The first
//! term is the uniform draw over the last 15 blocks taken when the age falls
//! inside the 10-block lock; the second the age past the lock.) An off-by-one
//! in the lock shift, the spendable age or the index-to-block mapping moves
//! mass between adjacent depths, which the goodness-of-fit and boundary tests
//! below see.
//!
//! Conventions:
//! - fixed ChaCha seeds; assertions are on statistics with tolerances, never on
//!   exact rings (libm's `exp`/`ln` are not bitwise portable, so the exact
//!   rings may differ between platforms);
//! - chi-square and binomial z-scores are computed here (no new dependencies);
//!   p-value thresholds are 1e-4, z thresholds 4.5;
//! - the measured values are printed (`--nocapture`); docs/transactions.md
//!   §11.3.1 cites them.
//!
//! The wallet's eligibility closure (`wallet/src/wallet/px_flows.rs`,
//! `plans_for`) is mirrored in [`Chain::eligible`]; this crate cannot depend
//! on the wallet.

use blacksilk_crypto::{Point, RistrettoPoint, Scalar};
use blacksilk_px_core::Digest;
use blacksilk_tx::decoy::{select_ring, select_ring_keeping, usable_outputs};
use blacksilk_tx::params::{COINBASE_MATURITY, RING_SIZE, SPENDABLE_AGE};
use blacksilk_tx::types::{Input, OutputKey};
use blacksilk_tx::validate::{resolve_input_rings, ChainView, OutputRecord, PxProgram};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use std::sync::OnceLock;

/// Block time in seconds (the testnet and mainnet value).
const T: u64 = 120;
const GAMMA_SHAPE: f64 = 19.28;
const GAMMA_RATE: f64 = 1.61;
/// The uniform draw below the lock covers this many blocks.
const RECENT_WINDOW: u64 = 15;
const DECOYS: usize = RING_SIZE - 1;
/// p-value below which a chi-square statistic fails.
const P_MIN: f64 = 1e-4;
/// |z| above which a binomial count fails.
const Z_MAX: f64 = 4.5;

// ------------------------------------------------------------------ statistics

/// ln Γ(x) for x > 0 (Lanczos, g = 7, n = 9; relative error below 1e-13).
fn ln_gamma(x: f64) -> f64 {
    const C: [f64; 9] = [
        0.999_999_999_999_809_9,
        676.520_368_121_885_1,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    let x = x - 1.0;
    let t = x + 7.5;
    let a = C[0]
        + C[1..]
            .iter()
            .enumerate()
            .map(|(i, c)| c / (x + i as f64 + 1.0))
            .sum::<f64>();
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// The regularized incomplete gamma functions (P(a, x), Q(a, x)): series for
/// x < a + 1, Lentz's continued fraction otherwise (Numerical Recipes §6.2).
fn incomplete_gamma(a: f64, x: f64) -> (f64, f64) {
    if x <= 0.0 {
        return (0.0, 1.0);
    }
    let front = (-x + a * x.ln() - ln_gamma(a)).exp();
    if x < a + 1.0 {
        let (mut ap, mut del, mut sum) = (a, 1.0 / a, 1.0 / a);
        for _ in 0..10_000 {
            ap += 1.0;
            del *= x / ap;
            sum += del;
            if del.abs() < sum.abs() * 1e-16 {
                break;
            }
        }
        let p = sum * front;
        (p, 1.0 - p)
    } else {
        const TINY: f64 = 1e-300;
        let mut b = x + 1.0 - a;
        let mut c = 1.0 / TINY;
        let mut d = 1.0 / b;
        let mut h = d;
        for i in 1..10_000 {
            let an = -(i as f64) * (i as f64 - a);
            b += 2.0;
            d = an * d + b;
            if d.abs() < TINY {
                d = TINY;
            }
            c = b + an / c;
            if c.abs() < TINY {
                c = TINY;
            }
            d = 1.0 / d;
            let del = d * c;
            h *= del;
            if (del - 1.0).abs() < 1e-16 {
                break;
            }
        }
        let q = front * h;
        (1.0 - q, q)
    }
}

/// The CDF of the picker's log-age Gamma(19.28, rate 1.61) at `g` log-seconds.
fn gamma_cdf(g: f64) -> f64 {
    incomplete_gamma(GAMMA_SHAPE, g * GAMMA_RATE).0
}

/// The upper tail of the chi-square distribution with `df` degrees of freedom.
fn chi_square_p(stat: f64, df: usize) -> f64 {
    incomplete_gamma(df as f64 / 2.0, stat / 2.0).1
}

/// Binomial z-score of `observed` successes in `n` trials of probability `p`.
fn z_score(observed: u64, n: u64, p: f64) -> f64 {
    let expected = n as f64 * p;
    (observed as f64 - expected) / (expected * (1.0 - p)).sqrt()
}

/// Pearson's statistic over bins of at least `min_expected` expected counts
/// (adjacent bins are merged in order). Returns (statistic, degrees of
/// freedom, p-value). `expected` must sum to the same total as `observed`.
fn chi_square(observed: &[u64], expected: &[f64], min_expected: f64) -> (f64, usize, f64) {
    assert_eq!(observed.len(), expected.len());
    let mut bins: Vec<(f64, f64)> = Vec::new();
    let (mut o, mut e) = (0.0, 0.0);
    for (&ob, &ex) in observed.iter().zip(expected) {
        o += ob as f64;
        e += ex;
        if e >= min_expected {
            bins.push((o, e));
            (o, e) = (0.0, 0.0);
        }
    }
    if e > 0.0 || o > 0.0 {
        match bins.last_mut() {
            Some(last) => {
                last.0 += o;
                last.1 += e;
            }
            None => bins.push((o, e)),
        }
    }
    let stat: f64 = bins.iter().map(|&(o, e)| (o - e) * (o - e) / e).sum();
    let df = bins.len() - 1;
    (stat, df, chi_square_p(stat, df))
}

fn uniform01(rng: &mut ChaCha20Rng) -> f64 {
    (rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64
}

// ------------------------------------------------------------------ the model

/// The picker's block-depth distribution on a chain whose next block has
/// height `height` and whose blocks all hold the same number of outputs (the
/// formula in the module documentation).
struct Model {
    /// `pmf[d]`: probability that a draw lands `d` blocks deep (0 below 10).
    pmf: Vec<f64>,
    /// `cdf[d]`: probability of a depth ≤ d.
    cdf: Vec<f64>,
}

impl Model {
    fn new(height: u64) -> Self {
        let f = |d: u64| gamma_cdf(((d * T) as f64).ln());
        let lock = f(SPENDABLE_AGE);
        let mut pmf = vec![0.0; height as usize + 1];
        let mut prev = lock;
        for d in SPENDABLE_AGE..=height {
            let next = f(d + 1);
            let mut p = next - prev;
            if d - SPENDABLE_AGE < RECENT_WINDOW {
                p += lock / RECENT_WINDOW as f64;
            }
            pmf[d as usize] = p;
            prev = next;
        }
        let total: f64 = pmf.iter().sum();
        pmf.iter_mut().for_each(|p| *p /= total);
        let mut acc = 0.0;
        let cdf = pmf
            .iter()
            .map(|p| {
                acc += p;
                acc
            })
            .collect();
        Self { pmf, cdf }
    }

    /// A depth drawn from the model (inverse CDF).
    fn sample(&self, rng: &mut ChaCha20Rng) -> u64 {
        let u = uniform01(rng);
        (self.cdf.partition_point(|&c| c < u) as u64).min(self.pmf.len() as u64 - 1)
    }

    /// Probability that a decoy is newer than an output at depth `d` sitting at
    /// position `j` of `k` outputs in its block (a decoy in the same block is
    /// one of the other `k − 1`, uniform).
    fn newer(&self, d: u64, j: u64, k: u64) -> f64 {
        let older_blocks = self.cdf[d as usize - 1];
        older_blocks + self.pmf[d as usize] * (k - 1 - j) as f64 / (k - 1) as f64
    }

    /// Expected guess-newest success for a real output at depth `d`, uniform
    /// in its block of `k` outputs (decoys treated as independent draws).
    fn guess_newest(&self, d: u64, k: u64) -> f64 {
        (0..k)
            .map(|j| (1.0 - self.newer(d, j, k)).powi(DECOYS as i32))
            .sum::<f64>()
            / k as f64
    }
}

fn model(height: u64) -> &'static Model {
    static STEADY: OnceLock<Model> = OnceLock::new();
    static YEAR: OnceLock<Model> = OnceLock::new();
    match height {
        STEADY_BLOCKS => STEADY.get_or_init(|| Model::new(height)),
        YEAR_BLOCKS => YEAR.get_or_init(|| Model::new(height)),
        _ => unreachable!("no cached model for {height}"),
    }
}

// ------------------------------------------------------------------ chains

/// A synthetic chain. The next block (the one a ring is built for) has height
/// `cum.len()`; block `b` is `height − b` deep.
struct Chain {
    /// Outputs in blocks `0..=b`.
    cum: Vec<u64>,
    /// The outputs of block `b` below `coinbase_end[b]` are coinbase outputs
    /// (a block's coinbase outputs come first).
    coinbase_end: Vec<u64>,
}

impl Chain {
    /// `blocks` blocks of `coinbase` coinbase and `per_block − coinbase`
    /// transfer outputs each.
    fn steady(blocks: u64, per_block: u64, coinbase: u64) -> Self {
        Self::from_blocks((0..blocks).map(|_| (coinbase, per_block - coinbase)))
    }

    /// Blocks of (coinbase outputs, transfer outputs).
    fn from_blocks(blocks: impl Iterator<Item = (u64, u64)>) -> Self {
        let (mut cum, mut coinbase_end) = (Vec::new(), Vec::new());
        let mut total = 0;
        for (c, t) in blocks {
            coinbase_end.push(total + c);
            total += c + t;
            cum.push(total);
        }
        Self { cum, coinbase_end }
    }

    fn height(&self) -> u64 {
        self.cum.len() as u64
    }

    fn block_start(&self, b: u64) -> u64 {
        if b == 0 {
            0
        } else {
            self.cum[b as usize - 1]
        }
    }

    fn block_of(&self, i: u64) -> u64 {
        self.cum.partition_point(|&c| c <= i) as u64
    }

    fn depth(&self, i: u64) -> u64 {
        self.height() - self.block_of(i)
    }

    fn is_coinbase(&self, i: u64) -> bool {
        i < self.coinbase_end[self.block_of(i) as usize]
    }

    /// The wallet's eligibility rule (`px_flows.rs`, `plans_for`): usable
    /// (at least 10 blocks deep) and, for a coinbase output, in a block at
    /// most `height − 60`.
    fn eligible(&self) -> impl Fn(u64) -> bool + '_ {
        let next = self.height();
        let usable = usable_outputs(&self.cum, next).unwrap_or(0);
        let coinbase_limit = next
            .checked_sub(COINBASE_MATURITY)
            .and_then(|h| self.cum.get(h as usize).copied())
            .unwrap_or(0);
        move |i| i < usable && !(self.is_coinbase(i) && i >= coinbase_limit)
    }

    fn ring(&self, rng: &mut ChaCha20Rng, real: u64) -> [u64; RING_SIZE] {
        select_ring(rng, &self.cum, self.height(), T, real, self.eligible()).unwrap()
    }

    /// A uniform output of the block `d` deep.
    fn output_at_depth(&self, rng: &mut ChaCha20Rng, d: u64) -> u64 {
        let b = self.height() - d;
        let start = self.block_start(b);
        start + rng.next_u64() % (self.cum[b as usize] - start)
    }
}

/// The steady chain of the distribution tests: 100,000 blocks (about 139 days
/// at 2 minutes), four transfer outputs each.
const STEADY_BLOCKS: u64 = 100_000;
const STEADY_K: u64 = 4;
/// One year at 2 minutes (the M4 "mature chain").
const YEAR_BLOCKS: u64 = 262_800;

/// Decoy depths drawn on the steady chain (shared by two tests).
struct DepthSample {
    /// `hist[d]`: decoys `d` blocks deep.
    hist: Vec<u64>,
    decoys: u64,
}

fn steady_sample() -> &'static DepthSample {
    static SAMPLE: OnceLock<DepthSample> = OnceLock::new();
    SAMPLE.get_or_init(|| {
        const RINGS: usize = 30_000;
        let chain = Chain::steady(STEADY_BLOCKS, STEADY_K, 0);
        let mut rng = ChaCha20Rng::seed_from_u64(0xD4_0001);
        let mut hist = vec![0u64; STEADY_BLOCKS as usize + 1];
        // The real input is the oldest output: the model puts no mass there.
        let real = 0;
        for _ in 0..RINGS {
            for m in chain
                .ring(&mut rng, real)
                .into_iter()
                .filter(|&m| m != real)
            {
                hist[chain.depth(m) as usize] += 1;
            }
        }
        DepthSample {
            hist,
            decoys: (RINGS * DECOYS) as u64,
        }
    })
}

// ------------------------------------------------------------------ distribution and D4

/// Baseline: on a steady chain the decoys' block depths follow the model
/// (chi-square over depth bins of at least 500 expected decoys).
#[test]
fn decoy_depths_follow_the_model_on_a_steady_chain() {
    let s = steady_sample();
    let m = model(STEADY_BLOCKS);
    let expected: Vec<f64> = m.pmf.iter().map(|p| p * s.decoys as f64).collect();
    let (stat, df, p) = chi_square(&s.hist, &expected, 500.0);
    println!("depth goodness of fit: chi2 {stat:.1}, df {df}, p {p:.3}");
    assert!(p > P_MIN, "decoy depths do not follow the model: p = {p}");
}

/// D4 (the Monero #8872 regression class): decoys exactly 10 blocks deep occur
/// at the model's rate; nothing younger ever occurs.
#[test]
fn decoys_exactly_spendable_age_deep_occur_at_the_model_rate() {
    let s = steady_sample();
    let m = model(STEADY_BLOCKS);
    let d = SPENDABLE_AGE as usize;
    let observed = s.hist[d];
    let z = z_score(observed, s.decoys, m.pmf[d]);
    println!(
        "depth 10: {observed} of {} decoys ({:.5}), model {:.5}, z {z:.2}",
        s.decoys,
        observed as f64 / s.decoys as f64,
        m.pmf[d]
    );
    assert!(observed > 0, "no decoy is exactly 10 blocks deep");
    assert!(z.abs() < Z_MAX, "depth-10 share off the model: z = {z}");
    assert_eq!(
        s.hist[..d].iter().sum::<u64>(),
        0,
        "a decoy younger than 10 blocks"
    );
    // The neighbours too: a shift by one block moves mass from 10 to 11.
    for d in [11, 12, 24, 25] {
        let z = z_score(s.hist[d], s.decoys, m.pmf[d]);
        assert!(z.abs() < Z_MAX, "depth {d}: z = {z}");
    }
}

/// D4 for coinbase outputs: on a chain of one coinbase and three transfer
/// outputs per block, coinbase decoys exactly 60 blocks deep occur at the rate
/// the model gives (a quarter of the block's draws), none younger; the
/// transfer outputs 59 blocks deep absorb the whole block's draws. On a
/// coinbase-only chain (a new testnet) coinbase decoys at 60 occur too.
#[test]
fn coinbase_decoys_exactly_coinbase_maturity_deep_occur_never_younger() {
    const RINGS: usize = 30_000;
    let chain = Chain::steady(STEADY_BLOCKS, STEADY_K, 1);
    let m = model(STEADY_BLOCKS);
    let mut rng = ChaCha20Rng::seed_from_u64(0xD4_0060);
    let real = 1; // the oldest transfer output
    let (mut coinbase_at, mut any_at) = (vec![0u64; 61], vec![0u64; 61]);
    let mut young_coinbase = 0;
    for _ in 0..RINGS {
        for i in chain
            .ring(&mut rng, real)
            .into_iter()
            .filter(|&i| i != real)
        {
            let (d, cb) = (chain.depth(i), chain.is_coinbase(i));
            if d <= COINBASE_MATURITY {
                any_at[d as usize] += 1;
                coinbase_at[d as usize] += cb as u64;
            }
            young_coinbase += (cb && d < COINBASE_MATURITY) as u64;
        }
    }
    let n = (RINGS * DECOYS) as u64;
    let p60 = m.pmf[60] / STEADY_K as f64;
    let z60 = z_score(coinbase_at[60], n, p60);
    let z59 = z_score(any_at[59], n, m.pmf[59]);
    println!(
        "coinbase decoys 60 deep: {} (model {:.1}, z {z60:.2}); decoys 59 deep: {} \
         (model {:.1}, z {z59:.2})",
        coinbase_at[60],
        p60 * n as f64,
        any_at[59],
        m.pmf[59] * n as f64
    );
    assert!(coinbase_at[60] > 0);
    assert!(z60.abs() < Z_MAX, "coinbase at 60: z = {z60}");
    assert!(z59.abs() < Z_MAX, "transfers at 59: z = {z59}");
    assert_eq!(young_coinbase, 0, "an immature coinbase decoy");

    // Coinbase-only: the neighbourhood rule feeds the young draws to the
    // first mature blocks (the bounded pile-up `no_pile_up_at_the_maturity_
    // boundary` measures); here only occurrence and maturity are checked.
    let chain = Chain::steady(3_000, 1, 1);
    let (mut at60, mut young) = (0, 0);
    for _ in 0..3_000 {
        for i in chain.ring(&mut rng, 0).into_iter().filter(|&i| i != 0) {
            at60 += (chain.depth(i) == COINBASE_MATURITY) as u64;
            young += (chain.depth(i) < COINBASE_MATURITY) as u64;
        }
    }
    println!("coinbase-only chain: {at60} decoys exactly 60 deep");
    assert!(at60 > 0);
    assert_eq!(young, 0);
}

// ------------------------------------------------------------------ property: picker vs consensus

/// A chain view over a synthetic chain: only `output` is answered.
struct View<'a> {
    chain: &'a Chain,
    key: OutputKey,
}

impl ChainView for View<'_> {
    fn output(&self, i: u64) -> Option<OutputRecord> {
        (i < *self.chain.cum.last()?).then(|| OutputRecord {
            key: self.key,
            height: self.chain.block_of(i),
            coinbase: self.chain.is_coinbase(i),
        })
    }
    fn is_key_image_spent(&self, _: &Point) -> bool {
        false
    }
    fn px_is_recent_root(&self, _: &Digest) -> bool {
        false
    }
    fn px_nullifier_spent(&self, _: &Digest) -> bool {
        false
    }
    fn px_pool(&self) -> u128 {
        0
    }
    fn px_function(&self, _: &Digest, _: &[u8; 32]) -> Option<PxProgram> {
        None
    }
    fn px_contract_exists(&self, _: &Digest) -> bool {
        false
    }
    fn px_tree_size(&self) -> u64 {
        0
    }
}

/// D4 property: on random chains (1–3 coinbase and 0–4 transfer outputs per
/// block), an output is eligible for the picker (the wallet's rule plus the
/// picker's usable range) exactly when the consensus ring check C1
/// (`resolve_input_rings`) accepts it at that height, and every ring the
/// picker builds passes C1. Across the chains, decoys exactly 10 (transfer)
/// and exactly 60 (coinbase) blocks deep occur.
#[test]
fn picker_eligibility_is_exactly_the_consensus_ring_check() {
    let mut rng = ChaCha20Rng::seed_from_u64(0xD4_C1);
    let point = Point::from_point(RistrettoPoint::mul_base(&Scalar::from(7u64)));
    let key = OutputKey {
        one_time_key: point,
        commitment: point,
    };
    let (mut chains, mut at10, mut coinbase_at60) = (0, 0u64, 0u64);
    while chains < 40 {
        let blocks = 70 + rng.next_u64() % 400;
        let shape: Vec<(u64, u64)> = (0..blocks)
            .map(|_| (1 + rng.next_u64() % 3, rng.next_u64() % 5))
            .collect();
        let chain = Chain::from_blocks(shape.into_iter());
        let height = chain.height();
        let eligible = chain.eligible();
        let view = View { chain: &chain, key };
        let c1 = |ring: [u64; RING_SIZE]| {
            resolve_input_rings(
                &[Input {
                    key_image: point,
                    ring,
                }],
                &view,
                height,
            )
            .is_ok()
        };
        let total = *chain.cum.last().unwrap();
        let pool: Vec<u64> = (0..total).filter(|&i| eligible(i)).collect();
        if pool.len() < RING_SIZE {
            continue;
        }
        chains += 1;
        for i in 0..total + 2 {
            assert_eq!(
                eligible(i),
                c1([i; RING_SIZE]),
                "output {i} (depth {}, coinbase {}) at height {height}",
                chain.depth(i.min(total - 1)),
                chain.is_coinbase(i.min(total - 1))
            );
        }
        for _ in 0..150 {
            let real = pool[(rng.next_u64() % pool.len() as u64) as usize];
            let ring = chain.ring(&mut rng, real);
            assert!(c1(ring), "a picked ring fails C1");
            assert!(ring.iter().all(|&i| eligible(i)));
            for &i in ring.iter().filter(|&&i| i != real) {
                let d = chain.depth(i);
                at10 += (d == SPENDABLE_AGE && !chain.is_coinbase(i)) as u64;
                coinbase_at60 += (d == COINBASE_MATURITY && chain.is_coinbase(i)) as u64;
            }
        }
    }
    println!("random chains: {at10} transfer decoys 10 deep, {coinbase_at60} coinbase 60 deep");
    assert!(at10 > 0 && coinbase_at60 > 0);
}

// ------------------------------------------------------------------ rank uniformity

/// If the real spend's depth follows the model, its rank among the 16 members
/// is uniform (chi-square over the 16 ranks). The real input is drawn from the
/// model computed here, the decoys by the picker, so a mismatch between the
/// two (an off-by-one included) skews the ranks. A negative control (real
/// spends uniform over the chain) shows the test has power.
#[test]
fn real_input_rank_is_uniform_when_spends_follow_the_model() {
    const RINGS: usize = 16_000;
    let chain = Chain::steady(STEADY_BLOCKS, STEADY_K, 0);
    let m = model(STEADY_BLOCKS);
    let mut rng = ChaCha20Rng::seed_from_u64(0xA5_0002);
    let rank = |rng: &mut ChaCha20Rng, real: u64| {
        let ring = chain.ring(rng, real);
        ring.iter().position(|&i| i == real).unwrap()
    };
    let mut ranks = [0u64; RING_SIZE];
    for _ in 0..RINGS {
        let depth = m.sample(&mut rng);
        let real = chain.output_at_depth(&mut rng, depth);
        ranks[rank(&mut rng, real)] += 1;
    }
    let uniform = [RINGS as f64 / RING_SIZE as f64; RING_SIZE];
    let (stat, df, p) = chi_square(&ranks, &uniform, 0.0);
    println!("rank of the real input (oldest first): {ranks:?}; chi2 {stat:.1}, df {df}, p {p:.3}");
    assert!(p > P_MIN, "ranks not uniform: p = {p}");

    let usable = usable_outputs(&chain.cum, chain.height()).unwrap();
    let mut control = [0u64; RING_SIZE];
    for _ in 0..2_000 {
        let real = rng.next_u64() % usable;
        control[rank(&mut rng, real)] += 1;
    }
    let uniform = [2_000.0 / RING_SIZE as f64; RING_SIZE];
    let (_, _, p) = chi_square(&control, &uniform, 0.0);
    assert!(p < 1e-6, "the control must be detected: p = {p}");
}

// ------------------------------------------------------------------ M4: guess-newest

/// M4 (F38-4): guess-newest success (the attacker names the newest ring
/// member) on a one-year steady chain (262,800 blocks, four outputs each):
/// - (a) real spends whose age follows the model: 1/16;
/// - (a') real spends at a fixed age of 12, 20, 60 and 120 blocks;
/// - (b) real spends skewed young: the age past the 10-block lock is a
///   quarter of a model draw.
///
/// Each measurement must match the model's prediction (decoys as independent
/// draws from the model) within 0.025 and lie in the range docs/transactions.md
/// §11.3.1 states.
#[test]
fn guess_newest_success_on_a_mature_chain() {
    const RINGS: usize = 3_000;
    let chain = Chain::steady(YEAR_BLOCKS, STEADY_K, 0);
    let m = model(YEAR_BLOCKS);
    let mut rng = ChaCha20Rng::seed_from_u64(0x4D_0004);
    let mut measure = |depth: &mut dyn FnMut(&mut ChaCha20Rng) -> u64| {
        let mut hits = 0;
        for _ in 0..RINGS {
            let d = depth(&mut rng);
            let real = chain.output_at_depth(&mut rng, d);
            hits += (chain.ring(&mut rng, real)[RING_SIZE - 1] == real) as u64;
        }
        hits as f64 / RINGS as f64
    };
    let skew = |d: u64| SPENDABLE_AGE + (d - SPENDABLE_AGE) / 4;
    let skewed_expected: f64 = (SPENDABLE_AGE..=YEAR_BLOCKS)
        .map(|d| m.pmf[d as usize] * m.guess_newest(skew(d), STEADY_K))
        .sum();

    let from_model = measure(&mut |rng| m.sample(rng));
    let skewed = measure(&mut |rng| skew(m.sample(rng)));
    let mut rows = vec![
        (
            "model".to_string(),
            from_model,
            1.0 / RING_SIZE as f64,
            (0.05, 0.08),
        ),
        ("skewed".to_string(), skewed, skewed_expected, (0.11, 0.17)),
    ];
    for (age, range) in [
        (12, (0.83, 0.89)),
        (20, (0.48, 0.57)),
        (60, (0.10, 0.16)),
        (120, (0.02, 0.05)),
    ] {
        let got = measure(&mut |_| age);
        rows.push((
            format!("age {age}"),
            got,
            m.guess_newest(age, STEADY_K),
            range,
        ));
    }
    for (what, got, expected, (lo, hi)) in rows {
        println!("{what}: guess-newest {got:.3}, model {expected:.3}, stated range {lo}-{hi}");
        assert!(
            (got - expected).abs() < 0.025,
            "{what}: {got} vs {expected}"
        );
        assert!((lo..=hi).contains(&got), "{what}: {got} outside {lo}-{hi}");
    }
}

// ------------------------------------------------------------------ D7 (a): coinbase proportionality

/// D7 part (a): on a chain of one coinbase and 0–4 transfer outputs per block
/// (coinbase about a third of all outputs), coinbase decoys in each depth
/// bucket appear in proportion to the coinbase share of the eligible outputs
/// of that bucket; below 60 blocks there are none.
#[test]
fn coinbase_decoys_appear_in_proportion_at_each_age() {
    const BLOCKS: u64 = 50_000;
    const RINGS: usize = 20_000;
    const EDGES: [u64; 12] = [
        10, 60, 70, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 20_000, 50_001,
    ];
    let mut rng = ChaCha20Rng::seed_from_u64(0xD7_000A);
    let chain = Chain::from_blocks(
        (0..BLOCKS)
            .map(|_| (1, rng.next_u64() % 5))
            .collect::<Vec<_>>()
            .into_iter(),
    );
    let bucket = |d: u64| EDGES.partition_point(|&e| e <= d) - 1;
    let eligible = chain.eligible();
    let buckets = EDGES.len() - 1;
    let (mut pool_cb, mut pool_all) = (vec![0u64; buckets], vec![0u64; buckets]);
    for i in 0..*chain.cum.last().unwrap() {
        if eligible(i) {
            let b = bucket(chain.depth(i));
            pool_all[b] += 1;
            pool_cb[b] += chain.is_coinbase(i) as u64;
        }
    }
    let (mut got_cb, mut got_all) = (vec![0u64; buckets], vec![0u64; buckets]);
    let real = 0; // block 0's coinbase output, 50,000 blocks deep
    for _ in 0..RINGS {
        for i in chain
            .ring(&mut rng, real)
            .into_iter()
            .filter(|&i| i != real)
        {
            let b = bucket(chain.depth(i));
            got_all[b] += 1;
            got_cb[b] += chain.is_coinbase(i) as u64;
        }
    }
    assert_eq!(pool_cb[0] + got_cb[0], 0, "immature coinbase");
    let mut stat = 0.0;
    for b in 1..buckets {
        let share = pool_cb[b] as f64 / pool_all[b] as f64;
        let z = z_score(got_cb[b], got_all[b], share);
        println!(
            "depth {}-{}: coinbase {:.3} of decoys, {share:.3} of eligible outputs ({} decoys, z {z:.2})",
            EDGES[b],
            EDGES[b + 1] - 1,
            got_cb[b] as f64 / got_all[b] as f64,
            got_all[b]
        );
        assert!(z.abs() < Z_MAX, "bucket {b}: z = {z}");
        stat += z * z;
    }
    let p = chi_square_p(stat, buckets - 1);
    println!(
        "coinbase proportionality: chi2 {stat:.1}, df {}, p {p:.3}",
        buckets - 1
    );
    assert!(p > P_MIN);
}

// ------------------------------------------------------------------ X7: rings rebuilt after a reorg

/// X7: a transfer is built, a reorganization of depth K replaces the last K
/// blocks (different outputs), and the wallet rebuilds the spend. Anyone who
/// saw both transactions (they share the key image) learns that the real
/// input is in the intersection of the two rings. The wallet keeps every old
/// member that still exists (W-5, `select_ring_keeping` with the members the
/// index still holds unchanged), so the intersection is exactly the real
/// input plus the surviving decoys; a fresh ring would leave about one.
///
/// Measured on the steady chain for a real input 1,000 blocks deep, 2,000
/// rings per depth; the mean intersection must match the model (15 decoys,
/// each orphaned with the model's mass at depths 10..=K) within 0.15.
#[test]
fn reorg_ring_intersection_after_rebuilding() {
    const RINGS: usize = 2_000;
    let chain = Chain::steady(STEADY_BLOCKS, STEADY_K, 0);
    let m = model(STEADY_BLOCKS);
    let height = chain.height();
    let mut rng = ChaCha20Rng::seed_from_u64(0x7_0007);
    let real = chain.output_at_depth(&mut rng, 1_000);
    for k in [10u64, 30, 100, 720] {
        // Blocks height-k..height are replaced by k blocks of 1-7 outputs.
        let fork_block = height - k;
        let fork_start = chain.block_start(fork_block);
        let replaced = Chain::from_blocks(
            (0..height)
                .map(|b| {
                    if b < fork_block {
                        (0, STEADY_K)
                    } else {
                        (0, 1 + rng.next_u64() % 7)
                    }
                })
                .collect::<Vec<_>>()
                .into_iter(),
        );
        let (mut kept_sum, mut fresh_sum, mut whole) = (0u64, 0u64, 0u64);
        for _ in 0..RINGS {
            let old = chain.ring(&mut rng, real);
            // The members the wallet's index still holds unchanged.
            let keep: Vec<u64> = old.iter().copied().filter(|&i| i < fork_start).collect();
            let rebuilt = select_ring_keeping(
                &mut rng,
                &replaced.cum,
                height,
                T,
                real,
                &keep,
                replaced.eligible(),
            )
            .unwrap();
            let fresh = replaced.ring(&mut rng, real);
            // Same output = same index below the fork; above it every output is new.
            let common = |new: &[u64; RING_SIZE]| {
                old.iter()
                    .filter(|&&i| i < fork_start && new.contains(&i))
                    .count() as u64
            };
            let kept = common(&rebuilt);
            assert_eq!(kept, keep.len() as u64, "a surviving member was dropped");
            kept_sum += kept;
            fresh_sum += common(&fresh);
            whole += (kept == RING_SIZE as u64) as u64;
        }
        let orphan_mass: f64 = m.pmf[..=k as usize].iter().sum();
        let expected = 1.0 + DECOYS as f64 * (1.0 - orphan_mass);
        let kept_mean = kept_sum as f64 / RINGS as f64;
        let fresh_mean = fresh_sum as f64 / RINGS as f64;
        println!(
            "reorg depth {k}: intersection {kept_mean:.2} of 16 (model {expected:.2}), \
             ring unchanged in {:.3}; fresh ring would share {fresh_mean:.2}",
            whole as f64 / RINGS as f64
        );
        assert!(
            (kept_mean - expected).abs() < 0.15,
            "{kept_mean} vs {expected}"
        );
        assert!(fresh_mean < 2.0, "fresh rings overlap: {fresh_mean}");
    }
}
