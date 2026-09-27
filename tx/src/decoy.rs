//! Wallet-side decoy selection (spec §11.3). Not consensus.
//!
//! Monero's gamma picker (Möser et al., "An Empirical Analysis of Traceability in
//! the Monero Blockchain", 2018; `wallet2::gamma_picker`). Real spends are mostly
//! of recent outputs, so decoys are drawn from the same age distribution:
//!
//! ```text
//! x = exp(Gamma(shape 19.28, scale 1/1.61))            seconds of age
//! x = x − 10·T if x > 10·T, else uniform in [0, 15·T)  (spendable-age shift)
//! i = x / average_output_time                           outputs back from the newest usable one
//! b = the block containing output i, at depth D         (the drawn age)
//! pick a uniform ELIGIBLE output of block b; if b has none, a uniform
//! eligible output of the blocks b ± w, w = clamp(D / 4, 9, 720);
//! if those have none either, discard the draw
//! ```
//!
//! **Eligibility is applied inside the draw** (docs/transactions.md §11.3.1,
//! review R3-1). Coinbase outputs need 60 blocks, so on a young chain most
//! outputs 10–59 blocks deep are ineligible. Rejecting them *after* the draw
//! and drawing again from scratch moves all of that age mass to older ages:
//! decoys younger than 60 blocks almost vanish, and a real input spent soon
//! after it was received becomes the newest ring member. Choosing among the
//! eligible outputs of the drawn age's neighbourhood keeps the age
//! distribution wherever eligible outputs of that age exist.
//!
//! The neighbourhood is proportional to the age and bounded. An unbounded
//! "nearest eligible block" rule was rejected: on a chain of coinbase-only
//! blocks it moved every young draw onto the few blocks just past the 60-block
//! maturity, a pile-up that would itself mark rings.
//!
//! Floating point is fine here: this is wallet policy, and every choice is
//! re-checked by consensus (C1). Given the RNG, the ring is deterministic.

use crate::params::{RING_SIZE, SPENDABLE_AGE};
use rand_core::RngCore;

const GAMMA_SHAPE: f64 = 19.28;
const GAMMA_SCALE: f64 = 1.0 / 1.61;
const RECENT_SPEND_WINDOW_BLOCKS: f64 = 15.0;
const MAX_ATTEMPTS: usize = 100_000;
/// Half-width of the neighbourhood searched when the drawn block has no
/// eligible output: a quarter of the drawn depth, at least
/// `NEIGHBOURHOOD_MIN_BLOCKS` and at most `NEIGHBOURHOOD_MAX_BLOCKS` each way.
pub const NEIGHBOURHOOD_MIN_BLOCKS: usize = 9;
pub const NEIGHBOURHOOD_MAX_BLOCKS: usize = 720;
const NEIGHBOURHOOD_DEPTH_DIVISOR: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecoyError {
    /// Fewer than 16 eligible outputs exist.
    NotEnoughOutputs,
    /// The real output is not in the usable range at this height.
    RealOutputNotUsable,
    /// The output distribution is empty or decreasing (it comes from a node, so
    /// it is checked rather than trusted).
    BadDistribution,
}

fn uniform01<R: RngCore>(rng: &mut R) -> f64 {
    // 53 random bits in (0, 1].
    ((rng.next_u64() >> 11) + 1) as f64 / (1u64 << 53) as f64
}

fn standard_normal<R: RngCore>(rng: &mut R) -> f64 {
    let (u1, u2) = (uniform01(rng), uniform01(rng));
    (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
}

/// Marsaglia–Tsang gamma sampler (shape ≥ 1).
fn gamma<R: RngCore>(rng: &mut R, shape: f64, scale: f64) -> f64 {
    let d = shape - 1.0 / 3.0;
    let c = 1.0 / (9.0 * d).sqrt();
    loop {
        let x = standard_normal(rng);
        let v = (1.0 + c * x).powi(3);
        if v <= 0.0 {
            continue;
        }
        let u = uniform01(rng);
        if u.ln() < 0.5 * x * x + d - d * v + d * v.ln() {
            return d * v * scale;
        }
    }
}

/// Selects a ring for the output `real` spent in a block at `height`.
///
/// `cumulative[h]` is the number of outputs in blocks `0..=h` of the current chain
/// (`MemoryChain::cumulative_outputs`). `eligible(i)` must return whether output
/// `i` may be a ring member at `height` (it matters for coinbase outputs, which
/// need 60 blocks). The picker only ever chooses eligible outputs, at the age
/// it drew or next to it (see the module documentation). Returns 16 strictly
/// increasing global indices containing `real`.
pub fn select_ring<R: RngCore>(
    rng: &mut R,
    cumulative: &[u64],
    height: u64,
    target_block_time: u64,
    real: u64,
    eligible: impl Fn(u64) -> bool,
) -> Result<[u64; RING_SIZE], DecoyError> {
    select_ring_keeping(
        rng,
        cumulative,
        height,
        target_block_time,
        real,
        &[],
        eligible,
    )
}

/// Like [`select_ring`], but the ring keeps every member of `keep` that is still
/// usable (old enough, eligible, not `real`, not repeated) and draws only the
/// rest. Wallets use it to spend an output again with the ring an earlier,
/// possibly relayed, transaction used: both transactions share the key image,
/// so the more members the two rings share, the less their intersection
/// reveals (docs/reviews/wallet-review.md W-5).
pub fn select_ring_keeping<R: RngCore>(
    rng: &mut R,
    cumulative: &[u64],
    height: u64,
    target_block_time: u64,
    real: u64,
    keep: &[u64],
    eligible: impl Fn(u64) -> bool,
) -> Result<[u64; RING_SIZE], DecoyError> {
    let picker = Picker::new(cumulative, height, target_block_time)?;
    if real >= picker.usable || !eligible(real) {
        return Err(DecoyError::RealOutputNotUsable);
    }
    let mut ring = vec![real];
    for &k in keep {
        if ring.len() < RING_SIZE && k < picker.usable && !ring.contains(&k) && eligible(k) {
            ring.push(k);
        }
    }
    for _ in 0..MAX_ATTEMPTS {
        if ring.len() == RING_SIZE {
            break;
        }
        // Members already chosen do not count as available: a draw next to
        // them moves on to the nearest other eligible output of that age.
        if let Some(pick) = picker.pick(rng, &|i| eligible(i) && !ring.contains(&i)) {
            ring.push(pick);
        }
    }
    if ring.len() < RING_SIZE {
        return Err(DecoyError::NotEnoughOutputs);
    }
    ring.sort_unstable();
    Ok(ring.try_into().expect("exactly RING_SIZE members"))
}

/// The number of outputs usable as ring members at `height` (those at least
/// `SPENDABLE_AGE` blocks deep).
pub fn usable_outputs(cumulative: &[u64], height: u64) -> Result<u64, DecoyError> {
    Ok(Picker::new(cumulative, height, 1)?.usable)
}

/// The gamma picker over a checked output distribution.
struct Picker<'a> {
    cumulative: &'a [u64],
    usable: u64,
    average_output_time: f64,
    t: f64,
}

impl<'a> Picker<'a> {
    fn new(cumulative: &'a [u64], height: u64, target_block_time: u64) -> Result<Self, DecoyError> {
        if cumulative.is_empty() || cumulative.windows(2).any(|w| w[0] > w[1]) {
            return Err(DecoyError::BadDistribution);
        }
        // Usable blocks: at least SPENDABLE_AGE deep.
        let Some(last_block) = height.checked_sub(SPENDABLE_AGE) else {
            return Err(DecoyError::NotEnoughOutputs);
        };
        let last_block = last_block.min(cumulative.len() as u64 - 1) as usize;
        let usable = cumulative[last_block];
        if usable < RING_SIZE as u64 {
            return Err(DecoyError::NotEnoughOutputs);
        }
        let blocks = (last_block + 1) as f64;
        Ok(Self {
            cumulative: &cumulative[..=last_block],
            usable,
            average_output_time: target_block_time as f64 * blocks / usable as f64,
            t: target_block_time as f64,
        })
    }

    /// The global indices of the outputs of usable block `b`.
    fn block_range(&self, b: usize) -> std::ops::Range<u64> {
        let start = if b == 0 { 0 } else { self.cumulative[b - 1] };
        start..self.cumulative[b]
    }

    /// The block at the age the gamma distribution draws; `None` if that age
    /// lies beyond the start of the chain.
    fn draw_block<R: RngCore>(&self, rng: &mut R) -> Option<usize> {
        let mut x = gamma(rng, GAMMA_SHAPE, GAMMA_SCALE).exp();
        let lock = SPENDABLE_AGE as f64 * self.t;
        if x > lock {
            x -= lock;
        } else {
            x = uniform01(rng) * RECENT_SPEND_WINDOW_BLOCKS * self.t;
        }
        let back = (x / self.average_output_time) as u64;
        if back >= self.usable {
            return None;
        }
        let target = self.usable - 1 - back;
        Some(self.cumulative.partition_point(|&c| c <= target))
    }

    /// A uniform eligible output of blocks `blocks`, if any.
    fn uniform_in<R: RngCore>(
        &self,
        rng: &mut R,
        blocks: std::ops::RangeInclusive<usize>,
        eligible: &impl Fn(u64) -> bool,
    ) -> Option<u64> {
        let candidates = || {
            blocks
                .clone()
                .flat_map(|x| self.block_range(x))
                .filter(|&i| eligible(i))
        };
        let count = candidates().count() as u64;
        if count == 0 {
            return None;
        }
        candidates().nth((rng.next_u64() % count) as usize)
    }

    /// One draw: a uniform eligible output of the drawn block or, if it has
    /// none, of its neighbourhood (see the module documentation). `None` if
    /// the age falls outside the chain or nothing eligible lies near it.
    fn pick<R: RngCore>(&self, rng: &mut R, eligible: &impl Fn(u64) -> bool) -> Option<u64> {
        let b = self.draw_block(rng)?;
        if let Some(i) = self.uniform_in(rng, b..=b, eligible) {
            return Some(i);
        }
        let last = self.cumulative.len() - 1;
        let depth = last - b + SPENDABLE_AGE as usize;
        let w = (depth / NEIGHBOURHOOD_DEPTH_DIVISOR)
            .clamp(NEIGHBOURHOOD_MIN_BLOCKS, NEIGHBOURHOOD_MAX_BLOCKS);
        self.uniform_in(rng, b.saturating_sub(w)..=(b + w).min(last), eligible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::COINBASE_MATURITY;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn chain(blocks: u64, per_block: u64) -> Vec<u64> {
        (1..=blocks).map(|b| b * per_block).collect()
    }

    #[test]
    fn ring_contains_real_is_sorted_and_eligible() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let cum = chain(5_000, 4);
        for real in [0u64, 7, 10_000, 19_950] {
            let ring = select_ring(&mut rng, &cum, 5_000, 120, real, |_| true).unwrap();
            assert!(ring.contains(&real));
            assert!(ring.windows(2).all(|w| w[0] < w[1]));
            // Nothing from the last 10 blocks.
            assert!(ring.iter().all(|&i| i < cum[5_000 - 10]));
        }
    }

    #[test]
    fn the_same_rng_gives_the_same_ring() {
        let cum = chain(3_000, 3);
        let odd = |i: u64| i % 3 != 1;
        let a = select_ring(
            &mut ChaCha20Rng::seed_from_u64(9),
            &cum,
            3_000,
            120,
            30,
            odd,
        );
        let b = select_ring(
            &mut ChaCha20Rng::seed_from_u64(9),
            &cum,
            3_000,
            120,
            30,
            odd,
        );
        assert_eq!(a, b);
    }

    #[test]
    fn kept_members_survive_and_only_the_rest_is_drawn() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let cum = chain(5_000, 4);
        let old = select_ring(&mut rng, &cum, 5_000, 120, 7_000, |_| true).unwrap();
        // All kept: the same ring.
        let same = select_ring_keeping(&mut rng, &cum, 5_000, 120, 7_000, &old, |_| true).unwrap();
        assert_eq!(same, old);
        // Some lost (too young now, ineligible, or equal to the real one):
        // the usable ones stay, the ring is still valid.
        let young = cum[5_000 - 5];
        let mut keep: Vec<u64> = old.iter().copied().filter(|&i| i != 7_000).collect();
        keep.truncate(10);
        keep.push(young); // too young
        keep.push(keep[0]); // repeated
        let ring = select_ring_keeping(&mut rng, &cum, 5_000, 120, 7_000, &keep, |i| i != keep[1])
            .unwrap();
        assert!(ring.contains(&7_000));
        assert!(ring.windows(2).all(|w| w[0] < w[1]));
        assert!(!ring.contains(&young) && !ring.contains(&keep[1]));
        for k in keep.iter().take(10).filter(|&&k| k != keep[1]) {
            assert!(ring.contains(k), "kept member {k} lost");
        }
    }

    #[test]
    fn a_bad_distribution_is_an_error_not_a_panic() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        assert_eq!(
            select_ring(&mut rng, &[], 100, 120, 0, |_| true),
            Err(DecoyError::BadDistribution)
        );
        let decreasing: Vec<u64> = (0..200).rev().collect();
        assert_eq!(
            select_ring(&mut rng, &decreasing, 150, 120, 0, |_| true),
            Err(DecoyError::BadDistribution)
        );
        // Flat stretches (blocks without outputs) are fine.
        let mut flat = chain(3_000, 3);
        for c in flat.iter_mut().skip(1_000).take(500) {
            *c = 3_000;
        }
        let mut last = 0;
        for c in flat.iter_mut() {
            *c = (*c).max(last);
            last = *c;
        }
        assert!(select_ring(&mut rng, &flat, 3_000, 120, 30, |_| true).is_ok());
    }

    #[test]
    fn respects_eligibility() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let cum = chain(3_000, 3);
        let ring = select_ring(&mut rng, &cum, 3_000, 120, 30, |i| i % 2 == 0).unwrap();
        assert!(ring.iter().all(|i| i % 2 == 0));
    }

    #[test]
    fn errors() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let cum = chain(20, 1);
        assert_eq!(
            select_ring(&mut rng, &cum, 20, 120, 3, |_| true),
            Err(DecoyError::NotEnoughOutputs)
        );
        let cum = chain(100, 2);
        assert_eq!(
            select_ring(&mut rng, &cum, 100, 120, 199, |_| true),
            Err(DecoyError::RealOutputNotUsable),
            "real output is too young"
        );
        // Fewer than 16 eligible outputs in the whole chain.
        let cum = chain(200, 2);
        assert_eq!(
            select_ring(&mut rng, &cum, 200, 120, 0, |i| i < 10),
            Err(DecoyError::NotEnoughOutputs)
        );
    }

    /// Decoys follow the recent-heavy spend distribution rather than uniform.
    #[test]
    fn distribution_favours_recent_outputs() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let blocks = 200_000u64; // ~9 months at 2 minutes
        let cum = chain(blocks, 2);
        let usable = cum[(blocks - 10) as usize];
        let mut recent = 0;
        let mut total = 0;
        for _ in 0..100 {
            let ring = select_ring(&mut rng, &cum, blocks, 120, 0, |_| true).unwrap();
            for &i in ring.iter().filter(|&&i| i != 0) {
                total += 1;
                // "Recent" = newest 10% of usable outputs.
                if i >= usable - usable / 10 {
                    recent += 1;
                }
            }
        }
        // Uniform selection would give ~10%; the gamma picker gives far more.
        assert!(recent * 100 / total > 30, "{recent}/{total}");
    }

    #[test]
    fn gamma_sampler_mean() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let n = 20_000;
        let mean: f64 = (0..n)
            .map(|_| gamma(&mut rng, GAMMA_SHAPE, GAMMA_SCALE))
            .sum::<f64>()
            / n as f64;
        let expected = GAMMA_SHAPE * GAMMA_SCALE; // ≈ 11.98
        assert!((mean - expected).abs() < 0.1, "{mean}");
    }

    /// A young chain (review R3-1): 3 days at 2 minutes, one coinbase output
    /// per block and a two-output transfer every 18th block (40 transfers a
    /// day), plus the transfer whose first output is the real input, spent 12
    /// blocks after it was mined.
    struct YoungChain {
        cumulative: Vec<u64>,
        /// Height of the block the spend goes into.
        height: u64,
        real: u64,
    }

    impl YoungChain {
        const BLOCKS: u64 = 2_160;
        const REAL_DEPTH: u64 = 12;

        fn new() -> Self {
            let height = Self::BLOCKS;
            let real_block = height - Self::REAL_DEPTH;
            let mut cumulative = Vec::with_capacity(Self::BLOCKS as usize);
            let mut total = 0;
            for h in 0..Self::BLOCKS {
                total += 1; // the coinbase output comes first in its block
                if h % 18 == 5 || h == real_block {
                    total += 2;
                }
                cumulative.push(total);
            }
            let real = cumulative[real_block as usize - 1] + 1;
            Self {
                cumulative,
                height,
                real,
            }
        }

        fn block_of(&self, i: u64) -> u64 {
            self.cumulative.partition_point(|&c| c <= i) as u64
        }

        fn is_coinbase(&self, i: u64) -> bool {
            let b = self.block_of(i) as usize;
            i == if b == 0 { 0 } else { self.cumulative[b - 1] }
        }

        /// The consensus rule: a coinbase output needs 60 blocks.
        fn mature(&self, i: u64) -> bool {
            !self.is_coinbase(i) || self.height >= self.block_of(i) + COINBASE_MATURITY
        }

        fn depth(&self, i: u64) -> u64 {
            self.height - self.block_of(i)
        }
    }

    /// The selection before R3-1: the draw ignores eligibility, an ineligible
    /// pick is thrown away and the next draw starts from scratch.
    fn reject_after_draw(rng: &mut ChaCha20Rng, c: &YoungChain) -> [u64; RING_SIZE] {
        let picker = Picker::new(&c.cumulative, c.height, 120).unwrap();
        let mut ring = vec![c.real];
        while ring.len() < RING_SIZE {
            if let Some(p) = picker.pick(rng, &|_| true) {
                if c.mature(p) && !ring.contains(&p) {
                    ring.push(p);
                }
            }
        }
        ring.try_into().unwrap()
    }

    /// (fraction of decoys younger than 60 blocks, fraction of rings whose
    /// newest member is the real input).
    fn measure(c: &YoungChain, rings: &[[u64; RING_SIZE]]) -> (f64, f64) {
        let (mut young, mut decoys, mut newest) = (0u64, 0u64, 0u64);
        for ring in rings {
            let mut real_is_newest = true;
            for &i in ring.iter().filter(|&&i| i != c.real) {
                decoys += 1;
                if c.depth(i) < COINBASE_MATURITY {
                    young += 1;
                }
                if c.depth(i) <= YoungChain::REAL_DEPTH {
                    real_is_newest = false;
                }
            }
            newest += real_is_newest as u64;
        }
        (
            young as f64 / decoys as f64,
            newest as f64 / rings.len() as f64,
        )
    }

    /// R3-1: on a young chain dominated by immature coinbase outputs, decoys
    /// younger than 60 blocks occur about as often as the gamma distribution
    /// says (the target: the same draws with every output eligible), instead
    /// of almost never. Fixed seed, 2,000 rings per variant.
    ///
    /// Tolerance: the young fraction must be within 0.05 (absolute) of the
    /// target. The measured values are printed (`--nocapture`); they are
    /// recorded in docs/transactions.md §11.3.1.
    #[test]
    fn young_decoys_survive_coinbase_maturity() {
        const RINGS: usize = 2_000;
        let c = YoungChain::new();
        let mut rng = ChaCha20Rng::seed_from_u64(0x5231);
        let draw = |rng: &mut ChaCha20Rng, eligible: &dyn Fn(u64) -> bool| {
            (0..RINGS)
                .map(|_| select_ring(rng, &c.cumulative, c.height, 120, c.real, eligible).unwrap())
                .collect::<Vec<_>>()
        };
        let target = draw(&mut rng, &|_| true);
        let after = draw(&mut rng, &|i| c.mature(i));
        let before: Vec<_> = (0..RINGS)
            .map(|_| reject_after_draw(&mut rng, &c))
            .collect();
        for ring in &after {
            assert!(ring.iter().all(|&i| c.mature(i)), "only eligible members");
        }
        let (target_young, target_newest) = measure(&c, &target);
        let (after_young, after_newest) = measure(&c, &after);
        let (before_young, before_newest) = measure(&c, &before);
        println!(
            "decoys < 60 blocks: target {target_young:.3}, before {before_young:.3}, \
             after {after_young:.3}; real (12 blocks) is the newest member: target \
             {target_newest:.3}, before {before_newest:.3}, after {after_newest:.3}"
        );
        assert!(
            (after_young - target_young).abs() <= 0.05,
            "after {after_young} vs target {target_young}"
        );
        assert!(
            before_young < target_young / 2.0,
            "the defect is reproduced"
        );
        assert!(after_newest < before_newest);
        // The gamma distribution itself puts little mass 10–12 blocks deep, so
        // even the target leaves the real input newest in most rings (§11.3.1).
        // After the fix it is at most slightly worse than the target. It can
        // be lower, because sparse young transfers (the real input's sibling
        // among them) absorb nearby draws.
        assert!(
            after_newest <= target_newest + 0.05,
            "after {after_newest} vs target {target_newest}"
        );
    }

    /// On a chain of coinbase-only blocks nothing younger than 60 blocks is
    /// eligible. Draws 51–59 blocks deep reach the first mature blocks through
    /// their neighbourhood, so decoys 60–69 blocks deep are about twice as
    /// frequent as with discarding and redrawing (measured 0.129 vs 0.060).
    /// This is the accepted cost of the minimum window (§11.3.1). The bound
    /// here, 2.5 times, catches a return to the unbounded nearest-block rule,
    /// which moved every young draw there.
    #[test]
    fn no_pile_up_at_the_maturity_boundary() {
        let height = 400u64;
        let cum = chain(height, 1); // output i is the coinbase of block i
        let mature = |i: u64| height >= i + COINBASE_MATURITY;
        let picker = Picker::new(&cum, height, 120).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(0x60);
        let boundary = |i: u64| (60..70).contains(&(height - i));
        let share = |picks: &[u64]| {
            picks.iter().filter(|&&i| boundary(i)).count() as f64 / picks.len() as f64
        };
        let mut after = Vec::new();
        let mut before = Vec::new();
        while after.len() < 20_000 {
            if let Some(i) = picker.pick(&mut rng, &mature) {
                after.push(i);
            }
        }
        while before.len() < 20_000 {
            if let Some(i) = picker.pick(&mut rng, &|_| true).filter(|&i| mature(i)) {
                before.push(i);
            }
        }
        let (a, b) = (share(&after), share(&before));
        println!("decoys 60-69 blocks deep: before {b:.3}, after {a:.3}");
        assert!(after.iter().all(|&i| mature(i)));
        assert!(a <= 2.5 * b, "pile-up: {a} vs {b}");
    }

    /// A draw that lands on a block without eligible outputs is served from
    /// its neighbourhood, and never returns an ineligible output.
    #[test]
    fn an_ineligible_block_is_replaced_from_its_neighbourhood() {
        let c = YoungChain::new();
        let picker = Picker::new(&c.cumulative, c.height, 120).unwrap();
        let mut rng = ChaCha20Rng::seed_from_u64(77);
        let only_transfers = |i: u64| !c.is_coinbase(i);
        for _ in 0..2_000 {
            if let Some(p) = picker.pick(&mut rng, &only_transfers) {
                assert!(!c.is_coinbase(p));
            }
        }
        // Everything ineligible: every draw fails, none panics.
        for _ in 0..100 {
            assert_eq!(picker.pick(&mut rng, &|_| false), None);
        }
    }
}
