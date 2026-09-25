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
//! pick the block containing that output, then a uniform output within the block
//! ```
//!
//! Floating point is fine here: this is wallet policy, and every choice is
//! re-checked by consensus (C1).

use crate::params::{RING_SIZE, SPENDABLE_AGE};
use rand_core::RngCore;

const GAMMA_SHAPE: f64 = 19.28;
const GAMMA_SCALE: f64 = 1.0 / 1.61;
const RECENT_SPEND_WINDOW_BLOCKS: f64 = 15.0;
const MAX_ATTEMPTS: usize = 100_000;

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
/// `i` satisfies the consensus age rule for `height` (it matters for coinbase
/// outputs, which need 60 blocks). Returns 16 strictly increasing global indices
/// containing `real`.
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
        if let Some(pick) = picker.pick(rng) {
            if !ring.contains(&pick) && eligible(pick) {
                ring.push(pick);
            }
        }
    }
    if ring.len() < RING_SIZE {
        return Err(DecoyError::NotEnoughOutputs);
    }
    ring.sort_unstable();
    Ok(ring.try_into().expect("exactly RING_SIZE members"))
}

/// Up to `count` distinct candidate decoys drawn from the same distribution as
/// [`select_ring`], none of them in `exclude`, all usable at `height`.
///
/// Wallets fetch a whole pool of candidates and the real output in **one**
/// node request, then choose decoys from the pool locally. Repeated requests
/// that each contained the real output would reveal it to the node by
/// intersection (docs/reviews/wallet-review.md F2).
pub fn draw_candidates<R: RngCore>(
    rng: &mut R,
    cumulative: &[u64],
    height: u64,
    target_block_time: u64,
    count: usize,
    exclude: &[u64],
) -> Result<Vec<u64>, DecoyError> {
    let picker = Picker::new(cumulative, height, target_block_time)?;
    let mut out: Vec<u64> = Vec::with_capacity(count);
    for _ in 0..MAX_ATTEMPTS {
        if out.len() == count {
            break;
        }
        if let Some(pick) = picker.pick(rng) {
            if !out.contains(&pick) && !exclude.contains(&pick) {
                out.push(pick);
            }
        }
    }
    Ok(out)
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

    /// One draw; `None` if it falls outside the chain or on an empty block.
    fn pick<R: RngCore>(&self, rng: &mut R) -> Option<u64> {
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
        // The block containing `target`, then a uniform output inside it.
        let block = self.cumulative.partition_point(|&c| c <= target);
        let start = if block == 0 {
            0
        } else {
            self.cumulative[block - 1]
        };
        let end = *self.cumulative.get(block)?;
        if end <= start {
            return None;
        }
        Some(start + rng.next_u64() % (end - start))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            draw_candidates(&mut rng, &decreasing, 150, 120, 10, &[]),
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
    fn candidates_are_distinct_usable_and_not_excluded() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let cum = chain(5_000, 4);
        let usable = usable_outputs(&cum, 5_000).unwrap();
        let exclude = [7_000u64, 7_001];
        let c = draw_candidates(&mut rng, &cum, 5_000, 120, 60, &exclude).unwrap();
        assert_eq!(c.len(), 60);
        let mut sorted = c.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), 60, "distinct");
        assert!(c.iter().all(|i| *i < usable && !exclude.contains(i)));
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
}
