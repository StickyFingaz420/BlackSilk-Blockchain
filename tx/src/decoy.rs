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
    // Usable blocks: at least SPENDABLE_AGE deep.
    let Some(last_block) = height.checked_sub(SPENDABLE_AGE) else {
        return Err(DecoyError::NotEnoughOutputs);
    };
    let last_block = last_block.min(cumulative.len() as u64 - 1) as usize;
    let usable = cumulative[last_block];
    if real >= usable || !eligible(real) {
        return Err(DecoyError::RealOutputNotUsable);
    }
    if usable < RING_SIZE as u64 {
        return Err(DecoyError::NotEnoughOutputs);
    }
    let blocks = (last_block + 1) as f64;
    let average_output_time = target_block_time as f64 * blocks / usable as f64;
    let t = target_block_time as f64;

    let mut ring = vec![real];
    for &k in keep {
        if ring.len() < RING_SIZE && k < usable && !ring.contains(&k) && eligible(k) {
            ring.push(k);
        }
    }
    for _ in 0..MAX_ATTEMPTS {
        if ring.len() == RING_SIZE {
            break;
        }
        let mut x = gamma(rng, GAMMA_SHAPE, GAMMA_SCALE).exp();
        let lock = SPENDABLE_AGE as f64 * t;
        if x > lock {
            x -= lock;
        } else {
            x = uniform01(rng) * RECENT_SPEND_WINDOW_BLOCKS * t;
        }
        let back = (x / average_output_time) as u64;
        if back >= usable {
            continue;
        }
        let target = usable - 1 - back;
        // The block containing `target`, then a uniform output inside it.
        let block = cumulative.partition_point(|&c| c <= target);
        let start = if block == 0 { 0 } else { cumulative[block - 1] };
        let end = cumulative[block];
        let pick = start + rng.next_u64() % (end - start);
        if !ring.contains(&pick) && eligible(pick) {
            ring.push(pick);
        }
    }
    if ring.len() < RING_SIZE {
        return Err(DecoyError::NotEnoughOutputs);
    }
    ring.sort_unstable();
    Ok(ring.try_into().expect("exactly RING_SIZE members"))
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
