//! A small deterministic PRNG (xoshiro256** seeded by SplitMix64). Simulation only:
//! it is not, and must never be used as, a cryptographic generator.

/// One SplitMix64 step.
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A seed derived from a base seed and a list of tags (scenario, cell, chunk, ...).
pub fn derive(base: u64, tags: &[u64]) -> u64 {
    let mut s = base;
    let mut out = splitmix64(&mut s);
    for &t in tags {
        s ^= t.wrapping_mul(0xD6E8_FEB8_6659_FD93);
        out ^= splitmix64(&mut s);
    }
    out
}

#[derive(Clone, Debug)]
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut s = [0u64; 4];
        for x in &mut s {
            *x = splitmix64(&mut sm);
        }
        Self { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in the open interval (0, 1).
    pub fn unit(&mut self) -> f64 {
        ((self.next_u64() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    /// Exponential with mean 1 (a solve time in units of the expected solve time).
    pub fn exp(&mut self) -> f64 {
        -self.unit().ln()
    }

    /// Uniform in `0..n` (`n > 0`; the modulo bias is irrelevant for simulation).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_well_spread() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        let xs: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let ys: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        assert_eq!(xs, ys);
        assert_ne!(Rng::new(43).next_u64(), xs[0]);
        // The exponential has mean 1 (to within sampling error).
        let mut r = Rng::new(7);
        let n = 200_000;
        let mean = (0..n).map(|_| r.exp()).sum::<f64>() / n as f64;
        assert!((mean - 1.0).abs() < 0.01, "{mean}");
        assert_ne!(derive(1, &[2, 3]), derive(1, &[3, 2]));
    }
}
