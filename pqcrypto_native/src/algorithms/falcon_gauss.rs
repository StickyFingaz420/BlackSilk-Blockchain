//! Discrete Gaussian sampler for Falcon
//! Uses SHAKE256-based PRNG
use super::falcon_prng::FalconPrng;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use core::f64::consts::PI;

/// Falcon's standard deviation for Gaussian sampling (sigma)
pub const SIGMA: f64 = 1.277833697;

/// Sample a single integer from a discrete Gaussian distribution centered at 0
/// with standard deviation sigma, using the PRNG.
pub fn sample_gaussian(prng: &mut FalconPrng, sigma: f64) -> i32 {
    // Rejection sampling: sample from continuous Gaussian, round, accept/reject
    // For simplicity, use Box-Muller for continuous Gaussian, then round
    loop {
        let u1 = (prng.next_u64() as f64) / (u64::MAX as f64 + 1.0);
        let u2 = (prng.next_u64() as f64) / (u64::MAX as f64 + 1.0);
        let z = sigma * (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();
        let x = z.round() as i32;
        // Accept with probability proportional to exp(-(x-z)^2/(2*sigma^2))
        let rho = (-((x as f64 - z).powi(2)) / (2.0 * sigma * sigma)).exp();
        let u = (prng.next_u64() as f64) / (u64::MAX as f64 + 1.0);
        if u < rho {
            return x;
        }
    }
}

/// Sample a vector of n integers from the discrete Gaussian
pub fn sample_gaussian_vec(prng: &mut FalconPrng, n: usize, sigma: f64) -> Vec<i32> {
    (0..n).map(|_| sample_gaussian(prng, sigma)).collect()
}
