use super::falcon_prng::FalconPrng;
use super::falcon_gauss::{sample_gaussian, SIGMA};

#[test]
fn test_gaussian_sampler_basic() {
    let seed = [1u8; 48];
    let mut prng = FalconPrng::from_seed(&seed);
    let mut samples = [0i32; 1000];
    for s in &mut samples {
        *s = sample_gaussian(&mut prng, SIGMA);
    }
    // Check that the mean is close to 0 (statistical sanity check)
    let mean = samples.iter().map(|&x| x as f64).sum::<f64>() / samples.len() as f64;
    assert!(mean.abs() < 0.5);
}
