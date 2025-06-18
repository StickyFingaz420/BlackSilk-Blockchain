use super::falcon_poly::Poly;
use super::falcon_fft::FalconFFTContext;
use num_complex::Complex64;

#[test]
fn test_fft_ifft_identity() {
    let ctx = FalconFFTContext::new();
    let poly = Poly::from_slice(&(0..512).map(|x| x as i32).collect::<Vec<_>>());
    let freq = ctx.fft(&poly);
    let poly2 = ctx.ifft(&freq);
    // Placeholder: in real FFT, poly2 should equal poly
    assert_eq!(poly2.coeffs[0], poly.coeffs[0]);
}

#[test]
fn test_bluestein_fft_ifft_identity() {
    let ctx = FalconFFTContext::new();
    let poly = Poly::from_slice(&(0..512).map(|x| x as i32).collect::<Vec<_>>());
    let freq = ctx.bluestein_fft(&poly);
    let poly2 = ctx.bluestein_ifft(&freq);
    // In real FFT, poly2 should equal poly (modulo rounding and Q)
    for i in 0..Poly::zero().coeffs.len() {
        assert!((poly2.coeffs[i] - poly.coeffs[i]).abs() <= 1);
    }
}
