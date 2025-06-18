//! Falcon FFT over Z_q[X]/(X^n+1)
//! For Falcon-512, n = 512, q = 12289
//! This is a real-number FFT (Bluestein/Chirp-Z) for Falcon, not a simple NTT.

use super::falcon_poly::{N, Q, Poly};
use num_complex::Complex64;
use core::f64::consts::PI;

use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;

/// Falcon FFT context (precomputed roots of unity, etc.)
pub struct FalconFFTContext {
    pub n: usize,
    pub q: u32,
    // TODO: Add precomputed roots of unity, twiddle factors, etc.
}

impl FalconFFTContext {
    pub fn new() -> Self {
        FalconFFTContext { n: N, q: Q }
    }

    /// Forward FFT: polynomial -> frequency domain (complex numbers)
    pub fn fft(&self, poly: &Poly) -> Vec<num_complex::Complex64> {
        // TODO: Implement Bluestein FFT for Falcon (complex64)
        // Placeholder: just convert coefficients to real part
        poly.coeffs.iter().map(|&c| num_complex::Complex64::new(c as f64, 0.0)).collect()
    }

    /// Inverse FFT: frequency domain -> polynomial
    pub fn ifft(&self, freq: &[num_complex::Complex64]) -> Poly {
        // TODO: Implement inverse Bluestein FFT for Falcon
        // Placeholder: just take real part and round
        let mut coeffs = [0i32; N];
        for (i, z) in freq.iter().enumerate().take(N) {
            coeffs[i] = z.re.round() as i32 % Q as i32;
        }
        Poly { coeffs }
    }

    /// Bluestein FFT (Chirp-Z) for arbitrary n (n=512 for Falcon)
    pub fn bluestein_fft(&self, poly: &Poly) -> Vec<Complex64> {
        let n = self.n;
        let mut a = vec![Complex64::new(0.0, 0.0); 2 * n];
        let mut b = vec![Complex64::new(0.0, 0.0); 2 * n];
        let mut w = vec![Complex64::new(0.0, 0.0); n];
        let q = self.q as f64;
        // Precompute chirp factors
        for k in 0..n {
            let angle = PI * (k * k) as f64 / n as f64;
            w[k] = Complex64::from_polar(1.0, -angle);
            a[k] = Complex64::new(poly.coeffs[k] as f64, 0.0) * w[k];
            b[k] = Complex64::from_polar(1.0, angle);
        }
        // Zero-pad
        for k in n..2 * n {
            a[k] = Complex64::new(0.0, 0.0);
            b[k] = Complex64::new(0.0, 0.0);
        }
        // FFT convolution
        let fa = fft(&a);
        let fb = fft(&b);
        let mut fc = vec![Complex64::new(0.0, 0.0); 2 * n];
        for i in 0..2 * n {
            fc[i] = fa[i] * fb[i];
        }
        let c = ifft(&fc);
        // De-chirp
        let mut out = vec![Complex64::new(0.0, 0.0); n];
        for k in 0..n {
            out[k] = c[k] * w[k];
        }
        out
    }
    /// Inverse Bluestein FFT
    pub fn bluestein_ifft(&self, freq: &[Complex64]) -> Poly {
        let n = self.n;
        let mut a = vec![Complex64::new(0.0, 0.0); 2 * n];
        let mut b = vec![Complex64::new(0.0, 0.0); 2 * n];
        let mut w = vec![Complex64::new(0.0, 0.0); n];
        let q = self.q as f64;
        for k in 0..n {
            let angle = PI * (k * k) as f64 / n as f64;
            w[k] = Complex64::from_polar(1.0, angle);
            a[k] = freq[k] * w[k];
            b[k] = Complex64::from_polar(1.0, -angle);
        }
        for k in n..2 * n {
            a[k] = Complex64::new(0.0, 0.0);
            b[k] = Complex64::new(0.0, 0.0);
        }
        let fa = fft(&a);
        let fb = fft(&b);
        let mut fc = vec![Complex64::new(0.0, 0.0); 2 * n];
        for i in 0..2 * n {
            fc[i] = fa[i] * fb[i];
        }
        let c = ifft(&fc);
        let mut coeffs = [0i32; N];
        for k in 0..n {
            coeffs[k] = (c[k].re / n as f64).round() as i32 % Q as i32;
        }
        Poly { coeffs }
    }
}

/// Cooley-Tukey radix-2 FFT (in-place, length must be power of 2)
pub fn fft(input: &[Complex64]) -> Vec<Complex64> {
    let n = input.len();
    let mut a = input.to_vec();
    let mut j = 0;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }
    let mut len = 2;
    while len <= n {
        let ang = -2.0 * PI / (len as f64);
        let wlen = Complex64::from_polar(1.0, ang);
        for i in (0..n).step_by(len) {
            let mut w = Complex64::new(1.0, 0.0);
            for j in 0..len / 2 {
                let u = a[i + j];
                let v = a[i + j + len / 2] * w;
                a[i + j] = u + v;
                a[i + j + len / 2] = u - v;
                w *= wlen;
            }
        }
        len <<= 1;
    }
    a
}

/// Inverse FFT (in-place, length must be power of 2)
pub fn ifft(input: &[Complex64]) -> Vec<Complex64> {
    let n = input.len();
    let mut a = input.to_vec();
    for x in &mut a {
        x.im = -x.im;
    }
    let a = fft(&a);
    let mut out = a;
    for x in &mut out {
        x.re /= n as f64;
        x.im = -x.im / n as f64;
    }
    out
}
