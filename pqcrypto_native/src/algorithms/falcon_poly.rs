//! Falcon polynomial arithmetic over Z_q[X]/(X^n+1)
//! For Falcon-512, n = 512, q = 12289

pub const N: usize = 512;
pub const Q: u32 = 12289;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Poly {
    pub fn zero() -> Self {
        Poly { coeffs: [0; N] }
    }
    pub fn from_slice(slice: &[i32]) -> Self {
        let mut coeffs = [0; N];
        for (i, &v) in slice.iter().enumerate().take(N) {
            coeffs[i] = v % Q as i32;
        }
        Poly { coeffs }
    }
    pub fn add(&self, rhs: &Poly) -> Poly {
        let mut res = [0; N];
        for i in 0..N {
            res[i] = (self.coeffs[i] + rhs.coeffs[i]) % Q as i32;
        }
        Poly { coeffs: res }
    }
    pub fn sub(&self, rhs: &Poly) -> Poly {
        let mut res = [0; N];
        for i in 0..N {
            res[i] = (self.coeffs[i] - rhs.coeffs[i]).rem_euclid(Q as i32);
        }
        Poly { coeffs: res }
    }
    pub fn neg(&self) -> Poly {
        let mut res = [0; N];
        for i in 0..N {
            res[i] = (-self.coeffs[i]).rem_euclid(Q as i32);
        }
        Poly { coeffs: res }
    }
    // TODO: Implement polynomial multiplication mod (X^N+1) and Q
}
