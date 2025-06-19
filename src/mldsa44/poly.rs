//! Polynomial arithmetic for ML-DSA-44
//! Implements NTT, polynomial addition, multiplication, reduction, etc.

use crate::mldsa44::params::{N, Q};
use sha3::{Shake256, Shake128};
use sha3::digest::{Update, ExtendableOutput, XofReader};
use crate::mldsa44::params::ETA;

/// A polynomial in R_q = Z_q[X]/(X^N + 1)
pub type Poly = [i32; N];

/// Add two polynomials (mod Q)
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = (a[i] + b[i]) % Q;
        if r[i] < 0 { r[i] += Q; }
    }
    r
}

/// Subtract two polynomials (mod Q)
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = (a[i] - b[i]) % Q;
        if r[i] < 0 { r[i] += Q; }
    }
    r
}

/// Reduce all coefficients of a polynomial mod Q
pub fn poly_reduce(a: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = a[i] % Q;
        if r[i] < 0 { r[i] += Q; }
    }
    r
}

/// Precomputed zetas for NTT (from Dilithium reference)
pub const ZETAS: [i32; 256] = [
    25847,  941251,  767357,  282634,  1024112,  287924,  1024112,  287924,
    1826347,  2353451,  -359251, -2091905, 3119733, -2884855,  3111497,  2680103,
    2725464,  1024112, -1079900,  3585928, -549488, -1119584,  2619752, -2108549,
    -2118186, -3859737, -1399561, -3277672, 1757237,   -19422,  4010497,   280005,
    2706023,    95776,  3077325, 3530437, -1661693, -3592148, -2537516,  3915439,
    -3861115, -3043716,  3574422, -2867647,  3539968,  -300467,  2348700,  -539299,
    -1699267, -1643818,  3505694, -3821735,  3507263, -2140649, -1600420,  3699596,
    811944,   531354,   954230, 3881043,  3900724, -2556880,  2071892, -2797779,
    -3930395, -1528703, -3677745, -3041255, -1452451,  3475950,  2176455, -1585221,
    -1257611,  1939314, -4083598, -1000202, -3190144, -3157330, -3632928,   126922,
    3412210,  -983419, 2147896,  2715295, -2967645, -3693493,  -411027, -2477047,
    -671102, -1228525,  -22981, -1308169,  -381987,  1349076,  1852771, -1430430,
    -3343383,   264944, 508951,  3097992,    44288, -1100098,   904516,  3958618,
    -3724342,    -8578, 1653064, -3249728,  2389356,  -210977,   759969, -1316856,
    189548, -3553272,  3159746, -1851402, -2409325,  -177440,  1315589,  1341330,
    1285669, -1584928,  -812732, -1439742, -3019102, -3881060, -3628969,  3839961,
    2091667, 3407706,  2316500,  3817976, -3342478,  2244091, -2446433, -3562462,
    266997, 2434439, -1235728,  3513181, -3520352, -3759364, -1197226, -3193378,
    900702, 1859098,   909542,   819034,   495491, -1613174,   -43260,  -522500,
    -655327, -3122442,  2031748,  3207046, -3556995,  -525098,  -768622, -3595838,
    342297,   286988, -2437823,  4108315,  3437287, -3342277,  1735879,   203044,
    2842341,  2691481, -2590150,  1265009,  4055324,  1247620,  2486353,  1595974,
    -3767016,  1250494,  2635921, -3548272, -2994039,  1869119,  1903435, -1050970,
    -1333058,  1237275, -3318210, -1430225,  -451100,  1312455,  3306115, -1962642,
    -1279661,  1917081, -2546312, -1374803,  1500165,   777191,  2235880, 3406031,
    -542412, -2831860, -1671176, -1846953, -2584293, -3724270,   594136, -3776993,
    -2013608,  2432395,  2454455,  -164721,  1957272,  3369112,   185531, -1207385,
    -3183426,   162844,  1616392,  3014001,   810149,  1652634, -3694233, -1799107,
    -3038916,  3523897,  3866901,   269760,  2213111,  -975884,  1717735, 472078,
    -426683,  1723600, -1803090,  1910376, -1667432, -1104333, -260646, -3833893,
    -2939036, -2235985,  -420899, -2286327,   183443,  -976891, 1612842, -3545687,
    -554416,  3919660,   -48306, -1362209,  3937738,  1400424, -846154,  1976782
];

/// Montgomery reduction: computes a * R^{-1} mod Q, where R=2^32
#[inline(always)]
pub fn montgomery_reduce(a: i64) -> i32 {
    const Q: i32 = 8380417;
    const QINV: u32 = 4236238847; // -q^{-1} mod 2^32
    let mut t = (a as i32).wrapping_mul(QINV as i32);
    t = ((a + (t as i64) * (Q as i64)) >> 32) as i32;
    if t >= Q { t - Q } else if t < 0 { t + Q } else { t }
}

/// Forward NTT (in-place, Cooley-Tukey)
pub fn poly_ntt(a: &mut Poly) {
    let mut k = 0;
    let n = N;
    let zetas = &ZETAS;
    let q = Q;
    let mut len = n / 2;
    while len > 0 {
        let mut start = 0;
        while start < n {
            let zeta = zetas[k];
            k += 1;
            for j in start..(start + len) {
                let t = montgomery_reduce((zeta as i64) * (a[j + len] as i64));
                a[j + len] = a[j] - t;
                a[j] = a[j] + t;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    for i in 0..n {
        a[i] = a[i] % q;
        if a[i] < 0 { a[i] += q; }
    }
}

/// Inverse NTT (in-place, Gentleman-Sande)
pub fn poly_inv_ntt(a: &mut Poly) {
    let mut k = 255;
    let n = N;
    let zetas = &ZETAS;
    let q = Q;
    let mut len = 1;
    while len < n {
        let mut start = 0;
        while start < n {
            let zeta = -zetas[k];
            k -= 1;
            for j in start..(start + len) {
                let t = a[j];
                a[j] = t + a[j + len];
                a[j + len] = t - a[j + len];
                a[j + len] = montgomery_reduce((zeta as i64) * (a[j + len] as i64));
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    // Final scaling by Montgomery constant f = 41978
    let f = 41978;
    for i in 0..n {
        a[i] = montgomery_reduce((f as i64) * (a[i] as i64));
        a[i] = a[i] % q;
        if a[i] < 0 { a[i] += q; }
    }
}

/// Pointwise multiplication in NTT domain
pub fn poly_pointwise(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = montgomery_reduce((a[i] as i64) * (b[i] as i64));
    }
    r
}

/// Sample a polynomial with coefficients in [-ETA, ETA] using SHAKE256(seed || nonce)
pub fn poly_sample_eta(seed: &[u8], nonce: u8) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut xof = hasher.finalize_xof();
    let mut poly = [0i32; N];
    let mut buf = [0u8; 128]; // Sufficient for N=256, ETA=2
    let mut ctr = 0;
    while ctr < N {
        xof.read(&mut buf);
        let mut i = 0;
        while i < buf.len() && ctr < N {
            let t0 = buf[i] & 0x0F;
            let t1 = buf[i] >> 4;
            i += 1;
            let eta_i32 = ETA as i32;
            if t0 < 15 {
                let val = 2 - (t0 as i32 - ((205 * t0 as i32) >> 10) * 5);
                if val >= -eta_i32 && val <= eta_i32 {
                    poly[ctr] = val;
                    ctr += 1;
                }
            }
            if t1 < 15 && ctr < N {
                let val = 2 - (t1 as i32 - ((205 * t1 as i32) >> 10) * 5);
                if val >= -eta_i32 && val <= eta_i32 {
                    poly[ctr] = val;
                    ctr += 1;
                }
            }
        }
    }
    poly
}

/// Sample a polynomial with uniformly random coefficients in [0, Q-1] using SHAKE128(seed|nonce)
pub fn poly_uniform(seed: &[u8], nonce: u16) -> Poly {
    let mut out = [0i32; N];
    let mut shake = Shake128::default();
    shake.update(seed);
    shake.update(&[(nonce & 0xFF) as u8, (nonce >> 8) as u8]);
    let mut xof = shake.finalize_xof();
    let mut buf = [0u8; 3 * N];
    xof.read(&mut buf);
    let mut ctr = 0;
    let mut pos = 0;
    while ctr < N && pos + 3 <= buf.len() {
        let t = ((buf[pos] as u32) | ((buf[pos + 1] as u32) << 8) | ((buf[pos + 2] as u32) << 16)) & 0x7FFFFF;
        if t < Q as u32 {
            out[ctr] = t as i32;
            ctr += 1;
        }
        pos += 3;
    }
    out
}

/// Pack polynomial with coefficients in [-ETA, ETA] (ETA=2) into bytes
pub fn poly_pack(a: &Poly) -> Vec<u8> {
    let mut r = vec![0u8; 96]; // 3 bytes per 8 coefficients, N=256
    for i in 0..(N/8) {
        let mut t = [0u8; 8];
        for j in 0..8 {
            t[j] = (ETA as i32 - a[8*i+j]) as u8;
        }
        r[3*i+0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
        r[3*i+1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
        r[3*i+2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
    }
    r
}

/// Unpack polynomial with coefficients in [-ETA, ETA] (ETA=2) from bytes
pub fn poly_unpack(bytes: &[u8]) -> Poly {
    let mut r = [0i32; N];
    for i in 0..(N/8) {
        let b0 = bytes[3*i+0];
        let b1 = bytes[3*i+1];
        let b2 = bytes[3*i+2];
        let mut t = [0u8; 8];
        t[0] = (b0 >> 0) & 7;
        t[1] = (b0 >> 3) & 7;
        t[2] = ((b0 >> 6) | (b1 << 2)) & 7;
        t[3] = (b1 >> 1) & 7;
        t[4] = (b1 >> 4) & 7;
        t[5] = ((b1 >> 7) | (b2 << 1)) & 7;
        t[6] = (b2 >> 2) & 7;
        t[7] = (b2 >> 5) & 7;
        for j in 0..8 {
            r[8*i+j] = ETA as i32 - t[j] as i32;
        }
    }
    r
}
