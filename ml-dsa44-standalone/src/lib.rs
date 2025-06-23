//! Standalone pure Rust ML-DSA-44 signature scheme

use ml_dsa::{PublicKey, SecretKey, Signature};
use zeroize::Zeroize;
use rand_chacha::ChaCha20Rng;
use rand_core::{SeedableRng, RngCore};

pub struct MLDSA44PublicKey(pub Vec<u8>);
pub struct MLDSA44SecretKey(pub Vec<u8>);
pub struct MLDSA44Signature(pub Vec<u8>);

impl Zeroize for MLDSA44SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

pub struct MLDSA44;

impl MLDSA44 {
    pub fn keypair() -> (MLDSA44PublicKey, MLDSA44SecretKey) {
        let (pk, sk) = SecretKey::keypair();
        (MLDSA44PublicKey(pk.to_bytes().to_vec()), MLDSA44SecretKey(sk.to_bytes().to_vec()))
    }
    pub fn sign(sk: &MLDSA44SecretKey, message: &[u8]) -> MLDSA44Signature {
        let sk = SecretKey::from_bytes(&sk.0).expect("Invalid secret key");
        let sig = sk.sign(message);
        MLDSA44Signature(sig.to_bytes().to_vec())
    }
    pub fn verify(pk: &MLDSA44PublicKey, message: &[u8], sig: &MLDSA44Signature) -> bool {
        let pk = PublicKey::from_bytes(&pk.0).expect("Invalid public key");
        let sig = Signature::from_bytes(&sig.0).expect("Invalid signature");
        pk.verify(message, &sig).is_ok()
    }
    /// Deterministic keypair generation from a 32-byte seed (for KATs)
    /// Ported from C reference (FIPS 204, PQClean style)
    ///
    /// This matches the C reference KAT logic:
    /// - Accepts a seed as input (like `uint8_t *seed` in C)
    /// - Replaces random seed generation with deterministic expansion from the provided seed
    /// - All randomness (polynomial sampling, matrix expansion) is derived from this seed
    /// - Equivalent to: memcpy(seedbuf, seed, SEEDBYTES); in C reference
    pub fn keypair_from_seed(seed: &[u8]) -> (MLDSA44PublicKey, MLDSA44SecretKey) {
        use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
        use crate::mldsa44::params::*;
        use crate::mldsa44::poly::{poly_sample_eta, poly_ntt, poly_inv_ntt, poly_pointwise, poly_add, poly_power2round};
        use crate::mldsa44::keypack::{pack_t1, pack_t0, pack_s1, pack_s2};
        // 1. Expand seed into rho and key
        let mut shake = Shake256::default();
        shake.update(seed);
        let mut xof = shake.finalize_xof();
        let mut rho = [0u8; 32];
        let mut key = [0u8; 32];
        xof.read(&mut rho);
        xof.read(&mut key);
        // 2. Sample s1 (L), s2 (K) polynomials
        let mut s1 = [[0i32; N]; L];
        let mut s2 = [[0i32; N]; K];
        for i in 0..L {
            s1[i] = poly_sample_eta(&key, i as u8);
        }
        for i in 0..K {
            s2[i] = poly_sample_eta(&key, (L + i) as u8);
        }
        // 3. Expand matrix A from rho, compute t = A * s1 + s2
        let mut t = [[0i32; N]; K];
        let mut mat_a = [[[0i32; N]; L]; K];
        for i in 0..K {
            for j in 0..L {
                mat_a[i][j] = crate::mldsa44::poly::poly_uniform(&rho, (j + (i << 8)) as u16);
            }
        }
        // NTT transform s1
        let mut s1_ntt = s1;
        for i in 0..L {
            poly_ntt(&mut s1_ntt[i]);
        }
        for i in 0..K {
            let mut acc = [0i32; N];
            for j in 0..L {
                let mut a_ntt = mat_a[i][j];
                poly_ntt(&mut a_ntt);
                let prod = poly_pointwise(&a_ntt, &s1_ntt[j]);
                acc = poly_add(&acc, &prod);
            }
            poly_inv_ntt(&mut acc);
            t[i] = poly_add(&acc, &s2[i]);
        }
        // 4. Split t into t1 (high bits) and t0 (low bits)
        let mut t1 = [[0i32; N]; K];
        let mut t0 = [[0i32; N]; K];
        for i in 0..K {
            let (hi, lo) = poly_power2round(&t[i]);
            t1[i] = hi;
            t0[i] = lo;
        }
        // 5. Compute pk = rho || t1
        let mut pk = Vec::with_capacity(32 + 896);
        pk.extend_from_slice(&rho);
        let packed_t1 = pack_t1(&t1);
        pk.extend_from_slice(&packed_t1);
        // 6. Compute tr = H(pk)
        let mut tr = [0u8; 48];
        let mut shake_tr = Shake256::default();
        shake_tr.update(&pk);
        let mut xof_tr = shake_tr.finalize_xof();
        xof_tr.read(&mut tr);
        // 7. Pack secret key
        let packed_s1 = pack_s1(&s1);
        let packed_s2 = pack_s2(&s2);
        let packed_t0 = pack_t0(&t0);
        let mut sk = Vec::with_capacity(32 + 32 + 48 + 384 + 384 + packed_t0.len());
        sk.extend_from_slice(&rho);
        sk.extend_from_slice(&key);
        sk.extend_from_slice(&tr);
        sk.extend_from_slice(&packed_s1[..384]);
        sk.extend_from_slice(&packed_s2[..384]);
        sk.extend_from_slice(&packed_t0);
        (MLDSA44PublicKey(pk), MLDSA44SecretKey(sk))
    }

    // Simple API for test harness compatibility
    pub fn keygen_api(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let (pk, sk) = MLDSA44::keypair_from_seed(seed);
        (pk.0, sk.0)
    }
}

#[link(name = "ml_dsa_ffi", kind = "static")]
extern "C" {
    pub fn crypto_sign_keypair_from_seed(
        pk: *mut u8,
        sk: *mut u8,
        seed: *const u8,
    ) -> i32;
}

pub fn ffi_keypair_from_seed(seed: &[u8; 32]) -> ([u8; 1184], [u8; 2400]) {
    let mut pk = [0u8; 1184];
    let mut sk = [0u8; 2400];
    let ret = unsafe {
        crypto_sign_keypair_from_seed(pk.as_mut_ptr(), sk.as_mut_ptr(), seed.as_ptr())
    };
    assert_eq!(ret, 0, "C keypair generation failed");
    (pk, sk)
}
