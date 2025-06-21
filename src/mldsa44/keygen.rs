//! ML-DSA-44 key generation logic
use crate::mldsa44::params::*;
use crate::mldsa44::poly::{Poly, poly_sample_eta, poly_ntt, poly_inv_ntt, poly_pointwise, poly_pack, poly_add};
use crate::mldsa44::keypack::{pack_t1, pack_t0, pack_s1, pack_s2};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Generate a keypair (public key, secret key) using NTT-based primitives
pub fn keygen(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    // 1. Expand seed into rho and key
    let mut shake = Shake256::default();
    shake.update(seed);
    let mut xof = shake.finalize_xof();
    let mut rho = [0u8; 32];
    let mut key = [0u8; 32];
    xof.read(&mut rho);
    xof.read(&mut key);

    #[cfg(feature = "debug_kat")]
    {
        use hex;
        println!("DEBUG_KAT: rho: {}", hex::encode(&rho));
        println!("DEBUG_KAT: key: {}", hex::encode(&key));
    }

    // 2. Sample s1 (L), s2 (K) polynomials
    let mut s1 = [ [0i32; N]; L ];
    let mut s2 = [ [0i32; N]; K ];
    for i in 0..L {
        s1[i] = crate::mldsa44::poly::poly_sample_eta(&key, i as u8);
    }
    for i in 0..K {
        s2[i] = crate::mldsa44::poly::poly_sample_eta(&key, (L + i) as u8);
    }

    // 3. Expand matrix A from rho, compute t = A * s1 + s2 (FIPS 204 compliant)
    let mut t = [ [0i32; N]; K ];
    let mut mat_a = [[ [0i32; N]; L ]; K];
    for i in 0..K {
        for j in 0..L {
            mat_a[i][j] = crate::mldsa44::poly::poly_uniform(&rho, (j + (i << 8)) as u16);
        }
    }
    // NTT transform s1
    let mut s1_ntt = s1;
    for i in 0..L {
        crate::mldsa44::poly::poly_ntt(&mut s1_ntt[i]);
    }
    for i in 0..K {
        let mut acc = [0i32; N];
        for j in 0..L {
            let mut a_ntt = mat_a[i][j];
            crate::mldsa44::poly::poly_ntt(&mut a_ntt);
            let prod = crate::mldsa44::poly::poly_pointwise(&a_ntt, &s1_ntt[j]);
            acc = crate::mldsa44::poly::poly_add(&acc, &prod);
        }
        crate::mldsa44::poly::poly_inv_ntt(&mut acc);
        t[i] = crate::mldsa44::poly::poly_add(&acc, &s2[i]);
    }

    // 4. Split t into t1 (high bits) and t0 (low bits)
    let mut t1 = [[0i32; N]; K];
    let mut t0 = [[0i32; N]; K];
    for i in 0..K {
        let (hi, lo) = crate::mldsa44::poly::poly_power2round(&t[i]);
        t1[i] = hi;
        t0[i] = lo;
    }
    // Debug: print packed t1 and t0 for first test vector
    #[cfg(feature = "debug_kat")]
    {
        use hex;
        let packed_t1 = pack_t1(&t1);
        let packed_t0 = pack_t0(&t0);
        println!("DEBUG_KAT: packed_t1: {}", hex::encode(&packed_t1));
        println!("DEBUG_KAT: packed_t0: {}", hex::encode(&packed_t0));
    }
    // 5. Compute tr = H(pk) (optional for KAT)
    let mut pk = Vec::with_capacity(32 + 1280);
    pk.extend_from_slice(&rho);
    pk.extend_from_slice(&pack_t1(&t1));

    #[cfg(feature = "debug_kat")]
    {
        use hex;
        let packed_t1 = pack_t1(&t1);
        let packed_t0 = pack_t0(&t0);
        println!("DEBUG_KAT: packed_t1: {}", hex::encode(&packed_t1));
        println!("DEBUG_KAT: packed_t0: {}", hex::encode(&packed_t0));
        println!("DEBUG_KAT: pk: {}", hex::encode(&pk));
    }
    // 5. Compute tr = H(pk) (optional for KAT)
    let mut tr = [0u8; 48];
    let mut shake_tr = Shake256::default();
    shake_tr.update(&pk);
    let mut xof_tr = shake_tr.finalize_xof();
    xof_tr.read(&mut tr);

    #[cfg(feature = "debug_kat")]
    {
        use hex;
        println!("DEBUG_KAT: tr: {}", hex::encode(&tr));
    }

    // 6. Pack secret key
    let packed_s1 = pack_s1(&s1);
    let packed_s2 = pack_s2(&s2);
    let packed_t0 = pack_t0(&t0);
    println!("DEBUG: packed_s1.len() = {}", packed_s1.len());
    println!("DEBUG: packed_s2.len() = {}", packed_s2.len());
    println!("DEBUG: packed_t0.len() = {}", packed_t0.len());
    let mut sk = Vec::with_capacity(32 + 32 + 48 + packed_s1.len() + packed_s2.len() + packed_t0.len());
    sk.extend_from_slice(&rho);
    sk.extend_from_slice(&key);
    sk.extend_from_slice(&tr);
    sk.extend_from_slice(&packed_s1);
    sk.extend_from_slice(&packed_s2);
    sk.extend_from_slice(&packed_t0);
    println!("DEBUG: sk.len() = {}", sk.len());

    #[cfg(feature = "debug_kat")]
    {
        use hex;
        println!("DEBUG_KAT: sk: {}", hex::encode(&sk));
    }

    (pk, sk)
}
