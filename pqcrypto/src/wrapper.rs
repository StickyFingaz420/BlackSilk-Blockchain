//! Safe Rust wrappers for PQ signature operations
use sha2::{Digest, Sha384};
use libc;
use std::io::{self, Write};

// Only include the generated FFI bindings; do not import as a module
include!(concat!(env!("OUT_DIR"), "/pqc_bindings.rs"));

#[derive(Debug, Clone, Copy)]
pub enum PQAlgorithm {
    Dilithium2,
    Falcon512,
    SphincsPlus, // SLH-DSA-Shake-128s
}

impl PQAlgorithm {
    pub fn to_c(&self) -> ::std::os::raw::c_int {
        match self {
            PQAlgorithm::Dilithium2 => bitcoin_pqc_algorithm_t_BITCOIN_PQC_ML_DSA_44,
            PQAlgorithm::Falcon512 => bitcoin_pqc_algorithm_t_BITCOIN_PQC_FN_DSA_512,
            PQAlgorithm::SphincsPlus => 3, // BITCOIN_PQC_SLH_DSA_SHAKE_128S
        }
    }
}

pub fn keypair_from_seed(algo: PQAlgorithm, seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
    unsafe {
        // Ensure seed is at least 128 bytes (C API requirement)
        assert!(seed.len() >= 128, "Seed must be at least 128 bytes");
        // Set up deterministic random source for ML-DSA-44
        if let PQAlgorithm::Dilithium2 = algo {
            ml_dsa_init_random_source(seed.as_ptr(), seed.len());
        }
        println!("[FFI] keypair_from_seed: algo={:?} seed_ptr={:p} seed[0..8]={:02x?} len={}", algo, seed.as_ptr(), &seed[..seed.len().min(8)], seed.len());
        io::stdout().flush().unwrap();
        let pk_size = bitcoin_pqc_public_key_size(algo.to_c());
        let sk_size = bitcoin_pqc_secret_key_size(algo.to_c());
        let mut keypair = bitcoin_pqc_keypair_t {
            algorithm: algo.to_c(),
            public_key: std::ptr::null_mut(),
            secret_key: std::ptr::null_mut(),
            public_key_size: 0,
            secret_key_size: 0,
        };
        let ret = bitcoin_pqc_keygen(
            algo.to_c(),
            &mut keypair,
            seed.as_ptr(),
            seed.len(),
        );
        println!("[FFI] keygen ret={} pk_size={} sk_size={}", ret, keypair.public_key_size, keypair.secret_key_size);
        io::stdout().flush().unwrap();
        if ret != 0 {
            eprintln!("keygen failed: algo={:?} ret={}", algo, ret);
        }
        assert_eq!(ret, 0, "Keygen failed: {}", ret);
        let pk = std::slice::from_raw_parts(keypair.public_key as *const u8, keypair.public_key_size).to_vec();
        let sk = std::slice::from_raw_parts(keypair.secret_key as *const u8, keypair.secret_key_size).to_vec();
        println!("[FFI] pk[0..8]={:02x?} sk[0..8]={:02x?}", &pk[..pk.len().min(8)], &sk[..sk.len().min(8)]);
        io::stdout().flush().unwrap();
        bitcoin_pqc_keypair_free(&mut keypair);
        // Restore random state after keygen for ML-DSA-44
        if let PQAlgorithm::Dilithium2 = algo {
            ml_dsa_restore_original_random();
        }
        (pk, sk)
    }
}

pub fn sign(algo: PQAlgorithm, sk: &[u8], msg: &[u8]) -> Result<Vec<u8>, i32> {
    unsafe {
        println!("[FFI] sign: algo={:?} sk_ptr={:p} sk[0..8]={:02x?} sk_len={} msg_ptr={:p} msg[0..8]={:02x?} msg_len={}",
            algo,
            sk.as_ptr(),
            &sk[..sk.len().min(8)],
            sk.len(),
            msg.as_ptr(),
            &msg[..msg.len().min(8)],
            msg.len()
        );
        io::stdout().flush().unwrap();
        let sig_size = bitcoin_pqc_signature_size(algo.to_c());
        let mut sig = vec![0u8; sig_size];
        let mut siglen: usize = sig_size;
        let ret = match algo {
            PQAlgorithm::Dilithium2 => ml_dsa_44_sign(
                sig.as_mut_ptr(),
                &mut siglen,
                msg.as_ptr(),
                msg.len(),
                sk.as_ptr(),
            ),
            PQAlgorithm::Falcon512 => {
                let mut signature = bitcoin_pqc_signature_t {
                    algorithm: algo.to_c(),
                    signature: std::ptr::null_mut(),
                    signature_size: 0,
                };
                let ret = bitcoin_pqc_sign(
                    algo.to_c(),
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    &mut signature,
                );
                if ret == 0 && !signature.signature.is_null() && signature.signature_size > 0 {
                    let sig_slice = std::slice::from_raw_parts(signature.signature, signature.signature_size);
                    sig[..sig_slice.len()].copy_from_slice(sig_slice);
                    siglen = sig_slice.len();
                    bitcoin_pqc_signature_free(&mut signature);
                }
                ret
            },
            PQAlgorithm::SphincsPlus => {
                let mut signature = bitcoin_pqc_signature_t {
                    algorithm: algo.to_c(),
                    signature: std::ptr::null_mut(),
                    signature_size: 0,
                };
                let ret = bitcoin_pqc_sign(
                    algo.to_c(),
                    sk.as_ptr(),
                    sk.len(),
                    msg.as_ptr(),
                    msg.len(),
                    &mut signature,
                );
                if ret == 0 && !signature.signature.is_null() && signature.signature_size > 0 {
                    let sig_slice = std::slice::from_raw_parts(signature.signature, signature.signature_size);
                    sig[..sig_slice.len()].copy_from_slice(sig_slice);
                    siglen = sig_slice.len();
                    bitcoin_pqc_signature_free(&mut signature);
                }
                ret
            }
        };
        println!("[FFI] sign ret={} siglen={}", ret, siglen);
        io::stdout().flush().unwrap();
        if ret != 0 {
            eprintln!("sign failed: algo={:?} ret={}", algo, ret);
            return Err(ret);
        }
        sig.truncate(siglen);
        Ok(sig)
    }
}

pub fn verify(algo: PQAlgorithm, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    unsafe {
        let ret = bitcoin_pqc_verify(
            algo.to_c(),
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        );
        ret == 0
    }
}

pub fn seed_from_phrase(phrase: &str) -> Vec<u8> {
    let mut hasher = Sha384::new();
    let mut seed = Vec::new();
    let mut counter = 0u32;
    while seed.len() < 128 {
        hasher.update(phrase.as_bytes());
        hasher.update(&counter.to_le_bytes());
        seed.extend_from_slice(&hasher.finalize_reset());
        counter += 1;
    }
    seed.truncate(128);
    seed
}
