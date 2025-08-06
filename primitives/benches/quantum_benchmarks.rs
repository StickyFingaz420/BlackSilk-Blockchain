#![feature(test)]
extern crate test;

use test::Bencher;
use super::*;
use crate::quantum::{QuantumScheme, QuantumSignature};
use ml_dsa_44::Keypair as MLDSAKeypair;
use pqcrypto_native::{dilithium2, falcon512};
use rayon::prelude::*;

#[bench]
fn bench_mldsa44_sign(b: &mut Bencher) {
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let message = b"benchmark message";
    
    b.iter(|| {
        ml_dsa_44::sign(message, &keypair.secret_key).unwrap()
    });
}

#[bench]
fn bench_mldsa44_verify(b: &mut Bencher) {
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let message = b"benchmark message";
    let signature = ml_dsa_44::sign(message, &keypair.secret_key).unwrap();
    
    b.iter(|| {
        ml_dsa_44::verify(&signature, message, &keypair.public_key).unwrap()
    });
}

#[bench]
fn bench_dilithium2_sign(b: &mut Bencher) {
    let (pk, sk) = dilithium2::keypair();
    let message = b"benchmark message";
    
    b.iter(|| {
        dilithium2::sign(&sk, message)
    });
}

#[bench]
fn bench_dilithium2_verify(b: &mut Bencher) {
    let (pk, sk) = dilithium2::keypair();
    let message = b"benchmark message";
    let signature = dilithium2::sign(&sk, message);
    
    b.iter(|| {
        dilithium2::verify(&pk, message, &signature)
    });
}

#[bench]
fn bench_falcon512_sign(b: &mut Bencher) {
    let (pk, sk) = falcon512::keypair();
    let message = b"benchmark message";
    
    b.iter(|| {
        falcon512::sign(&sk, message)
    });
}

#[bench]
fn bench_falcon512_verify(b: &mut Bencher) {
    let (pk, sk) = falcon512::keypair();
    let message = b"benchmark message";
    let signature = falcon512::sign(&sk, message);
    
    b.iter(|| {
        falcon512::verify(&pk, message, &signature)
    });
}

#[bench]
fn bench_batch_verification(b: &mut Bencher) {
    let num_signatures = 100;
    let message = b"benchmark message";
    
    // Create signatures with different schemes
    let mut signatures = Vec::with_capacity(num_signatures);
    
    for i in 0..num_signatures {
        let sig = match i % 3 {
            0 => {
                let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
                QuantumSignature {
                    scheme: QuantumScheme::MLDSA44,
                    signature: ml_dsa_44::sign(message, &keypair.secret_key)
                        .unwrap()
                        .to_bytes()
                        .to_vec(),
                    public_key: keypair.public_key.to_bytes().to_vec(),
                }
            },
            1 => {
                let (pk, sk) = dilithium2::keypair();
                QuantumSignature {
                    scheme: QuantumScheme::Dilithium2,
                    signature: dilithium2::sign(&sk, message).to_vec(),
                    public_key: pk.to_vec(),
                }
            },
            _ => {
                let (pk, sk) = falcon512::keypair();
                QuantumSignature {
                    scheme: QuantumScheme::Falcon512,
                    signature: falcon512::sign(&sk, message).to_vec(),
                    public_key: pk.to_vec(),
                }
            }
        };
        signatures.push(sig);
    }
    
    b.iter(|| {
        signatures.par_iter().all(|sig| sig.verify(message).unwrap())
    });
}

#[bench]
fn bench_signature_size_comparison(_b: &mut Bencher) {
    let message = b"benchmark message";
    
    // ML-DSA-44
    let mldsa_keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let mldsa_sig = ml_dsa_44::sign(message, &mldsa_keypair.secret_key).unwrap();
    println!("ML-DSA-44 signature size: {} bytes", mldsa_sig.to_bytes().len());
    
    // Dilithium2
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let dilithium_sig = dilithium2::sign(&dilithium_sk, message);
    println!("Dilithium2 signature size: {} bytes", dilithium_sig.len());
    
    // Falcon512
    let (falcon_pk, falcon_sk) = falcon512::keypair();
    let falcon_sig = falcon512::sign(&falcon_sk, message);
    println!("Falcon512 signature size: {} bytes", falcon_sig.len());
}
