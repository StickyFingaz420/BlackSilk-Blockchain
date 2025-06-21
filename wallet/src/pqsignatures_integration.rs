//! Example: PQ signature integration in wallet
use crate::pqkey::PQKeypair;
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};

/// Generate, sign, and verify a message using Dilithium2
pub fn dilithium2_demo() {
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"wallet transaction";
    let sig = Dilithium2::sign(&sk, msg);
    assert!(Dilithium2::verify(&pk, msg, &sig));
    println!("Dilithium2 signature verified in wallet!");
}

/// Generate, sign, and verify a message using Falcon512
pub fn falcon512_demo() {
    let (pk, sk) = Falcon512::keypair();
    let msg = b"wallet transaction";
    let sig = Falcon512::sign(&sk, msg);
    assert!(Falcon512::verify(&pk, msg, &sig));
    println!("Falcon512 signature verified in wallet!");
}

/// Sign a transaction with Dilithium2
pub fn sign_tx_dilithium2(tx_bytes: &[u8], pqkey: &PQKeypair) -> Vec<u8> {
    let sk = pqsignatures::dilithium2::SecretKey::from_bytes(&pqkey.dilithium2_sk);
    Dilithium2::sign(&sk, tx_bytes)
}

/// Sign a transaction with Falcon512
pub fn sign_tx_falcon512(tx_bytes: &[u8], pqkey: &PQKeypair) -> Vec<u8> {
    let sk = pqsignatures::falcon512::SecretKey::from_bytes(&pqkey.falcon512_sk).unwrap();
    Falcon512::sign(&sk, tx_bytes).to_bytes().to_vec()
}

/// Verify a Dilithium2 signature
pub fn verify_tx_dilithium2(tx_bytes: &[u8], sig: &[u8], pqkey: &PQKeypair) -> bool {
    let pk = pqsignatures::dilithium2::PublicKey::from_bytes(&pqkey.dilithium2_pk);
    Dilithium2::verify(&pk, tx_bytes, sig)
}

/// Verify a Falcon512 signature
pub fn verify_tx_falcon512(tx_bytes: &[u8], sig: &[u8], pqkey: &PQKeypair) -> bool {
    let pk = pqsignatures::falcon512::PublicKey::from_bytes(&pqkey.falcon512_pk).unwrap();
    let sig = pqsignatures::falcon512::Signature::from_bytes(sig).unwrap();
    Falcon512::verify(&pk, tx_bytes, &sig)
}
