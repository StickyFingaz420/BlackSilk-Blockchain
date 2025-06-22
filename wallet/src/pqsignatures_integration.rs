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
    let sk = Dilithium2::secret_key_from_bytes(&pqkey.dilithium2_sk).expect("Invalid Dilithium2 SK");
    Dilithium2::sign(&sk, tx_bytes).to_vec()
}

/// Sign a transaction with Falcon512
pub fn sign_tx_falcon512(tx_bytes: &[u8], pqkey: &PQKeypair) -> Vec<u8> {
    let sk = Falcon512::secret_key_from_bytes(&pqkey.falcon512_sk).expect("Invalid Falcon512 SK");
    Falcon512::sign(&sk, tx_bytes).to_vec()
}

/// Verify a Dilithium2 signature
pub fn verify_tx_dilithium2(tx_bytes: &[u8], sig: &[u8], pqkey: &PQKeypair) -> bool {
    let pk = Dilithium2::public_key_from_bytes(&pqkey.dilithium2_pk).expect("Invalid Dilithium2 PK");
    let signature = Dilithium2::signature_from_bytes(sig).expect("Invalid Dilithium2 signature");
    Dilithium2::verify(&pk, tx_bytes, &signature)
}

/// Verify a Falcon512 signature
pub fn verify_tx_falcon512(tx_bytes: &[u8], sig: &[u8], pqkey: &PQKeypair) -> bool {
    let pk = Falcon512::public_key_from_bytes(&pqkey.falcon512_pk).expect("Invalid Falcon512 PK");
    let signature = Falcon512::signature_from_bytes(sig).expect("Invalid Falcon512 signature");
    Falcon512::verify(&pk, tx_bytes, &signature)
}
