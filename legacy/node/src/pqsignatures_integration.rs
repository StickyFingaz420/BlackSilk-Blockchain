//! Example: PQ signature integration in node
use ml_dsa_44::{Keypair as MLDsa44Keypair, sign as mldsa44_sign, verify as mldsa44_verify};
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};

/// Generate, sign, and verify a message using Dilithium2
pub fn dilithium2_demo() {
    let (pk, sk) = Dilithium2::keypair();
    let msg = b"node transaction";
    let sig = Dilithium2::sign(&sk, msg);
    assert!(Dilithium2::verify(&pk, msg, &sig));
    println!("Dilithium2 signature verified in node!");
}

/// Generate, sign, and verify a message using Falcon512
pub fn falcon512_demo() {
    let (pk, sk) = Falcon512::keypair();
    let msg = b"node transaction";
    let sig = Falcon512::sign(&sk, msg);
    assert!(Falcon512::verify(&pk, msg, &sig));
    println!("Falcon512 signature verified in node!");
}

/// Generate, sign, and verify a message using ML-DSA-44
pub fn mldsa44_demo() {
    let keypair = MLDsa44Keypair::generate().expect("ML-DSA-44 keygen failed");
    let msg = b"node transaction";
    let signature = mldsa44_sign(msg, &keypair.secret_key).expect("ML-DSA-44 sign failed");
    let is_valid = mldsa44_verify(&signature, msg, &keypair.public_key).expect("ML-DSA-44 verify failed");
    assert!(is_valid);
    println!("ML-DSA-44 signature verified in node!");
}
