use ml_dsa_44::{Keypair as MldsaKeypair, sign as mldsa_sign, verify as mldsa_verify};
use pqsignatures::{Dilithium2, Falcon512, PQSignatureScheme};

#[test]
fn test_all_quantum_signatures_together() {
    let message = b"Quantum integration test!";

    // ML-DSA-44
    let mldsa_keypair = MldsaKeypair::generate().expect("ML-DSA-44 keygen failed");
    let mldsa_sig = mldsa_sign(message, &mldsa_keypair.secret_key).expect("ML-DSA-44 sign failed");
    assert!(mldsa_verify(&mldsa_sig, message, &mldsa_keypair.public_key).expect("ML-DSA-44 verify failed"));

    // Dilithium2
    let (dilithium_pk, dilithium_sk) = Dilithium2::keypair();
    let dilithium_sig = Dilithium2::sign(&dilithium_sk, message);
    assert!(Dilithium2::verify(&dilithium_pk, message, &dilithium_sig));

    // Falcon512
    let (falcon_pk, falcon_sk) = Falcon512::keypair();
    let falcon_sig = Falcon512::sign(&falcon_sk, message);
    assert!(Falcon512::verify(&falcon_pk, message, &falcon_sig));
}
