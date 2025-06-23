//! ML-DSA-44 integration test for wallet
use ml_dsa_44::{Keypair, sign, verify};

#[test]
fn test_wallet_mldsa44_sign_and_verify() {
    let keypair = Keypair::generate().expect("ML-DSA-44 keygen failed");
    let message = b"Wallet ML-DSA-44 integration test";
    let signature = sign(message, &keypair.secret_key).expect("ML-DSA-44 sign failed");
    let is_valid = verify(&signature, message, &keypair.public_key).expect("ML-DSA-44 verify failed");
    assert!(is_valid);
}
