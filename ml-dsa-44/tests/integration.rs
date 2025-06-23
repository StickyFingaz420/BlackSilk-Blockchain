use ml_dsa_44::{Keypair, sign, verify};

#[test]
fn test_cross_crate_usage() {
    let keypair = Keypair::generate().expect("Keygen failed");
    let message = b"Cross-crate integration test!";
    let signature = sign(message, &keypair.secret_key).expect("Sign failed");
    let is_valid = verify(&signature, message, &keypair.public_key).expect("Verify failed");
    assert!(is_valid, "Signature should be valid");
}

#[test]
fn test_error_handling_invalid_key() {
    use ml_dsa_44::constants;
    let message = b"Test message";
    // Invalid secret key (all zeros)
    let bad_sk = ml_dsa_44::SecretKey([0u8; constants::SECRET_KEY_BYTES]);
    let result = sign(message, &bad_sk);
    assert!(result.is_err(), "Signing with invalid key should fail");
}
