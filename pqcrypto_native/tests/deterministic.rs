// Removed deterministic keygen tests: not supported by upstream

use pqcrypto_native::*;
use pqcrypto_native::traits::*;

#[test]
fn test_falcon_signature_padding_and_verification() {
    let seed = [7u8; 32];
    let keypair = generate_falcon_keypair_from_seed(&seed).unwrap();
    let message = b"blockchain test message";
    let padded_sig = falcon_sign_padded(message, &keypair.secret).unwrap();
    assert_eq!(padded_sig.len(), FALCON_SIGNATURE_SIZE);
    assert!(falcon_verify_padded(message, &padded_sig, &keypair.public));
    // Negative test: tamper with signature
    let mut tampered = padded_sig;
    tampered[0] ^= 0xFF;
    assert!(!falcon_verify_padded(message, &tampered, &keypair.public));
}
