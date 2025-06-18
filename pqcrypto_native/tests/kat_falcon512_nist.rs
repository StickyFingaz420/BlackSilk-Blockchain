use pqcrypto_native::algorithms::falcon::Falcon512;
use pqcrypto_native::traits::SignatureScheme;
use std::time::Instant;

#[test]
fn test_falcon512_sign_verify_roundtrip() {
    let start = Instant::now();
    let (pk, sk) = Falcon512::keypair_from_seed(&[0u8; 32]).unwrap();
    let msg = b"test message";
    let sig = Falcon512::sign(&sk, msg).unwrap();
    assert!(Falcon512::verify(&pk, msg, &sig).is_ok());
    let elapsed = start.elapsed();
    println!("[timing] test_falcon512_sign_verify_roundtrip: {:?}", elapsed);
}
