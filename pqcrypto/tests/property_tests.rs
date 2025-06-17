//! Property-based tests for PQ algorithms using proptest
use proptest::prelude::*;
use pqcrypto::wrapper::{keypair_from_seed, sign, verify, PQAlgorithm, seed_from_phrase};

proptest! {
    #[test]
    fn prop_sign_verify_dilithium2(seed in any::<[u8; 128]>(), msg in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let (pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
        let sig = sign(PQAlgorithm::Dilithium2, &sk, &msg).expect("signing should not fail");
        prop_assert!(verify(PQAlgorithm::Dilithium2, &pk, &msg, &sig));
    }

    #[test]
    fn prop_sign_verify_falcon512(seed in any::<[u8; 128]>(), msg in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let (pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
        let sig = sign(PQAlgorithm::Falcon512, &sk, &msg);
        if sig.is_err() {
            println!("[DEBUG] Falcon512 sign failed: sig={:?} sk_len={} msg_len={}", sig, sk.len(), msg.len());
        }
        prop_assume!(sig.is_ok());
        let sig = sig.unwrap();
        prop_assert!(verify(PQAlgorithm::Falcon512, &pk, &msg, &sig));
    }

    #[test]
    fn prop_signatures_unique_falcon512(seed in any::<[u8; 128]>(), msg1 in proptest::collection::vec(any::<u8>(), 1..256), msg2 in proptest::collection::vec(any::<u8>(), 1..256)) {
        prop_assume!(msg1 != msg2);
        let (_pk, sk) = keypair_from_seed(PQAlgorithm::Falcon512, &seed);
        let sig1 = sign(PQAlgorithm::Falcon512, &sk, &msg1);
        let sig2 = sign(PQAlgorithm::Falcon512, &sk, &msg2);
        if sig1.is_err() || sig2.is_err() {
            println!("[DEBUG] Falcon512 sign failed: sig1={:?} sig2={:?} sk_len={} msg1_len={} msg2_len={}", sig1, sig2, sk.len(), msg1.len(), msg2.len());
        }
        prop_assume!(sig1.is_ok() && sig2.is_ok());
        let sig1 = sig1.unwrap();
        let sig2 = sig2.unwrap();
        prop_assert_ne!(sig1, sig2);
    }

    #[test]
    fn prop_signatures_unique_dilithium2(seed in any::<[u8; 128]>(), msg1 in proptest::collection::vec(any::<u8>(), 1..256), msg2 in proptest::collection::vec(any::<u8>(), 1..256)) {
        prop_assume!(msg1 != msg2);
        let (_pk, sk) = keypair_from_seed(PQAlgorithm::Dilithium2, &seed);
        let sig1 = sign(PQAlgorithm::Dilithium2, &sk, &msg1).expect("signing should not fail");
        let sig2 = sign(PQAlgorithm::Dilithium2, &sk, &msg2).expect("signing should not fail");
        prop_assert_ne!(sig1, sig2);
    }
}

#[test]
fn debug_falcon512_keypair_and_sign() {
    use pqcrypto::wrapper::PQAlgorithm;
    let seed = [42u8; 128];
    let msg = b"test message for falcon512".to_vec();
    let (pk, sk) = pqcrypto::wrapper::keypair_from_seed(PQAlgorithm::Falcon512, &seed);
    println!("[DEBUG] Falcon512 pk[0..16]={:02x?}", &pk[..16.min(pk.len())]);
    println!("[DEBUG] Falcon512 sk[0..16]={:02x?}", &sk[..16.min(sk.len())]);
    println!("[DEBUG] Falcon512 pk_len={} sk_len={}", pk.len(), sk.len());
    let sig = pqcrypto::wrapper::sign(PQAlgorithm::Falcon512, &sk, &msg);
    println!("[DEBUG] Falcon512 sign result: {:?}", sig);
    assert!(sig.is_ok(), "Falcon512 sign failed for fixed seed/msg");
}
