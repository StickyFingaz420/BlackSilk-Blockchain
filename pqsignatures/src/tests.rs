//! Test vectors and property-based tests for pqsignatures

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dilithium2, Falcon512, MLDSA44, PQSignatureScheme};
    use crate::hybrid::{Ed25519Dilithium2Hybrid, Ed25519Falcon512Hybrid, Ed25519MLDSA44Hybrid, HybridSigner};
    use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
    use proptest::prelude::*;

    #[test]
    fn dilithium2_sign_verify() {
        let (pk, sk) = Dilithium2::keypair();
        let msg = b"test message";
        let sig = Dilithium2::sign(&sk, msg);
        assert!(Dilithium2::verify(&pk, msg, &sig));
    }

    #[test]
    fn falcon512_sign_verify() {
        let (pk, sk) = Falcon512::keypair();
        let msg = b"test message";
        let sig = Falcon512::sign(&sk, msg);
        assert!(Falcon512::verify(&pk, msg, &sig));
    }

    #[test]
    fn mldsa44_sign_verify() {
        let (pk, sk) = MLDSA44::keypair();
        let msg = b"test message";
        let sig = MLDSA44::sign(&sk, msg);
        assert!(MLDSA44::verify(&pk, msg, &sig));
    }

    #[test]
    fn hybrid_dilithium2_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let ed_sk = SigningKey::generate(&mut csprng);
        let ed_pk = VerifyingKey::from(&ed_sk);
        let (pq_pk, pq_sk) = Dilithium2::keypair();
        let msg = b"hybrid test message";
        let sig = Ed25519Dilithium2Hybrid::sign_hybrid(&ed_sk, &pq_sk, msg);
        assert!(Ed25519Dilithium2Hybrid::verify_hybrid(&ed_pk, &pq_pk, msg, &sig));
    }

    #[test]
    fn hybrid_falcon512_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let ed_sk = SigningKey::generate(&mut csprng);
        let ed_pk = VerifyingKey::from(&ed_sk);
        let (pq_pk, pq_sk) = Falcon512::keypair();
        let msg = b"hybrid test message";
        let sig = Ed25519Falcon512Hybrid::sign_hybrid(&ed_sk, &pq_sk, msg);
        assert!(Ed25519Falcon512Hybrid::verify_hybrid(&ed_pk, &pq_pk, msg, &sig));
    }

    #[test]
    fn hybrid_mldsa44_sign_verify() {
        let mut csprng = rand::rngs::OsRng;
        let ed_sk = SigningKey::generate(&mut csprng);
        let ed_pk = VerifyingKey::from(&ed_sk);
        let (pq_pk, pq_sk) = MLDSA44::keypair();
        let msg = b"hybrid test message";
        let sig = Ed25519MLDSA44Hybrid::sign_hybrid(&ed_sk, &pq_sk, msg);
        assert!(Ed25519MLDSA44Hybrid::verify_hybrid(&ed_pk, &pq_pk, msg, &sig));
    }

    proptest! {
        #[test]
        fn dilithium2_fuzz(msg in any::<Vec<u8>>()) {
            let (pk, sk) = Dilithium2::keypair();
            let sig = Dilithium2::sign(&sk, &msg);
            prop_assert!(Dilithium2::verify(&pk, &msg, &sig));
        }
        #[test]
        fn falcon512_fuzz(msg in any::<Vec<u8>>()) {
            let (pk, sk) = Falcon512::keypair();
            let sig = Falcon512::sign(&sk, &msg);
            prop_assert!(Falcon512::verify(&pk, &msg, &sig));
        }
        #[test]
        fn mldsa44_fuzz(msg in any::<Vec<u8>>()) {
            let (pk, sk) = MLDSA44::keypair();
            let sig = MLDSA44::sign(&sk, &msg);
            prop_assert!(MLDSA44::verify(&pk, &msg, &sig));
        }
    }
}
