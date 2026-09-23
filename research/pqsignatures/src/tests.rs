//! Test vectors and property-based tests for pqsignatures

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dilithium2, Falcon512, PQSignatureScheme};
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
    }

    #[test]
    fn dilithium2_negative_tests() {
        let (pk, sk) = Dilithium2::keypair();
        let msg = b"test message";
        let mut sig = Dilithium2::sign(&sk, msg);
        // Tamper with signature
        if let Some(byte) = sig.as_mut().get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(!Dilithium2::verify(&pk, msg, &sig), "Tampered signature should not verify");
        // Wrong public key
        let (pk2, _) = Dilithium2::keypair();
        let sig2 = Dilithium2::sign(&sk, msg);
        assert!(!Dilithium2::verify(&pk2, msg, &sig2), "Wrong public key should not verify");
    }

    #[test]
    fn falcon512_negative_tests() {
        let (pk, sk) = Falcon512::keypair();
        let msg = b"test message";
        let mut sig = Falcon512::sign(&sk, msg);
        // Tamper with signature
        if let Some(byte) = sig.as_mut().get_mut(0) {
            *byte ^= 0xFF;
        }
        assert!(!Falcon512::verify(&pk, msg, &sig), "Tampered signature should not verify");
        // Wrong public key
        let (pk2, _) = Falcon512::keypair();
        let sig2 = Falcon512::sign(&sk, msg);
        assert!(!Falcon512::verify(&pk2, msg, &sig2), "Wrong public key should not verify");
    }

    #[test]
    fn dilithium2_empty_and_large_message() {
        let (pk, sk) = Dilithium2::keypair();
        let empty = b"";
        let sig_empty = Dilithium2::sign(&sk, empty);
        assert!(Dilithium2::verify(&pk, empty, &sig_empty));
        let large = vec![0xAB; 4096];
        let sig_large = Dilithium2::sign(&sk, &large);
        assert!(Dilithium2::verify(&pk, &large, &sig_large));
    }

    #[test]
    fn falcon512_empty_and_large_message() {
        let (pk, sk) = Falcon512::keypair();
        let empty = b"";
        let sig_empty = Falcon512::sign(&sk, empty);
        assert!(Falcon512::verify(&pk, empty, &sig_empty));
        let large = vec![0xCD; 4096];
        let sig_large = Falcon512::sign(&sk, &large);
        assert!(Falcon512::verify(&pk, &large, &sig_large));
    }
}
