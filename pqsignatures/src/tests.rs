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
}
