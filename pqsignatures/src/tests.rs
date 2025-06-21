//! Test vectors and property-based tests for pqsignatures

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Dilithium2, Falcon512, MLDSA44, PQSignatureScheme};
    use proptest::prelude::*;

    #[test]
    fn dilithium2_kat() {
        // TODO: Load and test against NIST KATs
        // Example: assert_eq!(Dilithium2::verify(&pk, msg, &sig), true);
    }

    #[test]
    fn falcon512_kat() {
        // TODO: Load and test against NIST KATs
    }

    #[test]
    fn mldsa44_kat() {
        // TODO: Load and test against NIST KATs
    }

    proptest! {
        #[test]
        fn dilithium2_fuzz(msg in any::<Vec<u8>>()) {
            // TODO: Generate keypair, sign, verify
            // let (pk, sk) = Dilithium2::keypair();
            // let sig = Dilithium2::sign(&sk, &msg);
            // prop_assert!(Dilithium2::verify(&pk, &msg, &sig));
        }
    }
}
