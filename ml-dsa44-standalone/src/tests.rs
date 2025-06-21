//! Test vectors and property-based tests for ML-DSA-44 standalone

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn mldsa44_sign_verify() {
        let (pk, sk) = MLDSA44::keypair();
        let msg = b"test message";
        let sig = MLDSA44::sign(&sk, msg);
        assert!(MLDSA44::verify(&pk, msg, &sig));
    }

    proptest! {
        #[test]
        fn mldsa44_fuzz(msg in any::<Vec<u8>>()) {
            let (pk, sk) = MLDSA44::keypair();
            let sig = MLDSA44::sign(&sk, &msg);
            prop_assert!(MLDSA44::verify(&pk, &msg, &sig));
        }
    }
}
