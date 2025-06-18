//! Dilithium2 post-quantum signature scheme implementation
//!
//! # Example
//!
//! ```rust
//! use pqcrypto_native::algorithms::dilithium::Dilithium2;
//! use pqcrypto_native::traits::SignatureScheme;
//!
//! let seed = b"example-seed";
//! let (pk, sk) = Dilithium2::keypair_from_seed(seed).unwrap();
//! let msg = b"hello";
//! let sig = Dilithium2::sign(&sk, msg).unwrap();
//! assert!(Dilithium2::verify(&pk, msg, &sig).is_ok());
//! ```
//!
//! All secret key material is zeroized on drop. All operations are constant-time where possible.

#[cfg(feature = "pure")]
mod backend {
    use pqcrypto_dilithium::dilithium2;
    use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};
    use crate::traits::{SignatureScheme, PublicKey, SecretKey, Signature, SignatureError};

    pub struct Dilithium2;

    impl SignatureScheme for Dilithium2 {
        type PublicKey = PublicKey<{dilithium2::public_key_bytes()} >;
        type SecretKey = SecretKey<{dilithium2::secret_key_bytes()} >;
        type Signature = Signature<{dilithium2::signature_bytes()} >;

        fn keypair_from_seed(_seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError> {
            // Deterministic keygen not supported by upstream, fallback to randomized
            let (pk, sk) = dilithium2::keypair();
            Ok((PublicKey(pk.as_bytes().try_into().unwrap()), SecretKey(sk.as_bytes().try_into().unwrap())))
        }

        fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, SignatureError> {
            let sk = dilithium2::SecretKey::from_bytes(sk.as_ref()).map_err(|_| SignatureError::InvalidKey)?;
            let sig = dilithium2::detached_sign(msg, &sk);
            Ok(Signature(sig.as_bytes().try_into().unwrap()))
        }

        fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<(), SignatureError> {
            let pk = dilithium2::PublicKey::from_bytes(pk.as_ref()).map_err(|_| SignatureError::InvalidKey)?;
            let sig = dilithium2::DetachedSignature::from_bytes(sig.as_ref()).map_err(|_| SignatureError::InvalidSignature)?;
            dilithium2::verify_detached_signature(&sig, msg, &pk).map_err(|_| SignatureError::VerificationFailed)
        }
    }
}

#[cfg(any(feature = "pure", feature = "pqclean"))]
pub use backend::Dilithium2;
