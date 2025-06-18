//! Falcon512 post-quantum signature scheme implementation
//!
//! # Example
//!
//! ```rust
//! use pqcrypto_native::algorithms::falcon::Falcon512;
//! use pqcrypto_native::traits::SignatureScheme;
//!
//! let (pk, sk) = Falcon512::keypair_from_seed(&[0u8; 32]).unwrap();
//! let msg = b"hello";
//! let sig = Falcon512::sign(&sk, msg).unwrap();
//! assert!(Falcon512::verify(&pk, msg, &sig).is_ok());
//! ```
//!
//! All secret key material is zeroized on drop. All operations are constant-time where possible.

use crate::traits::{SignatureScheme, PublicKey, SecretKey, Signature, SignatureError};
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey as _, SecretKey as _, DetachedSignature as _};

pub struct Falcon512;

impl SignatureScheme for Falcon512 {
    type PublicKey = PublicKey<{falcon512::public_key_bytes()} >;
    type SecretKey = SecretKey<{falcon512::secret_key_bytes()} >;
    type Signature = crate::traits::SignatureVec;

    fn keypair_from_seed(_seed: &[u8]) -> Result<(Self::PublicKey, Self::SecretKey), SignatureError> {
        // Deterministic keygen not supported by upstream, fallback to randomized
        let (pk, sk) = falcon512::keypair();
        Ok((PublicKey(pk.as_bytes().try_into().unwrap()), SecretKey(sk.as_bytes().try_into().unwrap())))
    }

    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> Result<Self::Signature, SignatureError> {
        let sk = falcon512::SecretKey::from_bytes(sk.as_ref()).map_err(|_| SignatureError::InvalidKey)?;
        let sig = falcon512::detached_sign(msg, &sk);
        Ok(crate::traits::SignatureVec(sig.as_bytes().to_vec()))
    }

    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> Result<(), SignatureError> {
        let pk = falcon512::PublicKey::from_bytes(pk.as_ref()).map_err(|_| SignatureError::InvalidKey)?;
        let sig = falcon512::DetachedSignature::from_bytes(sig.as_ref()).map_err(|_| SignatureError::InvalidSignature)?;
        falcon512::verify_detached_signature(&sig, msg, &pk).map_err(|_| SignatureError::VerificationFailed)
    }
}
