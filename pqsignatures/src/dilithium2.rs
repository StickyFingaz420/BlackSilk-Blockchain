use zeroize::{Zeroize};
use crate::traits::PQSignatureScheme;
use crystals_dilithium::dilithium2::{keypair, sign, verify, PublicKey, SecretKey, Signature};

/// Secure wrapper for Dilithium2 secret key
pub struct SecureDilithium2SecretKey(pub SecretKey);

impl Zeroize for SecureDilithium2SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

pub struct Dilithium2;

impl PQSignatureScheme for Dilithium2 {
    type PublicKey = PublicKey;
    type SecretKey = SecureDilithium2SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (public, secret) = keypair();
        (public, SecureDilithium2SecretKey(secret))
    }
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        sign(&sk.0, message)
    }
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Signature) -> bool {
        verify(pk, message, sig)
    }
}
