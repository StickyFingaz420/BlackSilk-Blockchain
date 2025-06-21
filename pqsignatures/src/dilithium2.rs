use crate::traits::PQSignatureScheme;
use crystals_dilithium::dilithium2::{Keypair, PublicKey, SecretKey, Signature};

pub struct Dilithium2;

impl PQSignatureScheme for Dilithium2 {
    type PublicKey = PublicKey;
    type SecretKey = SecretKey;
    type Signature = Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let Keypair { public, secret } = Keypair::generate(None);
        (public, secret)
    }
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        sk.sign(message)
    }
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Signature) -> bool {
        pk.verify(message, sig)
    }
}

impl Dilithium2 {
    pub fn public_key_from_bytes(bytes: &[u8]) -> Result<<Self as PQSignatureScheme>::PublicKey, &'static str> {
        crystals_dilithium::dilithium2::PublicKey::from_bytes(bytes).map_err(|_| "Invalid Dilithium2 public key")
    }
    pub fn signature_from_bytes(bytes: &[u8]) -> Result<<Self as PQSignatureScheme>::Signature, &'static str> {
        crystals_dilithium::dilithium2::Signature::mut_from_bytes(bytes).map_err(|_| "Invalid Dilithium2 signature")
    }
}
