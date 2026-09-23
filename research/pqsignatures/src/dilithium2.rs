use crate::traits::PQSignatureScheme;
use crystals_dilithium::dilithium2::{Keypair, PublicKey, SecretKey, Signature};
use std::convert::TryInto;

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
        if bytes.len() != 1312 {
            return Err("Dilithium2 public key must be 1312 bytes");
        }
        Ok(crystals_dilithium::dilithium2::PublicKey::from_bytes(bytes.try_into().unwrap()))
    }
    pub fn secret_key_from_bytes(bytes: &[u8]) -> Result<<Self as PQSignatureScheme>::SecretKey, &'static str> {
        if bytes.len() != 2528 {
            return Err("Dilithium2 secret key must be 2528 bytes");
        }
        Ok(crystals_dilithium::dilithium2::SecretKey::from_bytes(bytes.try_into().unwrap()))
    }
    pub fn signature_from_bytes(bytes: &[u8]) -> Result<<Self as PQSignatureScheme>::Signature, &'static str> {
        if bytes.len() != 2420 {
            return Err("Dilithium2 signature must be 2420 bytes");
        }
        Ok(bytes.try_into().unwrap())
    }
}
