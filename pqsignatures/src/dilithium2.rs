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
