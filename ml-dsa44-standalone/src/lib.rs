//! Standalone pure Rust ML-DSA-44 signature scheme

use ml_dsa::{PublicKey, SecretKey, Signature};
use zeroize::Zeroize;

pub struct MLDSA44PublicKey(pub Vec<u8>);
pub struct MLDSA44SecretKey(pub Vec<u8>);
pub struct MLDSA44Signature(pub Vec<u8>);

impl Zeroize for MLDSA44SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

pub struct MLDSA44;

impl MLDSA44 {
    pub fn keypair() -> (MLDSA44PublicKey, MLDSA44SecretKey) {
        let (pk, sk) = SecretKey::keypair();
        (MLDSA44PublicKey(pk.to_bytes().to_vec()), MLDSA44SecretKey(sk.to_bytes().to_vec()))
    }
    pub fn sign(sk: &MLDSA44SecretKey, message: &[u8]) -> MLDSA44Signature {
        let sk = SecretKey::from_bytes(&sk.0).expect("Invalid secret key");
        let sig = sk.sign(message);
        MLDSA44Signature(sig.to_bytes().to_vec())
    }
    pub fn verify(pk: &MLDSA44PublicKey, message: &[u8], sig: &MLDSA44Signature) -> bool {
        let pk = PublicKey::from_bytes(&pk.0).expect("Invalid public key");
        let sig = Signature::from_bytes(&sig.0).expect("Invalid signature");
        pk.verify(message, &sig).is_ok()
    }
}
