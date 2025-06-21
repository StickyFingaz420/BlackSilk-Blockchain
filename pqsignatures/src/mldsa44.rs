// ML-DSA-44: Pure Rust implementation using ml-dsa crate
use zeroize::Zeroize;
use crate::traits::PQSignatureScheme;
use ml_dsa::{PublicKey, SecretKey, Signature};

pub struct MLDSA44PublicKey(pub Vec<u8>);
pub struct MLDSA44SecretKey(pub Vec<u8>);
pub struct MLDSA44Signature(pub Vec<u8>);

impl Zeroize for MLDSA44SecretKey {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

pub struct MLDSA44;

impl PQSignatureScheme for MLDSA44 {
    type PublicKey = MLDSA44PublicKey;
    type SecretKey = MLDSA44SecretKey;
    type Signature = MLDSA44Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey) {
        let (pk, sk) = SecretKey::keypair();
        (MLDSA44PublicKey(pk.to_bytes().to_vec()), MLDSA44SecretKey(sk.to_bytes().to_vec()))
    }
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature {
        let sk = SecretKey::from_bytes(&sk.0).expect("Invalid secret key");
        let sig = sk.sign(message);
        MLDSA44Signature(sig.to_bytes().to_vec())
    }
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Signature) -> bool {
        let pk = PublicKey::from_bytes(&pk.0).expect("Invalid public key");
        let sig = Signature::from_bytes(&sig.0).expect("Invalid signature");
        pk.verify(message, &sig).is_ok()
    }
}

// === Porting Plan ===
// 1. Port ML-DSA-44 parameter constants and core math (hashing, tree, etc.)
// 2. Port keygen, sign, and verify routines from PQClean C to idiomatic Rust
// 3. Ensure constant-time, zeroize, and secure memory handling
// 4. Add test vectors and property-based tests
// 5. Document all security caveats and audit requirements
