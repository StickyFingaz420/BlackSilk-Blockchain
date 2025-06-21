use zeroize::Zeroize;

/// Trait for post-quantum signature schemes
pub trait PQSignatureScheme {
    type PublicKey;
    type SecretKey: Zeroize;
    type Signature;

    fn keypair() -> (Self::PublicKey, Self::SecretKey);
    fn sign(sk: &Self::SecretKey, message: &[u8]) -> Self::Signature;
    fn verify(pk: &Self::PublicKey, message: &[u8], sig: &Self::Signature) -> bool;
}
