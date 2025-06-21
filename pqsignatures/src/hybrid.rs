use crate::traits::PQSignatureScheme;
use zeroize::Zeroize;

/// Example hybrid signature: combines classical and PQ signatures
pub struct HybridSignature<C, P> {
    pub classical_sig: C,
    pub pq_sig: P,
}

pub trait HybridSigner {
    type ClassicalSk: Zeroize;
    type PQSk: Zeroize;
    type ClassicalSig;
    type PQSig;

    fn sign_hybrid(
        classical_sk: &Self::ClassicalSk,
        pq_sk: &Self::PQSk,
        message: &[u8],
    ) -> HybridSignature<Self::ClassicalSig, Self::PQSig>;

    fn verify_hybrid(
        classical_pk: &<Self::ClassicalSk as Zeroize>::Target,
        pq_pk: &<Self::PQSk as Zeroize>::Target,
        message: &[u8],
        sig: &HybridSignature<Self::ClassicalSig, Self::PQSig>,
    ) -> bool;
}
