use zeroize::Zeroize;
use crate::traits::HybridSigner;
use crate::dilithium2::{Dilithium2, SecureDilithium2SecretKey, Dilithium2PublicKey, Dilithium2Signature};
use crate::falcon512::{Falcon512, Falcon512SecretKey, Falcon512PublicKey, Falcon512Signature};
use crate::mldsa44::{MLDSA44, MLDSA44SecretKey, MLDSA44PublicKey, MLDSA44Signature};

pub struct HybridSignature<C, P> {
    pub classical_sig: C,
    pub pq_sig: P,
}

pub struct Ed25519Dilithium2Hybrid;
pub struct Ed25519Falcon512Hybrid;
pub struct Ed25519MLDSA44Hybrid;

impl HybridSigner for Ed25519Dilithium2Hybrid {
    type ClassicalSk = SigningKey;
    type PQSk = SecureDilithium2SecretKey;
    type ClassicalSig = Ed25519Signature;
    type PQSig = Dilithium2Signature;

    fn sign_hybrid(
        classical_sk: &Self::ClassicalSk,
        pq_sk: &Self::PQSk,
        message: &[u8],
    ) -> HybridSignature<Self::ClassicalSig, Self::PQSig> {
        let classical_sig = classical_sk.sign(message);
        let pq_sig = Dilithium2::sign(pq_sk, message);
        HybridSignature { classical_sig, pq_sig }
    }

    fn verify_hybrid(
        classical_pk: &VerifyingKey,
        pq_pk: &Dilithium2PublicKey,
        message: &[u8],
        sig: &HybridSignature<Self::ClassicalSig, Self::PQSig>,
    ) -> bool {
        classical_pk.verify(message, &sig.classical_sig).is_ok() &&
        Dilithium2::verify(pq_pk, message, &sig.pq_sig)
    }
}

impl HybridSigner for Ed25519Falcon512Hybrid {
    type ClassicalSk = SigningKey;
    type PQSk = Falcon512SecretKey;
    type ClassicalSig = Ed25519Signature;
    type PQSig = Falcon512Signature;

    fn sign_hybrid(
        classical_sk: &Self::ClassicalSk,
        pq_sk: &Self::PQSk,
        message: &[u8],
    ) -> HybridSignature<Self::ClassicalSig, Self::PQSig> {
        let classical_sig = classical_sk.sign(message);
        let pq_sig = Falcon512::sign(pq_sk, message);
        HybridSignature { classical_sig, pq_sig }
    }

    fn verify_hybrid(
        classical_pk: &VerifyingKey,
        pq_pk: &Falcon512PublicKey,
        message: &[u8],
        sig: &HybridSignature<Self::ClassicalSig, Self::PQSig>,
    ) -> bool {
        classical_pk.verify(message, &sig.classical_sig).is_ok() &&
        Falcon512::verify(pq_pk, message, &sig.pq_sig)
    }
}

impl HybridSigner for Ed25519MLDSA44Hybrid {
    type ClassicalSk = SigningKey;
    type PQSk = MLDSA44SecretKey;
    type ClassicalSig = Ed25519Signature;
    type PQSig = MLDSA44Signature;

    fn sign_hybrid(
        classical_sk: &Self::ClassicalSk,
        pq_sk: &Self::PQSk,
        message: &[u8],
    ) -> HybridSignature<Self::ClassicalSig, Self::PQSig> {
        let classical_sig = classical_sk.sign(message);
        let pq_sig = MLDSA44::sign(pq_sk, message);
        HybridSignature { classical_sig, pq_sig }
    }

    fn verify_hybrid(
        classical_pk: &VerifyingKey,
        pq_pk: &MLDSA44PublicKey,
        message: &[u8],
        sig: &HybridSignature<Self::ClassicalSig, Self::PQSig>,
    ) -> bool {
        classical_pk.verify(message, &sig.classical_sig).is_ok() &&
        MLDSA44::verify(pq_pk, message, &sig.pq_sig)
    }
}
