//! Kyber quantum-resistant signature scheme implementation

use super::QuantumValidationError;
use pqcrypto_kyber::{
    keypair as kyber_keypair,
    sign as kyber_sign,
    verify as kyber_verify,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
    Signature as KyberSignature,
};

pub struct KyberScheme;

impl KyberScheme {
    pub fn keypair() -> Result<(Vec<u8>, Vec<u8>), QuantumValidationError> {
        let (pk, sk) = kyber_keypair();
        Ok((pk.to_vec(), sk.to_vec()))
    }

    pub fn sign(sk: &[u8], message: &[u8]) -> Result<Vec<u8>, QuantumValidationError> {
        let secret_key = KyberSecretKey::from_bytes(sk)
            .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
            
        let signature = kyber_sign(message, &secret_key)
            .map_err(|_| QuantumValidationError::InvalidSignature)?;
            
        Ok(signature.to_vec())
    }

    pub fn verify(pk: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, QuantumValidationError> {
        let public_key = KyberPublicKey::from_bytes(pk)
            .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
            
        let sig = KyberSignature::from_bytes(signature)
            .map_err(|_| QuantumValidationError::MalformedSignature)?;
            
        kyber_verify(message, &sig, &public_key)
            .map_err(|_| QuantumValidationError::InvalidSignature)
            .map(|_| true)
    }
}
