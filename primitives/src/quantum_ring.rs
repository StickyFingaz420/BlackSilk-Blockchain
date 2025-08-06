//! Quantum-resistant ring signature implementation for BlackSilk
//! Combines ML-DSA-44, Dilithium2, and Falcon512 with ring signature structure

use super::quantum::{QuantumScheme, QuantumValidationError};
use sha3::{Digest, Keccak256};
use rand::{thread_rng, RngCore};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRingSignature {
    pub scheme: QuantumScheme,
    pub ring_size: usize,
    pub public_keys: Vec<Vec<u8>>,
    pub key_images: Vec<Vec<u8>>,
    pub responses: Vec<Vec<u8>>,
    pub challenge: Vec<u8>,
}

pub struct RingBuilder {
    scheme: QuantumScheme,
    ring_size: usize,
    public_keys: Vec<Vec<u8>>,
    secret_key: Option<Vec<u8>>,
    secret_index: Option<usize>,
}

impl RingBuilder {
    pub fn new(scheme: QuantumScheme) -> Self {
        Self {
            scheme,
            ring_size: 0,
            public_keys: Vec::new(),
            secret_key: None,
            secret_index: None,
        }
    }

    pub fn with_ring_size(mut self, size: usize) -> Self {
        self.ring_size = size;
        self
    }

    pub fn with_public_keys(mut self, keys: Vec<Vec<u8>>) -> Self {
        self.public_keys = keys;
        self
    }

    pub fn with_secret_key(mut self, key: Vec<u8>, index: usize) -> Self {
        self.secret_key = Some(key);
        self.secret_index = Some(index);
        self
    }

    pub fn build(self) -> Result<QuantumRingSignature, QuantumValidationError> {
        if self.public_keys.len() != self.ring_size {
            return Err(QuantumValidationError::RingSignatureError);
        }

        let mut rng = thread_rng();
        let mut key_images = Vec::with_capacity(self.ring_size);
        let mut responses = Vec::with_capacity(self.ring_size);

        // Generate key images for each public key
        for pk in &self.public_keys {
            let mut hasher = Keccak256::new();
            hasher.update(pk);
            key_images.push(hasher.finalize().to_vec());
        }

        // Generate random responses for all members except the real signer
        for i in 0..self.ring_size {
            if Some(i) == self.secret_index {
                responses.push(Vec::new()); // Will be filled later
                continue;
            }
            let mut response = vec![0u8; 64];
            rng.fill_bytes(&mut response);
            responses[i] = response;
        }

        // Generate challenge
        let mut hasher = Keccak256::new();
        for (i, pk) in self.public_keys.iter().enumerate() {
            hasher.update(pk);
            hasher.update(&key_images[i]);
            if Some(i) != self.secret_index {
                hasher.update(&responses[i]);
            }
        }
        let challenge = hasher.finalize().to_vec();

        // Generate real signer's response
        if let (Some(sk), Some(idx)) = (self.secret_key, self.secret_index) {
            match self.scheme {
                QuantumScheme::MLDSA44 => {
                    let secret_key = ml_dsa_44::SecretKey::from_bytes(&sk)
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    let signature = ml_dsa_44::sign(&challenge, &secret_key)
                        .map_err(|_| QuantumValidationError::RingSignatureError)?;
                    responses[idx] = signature.to_bytes().to_vec();
                }
                QuantumScheme::Dilithium2 => {
                    let signature = pqcrypto_native::dilithium2::sign(&sk, &challenge);
                    responses[idx] = signature.to_vec();
                }
                QuantumScheme::Falcon512 => {
                    let signature = pqcrypto_native::falcon512::sign(&sk, &challenge);
                    responses[idx] = signature.to_vec();
                }
            }
        }

        Ok(QuantumRingSignature {
            scheme: self.scheme,
            ring_size: self.ring_size,
            public_keys: self.public_keys,
            key_images,
            responses,
            challenge,
        })
    }
}

impl QuantumRingSignature {
    pub fn verify(&self, message: &[u8]) -> Result<bool, QuantumValidationError> {
        if self.public_keys.len() != self.ring_size || 
           self.key_images.len() != self.ring_size || 
           self.responses.len() != self.ring_size {
            return Err(QuantumValidationError::RingSignatureError);
        }

        // Verify each response in the ring
        for i in 0..self.ring_size {
            match self.scheme {
                QuantumScheme::MLDSA44 => {
                    let public_key = ml_dsa_44::PublicKey::from_bytes(&self.public_keys[i])
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    let signature = ml_dsa_44::Signature::from_bytes(&self.responses[i])
                        .map_err(|_| QuantumValidationError::MalformedSignature)?;
                    if !ml_dsa_44::verify(&signature, &self.challenge, &public_key)
                        .map_err(|_| QuantumValidationError::InvalidSignature)? {
                        return Ok(false);
                    }
                }
                QuantumScheme::Dilithium2 => {
                    let pk = pqcrypto_native::dilithium2::public_key_from_bytes(&self.public_keys[i])
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    if !pqcrypto_native::dilithium2::verify(&pk, &self.challenge, &self.responses[i]) {
                        return Ok(false);
                    }
                }
                QuantumScheme::Falcon512 => {
                    let pk = pqcrypto_native::falcon512::public_key_from_bytes(&self.public_keys[i])
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    if !pqcrypto_native::falcon512::verify(&pk, &self.challenge, &self.responses[i]) {
                        return Ok(false);
                    }
                }
            }
        }

        // Verify key images are unique (prevent double spending)
        let mut unique_images = std::collections::HashSet::new();
        for image in &self.key_images {
            if !unique_images.insert(image) {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn get_key_image(&self, index: usize) -> Option<&Vec<u8>> {
        self.key_images.get(index)
    }

    pub fn ring_size(&self) -> usize {
        self.ring_size
    }
}
