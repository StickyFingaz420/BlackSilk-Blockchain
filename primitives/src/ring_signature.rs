use super::quantum::{QuantumScheme, QuantumValidationError};
use rand::thread_rng;
use sha3::{Digest, Keccak256};

pub struct RingSignatureBuilder {
    scheme: QuantumScheme,
    ring_size: usize,
    public_keys: Vec<Vec<u8>>,
    secret_key: Vec<u8>,
    secret_index: usize,
}

impl RingSignatureBuilder {
    pub fn new(scheme: QuantumScheme) -> Self {
        Self {
            scheme,
            ring_size: 0,
            public_keys: Vec::new(),
            secret_key: Vec::new(),
            secret_index: 0,
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
        self.secret_key = key;
        self.secret_index = index;
        self
    }

    pub fn build(self) -> Result<QuantumRingSignature, QuantumValidationError> {
        if self.public_keys.len() != self.ring_size {
            return Err(QuantumValidationError::RingSignatureError);
        }

        let mut rng = thread_rng();
        let message = match self.scheme {
            QuantumScheme::MLDSA44 => {
                let key_pair = ml_dsa_44::Keypair::from_secret_key(
                    &ml_dsa_44::SecretKey::from_bytes(&self.secret_key)
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?,
                );
                
                // Generate random values for ring signature
                let mut random_values: Vec<Vec<u8>> = Vec::with_capacity(self.ring_size);
                for _ in 0..self.ring_size {
                    let mut random = vec![0u8; 32];
                    rng.fill_bytes(&mut random);
                    random_values.push(random);
                }

                // Create ring signature
                let mut hasher = Keccak256::new();
                for i in 0..self.ring_size {
                    if i == self.secret_index {
                        continue;
                    }
                    hasher.update(&random_values[i]);
                    hasher.update(&self.public_keys[i]);
                }
                
                let challenge = hasher.finalize().to_vec();
                let signature = ml_dsa_44::sign(&challenge, &key_pair.secret_key)
                    .map_err(|_| QuantumValidationError::RingSignatureError)?;

                random_values[self.secret_index] = signature.to_bytes().to_vec();
                random_values.concat()
            }
            QuantumScheme::Dilithium2 => {
                // Dilithium2 ring signature implementation
                let mut random_values: Vec<Vec<u8>> = Vec::with_capacity(self.ring_size);
                for _ in 0..self.ring_size {
                    let mut random = vec![0u8; 64];
                    rng.fill_bytes(&mut random);
                    random_values.push(random);
                }

                // Create ring signature
                let mut hasher = Keccak256::new();
                for i in 0..self.ring_size {
                    if i == self.secret_index {
                        continue;
                    }
                    hasher.update(&random_values[i]);
                    hasher.update(&self.public_keys[i]);
                }
                
                let challenge = hasher.finalize().to_vec();
                let signature = pqcrypto_native::dilithium2::sign(&self.secret_key, &challenge);
                
                random_values[self.secret_index] = signature.to_vec();
                random_values.concat()
            }
            QuantumScheme::Falcon512 => {
                // Falcon512 ring signature implementation
                let mut random_values: Vec<Vec<u8>> = Vec::with_capacity(self.ring_size);
                for _ in 0..self.ring_size {
                    let mut random = vec![0u8; 64];
                    rng.fill_bytes(&mut random);
                    random_values.push(random);
                }

                // Create ring signature
                let mut hasher = Keccak256::new();
                for i in 0..self.ring_size {
                    if i == self.secret_index {
                        continue;
                    }
                    hasher.update(&random_values[i]);
                    hasher.update(&self.public_keys[i]);
                }
                
                let challenge = hasher.finalize().to_vec();
                let signature = pqcrypto_native::falcon512::sign(&self.secret_key, &challenge);
                
                random_values[self.secret_index] = signature.to_vec();
                random_values.concat()
            }
        };

        Ok(QuantumRingSignature {
            scheme: self.scheme,
            ring_size: self.ring_size,
            public_keys: self.public_keys,
            signature: message,
            message: Vec::new(), // Will be set when signing actual message
        })
    }
}

impl QuantumRingSignature {
    pub fn verify(&self, message: &[u8]) -> Result<bool, QuantumValidationError> {
        let sig_size = match self.scheme {
            QuantumScheme::MLDSA44 => ml_dsa_44::SIGNATURE_SIZE,
            QuantumScheme::Dilithium2 => pqcrypto_native::dilithium2::SIGNATURE_SIZE,
            QuantumScheme::Falcon512 => pqcrypto_native::falcon512::SIGNATURE_SIZE,
        };

        if self.signature.len() != sig_size * self.ring_size {
            return Err(QuantumValidationError::MalformedSignature);
        }

        let mut hasher = Keccak256::new();
        hasher.update(message);

        for i in 0..self.ring_size {
            let sig_slice = &self.signature[i * sig_size..(i + 1) * sig_size];
            let pk = &self.public_keys[i];

            match self.scheme {
                QuantumScheme::MLDSA44 => {
                    let signature = ml_dsa_44::Signature::from_bytes(sig_slice)
                        .map_err(|_| QuantumValidationError::MalformedSignature)?;
                    let public_key = ml_dsa_44::PublicKey::from_bytes(pk)
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    
                    if !ml_dsa_44::verify(&signature, message, &public_key)
                        .map_err(|_| QuantumValidationError::InvalidSignature)? {
                        return Ok(false);
                    }
                }
                QuantumScheme::Dilithium2 => {
                    // Verify Dilithium2 signature in the ring
                    let pk = pqcrypto_native::dilithium2::public_key_from_bytes(pk)
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    
                    if !pqcrypto_native::dilithium2::verify(&pk, message, sig_slice) {
                        return Ok(false);
                    }
                }
                QuantumScheme::Falcon512 => {
                    // Verify Falcon512 signature in the ring
                    let pk = pqcrypto_native::falcon512::public_key_from_bytes(pk)
                        .map_err(|_| QuantumValidationError::InvalidPublicKey)?;
                    
                    if !pqcrypto_native::falcon512::verify(&pk, message, sig_slice) {
                        return Ok(false);
                    }
                }
            }
        }

        Ok(true)
    }
}
