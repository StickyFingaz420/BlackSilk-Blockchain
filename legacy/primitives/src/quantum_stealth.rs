//! Quantum-resistant stealth address implementation for BlackSilk
//! Supports ML-DSA-44, Dilithium2, and Falcon512 schemes

use super::quantum::{QuantumScheme, QuantumValidationError};
use sha3::{Digest, Keccak256};
use rand::{thread_rng, RngCore};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuantumStealthAddress {
    pub scheme: QuantumScheme,
    pub view_key: Vec<u8>,
    pub spend_key: Vec<u8>,
    pub payment_id: Option<[u8; 32]>,
    pub diversifier: [u8; 32], // For additional privacy
}

#[derive(Debug, Clone)]
pub struct StealthKeys {
    pub view_private: Vec<u8>,
    pub view_public: Vec<u8>,
    pub spend_private: Vec<u8>,
    pub spend_public: Vec<u8>,
}

impl QuantumStealthAddress {
    pub fn generate(scheme: QuantumScheme) -> Result<(StealthKeys, Self), QuantumValidationError> {
        match scheme {
            QuantumScheme::MLDSA44 => {
                let view_keypair = ml_dsa_44::Keypair::generate()
                    .map_err(|_| QuantumValidationError::RingSignatureError)?;
                let spend_keypair = ml_dsa_44::Keypair::generate()
                    .map_err(|_| QuantumValidationError::RingSignatureError)?;

                let keys = StealthKeys {
                    view_private: view_keypair.secret_key.to_bytes().to_vec(),
                    view_public: view_keypair.public_key.to_bytes().to_vec(),
                    spend_private: spend_keypair.secret_key.to_bytes().to_vec(),
                    spend_public: spend_keypair.public_key.to_bytes().to_vec(),
                };

                let mut diversifier = [0u8; 32];
                thread_rng().fill_bytes(&mut diversifier);

                Ok((keys, Self {
                    scheme,
                    view_key: keys.view_public.clone(),
                    spend_key: keys.spend_public.clone(),
                    payment_id: None,
                    diversifier,
                }))
            }
            QuantumScheme::Dilithium2 => {
                let (view_pk, view_sk) = pqcrypto_native::dilithium2::keypair();
                let (spend_pk, spend_sk) = pqcrypto_native::dilithium2::keypair();

                let keys = StealthKeys {
                    view_private: view_sk.to_vec(),
                    view_public: view_pk.to_vec(),
                    spend_private: spend_sk.to_vec(),
                    spend_public: spend_pk.to_vec(),
                };

                let mut diversifier = [0u8; 32];
                thread_rng().fill_bytes(&mut diversifier);

                Ok((keys, Self {
                    scheme,
                    view_key: keys.view_public.clone(),
                    spend_key: keys.spend_public.clone(),
                    payment_id: None,
                    diversifier,
                }))
            }
            QuantumScheme::Falcon512 => {
                let (view_pk, view_sk) = pqcrypto_native::falcon512::keypair();
                let (spend_pk, spend_sk) = pqcrypto_native::falcon512::keypair();

                let keys = StealthKeys {
                    view_private: view_sk.to_vec(),
                    view_public: view_pk.to_vec(),
                    spend_private: spend_sk.to_vec(),
                    spend_public: spend_pk.to_vec(),
                };

                let mut diversifier = [0u8; 32];
                thread_rng().fill_bytes(&mut diversifier);

                Ok((keys, Self {
                    scheme,
                    view_key: keys.view_public.clone(),
                    spend_key: keys.spend_public.clone(),
                    payment_id: None,
                    diversifier,
                }))
            }
        }
    }

    pub fn generate_payment_id(&mut self) -> [u8; 32] {
        let mut payment_id = [0u8; 32];
        thread_rng().fill_bytes(&mut payment_id);
        self.payment_id = Some(payment_id);
        payment_id
    }

    pub fn create_one_time_address(&self, tx_public: &[u8]) -> Result<Vec<u8>, QuantumValidationError> {
        let mut hasher = Keccak256::new();
        hasher.update(&self.view_key);
        hasher.update(tx_public);
        hasher.update(&self.diversifier);
        
        let mut one_time = hasher.finalize().to_vec();
        one_time.extend_from_slice(&self.spend_key);
        
        Ok(one_time)
    }

    pub fn scan_output(&self, tx_public: &[u8], one_time: &[u8], private_view: &[u8]) -> Result<bool, QuantumValidationError> {
        let mut hasher = Keccak256::new();
        hasher.update(&self.view_key);
        hasher.update(tx_public);
        hasher.update(&self.diversifier);
        
        let expected = hasher.finalize();
        let actual = &one_time[..32];
        
        Ok(expected.as_slice() == actual)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthTransaction {
    pub scheme: QuantumScheme,
    pub tx_public: Vec<u8>,
    pub one_time_address: Vec<u8>,
    pub amount: u64,
    pub payment_id: Option<[u8; 32]>,
}
