//! Migration utilities for upgrading classic transactions to quantum-resistant versions

use super::quantum::{QuantumScheme, QuantumValidationError};
use super::quantum_ring::QuantumRingSignature;
use super::quantum_stealth::QuantumStealthAddress;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationMetadata {
    pub original_tx_hash: Vec<u8>,
    pub quantum_scheme: QuantumScheme,
    pub migration_height: u64,
    pub original_pubkey_hash: Vec<u8>,
}

pub struct TransactionMigrator {
    scheme: QuantumScheme,
    current_height: u64,
}

impl TransactionMigrator {
    pub fn new(scheme: QuantumScheme, current_height: u64) -> Self {
        Self {
            scheme,
            current_height,
        }
    }

    pub fn migrate_transaction(&self, tx: &Transaction) -> Result<Transaction, MigrationError> {
        // Create quantum signatures for inputs
        let mut new_inputs = Vec::with_capacity(tx.inputs.len());
        for input in &tx.inputs {
            let quantum_input = self.migrate_input(input)?;
            new_inputs.push(quantum_input);
        }

        // Create quantum stealth addresses for outputs
        let mut new_outputs = Vec::with_capacity(tx.outputs.len());
        for output in &tx.outputs {
            let quantum_output = self.migrate_output(output)?;
            new_outputs.push(quantum_output);
        }

        // Create migration metadata
        let metadata = MigrationMetadata {
            original_tx_hash: tx.hash(),
            quantum_scheme: self.scheme.clone(),
            migration_height: self.current_height,
            original_pubkey_hash: tx.get_pubkey_hash(),
        };

        Ok(Transaction {
            version: tx.version,
            inputs: new_inputs,
            outputs: new_outputs,
            lock_time: tx.lock_time,
            metadata: Some(metadata),
        })
    }

    fn migrate_input(&self, input: &TransactionInput) -> Result<TransactionInput, MigrationError> {
        // Generate quantum ring signature for input
        let ring_sig = match self.scheme {
            QuantumScheme::MLDSA44 => {
                let keypair = ml_dsa_44::Keypair::generate()
                    .map_err(|_| MigrationError::KeyGenerationFailed)?;
                    
                RingBuilder::new(QuantumScheme::MLDSA44)
                    .with_ring_size(input.ring_size())
                    .with_public_keys(input.get_ring_members())
                    .with_secret_key(keypair.secret_key.to_bytes().to_vec(), 0)
                    .build()
                    .map_err(|_| MigrationError::SignatureCreationFailed)?
            }
            QuantumScheme::Dilithium2 => {
                let (pk, sk) = pqcrypto_native::dilithium2::keypair();
                
                RingBuilder::new(QuantumScheme::Dilithium2)
                    .with_ring_size(input.ring_size())
                    .with_public_keys(input.get_ring_members())
                    .with_secret_key(sk.to_vec(), 0)
                    .build()
                    .map_err(|_| MigrationError::SignatureCreationFailed)?
            }
            QuantumScheme::Falcon512 => {
                let (pk, sk) = pqcrypto_native::falcon512::keypair();
                
                RingBuilder::new(QuantumScheme::Falcon512)
                    .with_ring_size(input.ring_size())
                    .with_public_keys(input.get_ring_members())
                    .with_secret_key(sk.to_vec(), 0)
                    .build()
                    .map_err(|_| MigrationError::SignatureCreationFailed)?
            }
        };

        Ok(TransactionInput {
            prev_tx: input.prev_tx.clone(),
            prev_index: input.prev_index,
            script_sig: input.script_sig.clone(),
            ring_signature: Some(ring_sig),
            sequence: input.sequence,
        })
    }

    fn migrate_output(&self, output: &TransactionOutput) -> Result<TransactionOutput, MigrationError> {
        // Generate quantum stealth address for output
        let (_, stealth_addr) = QuantumStealthAddress::generate(self.scheme.clone())
            .map_err(|_| MigrationError::StealthAddressGenerationFailed)?;

        Ok(TransactionOutput {
            value: output.value,
            script_pubkey: output.script_pubkey.clone(),
            stealth_address: Some(stealth_addr),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
    #[error("Failed to generate quantum keys")]
    KeyGenerationFailed,
    
    #[error("Failed to create quantum signature")]
    SignatureCreationFailed,
    
    #[error("Failed to generate stealth address")]
    StealthAddressGenerationFailed,
    
    #[error("Invalid transaction format")]
    InvalidTransaction,
}

// Migration verification utilities
pub fn verify_migrated_transaction(tx: &Transaction) -> Result<bool, MigrationError> {
    // Verify all quantum signatures
    for input in &tx.inputs {
        if let Some(ring_sig) = &input.ring_signature {
            ring_sig.verify(&tx.hash())
                .map_err(|_| MigrationError::InvalidTransaction)?;
        } else {
            return Err(MigrationError::InvalidTransaction);
        }
    }

    // Verify all stealth addresses
    for output in &tx.outputs {
        if output.stealth_address.is_none() {
            return Err(MigrationError::InvalidTransaction);
        }
    }

    // Verify migration metadata
    if let Some(metadata) = &tx.metadata {
        if metadata.migration_height == 0 {
            return Err(MigrationError::InvalidTransaction);
        }
    } else {
        return Err(MigrationError::InvalidTransaction);
    }

    Ok(true)
}
