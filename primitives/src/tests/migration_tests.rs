#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum::{QuantumScheme, QuantumValidationError};
    use crate::quantum_ring::QuantumRingSignature;
    use crate::quantum_stealth::QuantumStealthAddress;

    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![
                TransactionInput {
                    prev_tx: vec![0; 32],
                    prev_index: 0,
                    script_sig: vec![],
                    ring_signature: None,
                    sequence: 0,
                }
            ],
            outputs: vec![
                TransactionOutput {
                    value: 1000,
                    script_pubkey: vec![],
                    stealth_address: None,
                }
            ],
            lock_time: 0,
            metadata: None,
        }
    }

    #[test]
    fn test_transaction_migration_mldsa44() {
        let tx = create_test_transaction();
        let migrator = TransactionMigrator::new(QuantumScheme::MLDSA44, 12345);
        
        let migrated_tx = migrator.migrate_transaction(&tx).unwrap();
        
        // Verify migration
        assert!(verify_migrated_transaction(&migrated_tx).unwrap());
        assert_eq!(migrated_tx.metadata.unwrap().quantum_scheme, QuantumScheme::MLDSA44);
        assert_eq!(migrated_tx.metadata.unwrap().migration_height, 12345);
        
        // Verify quantum signatures
        for input in &migrated_tx.inputs {
            assert!(input.ring_signature.is_some());
            let ring_sig = input.ring_signature.as_ref().unwrap();
            assert!(ring_sig.verify(&migrated_tx.hash()).unwrap());
        }
        
        // Verify stealth addresses
        for output in &migrated_tx.outputs {
            assert!(output.stealth_address.is_some());
        }
    }

    #[test]
    fn test_transaction_migration_dilithium2() {
        let tx = create_test_transaction();
        let migrator = TransactionMigrator::new(QuantumScheme::Dilithium2, 12345);
        
        let migrated_tx = migrator.migrate_transaction(&tx).unwrap();
        
        // Verify migration
        assert!(verify_migrated_transaction(&migrated_tx).unwrap());
        assert_eq!(migrated_tx.metadata.unwrap().quantum_scheme, QuantumScheme::Dilithium2);
        
        // Verify signatures and addresses
        for input in &migrated_tx.inputs {
            assert!(input.ring_signature.is_some());
        }
        for output in &migrated_tx.outputs {
            assert!(output.stealth_address.is_some());
        }
    }

    #[test]
    fn test_migration_chain() {
        // Test migrating a chain of transactions
        let tx1 = create_test_transaction();
        let migrator = TransactionMigrator::new(QuantumScheme::MLDSA44, 12345);
        
        let migrated_tx1 = migrator.migrate_transaction(&tx1).unwrap();
        
        // Create a transaction spending from the migrated transaction
        let mut tx2 = create_test_transaction();
        tx2.inputs[0].prev_tx = migrated_tx1.hash();
        
        let migrated_tx2 = migrator.migrate_transaction(&tx2).unwrap();
        
        // Verify both transactions
        assert!(verify_migrated_transaction(&migrated_tx1).unwrap());
        assert!(verify_migrated_transaction(&migrated_tx2).unwrap());
    }

    #[test]
    fn test_migration_error_handling() {
        let mut tx = create_test_transaction();
        let migrator = TransactionMigrator::new(QuantumScheme::MLDSA44, 12345);
        
        // Test invalid input
        tx.inputs[0].prev_tx = vec![]; // Invalid prev_tx
        assert!(migrator.migrate_transaction(&tx).is_err());
        
        // Test invalid metadata
        let mut migrated_tx = migrator.migrate_transaction(&create_test_transaction()).unwrap();
        migrated_tx.metadata = None;
        assert!(verify_migrated_transaction(&migrated_tx).is_err());
    }

    #[test]
    fn test_quantum_resistance() {
        let tx = create_test_transaction();
        let migrator = TransactionMigrator::new(QuantumScheme::MLDSA44, 12345);
        
        let migrated_tx = migrator.migrate_transaction(&tx).unwrap();
        
        // Verify quantum resistance properties
        for input in &migrated_tx.inputs {
            let ring_sig = input.ring_signature.as_ref().unwrap();
            
            // Test against message modification
            let mut modified_msg = migrated_tx.hash();
            modified_msg[0] ^= 1;
            assert!(!ring_sig.verify(&modified_msg).unwrap());
            
            // Test against signature modification
            let mut modified_sig = ring_sig.clone();
            modified_sig.responses[0][0] ^= 1;
            assert!(!modified_sig.verify(&migrated_tx.hash()).unwrap());
        }
        
        // Verify stealth address properties
        for output in &migrated_tx.outputs {
            let stealth_addr = output.stealth_address.as_ref().unwrap();
            assert!(stealth_addr.payment_id.is_none()); // Should be none by default
            
            // Test unlinkability
            let (_, another_addr) = QuantumStealthAddress::generate(QuantumScheme::MLDSA44).unwrap();
            assert!(stealth_addr != &another_addr);
        }
    }
}
