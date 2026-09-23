#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum::{QuantumScheme, QuantumSignature};
    use crate::ring_signature::RingSignatureBuilder;
    use ml_dsa_44::Keypair as MLDSAKeypair;

    fn create_test_transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![TransactionInput {
                prev_tx: vec![0; 32],
                prev_index: 0,
                amount: 1000000,
                script: vec![],
            }],
            outputs: vec![TransactionOutput {
                amount: 999000,
                script: vec![],
            }],
            lock_time: 0,
            signature: None,
            ring_signature: None,
        }
    }

    #[test]
    fn test_mldsa44_signature_validation() {
        let mut tx = create_test_transaction();
        let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
        let message = tx.hash();
        
        let signature = ml_dsa_44::sign(&message, &keypair.secret_key)
            .expect("Failed to sign transaction");

        tx.signature = Some(QuantumSignature {
            scheme: QuantumScheme::MLDSA44,
            signature: signature.to_bytes().to_vec(),
            public_key: keypair.public_key.to_bytes().to_vec(),
        });

        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_ring_signature_validation() {
        let mut tx = create_test_transaction();
        
        // Generate ring members
        let ring_size = 5;
        let mut public_keys = Vec::with_capacity(ring_size);
        let mut keypairs = Vec::with_capacity(ring_size);

        for _ in 0..ring_size {
            let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
            public_keys.push(keypair.public_key.to_bytes().to_vec());
            keypairs.push(keypair);
        }

        // Create ring signature
        let signer_index = 2; // Arbitrary position in the ring
        let ring_sig = RingSignatureBuilder::new(QuantumScheme::MLDSA44)
            .with_ring_size(ring_size)
            .with_public_keys(public_keys)
            .with_secret_key(
                keypairs[signer_index].secret_key.to_bytes().to_vec(),
                signer_index,
            )
            .build()
            .expect("Failed to build ring signature");

        tx.ring_signature = Some(ring_sig);
        assert!(tx.validate().is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let mut tx = create_test_transaction();
        let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
        
        // Create signature with wrong message
        let wrong_message = vec![1; 32];
        let signature = ml_dsa_44::sign(&wrong_message, &keypair.secret_key)
            .expect("Failed to sign transaction");

        tx.signature = Some(QuantumSignature {
            scheme: QuantumScheme::MLDSA44,
            signature: signature.to_bytes().to_vec(),
            public_key: keypair.public_key.to_bytes().to_vec(),
        });

        assert!(matches!(
            tx.validate(),
            Err(TransactionValidationError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_invalid_amounts() {
        let mut tx = create_test_transaction();
        
        // Set output amount greater than input
        tx.outputs[0].amount = 2000000;

        assert!(matches!(
            tx.validate(),
            Err(TransactionValidationError::InsufficientFunds)
        ));
    }

    #[test]
    fn test_invalid_fee() {
        let mut tx = create_test_transaction();
        
        // Set output amount equal to input (no fee)
        tx.outputs[0].amount = tx.inputs[0].amount;

        assert!(matches!(
            tx.validate(),
            Err(TransactionValidationError::InvalidFee)
        ));
    }

    #[test]
    fn test_batch_signature_verification() {
        let mut transactions = Vec::new();
        let num_transactions = 10;

        for _ in 0..num_transactions {
            let mut tx = create_test_transaction();
            let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
            let message = tx.hash();
            
            let signature = ml_dsa_44::sign(&message, &keypair.secret_key)
                .expect("Failed to sign transaction");

            tx.signature = Some(QuantumSignature {
                scheme: QuantumScheme::MLDSA44,
                signature: signature.to_bytes().to_vec(),
                public_key: keypair.public_key.to_bytes().to_vec(),
            });

            transactions.push(tx);
        }

        // Validate all transactions in parallel
        use rayon::prelude::*;
        let results: Vec<Result<bool, TransactionValidationError>> = transactions
            .par_iter()
            .map(|tx| tx.validate())
            .collect();

        assert!(results.iter().all(|r| r.is_ok()));
    }
}
