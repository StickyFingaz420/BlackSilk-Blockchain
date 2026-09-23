#[cfg(test)]
mod tests {
    use super::*;
    use crate::quantum::{QuantumScheme, QuantumValidationError};
    use crate::quantum_ring::{QuantumRingSignature, RingBuilder};
    use crate::quantum_stealth::{QuantumStealthAddress, StealthTransaction};

    #[test]
    fn test_quantum_ring_signature_mldsa44() {
        let message = b"test message";
        let ring_size = 5;
        
        // Generate ring members
        let mut public_keys = Vec::with_capacity(ring_size);
        let real_index = 2;
        let mut real_secret = Vec::new();
        
        for i in 0..ring_size {
            let keypair = ml_dsa_44::Keypair::generate().unwrap();
            if i == real_index {
                real_secret = keypair.secret_key.to_bytes().to_vec();
            }
            public_keys.push(keypair.public_key.to_bytes().to_vec());
        }
        
        let ring_sig = RingBuilder::new(QuantumScheme::MLDSA44)
            .with_ring_size(ring_size)
            .with_public_keys(public_keys.clone())
            .with_secret_key(real_secret, real_index)
            .build()
            .unwrap();
            
        assert!(ring_sig.verify(message).unwrap());
    }

    #[test]
    fn test_quantum_ring_signature_dilithium2() {
        let message = b"test message";
        let ring_size = 5;
        
        let mut public_keys = Vec::with_capacity(ring_size);
        let real_index = 2;
        let mut real_secret = Vec::new();
        
        for i in 0..ring_size {
            let (pk, sk) = pqcrypto_native::dilithium2::keypair();
            if i == real_index {
                real_secret = sk.to_vec();
            }
            public_keys.push(pk.to_vec());
        }
        
        let ring_sig = RingBuilder::new(QuantumScheme::Dilithium2)
            .with_ring_size(ring_size)
            .with_public_keys(public_keys.clone())
            .with_secret_key(real_secret, real_index)
            .build()
            .unwrap();
            
        assert!(ring_sig.verify(message).unwrap());
    }

    #[test]
    fn test_quantum_stealth_address_mldsa44() {
        let (keys, stealth_addr) = QuantumStealthAddress::generate(QuantumScheme::MLDSA44).unwrap();
        
        // Generate transaction
        let mut rng = thread_rng();
        let mut tx_public = vec![0u8; 32];
        rng.fill_bytes(&mut tx_public);
        
        let one_time = stealth_addr.create_one_time_address(&tx_public).unwrap();
        assert!(stealth_addr.scan_output(&tx_public, &one_time, &keys.view_private).unwrap());
    }

    #[test]
    fn test_quantum_stealth_address_unlinkability() {
        let (keys1, addr1) = QuantumStealthAddress::generate(QuantumScheme::MLDSA44).unwrap();
        let (keys2, addr2) = QuantumStealthAddress::generate(QuantumScheme::MLDSA44).unwrap();
        
        // Generate transactions
        let mut rng = thread_rng();
        let mut tx_public1 = vec![0u8; 32];
        let mut tx_public2 = vec![0u8; 32];
        rng.fill_bytes(&mut tx_public1);
        rng.fill_bytes(&mut tx_public2);
        
        let one_time1 = addr1.create_one_time_address(&tx_public1).unwrap();
        let one_time2 = addr2.create_one_time_address(&tx_public2).unwrap();
        
        // Verify unlinkability
        assert!(one_time1 != one_time2);
        assert!(!addr1.scan_output(&tx_public2, &one_time2, &keys1.view_private).unwrap());
        assert!(!addr2.scan_output(&tx_public1, &one_time1, &keys2.view_private).unwrap());
    }

    #[test]
    fn test_quantum_stealth_payment_id() {
        let (keys, mut addr) = QuantumStealthAddress::generate(QuantumScheme::MLDSA44).unwrap();
        
        // Generate payment ID
        let payment_id = addr.generate_payment_id();
        assert!(addr.payment_id.is_some());
        assert_eq!(addr.payment_id.unwrap(), payment_id);
        
        // Create transaction with payment ID
        let mut rng = thread_rng();
        let mut tx_public = vec![0u8; 32];
        rng.fill_bytes(&mut tx_public);
        
        let tx = StealthTransaction {
            scheme: QuantumScheme::MLDSA44,
            tx_public: tx_public.clone(),
            one_time_address: addr.create_one_time_address(&tx_public).unwrap(),
            amount: 1000,
            payment_id: Some(payment_id),
        };
        
        assert_eq!(tx.payment_id.unwrap(), payment_id);
    }

    #[test]
    fn test_quantum_ring_signature_unforgeability() {
        let message = b"test message";
        let ring_size = 5;
        
        // Generate ring members
        let mut public_keys = Vec::with_capacity(ring_size);
        let real_index = 2;
        let mut real_secret = Vec::new();
        
        for i in 0..ring_size {
            let keypair = ml_dsa_44::Keypair::generate().unwrap();
            if i == real_index {
                real_secret = keypair.secret_key.to_bytes().to_vec();
            }
            public_keys.push(keypair.public_key.to_bytes().to_vec());
        }
        
        let ring_sig = RingBuilder::new(QuantumScheme::MLDSA44)
            .with_ring_size(ring_size)
            .with_public_keys(public_keys.clone())
            .with_secret_key(real_secret, real_index)
            .build()
            .unwrap();
            
        // Try to forge by modifying the signature
        let mut forged_sig = ring_sig.clone();
        forged_sig.responses[0][0] ^= 1;
        
        assert!(!forged_sig.verify(message).unwrap());
    }

    #[test]
    fn test_hybrid_scheme_integration() {
        // Test that different quantum schemes can work together
        let message = b"test message";
        
        // Generate mixed ring with different schemes
        let mut public_keys = Vec::new();
        let mut real_secret = Vec::new();
        let real_index = 1;
        
        // Add ML-DSA-44 key
        let mldsa_keypair = ml_dsa_44::Keypair::generate().unwrap();
        public_keys.push(mldsa_keypair.public_key.to_bytes().to_vec());
        
        // Add Dilithium2 key (real signer)
        let (dil_pk, dil_sk) = pqcrypto_native::dilithium2::keypair();
        public_keys.push(dil_pk.to_vec());
        real_secret = dil_sk.to_vec();
        
        // Add Falcon512 key
        let (fal_pk, _) = pqcrypto_native::falcon512::keypair();
        public_keys.push(fal_pk.to_vec());
        
        let ring_sig = RingBuilder::new(QuantumScheme::Dilithium2)
            .with_ring_size(3)
            .with_public_keys(public_keys.clone())
            .with_secret_key(real_secret, real_index)
            .build()
            .unwrap();
            
        assert!(ring_sig.verify(message).unwrap());
    }
}
