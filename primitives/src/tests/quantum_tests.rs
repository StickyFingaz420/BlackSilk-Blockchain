use super::*;
use crate::quantum::{QuantumScheme, QuantumSignature, QuantumValidationError};
use ml_dsa_44::Keypair as MLDSAKeypair;
use pqcrypto_native::{dilithium2, falcon512};

#[test]
fn test_signature_scheme_switching() {
    // Test switching between different signature schemes
    let message = b"test message";
    
    // ML-DSA-44
    let mldsa_keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let mldsa_sig = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(message, &mldsa_keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: mldsa_keypair.public_key.to_bytes().to_vec(),
    };
    assert!(mldsa_sig.verify(message).unwrap());

    // Dilithium2
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let dilithium_sig = QuantumSignature {
        scheme: QuantumScheme::Dilithium2,
        signature: dilithium2::sign(&dilithium_sk, message).to_vec(),
        public_key: dilithium_pk.to_vec(),
    };
    assert!(dilithium_sig.verify(message).unwrap());

    // Falcon512
    let (falcon_pk, falcon_sk) = falcon512::keypair();
    let falcon_sig = QuantumSignature {
        scheme: QuantumScheme::Falcon512,
        signature: falcon512::sign(&falcon_sk, message).to_vec(),
        public_key: falcon_pk.to_vec(),
    };
    assert!(falcon_sig.verify(message).unwrap());
}

#[test]
fn test_signature_malleability() {
    // Test resistance to signature malleability
    let message = b"test message";
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let signature = ml_dsa_44::sign(message, &keypair.secret_key).unwrap();
    
    let mut sig_bytes = signature.to_bytes().to_vec();
    // Attempt to modify the signature
    sig_bytes[0] ^= 1;
    
    let modified_sig = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: sig_bytes,
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    assert!(modified_sig.verify(message).is_err());
}

#[test]
fn test_cross_scheme_attacks() {
    // Test prevention of cross-scheme attacks
    let message = b"test message";
    
    // Generate signatures with different schemes
    let (dilithium_pk, dilithium_sk) = dilithium2::keypair();
    let dilithium_sig = dilithium2::sign(&dilithium_sk, message);
    
    // Try to verify Dilithium2 signature as ML-DSA-44
    let cross_scheme_sig = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: dilithium_sig.to_vec(),
        public_key: dilithium_pk.to_vec(),
    };
    
    assert!(cross_scheme_sig.verify(message).is_err());
}

#[test]
fn test_message_binding() {
    // Test message binding properties
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let message1 = b"test message 1";
    let message2 = b"test message 2";
    
    let signature = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(message1, &keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    // Verify with correct message
    assert!(signature.verify(message1).unwrap());
    // Verify with wrong message
    assert!(!signature.verify(message2).unwrap());
}

#[test]
fn test_key_reuse() {
    // Test key reuse scenarios
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    let message1 = b"test message 1";
    let message2 = b"test message 2";
    
    // Sign multiple messages with same key
    let sig1 = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(message1, &keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    let sig2 = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(message2, &keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    assert!(sig1.verify(message1).unwrap());
    assert!(sig2.verify(message2).unwrap());
    assert!(!sig1.verify(message2).unwrap());
    assert!(!sig2.verify(message1).unwrap());
}

#[test]
fn test_empty_message() {
    // Test signing empty messages
    let message = b"";
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    
    let signature = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(message, &keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    assert!(signature.verify(message).unwrap());
}

#[test]
fn test_large_message() {
    // Test signing large messages
    let message = vec![0u8; 1024 * 1024]; // 1MB message
    let keypair = MLDSAKeypair::generate().expect("Failed to generate MLDSA keypair");
    
    let signature = QuantumSignature {
        scheme: QuantumScheme::MLDSA44,
        signature: ml_dsa_44::sign(&message, &keypair.secret_key)
            .unwrap()
            .to_bytes()
            .to_vec(),
        public_key: keypair.public_key.to_bytes().to_vec(),
    };
    
    assert!(signature.verify(&message).unwrap());
}
