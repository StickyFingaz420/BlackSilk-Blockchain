use std::time::Duration;
use reqwest;
use serde_json::Value;

/// Security test for ring signature validation
#[tokio::test]
async fn security_test_ring_signature_integrity() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Generate valid ring signature
    let valid_sig_response = client
        .post(&format!("{}/privacy/ring_signature", node_url))
        .json(&serde_json::json!({
            "ring_size": 5,
            "message": "test_message"
        }))
        .send()
        .await
        .expect("Failed to generate ring signature");
    
    let valid_sig: Value = valid_sig_response.json().await.unwrap();
    
    // Test signature verification
    let verify_response = client
        .post(&format!("{}/privacy/verify_ring_signature", node_url))
        .json(&valid_sig)
        .send()
        .await
        .expect("Failed to verify ring signature");
    
    let verify_result: Value = verify_response.json().await.unwrap();
    assert!(verify_result["valid"].as_bool() == Some(true), "Valid ring signature should verify");
    
    // Test tampered signature (should fail)
    let mut tampered_sig = valid_sig.clone();
    tampered_sig["signature"] = serde_json::Value::String("tampered_signature".to_string());
    
    let tampered_verify_response = client
        .post(&format!("{}/privacy/verify_ring_signature", node_url))
        .json(&tampered_sig)
        .send()
        .await
        .expect("Failed to verify tampered signature");
    
    let tampered_result: Value = tampered_verify_response.json().await.unwrap();
    assert!(tampered_result["valid"].as_bool() == Some(false), "Tampered signature should not verify");
}

/// Security test for double-spend prevention
#[tokio::test]
async fn security_test_double_spend_prevention() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Create first transaction
    let tx1_response = client
        .post(&format!("{}/create_transaction", node_url))
        .json(&serde_json::json!({
            "to": "test_address_1",
            "amount": 1000,
            "key_image": "duplicate_key_image_123"
        }))
        .send()
        .await
        .expect("Failed to create first transaction");
    
    let tx1_result: Value = tx1_response.json().await.unwrap();
    assert!(tx1_result["success"].as_bool() == Some(true), "First transaction should succeed");
    
    // Attempt double-spend with same key image
    let tx2_response = client
        .post(&format!("{}/create_transaction", node_url))
        .json(&serde_json::json!({
            "to": "test_address_2",
            "amount": 500,
            "key_image": "duplicate_key_image_123"
        }))
        .send()
        .await
        .expect("Failed to attempt second transaction");
    
    let tx2_result: Value = tx2_response.json().await.unwrap();
    assert!(tx2_result["success"].as_bool() == Some(false), "Double-spend should be rejected");
    assert!(tx2_result["error"].as_str().unwrap_or("").contains("double"), "Error should mention double-spend");
}

/// Security test for stealth address unlinkability
#[tokio::test]
async fn security_test_stealth_address_unlinkability() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let mut generated_addresses = Vec::new();
    
    // Generate multiple stealth addresses
    for _ in 0..10 {
        let addr_response = client
            .post(&format!("{}/address/stealth", node_url))
            .send()
            .await
            .expect("Failed to generate stealth address");
        
        let addr_result: Value = addr_response.json().await.unwrap();
        let address = addr_result["address"].as_str().unwrap().to_string();
        generated_addresses.push(address);
    }
    
    // Verify all addresses are unique (unlinkable)
    for i in 0..generated_addresses.len() {
        for j in (i+1)..generated_addresses.len() {
            assert_ne!(generated_addresses[i], generated_addresses[j], 
                      "Stealth addresses should be unique");
        }
    }
    
    // Test address validation
    for address in &generated_addresses {
        let validate_response = client
            .post(&format!("{}/address/validate", node_url))
            .json(&serde_json::json!({"address": address}))
            .send()
            .await
            .expect("Failed to validate address");
        
        let validate_result: Value = validate_response.json().await.unwrap();
        assert!(validate_result["valid"].as_bool() == Some(true), 
               "Generated stealth address should be valid");
    }
}

/// Security test for zero-knowledge proof integrity
#[tokio::test]
async fn security_test_zk_proof_integrity() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Generate valid ZK proof for amount
    let amount = 1000;
    let proof_response = client
        .post(&format!("{}/zkproof/create", node_url))
        .json(&serde_json::json!({
            "amount": amount,
            "type": "range_proof"
        }))
        .send()
        .await
        .expect("Failed to create ZK proof");
    
    let proof_result: Value = proof_response.json().await.unwrap();
    let proof = proof_result["proof"].as_str().unwrap();
    
    // Verify valid proof
    let verify_response = client
        .post(&format!("{}/zkproof/verify", node_url))
        .json(&serde_json::json!({
            "proof": proof,
            "amount": amount
        }))
        .send()
        .await
        .expect("Failed to verify ZK proof");
    
    let verify_result: Value = verify_response.json().await.unwrap();
    assert!(verify_result["valid"].as_bool() == Some(true), "Valid ZK proof should verify");
    
    // Test proof with wrong amount (should fail)
    let wrong_verify_response = client
        .post(&format!("{}/zkproof/verify", node_url))
        .json(&serde_json::json!({
            "proof": proof,
            "amount": 2000  // Different amount
        }))
        .send()
        .await
        .expect("Failed to verify ZK proof with wrong amount");
    
    let wrong_verify_result: Value = wrong_verify_response.json().await.unwrap();
    assert!(wrong_verify_result["valid"].as_bool() == Some(false), 
           "ZK proof should not verify with wrong amount");
}

/// Security test for transaction replay attack prevention
#[tokio::test]
async fn security_test_replay_attack_prevention() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Create and submit transaction
    let tx_response = client
        .post(&format!("{}/create_transaction", node_url))
        .json(&serde_json::json!({
            "to": "test_address_replay",
            "amount": 500,
            "nonce": 12345
        }))
        .send()
        .await
        .expect("Failed to create transaction");
    
    let tx_result: Value = tx_response.json().await.unwrap();
    let tx_data = tx_result["transaction"].clone();
    
    // Submit same transaction again (replay attack)
    let replay_response = client
        .post(&format!("{}/submit_transaction", node_url))
        .json(&tx_data)
        .send()
        .await
        .expect("Failed to submit replay transaction");
    
    let replay_result: Value = replay_response.json().await.unwrap();
    assert!(replay_result["success"].as_bool() == Some(false), 
           "Replay transaction should be rejected");
    assert!(replay_result["error"].as_str().unwrap_or("").contains("replay"), 
           "Error should mention replay attack");
}

/// Security test for timing attack resistance
#[tokio::test]
async fn security_test_timing_attack_resistance() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let mut verification_times = Vec::new();
    
    // Measure verification times for valid and invalid signatures
    for i in 0..10 {
        let is_valid = i % 2 == 0;
        let sig_data = if is_valid {
            generate_valid_signature(&client, &node_url).await
        } else {
            generate_invalid_signature()
        };
        
        let start = std::time::Instant::now();
        
        let _verify_response = client
            .post(&format!("{}/privacy/verify_ring_signature", node_url))
            .json(&sig_data)
            .send()
            .await
            .expect("Failed to verify signature");
        
        let elapsed = start.elapsed();
        verification_times.push((is_valid, elapsed));
    }
    
    // Calculate average times for valid vs invalid signatures
    let valid_times: Vec<_> = verification_times.iter()
        .filter(|(valid, _)| *valid)
        .map(|(_, time)| *time)
        .collect();
    
    let invalid_times: Vec<_> = verification_times.iter()
        .filter(|(valid, _)| !*valid)
        .map(|(_, time)| *time)
        .collect();
    
    let avg_valid_time = valid_times.iter().sum::<Duration>() / valid_times.len() as u32;
    let avg_invalid_time = invalid_times.iter().sum::<Duration>() / invalid_times.len() as u32;
    
    // Timing difference should be minimal (within 10% to prevent timing attacks)
    let timing_diff_ratio = (avg_valid_time.as_nanos() as f64 - avg_invalid_time.as_nanos() as f64).abs() 
                           / avg_valid_time.as_nanos() as f64;
    
    assert!(timing_diff_ratio < 0.1, 
           "Timing difference too large: {:.3}% (potential timing attack vector)", 
           timing_diff_ratio * 100.0);
}

/// Security test for cryptographic randomness
#[tokio::test]
async fn security_test_cryptographic_randomness() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let mut random_values = Vec::new();
    
    // Generate multiple random values
    for _ in 0..100 {
        let random_response = client
            .get(&format!("{}/crypto/random", node_url))
            .send()
            .await
            .expect("Failed to get random value");
        
        let random_result: Value = random_response.json().await.unwrap();
        let random_value = random_result["value"].as_str().unwrap();
        random_values.push(random_value.to_string());
    }
    
    // Test for uniqueness (no duplicates)
    let mut unique_values = random_values.clone();
    unique_values.sort();
    unique_values.dedup();
    
    assert_eq!(random_values.len(), unique_values.len(), 
              "Random values should be unique");
    
    // Basic entropy test (each position should have varied characters)
    if let Some(first_value) = random_values.first() {
        let value_length = first_value.len();
        for pos in 0..value_length {
            let chars_at_pos: std::collections::HashSet<char> = random_values
                .iter()
                .map(|val| val.chars().nth(pos).unwrap_or('0'))
                .collect();
            
            // Should have at least 25% unique characters at each position
            assert!(chars_at_pos.len() >= random_values.len() / 4, 
                   "Insufficient entropy at position {}", pos);
        }
    }
}

/// Security test for network privacy (Tor/I2P integration)
#[tokio::test]
async fn security_test_network_privacy() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test privacy mode configuration
    let privacy_config_response = client
        .get(&format!("{}/privacy/config", node_url))
        .send()
        .await
        .expect("Failed to get privacy config");
    
    let privacy_config: Value = privacy_config_response.json().await.unwrap();
    
    // Verify privacy features are enabled
    assert!(privacy_config["tor_enabled"].as_bool().unwrap_or(false), 
           "Tor should be enabled for privacy");
    
    // Test connection anonymization
    let connection_test_response = client
        .post(&format!("{}/privacy/test_anonymization", node_url))
        .send()
        .await
        .expect("Failed to test connection anonymization");
    
    let connection_result: Value = connection_test_response.json().await.unwrap();
    assert!(connection_result["anonymous"].as_bool() == Some(true), 
           "Connections should be anonymized");
}

// Helper functions
async fn generate_valid_signature(client: &reqwest::Client, node_url: &str) -> Value {
    let response = client
        .post(&format!("{}/privacy/ring_signature", node_url))
        .json(&serde_json::json!({
            "ring_size": 3,
            "message": "valid_test_message"
        }))
        .send()
        .await
        .expect("Failed to generate valid signature");
    
    response.json().await.unwrap()
}

fn generate_invalid_signature() -> Value {
    serde_json::json!({
        "ring": ["fake_key_1", "fake_key_2", "fake_key_3"],
        "signature": "invalid_signature_data",
        "message": "test_message"
    })
}

fn get_test_node_url() -> String {
    std::env::var("TEST_NODE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_string())
}
