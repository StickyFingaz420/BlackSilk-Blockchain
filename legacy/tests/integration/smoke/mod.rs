use std::time::Duration;
use reqwest;
use serde_json::Value;

const SMOKE_TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Quick smoke test to verify basic node functionality
#[tokio::test]
async fn smoke_test_node_startup() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test node health endpoint
    let health_response = client
        .get(&format!("{}/health", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(health_response.is_ok(), "Node health check failed");
    
    let health_data: Value = health_response.unwrap().json().await.unwrap();
    assert!(health_data["status"].as_str() == Some("ok"), "Node status is not ok");
}

/// Smoke test for blockchain info endpoint
#[tokio::test]
async fn smoke_test_blockchain_info() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let info_response = client
        .get(&format!("{}/info", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(info_response.is_ok(), "Blockchain info endpoint failed");
    
    let info_data: Value = info_response.unwrap().json().await.unwrap();
    assert!(info_data["height"].is_number(), "Blockchain height is not a number");
    assert!(info_data["network"].is_string(), "Network field is missing");
}

/// Smoke test for wallet functionality
#[tokio::test]
async fn smoke_test_wallet_creation() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test wallet creation
    let wallet_response = client
        .post(&format!("{}/wallet/create", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(wallet_response.is_ok(), "Wallet creation failed");
    
    let wallet_data: Value = wallet_response.unwrap().json().await.unwrap();
    assert!(wallet_data["address"].is_string(), "Wallet address not returned");
    assert!(wallet_data["mnemonic"].is_string(), "Wallet mnemonic not returned");
}

/// Smoke test for mining functionality
#[tokio::test]
async fn smoke_test_mining_capability() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test mining status
    let mining_response = client
        .get(&format!("{}/mining/status", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(mining_response.is_ok(), "Mining status check failed");
    
    let mining_data: Value = mining_response.unwrap().json().await.unwrap();
    assert!(mining_data["difficulty"].is_number(), "Mining difficulty not available");
}

/// Smoke test for mempool functionality
#[tokio::test]
async fn smoke_test_mempool_access() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let mempool_response = client
        .get(&format!("{}/mempool", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(mempool_response.is_ok(), "Mempool access failed");
    
    let mempool_data: Value = mempool_response.unwrap().json().await.unwrap();
    assert!(mempool_data["transactions"].is_array(), "Mempool transactions not an array");
}

/// Smoke test for marketplace backend
#[tokio::test]
async fn smoke_test_marketplace_backend() {
    let marketplace_url = get_test_marketplace_url();
    let client = reqwest::Client::new();
    
    // Test marketplace health
    let health_response = client
        .get(&format!("{}/health", marketplace_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(health_response.is_ok(), "Marketplace health check failed");
    
    // Test products endpoint
    let products_response = client
        .get(&format!("{}/api/products", marketplace_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(products_response.is_ok(), "Marketplace products endpoint failed");
}

/// Smoke test for privacy features availability
#[tokio::test]
async fn smoke_test_privacy_features() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test stealth address generation
    let stealth_response = client
        .post(&format!("{}/address/stealth", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(stealth_response.is_ok(), "Stealth address generation failed");
    
    // Test ring signature capability
    let ring_sig_response = client
        .post(&format!("{}/privacy/ring_signature_test", node_url))
        .json(&serde_json::json!({"ring_size": 3}))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(ring_sig_response.is_ok(), "Ring signature test failed");
}

/// Smoke test for network connectivity
#[tokio::test]
async fn smoke_test_network_connectivity() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    // Test peer count
    let peers_response = client
        .get(&format!("{}/peers", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(peers_response.is_ok(), "Peers endpoint failed");
    
    let peers_data: Value = peers_response.unwrap().json().await.unwrap();
    assert!(peers_data["count"].is_number(), "Peer count not available");
}

/// Smoke test for configuration loading
#[tokio::test] 
async fn smoke_test_configuration() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let config_response = client
        .get(&format!("{}/config", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(config_response.is_ok(), "Configuration endpoint failed");
    
    let config_data: Value = config_response.unwrap().json().await.unwrap();
    assert!(config_data["network"].is_string(), "Network configuration missing");
    assert!(config_data["p2p_port"].is_number(), "P2P port configuration missing");
}

/// Smoke test for metrics and monitoring
#[tokio::test]
async fn smoke_test_metrics() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let metrics_response = client
        .get(&format!("{}/metrics", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(metrics_response.is_ok(), "Metrics endpoint failed");
    
    // Should return Prometheus format metrics
    let metrics_text = metrics_response.unwrap().text().await.unwrap();
    assert!(metrics_text.contains("blacksilk_"), "BlackSilk metrics not found");
}

/// Smoke test for database connectivity
#[tokio::test]
async fn smoke_test_database() {
    let node_url = get_test_node_url();
    let client = reqwest::Client::new();
    
    let db_response = client
        .get(&format!("{}/database/status", node_url))
        .timeout(SMOKE_TEST_TIMEOUT)
        .send()
        .await;
    
    assert!(db_response.is_ok(), "Database status check failed");
    
    let db_data: Value = db_response.unwrap().json().await.unwrap();
    assert!(db_data["connected"].as_bool() == Some(true), "Database not connected");
}

// Helper functions
fn get_test_node_url() -> String {
    std::env::var("TEST_NODE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:18081".to_string())
}

fn get_test_marketplace_url() -> String {
    std::env::var("TEST_MARKETPLACE_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3001".to_string())
}

/// Test that all core binaries can be executed
#[test]
fn smoke_test_binary_execution() {
    use std::process::Command;
    
    // Test blacksilk-node
    let node_output = Command::new("cargo")
        .args(&["run", "--bin", "blacksilk-node", "--", "--help"])
        .output();
    assert!(node_output.is_ok(), "blacksilk-node binary failed to execute");
    
    // Test blacksilk-wallet  
    let wallet_output = Command::new("cargo")
        .args(&["run", "--bin", "blacksilk-wallet", "--", "--help"])
        .output();
    assert!(wallet_output.is_ok(), "blacksilk-wallet binary failed to execute");
    
    // Test blacksilk-miner
    let miner_output = Command::new("cargo")
        .args(&["run", "--bin", "blacksilk-miner", "--", "--help"])
        .output();
    assert!(miner_output.is_ok(), "blacksilk-miner binary failed to execute");
    
    // Test blacksilk-marketplace
    let marketplace_output = Command::new("cargo")
        .args(&["run", "--bin", "blacksilk-marketplace", "--", "--help"])
        .output();
    assert!(marketplace_output.is_ok(), "blacksilk-marketplace binary failed to execute");
}
