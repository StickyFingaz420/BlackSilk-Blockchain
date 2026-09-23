use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::thread;
use tempfile::TempDir;
use reqwest;
use serde_json::Value;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_STARTUP_DELAY: Duration = Duration::from_secs(5);

/// Integration test for complete blockchain workflow
#[tokio::test]
async fn test_complete_blockchain_workflow() {
    let test_env = setup_test_environment().await;
    
    // Step 1: Start multiple nodes
    let nodes = start_test_nodes(&test_env, 3).await;
    assert_eq!(nodes.len(), 3);
    
    // Step 2: Wait for nodes to connect
    thread::sleep(NODE_STARTUP_DELAY);
    
    // Step 3: Verify nodes are connected
    for node in &nodes {
        let health = check_node_health(node).await;
        assert!(health.is_ok(), "Node {} is not healthy", node.port);
    }
    
    // Step 4: Mine some blocks
    let blocks_mined = mine_test_blocks(&nodes[0], 5).await;
    assert_eq!(blocks_mined, 5);
    
    // Step 5: Create and submit transaction
    let tx_id = create_test_transaction(&nodes[0]).await;
    assert!(tx_id.is_some());
    
    // Step 6: Verify transaction propagation
    for node in &nodes {
        let tx_found = verify_transaction_in_mempool(node, &tx_id.unwrap()).await;
        assert!(tx_found, "Transaction not found in node {}", node.port);
    }
    
    // Step 7: Mine transaction into block
    let block_with_tx = mine_test_blocks(&nodes[0], 1).await;
    assert_eq!(block_with_tx, 1);
    
    // Step 8: Verify consensus across all nodes
    let consensus = verify_blockchain_consensus(&nodes).await;
    assert!(consensus, "Nodes do not have consensus");
    
    cleanup_test_environment(test_env).await;
}

/// Test privacy features end-to-end
#[tokio::test]
async fn test_privacy_features_e2e() {
    let test_env = setup_test_environment().await;
    let nodes = start_test_nodes(&test_env, 2).await;
    
    thread::sleep(NODE_STARTUP_DELAY);
    
    // Test ring signature transaction
    let private_tx = create_private_transaction(&nodes[0]).await;
    assert!(private_tx.is_ok());
    
    // Test stealth address generation
    let stealth_addr = generate_stealth_address(&nodes[0]).await;
    assert!(stealth_addr.is_ok());
    
    // Test zero-knowledge proof
    let zk_proof = create_zk_proof(&nodes[0], 1000).await;
    assert!(zk_proof.is_ok());
    
    // Verify privacy transaction in blockchain
    mine_test_blocks(&nodes[0], 1).await;
    let privacy_verified = verify_privacy_transaction(&nodes[0]).await;
    assert!(privacy_verified);
    
    cleanup_test_environment(test_env).await;
}

/// Test marketplace integration
#[tokio::test]
async fn test_marketplace_integration() {
    let test_env = setup_test_environment().await;
    let nodes = start_test_nodes(&test_env, 1).await;
    
    // Start marketplace backend
    let marketplace = start_marketplace_backend(&test_env).await;
    assert!(marketplace.is_ok());
    
    thread::sleep(NODE_STARTUP_DELAY);
    
    // Test product creation
    let product_id = create_test_product(&marketplace.unwrap()).await;
    assert!(product_id.is_some());
    
    // Test escrow contract creation
    let escrow = create_escrow_contract(&nodes[0], &product_id.unwrap(), 1000).await;
    assert!(escrow.is_ok());
    
    // Test purchase flow
    let purchase = complete_purchase_flow(&nodes[0], &escrow.unwrap()).await;
    assert!(purchase.is_ok());
    
    cleanup_test_environment(test_env).await;
}

/// Test multi-node consensus
#[tokio::test]
async fn test_multi_node_consensus() {
    let test_env = setup_test_environment().await;
    let nodes = start_test_nodes(&test_env, 5).await;
    
    thread::sleep(NODE_STARTUP_DELAY * 2);
    
    // Create transactions on different nodes
    let mut tx_ids = Vec::new();
    for (i, node) in nodes.iter().enumerate().take(3) {
        let tx_id = create_test_transaction(node).await;
        assert!(tx_id.is_some(), "Failed to create transaction on node {}", i);
        tx_ids.push(tx_id.unwrap());
    }
    
    // Mine blocks on one node
    mine_test_blocks(&nodes[0], 3).await;
    
    // Verify all nodes have same blockchain state
    let mut blockchain_states = Vec::new();
    for node in &nodes {
        let state = get_blockchain_state(node).await;
        assert!(state.is_ok());
        blockchain_states.push(state.unwrap());
    }
    
    // All states should be identical
    let first_state = &blockchain_states[0];
    for state in &blockchain_states[1..] {
        assert_eq!(first_state.height, state.height);
        assert_eq!(first_state.tip_hash, state.tip_hash);
    }
    
    cleanup_test_environment(test_env).await;
}

/// End-to-end test: node <-> wallet <-> miner <-> explorer <-> marketplace <-> faucet
#[tokio::test]
async fn test_full_decentralized_flow() {
    // 1. Start node and ensure it produces blocks
    // TODO: Launch node subprocess or use test harness
    // assert!(node_is_healthy());

    // 2. Create wallet, fund from faucet, and check balance
    // TODO: Use wallet CLI or API
    // let wallet = create_wallet();
    // fund_wallet_from_faucet(&wallet.address);
    // assert!(wallet_balance(&wallet) > 0);

    // 3. Start miner, connect to node, and mine blocks
    // TODO: Launch miner subprocess or use API
    // assert!(miner_is_connected());
    // assert!(blocks_mined() > 0);

    // 4. Query explorer for latest blocks and transactions
    // TODO: Use explorer API
    // let blocks = explorer_get_blocks();
    // assert!(!blocks.is_empty());

    // 5. List product on marketplace (signed, decentralized)
    // TODO: Use marketplace API
    // let product_id = marketplace_list_product(wallet, ...);
    // assert!(product_id.is_some());

    // 6. Place order, create escrow, and simulate delivery/dispute
    // TODO: Use marketplace API and smart contract
    // let order_id = marketplace_place_order(buyer_wallet, product_id);
    // assert!(order_id.is_some());
    // let escrow = create_escrow_contract(...);
    // assert!(escrow.is_active());
    // simulate_dispute_and_resolution(escrow);

    // 7. Check all logs, metrics, and state for correctness
    // TODO: Query Prometheus, logs, and on-chain state
    // assert!(system_is_consistent());
}

// Test helper structures and functions
#[derive(Debug)]
struct TestEnvironment {
    temp_dir: TempDir,
    network: String,
}

#[derive(Debug, Clone)]
struct TestNode {
    port: u16,
    rpc_port: u16,
    process: Option<std::process::Child>,
}

#[derive(Debug, serde::Deserialize)]
struct NodeHealth {
    connected: bool,
    synced: bool,
    height: u64,
}

#[derive(Debug, serde::Deserialize)]
struct BlockchainState {
    height: u64,
    tip_hash: String,
    tx_count: u64,
}

async fn setup_test_environment() -> TestEnvironment {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let network = std::env::var("BLACKSILK_NETWORK").unwrap_or_else(|_| "regtest".to_string());
    
    TestEnvironment { temp_dir, network }
}

async fn start_test_nodes(env: &TestEnvironment, count: usize) -> Vec<TestNode> {
    let mut nodes = Vec::new();
    let base_port = 18080;
    let base_rpc_port = 18081;
    
    for i in 0..count {
        let port = base_port + (i as u16 * 10);
        let rpc_port = base_rpc_port + (i as u16 * 10);
        
        let node_dir = env.temp_dir.path().join(format!("node_{}", i));
        std::fs::create_dir_all(&node_dir).expect("Failed to create node directory");
        
        let mut cmd = Command::new("cargo");
        cmd.args(&[
            "run", "--bin", "blacksilk-node", "--",
            "--data-dir", node_dir.to_str().unwrap(),
            "--port", &port.to_string(),
            "--rpc-port", &rpc_port.to_string(),
            "--network", &env.network,
        ]);
        
        if i > 0 {
            // Connect to first node
            let connect_addr = format!("127.0.0.1:{}", base_port);
            cmd.args(&["--connect", &connect_addr]);
        }
        
        let process = cmd
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start node");
        
        nodes.push(TestNode {
            port,
            rpc_port,
            process: Some(process),
        });
    }
    
    nodes
}

async fn check_node_health(node: &TestNode) -> Result<NodeHealth, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/health", node.rpc_port);
    
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    let health: NodeHealth = response.json().await?;
    Ok(health)
}

async fn mine_test_blocks(node: &TestNode, count: u32) -> u32 {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/mine", node.rpc_port);
    
    for i in 0..count {
        let response = client
            .post(&url)
            .json(&serde_json::json!({"count": 1}))
            .send()
            .await;
        
        if response.is_err() {
            return i;
        }
        
        // Small delay between blocks
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    
    count
}

async fn create_test_transaction(node: &TestNode) -> Option<String> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/create_transaction", node.rpc_port);
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "to": "test_address_123",
            "amount": 1000,
            "private": true
        }))
        .send()
        .await
        .ok()?;
    
    let result: Value = response.json().await.ok()?;
    result["tx_id"].as_str().map(|s| s.to_string())
}

async fn verify_transaction_in_mempool(node: &TestNode, tx_id: &str) -> bool {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/mempool", node.rpc_port);
    
    match client.get(&url).send().await {
        Ok(response) => {
            if let Ok(mempool) = response.json::<Value>().await {
                if let Some(transactions) = mempool["transactions"].as_array() {
                    return transactions.iter().any(|tx| {
                        tx["id"].as_str() == Some(tx_id)
                    });
                }
            }
        }
        Err(_) => return false,
    }
    
    false
}

async fn verify_blockchain_consensus(nodes: &[TestNode]) -> bool {
    let mut heights = Vec::new();
    let mut tip_hashes = Vec::new();
    
    for node in nodes {
        match get_blockchain_state(node).await {
            Ok(state) => {
                heights.push(state.height);
                tip_hashes.push(state.tip_hash);
            }
            Err(_) => return false,
        }
    }
    
    // All heights should be equal
    if !heights.windows(2).all(|w| w[0] == w[1]) {
        return false;
    }
    
    // All tip hashes should be equal
    tip_hashes.windows(2).all(|w| w[0] == w[1])
}

async fn get_blockchain_state(node: &TestNode) -> Result<BlockchainState, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/blockchain/state", node.rpc_port);
    
    let response = client
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    let state: BlockchainState = response.json().await?;
    Ok(state)
}

async fn create_private_transaction(node: &TestNode) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/transaction/private", node.rpc_port);
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "amount": 500,
            "ring_size": 3,
            "stealth": true
        }))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["tx_id"].as_str().unwrap().to_string())
}

async fn generate_stealth_address(node: &TestNode) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/address/stealth", node.rpc_port);
    
    let response = client.post(&url).send().await?;
    let result: Value = response.json().await?;
    Ok(result["address"].as_str().unwrap().to_string())
}

async fn create_zk_proof(node: &TestNode, amount: u64) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/zkproof/create", node.rpc_port);
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "amount": amount,
            "type": "range_proof"
        }))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["proof"].as_str().unwrap().to_string())
}

async fn verify_privacy_transaction(node: &TestNode) -> bool {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/privacy/verify", node.rpc_port);
    
    match client.get(&url).send().await {
        Ok(response) => {
            if let Ok(result) = response.json::<Value>().await {
                return result["privacy_enabled"].as_bool().unwrap_or(false);
            }
        }
        Err(_) => return false,
    }
    
    false
}

async fn start_marketplace_backend(env: &TestEnvironment) -> Result<TestNode, Box<dyn std::error::Error>> {
    let marketplace_dir = env.temp_dir.path().join("marketplace");
    std::fs::create_dir_all(&marketplace_dir)?;
    
    let port = 3001;
    
    let mut cmd = Command::new("cargo");
    cmd.args(&[
        "run", "--bin", "blacksilk-marketplace", "--",
        "--port", &port.to_string(),
        "--data-dir", marketplace_dir.to_str().unwrap(),
    ]);
    
    let process = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    
    Ok(TestNode {
        port,
        rpc_port: port,
        process: Some(process),
    })
}

async fn create_test_product(marketplace: &TestNode) -> Option<String> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/api/products", marketplace.rpc_port);
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "title": "Test Product",
            "description": "A test product for integration testing",
            "price": 1000,
            "category": "digital",
            "seller": "test_seller"
        }))
        .send()
        .await
        .ok()?;
    
    let result: Value = response.json().await.ok()?;
    result["id"].as_str().map(|s| s.to_string())
}

async fn create_escrow_contract(node: &TestNode, product_id: &str, amount: u64) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/escrow/create", node.rpc_port);
    
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "product_id": product_id,
            "amount": amount,
            "buyer": "test_buyer",
            "seller": "test_seller"
        }))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["contract_id"].as_str().unwrap().to_string())
}

async fn complete_purchase_flow(node: &TestNode, escrow_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    // Fund escrow
    let fund_url = format!("http://127.0.0.1:{}/escrow/{}/fund", node.rpc_port, escrow_id);
    client.post(&fund_url).send().await?;
    
    // Release escrow
    let release_url = format!("http://127.0.0.1:{}/escrow/{}/release", node.rpc_port, escrow_id);
    client.post(&release_url).send().await?;
    
    Ok(())
}

async fn cleanup_test_environment(_env: TestEnvironment) {
    // Cleanup is automatic with TempDir
    // Additional cleanup if needed
}
