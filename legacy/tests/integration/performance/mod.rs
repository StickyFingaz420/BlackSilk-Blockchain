use std::time::{Duration, Instant};
use std::collections::HashMap;
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use reqwest;
use serde_json::Value;
use tokio::runtime::Runtime;

/// Performance benchmark for transaction processing
pub fn benchmark_transaction_throughput(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("transaction_throughput");
    group.throughput(Throughput::Elements(100));
    
    group.bench_function("process_transactions", |b| {
        b.iter(|| {
            rt.block_on(async {
                let start = Instant::now();
                let mut successful_txs = 0;
                
                // Submit 100 transactions
                for i in 0..100 {
                    if create_test_transaction(&node_url, i).await.is_ok() {
                        successful_txs += 1;
                    }
                }
                
                let elapsed = start.elapsed();
                println!("Processed {} transactions in {:?}", successful_txs, elapsed);
                successful_txs
            })
        })
    });
    
    group.finish();
}

/// Performance benchmark for block mining
pub fn benchmark_mining_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("mining_performance");
    group.measurement_time(Duration::from_secs(60));
    
    group.bench_function("mine_blocks", |b| {
        b.iter(|| {
            rt.block_on(async {
                let start = Instant::now();
                let blocks_mined = mine_test_blocks(&node_url, 10).await;
                let elapsed = start.elapsed();
                
                let blocks_per_second = blocks_mined as f64 / elapsed.as_secs_f64();
                println!("Mining rate: {:.2} blocks/second", blocks_per_second);
                blocks_mined
            })
        })
    });
    
    group.finish();
}

/// Performance benchmark for privacy operations
pub fn benchmark_privacy_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("privacy_operations");
    
    group.bench_function("ring_signature_generation", |b| {
        b.iter(|| {
            rt.block_on(async {
                generate_ring_signature(&node_url, 5).await
            })
        })
    });
    
    group.bench_function("stealth_address_generation", |b| {
        b.iter(|| {
            rt.block_on(async {
                generate_stealth_address(&node_url).await
            })
        })
    });
    
    group.bench_function("zk_proof_generation", |b| {
        b.iter(|| {
            rt.block_on(async {
                generate_zk_proof(&node_url, 1000).await
            })
        })
    });
    
    group.finish();
}

/// Performance benchmark for network synchronization
pub fn benchmark_network_sync(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("network_sync");
    group.measurement_time(Duration::from_secs(30));
    
    group.bench_function("peer_discovery", |b| {
        b.iter(|| {
            rt.block_on(async {
                discover_peers(&node_url, 10).await
            })
        })
    });
    
    group.bench_function("block_propagation", |b| {
        b.iter(|| {
            rt.block_on(async {
                test_block_propagation(&node_url).await
            })
        })
    });
    
    group.finish();
}

/// Performance benchmark for marketplace operations
pub fn benchmark_marketplace_performance(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let marketplace_url = get_test_marketplace_url();
    
    let mut group = c.benchmark_group("marketplace_performance");
    group.throughput(Throughput::Elements(50));
    
    group.bench_function("product_operations", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut operations = 0;
                
                // Create products
                for i in 0..50 {
                    if create_test_product(&marketplace_url, i).await.is_ok() {
                        operations += 1;
                    }
                }
                
                operations
            })
        })
    });
    
    group.finish();
}

/// Memory usage benchmark
pub fn benchmark_memory_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("memory_usage");
    
    group.bench_function("blockchain_state_memory", |b| {
        b.iter(|| {
            rt.block_on(async {
                let initial_memory = get_memory_usage(&node_url).await.unwrap_or(0);
                
                // Load blockchain state
                let _state = get_blockchain_state(&node_url).await;
                
                let final_memory = get_memory_usage(&node_url).await.unwrap_or(0);
                final_memory - initial_memory
            })
        })
    });
    
    group.finish();
}

/// CPU usage benchmark
pub fn benchmark_cpu_usage(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let node_url = get_test_node_url();
    
    let mut group = c.benchmark_group("cpu_usage");
    
    group.bench_function("randomx_hashing", |b| {
        b.iter(|| {
            rt.block_on(async {
                perform_randomx_benchmark(&node_url).await
            })
        })
    });
    
    group.finish();
}

// Async helper functions
async fn create_test_transaction(node_url: &str, index: usize) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/create_transaction", node_url))
        .json(&serde_json::json!({
            "to": format!("test_address_{}", index),
            "amount": 100 + index,
            "private": true
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["tx_id"].as_str().unwrap_or("").to_string())
}

async fn mine_test_blocks(node_url: &str, count: u32) -> u32 {
    let client = reqwest::Client::new();
    let mut mined = 0;
    
    for _ in 0..count {
        let response = client
            .post(&format!("{}/mine", node_url))
            .json(&serde_json::json!({"count": 1}))
            .timeout(Duration::from_secs(10))
            .send()
            .await;
        
        if response.is_ok() {
            mined += 1;
        }
    }
    
    mined
}

async fn generate_ring_signature(node_url: &str, ring_size: usize) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/privacy/ring_signature", node_url))
        .json(&serde_json::json!({"ring_size": ring_size}))
        .timeout(Duration::from_secs(10))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["signature"].as_str().unwrap_or("").to_string())
}

async fn generate_stealth_address(node_url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/address/stealth", node_url))
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["address"].as_str().unwrap_or("").to_string())
}

async fn generate_zk_proof(node_url: &str, amount: u64) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/zkproof/create", node_url))
        .json(&serde_json::json!({
            "amount": amount,
            "type": "range_proof"
        }))
        .timeout(Duration::from_secs(15))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["proof"].as_str().unwrap_or("").to_string())
}

async fn discover_peers(node_url: &str, target_count: usize) -> usize {
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/peers", node_url))
        .timeout(Duration::from_secs(5))
        .send()
        .await;
    
    match response {
        Ok(resp) => {
            if let Ok(data) = resp.json::<Value>().await {
                data["count"].as_u64().unwrap_or(0) as usize
            } else {
                0
            }
        }
        Err(_) => 0,
    }
}

async fn test_block_propagation(node_url: &str) -> Duration {
    let client = reqwest::Client::new();
    let start = Instant::now();
    
    // Mine a block and measure propagation time
    let _response = client
        .post(&format!("{}/mine", node_url))
        .json(&serde_json::json!({"count": 1}))
        .send()
        .await;
    
    start.elapsed()
}

async fn create_test_product(marketplace_url: &str, index: usize) -> Result<String, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/api/products", marketplace_url))
        .json(&serde_json::json!({
            "title": format!("Test Product {}", index),
            "description": "Performance test product",
            "price": 100 + index,
            "category": "digital",
            "seller": format!("seller_{}", index)
        }))
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["id"].as_str().unwrap_or("").to_string())
}

async fn get_memory_usage(node_url: &str) -> Option<u64> {
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/metrics/memory", node_url))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .ok()?;
    
    let result: Value = response.json().await.ok()?;
    result["memory_mb"].as_u64()
}

async fn get_blockchain_state(node_url: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .get(&format!("{}/blockchain/state", node_url))
        .timeout(Duration::from_secs(5))
        .send()
        .await?;
    
    Ok(response.json().await?)
}

async fn perform_randomx_benchmark(node_url: &str) -> Result<f64, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let response = client
        .post(&format!("{}/benchmark/randomx", node_url))
        .timeout(Duration::from_secs(30))
        .send()
        .await?;
    
    let result: Value = response.json().await?;
    Ok(result["hash_rate"].as_f64().unwrap_or(0.0))
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

criterion_group!(
    benches,
    benchmark_transaction_throughput,
    benchmark_mining_performance,
    benchmark_privacy_operations,
    benchmark_network_sync,
    benchmark_marketplace_performance,
    benchmark_memory_usage,
    benchmark_cpu_usage
);

criterion_main!(benches);
