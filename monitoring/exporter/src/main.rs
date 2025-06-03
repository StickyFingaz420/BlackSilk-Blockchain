// BlackSilk Blockchain Metrics Exporter
// Custom Prometheus exporter for BlackSilk network monitoring

use prometheus::{
    Counter, Gauge, Histogram, IntCounter, IntGauge, Registry, Encoder, TextEncoder,
    HistogramOpts, Opts,
};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::interval;
use warp::Filter;

/// BlackSilk network metrics collector
#[derive(Clone)]
pub struct BlackSilkMetrics {
    // Node metrics
    pub chain_height: IntGauge,
    pub peers_connected: IntGauge,
    pub mempool_size: IntGauge,
    pub network_hashrate: Gauge,
    pub block_time: Histogram,
    pub latest_block_timestamp: IntGauge,
    
    // Mining metrics
    pub total_hashes: IntCounter,
    pub blocks_found: IntCounter,
    pub shares_accepted: IntCounter,
    pub shares_rejected: IntCounter,
    pub mining_difficulty: Gauge,
    pub suspicious_submissions: IntCounter,
    
    // Network metrics
    pub peer_connections: IntGauge,
    pub peer_disconnections: IntCounter,
    pub tor_connections: IntGauge,
    pub i2p_connections: IntGauge,
    pub clearnet_connections: IntGauge,
    pub privacy_mode: IntGauge,
    
    // Transaction metrics
    pub transactions_total: IntCounter,
    pub transactions_rejected: IntCounter,
    pub transaction_fees: Counter,
    pub tx_processing_time: Histogram,
    
    // Marketplace metrics
    pub marketplace_requests: IntCounter,
    pub marketplace_errors: IntCounter,
    pub marketplace_response_time: Histogram,
    pub active_listings: IntGauge,
    pub completed_orders: IntCounter,
    
    // System metrics
    pub node_uptime: IntGauge,
    pub memory_usage: Gauge,
    pub cpu_usage: Gauge,
    pub disk_usage: Gauge,
    pub block_validation_time: Histogram,
    
    registry: Registry,
}

impl BlackSilkMetrics {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let registry = Registry::new();
        
        let chain_height = IntGauge::new("blacksilk_chain_height", "Current blockchain height")?;
        let peers_connected = IntGauge::new("blacksilk_peers_connected", "Number of connected peers")?;
        let mempool_size = IntGauge::new("blacksilk_mempool_size", "Number of transactions in mempool")?;
        let network_hashrate = Gauge::new("blacksilk_network_hashrate", "Total network hashrate (H/s)")?;
        let block_time = Histogram::with_opts(
            HistogramOpts::new("blacksilk_block_time_seconds", "Time between blocks")
                .buckets(vec![30.0, 60.0, 90.0, 120.0, 150.0, 180.0, 240.0, 300.0])
        )?;
        let latest_block_timestamp = IntGauge::new("blacksilk_latest_block_timestamp", "Timestamp of latest block")?;
        
        let total_hashes = IntCounter::new("blacksilk_total_hashes", "Total hashes computed")?;
        let blocks_found = IntCounter::new("blacksilk_blocks_found", "Total blocks found by miners")?;
        let shares_accepted = IntCounter::new("blacksilk_shares_accepted", "Mining shares accepted")?;
        let shares_rejected = IntCounter::new("blacksilk_shares_rejected", "Mining shares rejected")?;
        let mining_difficulty = Gauge::new("blacksilk_mining_difficulty", "Current mining difficulty")?;
        let suspicious_submissions = IntCounter::new("blacksilk_suspicious_submissions", "Suspicious mining submissions detected")?;
        
        let peer_connections = IntGauge::new("blacksilk_peer_connections", "Active peer connections")?;
        let peer_disconnections = IntCounter::new("blacksilk_peer_disconnections", "Peer disconnection events")?;
        let tor_connections = IntGauge::new("blacksilk_tor_connections", "Tor network connections")?;
        let i2p_connections = IntGauge::new("blacksilk_i2p_connections", "I2P network connections")?;
        let clearnet_connections = IntGauge::new("blacksilk_clearnet_connections", "Clearnet connections")?;
        let privacy_mode = IntGauge::new("blacksilk_privacy_mode", "Current privacy mode (0=off, 1=tor, 2=max)")?;
        
        let transactions_total = IntCounter::new("blacksilk_transactions_total", "Total transactions processed")?;
        let transactions_rejected = IntCounter::new("blacksilk_transactions_rejected", "Transactions rejected")?;
        let transaction_fees = Counter::new("blacksilk_transaction_fees_total", "Total transaction fees collected")?;
        let tx_processing_time = Histogram::with_opts(
            HistogramOpts::new("blacksilk_tx_processing_seconds", "Transaction processing time")
                .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0])
        )?;
        
        let marketplace_requests = IntCounter::new("marketplace_requests_total", "Total marketplace API requests")?;
        let marketplace_errors = IntCounter::new("marketplace_errors_total", "Marketplace API errors")?;
        let marketplace_response_time = Histogram::with_opts(
            HistogramOpts::new("marketplace_request_duration_seconds", "Marketplace request duration")
                .buckets(vec![0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0])
        )?;
        let active_listings = IntGauge::new("marketplace_active_listings", "Number of active marketplace listings")?;
        let completed_orders = IntCounter::new("marketplace_completed_orders", "Completed marketplace orders")?;
        
        let node_uptime = IntGauge::new("blacksilk_node_uptime_seconds", "Node uptime in seconds")?;
        let memory_usage = Gauge::new("blacksilk_memory_usage_percent", "Memory usage percentage")?;
        let cpu_usage = Gauge::new("blacksilk_cpu_usage_percent", "CPU usage percentage")?;
        let disk_usage = Gauge::new("blacksilk_disk_usage_percent", "Disk usage percentage")?;
        let block_validation_time = Histogram::with_opts(
            HistogramOpts::new("blacksilk_block_validation_duration_seconds", "Block validation time")
                .buckets(vec![0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0])
        )?;
        
        // Register all metrics
        registry.register(Box::new(chain_height.clone()))?;
        registry.register(Box::new(peers_connected.clone()))?;
        registry.register(Box::new(mempool_size.clone()))?;
        registry.register(Box::new(network_hashrate.clone()))?;
        registry.register(Box::new(block_time.clone()))?;
        registry.register(Box::new(latest_block_timestamp.clone()))?;
        registry.register(Box::new(total_hashes.clone()))?;
        registry.register(Box::new(blocks_found.clone()))?;
        registry.register(Box::new(shares_accepted.clone()))?;
        registry.register(Box::new(shares_rejected.clone()))?;
        registry.register(Box::new(mining_difficulty.clone()))?;
        registry.register(Box::new(suspicious_submissions.clone()))?;
        registry.register(Box::new(peer_connections.clone()))?;
        registry.register(Box::new(peer_disconnections.clone()))?;
        registry.register(Box::new(tor_connections.clone()))?;
        registry.register(Box::new(i2p_connections.clone()))?;
        registry.register(Box::new(clearnet_connections.clone()))?;
        registry.register(Box::new(privacy_mode.clone()))?;
        registry.register(Box::new(transactions_total.clone()))?;
        registry.register(Box::new(transactions_rejected.clone()))?;
        registry.register(Box::new(transaction_fees.clone()))?;
        registry.register(Box::new(tx_processing_time.clone()))?;
        registry.register(Box::new(marketplace_requests.clone()))?;
        registry.register(Box::new(marketplace_errors.clone()))?;
        registry.register(Box::new(marketplace_response_time.clone()))?;
        registry.register(Box::new(active_listings.clone()))?;
        registry.register(Box::new(completed_orders.clone()))?;
        registry.register(Box::new(node_uptime.clone()))?;
        registry.register(Box::new(memory_usage.clone()))?;
        registry.register(Box::new(cpu_usage.clone()))?;
        registry.register(Box::new(disk_usage.clone()))?;
        registry.register(Box::new(block_validation_time.clone()))?;
        
        Ok(BlackSilkMetrics {
            chain_height,
            peers_connected,
            mempool_size,
            network_hashrate,
            block_time,
            latest_block_timestamp,
            total_hashes,
            blocks_found,
            shares_accepted,
            shares_rejected,
            mining_difficulty,
            suspicious_submissions,
            peer_connections,
            peer_disconnections,
            tor_connections,
            i2p_connections,
            clearnet_connections,
            privacy_mode,
            transactions_total,
            transactions_rejected,
            transaction_fees,
            tx_processing_time,
            marketplace_requests,
            marketplace_errors,
            marketplace_response_time,
            active_listings,
            completed_orders,
            node_uptime,
            memory_usage,
            cpu_usage,
            disk_usage,
            block_validation_time,
            registry,
        })
    }
    
    /// Collect metrics from BlackSilk node
    pub async fn collect_from_node(&self, client: &Client, node_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        // Get node info
        let info_response = client.get(&format!("{}/info", node_url)).send().await?;
        if info_response.status().is_success() {
            let info: Value = info_response.json().await?;
            
            if let Some(height) = info.get("height").and_then(|h| h.as_u64()) {
                self.chain_height.set(height as i64);
            }
            
            if let Some(peers) = info.get("peers").and_then(|p| p.as_u64()) {
                self.peers_connected.set(peers as i64);
            }
            
            if let Some(difficulty) = info.get("difficulty").and_then(|d| d.as_f64()) {
                self.mining_difficulty.set(difficulty);
            }
        }
        
        // Get mempool info
        let mempool_response = client.get(&format!("{}/api/mempool", node_url)).send().await?;
        if mempool_response.status().is_success() {
            let mempool: Value = mempool_response.json().await?;
            
            if let Some(count) = mempool.get("count").and_then(|c| c.as_u64()) {
                self.mempool_size.set(count as i64);
            }
        }
        
        // Get mining stats if available
        if let Ok(mining_response) = client.get(&format!("{}/api/mining/stats", node_url)).send().await {
            if mining_response.status().is_success() {
                if let Ok(mining: Value) = mining_response.json().await {
                    if let Some(hashrate) = mining.get("hashrate").and_then(|h| h.as_f64()) {
                        self.network_hashrate.set(hashrate);
                    }
                    
                    if let Some(blocks) = mining.get("blocks_found").and_then(|b| b.as_u64()) {
                        self.blocks_found.inc_by(blocks);
                    }
                }
            }
        }
        
        // Get privacy stats
        if let Ok(privacy_response) = client.get(&format!("{}/api/privacy/stats", node_url)).send().await {
            if privacy_response.status().is_success() {
                if let Ok(privacy: Value) = privacy_response.json().await {
                    if let Some(tor) = privacy.get("tor_connections").and_then(|t| t.as_u64()) {
                        self.tor_connections.set(tor as i64);
                    }
                    
                    if let Some(i2p) = privacy.get("i2p_connections").and_then(|i| i.as_u64()) {
                        self.i2p_connections.set(i2p as i64);
                    }
                    
                    if let Some(clearnet) = privacy.get("clearnet_connections").and_then(|c| c.as_u64()) {
                        self.clearnet_connections.set(clearnet as i64);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Update system metrics
    pub async fn update_system_metrics(&self) {
        let uptime = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.node_uptime.set(uptime as i64);
        
        // Note: In production, these would read from actual system sources
        // For now, we'll use placeholder values
        self.cpu_usage.set(45.2);
        self.memory_usage.set(62.8);
        self.disk_usage.set(23.1);
    }
    
    /// Get metrics in Prometheus format
    pub fn gather(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode_to_string(&metric_families).unwrap_or_default()
    }
}

/// Main exporter service
pub struct MetricsExporter {
    metrics: Arc<BlackSilkMetrics>,
    client: Client,
    node_url: String,
}

impl MetricsExporter {
    pub fn new(node_url: String) -> Result<Self, Box<dyn std::error::Error>> {
        let metrics = Arc::new(BlackSilkMetrics::new()?);
        let client = Client::new();
        
        Ok(MetricsExporter {
            metrics,
            client,
            node_url,
        })
    }
    
    /// Start the metrics collection loop
    pub async fn start_collection(&self, interval_secs: u64) {
        let mut interval = interval(Duration::from_secs(interval_secs));
        
        loop {
            interval.tick().await;
            
            let start = Instant::now();
            
            // Collect from node
            if let Err(e) = self.metrics.collect_from_node(&self.client, &self.node_url).await {
                eprintln!("Failed to collect node metrics: {}", e);
            }
            
            // Update system metrics
            self.metrics.update_system_metrics().await;
            
            let duration = start.elapsed();
            println!("Metrics collection completed in {:?}", duration);
        }
    }
    
    /// Start the HTTP server for Prometheus scraping
    pub async fn start_server(&self, port: u16) {
        let metrics = self.metrics.clone();
        
        let metrics_route = warp::path("metrics")
            .map(move || {
                let response = metrics.gather();
                warp::reply::with_header(response, "content-type", "text/plain; version=0.0.4; charset=utf-8")
            });
        
        let health_route = warp::path("health")
            .map(|| "OK");
        
        let routes = metrics_route.or(health_route);
        
        println!("Starting BlackSilk metrics exporter on port {}", port);
        warp::serve(routes)
            .run(([0, 0, 0, 0], port))
            .await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let node_url = std::env::var("BLACKSILK_NODE_URL")
        .unwrap_or_else(|_| "http://localhost:9333".to_string());
    
    let monitoring_interval = std::env::var("MONITORING_INTERVAL")
        .unwrap_or_else(|_| "15".to_string())
        .parse::<u64>()
        .unwrap_or(15);
    
    let exporter = MetricsExporter::new(node_url)?;
    
    // Start metrics collection in background
    let collection_metrics = exporter.metrics.clone();
    let collection_client = exporter.client.clone();
    let collection_url = exporter.node_url.clone();
    
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(monitoring_interval));
        loop {
            interval.tick().await;
            if let Err(e) = collection_metrics.collect_from_node(&collection_client, &collection_url).await {
                eprintln!("Failed to collect metrics: {}", e);
            }
            collection_metrics.update_system_metrics().await;
        }
    });
    
    // Start HTTP server
    exporter.start_server(9115).await;
    
    Ok(())
}
