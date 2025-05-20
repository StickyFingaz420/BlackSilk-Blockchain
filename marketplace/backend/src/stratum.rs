use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use std::sync::atomic::{AtomicU64, Ordering};
use hex;
use std::sync::Mutex;
use reqwest;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::time::interval;

static NEXT_NONCE: AtomicU64 = AtomicU64::new(0);
const NONCE_RANGE_SIZE: u64 = 1_000_000;
static MINER_COUNT: AtomicU64 = AtomicU64::new(0);
static SHARE_COUNT: AtomicU64 = AtomicU64::new(0);
static CONNECTED_MINERS: Mutex<Vec<String>> = Mutex::new(Vec::new());

#[derive(Default, Clone)]
struct MinerStats {
    shares: u64,
    invalid_shares: u64,
    stale_shares: u64,
    last_active: Instant,
    connected_since: Instant,
    hashrate: f64,
    last_hashrate_update: Instant,
    total_difficulty: u64,
    worker_name: String,
    estimated_earnings: f64,  // in coins
}

static MINER_STATS: once_cell::sync::Lazy<Mutex<HashMap<String, MinerStats>>> = once_cell::sync::Lazy::new(|| Mutex::new(HashMap::new()));

fn update_miner_stats(address: &str, shares: u64, difficulty: u64, is_valid: bool, is_stale: bool, worker: Option<&str>) {
    let mut stats = MINER_STATS.lock().unwrap();
    let entry = stats.entry(address.to_string()).or_insert_with(|| {
        let mut default_stats = MinerStats::default();
        default_stats.connected_since = Instant::now();
        default_stats.worker_name = worker.unwrap_or("default").to_string();
        default_stats
    });

    if is_valid && !is_stale {
        entry.shares += shares;
        entry.total_difficulty += difficulty;
        
        // Update hashrate (using exponential moving average)
        let elapsed = entry.last_hashrate_update.elapsed().as_secs_f64();
        if elapsed >= 1.0 {  // Update at most once per second
            let current_hashrate = difficulty as f64 / elapsed;
            entry.hashrate = if entry.hashrate == 0.0 {
                current_hashrate
            } else {
                entry.hashrate * 0.9 + current_hashrate * 0.1  // EMA with alpha=0.1
            };
            entry.last_hashrate_update = Instant::now();
        }
    } else if is_stale {
        entry.stale_shares += shares;
    } else {
        entry.invalid_shares += shares;
    }

    entry.last_active = Instant::now();
    
    // Estimate earnings (simplified)
    let network_difficulty = 1000000.0; // TODO: Get from chain
    let block_reward = 50.0; // TODO: Get from chain
    let share_value = block_reward * (difficulty as f64 / network_difficulty);
    entry.estimated_earnings += share_value;
}

fn print_miner_stats() {
    let stats = MINER_STATS.lock().unwrap();
    println!("\n[Stratum] Miner Statistics:");
    println!("┌─────────────────────────────────────────────────────────────────────────────┐");
    println!("│ Address                          │ Worker │ Hashrate │ Shares (A/R/S) │ Est. Earnings │");
    println!("├─────────────────────────────────────────────────────────────────────────────┤");
    
    for (addr, s) in stats.iter() {
        let short_addr = if addr.len() > 30 {
            format!("{}...{}", &addr[..15], &addr[addr.len()-12..])
        } else {
            addr.clone()
        };
        
        let uptime = s.connected_since.elapsed().as_secs();
        let uptime_str = format!("{}h{}m", uptime / 3600, (uptime % 3600) / 60);
        
        println!("│ {:<32} │ {:<6} │ {:<8.2} │ {}/{}/{} │ {:<12.8} │",
            short_addr,
            s.worker_name,
            s.hashrate,
            s.shares,
            s.invalid_shares,
            s.stale_shares,
            s.estimated_earnings
        );
    }
    println!("└─────────────────────────────────────────────────────────────────────────────┘");
}

fn dummy_block_header() -> Vec<u8> {
    // 80 bytes: version(4) + prev_hash(32) + merkle_root(32) + timestamp(4) + bits(4) + nonce(4)
    let mut header = vec![0u8; 80];
    header[0] = 1; // version
    header[4..36].copy_from_slice(&[2u8; 32]); // prev_hash
    header[36..68].copy_from_slice(&[3u8; 32]); // merkle_root
    header[68..72].copy_from_slice(&12345678u32.to_le_bytes()); // timestamp
    header[72..76].copy_from_slice(&0x1e0ffff0u32.to_le_bytes()); // bits
    // nonce will be set by miner
    header
}

fn dummy_seed() -> Vec<u8> {
    vec![0x42; 32]
}

fn dummy_target() -> Vec<u8> {
    // 32 bytes, low value for demo
    let mut t = vec![0xff; 32];
    t[0] = 0x00;
    t[1] = 0x00;
    t[2] = 0x0f;
    t
}

async fn get_real_block_template(address: &str) -> Option<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    // Query the node for a real block template
    let url = "http://127.0.0.1:8000/mining/get_block_template";
    let req = serde_json::json!({"address": address});
    let client = reqwest::Client::new();
    match client.post(url).json(&req).send().await {
        Ok(resp) => {
            if resp.status().is_success() {
                match resp.json::<serde_json::Value>().await {
                    Ok(val) => {
                        let header = val.get("header").and_then(|h| h.as_array()).map(|arr| arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect::<Vec<u8>>()).unwrap_or_else(|| vec![0; 80]);
                        let seed = val.get("seed").and_then(|h| h.as_array()).map(|arr| arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect::<Vec<u8>>()).unwrap_or_else(|| vec![0x42; 32]);
                        let difficulty = val.get("difficulty").and_then(|d| d.as_u64()).unwrap_or(1000000);
                        // Convert difficulty to target (simplified for demo)
                        let mut target = vec![0xff; 32];
                        let diff_bytes = difficulty.to_le_bytes();
                        for i in 0..8 { target[24+i] = diff_bytes[i]; }
                        Some((header, seed, target))
                    }
                    Err(_) => None,
                }
            } else { None }
        }
        Err(_) => None,
    }
}

#[derive(Clone)]
struct JobUpdate {
    header: Vec<u8>,
    seed: Vec<u8>,
    target: Vec<u8>,
    clean_jobs: bool,
}

async fn job_updater(mut rx: mpsc::Receiver<mpsc::Sender<JobUpdate>>) {
    let mut clients = Vec::new();
    let mut update_interval = interval(Duration::from_secs(30));
    
    loop {
        tokio::select! {
            Some(client_tx) = rx.recv() => {
                clients.push(client_tx);
            }
            _ = update_interval.tick() => {
                // Get new job template
                let (header, seed, target) = match get_real_block_template("pool").await {
                    Some((h, s, t)) => (h, s, t),
                    None => (dummy_block_header(), dummy_seed(), dummy_target()),
                };
                
                let job = JobUpdate {
                    header,
                    seed,
                    target,
                    clean_jobs: false,
                };
                
                // Send to all connected clients
                clients.retain(|client| {
                    if let Err(_) = client.try_send(job.clone()) {
                        false // Remove disconnected clients
                    } else {
                        true
                    }
                });
                
                println!("[Stratum] Sent new jobs to {} miners", clients.len());
            }
        }
    }
}

pub async fn start_stratum_server() {
    let (job_tx, job_rx) = mpsc::channel(100);
    
    // Start job updater
    tokio::spawn(job_updater(job_rx));
    
    let listener = TcpListener::bind("0.0.0.0:3333").await.expect("Failed to bind Stratum port");
    println!("[Stratum] Listening on 0.0.0.0:3333");
    
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                println!("[Stratum] New connection from {}", addr);
                MINER_COUNT.fetch_add(1, Ordering::SeqCst);
                {
                    let mut miners = CONNECTED_MINERS.lock().unwrap();
                    miners.push(addr.to_string());
                }
                
                // Create channel for this client
                let (client_tx, mut client_rx) = mpsc::channel(32);
                let _ = job_tx.send(client_tx).await;
                
                // Spawn client handler
                let job_stream = stream.try_clone().unwrap();
                tokio::spawn(handle_client(stream, addr.to_string(), client_rx));
            }
            Err(e) => println!("[Stratum] Accept error: {}", e),
        }
    }
}

async fn handle_client(stream: TcpStream, addr: String, mut job_rx: mpsc::Receiver<JobUpdate>) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    let mut extranonce = 0u32;
    let job_id = "1";
    let mut authorized = false;
    let mut start_nonce = 0u64;
    let mut end_nonce = 0u64;
    let mut miner_address = String::new();
    let mut worker_name = String::new();
    let mut current_difficulty = 1000000u64; // Starting difficulty
    let mut last_job_time = Instant::now();
    let stats_addr = addr.clone();

    // Start periodic stats printing
    let stats_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(30)).await;
            print_miner_stats();
        }
    });

    loop {
        tokio::select! {
            Some(job) = job_rx.recv() => {
                if authorized {
                    start_nonce = NEXT_NONCE.fetch_add(NONCE_RANGE_SIZE, Ordering::SeqCst);
                    end_nonce = start_nonce + NONCE_RANGE_SIZE;
                    
                    let notify = json!({
                        "id": null,
                        "method": "mining.notify",
                        "params": [
                            job_id,
                            hex::encode(&job.header),
                            hex::encode(&job.seed),
                            hex::encode(&job.target),
                            job.clean_jobs,
                            start_nonce,
                            end_nonce
                        ]
                    });
                    let _ = writer.write_all(format!("{}\n", notify).as_bytes()).await;
                    last_job_time = Instant::now();
                }
            }
            result = reader.read_line(&mut line) => {
                match result {
                    Ok(n) => {
                        if n == 0 { break; }
                        let msg: serde_json::Value = match serde_json::from_str(&line) {
                            Ok(m) => m,
                            Err(_) => continue,
                        };
                        
                        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
                        match method {
                            "mining.subscribe" => {
                                let resp = json!({
                                    "id": msg["id"],
                                    "result": [
                                        ["mining.set_difficulty", "1"],
                                        ["mining.notify", "1"],
                                        format!("BlackSilk_{:08x}", extranonce),
                                        4
                                    ],
                                    "error": null
                                });
                                let _ = writer.write_all(format!("{}\n", resp).as_bytes()).await;
                            }
                            "mining.authorize" => {
                                let username = msg["params"][0].as_str().unwrap_or("");
                                // Parse username for worker name: address.worker
                                let parts: Vec<&str> = username.split('.').collect();
                                miner_address = parts[0].to_string();
                                worker_name = parts.get(1).map(|w| w.to_string()).unwrap_or_else(|| "default".to_string());
                                
                                authorized = true;
                                update_miner_stats(&miner_address, 0, current_difficulty, true, false, Some(&worker_name));
                                
                                let resp = json!({ "id": msg["id"], "result": true, "error": null });
                                let _ = writer.write_all(format!("{}\n", resp).as_bytes()).await;

                                // Send initial difficulty
                                let diff_notify = json!({
                                    "id": null,
                                    "method": "mining.set_difficulty",
                                    "params": [current_difficulty as f64]
                                });
                                let _ = writer.write_all(format!("{}\n", diff_notify).as_bytes()).await;

                                // Send first job
                                start_nonce = NEXT_NONCE.fetch_add(NONCE_RANGE_SIZE, Ordering::SeqCst);
                                end_nonce = start_nonce + NONCE_RANGE_SIZE;
                                let (header, seed, target) = match get_real_block_template(&miner_address).await {
                                    Some((h, s, t)) => (h, s, t),
                                    None => (dummy_block_header(), dummy_seed(), dummy_target()),
                                };
                                let notify = json!({
                                    "id": null,
                                    "method": "mining.notify",
                                    "params": [job_id, hex::encode(&header), hex::encode(&seed), hex::encode(&target), false, start_nonce, end_nonce]
                                });
                                let _ = writer.write_all(format!("{}\n", notify).as_bytes()).await;
                            }
                            "mining.submit" => {
                                if authorized {
                                    let params = msg["params"].as_array().unwrap_or(&Vec::new());
                                    let worker = params.get(0).and_then(|v| v.as_str()).unwrap_or("");
                                    let job = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
                                    let nonce_hex = params.get(3).and_then(|v| v.as_str()).unwrap_or("");
                                    let hash_hex = params.get(4).and_then(|v| v.as_str()).unwrap_or("");

                                    // Validate share
                                    let is_valid = validate_share(job, nonce_hex, hash_hex, current_difficulty);
                                    let is_stale = last_job_time.elapsed() > Duration::from_secs(60);
                                    
                                    update_miner_stats(
                                        &miner_address,
                                        1,
                                        current_difficulty,
                                        is_valid,
                                        is_stale,
                                        Some(&worker_name)
                                    );

                                    // Adjust difficulty based on share time
                                    let share_time = last_job_time.elapsed().as_secs_f64();
                                    if share_time < 10.0 {
                                        // Increase difficulty if shares coming too fast
                                        current_difficulty = (current_difficulty as f64 * 1.2) as u64;
                                        let diff_notify = json!({
                                            "id": null,
                                            "method": "mining.set_difficulty",
                                            "params": [current_difficulty as f64]
                                        });
                                        let _ = writer.write_all(format!("{}\n", diff_notify).as_bytes()).await;
                                    } else if share_time > 30.0 {
                                        // Decrease difficulty if shares coming too slow
                                        current_difficulty = (current_difficulty as f64 * 0.8) as u64;
                                        let diff_notify = json!({
                                            "id": null,
                                            "method": "mining.set_difficulty",
                                            "params": [current_difficulty as f64]
                                        });
                                        let _ = writer.write_all(format!("{}\n", diff_notify).as_bytes()).await;
                                    }

                                    // Send response
                                    let resp = json!({
                                        "id": msg["id"],
                                        "result": is_valid && !is_stale,
                                        "error": if !is_valid {
                                            Some("Invalid share")
                                        } else if is_stale {
                                            Some("Stale share")
                                        } else {
                                            None
                                        }
                                    });
                                    let _ = writer.write_all(format!("{}\n", resp).as_bytes()).await;

                                    // Send new job
                                    start_nonce = NEXT_NONCE.fetch_add(NONCE_RANGE_SIZE, Ordering::SeqCst);
                                    end_nonce = start_nonce + NONCE_RANGE_SIZE;
                                    let (header, seed, target) = match get_real_block_template(&miner_address).await {
                                        Some((h, s, t)) => (h, s, t),
                                        None => (dummy_block_header(), dummy_seed(), dummy_target()),
                                    };
                                    let notify = json!({
                                        "id": null,
                                        "method": "mining.notify",
                                        "params": [job_id, hex::encode(&header), hex::encode(&seed), hex::encode(&target), false, start_nonce, end_nonce]
                                    });
                                    let _ = writer.write_all(format!("{}\n", notify).as_bytes()).await;
                                    last_job_time = Instant::now();
                                }
                            }
                            _ => {
                                let resp = json!({
                                    "id": msg.get("id").cloned().unwrap_or(json!(null)),
                                    "result": null,
                                    "error": ["Unknown method", null, null]
                                });
                                let _ = writer.write_all(format!("{}\n", resp).as_bytes()).await;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    println!("[Stratum] Client {} disconnected", addr);
    MINER_COUNT.fetch_sub(1, Ordering::SeqCst);
    {
        let mut miners = CONNECTED_MINERS.lock().unwrap();
        miners.retain(|a| a != &addr);
    }
}

fn validate_share(job: &str, nonce_hex: &str, hash_hex: &str, difficulty: u64) -> bool {
    // TODO: Implement proper share validation using RandomX
    // For now, just check if hash meets difficulty
    if let Ok(hash) = hex::decode(hash_hex) {
        if hash.len() >= 8 {
            let hash_val = u64::from_le_bytes(hash[0..8].try_into().unwrap());
            return hash_val < difficulty;
        }
    }
    false
} 