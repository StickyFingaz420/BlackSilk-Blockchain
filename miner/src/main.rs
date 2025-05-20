use clap::Parser;
use std::sync::{Arc, atomic::{AtomicU64, Ordering}};
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use randomx_rs::{RandomXCache, RandomXFlags, RandomXVM};
use crossbeam_channel::{bounded, select, tick, Receiver};
use std::net::TcpStream;
use std::io::{BufRead, BufReader, Write};
use hex;

/// BlackSilk Standalone Miner CLI
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Node address (host:port) or Stratum server
    #[arg(short, long, default_value = "127.0.0.1:1776")]
    node: String,

    /// Wallet address to mine to
    #[arg(short, long)]
    address: String,

    /// Number of mining threads
    #[arg(short, long, default_value_t = 1)]
    threads: usize,

    /// Use Stratum protocol (pool mining)
    #[arg(long, default_value_t = false)]
    stratum: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BlockTemplate {
    header: Vec<u8>,
    difficulty: u64,
    seed: Vec<u8>,
    coinbase_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SubmitBlockRequest {
    header: Vec<u8>,
    nonce: u64,
    hash: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BlockTemplateRequest {
    address: String,
}

fn main() {
    let args = Args::parse();
    println!("[BlackSilk Miner] Starting miner");
    println!("Node: {}", args.node);
    println!("Mining address: {}", args.address);
    println!("Threads: {}", args.threads);
    if args.stratum {
        stratum_mine(&args);
        return;
    }

    let client = Client::new();
    let node_url = format!("http://{}/mining/get_block_template", args.node);
    let submit_url = format!("http://{}/mining/submit_block", args.node);

    let hashes = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));

    // Setup Ctrl+C handler
    let (shutdown_tx, shutdown_rx) = bounded::<()>(1);
    {
        let shutdown_tx = shutdown_tx.clone();
        ctrlc::set_handler(move || {
            let _ = shutdown_tx.send(());
        }).expect("Error setting Ctrl+C handler");
    }

    'outer: loop {
        println!("[Miner] Requesting block template from node...");
        let req = BlockTemplateRequest {
            address: args.address.clone(),
        };
        let template = match client.post(&node_url).json(&req).send() {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<BlockTemplate>() {
                        Ok(t) => t,
                        Err(e) => {
                            println!("[Miner] Failed to parse block template: {}", e);
                            std::thread::sleep(Duration::from_secs(10));
                            continue;
                        }
                    }
                } else {
                    println!("[Miner] Node returned error: {}", resp.status());
                    std::thread::sleep(Duration::from_secs(10));
                    continue;
                }
            }
            Err(e) => {
                println!("[Miner] Failed to connect to node: {}", e);
                std::thread::sleep(Duration::from_secs(10));
                continue;
            }
        };
        println!("[Miner] Got block template: difficulty={}, header_len={}, seed={:x?}, coinbase_address={}",
            template.difficulty, template.header.len(), &template.seed[..4], template.coinbase_address);

        hashes.store(0, Ordering::Relaxed);
        let start = Instant::now();
        let mut handles = vec![];
        let found_flag = Arc::new(AtomicU64::new(0));
        for t in 0..args.threads {
            let template = template.clone();
            let hashes = Arc::clone(&hashes);
            let accepted = Arc::clone(&accepted);
            let rejected = Arc::clone(&rejected);
            let found_flag = Arc::clone(&found_flag);
            let submit_url = submit_url.clone();
            let client = client.clone();
            let thread_id = t;
            let shutdown_rx = shutdown_rx.clone();
            handles.push(thread::spawn(move || {
                let flags = RandomXFlags::default()
                    | RandomXFlags::FLAG_LARGE_PAGES
                    | RandomXFlags::FLAG_HARD_AES
                    | RandomXFlags::FLAG_FULL_MEM;
                let cache = RandomXCache::new(&template.seed, flags).expect("RandomX cache");
                let vm = RandomXVM::new(&cache, flags).expect("RandomX VM");
                let mut header = template.header.clone();
                let mut nonce = thread_id as u64 * 1_000_000;
                loop {
                    if shutdown_rx.try_recv().is_ok() || found_flag.load(Ordering::Relaxed) != 0 {
                        break;
                    }
                    let nonce_bytes = nonce.to_le_bytes();
                    let len = header.len();
                    if len >= 8 {
                        for i in 0..8 { header[len-8+i] = nonce_bytes[i]; }
                    }
                    let hash = vm.calculate_hash(&header).expect("RandomX hash");
                    let hash_val = u64::from_le_bytes(hash[0..8].try_into().unwrap());
                    hashes.fetch_add(1, Ordering::Relaxed);
                    if hash_val < template.difficulty {
                        if found_flag.compare_and_swap(0, 1, Ordering::SeqCst) == 0 {
                            println!("[Miner] Thread {} found valid nonce: {} (hash={:x?})", thread_id, nonce, &hash[..8]);
                            let submit_req = SubmitBlockRequest {
                                header: template.header.clone(),
                                nonce,
                                hash: hash.to_vec(),
                            };
                            match client.post(&submit_url)
                                .json(&submit_req)
                                .send() {
                                Ok(resp) => {
                                    if resp.status().is_success() {
                                        println!("[Miner] Block accepted by node!");
                                        accepted.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        println!("[Miner] Block rejected by node: {}", resp.status());
                                        rejected.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(e) => {
                                    println!("[Miner] Failed to submit block: {}", e);
                                    rejected.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        break;
                    }
                    nonce += args.threads as u64;
                }
            }));
        }
        // Print stats every 10s, break if a solution is found or shutdown
        let ticker = tick(Duration::from_secs(10));
        loop {
            select! {
                recv(ticker) -> _ => {
                    let elapsed = start.elapsed().as_secs_f64();
                    let h = hashes.load(Ordering::Relaxed);
                    let hash_rate = h as f64 / elapsed;
                    let acc = accepted.load(Ordering::Relaxed);
                    let rej = rejected.load(Ordering::Relaxed);
                    println!("[Miner] Hashrate: {:.2} H/s | Accepted: {} | Rejected: {}", hash_rate, acc, rej);
                    if found_flag.load(Ordering::Relaxed) != 0 {
                        break;
                    }
                }
                recv(shutdown_rx) -> _ => {
                    println!("[Miner] Shutting down...");
                    break 'outer;
                }
            }
        }
        // Wait for all threads to finish
        for handle in handles {
            let _ = handle.join();
        }
        if shutdown_rx.try_recv().is_ok() {
            println!("[Miner] Shutting down...");
            break;
        }
        println!("[Miner] Restarting with new block template...");
    }
    println!("[Miner] Exited cleanly.");
}

fn stratum_mine(args: &Args) {
    println!("[Miner] Connecting to Stratum server at {}...", args.node);
    let mut stream = match TcpStream::connect(&args.node) {
        Ok(s) => s,
        Err(e) => {
            println!("[Miner] Failed to connect to Stratum server: {}", e);
            return;
        }
    };
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    // Send subscribe
    let subscribe = serde_json::json!({"id": 1, "method": "mining.subscribe", "params": []});
    let _ = writeln!(stream, "{}", subscribe);
    // Send authorize
    let authorize = serde_json::json!({"id": 2, "method": "mining.authorize", "params": [args.address, "x"]});
    let _ = writeln!(stream, "{}", authorize);
    let mut line = String::new();
    let mut job_id = String::new();
    let mut extranonce = 0u32;
    let mut hashes = 0u64;
    let mut accepted = 0u64;
    let mut rejected = 0u64;
    let start = std::time::Instant::now();
    let mut start_nonce = 0u64;
    let mut end_nonce = 0u64;
    loop {
        line.clear();
        if reader.read_line(&mut line).is_err() { break; }
        if line.trim().is_empty() { continue; }
        let msg: serde_json::Value = match serde_json::from_str(&line) {
            Ok(m) => m,
            Err(_) => continue,
        };
        if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
            match method {
                "mining.notify" => {
                    // Parse job_id, header, seed, target, start_nonce, end_nonce
                    if let Some(params) = msg.get("params").and_then(|p| p.as_array()) {
                        job_id = params.get(0).and_then(|v| v.as_str()).unwrap_or("").to_string();
                        let header_hex = params.get(1).and_then(|v| v.as_str()).unwrap_or("");
                        let seed_hex = params.get(2).and_then(|v| v.as_str()).unwrap_or("");
                        let target_hex = params.get(3).and_then(|v| v.as_str()).unwrap_or("");
                        start_nonce = params.get(5).and_then(|v| v.as_u64()).unwrap_or(0);
                        end_nonce = params.get(6).and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("[Stratum] Assigned nonce range: {} - {}", start_nonce, end_nonce);
                        let header = match hex::decode(header_hex) { Ok(h) => h, Err(_) => continue };
                        let seed = match hex::decode(seed_hex) { Ok(s) => s, Err(_) => continue };
                        let target = match hex::decode(target_hex) { Ok(t) => t, Err(_) => continue };
                        // --- RandomX mining ---
                        let flags = randomx_rs::RandomXFlags::default()
                            | randomx_rs::RandomXFlags::FLAG_LARGE_PAGES
                            | randomx_rs::RandomXFlags::FLAG_HARD_AES
                            | randomx_rs::RandomXFlags::FLAG_FULL_MEM;
                        let cache = randomx_rs::RandomXCache::new(&seed, flags).expect("RandomX cache");
                        let vm = randomx_rs::RandomXVM::new(&cache, flags).expect("RandomX VM");
                        let mut found = false;
                        let mut found_nonce = 0u64;
                        let mut found_hash = vec![];
                        for nonce in start_nonce..end_nonce {
                            let mut header_work = header.clone();
                            let nonce_bytes = nonce.to_le_bytes();
                            let len = header_work.len();
                            if len >= 8 {
                                for i in 0..8 { header_work[len-8+i] = nonce_bytes[i]; }
                            }
                            let hash = vm.calculate_hash(&header_work).expect("RandomX hash");
                            hashes += 1;
                            // Compare hash to target (as big-endian)
                            if hash[..target.len()] < target[..] {
                                println!("[Miner] Found valid nonce: {} (hash={:x?})", nonce, &hash[..8]);
                                found = true;
                                found_nonce = nonce;
                                found_hash = hash.to_vec();
                                break;
                            }
                        }
                        if found {
                            let submit = serde_json::json!({
                                "id": 3,
                                "method": "mining.submit",
                                "params": [args.address, job_id, extranonce, format!("{:08x}", found_nonce), hex::encode(&found_hash)]
                            });
                            let _ = writeln!(stream, "{}", submit);
                        } else {
                            println!("[Miner] No valid nonce found in assigned range");
                        }
                        // --- End mining ---
                    }
                }
                _ => {}
            }
        }
        if let Some(result) = msg.get("result") {
            if result == &serde_json::Value::Bool(true) {
                accepted += 1;
            } else if result == &serde_json::Value::Bool(false) {
                rejected += 1;
            }
        }
        // Print stats every 10s
        if start.elapsed().as_secs() % 10 == 0 {
            let elapsed = start.elapsed().as_secs_f64();
            let hash_rate = hashes as f64 / elapsed;
            println!("[Miner] Hashrate: {:.2} H/s | Accepted: {} | Rejected: {}", hash_rate, accepted, rejected);
        }
    }
    println!("[Miner] Stratum connection closed.");
} 