use clap::{Parser, Subcommand};
use std::sync::{Arc, atomic::{AtomicU64, Ordering, AtomicBool}, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};
use std::sync::mpsc::{channel, Sender, Receiver};
use std::net::TcpStream;
use std::io::{BufReader, Write, BufRead};

/// BlackSilk Standalone Miner CLI
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start mining
    Start {
        #[arg(short, long, default_value = "127.0.0.1:1776")]
        node: String,
        #[arg(short, long)]
        address: String,
        #[arg(short, long, default_value_t = 1)]
        threads: usize,
        #[arg(long, default_value_t = false)]
        stratum: bool,
    },
    /// Stop mining (placeholder)
    Stop,
    /// Show miner status (placeholder)
    Status,
    /// Benchmark mining speed (placeholder)
    Benchmark,
    /// Set number of threads (placeholder)
    SetThreads {
        n: usize,
    },
    /// Set mining address (placeholder)
    SetAddress {
        addr: String,
    },
    /// Set node address (placeholder)
    SetNode {
        node: String,
    },
    /// Show mining stats (placeholder)
    Stats,
    /// Show help
    Help,
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

#[derive(Debug)]
struct Args {
    node: String,
    address: String,
    threads: usize,
    stratum: bool,
}

#[derive(Debug, Clone)]
struct MinerConfig {
    node: String,
    address: String,
    threads: usize,
}

enum MinerCommand {
    Stop,
    SetThreads(usize),
    SetAddress(String),
    SetNode(String),
    Status,
    Stats,
    Benchmark,
}

fn main() {
    let cli = Cli::parse();
    let config = Arc::new(Mutex::new(MinerConfig {
        node: "127.0.0.1:1776".to_string(),
        address: "".to_string(),
        threads: 1,
    }));
    let (cmd_tx, cmd_rx): (std::sync::mpsc::Sender<MinerCommand>, std::sync::mpsc::Receiver<MinerCommand>) = std::sync::mpsc::channel();
    use MinerCommand::*;
    match &cli.command {
        Some(Commands::Start { node, address, threads, stratum }) => {
            {
                let mut cfg = config.lock().unwrap();
                cfg.node = node.clone();
                cfg.address = address.clone();
                cfg.threads = *threads;
            }
            let config_clone = Arc::clone(&config);
            let handle = std::thread::spawn(move || {
                run_miner(config_clone, cmd_rx);
            });
            println!("[Miner] Mining started. Use 'stop', 'set-threads', 'set-address', 'set-node', 'status', 'stats', 'benchmark' commands in another terminal.");
        }
        Some(Commands::Stop) => {
            let _ = cmd_tx.send(Stop);
            println!("[Miner] Stop command sent.");
        }
        Some(Commands::SetThreads { n }) => {
            let _ = cmd_tx.send(MinerCommand::SetThreads(*n));
            println!("[Miner] Set threads command sent: {}", n);
        }
        Some(Commands::SetAddress { addr }) => {
            let _ = cmd_tx.send(MinerCommand::SetAddress(addr.clone()));
            println!("[Miner] Set address command sent: {}", addr);
        }
        Some(Commands::SetNode { node }) => {
            let _ = cmd_tx.send(MinerCommand::SetNode(node.clone()));
            println!("[Miner] Set node command sent: {}", node);
        }
        Some(Commands::Status) => {
            let _ = cmd_tx.send(MinerCommand::Status);
        }
        Some(Commands::Stats) => {
            let _ = cmd_tx.send(MinerCommand::Stats);
        }
        Some(Commands::Benchmark) => {
            let _ = cmd_tx.send(MinerCommand::Benchmark);
        }
        Some(Commands::Help) | None => {
            println!("BlackSilk Miner CLI - Available commands:");
            println!("  start --node <ip:port> --address <addr> [--threads <n>] [--stratum]   Start mining");
            println!("  stop                                                             Stop mining");
            println!("  status                                                           Show miner status");
            println!("  benchmark                                                        Benchmark mining speed");
            println!("  set-threads <n>                                                  Set number of threads");
            println!("  set-address <addr>                                               Set mining address");
            println!("  set-node <ip:port>                                               Set node address");
            println!("  stats                                                            Show mining stats");
            println!("  help                                                             Show this help message");
        }
    }
}

fn run_miner(config: Arc<Mutex<MinerConfig>>, cmd_rx: std::sync::mpsc::Receiver<MinerCommand>) {
    use MinerCommand::*;
    let should_stop = Arc::new(AtomicBool::new(false));
    let hashes = Arc::new(AtomicU64::new(0));
    let accepted = Arc::new(AtomicU64::new(0));
    let rejected = Arc::new(AtomicU64::new(0));
    let mut threads = vec![];
    let mut last_config = config.lock().unwrap().clone();
    // Refactor: Remove closure, use a function for spawn_miners to avoid double mutable borrow
    fn spawn_miners(
        cfg: &MinerConfig,
        should_stop: &Arc<AtomicBool>,
        hashes: &Arc<AtomicU64>,
        accepted: &Arc<AtomicU64>,
        rejected: &Arc<AtomicU64>,
        threads: &mut Vec<std::thread::JoinHandle<()>>,
    ) {
        should_stop.store(false, Ordering::SeqCst);
        hashes.store(0, Ordering::SeqCst);
        accepted.store(0, Ordering::SeqCst);
        rejected.store(0, Ordering::SeqCst);
        threads.clear();
        for t in 0..cfg.threads {
            let cfg = cfg.clone();
            let should_stop = Arc::clone(should_stop);
            let hashes = Arc::clone(hashes);
            let accepted = Arc::clone(accepted);
            let rejected = Arc::clone(rejected);
            threads.push(std::thread::spawn(move || {
                let client = Client::new();
                let node_url = format!("http://{}/mining/get_block_template", cfg.node);
                let submit_url = format!("http://{}/mining/submit_block", cfg.node);
                loop {
                    if should_stop.load(Ordering::SeqCst) { break; }
                    let req = BlockTemplateRequest { address: cfg.address.clone() };
                    let template = match client.post(&node_url).json(&req).send() {
                        Ok(resp) => {
                            if resp.status().is_success() {
                                match resp.json::<BlockTemplate>() {
                                    Ok(t) => t,
                                    Err(_) => { std::thread::sleep(Duration::from_secs(2)); continue; }
                                }
                            } else { std::thread::sleep(Duration::from_secs(2)); continue; }
                        }
                        Err(_) => { std::thread::sleep(Duration::from_secs(2)); continue; }
                    };
                    let mut header = template.header.clone();
                    let mut nonce = t as u64 * 1_000_000;
                    // Fix RandomXCache::new and RandomXVM::new argument order and count
                    let flags = RandomXFlag::default();
                    let cache = RandomXCache::new(flags, &template.seed).expect("RandomX cache");
                    let vm = RandomXVM::new(flags, Some(&cache), None).expect("RandomX VM");
                    loop {
                        if should_stop.load(Ordering::SeqCst) { break; }
                        let nonce_bytes = nonce.to_le_bytes();
                        let len = header.len();
                        if len >= 8 {
                            for i in 0..8 { header[len-8+i] = nonce_bytes[i]; }
                        }
                        let hash = vm.calculate_hash(&header).expect("RandomX hash");
                        let hash_val = u64::from_le_bytes(hash[0..8].try_into().unwrap());
                        hashes.fetch_add(1, Ordering::Relaxed);
                        if hash_val < template.difficulty {
                            let submit_req = SubmitBlockRequest {
                                header: template.header.clone(),
                                nonce,
                                hash: hash.to_vec(),
                            };
                            match client.post(&submit_url).json(&submit_req).send() {
                                Ok(resp) => {
                                    if resp.status().is_success() {
                                        accepted.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        rejected.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                                Err(_) => { rejected.fetch_add(1, Ordering::Relaxed); }
                            }
                            break;
                        }
                        nonce += cfg.threads as u64;
                    }
                }
            }));
        }
    };

    spawn_miners(&last_config, &should_stop, &hashes, &accepted, &rejected, &mut threads);
    let mut last_time = Instant::now();
    loop {
        if let Ok(cmd) = cmd_rx.try_recv() {
            match cmd {
                Stop => {
                    should_stop.store(true, Ordering::SeqCst);
                    for th in threads.drain(..) { let _ = th.join(); }
                    println!("[Miner] Mining stopped.");
                    break;
                }
                SetThreads(n) => {
                    should_stop.store(true, Ordering::SeqCst);
                    for th in threads.drain(..) { let _ = th.join(); }
                    config.lock().unwrap().threads = n;
                    last_config = config.lock().unwrap().clone();
                    spawn_miners(&last_config, &should_stop, &hashes, &accepted, &rejected, &mut threads);
                    println!("[Miner] Threads updated: {}", n);
                }
                SetAddress(addr) => {
                    should_stop.store(true, Ordering::SeqCst);
                    for th in threads.drain(..) { let _ = th.join(); }
                    config.lock().unwrap().address = addr.clone();
                    last_config = config.lock().unwrap().clone();
                    spawn_miners(&last_config, &should_stop, &hashes, &accepted, &rejected, &mut threads);
                    println!("[Miner] Address updated: {}", addr);
                }
                SetNode(node) => {
                    should_stop.store(true, Ordering::SeqCst);
                    for th in threads.drain(..) { let _ = th.join(); }
                    config.lock().unwrap().node = node.clone();
                    last_config = config.lock().unwrap().clone();
                    spawn_miners(&last_config, &should_stop, &hashes, &accepted, &rejected, &mut threads);
                    println!("[Miner] Node updated: {}", node);
                }
                Status | Stats => {
                    let elapsed = last_time.elapsed().as_secs_f64();
                    let h = hashes.load(Ordering::Relaxed);
                    let acc = accepted.load(Ordering::Relaxed);
                    let rej = rejected.load(Ordering::Relaxed);
                    let hashrate = if elapsed > 0.0 { h as f64 / elapsed } else { 0.0 };
                    let cfg = config.lock().unwrap().clone();
                    println!("[Miner] Status:");
                    println!("  Node: {}", cfg.node);
                    println!("  Address: {}", cfg.address);
                    println!("  Threads: {}", cfg.threads);
                    println!("  Hashrate: {:.2} H/s", hashrate);
                    println!("  Accepted: {} | Rejected: {}", acc, rej);
                }
                Benchmark => {
                    println!("[Miner] Benchmarking for 10 seconds...");
                    hashes.store(0, Ordering::SeqCst);
                    std::thread::sleep(Duration::from_secs(10));
                    let h = hashes.load(Ordering::Relaxed);
                    println!("[Miner] Benchmark result: {:.2} H/s", h as f64 / 10.0);
                }
            }
            last_time = Instant::now();
            hashes.store(0, Ordering::SeqCst);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
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
                        let flags = RandomXFlag::default();
                        let cache = RandomXCache::new(flags, &seed).expect("RandomX cache");
                        let vm = RandomXVM::new(flags, Some(&cache), None).expect("RandomX VM");
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